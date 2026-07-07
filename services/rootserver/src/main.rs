#![no_std]
#![no_main]
#![deny(warnings)]
#![allow(clippy::useless_conversion)]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;
#[macro_use]
extern crate libnova;

use novafs_core::FileSystem;

mod allocator;
mod arch;
mod drivers;
mod elf_loader;
mod filesystem;
mod fs;
mod handlers;
mod ipc;
mod memory;
mod process;
mod runtime;
mod services;
mod shared_memory;
mod shell;
mod tests;
mod vspace;

use alloc::boxed::Box;
use alloc::sync::Arc;
use libnova::cap::cap_rights_new;
use libnova::syscall::SyscallNum;
use sel4_sys::{seL4_BootInfo, seL4_CPtr, seL4_Word};
// Temporary constant until we confirm sel4_sys export
#[allow(dead_code, non_upper_case_globals)]
const seL4_X86_4K: seL4_Word = 8;

use crate::arch::{acpi, ioapic, port_io, serial};

use crate::ipc::Endpoint;
use crate::process::{get_process_manager, Process};
use crate::shared_memory::SharedMemoryManager;
use core::arch::global_asm;
use memory::{FrameAllocator, ObjectAllocator, SlotAllocator, UntypedAllocator};

use core::ptr::addr_of_mut;

static mut SHARED_MEMORY_MANAGER: SharedMemoryManager = SharedMemoryManager::new();

static mut WORKER_STACK: [u8; 4096] = [0; 4096];

const OOM_SLOT_RESERVE: usize = 64;
const OOM_MIN_FREE_RAM_BYTES: u64 = 256 * 1024;
pub(crate) const FS_READ_PREFER_SERVER: bool = true;
// Keep synchronous syscall forwarding disabled while fs_server remains a
// syscall-backed proxy. A RootServer thread that synchronously calls fs_server
// would deadlock once fs_server calls back into the same syscall endpoint.
pub(crate) const FS_SYNC_FORWARD_ENABLED: bool = false;

pub(crate) fn deny_if_memory_pressure(
    slots: &SlotAllocator,
    allocator: &UntypedAllocator,
    boot_info: &seL4_BootInfo,
    needed_slots: usize,
    context: &str,
) -> bool {
    let slots_ok = slots.can_allocate_with_reserve(needed_slots, OOM_SLOT_RESERVE);
    let free_ram = allocator.free_ram_bytes(boot_info);
    if slots_ok && free_ram >= OOM_MIN_FREE_RAM_BYTES {
        return false;
    }

    let (_, _, free_slots) = slots.stats();
    let fragmented = allocator.fragmentation_bytes(boot_info);
    let (oom_events, last_oom_bits) = allocator.oom_stats();
    println!(
        "[OOM] Admission denied for {}: need_slots={}, free_slots={}, free_ram={} bytes, fragmented_tail={} bytes, oom_events={}, last_oom_bits={}",
        context,
        needed_slots,
        free_slots,
        free_ram,
        fragmented,
        oom_events,
        last_oom_bits
    );
    true
}

pub(crate) fn refresh_local_fs_view(
    ata: Arc<crate::drivers::ata::AtaDriver>,
) -> Result<(), &'static str> {
    let fs = novafs_core::novafs::NovaFS::new(ata, 0)?;
    let fs_arc = alloc::sync::Arc::new(fs.clone());
    *crate::fs::DISK_FS.lock() = Some(fs_arc.clone());
    *novafs_core::VFS.lock() = Some(fs_arc);
    Ok(())
}

extern "C" fn irq_worker_entry(notification: usize, endpoint: usize) {
    serial::send_char('[');
    serial::send_char('W');
    serial::send_char(']');
    serial::send_char('\n');
    println!(
        "[WORKER] Thread started. Notification: {}, Endpoint: {}",
        notification, endpoint
    );

    loop {
        // Wait for notification
        let badge = libnova::ipc::wait(notification.try_into().unwrap());

        // Debug: print '!'
        // crate::serial::send_char('!');
        // println!("[WORKER] Received Notification! Badge: {}", badge);

        libnova::ipc::set_mr(0, badge);
        let info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
        let _ = libnova::ipc::call(endpoint.try_into().unwrap(), info);
    }
}

pub(crate) fn spawn_boot_process(
    boot_info: &seL4_BootInfo,
    allocator: &mut impl ObjectAllocator,
    slot_allocator: &mut SlotAllocator,
    frame_allocator: &mut FrameAllocator,
    syscall_ep_cap: seL4_CPtr,
    process_name: &str,
    file_name: &str,
    badge: u64,
    args: &[&str],
) -> bool {
    if badge < 100 {
        println!(
            "[KERNEL] Refusing to spawn '{}' with invalid badge {}",
            process_name, badge
        );
        return false;
    }
    let pid = (badge - 100) as usize;
    if get_process_manager().get_process(pid).is_some() {
        println!(
            "[KERNEL] Refusing to spawn '{}': PID {} already occupied for badge {}",
            process_name, pid, badge
        );
        return false;
    }
    println!(
        "[KERNEL] Spawning {} from /bin/{}...",
        process_name, file_name
    );
    let badged_ep_slot = match slot_allocator.alloc() {
        Ok(slot) => slot,
        Err(e) => {
            println!(
                "[KERNEL] Failed to alloc EP slot for '{}' (badge {}): {:?}",
                process_name, badge, e
            );
            return false;
        }
    };
    let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
    let cnode_depth = sel4_sys::seL4_WordBits as u8;

    let err = unsafe {
        sel4_sys::seL4_CNode_Mint(
            root_cnode,
            badged_ep_slot,
            cnode_depth,
            root_cnode,
            syscall_ep_cap,
            cnode_depth,
            cap_rights_new(false, true, true, true),
            badge,
        )
    };
    if err != 0.into() {
        println!(
            "[KERNEL] Failed to mint EP for '{}' (badge {}): {:?}",
            process_name, badge, err
        );
        return false;
    }

    let Some(elf_data) = crate::filesystem::get_file(file_name) else {
        println!("[KERNEL] Boot file '{}' not found", file_name);
        return false;
    };

    match Process::spawn(
        allocator,
        slot_allocator,
        frame_allocator,
        boot_info,
        process_name,
        elf_data,
        args,
        &[],
        100,
        badged_ep_slot,
        32,
        0,
        0,
    ) {
        Ok(mut process) => {
            if process_name == "fs_server" {
                process.fs_forwarding_enabled = false;
            }
            match get_process_manager().add_process_at(pid, process) {
                Ok(_) => {
                    println!(
                        "[KERNEL] Spawned '{}' as PID {} (badge {}).",
                        process_name, pid, badge
                    );
                    if process_name == "serial_server" {
                        services::register("serial.v1", badged_ep_slot);
                        println!("[KERNEL] Service 'serial.v1' registered (boot bootstrap).");
                    } else if process_name == "fs_server" {
                        services::register("fs.v1", badged_ep_slot);
                        println!("[KERNEL] Service 'fs.v1' registered (boot bootstrap).");
                    }
                    true
                }
                Err(e) => {
                    println!("[KERNEL] Failed to add '{}': {:?}", process_name, e);
                    false
                }
            }
        }
        Err(e) => {
            println!("[KERNEL] Failed to spawn '{}': {:?}", process_name, e);
            false
        }
    }
}

#[cfg(test)]
fn test_runner(tests: &[&dyn Fn()]) {
    println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
    println!("[TEST] PASSED");
    loop {}
}

#[test_case]
fn trivial_assertion() {
    print!("trivial assertion... ");
    assert_eq!(1, 1);
    println!("[ok]");
}

// 定义汇编入口点和栈
global_asm!(
    r#"
    .section .text.start
    .global _start
    // .type _start, @function
    _start:
        /* 设置栈指针 */
        lea stack_top(%rip), %rsp
        mov %rsp, %rbp

        /* 调用 Rust 入口点 */
        call rust_main
        
        /* 如果返回，则挂起 */
        ud2

    .section .bss
    .align 16
    .global stack_bottom
    stack_bottom:
    .space 262144 /* 256KB bootstrap stack */
    .global stack_top
    stack_top:
    "#,
    options(att_syntax)
);

/// RootServer 的 Rust 入口点
/// 由汇编 _start 调用
///
/// # Safety
/// This function is the entry point called by assembly. The `boot_info_ptr`
/// must be a valid pointer to `seL4_BootInfo` provided by the
/// kernel/bootloader.
#[no_mangle]
pub unsafe extern "C" fn rust_main(boot_info_ptr: *const seL4_BootInfo) -> ! {
    // 初始化运行时（例如堆分配器，如果需要）
    println!("[KERNEL] RootServer Started.");
    allocator::init_heap();
    println!("[KERNEL] Heap Initialized (1MB).");

    // Initialise log level from NOVA_LOG_LEVEL environment hint.
    // Default is 1 (info). Tests may set this to 0 or 2/3 via env var.
    // This is a compile-time constant for now; runtime env parsing
    // will be added when the full env framework is available.
    libnova::log::set_log_level(1);

    // 1. Get BootInfo
    if boot_info_ptr.is_null() {
        // We can't print safely yet, so just hang or rely on DebugPutChar if we had it
        // separately. panic!("Failed to get BootInfo! System halted.");
        // For now, let's just assume it's good or crash.
        loop {
            libnova::syscall::yield_thread();
        }
    }

    // SAFETY: We trust the bootloader provided a valid pointer
    let boot_info = &*boot_info_ptr;

    // Initialize IPC Buffer
    sel4_sys::seL4_SetIPCBuffer(boot_info.ipcBuffer);

    // 2. 初始化内存分配器
    let mut slot_allocator = SlotAllocator::new(boot_info);
    let mut allocator = UntypedAllocator::new(boot_info);
    let mut frame_allocator = FrameAllocator::new();

    println!("Initializing IO Port Capability...");

    // 1. Allocate a slot in the Root CNode for the IO Port Cap
    let io_port_slot = slot_allocator
        .alloc()
        .expect("Failed to allocate slot for IO Port Cap");

    // 2. Issue IO Port Cap directly into Root CNode
    // Extra Cap: Root CNode (Cap 2)
    // We need to provide the CPtr to the Root CNode so the kernel can look it up.
    let root_cnode_cptr = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as u64;

    match port_io::issue_ioport_cap(
        (sel4_sys::seL4_RootCNodeCapSlots::seL4_CapIOPortControl as u64)
            .try_into()
            .unwrap(),
        0x0000,
        0xFFFF,
        root_cnode_cptr.try_into().unwrap(), // Extra Cap: Root CNode
        io_port_slot,                        // Slot in Root CNode
        (sel4_sys::seL4_WordBits as u64).try_into().unwrap(),
    ) {
        Ok(_) => {
            println!("IO Port Capability issued successfully to Root CNode.");
        }
        Err(e) => {
            println!("Failed to issue IO Port Capability. Error: {:?}", e);
            loop {
                libnova::syscall::yield_thread();
            }
        }
    }

    // 3. Use the cap
    port_io::init(io_port_slot);

    // Initialize Disk Driver
    println!("[KERNEL] Initializing Disk Driver...");
    let mut ata_driver = drivers::ata::AtaDriver::new(0x1F0);
    let disk_size_sectors = if let Err(e) = ata_driver.init() {
        println!("[KERNEL] ATA Driver Init Failed: {}", e);
        // Fallback size (e.g. 5MB)
        1024 * 10
    } else {
        ata_driver.sector_count as u32
    };

    let ata = alloc::sync::Arc::new(ata_driver);

    // Initialize NovaFS (Mount)
    println!("[KERNEL] Mounting NovaFS...");
    let mut need_format = false;

    match novafs_core::novafs::NovaFS::new(ata.clone(), 0) {
        Ok(fs) => {
            let fs_arc = alloc::sync::Arc::new(fs.clone());
            *crate::fs::DISK_FS.lock() = Some(fs_arc.clone());
            *novafs_core::VFS.lock() = Some(fs_arc);
            if fs.root_inode().lookup("bin").is_err() {
                println!("[KERNEL] /bin not found.");
                need_format = true;
            }
        }
        Err(e) => {
            println!("[KERNEL] Mount failed: {}. Will format.", e);
            need_format = true;
        }
    }

    if need_format {
        println!("[KERNEL] Disk uninitialized or system missing. Formatting...");
        // Use detected size if valid, else default 5MB
        let format_size = if disk_size_sectors > 0 {
            disk_size_sectors
        } else {
            1024 * 10
        };
        let fs_new = novafs_core::novafs::NovaFS::format(ata.clone(), 0, format_size);
        let fs_arc = alloc::sync::Arc::new(fs_new.clone());
        *crate::fs::DISK_FS.lock() = Some(fs_arc.clone());
        *novafs_core::VFS.lock() = Some(fs_arc);

        if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
            let root = fs.root_inode();
            println!("[KERNEL] Creating /bin...");
            let bin = root
                .create("bin", novafs_core::FileType::Directory)
                .expect("Failed to create /bin");

            println!("[KERNEL] Installing system binaries...");
            for file in filesystem::FILES {
                println!("[KERNEL] Installing: {}", file.name);
                let inode = bin
                    .create(file.name, novafs_core::FileType::File)
                    .expect("Failed to create file");
                println!("[KERNEL] Writing data for: {}", file.name);
                inode.write_at(0, file.data).expect("Failed to write data");
                println!("  - Installed: {}", file.name);
            }

            // Create README
            println!("[KERNEL] Creating README.TXT...");
            let readme = root
                .create("README.TXT", novafs_core::FileType::File)
                .unwrap();
            println!("[KERNEL] Writing README.TXT...");
            readme
                .write_at(0, b"Welcome to NovaOS (Persistent Mode)!")
                .unwrap();
            println!("[KERNEL] Syncing README...");
            readme.sync().ok();
        }

        if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
            println!("[KERNEL] Syncing Filesystem...");
            fs.sync().ok();
        }
    } else {
        println!("[KERNEL] Filesystem healthy.");
    }
    println!("[KERNEL] VFS Initialized.");

    // Initialize Serial Port
    serial::init();
    serial::send_char('S'); // Test Serial
    serial::send_char('e');
    serial::send_char('r');
    serial::send_char('i');
    serial::send_char('a');
    serial::send_char('l');
    serial::send_char('\n');

    println!("\n========================================");
    println!("   NovaOS: The Future Secure OS");
    println!("   Status: RootServer Started");
    println!("========================================");

    println!("[INFO] BootInfo retrieved successfully.");
    println!("[INFO] BootInfo Addr: {:p}", boot_info);
    println!("[INFO] IPC Buffer: {:p}", boot_info.ipcBuffer);
    println!(
        "[INFO] Empty Slots: {} - {}",
        boot_info.empty.start, boot_info.empty.end
    );
    println!(
        "[INFO] Untyped Slots: {} - {}",
        boot_info.untyped.start, boot_info.untyped.end
    );

    println!(
        "[INFO] Untyped Memory: {} slots",
        boot_info.untyped.end - boot_info.untyped.start
    );
    println!(
        "[INFO] CNode Size: {} bits",
        boot_info.initThreadCNodeSizeBits
    );

    allocator.print_info(boot_info);

    let mut irq_handler_cap: usize = 0;
    let mut timer_irq_cap: usize = 0;
    let mut serial_irq_cap: usize = 0;
    let early_irq_notification_cap = match allocator.allocate(
        boot_info,
        sel4_sys::api_object_seL4_NotificationObject.into(),
        sel4_sys::seL4_NotificationBits.into(),
        &mut slot_allocator,
    ) {
        Ok(cap) => {
            println!("[KERNEL] Early IRQ notification allocated at slot {}", cap);
            cap as usize
        }
        Err(e) => {
            println!(
                "[KERNEL] Failed to allocate early IRQ notification: {:?}",
                e
            );
            0
        }
    };

    // Initialize ACPI
    let mut acpi_context = acpi::AcpiContext::new();

    if let Some(acpi_info) = acpi::init(boot_info) {
        println!("[INFO] ACPI Info found. Mapping RSDT...");
        match acpi::map_rsdt(
            boot_info,
            &acpi_info,
            &mut allocator,
            &mut slot_allocator,
            &mut acpi_context,
        ) {
            Ok(rsdt_ptr) => {
                let rsdt = unsafe { &*rsdt_ptr };
                if let Ok(sig) = core::str::from_utf8(&rsdt.header.signature) {
                    let len = rsdt.header.length;
                    let checksum = rsdt.header.checksum;
                    let oem_id_slice = rsdt.header.oem_id;
                    log_debug!(
                        libnova::log::DOM_ACPI,
                        "[ACPI] RSDT Mapped at {:p}, Signature: {}",
                        rsdt_ptr,
                        sig
                    );
                    log_debug!(libnova::log::DOM_ACPI, "[ACPI] RSDT Length: {}", len);
                    log_debug!(libnova::log::DOM_ACPI, "[ACPI] RSDT Checksum: {}", checksum);
                    log_debug!(
                        libnova::log::DOM_ACPI,
                        "[ACPI] RSDT OEM ID: {:?}",
                        core::str::from_utf8(&oem_id_slice).unwrap_or("Unknown")
                    );

                    // Iterate RSDT Entries
                    let header_size = core::mem::size_of::<crate::arch::acpi::AcpiTableHeader>();
                    let entries_count = (len as usize - header_size) / 4;
                    log_debug!(
                        libnova::log::DOM_ACPI,
                        "[ACPI] Scanning {} RSDT entries...",
                        entries_count
                    );

                    let entry_start = (rsdt_ptr as usize + header_size) as *const u32;
                    for i in 0..entries_count {
                        let table_paddr = unsafe { *entry_start.add(i) } as usize;

                        // Map table to check signature
                        let vaddr_base = 0x8001_0000 + (i * 0x10000); // 64KB spacing to be safe

                        match crate::arch::acpi::map_phys(
                            boot_info,
                            table_paddr,
                            vaddr_base,
                            &mut allocator,
                            &mut slot_allocator,
                            &mut acpi_context,
                        ) {
                            Ok(ptr_val) => {
                                let header = unsafe {
                                    &*(ptr_val as *const crate::arch::acpi::AcpiTableHeader)
                                };
                                if let Ok(sig) = core::str::from_utf8(&header.signature) {
                                    log_debug!(
                                        libnova::log::DOM_ACPI,
                                        "[ACPI] Table [{}] Signature: {}",
                                        i,
                                        sig
                                    );
                                    if sig == "APIC" {
                                        log_debug!(
                                            libnova::log::DOM_ACPI,
                                            "[ACPI] Found MADT (APIC) Table!"
                                        );
                                        // Check length and map remaining pages if needed
                                        let length = header.length as usize;
                                        if length > 4096 {
                                            let pages_needed = length.div_ceil(4096);
                                            log_debug!(libnova::log::DOM_ACPI, "[ACPI] MADT size {} bytes, mapping {} extra pages...", length, pages_needed - 1);
                                            for p in 1..pages_needed {
                                                let p_paddr = table_paddr + p * 4096;
                                                if let Err(e) = crate::arch::acpi::map_phys(
                                                    boot_info,
                                                    p_paddr,
                                                    0,
                                                    &mut allocator,
                                                    &mut slot_allocator,
                                                    &mut acpi_context,
                                                ) {
                                                    println!("[ACPI] Failed to map extra page for MADT: {:?}", e);
                                                }
                                            }
                                        }

                                        let madt = unsafe {
                                            &*(ptr_val as *const crate::arch::acpi::Madt)
                                        };
                                        let local_apic = madt.local_apic_address;
                                        let flags = madt.flags;
                                        log_debug!(
                                            libnova::log::DOM_ACPI,
                                            "[ACPI] Local APIC Address: 0x{:x}",
                                            local_apic
                                        );
                                        log_debug!(
                                            libnova::log::DOM_ACPI,
                                            "[ACPI] MADT Flags: 0x{:x}",
                                            flags
                                        );

                                        // Parse MADT records
                                        crate::arch::acpi::walk_madt(madt);

                                        // Initialize Local APIC
                                        if let Some(_apic) = crate::arch::apic::init(
                                            boot_info,
                                            local_apic as usize,
                                            &mut allocator,
                                            &mut slot_allocator,
                                            &mut acpi_context,
                                        ) {
                                            println!("[KERNEL] Local APIC Initialized.");
                                        } else {
                                            println!("[KERNEL] Local APIC init skipped (using default configuration).");
                                        }

                                        // Initialize IO APIC
                                        if let Some(ioapic_info) =
                                            crate::arch::acpi::find_first_ioapic(madt)
                                        {
                                            println!(
                                                "[KERNEL] Found IOAPIC at 0x{:x} (ID: {}).",
                                                ioapic_info.address, ioapic_info.id
                                            );

                                            let irq_control_cap =
                                                sel4_sys::seL4_RootCNodeCapSlots::seL4_CapIRQControl
                                                    as usize;
                                            let root_cnode_cap = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as usize;
                                            let depth = sel4_sys::seL4_WordBits as usize;

                                            // 1. Keyboard IRQ (IRQ 1)
                                            if let Ok(irq_slot) = slot_allocator.alloc() {
                                                let irq = 1;
                                                // Check for ISO
                                                let (gsi, level, polarity) = if let Some(iso) =
                                                    crate::arch::acpi::find_iso_for_irq(madt, irq)
                                                {
                                                    let iso_gsi = iso.gsi;
                                                    let iso_flags = iso.flags;
                                                    println!("[KERNEL] Found ISO for IRQ 1: GSI={}, Flags=0x{:x}", iso_gsi, iso_flags);
                                                    let p_flag = iso_flags & 0x3;
                                                    let t_flag = (iso_flags >> 2) & 0x3;

                                                    let pol = if p_flag == 3 { 1 } else { 0 };
                                                    let lev = if t_flag == 3 { 1 } else { 0 };

                                                    (iso_gsi as usize, lev, pol)
                                                } else {
                                                    // Legacy IRQ 1 is GSI 1, Active High, Edge
                                                    (1, 0, 0)
                                                };

                                                println!(
                                                    "[KERNEL] Config Keyboard IRQ {} -> GSI {}",
                                                    irq, gsi
                                                );

                                                let pin = gsi;
                                                let ioapic_idx = 0;
                                                let vector = 33; // 0x21

                                                let err = crate::arch::ioapic::get_ioapic_handler(
                                                    irq_control_cap,
                                                    ioapic_idx as usize,
                                                    pin as usize,
                                                    level,
                                                    polarity,
                                                    root_cnode_cap,
                                                    irq_slot.try_into().unwrap(),
                                                    depth,
                                                    vector,
                                                );
                                                if err.is_ok() {
                                                    println!("[KERNEL] IRQ Handler for Keyboard created.");

                                                    irq_handler_cap = irq_slot as usize;
                                                    if early_irq_notification_cap != 0 {
                                                        if let Err(e) = ioapic::set_irq_handler(
                                                            irq_handler_cap,
                                                            early_irq_notification_cap,
                                                        ) {
                                                            println!(
                                                                "[KERNEL] Failed to bind early KB IRQ notification: {}",
                                                                e
                                                            );
                                                        } else if let Err(e) =
                                                            ioapic::ack_irq(irq_handler_cap)
                                                        {
                                                            println!(
                                                                "[KERNEL] Failed to ack early KB IRQ: {}",
                                                                e
                                                            );
                                                        }
                                                    }
                                                }
                                            }

                                            // 2. Timer IRQ (IRQ 0)
                                            if let Ok(irq_slot) = slot_allocator.alloc() {
                                                let irq = 0;
                                                // Check for ISO (usually GSI 2)
                                                // Default: GSI 0, Edge (0), High (0) if no ISO.
                                                // If ISO exists: Use ISO GSI and Flags.
                                                // ACPI Flags: Polarity (0=Bus, 1=High, 3=Low),
                                                // Trigger (0=Bus, 1=Edge, 3=Level)
                                                // seL4: Polarity (0=High, 1=Low), Level (0=Edge,
                                                // 1=Level)

                                                let (gsi, level, polarity) = if let Some(iso) =
                                                    crate::arch::acpi::find_iso_for_irq(madt, irq)
                                                {
                                                    let iso_gsi = iso.gsi;
                                                    let iso_flags = iso.flags;
                                                    println!("[KERNEL] Found ISO for IRQ 0: GSI={}, Flags=0x{:x}", iso_gsi, iso_flags);
                                                    let p_flag = iso_flags & 0x3;
                                                    let t_flag = (iso_flags >> 2) & 0x3;

                                                    let pol = if p_flag == 3 { 1 } else { 0 }; // 3=Low -> 1
                                                    let lev = if t_flag == 3 { 1 } else { 0 }; // 3=Level -> 1

                                                    (iso_gsi as usize, lev, pol)
                                                } else {
                                                    // QEMU Default: IRQ 0 is often overridden to
                                                    // GSI 2, but if no ISO, assume legacy.
                                                    // Actually, on QEMU, IRQ 0 is GSI 2.
                                                    // If find_iso_for_irq returns None, we might be
                                                    // in trouble if it IS GSI 2.
                                                    // But find_iso_for_irq SHOULD find it on QEMU.
                                                    println!("[KERNEL] No ISO for IRQ 0. Assuming GSI 2 (Legacy override).");
                                                    (2, 0, 0)
                                                };

                                                println!("[KERNEL] Config Timer IRQ {} -> GSI {}, Level {}, Polarity {}", irq, gsi, level, polarity);

                                                let pin = gsi;
                                                let ioapic_idx = 0;
                                                let vector = 40; // 0x28

                                                let err = crate::arch::ioapic::get_ioapic_handler(
                                                    irq_control_cap,
                                                    ioapic_idx as usize,
                                                    pin as usize,
                                                    level,
                                                    polarity,
                                                    root_cnode_cap,
                                                    irq_slot.try_into().unwrap(),
                                                    depth,
                                                    vector,
                                                );

                                                if err.is_ok() {
                                                    timer_irq_cap = irq_slot as usize;
                                                    println!(
                                                        "[KERNEL] Timer IRQ Handler obtained."
                                                    );
                                                    if early_irq_notification_cap != 0 {
                                                        if let Err(e) = ioapic::set_irq_handler(
                                                            timer_irq_cap,
                                                            early_irq_notification_cap,
                                                        ) {
                                                            println!(
                                                                "[KERNEL] Failed to bind early Timer IRQ notification: {}",
                                                                e
                                                            );
                                                        } else if let Err(e) =
                                                            ioapic::ack_irq(timer_irq_cap)
                                                        {
                                                            println!(
                                                                "[KERNEL] Failed to ack early Timer IRQ: {}",
                                                                e
                                                            );
                                                        }
                                                    }
                                                } else {
                                                    println!(
                                                        "[KERNEL] Failed to get Timer IRQ Handler."
                                                    );
                                                }
                                            }

                                            // 3. Serial Port IRQ (IRQ 4 / COM1)
                                            if let Ok(irq_slot) = slot_allocator.alloc() {
                                                let irq = 4;
                                                let (gsi, level, polarity) = if let Some(iso) =
                                                    crate::arch::acpi::find_iso_for_irq(madt, irq)
                                                {
                                                    let iso_gsi = iso.gsi;
                                                    let iso_flags = iso.flags;
                                                    println!("[KERNEL] Found ISO for IRQ 4: GSI={}, Flags=0x{:x}", iso_gsi, iso_flags);
                                                    let p_flag = iso_flags & 0x3;
                                                    let t_flag = (iso_flags >> 2) & 0x3;

                                                    let pol = if p_flag == 3 { 1 } else { 0 };
                                                    let lev = if t_flag == 3 { 1 } else { 0 };

                                                    (iso_gsi as usize, lev, pol)
                                                } else {
                                                    (4, 0, 0)
                                                };

                                                println!(
                                                    "[KERNEL] Config Serial IRQ {} -> GSI {}",
                                                    irq, gsi
                                                );

                                                let pin = gsi;
                                                let ioapic_idx = 0;
                                                let vector = 52;

                                                let err = crate::arch::ioapic::get_ioapic_handler(
                                                    irq_control_cap,
                                                    ioapic_idx as usize,
                                                    pin as usize,
                                                    level,
                                                    polarity,
                                                    root_cnode_cap,
                                                    irq_slot.try_into().unwrap(),
                                                    depth,
                                                    vector,
                                                );
                                                if err.is_ok() {
                                                    serial_irq_cap = irq_slot as usize;
                                                    println!(
                                                        "[KERNEL] Serial IRQ Handler obtained."
                                                    );
                                                    if early_irq_notification_cap != 0 {
                                                        if let Err(e) = ioapic::set_irq_handler(
                                                            serial_irq_cap,
                                                            early_irq_notification_cap,
                                                        ) {
                                                            println!(
                                                                 "[KERNEL] Failed to bind early Serial IRQ notification: {}",
                                                                 e
                                                             );
                                                        } else if let Err(e) =
                                                            ioapic::ack_irq(serial_irq_cap)
                                                        {
                                                            println!(
                                                                 "[KERNEL] Failed to ack early Serial IRQ: {}",
                                                                 e
                                                             );
                                                        }
                                                    }
                                                } else {
                                                    println!("[KERNEL] Failed to get Serial IRQ Handler.");
                                                }
                                            }
                                        } else {
                                            println!("[KERNEL] No IOAPIC found in MADT.");
                                        }
                                    } else if sig == "FACP" {
                                        log_debug!(
                                            libnova::log::DOM_ACPI,
                                            "[ACPI] Found FADT Table!"
                                        );
                                        let fadt = unsafe { &*(ptr_val as *const acpi::Fadt) };
                                        acpi::set_fadt(fadt);
                                        acpi::enable_acpi(fadt);
                                    }
                                }
                            }
                            Err(e) => {
                                println!(
                                    "[ACPI] Failed to map table at 0x{:x}: {:?}",
                                    table_paddr, e
                                );
                            }
                        }
                    }
                } else {
                    println!("[ACPI] RSDT Mapped but signature invalid");
                }
            }
            Err(e) => {
                println!("[ACPI] Failed to map RSDT: {:?}", e);
            }
        }
    }

    // Mask legacy PIC before lengthy POST to avoid spurious early IRQ noise
    // while IRQ routing is still being finalized.
    port_io::outb(0x21, 0xFF);
    port_io::outb(0xA1, 0xFF);
    println!("[KERNEL] Legacy PIC Masked (pre-POST).");

    // 3. System Self-Test (POST)
    println!("[KERNEL] Performing Power-On Self-Test (POST)...");
    tests::run_all(
        boot_info,
        &mut allocator,
        &mut slot_allocator,
        &mut frame_allocator,
    );
    println!("[KERNEL] POST Completed Successfully.");

    // 4. Initialize Syscall Endpoint and Processes
    println!("[KERNEL] Initializing Process Manager...");

    // Allocate Syscall Endpoint
    let syscall_ep_cap = allocator
        .allocate(
            boot_info,
            sel4_sys::api_object_seL4_EndpointObject.into(),
            sel4_sys::seL4_EndpointBits.into(),
            &mut slot_allocator,
        )
        .expect("Failed to alloc EP");
    // Allocate dedicated fs service endpoint to avoid contention with syscall
    // endpoint.
    let fs_service_ep_cap = match allocator.allocate(
        boot_info,
        sel4_sys::api_object_seL4_EndpointObject.into(),
        sel4_sys::seL4_EndpointBits.into(),
        &mut slot_allocator,
    ) {
        Ok(cap) => {
            println!("[KERNEL] Dedicated fs service endpoint allocated: {}", cap);
            cap
        }
        Err(e) => {
            println!(
                "[KERNEL] Failed to allocate dedicated fs service endpoint: {:?}; fallback to syscall endpoint",
                e
            );
            syscall_ep_cap
        }
    };

    // Initialize Service Registry
    services::init();

    // Create and Register "test" service (Badge 200)
    let test_service_slot = slot_allocator
        .alloc()
        .expect("Failed to alloc slot for test service");
    let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
    let cnode_depth = sel4_sys::seL4_WordBits;

    let err = unsafe {
        sel4_sys::seL4_CNode_Mint(
            root_cnode,
            test_service_slot,
            cnode_depth as u8,
            root_cnode,
            syscall_ep_cap,
            cnode_depth as u8,
            cap_rights_new(false, true, true, true),
            200, // Badge 200 for Test Service
        )
    };
    if err != 0.into() {
        println!("[KERNEL] Failed to mint test service endpoint: {:?}", err);
    } else {
        services::register("test", test_service_slot);
        println!("[KERNEL] Service 'test' registered (Badge 200).");
    }

    // Keep the current process ordering to preserve existing integration test
    // assumptions.
    let _ = spawn_boot_process(
        boot_info,
        &mut allocator,
        &mut slot_allocator,
        &mut frame_allocator,
        syscall_ep_cap,
        "hello",
        "hello",
        100,
        &[],
    );
    let _ = spawn_boot_process(
        boot_info,
        &mut allocator,
        &mut slot_allocator,
        &mut frame_allocator,
        syscall_ep_cap,
        "hello2",
        "hello",
        101,
        &[],
    );

    // 5. Setup Interrupts
    println!("[KERNEL] Setting up Interrupts...");

    // Initialize PCI
    crate::arch::pci::init();

    // let mut notification_cap = 0; // Removed unused variable
    let mut driver_manager = drivers::DriverManager::new();
    let mut shell = shell::Shell::new();
    let mut system_tick: u64 = 0;
    let mut deferred_services_spawned = false;

    match allocator.allocate(
        boot_info,
        sel4_sys::api_object_seL4_NotificationObject.into(),
        sel4_sys::seL4_NotificationBits.into(),
        &mut slot_allocator,
    ) {
        Ok(notification_cap) => {
            // notification_cap = cap;
            println!(
                "[KERNEL] Allocated Notification at slot {}",
                notification_cap
            );

            // Spawn IRQ Worker Thread
            println!("[KERNEL] Spawning IRQ Worker Thread...");
            let worker_tcb_cap = allocator
                .allocate(
                    boot_info,
                    sel4_sys::api_object_seL4_TCBObject.into(),
                    sel4_sys::seL4_TCBBits.into(),
                    &mut slot_allocator,
                )
                .expect("Failed to alloc worker TCB");
            let worker_badged_ep = slot_allocator
                .alloc()
                .expect("Failed to alloc worker EP slot");

            let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
            let cnode_depth = sel4_sys::seL4_WordBits as u8;
            let vspace_root = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadVSpace as usize;

            unsafe {
                // Mint Badged Endpoint (Badge 999)
                sel4_sys::seL4_CNode_Mint(
                    root_cnode,
                    worker_badged_ep,
                    cnode_depth,
                    root_cnode,
                    syscall_ep_cap,
                    cnode_depth,
                    cap_rights_new(false, true, true, true),
                    999,
                );

                // Configure TCB Manually
                // Label: TCBConfigure (typically 1 or derived)
                // Args: FaultEP, CSpaceRootData, VSpaceRootData, BufferAddr
                // Extra Caps: CSpaceRoot, VSpaceRoot, BufferFrame(Optional)

                libnova::ipc::set_mr(0, 0); // Fault EP
                libnova::ipc::set_mr(1, 0); // CSpace Data
                libnova::ipc::set_mr(2, 0); // VSpace Data
                libnova::ipc::set_mr(3, 0); // Buffer Address (No IPC Buffer)

                libnova::ipc::set_cap(0, root_cnode);
                libnova::ipc::set_cap(1, vspace_root as seL4_CPtr);
                libnova::ipc::set_cap(2, 0); // BufferFrame (Null)

                let info = libnova::ipc::MessageInfo::new(
                    sel4_sys::invocation_label_TCBConfigure as seL4_Word,
                    0,
                    3, // ExtraCaps: CSpace, VSpace, BufferFrame
                    5, // Length
                );
                let _ = libnova::ipc::call(worker_tcb_cap, info);

                // Set Priority
                let authority =
                    sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadTCB as seL4_CPtr;
                libnova::ipc::set_mr(0, 255); // Priority

                // We need to pass authority as an extra cap?
                // No, seL4_TCB_SetPriority(tcb, auth, prio)
                // The syscall is on TCB. Auth is passed as ExtraCap? Or MR?
                // Checking seL4 manual: seL4_TCB_SetPriority takes (service, authority,
                // priority). authority is a CPtr. In MCS, it might be
                // different. In Master (non-MCS), authority is usually passed
                // as an argument in the message? Actually, standard binding:
                // seL4_TCB_SetPriority(tcb, authority, priority) invokes tcb.
                // The authority is passed in the message?
                // Let's check generated bindings logic usually.
                // Usually: SetMR(0, priority). SetCap(0, authority). ExtraCaps=1.
                // Let's assume ExtraCap 0 is authority.

                libnova::ipc::set_cap(0, authority);
                let info = libnova::ipc::MessageInfo::new(
                    sel4_sys::invocation_label_TCBSetPriority as seL4_Word,
                    0,
                    1, // ExtraCaps: Authority
                    1, // Length: Priority
                );
                let _ = libnova::ipc::call(worker_tcb_cap, info);

                // Write Registers
                let stack_top = (core::ptr::addr_of_mut!(WORKER_STACK) as usize) + 4096;
                let mut regs = [0u64; 20];
                // 0: rip, 1: rsp, 2: rflags
                regs[0] = irq_worker_entry as *const () as u64; // rip
                regs[1] = stack_top as u64; // rsp
                regs[2] = 0x202; // rflags (IF enabled)
                                 // 8: rdi (notification)
                regs[8] = notification_cap as u64;
                // 7: rsi (endpoint)
                regs[7] = worker_badged_ep as u64;

                let info = libnova::ipc::MessageInfo::new(
                    sel4_sys::invocation_label_TCBWriteRegisters as seL4_Word,
                    0,
                    0,
                    2 + 20, // Length: flags(1) + count(1) + regs(20)
                );
                libnova::ipc::set_mr(0, 0); // Resume=false
                libnova::ipc::set_mr(1, 20); // Count
                for i in 0..20 {
                    libnova::ipc::set_mr(i + 2, regs[i].try_into().unwrap());
                }
                let _ = libnova::ipc::call(worker_tcb_cap, info);

                // Resume
                let info = libnova::ipc::MessageInfo::new(
                    sel4_sys::invocation_label_TCBResume as seL4_Word,
                    0,
                    0,
                    0,
                );
                let _ = libnova::ipc::call(worker_tcb_cap, info);

                println!("[KERNEL] IRQ Worker Thread Started.");
            }

            // 1. Configure Keyboard (Badge 1)
            if irq_handler_cap != 0 {
                let kb_badge_cap = slot_allocator.alloc().unwrap();
                let root_cnode =
                    sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                let cnode_depth = sel4_sys::seL4_WordBits as u8;

                let err = unsafe {
                    sel4_sys::seL4_CNode_Mint(
                        root_cnode,
                        kb_badge_cap,
                        cnode_depth,
                        root_cnode,
                        notification_cap,
                        cnode_depth,
                        cap_rights_new(false, true, true, true),
                        1, // Badge 1
                    )
                };

                if err == 0.into() {
                    if let Err(e) = ioapic::set_irq_handler(irq_handler_cap, kb_badge_cap as usize)
                    {
                        println!("[KERNEL] Failed to SetKBIRQHandler: {}", e);
                    } else {
                        if let Err(e) = ioapic::ack_irq(irq_handler_cap) {
                            println!("[KERNEL] Failed to Ack KB IRQ: {}", e);
                        } else {
                            println!("[KERNEL] Keyboard IRQ Configured.");
                            driver_manager.register_irq_driver(
                                1,
                                Box::new(drivers::keyboard::Keyboard::new(irq_handler_cap)),
                            );
                        }
                    }
                } else {
                    println!("[KERNEL] Failed to mint KB notification badge: {:?}", err);
                }
            }

            // 2. Configure Timer (Badge 2)
            if timer_irq_cap != 0 {
                let timer_badge_cap = slot_allocator.alloc().unwrap();
                let root_cnode =
                    sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                let cnode_depth = sel4_sys::seL4_WordBits as u8;

                let err = unsafe {
                    sel4_sys::seL4_CNode_Mint(
                        root_cnode,
                        timer_badge_cap,
                        cnode_depth,
                        root_cnode,
                        notification_cap,
                        cnode_depth,
                        cap_rights_new(false, true, true, true),
                        2, // Badge 2
                    )
                };

                if err == 0.into() {
                    if let Err(e) = ioapic::set_irq_handler(timer_irq_cap, timer_badge_cap as usize)
                    {
                        println!("[KERNEL] Failed to SetTimerIRQHandler: {}", e);
                    } else {
                        if let Err(e) = ioapic::ack_irq(timer_irq_cap) {
                            println!("[KERNEL] Failed to Ack Timer IRQ: {}", e);
                        } else {
                            println!("[KERNEL] Timer IRQ Configured.");
                            driver_manager.register_irq_driver(
                                2,
                                Box::new(drivers::timer::TimerDriver::new(timer_irq_cap)),
                            );
                        }
                    }
                } else {
                    println!(
                        "[KERNEL] Failed to mint Timer notification badge: {:?}",
                        err
                    );
                }
            }

            // 3. Configure Serial (Badge 4)
            if serial_irq_cap != 0 {
                let serial_badge_cap = slot_allocator.alloc().unwrap();
                let root_cnode =
                    sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                let cnode_depth = sel4_sys::seL4_WordBits as u8;

                let err = unsafe {
                    sel4_sys::seL4_CNode_Mint(
                        root_cnode,
                        serial_badge_cap,
                        cnode_depth,
                        root_cnode,
                        notification_cap,
                        cnode_depth,
                        cap_rights_new(false, true, true, true),
                        4, // Badge 4
                    )
                };

                if err == 0.into() {
                    if let Err(e) =
                        ioapic::set_irq_handler(serial_irq_cap, serial_badge_cap as usize)
                    {
                        println!("[KERNEL] Failed to SetSerialIRQHandler: {}", e);
                    } else {
                        if let Err(e) = ioapic::ack_irq(serial_irq_cap) {
                            println!("[KERNEL] Failed to Ack Serial IRQ: {}", e);
                        } else {
                            println!("[KERNEL] Serial IRQ Configured.");
                            // Driver is registered in main loop setup, but we should probably move
                            // it here or ensure consistency.
                            // Actually, let's keep registration here to be consistent with others.
                            // But wait, I already have registration code later:
                            // driver_manager.register_irq_driver(4,
                            // Box::new(drivers::serial::SerialDriver::new(0x3F8)));
                            // Duplicate registration might be fine if BTreeMap overwrites, but
                            // let's avoid it. I will remove the later
                            // registration and put it here.
                            driver_manager.register_irq_driver(
                                4,
                                Box::new(drivers::serial::SerialDriver::new(0x3F8, serial_irq_cap)),
                            );
                        }
                    }
                } else {
                    println!(
                        "[KERNEL] Failed to mint Serial notification badge: {:?}",
                        err
                    );
                }
            }

            // 4. Register RTC Driver (Badge 8) - No IRQ yet
            driver_manager.register_irq_driver(8, Box::new(drivers::rtc::RtcDriver::new()));
        }
        Err(e) => println!("[KERNEL] Failed to allocate Notification: {:?}", e),
    }

    // 6. Unified Event Loop
    println!("[KERNEL] Entering Unified Event Loop...");

    // Run Disk Driver Test (Temporary Verification)
    crate::tests::test_disk_driver();

    // Disable Legacy PIC (Mask all) to prevent interference with IOAPIC
    port_io::outb(0x21, 0xFF);
    port_io::outb(0xA1, 0xFF);
    println!("[KERNEL] Legacy PIC Masked.");

    // Initialize PIT for 100Hz Timer
    port_io::outb(0x43, 0x34);
    let divisor = 11931; // 100Hz
    port_io::outb(0x40, (divisor & 0xFF) as u8);
    port_io::outb(0x40, (divisor >> 8) as u8);
    println!("[KERNEL] PIT Initialized (100Hz)");

    let ipc_buf = unsafe { sel4_sys::seL4_GetIPCBuffer() };
    println!("[KERNEL] RootServer IPC Buffer: {:p}", ipc_buf);

    driver_manager.init_all();

    // Initialize Shell (prints prompt)
    shell.init(
        boot_info,
        &mut allocator,
        &mut slot_allocator,
        &mut frame_allocator,
        syscall_ep_cap,
    );

    let syscall_ep = Endpoint::new(syscall_ep_cap);

    // Allocate slot for receiving caps during syscalls
    let syscall_recv_slot = slot_allocator
        .alloc()
        .expect("Failed to alloc syscall recv slot");
    let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
    let cnode_depth = sel4_sys::seL4_WordBits;

    // Set receive path
    libnova::ipc::set_cap_receive_path(root_cnode, syscall_recv_slot, cnode_depth.into());

    let mut reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 0);
    let mut need_reply = false;
    let mut manual_reply = false;
    let mut reply_mrs = [0u64; 4];

    loop {
        let (info, badge, mrs) = if need_reply {
            if manual_reply {
                // Manually set MR0, preserve other MRs (set by syscall handler)
                libnova::ipc::set_mr(0, reply_mrs[0]);

                // Sync MR1-MR3 from IPC buffer if message length requires it.
                // sys_read writes data to IPC buffer (msg[1..]), but seL4 expects MR1-MR3 in
                // registers.
                let len = reply_info.length() as usize;
                if len > 1 {
                    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };
                    if len > 1 {
                        libnova::ipc::set_mr(1, ipc_buf.msg[1]);
                    }
                    if len > 2 {
                        libnova::ipc::set_mr(2, ipc_buf.msg[2]);
                    }
                    if len > 3 {
                        libnova::ipc::set_mr(3, ipc_buf.msg[3]);
                    }
                }

                let (badge, info) = libnova::ipc::reply_recv(syscall_ep.cptr, reply_info)
                    .expect("IPC ReplyRecv failed");

                let mr0 = libnova::ipc::get_mr(0);
                let mr1 = libnova::ipc::get_mr(1);
                let mr2 = libnova::ipc::get_mr(2);
                let mr3 = libnova::ipc::get_mr(3);

                (
                    info,
                    badge,
                    [mr0.into(), mr1.into(), mr2.into(), mr3.into()],
                )
            } else {
                syscall_ep.reply_recv_with_mrs(reply_info, reply_mrs)
            }
        } else {
            syscall_ep.recv_with_mrs()
        };

        // Reset reply flags
        need_reply = false;
        manual_reply = false;

        if badge == 999 {
            // Worker Thread Interrupt Forwarding
            let irq_badge = mrs[0] as seL4_Word;

            let events = driver_manager.handle_interrupt(irq_badge);
            for event in events {
                match event {
                    drivers::DriverEvent::KeyboardInput(k) => shell.on_key(k),
                    drivers::DriverEvent::SerialInput(byte) => {
                        // Serial to Key mapping
                        let key = match byte {
                            b'\r' => Some(drivers::keyboard::Key::Enter),
                            b'\n' => None,
                            b'\x08' | 0x7F => Some(drivers::keyboard::Key::Backspace),
                            b'\t' => Some(drivers::keyboard::Key::Tab),
                            0x1B => Some(drivers::keyboard::Key::Esc),
                            c if c >= 32 && c <= 126 => {
                                Some(drivers::keyboard::Key::Char(c as char))
                            }
                            _ => None,
                        };

                        if let Some(k) = key {
                            shell.on_key(k);
                        }
                    }
                    drivers::DriverEvent::Tick => {
                        system_tick += 1;

                        // Wake up sleeping processes
                        let mut pm = get_process_manager();
                        for pid in 0..crate::process::MAX_PROCESSES {
                            if let Some(p) = pm.get_process_mut(pid) {
                                if p.state == process::ProcessState::Sleeping
                                    && system_tick >= p.wake_at_tick
                                {
                                    p.state = process::ProcessState::Running;
                                    let wake_msg = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                                    libnova::ipc::set_mr(0, 0);
                                    libnova::ipc::send(p.saved_reply_cap, wake_msg);
                                }
                            }
                        }
                    }
                }
            }

            // Reply to Worker to unblock it for next IRQ
            need_reply = true;
            reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 0);
            continue;
        }

        if badge < 100 {
            // Legacy/Unused
        } else if badge >= 100 {
            let pid = (badge - 100) as usize;
            // Syscall from Process
            let label = info.label();

            match SyscallNum::from_u64(label) {
                Some(SyscallNum::Print) => {
                    // sys_print
                    let len = info.length(); // u64
                    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };
                    let msg_len = ipc_buf.msg.len() as u64;
                    let safe_len = if len > msg_len { msg_len } else { len };
                    for i in 0..safe_len {
                        let word = if i < 4 {
                            mrs[i as usize]
                        } else {
                            ipc_buf.msg[i as usize]
                        };
                        let bytes = word.to_le_bytes();
                        for b in bytes {
                            if b != 0 {
                                print!("{}", b as char);
                            }
                        }
                    }
                    reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 0);
                    need_reply = true;
                }
                Some(SyscallNum::Exit) => {
                    // sys_exit
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    handlers::core::handle_exit(&mut ctx);
                    need_reply = false;
                }
                Some(SyscallNum::Brk) => {
                    // sys_brk
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) = handlers::core::handle_brk(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::Yield) => {
                    // sys_yield
                    let (info, mrs) = handlers::core::handle_yield();
                    reply_info = info;
                    reply_mrs = mrs;
                    need_reply = true;
                }
                Some(SyscallNum::WaitPid) => {
                    // sys_waitpid(pid, options) -> (pid, status)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) = handlers::core::handle_wait(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::Spawn) => {
                    // sys_spawn(path, args, envs)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) = handlers::core::handle_spawn(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::Fork) => {
                    // sys_fork() -> pid
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) = handlers::core::handle_fork(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::GetPid) => {
                    // sys_get_pid() -> pid
                    let (info, mrs) = handlers::core::handle_get_pid(pid);
                    reply_info = info;
                    reply_mrs = mrs;
                    need_reply = true;
                }
                Some(SyscallNum::Kill) => {
                    // sys_kill(pid, sig)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) = handlers::core::handle_kill(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::Write) => {
                    // sys_write(fd, len, data...) -> bytes_written
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply, _r_manual) = handlers::fs::handle_write(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::Close) => {
                    // sys_close(fd)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply, _r_manual) = handlers::fs::handle_close(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::Open) => {
                    // sys_open(path, mode) -> fd
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply, r_manual) = handlers::fs::handle_open(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                    manual_reply = r_manual;
                }
                Some(SyscallNum::Read) => {
                    // sys_read(fd, len) -> bytes_read
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply, r_manual) = handlers::fs::handle_read(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                    manual_reply = r_manual;
                }
                Some(SyscallNum::GetUid) => {
                    // sys_getuid()
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) = handlers::metadata::handle_getuid(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::SetUid) => {
                    // sys_setuid(uid)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) = handlers::metadata::handle_setuid(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::GetGid) => {
                    // sys_getgid()
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) = handlers::metadata::handle_getgid(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::SetGid) => {
                    // sys_setgid(gid)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) = handlers::metadata::handle_setgid(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::Chmod) => {
                    // sys_chmod(path, mode)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply, _r_manual) = handlers::fs::handle_chmod(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::Chown) => {
                    // sys_chown(path, uid, gid)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply, _r_manual) = handlers::fs::handle_chown(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::Symlink) => {
                    // sys_symlink(target, linkpath)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply, _r_manual) =
                        handlers::fs::handle_symlink(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::Readlink) => {
                    // sys_readlink(path, buf_len)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply, r_manual) =
                        handlers::fs::handle_readlink(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                    manual_reply = r_manual;
                }
                Some(SyscallNum::Mkdir) => {
                    // sys_mkdir(path)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply, _r_manual) = handlers::fs::handle_mkdir(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::Rmdir) => {
                    // sys_rmdir(path)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply, _r_manual) = handlers::fs::handle_rmdir(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::Unlink) => {
                    // sys_unlink(path)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply, _r_manual) = handlers::fs::handle_unlink(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::Rename) => {
                    // sys_rename(old_path, new_path)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply, _r_manual) = handlers::fs::handle_rename(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::Link) => {
                    // sys_link(target_path, link_path)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply, _r_manual) = handlers::fs::handle_link(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::BlockRead) => {
                    // sys_block_read(block_id) -> (bytes_read, data...)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply, r_manual) =
                        handlers::fs::handle_block_read(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                    manual_reply = r_manual;
                }
                Some(SyscallNum::BlockWrite) => {
                    // sys_block_write(block_id, 512-byte block)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply, _r_manual) =
                        handlers::fs::handle_block_write(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::BlockInfo) => {
                    // sys_block_info() -> (sector_count, is_rotational)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply, _r_manual) =
                        handlers::fs::handle_block_info(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::GetUnixTime) => {
                    // sys_get_unix_time() -> unix_timestamp
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) =
                        handlers::service::handle_get_unix_time(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::ServiceSetReady) => {
                    // sys_service_set_ready (MR0=len, MR1..=name)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) =
                        handlers::service::handle_service_set_ready(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::FsViewEpoch) => {
                    // sys_fs_view_epoch() -> current epoch
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) =
                        handlers::service::handle_fs_view_epoch(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::Shutdown) => {
                    // sys_shutdown
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    handlers::service::handle_shutdown(&mut ctx);
                }
                Some(SyscallNum::VmFault) => {
                    // seL4_Fault_VMFault
                    let fault_addr = mrs[1] as usize;
                    let ip = mrs[0] as usize;
                    let is_prefetch = mrs[2] == 1;

                    const DEMAND_PAGING_START: usize = 0x4000_0000;
                    const DEMAND_PAGING_END: usize = 0x7000_0000;

                    if fault_addr >= DEMAND_PAGING_START && fault_addr < DEMAND_PAGING_END {
                        let aligned_addr = fault_addr & !0xFFF; // Align to 4K
                        log_debug!(
                            libnova::log::DOM_PAGING,
                            "[KERNEL] Demand Paging(pid={}): Mapping 0x{:x} (IP: 0x{:x}, Prefetch: {}) for fault at 0x{:x}",
                            pid,
                            aligned_addr,
                            ip,
                            is_prefetch,
                            fault_addr
                        );

                        if let Some(p) = get_process_manager().get_process_mut(pid) {
                            // Allocate frame
                            if let Ok((frame_cap, recycled)) = frame_allocator.alloc(
                                &mut allocator,
                                boot_info,
                                &mut slot_allocator,
                            ) {
                                if recycled {
                                    if let Err(e) = process::clear_frame(
                                        &mut allocator,
                                        &mut slot_allocator,
                                        boot_info,
                                        frame_cap,
                                    ) {
                                        println!("[KERNEL] Failed to zero recycled frame: {:?}", e);
                                        let cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                                        unsafe {
                                            let _ = (*addr_of_mut!(SHARED_MEMORY_MANAGER))
                                                .detach_process(pid, &mut slot_allocator);
                                        }
                                        let _ = p.terminate(
                                            cnode,
                                            &mut slot_allocator,
                                            &mut frame_allocator,
                                        );
                                        get_process_manager().remove_process(pid);
                                        // need_reply = false;
                                        // Continue to next loop iteration? No,
                                        // this is inside VMFault handler.
                                        // We set need_reply=false, so we just
                                        // break out of this case.
                                    }
                                }

                                // Map it
                                let rights = cap_rights_new(false, true, true, true);
                                let attr =
                                    sel4_sys::seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes;
                                if let Ok(_) = p.vspace.map_page(
                                    &mut allocator,
                                    &mut slot_allocator,
                                    boot_info,
                                    frame_cap,
                                    aligned_addr,
                                    rights,
                                    attr,
                                ) {
                                    let _ = p.track_frame(frame_cap, aligned_addr, rights, attr);
                                    reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 0);
                                    need_reply = true;
                                } else {
                                    println!("[KERNEL] Failed to map page.");
                                    let cnode =
                                        sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode
                                            as seL4_CPtr;
                                    unsafe {
                                        let _ = (*addr_of_mut!(SHARED_MEMORY_MANAGER))
                                            .detach_process(pid, &mut slot_allocator);
                                    }
                                    let _ = p.terminate(
                                        cnode,
                                        &mut slot_allocator,
                                        &mut frame_allocator,
                                    );
                                    get_process_manager().remove_process(pid);
                                    need_reply = false;
                                }
                            } else {
                                println!("[KERNEL] Failed to allocate frame.");
                                let cnode =
                                    sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode
                                        as seL4_CPtr;
                                unsafe {
                                    let _ = (*addr_of_mut!(SHARED_MEMORY_MANAGER))
                                        .detach_process(pid, &mut slot_allocator);
                                }
                                let _ =
                                    p.terminate(cnode, &mut slot_allocator, &mut frame_allocator);
                                get_process_manager().remove_process(pid);
                                need_reply = false;
                            }
                        } else {
                            println!("[KERNEL] Process {} not found for VMFault", pid);
                            need_reply = false;
                        }
                    } else {
                        println!(
                            "[KERNEL] Unhandled VM Fault at 0x{:x} (IP: 0x{:x}). Terminating.",
                            fault_addr, ip
                        );
                        if let Some(p) = get_process_manager().get_process_mut(pid) {
                            let cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode
                                as seL4_CPtr;
                            unsafe {
                                let _ = (*addr_of_mut!(SHARED_MEMORY_MANAGER))
                                    .detach_process(pid, &mut slot_allocator);
                            }
                            let _ = p.terminate(cnode, &mut slot_allocator, &mut frame_allocator);
                        }
                        get_process_manager().remove_process(pid);
                        need_reply = false;
                    }
                }
                Some(SyscallNum::GetTime) => {
                    // sys_get_time
                    let (r_info, r_mrs, r_reply) = handlers::service::handle_get_time(system_tick);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::Sleep) => {
                    // sys_sleep (MR0 = ticks)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    match handlers::core::handle_sleep(&mut ctx, system_tick) {
                        Ok((info, mrs, reply_now)) => {
                            reply_info = info;
                            reply_mrs = mrs;
                            need_reply = reply_now;
                        }
                        Err(e) => {
                            println!("[KERNEL] sys_sleep failed for pid {}: {}", pid, e);
                            reply_mrs[0] = 0;
                            reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                            need_reply = true;
                        }
                    }
                }
                Some(SyscallNum::ShmAlloc) => {
                    // sys_shm_alloc(size)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) = handlers::core::handle_shm_alloc(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::ShmMap) => {
                    // sys_shm_map(key, vaddr)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) = handlers::core::handle_shm_map(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::MmapShared) => {
                    // sys_mmap_shared(size) -> vaddr(0 on error)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) = handlers::core::handle_mmap_shared(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::MunmapShared) => {
                    // sys_munmap_shared(vaddr, size) -> 0 on success
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) = handlers::core::handle_munmap_shared(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::ServiceRegister) => {
                    // sys_service_register (MR0=len, MR1..=name, ExtraCap=service)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) =
                        handlers::service::handle_service_register(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }
                Some(SyscallNum::ServiceLookup) => {
                    // sys_service_lookup (MR0=len, MR1..=name)
                    let mut ctx = handlers::SyscallContext {
                        pid,
                        info: &info,
                        mrs: &mrs,
                        boot_info,
                        syscall_ep_cap,
                        fs_service_ep_cap,
                        test_service_slot,
                        syscall_recv_slot,
                        slot_allocator: &mut slot_allocator,
                        allocator: &mut allocator,
                        frame_allocator: &mut frame_allocator,
                        ata: &ata,
                        shell: &mut shell,
                        deferred_services_spawned: &mut deferred_services_spawned,
                    };
                    let (r_info, r_mrs, r_reply) =
                        handlers::service::handle_service_lookup(&mut ctx);
                    reply_info = r_info;
                    reply_mrs = r_mrs;
                    need_reply = r_reply;
                }

                Some(SyscallNum::Send) => {
                    // sys_send (MR0=TargetPID, MR1..3=Msg)
                    let target_pid = mrs[0] as usize;
                    let msg_content = [mrs[1], mrs[2], mrs[3], 0];

                    if let Some(target_p) = get_process_manager().get_process_mut(target_pid) {
                        if target_p.state == process::ProcessState::BlockedOnRecv {
                            // Target is waiting, wake it up directly with data
                            target_p.state = process::ProcessState::Running;
                            let reply_msg = libnova::ipc::MessageInfo::new(0, 0, 0, 4);
                            let reply_data =
                                [pid as u64, msg_content[0], msg_content[1], msg_content[2]];

                            libnova::ipc::set_mr(0, reply_data[0].try_into().unwrap());
                            libnova::ipc::set_mr(1, reply_data[1].try_into().unwrap());
                            libnova::ipc::set_mr(2, reply_data[2].try_into().unwrap());
                            libnova::ipc::set_mr(3, reply_data[3].try_into().unwrap());
                            libnova::ipc::send(target_p.saved_reply_cap, reply_msg);

                            // Reply to sender: Success
                            reply_mrs[0] = 0; // Success
                            reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                            need_reply = true;
                        } else {
                            // Target not waiting, store in mailbox
                            target_p.mailbox = Some(process::IpcMessage {
                                sender_pid: pid,
                                content: msg_content,
                                len: 3,
                            });
                            // Reply to sender: Success
                            reply_mrs[0] = 0; // Success
                            reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                            need_reply = true;
                        }
                    } else {
                        // Target not found
                        reply_mrs[0] = 1; // Error
                        reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                        need_reply = true;
                    }
                }

                _ => {
                    println!("[INFO] Unknown syscall label: {}. Badge: {}", label, badge);
                    need_reply = true;
                }
            }
        } else {
            println!("[KERNEL] Unexpected badge: {}", badge);
        }
    }
}

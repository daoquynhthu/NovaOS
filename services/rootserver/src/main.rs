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

use crate::vfs::FileSystem;

mod runtime;
mod memory;
mod allocator;
mod vspace;
mod process;
mod ipc;
mod elf_loader;
mod tests;
mod arch;
mod drivers;
mod shell;
mod filesystem;
mod shared_memory;
mod vfs;
mod fs;
mod services;

use alloc::boxed::Box;
use sel4_sys::{
    seL4_BootInfo, seL4_CPtr, seL4_Word,
};
use libnova::cap::cap_rights_new;
// Temporary constant until we confirm sel4_sys export
#[allow(dead_code, non_upper_case_globals)]
const seL4_X86_4K: seL4_Word = 8;

use crate::arch::{port_io, ioapic, acpi, serial};

use core::arch::global_asm;
use memory::{SlotAllocator, UntypedAllocator, ObjectAllocator, FrameAllocator};
use crate::process::{Process, get_process_manager};
use crate::ipc::Endpoint;
use crate::shared_memory::SharedMemoryManager;

use core::ptr::addr_of_mut;

static mut SHARED_MEMORY_MANAGER: SharedMemoryManager = SharedMemoryManager::new();

static mut WORKER_STACK: [u8; 4096] = [0; 4096];

extern "C" fn irq_worker_entry(notification: usize, endpoint: usize) {
    serial::send_char('[');
    serial::send_char('W');
    serial::send_char(']');
    serial::send_char('\n');
    println!("[WORKER] Thread started. Notification: {}, Endpoint: {}", notification, endpoint);

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
    .space 65536 /* 64KB stack */
    .global stack_top
    stack_top:
    "#,
    options(att_syntax)
);

/// RootServer 的 Rust 入口点
/// 由汇编 _start 调用
/// 
/// # Safety
/// This function is the entry point called by assembly. The `boot_info_ptr` must be a valid pointer
/// to `seL4_BootInfo` provided by the kernel/bootloader.
#[no_mangle]
pub unsafe extern "C" fn rust_main(boot_info_ptr: *const seL4_BootInfo) -> ! {
    // 初始化运行时（例如堆分配器，如果需要）
    println!("[KERNEL] RootServer Started.");
    allocator::init_heap();
    println!("[KERNEL] Heap Initialized (1MB).");
    
    // 1. Get BootInfo
    if boot_info_ptr.is_null() {
        // We can't print safely yet, so just hang or rely on DebugPutChar if we had it separately.
        // panic!("Failed to get BootInfo! System halted."); 
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
    let io_port_slot = slot_allocator.alloc().expect("Failed to allocate slot for IO Port Cap");

    // 2. Issue IO Port Cap directly into Root CNode
    // Extra Cap: Root CNode (Cap 2)
    // We need to provide the CPtr to the Root CNode so the kernel can look it up.
    let root_cnode_cptr = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as u64;

    match port_io::issue_ioport_cap(
        (sel4_sys::seL4_RootCNodeCapSlots::seL4_CapIOPortControl as u64).try_into().unwrap(),
        0x0000,
        0xFFFF,
        root_cnode_cptr.try_into().unwrap(),   // Extra Cap: Root CNode
        io_port_slot, // Slot in Root CNode
        (sel4_sys::seL4_WordBits as u64).try_into().unwrap(),
    ) {
        Ok(_) => {
            println!("IO Port Capability issued successfully to Root CNode.");
        },
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
    
    match crate::fs::novafs::NovaFS::new(ata.clone(), 0) {
        Ok(fs) => {
             *crate::fs::DISK_FS.lock() = Some(alloc::sync::Arc::new(fs.clone()));
             if fs.root_inode().lookup("bin").is_err() {
                 println!("[KERNEL] /bin not found.");
                 need_format = true;
             }
        },
        Err(e) => {
             println!("[KERNEL] Mount failed: {}. Will format.", e);
             need_format = true;
        }
    }

    if need_format {
         println!("[KERNEL] Disk uninitialized or system missing. Formatting...");
         // Use detected size if valid, else default 5MB
         let format_size = if disk_size_sectors > 0 { disk_size_sectors } else { 1024 * 10 };
         let fs_new = crate::fs::novafs::NovaFS::format(ata.clone(), 0, format_size); 
         *crate::fs::DISK_FS.lock() = Some(alloc::sync::Arc::new(fs_new.clone()));
         
         if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
             let root = fs.root_inode();
             println!("[KERNEL] Creating /bin...");
             let bin = root.create("bin", crate::vfs::FileType::Directory).expect("Failed to create /bin");
             
             println!("[KERNEL] Installing system binaries...");
             for file in filesystem::FILES {
                 println!("[KERNEL] Installing: {}", file.name);
                 let inode = bin.create(file.name, crate::vfs::FileType::File).expect("Failed to create file");
                 println!("[KERNEL] Writing data for: {}", file.name);
                 inode.write_at(0, file.data).expect("Failed to write data");
                 println!("  - Installed: {}", file.name);
             }
             
             // Create README
             println!("[KERNEL] Creating README.TXT...");
             let readme = root.create("README.TXT", crate::vfs::FileType::File).unwrap();
             println!("[KERNEL] Writing README.TXT...");
             readme.write_at(0, b"Welcome to NovaOS (Persistent Mode)!").unwrap();
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
    println!("[INFO] Empty Slots: {} - {}", boot_info.empty.start, boot_info.empty.end);
    println!("[INFO] Untyped Slots: {} - {}", boot_info.untyped.start, boot_info.untyped.end);
    
    println!("[INFO] Untyped Memory: {} slots",  
             boot_info.untyped.end - boot_info.untyped.start);
    println!("[INFO] CNode Size: {} bits", boot_info.initThreadCNodeSizeBits);

    allocator.print_info(boot_info);

    let mut irq_handler_cap: usize = 0;
    let mut timer_irq_cap: usize = 0;
    let mut serial_irq_cap: usize = 0;

    // Initialize ACPI
    let mut acpi_context = acpi::AcpiContext::new();

    if let Some(acpi_info) = acpi::init(boot_info) {
        println!("[INFO] ACPI Info found. Mapping RSDT...");
        match acpi::map_rsdt(boot_info, &acpi_info, &mut allocator, &mut slot_allocator, &mut acpi_context) {
            Ok(rsdt_ptr) => {
                let rsdt = unsafe { &*rsdt_ptr };
                if let Ok(sig) = core::str::from_utf8(&rsdt.header.signature) {
                    let len = rsdt.header.length;
                    let checksum = rsdt.header.checksum;
                    let oem_id_slice = rsdt.header.oem_id;
                    println!("[ACPI] RSDT Mapped at {:p}, Signature: {}", rsdt_ptr, sig);
                    println!("[ACPI] RSDT Length: {}", len);
                    println!("[ACPI] RSDT Checksum: {}", checksum);
                    println!("[ACPI] RSDT OEM ID: {:?}", core::str::from_utf8(&oem_id_slice).unwrap_or("Unknown"));
                    
                    // Iterate RSDT Entries
                    let header_size = core::mem::size_of::<crate::arch::acpi::AcpiTableHeader>();
                    let entries_count = (len as usize - header_size) / 4;
                    println!("[ACPI] Scanning {} RSDT entries...", entries_count);
                    
                    let entry_start = (rsdt_ptr as usize + header_size) as *const u32;
                    for i in 0..entries_count {
                        let table_paddr = unsafe { *entry_start.add(i) } as usize;
                        
                        // Map table to check signature
                        let vaddr_base = 0x8001_0000 + (i * 0x10000); // 64KB spacing to be safe
                        
                        match crate::arch::acpi::map_phys(boot_info, table_paddr, vaddr_base, &mut allocator, &mut slot_allocator, &mut acpi_context) {
                            Ok(ptr_val) => {
                                let header = unsafe { &*(ptr_val as *const crate::arch::acpi::AcpiTableHeader) };
                                 if let Ok(sig) = core::str::from_utf8(&header.signature) {
                                     println!("[ACPI] Table [{}] Signature: {}", i, sig);
                                    if sig == "APIC" {
                                         println!("[ACPI] Found MADT (APIC) Table!");
                                         // Check length and map remaining pages if needed
                                         let length = header.length as usize;
                                         if length > 4096 {
                                             let pages_needed = length.div_ceil(4096);
                                             println!("[ACPI] MADT size {} bytes, mapping {} extra pages...", length, pages_needed - 1);
                                             for p in 1..pages_needed {
                                                 let p_paddr = table_paddr + p * 4096;
                                                 if let Err(e) = crate::arch::acpi::map_phys(boot_info, p_paddr, 0, &mut allocator, &mut slot_allocator, &mut acpi_context) {
                                                     println!("[ACPI] Failed to map extra page for MADT: {:?}", e);
                                                 }

                                             }
                                         }
                                         
                                         let madt = unsafe { &*(ptr_val as *const crate::arch::acpi::Madt) };
                                         let local_apic = madt.local_apic_address;
                                         let flags = madt.flags;
                                         println!("[ACPI] Local APIC Address: 0x{:x}", local_apic);
                                         println!("[ACPI] MADT Flags: 0x{:x}", flags);
                                         
                                         // Parse MADT records
                                         crate::arch::acpi::walk_madt(madt);
                                         
                                         // Initialize Local APIC
                                         if let Some(_apic) = crate::arch::apic::init(boot_info, local_apic as usize, &mut allocator, &mut slot_allocator, &mut acpi_context) {
                                             println!("[KERNEL] Local APIC Initialized.");
                                         } else {
                                             println!("[KERNEL] Local APIC init skipped (using default configuration).");
                                         }

                                         // Initialize IO APIC
                                         if let Some(ioapic_info) = crate::arch::acpi::find_first_ioapic(madt) {
                                             println!("[KERNEL] Found IOAPIC at 0x{:x} (ID: {}).", ioapic_info.address, ioapic_info.id);
                                             
                                             let irq_control_cap = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapIRQControl as usize;
                                            let root_cnode_cap = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as usize;
                                            let depth = sel4_sys::seL4_WordBits as usize;

                                            // 1. Keyboard IRQ (IRQ 1)
                                            if let Ok(irq_slot) = slot_allocator.alloc() {
                                               let irq = 1;
                                               // Check for ISO
                                               let (gsi, level, polarity) = if let Some(iso) = crate::arch::acpi::find_iso_for_irq(madt, irq) {
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
                                               
                                               println!("[KERNEL] Config Keyboard IRQ {} -> GSI {}", irq, gsi);

                                               let pin = gsi;
                                               let ioapic_idx = 0; 
                                               let vector = 33; // 0x21
                                               
                                               let err = crate::arch::ioapic::get_ioapic_handler(
                                                       irq_control_cap, ioapic_idx as usize, pin as usize, level, polarity,
                                                       root_cnode_cap, irq_slot.try_into().unwrap(), depth, vector
                                                   );
                                                if err.is_ok() {
                                                    println!("[KERNEL] IRQ Handler for Keyboard created.");
                                                    
                                                    irq_handler_cap = irq_slot as usize;

                                                }
                                             }


                                             // 2. Timer IRQ (IRQ 0)
                                             if let Ok(irq_slot) = slot_allocator.alloc() {
                                                let irq = 0;
                                                // Check for ISO (usually GSI 2)
                                                 // Default: GSI 0, Edge (0), High (0) if no ISO.
                                                 // If ISO exists: Use ISO GSI and Flags.
                                                 // ACPI Flags: Polarity (0=Bus, 1=High, 3=Low), Trigger (0=Bus, 1=Edge, 3=Level)
                                                 // seL4: Polarity (0=High, 1=Low), Level (0=Edge, 1=Level)
                                                 
                                                 let (gsi, level, polarity) = if let Some(iso) = crate::arch::acpi::find_iso_for_irq(madt, irq) {
                                                    let iso_gsi = iso.gsi;
                                                    let iso_flags = iso.flags;
                                                    println!("[KERNEL] Found ISO for IRQ 0: GSI={}, Flags=0x{:x}", iso_gsi, iso_flags);
                                                    let p_flag = iso_flags & 0x3;
                                                    let t_flag = (iso_flags >> 2) & 0x3;
                                                    
                                                    let pol = if p_flag == 3 { 1 } else { 0 }; // 3=Low -> 1
                                                    let lev = if t_flag == 3 { 1 } else { 0 }; // 3=Level -> 1
                                                    
                                                    (iso_gsi as usize, lev, pol)
                                                } else {
                                                   // QEMU Default: IRQ 0 is often overridden to GSI 2, but if no ISO, assume legacy.
                                                   // Actually, on QEMU, IRQ 0 is GSI 2.
                                                   // If find_iso_for_irq returns None, we might be in trouble if it IS GSI 2.
                                                   // But find_iso_for_irq SHOULD find it on QEMU.
                                                   println!("[KERNEL] No ISO for IRQ 0. Assuming GSI 2 (Legacy override).");
                                                   (2, 0, 0)
                                               };

                                               println!("[KERNEL] Config Timer IRQ {} -> GSI {}, Level {}, Polarity {}", irq, gsi, level, polarity);

                                               let pin = gsi;
                                               let ioapic_idx = 0;
                                               let vector = 40; // 0x28
                                               
                                               let err = crate::arch::ioapic::get_ioapic_handler(
                                                   irq_control_cap, ioapic_idx as usize, pin as usize, level, polarity,
                                                   root_cnode_cap, irq_slot.try_into().unwrap(), depth, vector
                                               );

                                                if err.is_ok() {
                                                    timer_irq_cap = irq_slot as usize;
                                                    println!("[KERNEL] Timer IRQ Handler obtained.");
                                                } else {
                                                    println!("[KERNEL] Failed to get Timer IRQ Handler.");
                                                }
                                             }

                                             // 3. Serial Port IRQ (IRQ 4 / COM1)
                                             if let Ok(irq_slot) = slot_allocator.alloc() {
                                                let irq = 4;
                                                let (gsi, level, polarity) = if let Some(iso) = crate::arch::acpi::find_iso_for_irq(madt, irq) {
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
                                                
                                                println!("[KERNEL] Config Serial IRQ {} -> GSI {}", irq, gsi);

                                                let pin = gsi;
                                                let ioapic_idx = 0; 
                                                let vector = 52; 
                                                
                                                let err = crate::arch::ioapic::get_ioapic_handler(
                                                        irq_control_cap, ioapic_idx as usize, pin as usize, level, polarity,
                                                        root_cnode_cap, irq_slot.try_into().unwrap(), depth, vector
                                                    );
                                                 if err.is_ok() {
                                                     serial_irq_cap = irq_slot as usize;
                                                     println!("[KERNEL] Serial IRQ Handler obtained.");
                                                 } else {
                                                     println!("[KERNEL] Failed to get Serial IRQ Handler.");
                                                 }
                                             }
                                             
                                         } else {
                                             println!("[KERNEL] No IOAPIC found in MADT.");
                                         }
                                     } else if sig == "FACP" {
                                        println!("[ACPI] Found FADT Table!");
                                        let fadt = unsafe { &*(ptr_val as *const acpi::Fadt) };
                                        acpi::set_fadt(fadt);
                                        acpi::enable_acpi(fadt);
                                     }
                                }
                            },
                            Err(e) => {
                                println!("[ACPI] Failed to map table at 0x{:x}: {:?}", table_paddr, e);
                            }
                        }
                    }

                 } else {
                    println!("[ACPI] RSDT Mapped but signature invalid");
                }
            },
            Err(e) => {
                println!("[ACPI] Failed to map RSDT: {:?}", e);
            }
        }
    }

    // 3. System Self-Test (POST)
    println!("[KERNEL] Performing Power-On Self-Test (POST)...");
    tests::run_all(boot_info, &mut allocator, &mut slot_allocator, &mut frame_allocator);
    println!("[KERNEL] POST Completed Successfully.");

    // 4. Initialize Syscall Endpoint and Processes
    println!("[KERNEL] Initializing Process Manager...");
    
    // Allocate Syscall Endpoint
    let syscall_ep_cap = allocator.allocate(boot_info, sel4_sys::api_object_seL4_EndpointObject.into(), sel4_sys::seL4_EndpointBits.into(), &mut slot_allocator).expect("Failed to alloc EP");
    
    // Initialize Service Registry
    services::init();
    
    // Create and Register "test" service (Badge 200)
    let test_service_slot = slot_allocator.alloc().expect("Failed to alloc slot for test service");
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
            200 // Badge 200 for Test Service
        )
    };
    if err != 0.into() {
        println!("[KERNEL] Failed to mint test service endpoint: {:?}", err);
    } else {
        services::register("test", test_service_slot);
        println!("[KERNEL] Service 'test' registered (Badge 200).");
    }

    // Mint Badged Endpoint for Process 1
    let badged_ep_slot = slot_allocator.alloc().expect("Failed to alloc slot for badged EP");
    let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
    let cnode_depth = sel4_sys::seL4_WordBits; 
    
    let err = unsafe {
        sel4_sys::seL4_CNode_Mint(
            root_cnode,
            badged_ep_slot,
            cnode_depth as u8,
            root_cnode,
            syscall_ep_cap,
            cnode_depth as u8,
            cap_rights_new(false, true, true, true),
            100 // Badge for Process 1
        )
    };
    if err != 0.into() {
        println!("[KERNEL] Failed to mint badged endpoint: {:?}", err);
    }
    
    // Spawn Hello Process
    println!("[KERNEL] Spawning Hello Process...");
    let hello_elf = crate::filesystem::get_file("hello").expect("hello binary not found");
    let process = Process::spawn(
        &mut allocator,
        &mut slot_allocator,
        &mut frame_allocator,
        boot_info,
        hello_elf,
        &[],
        100, // Priority
        badged_ep_slot // Give badged cap
    ).expect("Failed to spawn process");
    
    get_process_manager().add_process(process).expect("Failed to add process");

    // Spawn Hello Process 2
    println!("[KERNEL] Spawning Hello Process 2...");
    let badged_ep_slot_2 = slot_allocator.alloc().expect("Failed to alloc slot for badged EP 2");
    
    let err = unsafe {
        sel4_sys::seL4_CNode_Mint(
            root_cnode,
            badged_ep_slot_2,
            cnode_depth as u8,
            root_cnode,
            syscall_ep_cap,
            cnode_depth as u8,
            cap_rights_new(false, true, true, true),
            101 // Badge for Process 2
        )
    };
    if err != 0.into() {
        println!("[KERNEL] Failed to mint badged endpoint 2: {:?}", err);
    }

    let process2 = Process::spawn(
        &mut allocator,
        &mut slot_allocator,
        &mut frame_allocator,
        boot_info,
        hello_elf,
        &[], // No args
        100, // Priority
        badged_ep_slot_2
    ).expect("Failed to spawn process 2");
    
    get_process_manager().add_process(process2).expect("Failed to add process 2");



    // 5. Setup Interrupts
    println!("[KERNEL] Setting up Interrupts...");
    
    // Initialize PCI
    crate::arch::pci::init();

    // let mut notification_cap = 0; // Removed unused variable
    let mut driver_manager = drivers::DriverManager::new();
    let mut shell = shell::Shell::new();
    let mut system_tick: u64 = 0;
    
    match allocator.allocate(boot_info, sel4_sys::api_object_seL4_NotificationObject.into(), sel4_sys::seL4_NotificationBits.into(), &mut slot_allocator) {
        Ok(notification_cap) => {
            // notification_cap = cap;
            println!("[KERNEL] Allocated Notification at slot {}", notification_cap);
            
            // Spawn IRQ Worker Thread
            println!("[KERNEL] Spawning IRQ Worker Thread...");
            let worker_tcb_cap = allocator.allocate(boot_info, sel4_sys::api_object_seL4_TCBObject.into(), sel4_sys::seL4_TCBBits.into(), &mut slot_allocator).expect("Failed to alloc worker TCB");
            let worker_badged_ep = slot_allocator.alloc().expect("Failed to alloc worker EP slot");

            let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
            let cnode_depth = sel4_sys::seL4_WordBits as u8;
            let vspace_root = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadVSpace as usize;

            unsafe {
                // Mint Badged Endpoint (Badge 999)
                sel4_sys::seL4_CNode_Mint(
                    root_cnode, worker_badged_ep, cnode_depth,
                    root_cnode, syscall_ep_cap, cnode_depth,
                    cap_rights_new(false, true, true, true),
                    999
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
                let authority = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadTCB as seL4_CPtr;
                libnova::ipc::set_mr(0, 255); // Priority
                
                // We need to pass authority as an extra cap?
                // No, seL4_TCB_SetPriority(tcb, auth, prio)
                // The syscall is on TCB. Auth is passed as ExtraCap? Or MR?
                // Checking seL4 manual: seL4_TCB_SetPriority takes (service, authority, priority).
                // authority is a CPtr. In MCS, it might be different.
                // In Master (non-MCS), authority is usually passed as an argument in the message?
                // Actually, standard binding: seL4_TCB_SetPriority(tcb, authority, priority)
                // invokes tcb.
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
                    libnova::ipc::set_mr(i+2, regs[i].try_into().unwrap());
                }
                let _ = libnova::ipc::call(worker_tcb_cap, info);

                // Resume
                let info = libnova::ipc::MessageInfo::new(
                    sel4_sys::invocation_label_TCBResume as seL4_Word,
                    0, 0, 0
                );
                let _ = libnova::ipc::call(worker_tcb_cap, info);

                println!("[KERNEL] IRQ Worker Thread Started.");
            }
            
            // 1. Configure Keyboard (Badge 1)
            if irq_handler_cap != 0 {
                let kb_badge_cap = slot_allocator.alloc().unwrap();
                let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                let cnode_depth = sel4_sys::seL4_WordBits as u8;
                
                let err = unsafe {
                    sel4_sys::seL4_CNode_Mint(
                        root_cnode, kb_badge_cap, cnode_depth,
                        root_cnode, notification_cap, cnode_depth,
                        cap_rights_new(false, true, true, true),
                        1 // Badge 1
                    )
                };
                
                if err == 0.into() {
                    if let Err(e) = ioapic::set_irq_handler(irq_handler_cap, kb_badge_cap as usize) {
                        println!("[KERNEL] Failed to SetKBIRQHandler: {}", e);
                    } else {
                        if let Err(e) = ioapic::ack_irq(irq_handler_cap) {
                            println!("[KERNEL] Failed to Ack KB IRQ: {}", e);
                        } else {
                            println!("[KERNEL] Keyboard IRQ Configured.");
                            shell.init(boot_info, &mut allocator, &mut slot_allocator, &mut frame_allocator, syscall_ep_cap);
                            driver_manager.register_irq_driver(1, Box::new(drivers::keyboard::Keyboard::new(irq_handler_cap)));
                        }
                    }
                } else {
                    println!("[KERNEL] Failed to mint KB notification badge: {:?}", err);
                }
            }
            
            // 2. Configure Timer (Badge 2)
            if timer_irq_cap != 0 {
                let timer_badge_cap = slot_allocator.alloc().unwrap();
                let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                let cnode_depth = sel4_sys::seL4_WordBits as u8;
                
                let err = unsafe {
                    sel4_sys::seL4_CNode_Mint(
                        root_cnode, timer_badge_cap, cnode_depth,
                        root_cnode, notification_cap, cnode_depth,
                        cap_rights_new(false, true, true, true),
                        2 // Badge 2
                    )
                };
                
                if err == 0.into() {
                    if let Err(e) = ioapic::set_irq_handler(timer_irq_cap, timer_badge_cap as usize) {
                            println!("[KERNEL] Failed to SetTimerIRQHandler: {}", e);
                    } else {
                        if let Err(e) = ioapic::ack_irq(timer_irq_cap) {
                            println!("[KERNEL] Failed to Ack Timer IRQ: {}", e);
                        } else {
                            println!("[KERNEL] Timer IRQ Configured.");
                            driver_manager.register_irq_driver(2, Box::new(drivers::timer::TimerDriver::new(timer_irq_cap)));
                        }
                    }
                } else {
                    println!("[KERNEL] Failed to mint Timer notification badge: {:?}", err);
                }
            }

            // 3. Configure Serial (Badge 4)
            if serial_irq_cap != 0 {
                let serial_badge_cap = slot_allocator.alloc().unwrap();
                let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                let cnode_depth = sel4_sys::seL4_WordBits as u8;
                
                let err = unsafe {
                    sel4_sys::seL4_CNode_Mint(
                        root_cnode, serial_badge_cap, cnode_depth,
                        root_cnode, notification_cap, cnode_depth,
                        cap_rights_new(false, true, true, true),
                        4 // Badge 4
                    )
                };
                
                if err == 0.into() {
                    if let Err(e) = ioapic::set_irq_handler(serial_irq_cap, serial_badge_cap as usize) {
                            println!("[KERNEL] Failed to SetSerialIRQHandler: {}", e);
                    } else {
                        if let Err(e) = ioapic::ack_irq(serial_irq_cap) {
                            println!("[KERNEL] Failed to Ack Serial IRQ: {}", e);
                        } else {
                            println!("[KERNEL] Serial IRQ Configured.");
                        // Driver is registered in main loop setup, but we should probably move it here or ensure consistency.
                        // Actually, let's keep registration here to be consistent with others.
                        // But wait, I already have registration code later: 
                        // driver_manager.register_irq_driver(4, Box::new(drivers::serial::SerialDriver::new(0x3F8)));
                        // Duplicate registration might be fine if BTreeMap overwrites, but let's avoid it.
                        // I will remove the later registration and put it here.
                        driver_manager.register_irq_driver(4, Box::new(drivers::serial::SerialDriver::new(0x3F8, serial_irq_cap)));
                        }
                    }
                } else {
                    println!("[KERNEL] Failed to mint Serial notification badge: {:?}", err);
                }
            }

            // 4. Register RTC Driver (Badge 8) - No IRQ yet
            driver_manager.register_irq_driver(8, Box::new(drivers::rtc::RtcDriver::new()));
        },
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

    let syscall_ep = Endpoint::new(syscall_ep_cap);

    // Allocate slot for receiving caps during syscalls
    let syscall_recv_slot = slot_allocator.alloc().expect("Failed to alloc syscall recv slot");
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
                    
                    let (badge, info) = libnova::ipc::reply_recv(syscall_ep.cptr, reply_info).expect("IPC ReplyRecv failed");
                    
                    let mr0 = libnova::ipc::get_mr(0);
                let mr1 = libnova::ipc::get_mr(1);
                let mr2 = libnova::ipc::get_mr(2);
                let mr3 = libnova::ipc::get_mr(3);
                
                (info, badge, [mr0.into(), mr1.into(), mr2.into(), mr3.into()])
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
                             b'\r' | b'\n' => Some(drivers::keyboard::Key::Enter),
                             b'\x08' | 0x7F => Some(drivers::keyboard::Key::Backspace),
                             b'\t' => Some(drivers::keyboard::Key::Tab),
                             0x1B => Some(drivers::keyboard::Key::Esc),
                             c if c >= 32 && c <= 126 => Some(drivers::keyboard::Key::Char(c as char)),
                             _ => None,
                         };

                         if let Some(k) = key {
                             shell.on_key(k);
                         }
                    },
                    drivers::DriverEvent::Tick => {
                        system_tick += 1;
                        
                        // Wake up sleeping processes
                        let mut pm = get_process_manager();
                        for pid in 0..crate::process::MAX_PROCESSES {
                            if let Some(p) = pm.get_process_mut(pid) {
                                if p.state == process::ProcessState::Sleeping && system_tick >= p.wake_at_tick {
                                    p.state = process::ProcessState::Running;
                                    let wake_msg = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                                    libnova::ipc::set_mr(0, 0);
                                    libnova::ipc::send(p.saved_reply_cap, wake_msg);
                                }
                            }
                        }
                    },
                    drivers::DriverEvent::None => {}
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

            match label {
                1 => { // sys_write (debug_print)
                    let mut bytes = [0u8; 32];
                    unsafe {
                        let p = bytes.as_mut_ptr() as *mut u64;
                        *p.add(0) = mrs[0];
                        *p.add(1) = mrs[1];
                        *p.add(2) = mrs[2];
                        *p.add(3) = mrs[3];
                    }
                    for &b in bytes.iter() {
                        if b == 0 { break; }
                        print!("{}", b as char);
                    }
                    reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                    need_reply = true;
                }
                2 => { // sys_exit
                    println!("[INFO] Process {} exited with code: {}", pid, mrs[0]);
                    
                    // Check if the test process (PID 0) exited successfully
                    if pid == 0 && mrs[0] == 0 {
                        println!("[TEST] PASSED");
                    }

                    if let Some(p) = get_process_manager().get_process_mut(pid) {
                         let cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                         let _ = p.terminate(cnode, &mut slot_allocator, &mut frame_allocator);
                    }
                    // Remove process from manager
                    get_process_manager().remove_process(pid);
                    
                    need_reply = false; 
                }
                3 => { // sys_brk
                    let new_addr = mrs[0] as usize;
                    // Sanity check: User address space only (e.g. < 0x8000_0000) and non-null (unless query)
                    // If new_addr is 0, it's a query, so we pass it through.
                    if new_addr >= 0x8000_0000 {
                         println!("[KERNEL] sys_brk invalid address: 0x{:x}", new_addr);
                         reply_mrs[0] = 0;
                         reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                         need_reply = true;
                    } else {
                        if let Some(p) = get_process_manager().get_process_mut(pid) {
                             match p.brk(&mut allocator, &mut slot_allocator, &mut frame_allocator, boot_info, new_addr) {
                             Ok(new_brk) => {
                                 reply_mrs[0] = new_brk as u64;
                                 reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                                 need_reply = true;
                             },
                             Err(e) => {
                                 println!("[KERNEL] sys_brk failed for pid {}: {:?}", pid, e);
                                 reply_mrs[0] = 0; 
                                 reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                                 need_reply = true;
                             }
                         }
                    } else {
                         println!("[KERNEL] Process {} not found for sys_brk", pid);
                         need_reply = true;
                    }
                }
                }
                4 => { // sys_yield
                    // reply immediately
                    reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 0);
                    need_reply = true;
                }
                20 => { // sys_open(path, mode) -> fd
                    let path_len = mrs[0] as usize;
                    let mode = match mrs[1] {
                        1 => crate::process::FileMode::WriteOnly,
                        2 => crate::process::FileMode::ReadWrite,
                        3 => crate::process::FileMode::Append,
                        _ => crate::process::FileMode::ReadOnly,
                    };
                    
                    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };
                    // Path starts after MR0 and MR1 (16 bytes offset)
                    let offset = 2 * core::mem::size_of::<seL4_Word>();
                    
                    // Limit path length to 256 bytes for safety
                    let safe_len = if path_len > 256 { 256 } else { path_len };
                    let path_bytes = unsafe { core::slice::from_raw_parts((ipc_buf.msg.as_ptr() as *const u8).add(offset), safe_len) };
                    let path = alloc::string::String::from(core::str::from_utf8(path_bytes).unwrap_or(""));

                    // Auto-create file if it doesn't exist and we are writing
                    if mode != crate::process::FileMode::ReadOnly {
                        if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
                            if crate::vfs::resolve_path(fs, "/", &path).is_err() {
                                // File missing, try to create
                                let res = if let Some(idx) = path.rfind('/') {
                                    let (parent_path, name) = path.split_at(idx);
                                    let name = &name[1..];
                                    let parent_path = if parent_path.is_empty() { "/" } else { parent_path };
                                    
                                    match crate::vfs::resolve_path(fs, "/", parent_path) {
                                        Ok(parent) => parent.create(name, crate::vfs::FileType::File).map(|_| ()),
                                        Err(e) => Err(e),
                                    }
                                } else {
                                    fs.root_inode().create(&path, crate::vfs::FileType::File).map(|_| ())
                                };
                                
                                match res {
                                    Ok(_) => println!("[KERNEL] sys_open: Created new file '{}'", path),
                                    Err(e) => println!("[KERNEL] sys_open: Failed to create '{}': {}", path, e),
                                }
                            }
                        }
                    }

                    let mut fd_idx = -1isize;
                    if let Some(p) = get_process_manager().get_process_mut(pid) {
                        if p.fds.len() < crate::process::MAX_FDS {
                            p.fds.resize(crate::process::MAX_FDS, None);
                        }
                        for (i, slot) in p.fds.iter_mut().enumerate() {
                            if slot.is_none() {
                                *slot = Some(crate::process::FileDescriptor {
                                    path,
                                    offset: 0,
                                    mode,
                                });
                                fd_idx = i as isize;
                                break;
                            }
                        }
                    }
                    reply_mrs[0] = fd_idx as u64;
                    reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                    need_reply = true;
                }
                21 => { // sys_read(fd, len) -> bytes_read
                    let fd = mrs[0] as usize;
                    let len = mrs[1] as usize;
                    // Cap read length to IPC buffer size (approx 900 bytes safe limit)
                    let read_len = if len > 900 { 900 } else { len };
                    
                    let mut bytes_read = 0;
                    if let Some(p) = get_process_manager().get_process_mut(pid) {
                        if fd < p.fds.len() {
                            if let Some(desc) = &mut p.fds[fd] {
                                if desc.mode != crate::process::FileMode::WriteOnly {
                                    if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
                                        if let Ok(inode) = crate::vfs::resolve_path(fs, "/", &desc.path) {
                                            let mut buf = alloc::vec![0u8; read_len];
                                            if let Ok(n) = inode.read_at(desc.offset, &mut buf) {
                                                desc.offset += n;
                                                bytes_read = n;
                                                // Copy to IPC Buffer
                                                let ipc_buf = unsafe { &mut *sel4_sys::seL4_GetIPCBuffer() };
                                                // Offset for MR0
                                                let offset = core::mem::size_of::<seL4_Word>();
                                                let msg_bytes = unsafe { core::slice::from_raw_parts_mut((ipc_buf.msg.as_mut_ptr() as *mut u8).add(offset), n) };
                                                msg_bytes.copy_from_slice(&buf[..n]);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    // Calculate message length in words
                    // Data words + 1 MR word
                    let data_words = (bytes_read + 7) / 8;
                    reply_mrs[0] = bytes_read as u64;
                    reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1 + data_words as u64); // 1 MR (len) + Data
                    need_reply = true;
                    manual_reply = true;
                }
                22 => { // sys_write(fd, len) -> bytes_written
                    let fd = mrs[0] as usize;
                    let len = mrs[1] as usize;
                    let write_len = if len > 900 { 900 } else { len };
                    
                    let mut bytes_written = 0;
                    if let Some(p) = get_process_manager().get_process_mut(pid) {
                         if fd < p.fds.len() {
                            if let Some(desc) = &mut p.fds[fd] {
                                if desc.mode != crate::process::FileMode::ReadOnly {
                                    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };
                                    // Offset for MR0, MR1
                                    let offset = 2 * core::mem::size_of::<seL4_Word>();
                                    let data = unsafe { core::slice::from_raw_parts((ipc_buf.msg.as_ptr() as *const u8).add(offset), write_len) };
                                    
                                    if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
                                         // For write, we might need to create file if not exists?
                                         // Or sys_open should handle creation?
                                         // Assuming file exists or created by sys_open (if we add O_CREAT).
                                         // For now, assume simple write to existing inode.
                                         match crate::vfs::resolve_path(fs, "/", &desc.path) {
                                             Ok(inode) => {
                                                 match inode.write_at(desc.offset, data) {
                                                     Ok(n) => {
                                                         desc.offset += n;
                                                         bytes_written = n;
                                                     },
                                                     Err(e) => println!("[KERNEL] sys_write: write_at failed: {}", e),
                                                 }
                                             },
                                             Err(e) => println!("[KERNEL] sys_write: resolve_path failed for '{}': {}", desc.path, e),
                                         }
                                    }
                                }
                            }
                         }
                    }
                    reply_mrs[0] = bytes_written as u64;
                    reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                    need_reply = true;
                }
                23 => { // sys_close(fd)
                    let fd = mrs[0] as usize;
                    if let Some(p) = get_process_manager().get_process_mut(pid) {
                        if fd < p.fds.len() {
                            p.fds[fd] = None;
                        }
                    }
                    reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 0);
                    need_reply = true;
                }
                50 => { // sys_shutdown
                    println!("[KERNEL] Process {} requested system shutdown.", pid);
                    acpi::shutdown();
                }
                5 => { // seL4_Fault_VMFault
                    let fault_addr = mrs[1] as usize;
                    let ip = mrs[0] as usize;
                    let is_prefetch = mrs[2] == 1;
                    
                    const DEMAND_PAGING_START: usize = 0x4000_0000;
                    const DEMAND_PAGING_END: usize = 0x7000_0000;

                    if fault_addr >= DEMAND_PAGING_START && fault_addr < DEMAND_PAGING_END {
                        let aligned_addr = fault_addr & !0xFFF; // Align to 4K
                        println!("[KERNEL] Demand Paging: Mapping 0x{:x} (IP: 0x{:x}, Prefetch: {}) for fault at 0x{:x}", aligned_addr, ip, is_prefetch, fault_addr);
                        
                        if let Some(p) = get_process_manager().get_process_mut(pid) {
                             // Allocate frame
                             if let Ok(frame_cap) = frame_allocator.alloc(&mut allocator, boot_info, &mut slot_allocator) {
                                 // Map it
                                 if let Ok(_) = p.vspace.map_page(
                                    &mut allocator,
                                    &mut slot_allocator,
                                    boot_info,
                                    frame_cap,
                                    aligned_addr,
                                    cap_rights_new(false, true, true, true),
                                   sel4_sys::seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes
                                 ) {
                                     let _ = p.track_frame(frame_cap);
                                     reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 0);
                                     need_reply = true;
                                 } else {
                                     println!("[KERNEL] Failed to map page.");
                                     let cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                                     let _ = p.terminate(cnode, &mut slot_allocator, &mut frame_allocator);
                                     get_process_manager().remove_process(pid);
                                     need_reply = false;
                                 }
                             } else {
                                 println!("[KERNEL] Failed to allocate frame.");
                                 let cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                                 let _ = p.terminate(cnode, &mut slot_allocator, &mut frame_allocator);
                                 get_process_manager().remove_process(pid);
                                 need_reply = false;
                             }
                        } else {
                             println!("[KERNEL] Process {} not found for VMFault", pid);
                             need_reply = false;
                        }
                    } else {
                        println!("[KERNEL] Unhandled VM Fault at 0x{:x} (IP: 0x{:x}). Terminating.", fault_addr, ip);
                         if let Some(p) = get_process_manager().get_process_mut(pid) {
                             let cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                             let _ = p.terminate(cnode, &mut slot_allocator, &mut frame_allocator);
                         }
                         get_process_manager().remove_process(pid);
                         need_reply = false;
                    }
                }
                6 => { // sys_get_time
                    reply_mrs[0] = system_tick;
                    reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                    need_reply = true;
                }
                10 => { // sys_sleep (MR0 = ticks)
                    let ticks = mrs[0];
                    if ticks == 0 {
                        reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 0);
                        need_reply = true;
                    } else {
                        if let Some(p) = get_process_manager().get_process_mut(pid) {
                            p.wake_at_tick = system_tick + ticks;
                            p.state = process::ProcessState::Sleeping;
                            
                            let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                            if let Err(e) = p.save_caller(root_cnode, &mut slot_allocator) {
                                println!("[KERNEL] Failed to save caller for sys_sleep: {:?}", e);
                                reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1); // Error
                                need_reply = true;
                            } else {
                                // Successful suspend
                                // println!("[KERNEL] Process {} sleeping for {} ticks", pid, ticks);
                                need_reply = false; // Do not reply immediately
                            }
                        } else {
                             need_reply = true;
                        }
                    }
                }
                11 => { // sys_shm_alloc(size)
                    let size = mrs[0] as usize;
                    unsafe {
                        match (*addr_of_mut!(SHARED_MEMORY_MANAGER)).create_shared_region(
                            &mut allocator, 
                            &mut slot_allocator, 
                            boot_info, 
                            size
                        ) {
                            Ok(key) => {
                                reply_mrs[0] = (key + 1) as u64;
                            },
                            Err(e) => {
                                println!("[KERNEL] sys_shm_alloc failed: {:?}", e);
                                reply_mrs[0] = 0; 
                            }
                        }
                    }
                    reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                    need_reply = true;
                }
                12 => { // sys_shm_map(key, vaddr)
                    let key = mrs[0] as usize;
                    let vaddr = mrs[1] as usize;
                    if let Some(p) = get_process_manager().get_process_mut(pid) {
                        unsafe {
                            if key == 0 {
                                reply_mrs[0] = 1; // Error
                            } else {
                                match (*addr_of_mut!(SHARED_MEMORY_MANAGER)).map_shared_region(
                                    key - 1, 
                                    p, 
                                    &mut allocator, 
                                    &mut slot_allocator, 
                                    boot_info, 
                                    vaddr
                                ) {
                                    Ok(_) => {
                                        reply_mrs[0] = 0; // Success
                                    },
                                    Err(e) => {
                                        reply_mrs[0] = e as u64; // Error code
                                    }
                                }
                            }
                        }
                    } else {
                        reply_mrs[0] = 1; // Error
                    }
                    reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                    need_reply = true;
                }
                30 => { // sys_service_register (MR0=len, MR1..=name, ExtraCap=service)
                    let len = mrs[0] as usize;
                    let mut name_bytes = alloc::vec::Vec::with_capacity(len);
                    let mut current_len = 0;
                    let mut mr_idx = 1;
                    while current_len < len {
                        let word = mrs[mr_idx];
                        let bytes = word.to_le_bytes();
                        for b in bytes.iter() {
                            if current_len < len {
                                name_bytes.push(*b);
                                current_len += 1;
                            }
                        }
                        mr_idx += 1;
                    }
                    let name_str = alloc::string::String::from_utf8(name_bytes).unwrap_or_default();

                    unsafe {
                        if sel4_sys::seL4_MessageInfo_get_extraCaps(info.inner) > 0 {
                            // Move cap from syscall_recv_slot to new slot
                            let new_slot = slot_allocator.alloc().expect("Failed to alloc slot for service");
                            let err = sel4_sys::seL4_CNode_Move(
                                root_cnode, new_slot, cnode_depth as u8,
                                root_cnode, syscall_recv_slot, cnode_depth as u8
                            );
                            if err == 0.into() {
                                services::register(&name_str, new_slot);
                                println!("[KERNEL] Service '{}' registered via syscall.", name_str);
                                reply_mrs[0] = 0;
                            } else {
                                println!("[KERNEL] Failed to move service cap: {:?}", err);
                                reply_mrs[0] = 1;
                            }
                        } else {
                            reply_mrs[0] = 2; // No cap
                        }
                    }
                    reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                    need_reply = true;
                }
                31 => { // sys_service_lookup (MR0=len, MR1..=name)
                    let len = mrs[0] as usize;
                    let mut name_bytes = alloc::vec::Vec::with_capacity(len);
                    let mut current_len = 0;
                    let mut mr_idx = 1;
                    while current_len < len {
                        let word = mrs[mr_idx];
                        let bytes = word.to_le_bytes();
                        for b in bytes.iter() {
                            if current_len < len {
                                name_bytes.push(*b);
                                current_len += 1;
                            }
                        }
                        mr_idx += 1;
                    }
                    let name_str = alloc::string::String::from_utf8(name_bytes).unwrap_or_default();
                    
                    if let Some(ep) = services::lookup(&name_str) {
                        libnova::ipc::set_cap(0, ep);
                        reply_info = libnova::ipc::MessageInfo::new(0, 0, 1, 0); // 1 Extra Cap
                    } else {
                        reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 0); // Error
                    }
                    need_reply = true;
                }

                7 => { // sys_send (MR0=TargetPID, MR1..3=Msg)
                    let target_pid = mrs[0] as usize;
                    let msg_content = [mrs[1], mrs[2], mrs[3], 0];
                    
                    if let Some(target_p) = get_process_manager().get_process_mut(target_pid) {
                        if target_p.state == process::ProcessState::BlockedOnRecv {
                            // Target is waiting, wake it up directly with data
                            target_p.state = process::ProcessState::Running;
                            let reply_msg = libnova::ipc::MessageInfo::new(0, 0, 0, 4);
                            let reply_data = [pid as u64, msg_content[0], msg_content[1], msg_content[2]];
                            
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
                8 => { // sys_recv (Blocking)
                    let mut found_msg = None;
                    if let Some(p) = get_process_manager().get_process_mut(pid) {
                        if let Some(msg) = p.mailbox.take() {
                            found_msg = Some(msg);
                        } else {
                            // Block
                            p.state = process::ProcessState::BlockedOnRecv;
                            let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                            if let Err(e) = p.save_caller(root_cnode, &mut slot_allocator) {
                                println!("[KERNEL] Failed to save caller for sys_recv: {:?}", e);
                                reply_mrs[0] = 2; // Error
                                reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                                need_reply = true;
                            } else {
                                need_reply = false;
                            }
                        }
                    }
                    
                    if let Some(msg) = found_msg {
                         reply_mrs[0] = msg.sender_pid as u64;
                         reply_mrs[1] = msg.content[0];
                         reply_mrs[2] = msg.content[1];
                         reply_mrs[3] = msg.content[2];
                         reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 4);
                         need_reply = true;
                    }
                }
                9 => { // sys_get_pid
                    reply_mrs[0] = pid as u64;
                    reply_info = libnova::ipc::MessageInfo::new(0, 0, 0, 1);
                    need_reply = true;
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

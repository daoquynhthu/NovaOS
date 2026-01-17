#![no_std]
#![no_main]
#![deny(warnings)]
#![allow(clippy::useless_conversion)]

#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

mod runtime;
mod memory;
mod allocator;
mod vspace;
mod process;
mod ipc;
mod elf_loader;
mod utils;
mod tests;
mod ioapic;
mod acpi;
mod apic;
mod port_io;
mod keyboard;
mod serial;
mod shell;
mod filesystem;
mod shared_memory;
mod vfs;

use sel4_sys::*;
use sel4_sys::{
    seL4_BootInfo, seL4_CPtr, seL4_MessageInfo_new, seL4_Word,
    seL4_Call, seL4_Wait, seL4_SetMR, seL4_SetCap_My,
    seL4_PageBits
};
use crate::utils::seL4_X86_4K;
use sel4_sys::seL4_RootCNodeCapSlots::{
    seL4_CapInitThreadCNode,
    seL4_CapInitThreadVSpace
};
use core::arch::global_asm;
use memory::{SlotAllocator, UntypedAllocator, ObjectAllocator};
use crate::process::{Process, get_process_manager, FileMode, FileDescriptor, MAX_FDS};
use crate::ipc::Endpoint;
use crate::shared_memory::SharedMemoryManager;

use core::ptr::addr_of_mut;

static mut SHARED_MEMORY_MANAGER: SharedMemoryManager = SharedMemoryManager::new();

static mut WORKER_STACK: [u8; 4096] = [0; 4096];

extern "C" fn irq_worker_entry(notification: usize, endpoint: usize) {
    crate::serial::send_char('[');
    crate::serial::send_char('W');
    crate::serial::send_char(']');
    crate::serial::send_char('\n');
    println!("[WORKER] Thread started. Notification: {}, Endpoint: {}", notification, endpoint);

    loop {
        let mut badge: seL4_Word = 0;
        unsafe {
            seL4_Wait(notification.try_into().unwrap(), &mut badge);
            // Debug: print '!'
            // crate::serial::send_char('!');
            // println!("[WORKER] Received Notification! Badge: {}", badge);
            
            seL4_SetMR(0, badge);
            let info = seL4_MessageInfo_new(0, 0, 0, 1);
            seL4_Call(endpoint.try_into().unwrap(), info);
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
    .type _start, @function
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
    
    // Initialize VFS
    vfs::init();
    // Populate VFS from static filesystem
    {
        let mut vfs_lock = vfs::VFS.lock();
        if let Some(fs) = vfs_lock.as_mut() {
             for file in filesystem::FILES {
                 let path = alloc::format!("/bin/{}", file.name);
                 fs.create_file(&path).expect("Failed to create file");
                 fs.write_file(&path, file.data).expect("Failed to write file");
             }
             // Create a README
             fs.create_file("/home/README.txt").unwrap();
             fs.write_file("/home/README.txt", b"Welcome to NovaOS! This is a RamFS file.").unwrap();
        }
    }
    println!("[KERNEL] VFS Initialized.");
    
    // 1. Get BootInfo
    if boot_info_ptr.is_null() {
        // We can't print safely yet, so just hang or rely on DebugPutChar if we had it separately.
        // panic!("Failed to get BootInfo! System halted."); 
        // For now, let's just assume it's good or crash.
        loop {
            sel4_sys::seL4_Yield();
        }
    }
    
    // SAFETY: We trust the bootloader provided a valid pointer
    let boot_info = &*boot_info_ptr;

    // Initialize IPC Buffer
    sel4_sys::seL4_SetIPCBuffer(boot_info.ipcBuffer);

    // 2. 初始化内存分配器
    let mut slot_allocator = SlotAllocator::new(boot_info);
    let mut allocator = UntypedAllocator::new(boot_info);

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
                sel4_sys::seL4_Yield();
            }
        }
    }
    
    // 3. Use the cap
    port_io::init(io_port_slot);

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
                    let header_size = core::mem::size_of::<acpi::AcpiTableHeader>();
                    let entries_count = (len as usize - header_size) / 4;
                    println!("[ACPI] Scanning {} RSDT entries...", entries_count);
                    
                    let entry_start = (rsdt_ptr as usize + header_size) as *const u32;
                    for i in 0..entries_count {
                        let table_paddr = unsafe { *entry_start.add(i) } as usize;
                        
                        // Map table to check signature
                        let vaddr_base = 0x8001_0000 + (i * 0x10000); // 64KB spacing to be safe
                        
                        match acpi::map_phys(boot_info, table_paddr, vaddr_base, &mut allocator, &mut slot_allocator, &mut acpi_context) {
                            Ok(ptr_val) => {
                                let header = unsafe { &*(ptr_val as *const acpi::AcpiTableHeader) };
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
                                                 if let Err(e) = acpi::map_phys(boot_info, p_paddr, 0, &mut allocator, &mut slot_allocator, &mut acpi_context) {
                                                     println!("[ACPI] Failed to map extra page for MADT: {:?}", e);
                                                 }
                                             }
                                         }
                                         
                                         let madt = unsafe { &*(ptr_val as *const acpi::Madt) };
                                         let local_apic = madt.local_apic_address;
                                         let flags = madt.flags;
                                         println!("[ACPI] Local APIC Address: 0x{:x}", local_apic);
                                         println!("[ACPI] MADT Flags: 0x{:x}", flags);
                                         
                                         // Parse MADT records
                                         acpi::walk_madt(madt);
                                         
                                         // Initialize Local APIC
                                         if let Some(_apic) = apic::init(boot_info, local_apic as usize, &mut allocator, &mut slot_allocator, &mut acpi_context) {
                                             println!("[KERNEL] Local APIC Initialized.");
                                         } else {
                                             println!("[KERNEL] Local APIC init skipped (using default configuration).");
                                         }

                                         // Initialize IO APIC
                                         if let Some(ioapic_info) = acpi::find_first_ioapic(madt) {
                                             println!("[KERNEL] Found IOAPIC at 0x{:x} (ID: {}).", ioapic_info.address, ioapic_info.id);
                                             
                                             let irq_control_cap = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapIRQControl as usize;
                                             let root_cnode_cap = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as usize;
                                             let depth = sel4_sys::seL4_WordBits as usize;

                                             // 1. Keyboard IRQ (IRQ 1)
                                             if let Ok(irq_slot) = slot_allocator.alloc() {
                                                let irq = 1;
                                                // Check for ISO
                                                let (gsi, level, polarity) = if let Some(iso) = acpi::find_iso_for_irq(madt, irq) {
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
                                                
                                                let err = unsafe {
                                                    ioapic::get_ioapic_handler(
                                                        irq_control_cap, ioapic_idx as usize, pin as usize, level, polarity,
                                                        root_cnode_cap, irq_slot.try_into().unwrap(), depth, vector
                                                    )
                                                };
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
                                                 
                                                 let (gsi, level, polarity) = if let Some(iso) = acpi::find_iso_for_irq(madt, irq) {
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
                                                
                                                let err = unsafe {
                                                    ioapic::get_ioapic_handler(
                                                        irq_control_cap, ioapic_idx as usize, pin as usize, level, polarity,
                                                        root_cnode_cap, irq_slot.try_into().unwrap(), depth, vector
                                                    )
                                                };

                                                if err.is_ok() {
                                                    timer_irq_cap = irq_slot as usize;
                                                    println!("[KERNEL] Timer IRQ Handler obtained.");
                                                } else {
                                                    println!("[KERNEL] Failed to get Timer IRQ Handler.");
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
    tests::run_all(boot_info, &mut allocator, &mut slot_allocator);
    println!("[KERNEL] POST Completed Successfully.");

    // 4. Initialize Syscall Endpoint and Processes
    println!("[KERNEL] Initializing Process Manager...");
    
    // Allocate Syscall Endpoint
    let syscall_ep_cap = allocator.allocate(boot_info, api_object_seL4_EndpointObject.into(), seL4_EndpointBits.into(), &mut slot_allocator).expect("Failed to alloc EP");
    
    // Mint Badged Endpoint for Process 1
    let badged_ep_slot = slot_allocator.alloc().expect("Failed to alloc slot for badged EP");
    let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
    let cnode_depth = seL4_WordBits; 
    
    let err = unsafe {
        sel4_sys::seL4_CNode_Mint(
            root_cnode,
            badged_ep_slot,
            cnode_depth as u8,
            root_cnode,
            syscall_ep_cap,
            cnode_depth as u8,
            crate::utils::seL4_CapRights_new(0, 1, 1, 1),
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
        boot_info,
        hello_elf,
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
            crate::utils::seL4_CapRights_new(0, 1, 1, 1),
            101 // Badge for Process 2
        )
    };
    if err != 0.into() {
        println!("[KERNEL] Failed to mint badged endpoint 2: {:?}", err);
    }

    let process2 = Process::spawn(
        &mut allocator,
        &mut slot_allocator,
        boot_info,
        hello_elf,
        100, // Priority
        badged_ep_slot_2
    ).expect("Failed to spawn process 2");
    
    get_process_manager().add_process(process2).expect("Failed to add process 2");



    // 5. Setup Interrupts
    println!("[KERNEL] Setting up Interrupts...");
    
    // let mut notification_cap = 0; // Removed unused variable
    let mut keyboard_driver = keyboard::Keyboard::new();
    let mut shell = shell::Shell::new();
    let mut system_tick: u64 = 0;
    
    match allocator.allocate(boot_info, api_object_seL4_NotificationObject.into(), seL4_NotificationBits.into(), &mut slot_allocator) {
        Ok(notification_cap) => {
            // notification_cap = cap;
            println!("[KERNEL] Allocated Notification at slot {}", notification_cap);
            
            // Spawn IRQ Worker Thread
            println!("[KERNEL] Spawning IRQ Worker Thread...");
            let worker_tcb_cap = allocator.allocate(boot_info, api_object_seL4_TCBObject.into(), seL4_TCBBits.into(), &mut slot_allocator).expect("Failed to alloc worker TCB");
            let worker_badged_ep = slot_allocator.alloc().expect("Failed to alloc worker EP slot");

            let root_cnode = seL4_CapInitThreadCNode as seL4_CPtr;
            let cnode_depth = seL4_WordBits as u8;
            let vspace_root = seL4_CapInitThreadVSpace as usize;

            unsafe {
                // Mint Badged Endpoint (Badge 999)
                sel4_sys::seL4_CNode_Mint(
                    root_cnode, worker_badged_ep, cnode_depth,
                    root_cnode, syscall_ep_cap, cnode_depth,
                    crate::utils::seL4_CapRights_new(0, 1, 1, 1),
                    999
                );

                // Configure TCB Manually
                // Label: TCBConfigure (typically 1 or derived)
                // Args: FaultEP, CSpaceRootData, VSpaceRootData, BufferAddr
                // Extra Caps: CSpaceRoot, VSpaceRoot, BufferFrame(Optional)
                
                seL4_SetMR(0, 0); // Fault EP
                seL4_SetMR(1, 0); // CSpace Data
                seL4_SetMR(2, 0); // VSpace Data
                seL4_SetMR(3, 0); // Buffer Address (No IPC Buffer)
                
                seL4_SetCap_My(0, root_cnode);
            seL4_SetCap_My(1, vspace_root as seL4_CPtr);
            seL4_SetCap_My(2, 0); // BufferFrame (Null)

            let info = seL4_MessageInfo_new(
                sel4_sys::invocation_label_TCBConfigure as seL4_Word,
                0,
                3, // ExtraCaps: CSpace, VSpace, BufferFrame
                5, // Length
            );
                seL4_Call(worker_tcb_cap, info);

                // Set Priority
                let authority = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadTCB as seL4_CPtr;
                seL4_SetMR(0, 255); // Priority
                
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
                
                seL4_SetCap_My(0, authority);
                let info = seL4_MessageInfo_new(
                    sel4_sys::invocation_label_TCBSetPriority as seL4_Word,
                    0,
                    1, // ExtraCaps: Authority
                    1, // Length: Priority
                );
                seL4_Call(worker_tcb_cap, info);

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

                let info = seL4_MessageInfo_new(
                    sel4_sys::invocation_label_TCBWriteRegisters as seL4_Word,
                    0,
                    0,
                    2 + 20, // Length: flags(1) + count(1) + regs(20)
                );
                seL4_SetMR(0, 0); // Resume=false
                seL4_SetMR(1, 20); // Count
                for i in 0..20 {
                    seL4_SetMR(i+2, regs[i]);
                }
                seL4_Call(worker_tcb_cap, info);

                // Resume
                let info = seL4_MessageInfo_new(
                    sel4_sys::invocation_label_TCBResume as seL4_Word,
                    0, 0, 0
                );
                seL4_Call(worker_tcb_cap, info);

                println!("[KERNEL] IRQ Worker Thread Started.");
            }
            
            // 1. Configure Keyboard (Badge 1)
            if irq_handler_cap != 0 {
                let kb_badge_cap = slot_allocator.alloc().unwrap();
                let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                let cnode_depth = seL4_WordBits as u8;
                
                let err = unsafe {
                    sel4_sys::seL4_CNode_Mint(
                        root_cnode, kb_badge_cap, cnode_depth,
                        root_cnode, notification_cap, cnode_depth,
                        crate::utils::seL4_CapRights_new(0, 1, 1, 1),
                        1 // Badge 1
                    )
                };
                
                if err == 0.into() {
                    unsafe {
                        if let Err(e) = ioapic::set_irq_handler(irq_handler_cap, kb_badge_cap as usize) {
                            println!("[KERNEL] Failed to SetKBIRQHandler: {}", e);
                        } else {
                            if let Err(e) = ioapic::ack_irq(irq_handler_cap) {
                                println!("[KERNEL] Failed to Ack KB IRQ: {}", e);
                            } else {
                                println!("[KERNEL] Keyboard IRQ Configured.");
                                shell.init(boot_info, &mut allocator, &mut slot_allocator, syscall_ep_cap);
                            }
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
                let cnode_depth = seL4_WordBits as u8;
                
                let err = unsafe {
                    sel4_sys::seL4_CNode_Mint(
                        root_cnode, timer_badge_cap, cnode_depth,
                        root_cnode, notification_cap, cnode_depth,
                        crate::utils::seL4_CapRights_new(0, 1, 1, 1),
                        2 // Badge 2
                    )
                };
                
                if err == 0.into() {
                    unsafe {
                        if let Err(e) = ioapic::set_irq_handler(timer_irq_cap, timer_badge_cap as usize) {
                             println!("[KERNEL] Failed to SetTimerIRQHandler: {}", e);
                        } else {
                            if let Err(e) = ioapic::ack_irq(timer_irq_cap) {
                                println!("[KERNEL] Failed to Ack Timer IRQ: {}", e);
                            } else {
                                println!("[KERNEL] Timer IRQ Configured.");
                            }
                        }
                    }
                } else {
                    println!("[KERNEL] Failed to mint Timer notification badge: {:?}", err);
                }
            }
        },
        Err(e) => println!("[KERNEL] Failed to allocate Notification: {:?}", e),
    }

    // 6. Unified Event Loop
    println!("[KERNEL] Entering Unified Event Loop...");
    
    // Disable Legacy PIC (Mask all) to prevent interference with IOAPIC
    unsafe {
        port_io::outb(0x21, 0xFF);
        port_io::outb(0xA1, 0xFF);
        println!("[KERNEL] Legacy PIC Masked.");
    }
    
    // Initialize PIT for 100Hz Timer
    unsafe {
        port_io::outb(0x43, 0x34);
        let divisor = 11931; // 100Hz
        port_io::outb(0x40, (divisor & 0xFF) as u8);
        port_io::outb(0x40, (divisor >> 8) as u8);
        println!("[KERNEL] PIT Initialized (100Hz)");
        
        let ipc_buf = sel4_sys::seL4_GetIPCBuffer();
        println!("[KERNEL] RootServer IPC Buffer: {:p}", ipc_buf);
    }

    let syscall_ep = Endpoint::new(syscall_ep_cap);
    let mut reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 0);
    let mut need_reply = false;
    let mut reply_mrs = [0u64; 4];

    loop {
        let (info, badge, mrs) = if need_reply {
            syscall_ep.reply_recv_with_mrs(reply_info, reply_mrs)
        } else {
            syscall_ep.recv_with_mrs()
        };
        
        // Reset reply flag
        need_reply = false;
        
        if badge == 999 {
            // Worker Thread Interrupt Forwarding
            let irq_badge = mrs[0] as seL4_Word;
            
            // Check Keyboard (Badge 1)
            if irq_badge & 1 != 0 {
                for _ in 0..32 {
                    if unsafe { port_io::inb(0x64) } & 0x01 == 0 {
                        break;
                    }

                    let scancode = unsafe { port_io::inb(0x60) };
                    if let Some(k) = keyboard_driver.process_scancode(scancode) {
                        shell.on_key(k);
                    }
                }
                unsafe {
                    if let Err(e) = ioapic::ack_irq(irq_handler_cap) {
                         println!("[KERNEL] Failed to Ack KB IRQ in loop: {}", e);
                    }
                }
            }
            
            // Check Timer (Badge 2)
            if irq_badge & 2 != 0 {
                system_tick += 1;
                // if system_tick % 100 == 0 {
                //      println!("[KERNEL] Tick {}", system_tick);
                // }

                unsafe {
                    if let Err(e) = ioapic::ack_irq(timer_irq_cap) {
                         println!("[KERNEL] Failed to Ack Timer IRQ in loop: {}", e);
                    }
                }
                
                // Wake up sleeping processes
                let pm = get_process_manager();
                for pid in 0..crate::process::MAX_PROCESSES {
                    if let Some(p) = pm.get_process_mut(pid) {
                        if p.state == process::ProcessState::Sleeping && system_tick >= p.wake_at_tick {
                            // println!("[KERNEL] Waking up PID {} at tick {}", pid, system_tick);
                            p.state = process::ProcessState::Running;

                            // Send reply to wake up the process
                            let wake_msg = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
                            unsafe {
                                // println!("[KERNEL] Sending wake reply to cap: {}", p.saved_reply_cap);
                                // sel4_sys::seL4_SetMR(0, 0); // Not needed with custom seL4_Send
                                crate::utils::seL4_Send(p.saved_reply_cap, wake_msg.words[0], [0; 4]);
                                // println!("[KERNEL] Wake reply sent.");
                            }
                        }
                    }
                }
            }
            
            // Reply to Worker to unblock it for next IRQ
            need_reply = true;
            reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 0);
            continue;
        }

        if badge < 100 {
            // Legacy/Unused
        } else if badge >= 100 {
            let pid = (badge - 100) as usize;
            // Syscall from Process
             let label = sel4_sys::seL4_MessageInfo_get_label(info);

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
                    reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
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
                         let _ = p.terminate(cnode, &mut slot_allocator);
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
                         reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
                         need_reply = true;
                    } else {
                        if let Some(p) = get_process_manager().get_process_mut(pid) {
                             match p.brk(&mut allocator, &mut slot_allocator, boot_info, new_addr) {
                             Ok(new_brk) => {
                                 reply_mrs[0] = new_brk as u64;
                                 reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
                                 need_reply = true;
                             },
                             Err(e) => {
                                 println!("[KERNEL] sys_brk failed for pid {}: {:?}", pid, e);
                                 reply_mrs[0] = 0; 
                                 reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
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
                    reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 0);
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
                             if let Ok(frame_cap) = allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), &mut slot_allocator) {
                                 // Map it
                                 if let Ok(_) = p.vspace.map_page(
                                    &mut allocator,
                                    &mut slot_allocator,
                                    boot_info,
                                    frame_cap,
                                    aligned_addr,
                                    crate::utils::seL4_CapRights_new(0, 1, 1, 1),
                                    sel4_sys::seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes
                                 ) {
                                     let _ = p.track_frame(frame_cap);
                                     reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 0);
                                     need_reply = true;
                                 } else {
                                     println!("[KERNEL] Failed to map page.");
                                     let cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                                     let _ = p.terminate(cnode, &mut slot_allocator);
                                     get_process_manager().remove_process(pid);
                                     need_reply = false;
                                 }
                             } else {
                                 println!("[KERNEL] Failed to allocate frame.");
                                 let cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                                 let _ = p.terminate(cnode, &mut slot_allocator);
                                 get_process_manager().remove_process(pid);
                                 need_reply = false;
                             }
                        } else {
                             need_reply = true;
                        }
                    } else {
                        println!("[KERNEL] Unhandled VM Fault at 0x{:x} (IP: 0x{:x}). Terminating.", fault_addr, ip);
                         if let Some(p) = get_process_manager().get_process_mut(pid) {
                             let cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                             let _ = p.terminate(cnode, &mut slot_allocator);
                         }
                         get_process_manager().remove_process(pid);
                         need_reply = false;
                    }
                }
                6 => { // sys_get_time
                    reply_mrs[0] = system_tick;
                    reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
                    need_reply = true;
                }
                10 => { // sys_sleep (MR0 = ticks)
                    let ticks = mrs[0];
                    if ticks == 0 {
                        reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 0);
                        need_reply = true;
                    } else {
                        if let Some(p) = get_process_manager().get_process_mut(pid) {
                            p.wake_at_tick = system_tick + ticks;
                            p.state = process::ProcessState::Sleeping;
                            
                            let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                            if let Err(e) = p.save_caller(root_cnode, &mut slot_allocator) {
                                println!("[KERNEL] Failed to save caller for sys_sleep: {:?}", e);
                                reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1); // Error
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
                                reply_mrs[0] = key as u64;
                            },
                            Err(_) => {
                                reply_mrs[0] = 0; 
                            }
                        }
                    }
                    reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
                    need_reply = true;
                }
                12 => { // sys_shm_map(key, vaddr)
                    let key = mrs[0] as usize;
                    let vaddr = mrs[1] as usize;
                    if let Some(p) = get_process_manager().get_process_mut(pid) {
                        unsafe {
                             match (*addr_of_mut!(SHARED_MEMORY_MANAGER)).map_shared_region(
                                key, 
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
                    } else {
                         reply_mrs[0] = 1; // Error
                    }
                    reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
                    need_reply = true;
                }
                20 => { // sys_file_open (MR0=len|mode<<32, MR1..=path)
                    let len = (mrs[0] & 0xFFFFFFFF) as usize;
                    let mode_val = (mrs[0] >> 32) as u8;
                    let mode = match mode_val {
                        0 => FileMode::ReadOnly,
                        1 => FileMode::WriteOnly,
                        2 => FileMode::ReadWrite,
                        3 => FileMode::Append,
                        _ => FileMode::ReadOnly,
                    };
                    
                    let mut path_bytes = alloc::vec::Vec::with_capacity(len);
                    let mut current_len = 0;
                    let mut mr_idx = 1;
                    
                    while current_len < len {
                        let word = mrs[mr_idx];
                        let bytes = word.to_le_bytes();
                        for b in bytes.iter() {
                            if current_len < len {
                                path_bytes.push(*b);
                                current_len += 1;
                            }
                        }
                        mr_idx += 1;
                    }
                    
                    let path_str = alloc::string::String::from_utf8(path_bytes).unwrap_or_default();
                    
                    if let Some(p) = get_process_manager().get_process_mut(pid) {
                        let mut fd_idx = None;
                        for (i, fd) in p.fds.iter().enumerate() {
                            if fd.is_none() {
                                fd_idx = Some(i);
                                break;
                            }
                        }
                        
                        if let Some(idx) = fd_idx {
                            let mut success = false;
                            {
                                let mut lock = crate::vfs::VFS.lock();
                                if let Some(fs) = lock.as_mut() {
                                    if mode == FileMode::ReadOnly {
                                        if fs.exists(&path_str) {
                                            success = true;
                                        }
                                    } else {
                                        if !fs.exists(&path_str) {
                                             if fs.create_file(&path_str).is_ok() {
                                                 success = true;
                                             }
                                        } else {
                                             success = true;
                                        }
                                    }
                                }
                            }
                            
                            if success {
                                p.fds[idx] = Some(FileDescriptor {
                                    path: path_str,
                                    offset: 0,
                                    mode: mode,
                                });
                                reply_mrs[0] = idx as u64;
                            } else {
                                reply_mrs[0] = u64::MAX;
                            }
                        } else {
                            reply_mrs[0] = u64::MAX;
                        }
                    } else {
                        reply_mrs[0] = u64::MAX;
                    }
                    reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
                    need_reply = true;
                }
                21 => { // sys_file_close (MR0=fd)
                    let fd = mrs[0] as usize;
                    if let Some(p) = get_process_manager().get_process_mut(pid) {
                        if fd < MAX_FDS {
                            p.fds[fd] = None;
                            reply_mrs[0] = 0;
                        } else {
                            reply_mrs[0] = 1;
                        }
                    }
                    reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
                    need_reply = true;
                }
                22 => { // sys_file_read (MR0=fd|len<<32)
                    let fd = (mrs[0] & 0xFFFFFFFF) as usize;
                    let len = (mrs[0] >> 32) as usize;
                    
                    let mut bytes_read = 0;
                    let mut data = alloc::vec::Vec::new();
                    
                    if let Some(p) = get_process_manager().get_process_mut(pid) {
                         if fd < MAX_FDS {
                             if let Some(file_desc) = &mut p.fds[fd] {
                                 if file_desc.mode != FileMode::WriteOnly {
                                     let lock = crate::vfs::VFS.lock();
                                     if let Some(fs) = lock.as_ref() {
                                         if let Some(file_data) = fs.read_file(&file_desc.path) {
                                             if file_desc.offset < file_data.len() {
                                                 let available = file_data.len() - file_desc.offset;
                                                 let to_read = core::cmp::min(len, available);
                                                 let max_mrs_bytes = 64; 
                                                 let actual_read = core::cmp::min(to_read, max_mrs_bytes);
                                                 
                                                 data.extend_from_slice(&file_data[file_desc.offset..file_desc.offset + actual_read]);
                                                 bytes_read = actual_read;
                                                 file_desc.offset += actual_read;
                                             }
                                         }
                                     }
                                 }
                             }
                         }
                    }
                    
                    reply_mrs[0] = bytes_read as u64;
                    let mut mr_idx = 1;
                    for chunk in data.chunks(8) {
                        let mut word_bytes = [0u8; 8];
                        for (i, b) in chunk.iter().enumerate() {
                            word_bytes[i] = *b;
                        }
                        reply_mrs[mr_idx] = u64::from_le_bytes(word_bytes);
                        mr_idx += 1;
                    }
                    
                    reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, mr_idx as u64);
                    need_reply = true;
                }
                23 => { // sys_file_write (MR0=fd|len<<32, MR1..=data)
                    let fd = (mrs[0] & 0xFFFFFFFF) as usize;
                    let len = (mrs[0] >> 32) as usize;
                    let mut bytes_written = 0;
                    
                    if let Some(p) = get_process_manager().get_process_mut(pid) {
                         if fd < MAX_FDS {
                             if let Some(file_desc) = &mut p.fds[fd] {
                                 if file_desc.mode != FileMode::ReadOnly {
                                     let mut data = alloc::vec::Vec::with_capacity(len);
                                     let mut current_len = 0;
                                     let mut mr_idx = 1;
                                     while current_len < len {
                                         let word = mrs[mr_idx];
                                         let bytes = word.to_le_bytes();
                                         for b in bytes.iter() {
                                             if current_len < len {
                                                 data.push(*b);
                                                 current_len += 1;
                                             }
                                         }
                                         mr_idx += 1;
                                     }
                                     
                                     let mut lock = crate::vfs::VFS.lock();
                                    if let Some(fs) = lock.as_mut() {
                                        if let Ok(_n) = fs.append_file(&file_desc.path, &data) {
                                            // For now, append_file returns new size.
                                            // We just assume all bytes written.
                                             bytes_written = data.len();
                                             file_desc.offset += bytes_written; // Update offset? Append always writes to end.
                                         }
                                     }
                                 }
                             }
                         }
                    }
                    reply_mrs[0] = bytes_written as u64;
                    reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
                    need_reply = true;
                }
                7 => { // sys_send (MR0=TargetPID, MR1..3=Msg)
                    let target_pid = mrs[0] as usize;
                    let msg_content = [mrs[1], mrs[2], mrs[3], 0];
                    
                    if let Some(target_p) = get_process_manager().get_process_mut(target_pid) {
                        if target_p.state == process::ProcessState::BlockedOnRecv {
                            // Target is waiting, wake it up directly with data
                            target_p.state = process::ProcessState::Running;
                            let reply_msg = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 4);
                            let reply_data = [pid as u64, msg_content[0], msg_content[1], msg_content[2]];
                            unsafe {
                                crate::utils::seL4_Send(target_p.saved_reply_cap, reply_msg.words[0], reply_data);
                            }
                            
                            // Reply to sender: Success
                            reply_mrs[0] = 0; // Success
                            reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
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
                            reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
                            need_reply = true;
                        }
                    } else {
                        // Target not found
                        reply_mrs[0] = 1; // Error
                        reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
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
                                reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
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
                         reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 4);
                         need_reply = true;
                    }
                }
                9 => { // sys_get_pid
                    reply_mrs[0] = pid as u64;
                    reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
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

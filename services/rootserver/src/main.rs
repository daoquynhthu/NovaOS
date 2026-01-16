#![no_std]
#![no_main]
#![deny(warnings)]

#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

mod runtime;
mod memory;
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

use sel4_sys::*;
use core::arch::global_asm;
use memory::{SlotAllocator, UntypedAllocator, ObjectAllocator};
use crate::process::{Process, get_process_manager};
use crate::ipc::Endpoint;
use crate::shell::USER_HELLO_ELF;

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
    let root_cnode_cptr = sel4_sys::seL4_RootCNodeCapSlots_seL4_CapInitThreadCNode as u64;

    match port_io::issue_ioport_cap(
        sel4_sys::seL4_RootCNodeCapSlots_seL4_CapIOPortControl as u64,
        0x0000,
        0xFFFF,
        root_cnode_cptr,   // Extra Cap: Root CNode
        io_port_slot, // Slot in Root CNode
        sel4_sys::seL4_WordBits as u64,
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
                                             
                                             // Try to get an IRQ Handler for IRQ 1 (Keyboard)
                                            if let Ok(irq_slot) = slot_allocator.alloc() {
                                                println!("[KERNEL] Requesting IRQ Handler for IRQ 1 (Keyboard)...");
                                                let irq = 1; 
                                                let pin = irq;
                                                let level = 0; // Edge
                                                let polarity = 0; // Active High
                                                let ioapic_idx = 0; // First IOAPIC

                                                let irq_control_cap = sel4_sys::seL4_RootCNodeCapSlots_seL4_CapIRQControl as usize;
                                                let root_cnode_cap = sel4_sys::seL4_RootCNodeCapSlots_seL4_CapInitThreadCNode as usize;
                                                let depth = sel4_sys::seL4_WordBits as usize;

                                                let vector = 33; // 0x21
                                                
                                                let err = unsafe {
                                                    ioapic::get_ioapic_handler(
                                                        irq_control_cap,
                                                        ioapic_idx as usize,
                                                        pin as usize,
                                                        level as usize,
                                                        polarity as usize,
                                                        root_cnode_cap,
                                                        irq_slot as usize,
                                                        depth,
                                                        vector as usize
                                                    )
                                                };
                                                
                                                match err {
                                                    Ok(_) => {
                                                        println!("[KERNEL] Successfully obtained IRQ Handler for IRQ 1 at slot {}", irq_slot);
                                                        irq_handler_cap = irq_slot as usize;
                                                    },
                                                    Err(e) => println!("[KERNEL] Failed to get IRQ Handler for IRQ 1: Error {}", e),
                                                }
                                            }
                                             
                                         } else {
                                             println!("[KERNEL] No IOAPIC found in MADT.");
                                         }
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
    let root_cnode = seL4_RootCNodeCapSlots_seL4_CapInitThreadCNode as seL4_CPtr;
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
    let process = Process::spawn(
        &mut allocator,
        &mut slot_allocator,
        boot_info,
        USER_HELLO_ELF,
        100, // Priority
        badged_ep_slot // Give badged cap
    ).expect("Failed to spawn process");
    
    get_process_manager().add_process(process).expect("Failed to add process");


    // 5. Setup Keyboard Interrupt
    let mut notification_cap = 0;
    let mut keyboard_driver = keyboard::Keyboard::new();
    let mut shell = shell::Shell::new();
    
    if irq_handler_cap != 0 {
        match allocator.allocate(boot_info, api_object_seL4_NotificationObject as u64, seL4_NotificationBits as u64, &mut slot_allocator) {
            Ok(cap) => {
                notification_cap = cap;
                println!("[KERNEL] Allocated Notification for Keyboard at slot {}", cap);
                unsafe {
                    if let Err(e) = ioapic::set_irq_handler(irq_handler_cap, notification_cap as usize) {
                            println!("[KERNEL] Failed to SetIRQHandler: {}", e);
                    } else {
                            println!("[KERNEL] IRQ Handler connected to Notification.");
                            
                            // Bind Notification to RootServer TCB
                            let tcb_cap = seL4_RootCNodeCapSlots_seL4_CapInitThreadTCB as usize;
                            
                            // seL4_TCB_BindNotification implementation using seL4_Call
                            // Method ID for TCBBindNotification is in invocation_label
                            let info = seL4_MessageInfo_new(
                                invocation_label_TCBBindNotification as seL4_Word,
                                0,
                                1, // ExtraCaps: 1
                                0
                            );
                            
                            seL4_SetCap_My(0, notification_cap);
                            
                            let resp = seL4_Call(tcb_cap.try_into().unwrap(), info);
                            let err_label = seL4_MessageInfo_get_label(resp);
                            
                            if err_label != 0 {
                                println!("[KERNEL] Failed to Bind Notification to TCB: {}", err_label);
                            } else {
                                println!("[KERNEL] Notification Bound to RootServer TCB.");
                            }
                            
                            if let Err(e) = ioapic::ack_irq(irq_handler_cap) {
                                println!("[KERNEL] Failed to Ack IRQ: {}", e);
                            } else {
                                println!("[KERNEL] IRQ Acked.");
                                
                                // Init Shell with Syscall EP
                                shell.init(boot_info, &mut allocator, &mut slot_allocator, syscall_ep_cap);
                            }
                    }
                }
            },
            Err(e) => println!("[KERNEL] Failed to allocate Notification: {:?}", e),
        }
    }

    // 6. Unified Event Loop
    println!("[KERNEL] Entering Unified Event Loop...");
    
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
        
        if badge == 0 {
            // Interrupt (assuming Badge 0)
            if notification_cap != 0 {
                 for _ in 0..32 {
                        if port_io::inb(0x64) & 0x01 == 0 {
                            break;
                        }

                        let scancode = port_io::inb(0x60);
                        if let Some(k) = keyboard_driver.process_scancode(scancode) {
                            shell.on_key(k);
                        }
                }
                if let Err(e) = ioapic::ack_irq(irq_handler_cap) {
                     println!("[KERNEL] Failed to Ack IRQ in loop: {}", e);
                }
            }
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
                         let cnode = seL4_RootCNodeCapSlots_seL4_CapInitThreadCNode as seL4_CPtr;
                         let _ = p.terminate(cnode);
                    }
                    // Remove process from manager
                    get_process_manager().remove_process(pid);
                    
                    need_reply = false; 
                }
                3 => { // sys_brk
                    if let Some(p) = get_process_manager().get_process_mut(pid) {
                         match p.brk(&mut allocator, &mut slot_allocator, boot_info, mrs[0] as usize) {
                             Ok(new_brk) => {
                                 reply_mrs[0] = new_brk as u64;
                                 reply_info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 1);
                                 need_reply = true;
                             },
                             Err(e) => {
                                 println!("[KERNEL] sys_brk failed for pid {}: {:?}", pid, e);
                                 // Return 0 or old break on error? Linux returns current break on failure sometimes or -1.
                                 // Here we just return 0 to indicate failure if we want, or handle it in user lib.
                                 // But usually sbrk(0) returns current. sbrk(inc) returns old.
                                 // brk(addr) returns new addr on success.
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

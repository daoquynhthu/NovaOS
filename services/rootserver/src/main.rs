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
mod acpi;
mod apic;

use sel4_sys::seL4_BootInfo;
use core::arch::global_asm;
use memory::{UntypedAllocator, SlotAllocator};

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
    
    println!("\n========================================");
    println!("   NovaOS: The Future Secure OS");
    println!("   Status: RootServer Started");
    println!("========================================");

    // 1. Get BootInfo
    if boot_info_ptr.is_null() {
        panic!("Failed to get BootInfo! System halted.");
    }
    
    // SAFETY: We trust the bootloader provided a valid pointer
    // The function is unsafe, so dereferencing raw pointer is allowed if we respect safety contracts.
    let boot_info = &*boot_info_ptr;
    
    // Initialize IPC Buffer
    sel4_sys::seL4_SetIPCBuffer(boot_info.ipcBuffer);

    println!("[INFO] BootInfo retrieved successfully.");
    println!("[INFO] BootInfo Addr: {:p}", boot_info);
    println!("[INFO] IPC Buffer: {:p}", boot_info.ipcBuffer);
    println!("[INFO] Empty Slots: {} - {}", boot_info.empty.start, boot_info.empty.end);
    println!("[INFO] Untyped Slots: {} - {}", boot_info.untyped.start, boot_info.untyped.end);
    
    // Dump raw bootinfo (Disabled for production)
    /*
    let raw_ptr = boot_info as *const seL4_BootInfo as *const usize;
    for i in 0..10 {
        // println!("[DEBUG] BootInfo Word {}: 0x{:x}", i, unsafe { *raw_ptr.add(i) });
    }
    */
    println!("[INFO] Untyped Memory: {} slots",  
             boot_info.untyped.end - boot_info.untyped.start);
    println!("[INFO] CNode Size: {} bits", boot_info.initThreadCNodeSizeBits);

    // 2. 初始化内存分配器
    let mut slot_allocator = SlotAllocator::new(boot_info);
    let mut allocator = UntypedAllocator::new(boot_info);
    allocator.print_info(boot_info);

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
                        // println!("[ACPI] Entry {}: paddr 0x{:x}", i, table_paddr);
                        
                        // Map table to check signature
                        // We use a simple incrementing vaddr. 
                        // WARNING: This is temporary. Real OS should have a proper VM allocator.
                        let vaddr_base = 0x8001_0000 + (i * 0x10000); // 64KB spacing to be safe
                        
                        match acpi::map_phys(boot_info, table_paddr, vaddr_base, &mut allocator, &mut slot_allocator, &mut acpi_context) {
                            Ok(ptr_val) => {
                                let header = unsafe { &*(ptr_val as *const acpi::AcpiTableHeader) };
                                 println!("[ACPI] Table [{}] Paddr: 0x{:x} Vaddr: 0x{:x} SigBytes: {:?}", i, table_paddr, ptr_val, header.signature);
                                 if let Ok(sig) = core::str::from_utf8(&header.signature) {
                                     println!("[ACPI] Table [{}] Signature: {}", i, sig);
                                    if sig == "APIC" {
                                         println!("[ACPI] Found MADT (APIC) Table!");
                                         // Check length and map remaining pages if needed
                                         let length = header.length as usize;
                                         if length > 4096 {
                                             let pages_needed = (length + 4095) / 4096;
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

    // 4. Idle Loop
    println!("[KERNEL] System Ready. Entering Idle Loop...");
    println!("[TEST] PASSED");

    loop {
        unsafe { sel4_sys::seL4_Yield(); }
    }
}

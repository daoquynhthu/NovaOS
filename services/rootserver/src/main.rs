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

use sel4_sys::seL4_BootInfo;
use core::arch::global_asm;
use memory::{UntypedAllocator, SlotAllocator};
use process::ProcessManager;

static mut PROCESS_MANAGER: ProcessManager = ProcessManager::new();

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

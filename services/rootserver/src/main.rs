#![no_std]
#![no_main]

mod runtime;
mod memory;

use sel4_sys::seL4_BootInfo;
use core::arch::global_asm;
use memory::{BumpAllocator, SlotAllocator};
use sel4_sys::seL4_PageBits;

// Temporary definition if missing in bindings
#[allow(non_upper_case_globals)]
// seL4_X86_4K is seL4_ModeObjectTypeCount.
// On x86_64:
// seL4_NonArchObjectTypeCount = 5
// seL4_X86_PDPTObject = 5
// seL4_X64_PML4Object = 6
// seL4_X64_HugePageObject = 7 (if CONFIG_HUGE_PAGE, which is default)
// seL4_ModeObjectTypeCount = 8
const seL4_X86_4K: sel4_sys::seL4_Word = 8; 

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
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn rust_main(boot_info_ptr: *const seL4_BootInfo) -> ! {
    // 初始化运行时（例如堆分配器，如果需要）
    
    println!("\n========================================");
    println!("   NovaOS: The Future Secure OS");
    println!("   Status: RootServer Started");
    println!("========================================");

    // 1. 获取 boot_info
    if boot_info_ptr.is_null() {
        panic!("Failed to get BootInfo! System halted.");
    }
    
    let boot_info = unsafe { &*boot_info_ptr };
    
    // Initialize IPC Buffer
    unsafe {
        sel4_sys::seL4_SetIPCBuffer(boot_info.ipcBuffer);
    }

    println!("[INFO] BootInfo retrieved successfully.");
    println!("[INFO] BootInfo Addr: {:p}", boot_info);
    println!("[INFO] IPC Buffer: {:p}", boot_info.ipcBuffer);
    println!("[INFO] Empty Slots: {} - {}", boot_info.empty.start, boot_info.empty.end);
    println!("[INFO] Untyped Slots: {} - {}", boot_info.untyped.start, boot_info.untyped.end);
    
    // Dump raw bootinfo
    let raw_ptr = boot_info as *const seL4_BootInfo as *const usize;
    for i in 0..10 {
        println!("[DEBUG] BootInfo Word {}: 0x{:x}", i, unsafe { *raw_ptr.add(i) });
    }
    println!("[INFO] Untyped Memory: {} slots", 
             boot_info.untyped.end - boot_info.untyped.start);
    println!("[INFO] CNode Size: {} bits", boot_info.initThreadCNodeSizeBits);

    // 2. 初始化内存分配器
    let mut slot_allocator = SlotAllocator::new(boot_info);
    let mut allocator = BumpAllocator::new(boot_info);
    allocator.print_info(boot_info);

    // 3. Test Allocation
    println!("[INFO] Testing allocation of 5 x 4KB Frames...");
    for i in 0..5 {
        match allocator.retype(boot_info, seL4_X86_4K.into(), seL4_PageBits.into(), &mut slot_allocator) {
           Ok(slot) => println!("[INFO] Allocated 4KB Frame #{} in slot {}", i + 1, slot),
           Err(e) => println!("[ERROR] Allocation #{} failed with error: {:?}", i + 1, e),
        }
    }

    // 4. 打印欢迎信息
    println!("[INFO] System is ready. Waiting for instructions...");

    loop {}
}

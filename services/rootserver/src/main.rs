#![no_std]
#![no_main]

use core::panic::PanicInfo;

/// RootServer 的入口点
/// seL4 会在启动后将控制权交给这里
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. 获取 boot_info
    // 2. 初始化 libnova
    // 3. 启动基础服务
    
    loop {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

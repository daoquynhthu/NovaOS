#![no_std]
#![no_main]

use libnova::env::env_logger_init;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. Initialize Logger
    // 2. Register with RootServer (if dynamic) or just start listening
    // 3. Loop: recv(IPC) -> handle_request -> reply
    
    loop {
        // Placeholder for event loop
        sel4_sys::seL4_Yield();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

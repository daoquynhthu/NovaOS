#![no_std]
#![no_main]

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. Initialize ATA Driver (moved from RootServer)
    // 2. Initialize NovaFS (moved from RootServer)
    // 3. Listen for IPC from RootServer/UserApps
    
    loop {
        // Placeholder for event loop
        sel4_sys::seL4_Yield();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub mod console;

use core::panic::PanicInfo;
use sel4_sys::seL4_IPCBuffer;

#[no_mangle]
pub static mut __sel4_ipc_buffer: *mut seL4_IPCBuffer = core::ptr::null_mut();

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    crate::println!("\n!!! NovaOS RootServer PANIC !!!");
    
    if let Some(location) = info.location() {
        crate::println!("Location: {}:{}:{}", location.file(), location.line(), location.column());
    }
    
    // PanicInfo::message() returns &PanicMessage (Display) in recent Rust
    // or we can just print the info directly which formats nicely.
    crate::println!("Panic Info: {}", info);
    
    // Legacy support if needed:
    // if let Some(message) = info.message() { ... } 
    // But since 1.81 message() returns &PanicMessage, not Option.
    // We can just rely on info's Display impl or just use message().
    // crate::println!("Message: {}", info.message());
    
    // 死循环挂起
    loop {}
}

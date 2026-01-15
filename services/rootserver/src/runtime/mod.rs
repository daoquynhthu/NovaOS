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
    
    crate::println!("Panic Info: {}", info);
    
    // 死循环挂起
    loop {}
}

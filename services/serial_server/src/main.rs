#![no_std]
#![no_main]

mod allocator;

use libnova::syscall::{
    sys_get_pid, sys_print, sys_service_lookup_exists, sys_service_register, sys_service_set_ready,
    sys_yield,
};
use sel4_sys::{seL4_CPtr, seL4_IPCBuffer};

#[no_mangle]
pub static mut __sel4_ipc_buffer: *mut seL4_IPCBuffer = 0x3000_0000 as *mut seL4_IPCBuffer;

#[no_mangle]
pub extern "C" fn _start(
    _argc: usize,
    _argv: *const *const u8,
    ep_cap_usize: usize,
    _envp: *const *const u8,
) -> ! {
    let ep_cap = ep_cap_usize as seL4_CPtr;
    libnova::console::init_console(ep_cap_usize);

    let pid = sys_get_pid(ep_cap);
    let _ = sys_service_register(ep_cap, "serial.v1", ep_cap);
    let _ = sys_service_set_ready(ep_cap, "serial.v1");

    sys_print(ep_cap, "[serial_server] booted\n");
    if sys_service_lookup_exists(ep_cap, "serial.v1") {
        sys_print(ep_cap, "[serial_server] registry visible\n");
    } else {
        sys_print(ep_cap, "[serial_server] registry missing\n");
    }

    if pid == usize::MAX {
        sys_print(ep_cap, "[serial_server] pid invalid\n");
    }

    loop {
        sys_yield(ep_cap);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

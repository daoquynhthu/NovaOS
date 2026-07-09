use core::sync::atomic::{AtomicU64, Ordering};
use sel4_sys::{seL4_CPtr, seL4_Word};

#[derive(Clone, Copy)]
pub struct PortIO {
    pub cap: seL4_CPtr,
}

impl PortIO {
    pub const fn new(cap: seL4_CPtr) -> Self {
        PortIO { cap }
    }

    pub fn in8(&self, port: u16) -> u8 {
        inb(port)
    }

    pub fn out8(&self, port: u16, value: u8) {
        outb(port, value)
    }
}

const X86_IO_PORT_CONTROL_ISSUE: seL4_Word = 45;
const X86_IO_PORT_IN8: seL4_Word = 46;
const X86_IO_PORT_IN16: seL4_Word = 47;
const X86_IO_PORT_IN32: seL4_Word = 48;
const X86_IO_PORT_OUT8: seL4_Word = 49;
const X86_IO_PORT_OUT16: seL4_Word = 50;
const X86_IO_PORT_OUT32: seL4_Word = 51;

static IO_PORT_CAP: AtomicU64 = AtomicU64::new(0);

pub fn init(cap: seL4_CPtr) {
    IO_PORT_CAP.store(cap.into(), Ordering::Release);
}

pub fn is_valid() -> bool {
    IO_PORT_CAP.load(Ordering::Acquire) != 0
}

pub fn issue_ioport_cap(
    control_cap: seL4_CPtr,
    first_port: u16,
    last_port: u16,
    root_cnode: seL4_CPtr,
    dest_index: seL4_Word,
    dest_depth: seL4_Word,
) -> Result<(), seL4_Word> {
    crate::ipc::set_cap(0, root_cnode);
    crate::ipc::set_mr(0, first_port as seL4_Word);
    crate::ipc::set_mr(1, last_port as seL4_Word);
    crate::ipc::set_mr(2, dest_index);
    crate::ipc::set_mr(3, dest_depth);

    let info = crate::ipc::MessageInfo::new(X86_IO_PORT_CONTROL_ISSUE, 0, 1, 4);
    let resp = crate::ipc::call(control_cap, info);
    let label = resp.expect("PortIO issue failed").label();
    if label == 0 {
        Ok(())
    } else {
        Err(label)
    }
}

pub fn inb(port: u16) -> u8 {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        crate::println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            crate::syscall::yield_thread();
        }
    }
    crate::ipc::set_mr(0, port as seL4_Word);
    let info = crate::ipc::MessageInfo::new(X86_IO_PORT_IN8, 0, 0, 1);
    match crate::ipc::call(cap, info) {
        Ok(msg) if msg.label() == 0 => crate::ipc::get_mr(0) as u8,
        _ => 0xFF,
    }
}

pub fn outb(port: u16, value: u8) {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        crate::println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            crate::syscall::yield_thread();
        }
    }
    crate::ipc::set_mr(0, port as seL4_Word);
    crate::ipc::set_mr(1, value as seL4_Word);
    let info = crate::ipc::MessageInfo::new(X86_IO_PORT_OUT8, 0, 0, 2);
    match crate::ipc::call(cap, info) {
        Ok(_) => {},
        Err(_) => crate::println!("[PortIO] outb failed"),
    }
}

pub fn inw(port: u16) -> u16 {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        crate::println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            crate::syscall::yield_thread();
        }
    }
    crate::ipc::set_mr(0, port as seL4_Word);
    let info = crate::ipc::MessageInfo::new(X86_IO_PORT_IN16, 0, 0, 1);
    match crate::ipc::call(cap, info) {
        Ok(msg) if msg.label() == 0 => crate::ipc::get_mr(0) as u16,
        _ => 0xFFFF,
    }
}

pub fn outw(port: u16, value: u16) {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        crate::println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            crate::syscall::yield_thread();
        }
    }
    crate::ipc::set_mr(0, port as seL4_Word);
    crate::ipc::set_mr(1, value as seL4_Word);
    let info = crate::ipc::MessageInfo::new(X86_IO_PORT_OUT16, 0, 0, 2);
    match crate::ipc::call(cap, info) {
        Ok(_) => {},
        Err(_) => crate::println!("[PortIO] outw failed"),
    }
}

pub fn inl(port: u16) -> u32 {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        crate::println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            crate::syscall::yield_thread();
        }
    }
    crate::ipc::set_mr(0, port as seL4_Word);
    let info = crate::ipc::MessageInfo::new(X86_IO_PORT_IN32, 0, 0, 1);
    match crate::ipc::call(cap, info) {
        Ok(msg) if msg.label() == 0 => crate::ipc::get_mr(0) as u32,
        _ => 0xFFFFFFFF,
    }
}

pub fn outl(port: u16, value: u32) {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        crate::println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            crate::syscall::yield_thread();
        }
    }
    crate::ipc::set_mr(0, port as seL4_Word);
    crate::ipc::set_mr(1, value as seL4_Word);
    let info = crate::ipc::MessageInfo::new(X86_IO_PORT_OUT32, 0, 0, 2);
    match crate::ipc::call(cap, info) {
        Ok(_) => {},
        Err(_) => crate::println!("[PortIO] outl failed"),
    }
}

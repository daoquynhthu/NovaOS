#![allow(dead_code)]
use sel4_sys::{seL4_CPtr, seL4_Word};
use core::sync::atomic::{AtomicU64, Ordering};

// Invocation labels from bindings.rs
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

/// Issues a new IO Port capability from the control capability.
///
/// # Arguments
/// * `control_cap` - The IO Port Control capability (usually seL4_CapIOPortControl)
/// * `first_port` - The first port in the range
/// * `last_port` - The last port in the range
/// * `root_cnode` - The root CNode capability (to store the new cap)
/// * `dest_index` - The slot index in the root CNode to store the new cap
/// * `dest_depth` - The depth of the slot
pub fn issue_ioport_cap(
    control_cap: seL4_CPtr,
    first_port: u16,
    last_port: u16,
    root_cnode: seL4_CPtr,
    dest_index: seL4_Word,
    dest_depth: seL4_Word,
) -> Result<(), seL4_Word> {
    libnova::ipc::set_cap(0, root_cnode);
    libnova::ipc::set_mr(0, first_port as seL4_Word);
    libnova::ipc::set_mr(1, last_port as seL4_Word);
    libnova::ipc::set_mr(2, dest_index);
    libnova::ipc::set_mr(3, dest_depth);

    let info = libnova::ipc::MessageInfo::new(
        X86_IO_PORT_CONTROL_ISSUE,
        0,
        1, // 1 extra cap
        4, // 4 message registers
    );

    let resp = libnova::ipc::call(control_cap, info);
    let label = resp.expect("PortIO issue failed").label();
    if label == 0 { Ok(()) } else { Err(label) }
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct PortIO {
    pub cap: seL4_CPtr,
}

#[allow(dead_code)]
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

/// Helper for port I/O using seL4 capabilities
pub fn inb(port: u16) -> u8 {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            libnova::syscall::yield_thread();
        }
    }
    
    libnova::ipc::set_mr(0, port as seL4_Word);
    
    let info = libnova::ipc::MessageInfo::new(X86_IO_PORT_IN8, 0, 0, 1);
    
    let resp = libnova::ipc::call(cap, info);
    
    if resp.expect("inb failed").label() != 0 {
        return 0xFF;
    }
    
    libnova::ipc::get_mr(0) as u8
}

/// Helper for port I/O using seL4 capabilities
pub fn outb(port: u16, value: u8) {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
             libnova::syscall::yield_thread();
        }
    }
    
    libnova::ipc::set_mr(0, port as seL4_Word);
    libnova::ipc::set_mr(1, value as seL4_Word);
    
    let info = libnova::ipc::MessageInfo::new(X86_IO_PORT_OUT8, 0, 0, 2);
    
    let resp = libnova::ipc::call(cap, info);
    
    if resp.expect("outb failed").label() != 0 {
        println!("[PortIO] outb failed");
    }
}

pub fn inw(port: u16) -> u16 {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            libnova::syscall::yield_thread();
        }
    }
    
    libnova::ipc::set_mr(0, port as seL4_Word);
    
    let info = libnova::ipc::MessageInfo::new(X86_IO_PORT_IN16, 0, 0, 1);
    
    let resp = libnova::ipc::call(cap, info);
    
    if resp.expect("inw failed").label() != 0 {
        return 0xFFFF;
    }
    
    libnova::ipc::get_mr(0) as u16
}

pub fn outw(port: u16, value: u16) {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            libnova::syscall::yield_thread();
        }
    }
    
    libnova::ipc::set_mr(0, port as seL4_Word);
    libnova::ipc::set_mr(1, value as seL4_Word);
    
    let info = libnova::ipc::MessageInfo::new(X86_IO_PORT_OUT16, 0, 0, 2);
    
    let resp = libnova::ipc::call(cap, info);
    
    if resp.expect("outl failed").label() != 0 {
        return;
    }
}

pub fn inl(port: u16) -> u32 {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            libnova::syscall::yield_thread();
        }
    }
    
    libnova::ipc::set_mr(0, port as seL4_Word);
    
    let info = libnova::ipc::MessageInfo::new(X86_IO_PORT_IN32, 0, 0, 1);
    
    let resp = libnova::ipc::call(cap, info);
    
    if resp.expect("inl failed").label() != 0 {
        return 0xFFFFFFFF;
    }
    
    libnova::ipc::get_mr(0) as u32
}

pub fn outl(port: u16, value: u32) {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            libnova::syscall::yield_thread();
        }
    }
    
    libnova::ipc::set_mr(0, port as seL4_Word);
    libnova::ipc::set_mr(1, value as seL4_Word);
    
    let info = libnova::ipc::MessageInfo::new(X86_IO_PORT_OUT32, 0, 0, 2);
    
    let resp = libnova::ipc::call(cap, info);
    
    if resp.expect("outl failed").label() != 0 {
        return;
    }
}

#![allow(dead_code)]
use sel4_sys::*;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::println;

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
    unsafe {
        seL4_SetCap_My(0, root_cnode);
        seL4_SetMR(0, first_port as seL4_Word);
        seL4_SetMR(1, last_port as seL4_Word);
        seL4_SetMR(2, dest_index);
        seL4_SetMR(3, dest_depth);

        let info = seL4_MessageInfo_new(
            X86_IO_PORT_CONTROL_ISSUE,
            0,
            1, // 1 extra cap
            4, // 4 message registers
        );

        let resp = seL4_Call(control_cap, info);
        let label = seL4_MessageInfo_get_label(resp);
        if label == 0 { Ok(()) } else { Err(label) }
    }
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
        unsafe { inb(port) }
    }

    pub fn out8(&self, port: u16, value: u8) {
        unsafe { outb(port, value) }
    }
}

/// Helper for port I/O using seL4 capabilities
pub unsafe fn inb(port: u16) -> u8 {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            seL4_Yield();
        }
    }
    
    seL4_SetMR(0, port as seL4_Word);
    
    let info = seL4_MessageInfo_new(X86_IO_PORT_IN8, 0, 0, 1);
    
    let resp = seL4_Call(cap, info);
    
    if seL4_MessageInfo_get_label(resp) != 0 {
        return 0xFF;
    }
    
    seL4_GetMR(0) as u8
}

pub unsafe fn outb(port: u16, value: u8) {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            seL4_Yield();
        }
    }
    
    seL4_SetMR(0, port as seL4_Word);
    seL4_SetMR(1, value as seL4_Word);
    
    let info = seL4_MessageInfo_new(X86_IO_PORT_OUT8, 0, 0, 2);
    
    let resp = seL4_Call(cap, info);
    
    if seL4_MessageInfo_get_label(resp) != 0 {
        return;
    }
}

pub unsafe fn inw(port: u16) -> u16 {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            seL4_Yield();
        }
    }
    
    seL4_SetMR(0, port as seL4_Word);
    
    let info = seL4_MessageInfo_new(X86_IO_PORT_IN16, 0, 0, 1);
    
    let resp = seL4_Call(cap, info);
    
    if seL4_MessageInfo_get_label(resp) != 0 {
        return 0xFFFF;
    }
    
    seL4_GetMR(0) as u16
}

pub unsafe fn outw(port: u16, value: u16) {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            seL4_Yield();
        }
    }
    
    seL4_SetMR(0, port as seL4_Word);
    seL4_SetMR(1, value as seL4_Word);
    
    let info = seL4_MessageInfo_new(X86_IO_PORT_OUT16, 0, 0, 2);
    
    let resp = seL4_Call(cap, info);
    
    if seL4_MessageInfo_get_label(resp) != 0 {
        return;
    }
}

pub unsafe fn inl(port: u16) -> u32 {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            seL4_Yield();
        }
    }
    
    seL4_SetMR(0, port as seL4_Word);
    
    let info = seL4_MessageInfo_new(X86_IO_PORT_IN32, 0, 0, 1);
    
    let resp = seL4_Call(cap, info);
    
    if seL4_MessageInfo_get_label(resp) != 0 {
        return 0xFFFFFFFF;
    }
    
    seL4_GetMR(0) as u32
}

pub unsafe fn outl(port: u16, value: u32) {
    let cap = IO_PORT_CAP.load(Ordering::Acquire) as seL4_CPtr;
    if cap == 0 {
        println!("[SECURITY] Port I/O attempted without IOPort capability");
        loop {
            seL4_Yield();
        }
    }
    
    seL4_SetMR(0, port as seL4_Word);
    seL4_SetMR(1, value as seL4_Word);
    
    let info = seL4_MessageInfo_new(X86_IO_PORT_OUT32, 0, 0, 2);
    
    let resp = seL4_Call(cap, info);
    
    if seL4_MessageInfo_get_label(resp) != 0 {
        return;
    }
}

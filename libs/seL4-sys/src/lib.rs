#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

// Include generated bindings
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// Helper types
pub type SeL4Error = seL4_Error;
pub type SeL4Result = Result<(), SeL4Error>;

// Re-export common types
pub use self::seL4_BootInfo as BootInfo;
pub use self::seL4_CapRights as CapRights;
pub use self::seL4_MessageInfo as MessageInfo;

impl From<i32> for seL4_Error {
    fn from(code: i32) -> Self {
        unsafe { core::mem::transmute(code) }
    }
}

// --------------------------------------------------------------------------------
// Manual Implementations of Static Inline Functions (x86_64)
// --------------------------------------------------------------------------------

// seL4_MessageInfo helpers
pub fn seL4_MessageInfo_new(
    label: seL4_Word,
    capsUnwrapped: seL4_Word,
    extraCaps: seL4_Word,
    length: seL4_Word,
) -> seL4_MessageInfo {
    seL4_MessageInfo {
        words: [
            (label << 12)
            | ((capsUnwrapped & 0x7) << 9)
            | ((extraCaps & 0x3) << 7)
            | (length & 0x7f),
        ],
    }
}

pub fn seL4_MessageInfo_get_label(info: seL4_MessageInfo) -> seL4_Word {
    info.words[0] >> 12
}

pub fn seL4_MessageInfo_get_length(info: seL4_MessageInfo) -> seL4_Word {
    info.words[0] & 0x7f
}

#[inline(always)]
pub unsafe fn seL4_GetIPCBuffer() -> *mut seL4_IPCBuffer {
    __sel4_ipc_buffer
}

pub unsafe fn seL4_SetIPCBuffer(ptr: *mut seL4_IPCBuffer) {
    __sel4_ipc_buffer = ptr;
}

pub unsafe fn seL4_SetMR(i: usize, v: seL4_Word) {
    if !__sel4_ipc_buffer.is_null() {
        (*__sel4_ipc_buffer).msg[i] = v;
    }
}

pub unsafe fn seL4_SetCap_My(i: usize, cptr: seL4_CPtr) {
    if !__sel4_ipc_buffer.is_null() {
        (*__sel4_ipc_buffer).caps_or_badges[i] = cptr;
    }
}

pub unsafe fn seL4_GetMR(i: usize) -> seL4_Word {
    if !__sel4_ipc_buffer.is_null() {
        (*__sel4_ipc_buffer).msg[i]
    } else {
        0
    }
}

pub unsafe fn seL4_Call(dest: seL4_CPtr, msgInfo: seL4_MessageInfo) -> seL4_MessageInfo {
    let mut info_val = msgInfo.words[0];
    let mut mr0 = seL4_GetMR(0);
    let mut mr1 = seL4_GetMR(1);
    let mut mr2 = seL4_GetMR(2);
    let mut mr3 = seL4_GetMR(3);
    let _badge: seL4_Word;
    
    // seL4_SysCall constant from bindings
    
    core::arch::asm!(
        "push rbx",       // Save RBX (callee-saved)
        "mov rbx, rsp",   // Save RSP to RBX
        "syscall",
        "mov rsp, rbx",   // Restore RSP from RBX
        "pop rbx",        // Restore RBX
        in("rdx") seL4_Syscall_ID_seL4_SysCall, 
        in("rdi") dest,
        inout("rsi") info_val,
        inout("r10") mr0,
        inout("r8") mr1,
        inout("r9") mr2,
        inout("r15") mr3,
        lateout("rdi") _badge,
        out("rcx") _,
        out("r11") _,
        // out("rbx") _, // removed
    );

    seL4_SetMR(0, mr0);
    seL4_SetMR(1, mr1);
    seL4_SetMR(2, mr2);
    seL4_SetMR(3, mr3);

    seL4_MessageInfo { words: [info_val] }
}

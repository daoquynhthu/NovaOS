#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

// Include generated bindings
mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
pub use bindings::*;

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

pub unsafe fn seL4_CallWithMRs(
    dest: seL4_CPtr,
    msgInfo: seL4_MessageInfo,
    mr0: seL4_Word,
    mr1: seL4_Word,
    mr2: seL4_Word,
    mr3: seL4_Word,
) -> (seL4_MessageInfo, seL4_Word, seL4_Word, seL4_Word, seL4_Word, seL4_Word) {
    let mut info_val = msgInfo.words[0];
    let mut out_mr0 = mr0;
    let mut out_mr1 = mr1;
    let mut out_mr2 = mr2;
    let mut out_mr3 = mr3;
    let badge: seL4_Word;

    core::arch::asm!(
        "push rbx",
        "mov rbx, rsp",
        "syscall",
        "mov rsp, rbx",
        "pop rbx",
        in("rdx") seL4_Syscall_ID_seL4_SysCall,
        in("rdi") dest,
        inout("rsi") info_val,
        inout("r10") out_mr0,
        inout("r8") out_mr1,
        inout("r9") out_mr2,
        inout("r15") out_mr3,
        lateout("rdi") badge,
        out("rcx") _,
        out("r11") _,
    );

    (
        seL4_MessageInfo { words: [info_val] },
        badge,
        out_mr0,
        out_mr1,
        out_mr2,
        out_mr3,
    )
}

pub unsafe fn seL4_RecvWithMRs(
    src: seL4_CPtr,
    sender: *mut seL4_Word,
) -> (seL4_MessageInfo, seL4_Word, seL4_Word, seL4_Word, seL4_Word) {
    let mut info_val: seL4_Word = 0;
    let badge: seL4_Word;
    let mut out_mr0: seL4_Word = 0;
    let mut out_mr1: seL4_Word = 0;
    let mut out_mr2: seL4_Word = 0;
    let mut out_mr3: seL4_Word = 0;

    core::arch::asm!(
        "push rbx",
        "mov rbx, rsp",
        "syscall",
        "mov rsp, rbx",
        "pop rbx",
        in("rdx") seL4_Syscall_ID_seL4_SysRecv,
        in("rdi") src,
        inout("rsi") info_val,
        lateout("r10") out_mr0,
        lateout("r8") out_mr1,
        lateout("r9") out_mr2,
        lateout("r15") out_mr3,
        lateout("rdi") badge,
        out("rcx") _,
        out("r11") _,
    );

    if !sender.is_null() {
        *sender = badge;
    }

    (
        seL4_MessageInfo { words: [info_val] },
        out_mr0,
        out_mr1,
        out_mr2,
        out_mr3,
    )
}

pub unsafe fn seL4_ReplyRecvWithMRs(
    src: seL4_CPtr,
    msgInfo: seL4_MessageInfo,
    sender: *mut seL4_Word,
    mr0: seL4_Word,
    mr1: seL4_Word,
    mr2: seL4_Word,
    mr3: seL4_Word,
) -> (seL4_MessageInfo, seL4_Word, seL4_Word, seL4_Word, seL4_Word) {
    let mut info_val = msgInfo.words[0];
    let badge: seL4_Word;
    let mut out_mr0 = mr0;
    let mut out_mr1 = mr1;
    let mut out_mr2 = mr2;
    let mut out_mr3 = mr3;

    core::arch::asm!(
        "push rbx",
        "mov rbx, rsp",
        "syscall",
        "mov rsp, rbx",
        "pop rbx",
        in("rdx") seL4_Syscall_ID_seL4_SysReplyRecv,
        in("rdi") src,
        inout("rsi") info_val,
        inout("r10") out_mr0,
        inout("r8") out_mr1,
        inout("r9") out_mr2,
        inout("r15") out_mr3,
        lateout("rdi") badge,
        out("rcx") _,
        out("r11") _,
    );

    if !sender.is_null() {
        *sender = badge;
    }

    (
        seL4_MessageInfo { words: [info_val] },
        out_mr0,
        out_mr1,
        out_mr2,
        out_mr3,
    )
}

pub unsafe fn seL4_Recv(src: seL4_CPtr, sender: *mut seL4_Word) -> seL4_MessageInfo {
    let mut info_val: seL4_Word = 0;
    let mut badge: seL4_Word;
    let mut mr0: seL4_Word = 0;
    let mut mr1: seL4_Word = 0;
    let mut mr2: seL4_Word = 0;
    let mut mr3: seL4_Word = 0;

    core::arch::asm!(
        "push rbx",
        "mov rbx, rsp",
        "syscall",
        "mov rsp, rbx",
        "pop rbx",
        in("rdx") seL4_Syscall_ID_seL4_SysRecv,
        in("rdi") src,
        inout("rsi") info_val,
        lateout("r10") mr0,
        lateout("r8") mr1,
        lateout("r9") mr2,
        lateout("r15") mr3,
        lateout("rdi") badge,
        out("rcx") _,
        out("r11") _,
    );

    if !sender.is_null() {
        *sender = badge;
    }

    seL4_SetMR(0, mr0);
    seL4_SetMR(1, mr1);
    seL4_SetMR(2, mr2);
    seL4_SetMR(3, mr3);

    seL4_MessageInfo { words: [info_val] }
}

pub unsafe fn seL4_ReplyRecv(src: seL4_CPtr, msgInfo: seL4_MessageInfo, sender: *mut seL4_Word) -> seL4_MessageInfo {
    let mut info_val = msgInfo.words[0];
    let mut badge: seL4_Word;
    
    let mut mr0 = seL4_GetMR(0);
    let mut mr1 = seL4_GetMR(1);
    let mut mr2 = seL4_GetMR(2);
    let mut mr3 = seL4_GetMR(3);

    core::arch::asm!(
        "push rbx",
        "mov rbx, rsp",
        "syscall",
        "mov rsp, rbx",
        "pop rbx",
        in("rdx") seL4_Syscall_ID_seL4_SysReplyRecv,
        in("rdi") src,
        inout("rsi") info_val,
        inout("r10") mr0,
        inout("r8") mr1,
        inout("r9") mr2,
        inout("r15") mr3,
        lateout("rdi") badge,
        out("rcx") _,
        out("r11") _,
    );

    if !sender.is_null() {
        *sender = badge;
    }

    seL4_SetMR(0, mr0);
    seL4_SetMR(1, mr1);
    seL4_SetMR(2, mr2);
    seL4_SetMR(3, mr3);

    seL4_MessageInfo { words: [info_val] }
}

pub unsafe fn seL4_CNode_Mint(
    service: seL4_CPtr,
    dest_index: seL4_Word,
    dest_depth: u8,
    src_root: seL4_CPtr,
    src_index: seL4_Word,
    src_depth: u8,
    rights: seL4_CapRights,
    badge: seL4_Word,
) -> seL4_Error {
    // Hardcoded invocation label for seL4_CNode_Mint
        // Based on seL4 XML: Revoke=17, Delete=18, CancelBadgedSends=19, Copy=20, Mint=21
        const SE_L4_CNODE_MINT: seL4_Word = 21;

    let info = seL4_MessageInfo_new(
        SE_L4_CNODE_MINT, // Label = Method ID
        0, // capsUnwrapped
        1, // extraCaps (src_root)
        6, // length
    );

    seL4_SetMR(0, dest_index);
    seL4_SetMR(1, dest_depth as seL4_Word);
    seL4_SetMR(2, src_index);
    seL4_SetMR(3, src_depth as seL4_Word);
    seL4_SetMR(4, rights.words[0]);
    seL4_SetMR(5, badge);
    
    seL4_SetCap_My(0, src_root);

    let dest_info = seL4_Call(service, info);
    seL4_Error::from(seL4_MessageInfo_get_label(dest_info) as i32)
}

pub unsafe fn seL4_Yield() {
    core::arch::asm!(
        "syscall",
        in("rdx") seL4_Syscall_ID_seL4_SysYield,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
}

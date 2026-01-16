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
/// # Safety
/// `__sel4_ipc_buffer` must be initialized to a valid seL4 IPC buffer pointer
/// for the current thread, as required by the seL4 ABI.
pub unsafe fn seL4_GetIPCBuffer() -> *mut seL4_IPCBuffer {
    __sel4_ipc_buffer
}

/// # Safety
/// `ptr` must either be null (to disable IPC-buffer-backed operations) or a
/// valid seL4 IPC buffer pointer for the current thread, as required by the
/// seL4 ABI.
pub unsafe fn seL4_SetIPCBuffer(ptr: *mut seL4_IPCBuffer) {
    __sel4_ipc_buffer = ptr;
}

/// # Safety
/// - `__sel4_ipc_buffer` must be null or a valid seL4 IPC buffer pointer.
/// - If `__sel4_ipc_buffer` is non-null, `i` must be in-bounds for the IPC
///   buffer message register array.
pub unsafe fn seL4_SetMR(i: usize, v: seL4_Word) {
    if !__sel4_ipc_buffer.is_null() {
        (*__sel4_ipc_buffer).msg[i] = v;
    }
}

/// # Safety
/// - `__sel4_ipc_buffer` must be null or a valid seL4 IPC buffer pointer.
/// - If `__sel4_ipc_buffer` is non-null, `i` must be in-bounds for the IPC
///   buffer capability slot array.
pub unsafe fn seL4_SetCap_My(i: usize, cptr: seL4_CPtr) {
    if !__sel4_ipc_buffer.is_null() {
        (*__sel4_ipc_buffer).caps_or_badges[i] = cptr;
    }
}

/// # Safety
/// - `__sel4_ipc_buffer` must be null or a valid seL4 IPC buffer pointer.
/// - If `__sel4_ipc_buffer` is non-null, `i` must be in-bounds for the IPC
///   buffer message register array.
pub unsafe fn seL4_GetMR(i: usize) -> seL4_Word {
    if !__sel4_ipc_buffer.is_null() {
        (*__sel4_ipc_buffer).msg[i]
    } else {
        0
    }
}

/// # Safety
/// - Must only be called in a seL4 user context on x86_64 using the seL4 syscall ABI.
/// - `dest` must be a valid capability pointer for the expected invocation.
/// - If this call expects to read/write message registers or extra caps, the
///   IPC buffer must be initialized appropriately via `seL4_SetIPCBuffer`.
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

/// # Safety
/// - Must only be called in a seL4 user context on x86_64 using the seL4 syscall ABI.
/// - `dest` must be a valid capability pointer for the expected invocation.
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

/// # Safety
/// - Must only be called in a seL4 user context on x86_64 using the seL4 syscall ABI.
/// - `src` must be a valid capability pointer for a receive endpoint.
/// - `sender` must be null or point to valid writable memory for a `seL4_Word`.
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

/// # Safety
/// Same requirements as `seL4_RecvWithMRs`.
pub unsafe fn seL4_Wait(src: seL4_CPtr, sender: *mut seL4_Word) {
    let _ = seL4_RecvWithMRs(src, sender);
}

/// # Safety
/// - Must only be called in a seL4 user context on x86_64 using the seL4 syscall ABI.
/// - `src` must be a valid capability pointer for a receive endpoint.
/// - `sender` must be null or point to valid writable memory for a `seL4_Word`.
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

/// # Safety
/// - Must only be called in a seL4 user context on x86_64 using the seL4 syscall ABI.
/// - `src` must be a valid capability pointer for a receive endpoint.
/// - `sender` must be null or point to valid writable memory for a `seL4_Word`.
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

/// # Safety
/// - Must only be called in a seL4 user context on x86_64 using the seL4 syscall ABI.
/// - `src` must be a valid capability pointer for a receive endpoint.
/// - `sender` must be null or point to valid writable memory for a `seL4_Word`.
/// - If this call expects to read/write message registers or extra caps, the
///   IPC buffer must be initialized appropriately via `seL4_SetIPCBuffer`.
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

#[allow(clippy::too_many_arguments)]
/// # Safety
/// - Must only be called in a seL4 user context on x86_64 using the seL4 syscall ABI.
/// - `service` must be a valid CNode capability pointer.
/// - `src_root` must be a valid capability pointer for the source CNode.
/// - All indices and depths must follow seL4 CSpace addressing rules for the
///   provided CNodes.
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

/// # Safety
/// Must only be called in a seL4 user context on x86_64 using the seL4 syscall ABI.
pub unsafe fn seL4_Yield() {
    core::arch::asm!(
        "syscall",
        in("rdx") seL4_Syscall_ID_seL4_SysYield,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
}

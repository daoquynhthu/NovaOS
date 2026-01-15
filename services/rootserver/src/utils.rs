use sel4_sys::{
    seL4_CapRights, seL4_Word, seL4_CPtr, seL4_Error,
    seL4_MessageInfo_new, seL4_SetMR, seL4_Call, seL4_MessageInfo_get_label, seL4_SetCap_My
};

// Helper for CapRights (missing in bindings)
#[allow(non_snake_case)]
pub fn seL4_CapRights_new(grant_reply: u64, grant: u64, read: u64, write: u64) -> seL4_CapRights {
    let word = ((grant_reply & 0x1) << 3)
             | ((grant & 0x1) << 2)
             | ((read & 0x1) << 1)
             | (write & 0x1);
    seL4_CapRights { words: [word] }
}

// Temporary definition if missing in bindings
#[allow(non_upper_case_globals)]
pub const seL4_X86_4K: seL4_Word = 8; 

// Helper for Copying Capabilities
pub unsafe fn copy_cap(
    dest_root: seL4_CPtr,
    dest_index: seL4_Word,
    dest_depth: u8,
    src_root: seL4_CPtr,
    src_index: seL4_Word,
    src_depth: u8,
    rights: seL4_CapRights,
) -> seL4_Error {
    const SE_L4_CNODE_COPY: seL4_Word = 20;

    let info = seL4_MessageInfo_new(
        SE_L4_CNODE_COPY,
        0,
        1, // extraCaps (src_root)
        5, // length (no badge)
    );

    seL4_SetMR(0, dest_index);
    seL4_SetMR(1, dest_depth as seL4_Word);
    seL4_SetMR(2, src_index);
    seL4_SetMR(3, src_depth as seL4_Word);
    seL4_SetMR(4, rights.words[0]);
    
    seL4_SetCap_My(0, src_root);

    let dest_info = seL4_Call(dest_root, info);
    seL4_Error::from(seL4_MessageInfo_get_label(dest_info) as i32)
}

// Helper for Deleting Capabilities
#[allow(non_snake_case)]
pub unsafe fn seL4_CNode_Delete(
    service: seL4_CPtr,
    index: seL4_Word,
    depth: u8,
) -> seL4_Error {
    const SE_L4_CNODE_DELETE: seL4_Word = 18;
    
    let info = seL4_MessageInfo_new(
        SE_L4_CNODE_DELETE,
        0,
        0,
        2,
    );

    seL4_SetMR(0, index);
    seL4_SetMR(1, depth as seL4_Word);

    let dest_info = seL4_Call(service, info);
    seL4_Error::from(seL4_MessageInfo_get_label(dest_info) as i32)
}

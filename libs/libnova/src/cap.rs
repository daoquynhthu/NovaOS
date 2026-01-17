use sel4_sys::*;
use crate::syscall::{Result, check_err};

// Import invocation labels
// Note: If these are missing, we might need to hardcode them based on architecture
// x86_64: Revoke=17? No, bindings usually export invocation_label_...
use sel4_sys::{
    invocation_label_CNodeCopy,
    invocation_label_CNodeMint,
    invocation_label_CNodeMove,
    invocation_label_CNodeDelete,
    invocation_label_CNodeRevoke,
};

/// Wrapper for CNode operations
#[derive(Debug, Clone, Copy)]
pub struct CNode {
    pub cptr: seL4_CPtr,
    pub depth: u8,
}

impl CNode {
    /// Create a new CNode wrapper
    pub fn new(cptr: seL4_CPtr, depth: u8) -> Self {
        Self { cptr, depth }
    }

    /// Copy a capability
    pub fn copy(
        &self,
        dest_index: seL4_Word,
        src_root: &CNode,
        src_index: seL4_Word,
        rights: seL4_CapRights,
    ) -> Result<()> {
        unsafe {
            let info = seL4_MessageInfo_new(
                invocation_label_CNodeCopy as seL4_Word,
                0,
                1, // extraCaps (src_root)
                5, // length
            );

            seL4_SetMR(0, dest_index);
            seL4_SetMR(1, self.depth as seL4_Word); // dest_depth
            seL4_SetMR(2, src_index);
            seL4_SetMR(3, src_root.depth as seL4_Word); // src_depth
            seL4_SetMR(4, rights.words[0]);

            seL4_SetCap_My(0, src_root.cptr);

            let dest_info = seL4_Call(self.cptr, info);
            check_err(seL4_Error::from(seL4_MessageInfo_get_label(dest_info) as i32))
        }
    }

    /// Mint a capability (Copy with modified rights/badge)
    pub fn mint(
        &self,
        dest_index: seL4_Word,
        src_root: &CNode,
        src_index: seL4_Word,
        rights: seL4_CapRights,
        badge: seL4_Word,
    ) -> Result<()> {
        unsafe {
            let info = seL4_MessageInfo_new(
                invocation_label_CNodeMint as seL4_Word,
                0,
                1, // extraCaps
                6, // length
            );

            seL4_SetMR(0, dest_index);
            seL4_SetMR(1, self.depth as seL4_Word);
            seL4_SetMR(2, src_index);
            seL4_SetMR(3, src_root.depth as seL4_Word);
            seL4_SetMR(4, rights.words[0]);
            seL4_SetMR(5, badge);

            seL4_SetCap_My(0, src_root.cptr);

            let dest_info = seL4_Call(self.cptr, info);
            check_err(seL4_Error::from(seL4_MessageInfo_get_label(dest_info) as i32))
        }
    }

    /// Move a capability
    pub fn move_(
        &self,
        dest_index: seL4_Word,
        src_root: &CNode,
        src_index: seL4_Word,
    ) -> Result<()> {
        unsafe {
            let info = seL4_MessageInfo_new(
                invocation_label_CNodeMove as seL4_Word,
                0,
                1, // extraCaps
                4, // length
            );

            seL4_SetMR(0, dest_index);
            seL4_SetMR(1, self.depth as seL4_Word);
            seL4_SetMR(2, src_index);
            seL4_SetMR(3, src_root.depth as seL4_Word);

            seL4_SetCap_My(0, src_root.cptr);

            let dest_info = seL4_Call(self.cptr, info);
            check_err(seL4_Error::from(seL4_MessageInfo_get_label(dest_info) as i32))
        }
    }

    /// Delete a capability
    pub fn delete(&self, index: seL4_Word) -> Result<()> {
        unsafe {
            let info = seL4_MessageInfo_new(
                invocation_label_CNodeDelete as seL4_Word,
                0,
                0, // extraCaps
                2, // length
            );

            seL4_SetMR(0, index);
            seL4_SetMR(1, self.depth as seL4_Word);

            let dest_info = seL4_Call(self.cptr, info);
            check_err(seL4_Error::from(seL4_MessageInfo_get_label(dest_info) as i32))
        }
    }

    /// Revoke a capability
    pub fn revoke(&self, index: seL4_Word) -> Result<()> {
        unsafe {
            let info = seL4_MessageInfo_new(
                invocation_label_CNodeRevoke as seL4_Word,
                0,
                0, // extraCaps
                2, // length
            );

            seL4_SetMR(0, index);
            seL4_SetMR(1, self.depth as seL4_Word);

            let dest_info = seL4_Call(self.cptr, info);
            check_err(seL4_Error::from(seL4_MessageInfo_get_label(dest_info) as i32))
        }
    }

    /// Save the reply capability of the caller
    pub fn save_caller(&self, index: seL4_Word) -> Result<()> {
        unsafe {
            // invocation_label_CNodeSaveCaller usually 25
            const SE_L4_CNODE_SAVECALLER: seL4_Word = 25;
            let info = seL4_MessageInfo_new(
                SE_L4_CNODE_SAVECALLER,
                0,
                0,
                2,
            );

            seL4_SetMR(0, index);
            seL4_SetMR(1, self.depth as seL4_Word);

            let dest_info = seL4_Call(self.cptr, info);
            check_err(seL4_Error::from(seL4_MessageInfo_get_label(dest_info) as i32))
        }
    }
}

/// Retype an untyped capability
#[allow(clippy::too_many_arguments)]
pub fn untyped_retype(
    service: seL4_CPtr,
    type_: seL4_Word,
    size_bits: seL4_Word,
    root: &CNode,
    node_index: seL4_Word,
    node_depth: seL4_Word,
    node_offset: seL4_Word,
    num_objects: seL4_Word,
) -> Result<()> {
    unsafe {
        const SE_L4_UNTYPED_RETYPE: seL4_Word = 1;
        
        let info = seL4_MessageInfo_new(SE_L4_UNTYPED_RETYPE, 0, 1, 7);
        seL4_SetMR(0, type_);
        seL4_SetMR(1, size_bits);
        seL4_SetCap_My(0, root.cptr);
        seL4_SetMR(2, node_index);
        seL4_SetMR(3, node_depth);
        seL4_SetMR(4, node_offset);
        seL4_SetMR(5, num_objects);
        
        let dest_info = seL4_Call(service, info);
        check_err(seL4_Error::from(seL4_MessageInfo_get_label(dest_info) as i32))
    }
}



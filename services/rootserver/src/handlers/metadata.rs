//! Metadata syscall handlers (uid/gid).
//!
//! `chmod`/`chown`/`symlink`/`readlink` are handled in `handlers::fs` because
//! they operate on the NovaFS data plane.

use crate::handlers::SyscallContext;
use crate::process::get_process_manager;
use libnova::ipc::MessageInfo;
use libnova::validate::ValidateError;

fn validate_one_mr(ctx: &SyscallContext<'_>) -> Result<(), ValidateError> {
    libnova::validate::validate_message_length(ctx.info)?;
    libnova::validate::validate_mr_index(ctx.info, 0)?;
    Ok(())
}

fn error_reply() -> (MessageInfo, [u64; 4], bool) {
    let mut reply_mrs = [0u64; 4];
    reply_mrs[0] = (-1i64) as u64;
    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

/// Handle `sys_getuid() -> uid`.
pub fn handle_getuid(ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    let mut reply_mrs = [0u64; 4];
    reply_mrs[0] = get_process_manager()
        .get_process(ctx.pid)
        .map(|p| p.uid as u64)
        .unwrap_or(0);
    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

/// Handle `sys_setuid(uid) -> 0/-1`.
pub fn handle_setuid(ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    if let Err(_e) = validate_one_mr(ctx) {
        return error_reply();
    }

    let new_uid = ctx.mrs[0] as u32;
    let mut res = -1i64;
    if let Some(p) = get_process_manager().get_process_mut(ctx.pid) {
        if p.uid == 0 {
            p.uid = new_uid;
            res = 0;
        }
    }
    let mut reply_mrs = [0u64; 4];
    reply_mrs[0] = res as u64;
    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

/// Handle `sys_getgid() -> gid`.
pub fn handle_getgid(ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    let mut reply_mrs = [0u64; 4];
    reply_mrs[0] = get_process_manager()
        .get_process(ctx.pid)
        .map(|p| p.gid as u64)
        .unwrap_or(0);
    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

/// Handle `sys_setgid(gid) -> 0/-1`.
pub fn handle_setgid(ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    if let Err(_e) = validate_one_mr(ctx) {
        return error_reply();
    }

    let new_gid = ctx.mrs[0] as u32;
    let mut res = -1i64;
    if let Some(p) = get_process_manager().get_process_mut(ctx.pid) {
        if p.uid == 0 {
            p.gid = new_gid;
            res = 0;
        }
    }
    let mut reply_mrs = [0u64; 4];
    reply_mrs[0] = res as u64;
    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

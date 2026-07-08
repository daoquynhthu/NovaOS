//! Service registry and system syscall handlers.
//!
//! Covers service registration/lookup/ready, filesystem view epoch,
//! wall-clock time, shutdown, and the system tick query.

use crate::handlers::SyscallContext;
use libnova::ipc::MessageInfo;
use libnova::validate::ValidateError;
use sel4_sys::seL4_CPtr;

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

/// Read a length-prefixed name from the IPC message starting at MR0/MR1.
///
/// Returns `Err` if the declared name length does not fit inside the message.
fn read_name_from_ipc(ctx: &SyscallContext<'_>) -> Result<alloc::string::String, ValidateError> {
    let len = ctx.mrs[0] as usize;
    let name_words = len.div_ceil(8);
    if name_words > 0 {
        let last_idx = 1 + name_words - 1;
        libnova::validate::validate_mr_index(ctx.info, last_idx)?;
    }

    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };
    let msg_len = ctx.info.length() as usize;
    let mut name_bytes = alloc::vec::Vec::with_capacity(len);
    let mut current_len = 0usize;
    let mut word_idx = 1usize;
    while current_len < len && word_idx < msg_len {
        let word = if word_idx < 4 {
            ctx.mrs[word_idx]
        } else {
            ipc_buf.msg[word_idx]
        };
        let bytes = word.to_le_bytes();
        for b in bytes.iter() {
            if current_len < len {
                name_bytes.push(*b);
                current_len += 1;
            }
        }
        word_idx += 1;
    }
    Ok(alloc::string::String::from_utf8(name_bytes).unwrap_or_default())
}

/// Handle `sys_service_register(name, cap) -> 0/1/2`.
pub fn handle_service_register(ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    if validate_one_mr(ctx).is_err() {
        return error_reply();
    }
    if libnova::validate::validate_cap_index(ctx.info, 0).is_err() {
        return error_reply();
    }

    let name_str = match read_name_from_ipc(ctx) {
        Ok(name) => name,
        Err(_) => return error_reply(),
    };
    let mut reply_mrs = [0u64; 4];

    unsafe {
        if sel4_sys::seL4_MessageInfo_get_extraCaps(ctx.info.inner) > 0 {
            let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
            let cnode_depth = sel4_sys::seL4_WordBits as u8;

            let new_slot = ctx
                .slot_allocator
                .alloc()
                .expect("Failed to alloc slot for service");
            let err = sel4_sys::seL4_CNode_Move(
                root_cnode,
                new_slot,
                cnode_depth,
                root_cnode,
                ctx.syscall_recv_slot,
                cnode_depth,
            );
            if err == 0.into() {
                crate::services::register(&name_str, new_slot);
                println!("[KERNEL] Service '{}' registered via syscall.", name_str);
                reply_mrs[0] = 0;
            } else {
                println!("[KERNEL] Failed to move service cap: {:?}", err);
                reply_mrs[0] = 1;
            }
        } else {
            reply_mrs[0] = 2; // No cap
        }
    }

    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

/// Handle `sys_service_lookup(name) -> cap`.
pub fn handle_service_lookup(ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    if validate_one_mr(ctx).is_err() {
        return error_reply();
    }

    let name_str = match read_name_from_ipc(ctx) {
        Ok(name) => name,
        Err(_) => return error_reply(),
    };
    let reply_mrs = [0u64; 4];

    if let Some(ep) = crate::services::lookup(&name_str) {
        libnova::ipc::set_cap(0, ep);
        (MessageInfo::new(0, 0, 1, 0), reply_mrs, true) // 1 Extra Cap
    } else if let Some((resolved_name, ep, _version)) = crate::services::lookup_latest(&name_str) {
        libnova::ipc::set_cap(0, ep);
        println!(
            "[KERNEL] Service lookup '{}' resolved to '{}'",
            name_str, resolved_name
        );
        (MessageInfo::new(0, 0, 1, 0), reply_mrs, true) // 1 Extra Cap
    } else {
        (MessageInfo::new(0, 0, 0, 0), reply_mrs, true) // Error
    }
}

/// Handle `sys_service_set_ready(name) -> 0/1`.
pub fn handle_service_set_ready(ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    if validate_one_mr(ctx).is_err() {
        return error_reply();
    }

    let name_str = match read_name_from_ipc(ctx) {
        Ok(name) => name,
        Err(_) => return error_reply(),
    };
    let mut reply_mrs = [0u64; 4];

    if crate::services::mark_ready(&name_str) {
        println!("[KERNEL] Service '{}' marked ready.", name_str);
        reply_mrs[0] = 0;
    } else {
        println!(
            "[KERNEL] Service '{}' ready signal ignored (not registered).",
            name_str
        );
        reply_mrs[0] = 1;
    }

    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

/// Handle `sys_fs_view_epoch() -> epoch`.
pub fn handle_fs_view_epoch(_ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    let mut reply_mrs = [0u64; 4];
    reply_mrs[0] = crate::services::current_fs_view_epoch();
    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

/// Handle `sys_get_time() -> system_tick`.
pub fn handle_get_time(system_tick: u64) -> (MessageInfo, [u64; 4], bool) {
    let mut reply_mrs = [0u64; 4];
    reply_mrs[0] = system_tick;
    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

/// Handle `sys_get_unix_time() -> unix_timestamp`.
pub fn handle_get_unix_time(_ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    let ts = crate::drivers::rtc::RtcDriver::new().get_unix_timestamp();
    novafs_core::set_wall_clock(ts);
    let mut reply_mrs = [0u64; 4];
    reply_mrs[0] = ts;
    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

/// Handle `sys_shutdown()`.
///
/// This handler never returns a reply; it powers off the machine.
pub fn handle_shutdown(ctx: &mut SyscallContext<'_>) -> ! {
    let _ = validate_one_mr(ctx);
    println!("[KERNEL] Process {} requested system shutdown.", ctx.pid);
    crate::acpi::shutdown();
}

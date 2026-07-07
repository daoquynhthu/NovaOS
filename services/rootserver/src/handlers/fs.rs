//! File-system syscall handlers.
//!
//! These handlers implement the RootServer side of the NovaFS syscall
//! interface: open/read/write/close and the directory/permission helpers.
//! They live in a dedicated module so the giant dispatch `match` in
//! `main.rs` stays readable.

use crate::handlers::SyscallContext;
use crate::process::{get_process_manager, FileMode};
use libnova::fs_ipc::FsLabel;
use libnova::ipc::MessageInfo;
use libnova::validate::ValidateError;
use novafs_core::BlockDevice;
use sel4_sys::{seL4_CPtr, seL4_Word};

const MAX_PATH_LEN: usize = 256;
const MAX_READ_LEN: usize = 900;
const MAX_BLOCK_LEN: usize = 512;

/// Copy payload bytes into the IPC buffer right after MR0.
///
/// Used by syscalls that return a variable-length byte payload (read,
/// readlink, block_read). The caller is responsible for setting the reply
/// message length to `1 + payload_words` and for setting `manual_reply`.
fn copy_bytes_to_ipc_after_mr0(data: &[u8]) {
    let ipc_buf = unsafe { &mut *sel4_sys::seL4_GetIPCBuffer() };
    let offset = core::mem::size_of::<seL4_Word>();
    let msg_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (ipc_buf.msg.as_mut_ptr() as *mut u8).add(offset),
            data.len(),
        )
    };
    msg_bytes.copy_from_slice(data);
}

/// Resolve the current fs_server endpoint if it has been registered and is
/// ready.
fn resolve_fs_service_endpoint() -> Option<seL4_CPtr> {
    if let Some(ep) = crate::services::lookup_ready("fs.v1") {
        return Some(ep);
    }
    if let Some(ep) = crate::services::lookup_ready("fs") {
        return Some(ep);
    }
    crate::services::lookup_latest_ready("fs").map(|(_, ep, _)| ep)
}

/// Look up the remote FD that fs_server uses for a local process FD.
fn lookup_remote_fd(pid: usize, fd: usize) -> Option<usize> {
    let pm = get_process_manager();
    let process = pm.get_process(pid)?;
    if fd >= process.fds.len() {
        return None;
    }
    process.fds[fd].as_ref().and_then(|desc| desc.remote_fd)
}

/// Returns whether synchronous FS forwarding is enabled for `pid`.
fn fs_forwarding_enabled_for_pid(pid: usize) -> bool {
    let pm = get_process_manager();
    pm.get_process(pid)
        .map(|process| process.fs_forwarding_enabled)
        .unwrap_or(true)
        && crate::FS_SYNC_FORWARD_ENABLED
}

/// Forward a short FS request to fs_server.
///
/// Returns `Some(info)` if fs_server accepted the call, or `None` if it
/// should be retried locally.
fn try_forward_fs_call(
    fs_ep: seL4_CPtr,
    syscall_ep_cap: seL4_CPtr,
    label: seL4_Word,
    req_len: seL4_Word,
    req_mrs: &[seL4_Word; 4],
) -> Option<MessageInfo> {
    // Never call back into the syscall endpoint from within syscall handling.
    if fs_ep == 0 || fs_ep == syscall_ep_cap {
        return None;
    }

    let ipc_buf = unsafe { &mut *sel4_sys::seL4_GetIPCBuffer() };
    let backup_msg = ipc_buf.msg;
    for (i, word) in req_mrs.iter().enumerate() {
        libnova::ipc::set_mr(i, *word);
    }

    let resp = libnova::ipc::call(fs_ep, libnova::ipc::MessageInfo::new(label, 0, 0, req_len));
    match resp {
        Ok(info) => {
            let status = libnova::ipc::get_mr(0);
            if !libnova::fs_ipc::is_not_implemented(status) {
                crate::services::note_fs_forward(label);
                Some(info)
            } else {
                ipc_buf.msg = backup_msg;
                None
            }
        }
        Err(_) => {
            ipc_buf.msg = backup_msg;
            None
        }
    }
}

/// Forward a write payload to fs_server.
fn try_forward_fs_write_data(
    fs_ep: seL4_CPtr,
    syscall_ep_cap: seL4_CPtr,
    remote_fd: seL4_Word,
    data: &[u8],
) -> Option<MessageInfo> {
    if fs_ep == 0 || fs_ep == syscall_ep_cap {
        return None;
    }

    let ipc_buf = unsafe { &mut *sel4_sys::seL4_GetIPCBuffer() };
    let backup_msg = ipc_buf.msg;

    let max_payload = (ipc_buf.msg.len().saturating_sub(2)) * core::mem::size_of::<seL4_Word>();
    let payload_len = if data.len() > max_payload {
        max_payload
    } else {
        data.len()
    };

    libnova::ipc::set_mr(0, remote_fd);
    libnova::ipc::set_mr(1, payload_len as seL4_Word);

    let payload_words = payload_len.div_ceil(8);
    for w in 0..payload_words {
        ipc_buf.msg[2 + w] = 0;
    }
    for (i, b) in data[..payload_len].iter().enumerate() {
        let word_idx = 2 + (i / 8);
        let shift = ((i % 8) * 8) as seL4_Word;
        ipc_buf.msg[word_idx] |= (*b as seL4_Word) << shift;
    }

    let req_len = (2 + payload_words) as seL4_Word;
    let resp = libnova::ipc::call(
        fs_ep,
        libnova::ipc::MessageInfo::new(FsLabel::Write.as_word(), 0, 0, req_len),
    );
    let ret = match resp {
        Ok(info) => {
            let status = libnova::ipc::get_mr(0);
            if !libnova::fs_ipc::is_not_implemented(status) {
                crate::services::note_fs_forward(FsLabel::Write.as_word());
                Some(info)
            } else {
                None
            }
        }
        Err(_) => None,
    };

    ipc_buf.msg = backup_msg;
    ret
}

/// Forward a read request to fs_server and copy the returned payload into
/// `out`.
fn try_forward_fs_read_data(
    fs_ep: seL4_CPtr,
    syscall_ep_cap: seL4_CPtr,
    remote_fd: seL4_Word,
    out: &mut [u8],
) -> Option<usize> {
    if fs_ep == 0 || fs_ep == syscall_ep_cap {
        return None;
    }

    let ipc_buf = unsafe { &mut *sel4_sys::seL4_GetIPCBuffer() };
    let backup_msg = ipc_buf.msg;

    libnova::ipc::set_mr(0, remote_fd);
    libnova::ipc::set_mr(1, out.len() as seL4_Word);

    let resp = libnova::ipc::call(
        fs_ep,
        libnova::ipc::MessageInfo::new(FsLabel::Read.as_word(), 0, 0, 2),
    );

    let ret = match resp {
        Ok(info) => {
            let status_word = libnova::ipc::get_mr(0);
            let status = status_word as i64;
            if status < 0 || libnova::fs_ipc::is_not_implemented(status_word) {
                None
            } else {
                let requested = status as usize;
                let payload_words = info.length().saturating_sub(1) as usize;
                let payload_bytes = payload_words.saturating_mul(core::mem::size_of::<seL4_Word>());
                let copy_len = core::cmp::min(requested, core::cmp::min(out.len(), payload_bytes));
                for (i, dst) in out.iter_mut().enumerate().take(copy_len) {
                    let word = ipc_buf.msg[1 + (i / 8)];
                    *dst = ((word >> ((i % 8) * 8)) & 0xFF) as u8;
                }
                crate::services::note_fs_forward(FsLabel::Read.as_word());
                Some(copy_len)
            }
        }
        Err(_) => None,
    };

    ipc_buf.msg = backup_msg;
    ret
}

/// Read a single word from the message, falling back to the IPC buffer for
/// indices beyond the inline MRs.
fn get_word(idx: usize, mrs: &[u64; 4], ipc_buf: &sel4_sys::seL4_IPCBuffer) -> u64 {
    if idx < 4 {
        mrs[idx]
    } else {
        ipc_buf.msg[idx]
    }
}

/// Read a byte slice from the IPC buffer starting at `word_offset`.
fn read_bytes_from_ipc(
    word_offset: usize,
    len: usize,
    mrs: &[u64; 4],
    ipc_buf: &sel4_sys::seL4_IPCBuffer,
) -> alloc::vec::Vec<u8> {
    let mut bytes = alloc::vec![0u8; len];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let word_idx = word_offset + (i / 8);
        let word = get_word(word_idx, mrs, ipc_buf);
        *byte = ((word >> ((i % 8) * 8)) & 0xFF) as u8;
    }
    bytes
}

/// Read a length-prefixed string starting at `word_offset`.
fn read_path_from_ipc(
    word_offset: usize,
    len: usize,
    mrs: &[u64; 4],
    ipc_buf: &sel4_sys::seL4_IPCBuffer,
) -> alloc::string::String {
    let safe_len = if len > MAX_PATH_LEN {
        MAX_PATH_LEN
    } else {
        len
    };
    let bytes = read_bytes_from_ipc(word_offset, safe_len, mrs, ipc_buf);
    alloc::string::String::from_utf8(bytes).unwrap_or_default()
}

/// Read a mode value and map it to `FileMode`.
fn decode_file_mode(mode_word: u64) -> FileMode {
    match mode_word {
        1 => FileMode::WriteOnly,
        2 => FileMode::ReadWrite,
        3 => FileMode::Append,
        _ => FileMode::ReadOnly,
    }
}

/// Common 4-tuple return type for FS handlers: `(reply_info, reply_mrs,
/// need_reply, manual_reply)`.
type FsHandlerResult = (MessageInfo, [u64; 4], bool, bool);

fn validate_message_only(ctx: &SyscallContext<'_>) -> Result<(), ValidateError> {
    libnova::validate::validate_message_length(ctx.info)
}

fn validate_one_mr(ctx: &SyscallContext<'_>) -> Result<(), ValidateError> {
    libnova::validate::validate_message_length(ctx.info)?;
    libnova::validate::validate_mr_index(ctx.info, 0)?;
    Ok(())
}

fn validate_two_mrs(ctx: &SyscallContext<'_>) -> Result<(), ValidateError> {
    validate_one_mr(ctx)?;
    libnova::validate::validate_mr_index(ctx.info, 1)?;
    Ok(())
}

fn validate_three_mrs(ctx: &SyscallContext<'_>) -> Result<(), ValidateError> {
    validate_two_mrs(ctx)?;
    libnova::validate::validate_mr_index(ctx.info, 2)?;
    Ok(())
}

/// Validate that a byte payload of `len` bytes starting at `word_offset`
/// fits inside the declared message length.
fn validate_payload_fits(
    ctx: &SyscallContext<'_>,
    word_offset: usize,
    len: usize,
) -> Result<(), ValidateError> {
    if len == 0 {
        return Ok(());
    }
    let words = len.div_ceil(8);
    let last_idx = word_offset + words - 1;
    libnova::validate::validate_mr_index(ctx.info, last_idx)
}

fn error_reply(_err: ValidateError) -> FsHandlerResult {
    let mut reply_mrs = [0u64; 4];
    reply_mrs[0] = (-1i64) as u64;
    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true, false)
}

fn ok_reply_word(value: u64) -> FsHandlerResult {
    let mut reply_mrs = [0u64; 4];
    reply_mrs[0] = value;
    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true, false)
}

fn err_reply_word() -> FsHandlerResult {
    let mut reply_mrs = [0u64; 4];
    reply_mrs[0] = (-1i64) as u64;
    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true, false)
}

/// Handle `sys_open(path_len, mode, path...) -> fd`.
pub fn handle_open(ctx: &mut SyscallContext<'_>) -> FsHandlerResult {
    if let Err(e) = validate_two_mrs(ctx) {
        return error_reply(e);
    }

    let path_len = ctx.mrs[0] as usize;
    let mode = decode_file_mode(ctx.mrs[1]);

    if let Err(e) = validate_payload_fits(ctx, 2, path_len) {
        return error_reply(e);
    }

    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };
    let path = read_path_from_ipc(2, path_len, ctx.mrs, ipc_buf);

    let mut success = false;
    let mut caller_uid = 0;
    let mut caller_gid = 0;

    if let Some(p) = get_process_manager().get_process(ctx.pid) {
        caller_uid = p.uid;
        caller_gid = p.gid;
    }

    if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
        match novafs_core::resolve_path(fs, "/", &path) {
            Ok(inode) => {
                let access_mask = match mode {
                    FileMode::ReadOnly => 4,
                    FileMode::WriteOnly => 2,
                    FileMode::ReadWrite => 6,
                    FileMode::Append => 2,
                };

                if novafs_core::check_permission(&inode, caller_uid, caller_gid, access_mask) {
                    success = true;
                } else {
                    println!("[KERNEL] sys_open: Permission denied for '{}'", path);
                }
            }
            Err(_) => {
                if mode != FileMode::ReadOnly {
                    let parent_res = if let Some(idx) = path.rfind('/') {
                        let (parent_path, name) = path.split_at(idx);
                        let name = &name[1..];
                        let parent_path = if parent_path.is_empty() {
                            "/"
                        } else {
                            parent_path
                        };

                        match novafs_core::resolve_path(fs, "/", parent_path) {
                            Ok(parent) => Some((parent, name)),
                            Err(_) => None,
                        }
                    } else {
                        Some((fs.root_inode(), path.as_str()))
                    };

                    if let Some((parent, name)) = parent_res {
                        if novafs_core::check_permission(&parent, caller_uid, caller_gid, 2) {
                            if parent.create(name, novafs_core::FileType::File).is_ok() {
                                println!("[KERNEL] sys_open: Created new file '{}'", path);
                                success = true;
                            } else {
                                println!("[KERNEL] sys_open: Failed to create '{}'", path);
                            }
                        } else {
                            println!(
                                "[KERNEL] sys_open: Permission denied to create in parent of '{}'",
                                path
                            );
                        }
                    } else {
                        println!(
                            "[KERNEL] sys_open: Parent directory not found for '{}'",
                            path
                        );
                    }
                } else {
                    println!("[KERNEL] sys_open: File not found '{}'", path);
                }
            }
        }
    }

    let fs_ep = if fs_forwarding_enabled_for_pid(ctx.pid) {
        resolve_fs_service_endpoint()
    } else {
        None
    };
    let mut fs_remote_fd: Option<usize> = None;
    let mut fd_idx = -1isize;

    if success {
        if let Some(fs_ep) = fs_ep {
            if let Some(fs_reply_info) = try_forward_fs_call(
                fs_ep,
                ctx.syscall_ep_cap,
                FsLabel::Open.as_word(),
                ctx.info.length(),
                ctx.mrs,
            ) {
                if fs_reply_info.length() > 0 {
                    let fs_fd_word = libnova::ipc::get_mr(0);
                    let fs_fd = fs_fd_word as i64;
                    if fs_fd >= 0 {
                        fs_remote_fd = Some(fs_fd as usize);
                    } else if !libnova::fs_ipc::is_not_implemented(fs_fd_word) {
                        println!(
                            "[KERNEL] sys_open: fs_server open failed (res={}), fallback to local-only fd",
                            fs_fd
                        );
                    }
                }
            }
        }

        if let Some(p) = get_process_manager().get_process_mut(ctx.pid) {
            if p.fds.len() < crate::process::MAX_FDS {
                p.fds.resize(crate::process::MAX_FDS, None);
            }
            for (i, slot) in p.fds.iter_mut().enumerate() {
                if slot.is_none() {
                    *slot = Some(crate::process::FileDescriptor {
                        path,
                        offset: 0,
                        mode,
                        remote_fd: fs_remote_fd,
                    });
                    fd_idx = i as isize;
                    break;
                }
            }
        }
    }

    if fd_idx < 0 {
        if let (Some(fs_ep), Some(remote_fd)) = (fs_ep, fs_remote_fd) {
            let req = [remote_fd as u64, 0, 0, 0];
            let _ = try_forward_fs_call(
                fs_ep,
                ctx.syscall_ep_cap,
                FsLabel::Close.as_word(),
                1,
                &req,
            );
        }
    }

    ok_reply_word(fd_idx as u64)
}

/// Handle `sys_read(fd, len) -> bytes_read`.
pub fn handle_read(ctx: &mut SyscallContext<'_>) -> FsHandlerResult {
    if let Err(e) = validate_two_mrs(ctx) {
        return error_reply(e);
    }

    let fd = ctx.mrs[0] as usize;
    let len = ctx.mrs[1] as usize;
    let fs_forwarding_enabled = fs_forwarding_enabled_for_pid(ctx.pid);
    let read_len = if len > MAX_READ_LEN {
        MAX_READ_LEN
    } else {
        len
    };

    let mut bytes_read = 0;
    let mut error_code = 0;

    if let Some(p) = get_process_manager().get_process_mut(ctx.pid) {
        if fd < p.fds.len() {
            if let Some(desc) = &mut p.fds[fd] {
                if desc.mode != FileMode::WriteOnly {
                    if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
                        if let Ok(inode) = novafs_core::resolve_path(fs, "/", &desc.path) {
                            if novafs_core::check_permission(&inode, p.uid, p.gid, 4) {
                                let mut served_by_fs_server = false;
                                if crate::FS_READ_PREFER_SERVER && fs_forwarding_enabled {
                                    if let (Some(fs_ep), Some(remote_fd)) =
                                        (resolve_fs_service_endpoint(), desc.remote_fd)
                                    {
                                        let mut fs_buf = alloc::vec![0u8; read_len];
                                        if let Some(n) = try_forward_fs_read_data(
                                            fs_ep,
                                            ctx.syscall_ep_cap,
                                            remote_fd as seL4_Word,
                                            &mut fs_buf,
                                        ) {
                                            desc.offset += n;
                                            bytes_read = n;
                                            copy_bytes_to_ipc_after_mr0(&fs_buf[..n]);
                                            served_by_fs_server = true;
                                        }
                                    }
                                }

                                if !served_by_fs_server {
                                    let mut buf = alloc::vec![0u8; read_len];
                                    if let Ok(n) = inode.read_at(desc.offset, &mut buf) {
                                        desc.offset += n;
                                        bytes_read = n;
                                        copy_bytes_to_ipc_after_mr0(&buf[..n]);
                                    }
                                }
                            } else {
                                println!(
                                    "[KERNEL] sys_read: Permission denied for '{}'",
                                    desc.path
                                );
                                error_code = 1; // EPERM
                            }
                        }
                    }
                }
            }
        }
    }

    if error_code != 0 {
        err_reply_word()
    } else {
        let data_words = bytes_read.div_ceil(8);
        let mut reply_mrs = [0u64; 4];
        reply_mrs[0] = bytes_read as u64;
        (
            MessageInfo::new(0, 0, 0, 1 + data_words as u64),
            reply_mrs,
            true,
            true,
        )
    }
}

/// Handle `sys_write(fd, len, data...) -> bytes_written`.
pub fn handle_write(ctx: &mut SyscallContext<'_>) -> FsHandlerResult {
    if let Err(e) = validate_two_mrs(ctx) {
        return error_reply(e);
    }

    let fd = ctx.mrs[0] as usize;
    let len = ctx.mrs[1] as usize;

    if let Err(e) = validate_payload_fits(ctx, 2, len) {
        return error_reply(e);
    }

    let mut bytes_written = 0;
    let mut error_code = 0;
    let mut fs_write_shadow: Option<alloc::vec::Vec<u8>> = None;

    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };

    if let Some(p) = get_process_manager().get_process_mut(ctx.pid) {
        if fd < p.fds.len() {
            if let Some(desc) = &mut p.fds[fd] {
                if desc.mode != FileMode::ReadOnly {
                    if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
                        if let Ok(inode) = novafs_core::resolve_path(fs, "/", &desc.path) {
                            if novafs_core::check_permission(&inode, p.uid, p.gid, 2) {
                                let mut data = alloc::vec![0u8; len];
                                let current_word_idx = 2; // MR2
                                for (i, byte) in data.iter_mut().enumerate() {
                                    let word_idx = current_word_idx + (i / 8);
                                    let word = get_word(word_idx, ctx.mrs, ipc_buf);
                                    let byte_idx = i % 8;
                                    *byte = ((word >> (byte_idx * 8)) & 0xFF) as u8;
                                }

                                if desc.mode == FileMode::Append {
                                    if let Ok(meta) = inode.metadata() {
                                        desc.offset = meta.size;
                                    }
                                }

                                match inode.write_at(desc.offset, &data) {
                                    Ok(n) => {
                                        desc.offset += n;
                                        bytes_written = n;
                                        fs_write_shadow = Some(data[..n].to_vec());
                                    }
                                    Err(e) => {
                                        println!("[KERNEL] sys_write: Write failed: {:?}", e);
                                        error_code = 1; // EIO
                                    }
                                }
                            } else {
                                println!(
                                    "[KERNEL] sys_write: Permission denied for '{}'",
                                    desc.path
                                );
                                error_code = 1; // EPERM
                            }
                        }
                    }
                } else {
                    println!("[KERNEL] sys_write: Bad mode (ReadOnly)");
                    error_code = 1; // EBADF
                }
            } else {
                error_code = 1; // EBADF
            }
        } else {
            error_code = 1; // EBADF
        }
    }

    if error_code != 0 {
        err_reply_word()
    } else {
        if fs_forwarding_enabled_for_pid(ctx.pid) {
            if let Some(fs_ep) = resolve_fs_service_endpoint() {
                let fs_fd = lookup_remote_fd(ctx.pid, fd).unwrap_or(fd);
                let payload = fs_write_shadow.as_deref().unwrap_or(&[]);
                let _ = try_forward_fs_write_data(
                    fs_ep,
                    ctx.syscall_ep_cap,
                    fs_fd as seL4_Word,
                    payload,
                );
            }
        }
        ok_reply_word(bytes_written as u64)
    }
}

/// Handle `sys_close(fd) -> 0/-1`.
pub fn handle_close(ctx: &mut SyscallContext<'_>) -> FsHandlerResult {
    if let Err(e) = validate_one_mr(ctx) {
        return error_reply(e);
    }

    let fd = ctx.mrs[0] as usize;

    let close_local = |pid: usize, fd: usize| -> i64 {
        if let Some(p) = get_process_manager().get_process_mut(pid) {
            if fd < p.fds.len() && p.fds[fd].is_some() {
                p.fds[fd] = None;
                return 0;
            }
        }
        -1
    };

    let remote_fd = {
        let pm = get_process_manager();
        if let Some(p) = pm.get_process(ctx.pid) {
            if fd < p.fds.len() {
                p.fds[fd].as_ref().and_then(|desc| desc.remote_fd)
            } else {
                None
            }
        } else {
            None
        }
    };

    if fs_forwarding_enabled_for_pid(ctx.pid) {
        if let Some(remote_fd) = remote_fd {
            if let Some(fs_ep) = resolve_fs_service_endpoint() {
                let req = [remote_fd as u64, 0, 0, 0];
                if let Some(fs_reply_info) = try_forward_fs_call(
                    fs_ep,
                    ctx.syscall_ep_cap,
                    FsLabel::Close.as_word(),
                    1,
                    &req,
                ) {
                    let fs_res = if fs_reply_info.length() > 0 {
                        libnova::ipc::get_mr(0) as i64
                    } else {
                        libnova::fs_ipc::FS_ERR_NOT_IMPLEMENTED
                    };
                    if fs_res != 0 {
                        println!(
                            "[KERNEL] sys_close: fs_server close failed (remote_fd={}, res={})",
                            remote_fd, fs_res
                        );
                    }
                }
            }
        }
    }

    ok_reply_word(close_local(ctx.pid, fd) as u64)
}

/// Handle `sys_chmod(path_len, mode, path) -> 0/-1`.
pub fn handle_chmod(ctx: &mut SyscallContext<'_>) -> FsHandlerResult {
    if let Err(e) = validate_two_mrs(ctx) {
        return error_reply(e);
    }

    let path_len = ctx.mrs[0] as usize;
    let mode = ctx.mrs[1] as u16;

    if let Err(e) = validate_payload_fits(ctx, 2, path_len) {
        return error_reply(e);
    }

    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };
    let offset = 2 * core::mem::size_of::<seL4_Word>();
    let safe_len = if path_len > MAX_PATH_LEN {
        MAX_PATH_LEN
    } else {
        path_len
    };
    let path_bytes = unsafe {
        core::slice::from_raw_parts((ipc_buf.msg.as_ptr() as *const u8).add(offset), safe_len)
    };
    let path = alloc::string::String::from(core::str::from_utf8(path_bytes).unwrap_or(""));

    let mut res = -1i64;
    if let Some(p) = get_process_manager().get_process_mut(ctx.pid) {
        if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
            if let Ok(inode) = novafs_core::resolve_path(fs, "/", &path) {
                let is_owner = if let Ok(stat) = inode.metadata() {
                    p.uid == 0 || stat.uid == p.uid
                } else {
                    false
                };

                if is_owner && inode.control(4, mode as u64).is_ok() {
                    res = 0;
                }
            }
        }
    }
    ok_reply_word(res as u64)
}

/// Handle `sys_chown(path_len, uid, gid, path) -> 0/-1`.
pub fn handle_chown(ctx: &mut SyscallContext<'_>) -> FsHandlerResult {
    if let Err(e) = validate_three_mrs(ctx) {
        return error_reply(e);
    }

    let path_len = ctx.mrs[0] as usize;
    let uid = ctx.mrs[1] as u32;
    let gid = ctx.mrs[2] as u32;

    if let Err(e) = validate_payload_fits(ctx, 3, path_len) {
        return error_reply(e);
    }

    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };
    let offset = 3 * core::mem::size_of::<seL4_Word>();
    let safe_len = if path_len > MAX_PATH_LEN {
        MAX_PATH_LEN
    } else {
        path_len
    };
    let path_bytes = unsafe {
        core::slice::from_raw_parts((ipc_buf.msg.as_ptr() as *const u8).add(offset), safe_len)
    };
    let path = alloc::string::String::from(core::str::from_utf8(path_bytes).unwrap_or(""));

    let mut res = -1i64;
    if let Some(p) = get_process_manager().get_process_mut(ctx.pid) {
        if p.uid == 0 {
            if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
                if let Ok(inode) = novafs_core::resolve_path(fs, "/", &path) {
                    if inode.control(5, uid as u64).is_ok() && inode.control(6, gid as u64).is_ok()
                    {
                        res = 0;
                    }
                }
            }
        }
    }
    ok_reply_word(res as u64)
}

/// Handle `sys_symlink(target_len, link_len, target..., linkpath...) -> 0/-1`.
pub fn handle_symlink(ctx: &mut SyscallContext<'_>) -> FsHandlerResult {
    if let Err(e) = validate_two_mrs(ctx) {
        return error_reply(e);
    }

    let target_len = ctx.mrs[0] as usize;
    let link_len = ctx.mrs[1] as usize;

    // Reject path lengths beyond the protocol limit; otherwise the second-path
    // offset would not match the sender's layout.
    if target_len > MAX_PATH_LEN || link_len > MAX_PATH_LEN {
        return error_reply(ValidateError::MessageLengthTooLarge);
    }

    // Validate payload coverage.
    if let Err(e) = validate_payload_fits(ctx, 2, target_len) {
        return error_reply(e);
    }
    let link_word_offset = 2 + target_len.div_ceil(8);
    if let Err(e) = validate_payload_fits(ctx, link_word_offset, link_len) {
        return error_reply(e);
    }

    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };
    let offset = 2 * core::mem::size_of::<seL4_Word>();
    let base_ptr = unsafe { (ipc_buf.msg.as_ptr() as *const u8).add(offset) };

    let target_bytes = unsafe { core::slice::from_raw_parts(base_ptr, target_len) };
    let target = alloc::string::String::from(core::str::from_utf8(target_bytes).unwrap_or(""));

    let link_bytes = unsafe { core::slice::from_raw_parts(base_ptr.add(target_len), link_len) };
    let linkpath = alloc::string::String::from(core::str::from_utf8(link_bytes).unwrap_or(""));

    let mut res = -1i64;
    if let Some(p) = get_process_manager().get_process_mut(ctx.pid) {
        if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
            if let Some(idx) = linkpath.rfind('/') {
                let (parent_path, name) = linkpath.split_at(idx);
                let name = &name[1..];
                let parent_path = if parent_path.is_empty() {
                    "/"
                } else {
                    parent_path
                };

                if let Ok(parent) = novafs_core::resolve_path(fs, "/", parent_path) {
                    if novafs_core::check_permission(&parent, p.uid, p.gid, 2) {
                        match parent.create(name, novafs_core::FileType::Symlink) {
                            Ok(inode) => {
                                if let Err(e) = inode.write_at(0, target.as_bytes()) {
                                    println!("[KERNEL] sys_symlink: write failed: {}", e);
                                } else {
                                    res = 0;
                                }
                            }
                            Err(e) => println!("[KERNEL] sys_symlink: create failed: {}", e),
                        }
                    } else {
                        println!(
                            "[KERNEL] sys_symlink: Permission denied for parent '{}'",
                            parent_path
                        );
                    }
                }
            }
        }
    }
    ok_reply_word(res as u64)
}

/// Handle `sys_readlink(path_len, buf_len, path...) -> bytes_read`.
pub fn handle_readlink(ctx: &mut SyscallContext<'_>) -> FsHandlerResult {
    if let Err(e) = validate_two_mrs(ctx) {
        return error_reply(e);
    }

    let path_len = ctx.mrs[0] as usize;
    let buf_len = ctx.mrs[1] as usize;
    let read_len = if buf_len > MAX_READ_LEN {
        MAX_READ_LEN
    } else {
        buf_len
    };

    if let Err(e) = validate_payload_fits(ctx, 2, path_len) {
        return error_reply(e);
    }

    let ipc_buf = unsafe { &mut *sel4_sys::seL4_GetIPCBuffer() };
    let offset = 2 * core::mem::size_of::<seL4_Word>();
    let safe_len = if path_len > MAX_PATH_LEN {
        MAX_PATH_LEN
    } else {
        path_len
    };
    let path_bytes = unsafe {
        core::slice::from_raw_parts((ipc_buf.msg.as_ptr() as *const u8).add(offset), safe_len)
    };
    let path = alloc::string::String::from(core::str::from_utf8(path_bytes).unwrap_or(""));

    let mut bytes_read = 0;
    let mut error_code = 0;

    if let Some(p) = get_process_manager().get_process_mut(ctx.pid) {
        if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
            match fs.resolve_path_ex("/", &path, false) {
                Ok(inode) => {
                    if novafs_core::check_permission(&inode, p.uid, p.gid, 4) {
                        if let Ok(meta) = inode.metadata() {
                            if meta.file_type == novafs_core::FileType::Symlink {
                                let mut buf = alloc::vec![0u8; read_len];
                                if let Ok(n) = inode.read_at(0, &mut buf) {
                                    let data_offset = core::mem::size_of::<seL4_Word>();
                                    let msg_bytes = unsafe {
                                        core::slice::from_raw_parts_mut(
                                            (ipc_buf.msg.as_mut_ptr() as *mut u8).add(data_offset),
                                            n,
                                        )
                                    };
                                    msg_bytes.copy_from_slice(&buf[..n]);
                                    bytes_read = n;
                                }
                            } else {
                                println!("[KERNEL] sys_readlink: Not a symlink: '{}'", path);
                                error_code = 1;
                            }
                        }
                    } else {
                        println!("[KERNEL] sys_readlink: Permission denied for '{}'", path);
                        error_code = 1;
                    }
                }
                Err(e) => {
                    println!(
                        "[KERNEL] sys_readlink: resolve_path failed for '{}': {}",
                        path, e
                    );
                    error_code = 1;
                }
            }
        }
    }

    if error_code != 0 {
        err_reply_word()
    } else {
        let data_words = bytes_read.div_ceil(8);
        let mut reply_mrs = [0u64; 4];
        reply_mrs[0] = bytes_read as u64;
        (
            MessageInfo::new(0, 0, 0, 1 + data_words as u64),
            reply_mrs,
            true,
            true,
        )
    }
}

/// Handle `sys_mkdir(path_len, path...) -> 0/-1`.
pub fn handle_mkdir(ctx: &mut SyscallContext<'_>) -> FsHandlerResult {
    if let Err(e) = validate_one_mr(ctx) {
        return error_reply(e);
    }

    let path_len = ctx.mrs[0] as usize;
    let safe_path_len = if path_len > MAX_PATH_LEN {
        MAX_PATH_LEN
    } else {
        path_len
    };
    if let Err(e) = validate_payload_fits(ctx, 1, safe_path_len) {
        return error_reply(e);
    }

    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };
    let path = read_path_from_ipc(1, path_len, ctx.mrs, ipc_buf);

    let mut res = -1i64;
    if let Some(p) = get_process_manager().get_process_mut(ctx.pid) {
        if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
            let parent_res = if let Some(idx) = path.rfind('/') {
                let (parent_path, name) = path.split_at(idx);
                let name = &name[1..];
                let parent_path = if parent_path.is_empty() {
                    "/"
                } else {
                    parent_path
                };
                match novafs_core::resolve_path(fs, "/", parent_path) {
                    Ok(parent) => Some((parent, name)),
                    Err(_) => None,
                }
            } else {
                Some((fs.root_inode(), path.as_str()))
            };

            if let Some((parent, name)) = parent_res {
                if novafs_core::check_permission(&parent, p.uid, p.gid, 2) {
                    match parent.create(name, novafs_core::FileType::Directory) {
                        Ok(_) => res = 0,
                        Err(e) => println!("[KERNEL] sys_mkdir: failed: {}", e),
                    }
                } else {
                    println!("[KERNEL] sys_mkdir: Permission denied");
                }
            }
        }
    }
    ok_reply_word(res as u64)
}

/// Handle `sys_rmdir(path_len, path...) -> 0/-1`.
pub fn handle_rmdir(ctx: &mut SyscallContext<'_>) -> FsHandlerResult {
    if let Err(e) = validate_one_mr(ctx) {
        return error_reply(e);
    }

    let path_len = ctx.mrs[0] as usize;
    let safe_path_len = if path_len > MAX_PATH_LEN {
        MAX_PATH_LEN
    } else {
        path_len
    };
    if let Err(e) = validate_payload_fits(ctx, 1, safe_path_len) {
        return error_reply(e);
    }

    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };
    let path = read_path_from_ipc(1, path_len, ctx.mrs, ipc_buf);

    let mut res = -1i64;
    if let Some(p) = get_process_manager().get_process_mut(ctx.pid) {
        if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
            let parent_res = if let Some(idx) = path.rfind('/') {
                let (parent_path, name) = path.split_at(idx);
                let name = &name[1..];
                let parent_path = if parent_path.is_empty() {
                    "/"
                } else {
                    parent_path
                };
                match novafs_core::resolve_path(fs, "/", parent_path) {
                    Ok(parent) => Some((parent, name)),
                    Err(_) => None,
                }
            } else {
                Some((fs.root_inode(), path.as_str()))
            };

            if let Some((parent, name)) = parent_res {
                if novafs_core::check_permission(&parent, p.uid, p.gid, 2) {
                    if let Ok(target) = parent.lookup(name) {
                        if let Ok(meta) = target.metadata() {
                            if meta.file_type == novafs_core::FileType::Directory {
                                match parent.remove(name) {
                                    Ok(_) => res = 0,
                                    Err(e) => println!("[KERNEL] sys_rmdir: failed: {}", e),
                                }
                            } else {
                                println!("[KERNEL] sys_rmdir: Not a directory");
                            }
                        }
                    } else {
                        println!("[KERNEL] sys_rmdir: Target not found");
                    }
                } else {
                    println!("[KERNEL] sys_rmdir: Permission denied");
                }
            }
        }
    }
    ok_reply_word(res as u64)
}

/// Handle `sys_unlink(path_len, path...) -> 0/-1`.
pub fn handle_unlink(ctx: &mut SyscallContext<'_>) -> FsHandlerResult {
    if let Err(e) = validate_one_mr(ctx) {
        return error_reply(e);
    }

    let path_len = ctx.mrs[0] as usize;
    let safe_path_len = if path_len > MAX_PATH_LEN {
        MAX_PATH_LEN
    } else {
        path_len
    };
    if let Err(e) = validate_payload_fits(ctx, 1, safe_path_len) {
        return error_reply(e);
    }

    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };
    let path = read_path_from_ipc(1, path_len, ctx.mrs, ipc_buf);

    let mut res = -1i64;
    if let Some(p) = get_process_manager().get_process_mut(ctx.pid) {
        if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
            let parent_res = if let Some(idx) = path.rfind('/') {
                let (parent_path, name) = path.split_at(idx);
                let name = &name[1..];
                let parent_path = if parent_path.is_empty() {
                    "/"
                } else {
                    parent_path
                };
                match novafs_core::resolve_path(fs, "/", parent_path) {
                    Ok(parent) => Some((parent, name)),
                    Err(_) => None,
                }
            } else {
                Some((fs.root_inode(), path.as_str()))
            };

            if let Some((parent, name)) = parent_res {
                if novafs_core::check_permission(&parent, p.uid, p.gid, 2) {
                    match parent.remove(name) {
                        Ok(_) => res = 0,
                        Err(e) => println!("[KERNEL] sys_unlink: failed: {}", e),
                    }
                } else {
                    println!("[KERNEL] sys_unlink: Permission denied");
                }
            }
        }
    }
    ok_reply_word(res as u64)
}

/// Handle `sys_rename(old_len, new_len, old_path..., new_path...) -> 0/-1`.
pub fn handle_rename(ctx: &mut SyscallContext<'_>) -> FsHandlerResult {
    if let Err(e) = validate_two_mrs(ctx) {
        return error_reply(e);
    }

    let old_len = ctx.mrs[0] as usize;
    let new_len = ctx.mrs[1] as usize;

    // Reject path lengths beyond the protocol limit; otherwise the second-path
    // offset would not match the sender's layout.
    if old_len > MAX_PATH_LEN || new_len > MAX_PATH_LEN {
        return error_reply(ValidateError::MessageLengthTooLarge);
    }

    // Validate payload coverage.
    if let Err(e) = validate_payload_fits(ctx, 2, old_len) {
        return error_reply(e);
    }
    let new_word_offset = 2 + old_len.div_ceil(8);
    if let Err(e) = validate_payload_fits(ctx, new_word_offset, new_len) {
        return error_reply(e);
    }

    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };

    let mut old_path_bytes = alloc::vec![0u8; old_len];
    let start_word = 2;
    for (i, byte) in old_path_bytes.iter_mut().enumerate() {
        let word_idx = start_word + (i / 8);
        let word = get_word(word_idx, ctx.mrs, ipc_buf);
        *byte = ((word >> ((i % 8) * 8)) & 0xFF) as u8;
    }
    let old_path = alloc::string::String::from_utf8(old_path_bytes).unwrap_or_default();

    let mut new_path_bytes = alloc::vec![0u8; new_len];
    for (i, byte) in new_path_bytes.iter_mut().enumerate() {
        let total_byte_idx = old_len + i;
        let word_idx = start_word + (total_byte_idx / 8);
        let word = get_word(word_idx, ctx.mrs, ipc_buf);
        *byte = ((word >> ((total_byte_idx % 8) * 8)) & 0xFF) as u8;
    }
    let new_path = alloc::string::String::from_utf8(new_path_bytes).unwrap_or_default();
    println!(
        "[KERNEL] sys_rename: new_path='{}' (len={})",
        new_path, new_len
    );

    let mut res = -1i64;
    if let Some(p) = get_process_manager().get_process_mut(ctx.pid) {
        if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
            let old_res = if let Some(idx) = old_path.rfind('/') {
                let (parent_path, name) = old_path.split_at(idx);
                let name = &name[1..];
                let parent_path = if parent_path.is_empty() {
                    "/"
                } else {
                    parent_path
                };
                match novafs_core::resolve_path(fs, "/", parent_path) {
                    Ok(parent) => Some((parent, name)),
                    Err(_) => None,
                }
            } else {
                Some((fs.root_inode(), old_path.as_str()))
            };

            let new_res = if let Some(idx) = new_path.rfind('/') {
                let (parent_path, name) = new_path.split_at(idx);
                let name = &name[1..];
                let parent_path = if parent_path.is_empty() {
                    "/"
                } else {
                    parent_path
                };
                match novafs_core::resolve_path(fs, "/", parent_path) {
                    Ok(parent) => Some((parent, name)),
                    Err(_) => None,
                }
            } else {
                Some((fs.root_inode(), new_path.as_str()))
            };

            if let (Some((old_parent, old_name)), Some((new_parent, new_name))) = (old_res, new_res)
            {
                let p1 = novafs_core::check_permission(&old_parent, p.uid, p.gid, 2);
                let p2 = novafs_core::check_permission(&new_parent, p.uid, p.gid, 2);

                if p1 && p2 {
                    match old_parent.rename(old_name, &new_parent, new_name) {
                        Ok(_) => res = 0,
                        Err(e) => println!("[KERNEL] sys_rename: failed: {}", e),
                    }
                } else {
                    println!("[KERNEL] sys_rename: Permission denied");
                }
            } else {
                println!("[KERNEL] sys_rename: Parent not found");
            }
        }
    }
    ok_reply_word(res as u64)
}

/// Handle `sys_link(target_len, link_len, target..., linkpath...) -> 0/-1`.
pub fn handle_link(ctx: &mut SyscallContext<'_>) -> FsHandlerResult {
    if let Err(e) = validate_two_mrs(ctx) {
        return error_reply(e);
    }

    let target_len = ctx.mrs[0] as usize;
    let link_len = ctx.mrs[1] as usize;

    // Reject path lengths beyond the protocol limit; otherwise the second-path
    // offset would not match the sender's layout.
    if target_len > MAX_PATH_LEN || link_len > MAX_PATH_LEN {
        return error_reply(ValidateError::MessageLengthTooLarge);
    }

    // Validate payload coverage.
    if let Err(e) = validate_payload_fits(ctx, 2, target_len) {
        return error_reply(e);
    }
    let link_word_offset = 2 + target_len.div_ceil(8);
    if let Err(e) = validate_payload_fits(ctx, link_word_offset, link_len) {
        return error_reply(e);
    }

    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };

    let mut target_bytes = alloc::vec![0u8; target_len];
    let start_word = 2;
    for (i, byte) in target_bytes.iter_mut().enumerate() {
        let word_idx = start_word + (i / 8);
        let word = get_word(word_idx, ctx.mrs, ipc_buf);
        *byte = ((word >> ((i % 8) * 8)) & 0xFF) as u8;
    }
    let target_path = alloc::string::String::from_utf8(target_bytes).unwrap_or_default();

    let mut link_bytes = alloc::vec![0u8; link_len];
    for (i, byte) in link_bytes.iter_mut().enumerate() {
        let total_byte_idx = target_len + i;
        let word_idx = start_word + (total_byte_idx / 8);
        let word = get_word(word_idx, ctx.mrs, ipc_buf);
        *byte = ((word >> ((total_byte_idx % 8) * 8)) & 0xFF) as u8;
    }
    let link_path = alloc::string::String::from_utf8(link_bytes).unwrap_or_default();

    let mut res = -1i64;
    if let Some(p) = get_process_manager().get_process_mut(ctx.pid) {
        if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
            if let Ok(target_inode) = novafs_core::resolve_path(fs, "/", &target_path) {
                let parent_res = if let Some(idx) = link_path.rfind('/') {
                    let (parent_path, name) = link_path.split_at(idx);
                    let name = &name[1..];
                    let parent_path = if parent_path.is_empty() {
                        "/"
                    } else {
                        parent_path
                    };
                    match novafs_core::resolve_path(fs, "/", parent_path) {
                        Ok(parent) => Some((parent, name)),
                        Err(_) => None,
                    }
                } else {
                    Some((fs.root_inode(), link_path.as_str()))
                };

                if let Some((parent, name)) = parent_res {
                    if novafs_core::check_permission(&parent, p.uid, p.gid, 2) {
                        match parent.link(name, target_inode.as_ref()) {
                            Ok(_) => res = 0,
                            Err(e) => println!("[KERNEL] sys_link: failed: {}", e),
                        }
                    } else {
                        println!("[KERNEL] sys_link: Permission denied");
                    }
                } else {
                    println!("[KERNEL] sys_link: Parent not found");
                }
            } else {
                println!("[KERNEL] sys_link: Target not found");
            }
        }
    }
    ok_reply_word(res as u64)
}

/// Handle `sys_block_read(block_id) -> (bytes_read, data...)`.
pub fn handle_block_read(ctx: &mut SyscallContext<'_>) -> FsHandlerResult {
    if let Err(e) = validate_one_mr(ctx) {
        return error_reply(e);
    }

    let block_id = ctx.mrs[0] as u32;
    if ctx.pid == 3 && block_id < 4 {
        println!(
            "[KERNEL] sys_block_read from pid={} block={}",
            ctx.pid, block_id
        );
    }
    let mut block = [0u8; MAX_BLOCK_LEN];

    match ctx.ata.read_block(block_id, &mut block) {
        Ok(()) => {
            let mut reply_mrs = [0u64; 4];
            reply_mrs[0] = block.len() as u64;
            copy_bytes_to_ipc_after_mr0(&block);
            (
                MessageInfo::new(
                    0,
                    0,
                    0,
                    1 + block.len().div_ceil(core::mem::size_of::<seL4_Word>()) as u64,
                ),
                reply_mrs,
                true,
                true,
            )
        }
        Err(e) => {
            println!("[KERNEL] sys_block_read: block={} failed: {}", block_id, e);
            err_reply_word()
        }
    }
}

/// Handle `sys_block_write(block_id, 512-byte block) -> 0/-1`.
pub fn handle_block_write(ctx: &mut SyscallContext<'_>) -> FsHandlerResult {
    if let Err(e) = validate_message_only(ctx) {
        return error_reply(e);
    }

    let block_id = ctx.mrs[0] as u32;

    if let Err(e) = validate_payload_fits(ctx, 1, MAX_BLOCK_LEN) {
        return error_reply(e);
    }

    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };
    let mut block = [0u8; MAX_BLOCK_LEN];

    for (i, byte) in block.iter_mut().enumerate() {
        let word_idx = 1 + (i / 8);
        let word = get_word(word_idx, ctx.mrs, ipc_buf);
        *byte = ((word >> ((i % 8) * 8)) & 0xFF) as u8;
    }

    let res = match ctx.ata.write_block(block_id, &block) {
        Ok(()) => 0i64,
        Err(e) => {
            println!("[KERNEL] sys_block_write: block={} failed: {}", block_id, e);
            -1
        }
    };
    ok_reply_word(res as u64)
}

/// Handle `sys_block_info() -> (sector_count, is_rotational)`.
pub fn handle_block_info(ctx: &mut SyscallContext<'_>) -> FsHandlerResult {
    if let Err(e) = validate_message_only(ctx) {
        return error_reply(e);
    }

    println!("[KERNEL] sys_block_info from pid={}", ctx.pid);
    let mut reply_mrs = [0u64; 4];
    reply_mrs[0] = ctx.ata.sector_count;
    reply_mrs[1] = if ctx.ata.is_rotational() { 1 } else { 0 };
    (MessageInfo::new(0, 0, 0, 2), reply_mrs, true, false)
}

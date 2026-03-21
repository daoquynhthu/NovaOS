#![no_std]
#![no_main]

mod allocator;

use core::sync::atomic::{AtomicU64, Ordering};
use libnova::fs_ipc::{
    fs_err_not_implemented_word, FS_LABEL_CLOSE, FS_LABEL_LINK, FS_LABEL_OPEN, FS_LABEL_PING,
    FS_LABEL_READ, FS_LABEL_RENAME, FS_LABEL_SYMLINK, FS_LABEL_UNLINK, FS_LABEL_WRITE,
    FS_PROTO_V1, FS_STATUS_READY,
};
use libnova::ipc;
use libnova::syscall::{
    sys_close, sys_file_write, sys_link, sys_open, sys_read, sys_rename, sys_symlink, sys_unlink,
};
use sel4_sys::{seL4_CPtr, seL4_IPCBuffer, seL4_Word};
use spin::Mutex;

static OPEN_COUNT: AtomicU64 = AtomicU64::new(0);
static READ_COUNT: AtomicU64 = AtomicU64::new(0);
static WRITE_COUNT: AtomicU64 = AtomicU64::new(0);
static CLOSE_COUNT: AtomicU64 = AtomicU64::new(0);
static FS_STATE: Mutex<Option<FsState>> = Mutex::new(None);

const FS_ERR_BADF: i64 = -9;
const FS_ERR_INVAL: i64 = -22;
const FS_ERR_MFILE: i64 = -24;
const MAX_TRACKED_FDS: usize = 32;
const MAX_PATH_LEN: usize = 255;
const MAX_RW_LEN: usize = 900;

#[derive(Clone, Copy)]
struct FdEntry {
    local_fd: usize,
    mode: u64,
}

struct FsState {
    fds: [Option<FdEntry>; MAX_TRACKED_FDS],
}

impl FsState {
    fn new() -> Self {
        Self {
            fds: [None; MAX_TRACKED_FDS],
        }
    }
}

#[inline]
fn pack_u32_pair(high: u64, low: u64) -> u64 {
    ((high & 0xFFFF_FFFF) << 32) | (low & 0xFFFF_FFFF)
}

fn copy_bytes_from_msg(start_word: usize, requested_len: usize, msg_words: usize, out: &mut [u8]) -> usize {
    let available_words = msg_words.saturating_sub(start_word);
    let available_bytes = available_words.saturating_mul(core::mem::size_of::<seL4_Word>());
    let len = core::cmp::min(requested_len, core::cmp::min(available_bytes, out.len()));
    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };
    for i in 0..len {
        let word_idx = start_word + (i / 8);
        let byte_idx = i % 8;
        let word = ipc_buf.msg[word_idx];
        out[i] = ((word >> (byte_idx * 8)) & 0xFF) as u8;
    }
    len
}

fn write_bytes_to_msg(start_word: usize, data: &[u8]) {
    let ipc_buf = unsafe { &mut *sel4_sys::seL4_GetIPCBuffer() };
    let words = (data.len() + 7) / 8;
    for w in 0..words {
        ipc_buf.msg[start_word + w] = 0;
    }
    for (i, b) in data.iter().enumerate() {
        let word_idx = start_word + (i / 8);
        let shift = ((i % 8) * 8) as seL4_Word;
        ipc_buf.msg[word_idx] |= (*b as seL4_Word) << shift;
    }
}

#[no_mangle]
pub static mut __sel4_ipc_buffer: *mut seL4_IPCBuffer = 0x3000_0000 as *mut seL4_IPCBuffer;

#[no_mangle]
pub extern "C" fn _start(
    argc: usize,
    argv: *const *const u8,
    ep_cap_usize: usize,
    _envp: *const *const u8,
) -> ! {
    let syscall_ep_cap = ep_cap_usize as seL4_CPtr;

    let mut service_ep_cap = syscall_ep_cap;
    unsafe {
        if argc > 0 && !argv.is_null() {
            let arg0 = *argv;
            if !arg0.is_null() {
                let mut slot: usize = 0;
                let mut seen_digit = false;
                let mut valid = true;
                let mut i = 0usize;
                loop {
                    let b = *arg0.add(i);
                    if b == 0 {
                        break;
                    }
                    if b.is_ascii_digit() {
                        seen_digit = true;
                        slot = slot
                            .saturating_mul(10)
                            .saturating_add((b - b'0') as usize);
                    } else {
                        valid = false;
                        break;
                    }
                    i += 1;
                    if i > 20 {
                        valid = false;
                        break;
                    }
                }
                if valid && seen_digit && slot != 0 {
                    service_ep_cap = slot as seL4_CPtr;
                }
            }
        }
    }

    {
        let mut state = FS_STATE.lock();
        *state = Some(FsState::new());
    }

    loop {
        let (_badge, info) = ipc::recv(service_ep_cap);
        let label = info.label();

        match label {
            FS_LABEL_PING => {
                let _requested_proto = ipc::get_mr(0);
                ipc::set_mr(0, FS_STATUS_READY);
                ipc::set_mr(1, FS_PROTO_V1);
                let open = OPEN_COUNT.load(Ordering::Relaxed);
                let close = CLOSE_COUNT.load(Ordering::Relaxed);
                let read = READ_COUNT.load(Ordering::Relaxed);
                let write = WRITE_COUNT.load(Ordering::Relaxed);
                ipc::set_mr(2, pack_u32_pair(open, close));
                ipc::set_mr(3, pack_u32_pair(read, write));
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 4));
            }
            FS_LABEL_OPEN => {
                let path_len = ipc::get_mr(0) as usize;
                let mode = ipc::get_mr(1);
                let mut path_buf = [0u8; MAX_PATH_LEN];
                let actual_len = copy_bytes_from_msg(2, path_len, info.length() as usize, &mut path_buf);
                let path_str = match core::str::from_utf8(&path_buf[..actual_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };
                libnova::println!("[FS_SERVER] open path={} mode={}", path_str, mode);

                let mut state_guard = FS_STATE.lock();
                let state = match state_guard.as_mut() {
                    Some(s) => s,
                    None => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                let local_fd = sys_open(syscall_ep_cap, path_str, mode as usize);
                if local_fd < 0 {
                    ipc::set_mr(0, local_fd as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let Some(slot) = state.fds.iter_mut().enumerate().find_map(|(idx, entry)| {
                    if entry.is_none() {
                        Some((idx, entry))
                    } else {
                        None
                    }
                }) else {
                    let _ = sys_close(syscall_ep_cap, local_fd as usize);
                    ipc::set_mr(0, FS_ERR_MFILE as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                };

                *slot.1 = Some(FdEntry {
                    local_fd: local_fd as usize,
                    mode,
                });
                let fd = (slot.0 + 3) as u64;
                libnova::println!("[FS_SERVER] open ok remote_fd={} local_fd={}", fd, local_fd);
                OPEN_COUNT.fetch_add(1, Ordering::Relaxed);
                ipc::set_mr(0, fd);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_CLOSE => {
                let fd = ipc::get_mr(0);
                libnova::println!("[FS_SERVER] close remote_fd={}", fd);
                let mut state_guard = FS_STATE.lock();
                let state = match state_guard.as_mut() {
                    Some(s) => s,
                    None => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                let Some(idx) = fd.checked_sub(3).and_then(|v| usize::try_from(v).ok()) else {
                    ipc::set_mr(0, FS_ERR_BADF as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                };

                if idx < state.fds.len() {
                    if let Some(entry) = state.fds[idx].take() {
                    let res = sys_close(syscall_ep_cap, entry.local_fd);
                    if res == 0 {
                        CLOSE_COUNT.fetch_add(1, Ordering::Relaxed);
                    }
                    libnova::println!("[FS_SERVER] close ok remote_fd={} local_fd={} res={}", fd, entry.local_fd, res);
                    ipc::set_mr(0, res as u64);
                } else {
                    ipc::set_mr(0, FS_ERR_BADF as u64);
                }
                } else {
                    ipc::set_mr(0, FS_ERR_BADF as u64);
                }
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_UNLINK => {
                let path_len = ipc::get_mr(0) as usize;
                let mut path_buf = [0u8; MAX_PATH_LEN];
                let actual_len = copy_bytes_from_msg(1, path_len, info.length() as usize, &mut path_buf);
                let path_str = match core::str::from_utf8(&path_buf[..actual_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };
                libnova::println!("[FS_SERVER] unlink path={}", path_str);
                let res = sys_unlink(syscall_ep_cap, path_str);
                libnova::println!("[FS_SERVER] unlink ok path={} res={}", path_str, res);
                ipc::set_mr(0, res as u64);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_RENAME => {
                let old_len = ipc::get_mr(0) as usize;
                let new_len = ipc::get_mr(1) as usize;
                if old_len == 0 || old_len > MAX_PATH_LEN || new_len == 0 || new_len > MAX_PATH_LEN {
                    ipc::set_mr(0, FS_ERR_INVAL as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let mut path_buf = [0u8; MAX_PATH_LEN * 2];
                let actual_len = copy_bytes_from_msg(2, old_len + new_len, info.length() as usize, &mut path_buf);
                if actual_len < old_len + new_len {
                    ipc::set_mr(0, FS_ERR_INVAL as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let old_path = match core::str::from_utf8(&path_buf[..old_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };
                let new_path = match core::str::from_utf8(&path_buf[old_len..old_len + new_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                libnova::println!("[FS_SERVER] rename {} -> {}", old_path, new_path);
                let res = sys_rename(syscall_ep_cap, old_path, new_path);
                libnova::println!("[FS_SERVER] rename ok {} -> {} res={}", old_path, new_path, res);
                ipc::set_mr(0, res as u64);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_LINK => {
                let target_len = ipc::get_mr(0) as usize;
                let link_len = ipc::get_mr(1) as usize;
                if target_len == 0 || target_len > MAX_PATH_LEN || link_len == 0 || link_len > MAX_PATH_LEN {
                    ipc::set_mr(0, FS_ERR_INVAL as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let mut path_buf = [0u8; MAX_PATH_LEN * 2];
                let actual_len = copy_bytes_from_msg(2, target_len + link_len, info.length() as usize, &mut path_buf);
                if actual_len < target_len + link_len {
                    ipc::set_mr(0, FS_ERR_INVAL as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let target_path = match core::str::from_utf8(&path_buf[..target_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };
                let link_path = match core::str::from_utf8(&path_buf[target_len..target_len + link_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                libnova::println!("[FS_SERVER] link {} => {}", link_path, target_path);
                let res = sys_link(syscall_ep_cap, target_path, link_path);
                libnova::println!("[FS_SERVER] link ok {} => {} res={}", link_path, target_path, res);
                ipc::set_mr(0, res as u64);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_SYMLINK => {
                let target_len = ipc::get_mr(0) as usize;
                let link_len = ipc::get_mr(1) as usize;
                if target_len == 0 || target_len > MAX_PATH_LEN || link_len == 0 || link_len > MAX_PATH_LEN {
                    ipc::set_mr(0, FS_ERR_INVAL as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let mut path_buf = [0u8; MAX_PATH_LEN * 2];
                let actual_len = copy_bytes_from_msg(2, target_len + link_len, info.length() as usize, &mut path_buf);
                if actual_len < target_len + link_len {
                    ipc::set_mr(0, FS_ERR_INVAL as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let target = match core::str::from_utf8(&path_buf[..target_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };
                let link_path = match core::str::from_utf8(&path_buf[target_len..target_len + link_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                libnova::println!("[FS_SERVER] symlink {} -> {}", link_path, target);
                let res = sys_symlink(syscall_ep_cap, target, link_path);
                libnova::println!("[FS_SERVER] symlink ok {} -> {} res={}", link_path, target, res);
                ipc::set_mr(0, res as u64);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_WRITE => {
                let fd = ipc::get_mr(0);
                let len = ipc::get_mr(1) as usize;
                libnova::println!("[FS_SERVER] write remote_fd={} len={}", fd, len);
                let Some(idx) = fd.checked_sub(3).and_then(|v| usize::try_from(v).ok()) else {
                    ipc::set_mr(0, FS_ERR_BADF as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                };

                let mut state_guard = FS_STATE.lock();
                let state = match state_guard.as_mut() {
                    Some(s) => s,
                    None => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                let (local_fd, mode) = match state.fds.get(idx).and_then(|entry| *entry) {
                    Some(e) => (e.local_fd, e.mode),
                    None => {
                        ipc::set_mr(0, FS_ERR_BADF as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                if mode == 0 {
                    ipc::set_mr(0, FS_ERR_BADF as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let mut data = [0u8; MAX_RW_LEN];
                let data_len = copy_bytes_from_msg(2, len, info.length() as usize, &mut data);
                let written = sys_file_write(syscall_ep_cap, local_fd, &data[..data_len]);
                libnova::println!("[FS_SERVER] write ok remote_fd={} local_fd={} written={}", fd, local_fd, written);
                if written >= 0 {
                    WRITE_COUNT.fetch_add(1, Ordering::Relaxed);
                }
                ipc::set_mr(0, written as u64);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_READ => {
                let fd = ipc::get_mr(0);
                let len = ipc::get_mr(1) as usize;
                libnova::println!("[FS_SERVER] read remote_fd={} len={}", fd, len);
                let Some(idx) = fd.checked_sub(3).and_then(|v| usize::try_from(v).ok()) else {
                    ipc::set_mr(0, FS_ERR_BADF as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                };

                let mut state_guard = FS_STATE.lock();
                let state = match state_guard.as_mut() {
                    Some(s) => s,
                    None => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                let (local_fd, mode) = match state.fds.get(idx).and_then(|entry| *entry) {
                    Some(e) => (e.local_fd, e.mode),
                    None => {
                        ipc::set_mr(0, FS_ERR_BADF as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                if mode == 1 {
                    ipc::set_mr(0, FS_ERR_BADF as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let capped_len = core::cmp::min(len, MAX_RW_LEN);
                let mut out = [0u8; MAX_RW_LEN];
                let read_res = sys_read(syscall_ep_cap, local_fd, &mut out);
                if read_res < 0 {
                    ipc::set_mr(0, read_res as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }
                let read_len = read_res as usize;

                libnova::println!("[FS_SERVER] read ok remote_fd={} local_fd={} read={}", fd, local_fd, read_len);
                READ_COUNT.fetch_add(1, Ordering::Relaxed);
                ipc::set_mr(0, read_len as u64);
                write_bytes_to_msg(1, &out[..core::cmp::min(read_len, capped_len)]);
                let words = 1 + read_len.div_ceil(8) as u64;
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, words));
            }
            _ => {
                ipc::set_mr(0, fs_err_not_implemented_word());
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

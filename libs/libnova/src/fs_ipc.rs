use crate::ipc;
use sel4_sys::{seL4_CPtr, seL4_Word};

pub const FS_LABEL_OPEN: seL4_Word = 20;
pub const FS_LABEL_READ: seL4_Word = 21;
pub const FS_LABEL_WRITE: seL4_Word = 22;
pub const FS_LABEL_CLOSE: seL4_Word = 23;
pub const FS_LABEL_UNLINK: seL4_Word = 24;
pub const FS_LABEL_RENAME: seL4_Word = 25;
pub const FS_LABEL_LINK: seL4_Word = 26;
pub const FS_LABEL_SYMLINK: seL4_Word = 27;
pub const FS_LABEL_REFRESH: seL4_Word = 28;
pub const FS_LABEL_MKDIR: seL4_Word = 29;
pub const FS_LABEL_TRUNCATE: seL4_Word = 30;
pub const FS_LABEL_CHMOD: seL4_Word = 31;
pub const FS_LABEL_CHOWN: seL4_Word = 32;
pub const FS_LABEL_SYNC: seL4_Word = 33;
pub const FS_LABEL_ENCRYPT: seL4_Word = 34;
pub const FS_LABEL_DECRYPT: seL4_Word = 35;
pub const FS_LABEL_LIST: seL4_Word = 36;
pub const FS_LABEL_WRITETEST: seL4_Word = 37;
pub const FS_LABEL_STAT: seL4_Word = 38;
pub const FS_LABEL_PING: seL4_Word = 0xF500;

pub const FS_STATUS_READY: seL4_Word = 0x4653_5256;
pub const FS_PROTO_V1: seL4_Word = 1;

pub const FS_ERR_NOT_IMPLEMENTED: i64 = -38;
pub const FS_MAX_PATH_LEN: usize = 255;
pub const FS_MAX_RW_LEN: usize = 900;

#[inline]
pub const fn fs_err_not_implemented_word() -> seL4_Word {
    FS_ERR_NOT_IMPLEMENTED as seL4_Word
}

#[inline]
pub const fn is_not_implemented(word: seL4_Word) -> bool {
    word as i64 == FS_ERR_NOT_IMPLEMENTED
}

fn write_bytes_at(start_word: usize, bytes: &[u8]) -> Result<(), ipc::pack::BoundError> {
    let mut w = ipc::pack::MessageWriter::with_cursor(
        start_word,
        sel4_sys::seL4_MsgLimits::seL4_MsgMaxLength as usize,
    );
    w.write_bytes(bytes)
}

pub fn open_direct(fs_ep: seL4_CPtr, path: &str, mode: usize) -> isize {
    let len = path.len();
    if len == 0 || len > FS_MAX_PATH_LEN {
        return -1;
    }

    ipc::set_mr(0, len as seL4_Word);
    ipc::set_mr(1, mode as seL4_Word);
    if write_bytes_at(2, path.as_bytes()).is_err() {
        return -1;
    }
    let path_words = len.div_ceil(8);
    let info = ipc::MessageInfo::new(FS_LABEL_OPEN, 0, 0, (2 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn close_direct(fs_ep: seL4_CPtr, fd: usize) -> isize {
    ipc::set_mr(0, fd as seL4_Word);
    match ipc::call(fs_ep, ipc::MessageInfo::new(FS_LABEL_CLOSE, 0, 0, 1)) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn write_direct(fs_ep: seL4_CPtr, fd: usize, buf: &[u8]) -> isize {
    if buf.len() > FS_MAX_RW_LEN {
        return -1;
    }

    ipc::set_mr(0, fd as seL4_Word);
    ipc::set_mr(1, buf.len() as seL4_Word);
    if write_bytes_at(2, buf).is_err() {
        return -1;
    }
    let data_words = buf.len().div_ceil(8);
    let info = ipc::MessageInfo::new(FS_LABEL_WRITE, 0, 0, (2 + data_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn read_direct(fs_ep: seL4_CPtr, fd: usize, buf: &mut [u8]) -> isize {
    if buf.len() > FS_MAX_RW_LEN {
        return -1;
    }

    ipc::set_mr(0, fd as seL4_Word);
    ipc::set_mr(1, buf.len() as seL4_Word);
    let info = ipc::MessageInfo::new(FS_LABEL_READ, 0, 0, 2);
    match ipc::call(fs_ep, info) {
        Ok(reply) => {
            let mut r = ipc::pack::MessageReader::new(reply.length() as usize);
            let read_len = r.read_usize().map(|v| v as isize).unwrap_or(-1);
            if read_len <= 0 {
                return read_len;
            }
            let payload_len = core::cmp::min(read_len as usize, buf.len());
            if r.read_bytes(&mut buf[..payload_len]).is_err() {
                return -1;
            }
            read_len
        }
        Err(_) => -1,
    }
}

pub fn unlink_direct(fs_ep: seL4_CPtr, path: &str) -> isize {
    let len = path.len();
    if len == 0 || len > FS_MAX_PATH_LEN {
        return -1;
    }

    ipc::set_mr(0, len as seL4_Word);
    if write_bytes_at(1, path.as_bytes()).is_err() {
        return -1;
    }
    let path_words = len.div_ceil(8);
    let info = ipc::MessageInfo::new(FS_LABEL_UNLINK, 0, 0, (1 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn rename_direct(fs_ep: seL4_CPtr, old_path: &str, new_path: &str) -> isize {
    let old_len = old_path.len();
    let new_len = new_path.len();
    if old_len == 0 || old_len > FS_MAX_PATH_LEN || new_len == 0 || new_len > FS_MAX_PATH_LEN {
        return -1;
    }

    ipc::set_mr(0, old_len as seL4_Word);
    ipc::set_mr(1, new_len as seL4_Word);

    let mut payload = [0u8; FS_MAX_PATH_LEN * 2];
    payload[..old_len].copy_from_slice(old_path.as_bytes());
    payload[old_len..old_len + new_len].copy_from_slice(new_path.as_bytes());
    if write_bytes_at(2, &payload[..old_len + new_len]).is_err() {
        return -1;
    }

    let path_words = (old_len + new_len).div_ceil(8);
    let info = ipc::MessageInfo::new(FS_LABEL_RENAME, 0, 0, (2 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn link_direct(fs_ep: seL4_CPtr, target_path: &str, link_path: &str) -> isize {
    let target_len = target_path.len();
    let link_len = link_path.len();
    if target_len == 0
        || target_len > FS_MAX_PATH_LEN
        || link_len == 0
        || link_len > FS_MAX_PATH_LEN
    {
        return -1;
    }

    ipc::set_mr(0, target_len as seL4_Word);
    ipc::set_mr(1, link_len as seL4_Word);

    let mut payload = [0u8; FS_MAX_PATH_LEN * 2];
    payload[..target_len].copy_from_slice(target_path.as_bytes());
    payload[target_len..target_len + link_len].copy_from_slice(link_path.as_bytes());
    if write_bytes_at(2, &payload[..target_len + link_len]).is_err() {
        return -1;
    }

    let path_words = (target_len + link_len).div_ceil(8);
    let info = ipc::MessageInfo::new(FS_LABEL_LINK, 0, 0, (2 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn symlink_direct(fs_ep: seL4_CPtr, target: &str, link_path: &str) -> isize {
    let target_len = target.len();
    let link_len = link_path.len();
    if target_len == 0
        || target_len > FS_MAX_PATH_LEN
        || link_len == 0
        || link_len > FS_MAX_PATH_LEN
    {
        return -1;
    }

    ipc::set_mr(0, target_len as seL4_Word);
    ipc::set_mr(1, link_len as seL4_Word);

    let mut payload = [0u8; FS_MAX_PATH_LEN * 2];
    payload[..target_len].copy_from_slice(target.as_bytes());
    payload[target_len..target_len + link_len].copy_from_slice(link_path.as_bytes());
    if write_bytes_at(2, &payload[..target_len + link_len]).is_err() {
        return -1;
    }

    let path_words = (target_len + link_len).div_ceil(8);
    let info = ipc::MessageInfo::new(FS_LABEL_SYMLINK, 0, 0, (2 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn refresh_direct(fs_ep: seL4_CPtr) -> isize {
    match ipc::call(fs_ep, ipc::MessageInfo::new(FS_LABEL_REFRESH, 0, 0, 0)) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn mkdir_direct(fs_ep: seL4_CPtr, path: &str) -> isize {
    let len = path.len();
    if len == 0 || len > FS_MAX_PATH_LEN {
        return -1;
    }

    ipc::set_mr(0, len as seL4_Word);
    if write_bytes_at(1, path.as_bytes()).is_err() {
        return -1;
    }
    let path_words = len.div_ceil(8);
    let info = ipc::MessageInfo::new(FS_LABEL_MKDIR, 0, 0, (1 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn truncate_direct(fs_ep: seL4_CPtr, path: &str, size: u64) -> isize {
    let len = path.len();
    if len == 0 || len > FS_MAX_PATH_LEN {
        return -1;
    }

    ipc::set_mr(0, len as seL4_Word);
    ipc::set_mr(1, size as seL4_Word);
    if write_bytes_at(2, path.as_bytes()).is_err() {
        return -1;
    }
    let path_words = len.div_ceil(8);
    let info = ipc::MessageInfo::new(FS_LABEL_TRUNCATE, 0, 0, (2 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn chmod_direct(fs_ep: seL4_CPtr, path: &str, mode: u16) -> isize {
    let len = path.len();
    if len == 0 || len > FS_MAX_PATH_LEN {
        return -1;
    }

    ipc::set_mr(0, len as seL4_Word);
    ipc::set_mr(1, mode as seL4_Word);
    if write_bytes_at(2, path.as_bytes()).is_err() {
        return -1;
    }
    let path_words = len.div_ceil(8);
    let info = ipc::MessageInfo::new(FS_LABEL_CHMOD, 0, 0, (2 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn chown_direct(fs_ep: seL4_CPtr, path: &str, uid: u32, gid: u32) -> isize {
    let len = path.len();
    if len == 0 || len > FS_MAX_PATH_LEN {
        return -1;
    }

    ipc::set_mr(0, len as seL4_Word);
    ipc::set_mr(1, uid as seL4_Word);
    ipc::set_mr(2, gid as seL4_Word);
    if write_bytes_at(3, path.as_bytes()).is_err() {
        return -1;
    }
    let path_words = len.div_ceil(8);
    let info = ipc::MessageInfo::new(FS_LABEL_CHOWN, 0, 0, (3 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn sync_direct(fs_ep: seL4_CPtr) -> isize {
    match ipc::call(fs_ep, ipc::MessageInfo::new(FS_LABEL_SYNC, 0, 0, 0)) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn encrypt_direct(fs_ep: seL4_CPtr, path: &str) -> isize {
    let len = path.len();
    if len == 0 || len > FS_MAX_PATH_LEN {
        return -1;
    }

    ipc::set_mr(0, len as seL4_Word);
    if write_bytes_at(1, path.as_bytes()).is_err() {
        return -1;
    }
    let path_words = len.div_ceil(8);
    let info = ipc::MessageInfo::new(FS_LABEL_ENCRYPT, 0, 0, (1 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn decrypt_direct(fs_ep: seL4_CPtr, path: &str) -> isize {
    let len = path.len();
    if len == 0 || len > FS_MAX_PATH_LEN {
        return -1;
    }

    ipc::set_mr(0, len as seL4_Word);
    if write_bytes_at(1, path.as_bytes()).is_err() {
        return -1;
    }
    let path_words = len.div_ceil(8);
    let info = ipc::MessageInfo::new(FS_LABEL_DECRYPT, 0, 0, (1 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn list_direct(fs_ep: seL4_CPtr, path: &str) -> isize {
    let len = path.len();
    if len == 0 || len > FS_MAX_PATH_LEN {
        return -1;
    }

    ipc::set_mr(0, len as seL4_Word);
    if write_bytes_at(1, path.as_bytes()).is_err() {
        return -1;
    }
    let path_words = len.div_ceil(8);
    let info = ipc::MessageInfo::new(FS_LABEL_LIST, 0, 0, (1 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn stat_direct(fs_ep: seL4_CPtr, path: &str) -> isize {
    let len = path.len();
    if len == 0 || len > FS_MAX_PATH_LEN {
        return -1;
    }

    ipc::set_mr(0, len as seL4_Word);
    if write_bytes_at(1, path.as_bytes()).is_err() {
        return -1;
    }
    let path_words = len.div_ceil(8);
    let info = ipc::MessageInfo::new(FS_LABEL_STAT, 0, 0, (1 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn writetest_direct(fs_ep: seL4_CPtr, path: &str, size_kb: usize) -> isize {
    let len = path.len();
    if len == 0 || len > FS_MAX_PATH_LEN {
        return -1;
    }

    ipc::set_mr(0, len as seL4_Word);
    ipc::set_mr(1, size_kb as seL4_Word);
    if write_bytes_at(2, path.as_bytes()).is_err() {
        return -1;
    }
    let path_words = len.div_ceil(8);
    let info = ipc::MessageInfo::new(FS_LABEL_WRITETEST, 0, 0, (2 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

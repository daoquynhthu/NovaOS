use crate::ipc;
use sel4_sys::{seL4_CPtr, seL4_Word};

/// NovaOS direct fs_server IPC protocol labels.
///
/// These are sent directly to the `fs.v1` endpoint by user-mode helpers; they
/// are distinct from the syscall labels used for RootServer dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FsLabel {
    Open = 20,
    Read = 21,
    Write = 22,
    Close = 23,
    Unlink = 24,
    Rename = 25,
    Link = 26,
    Symlink = 27,
    Refresh = 28,
    Mkdir = 29,
    Truncate = 30,
    Chmod = 31,
    Chown = 32,
    Sync = 33,
    Encrypt = 34,
    Decrypt = 35,
    List = 36,
    Writetest = 37,
    Stat = 38,
    Ping = 0xF500,
}

impl FsLabel {
    pub const fn as_u64(self) -> u64 {
        self as u64
    }

    pub const fn as_word(self) -> seL4_Word {
        self as u64 as seL4_Word
    }

    pub const fn from_u64(v: u64) -> Option<Self> {
        match v {
            20 => Some(Self::Open),
            21 => Some(Self::Read),
            22 => Some(Self::Write),
            23 => Some(Self::Close),
            24 => Some(Self::Unlink),
            25 => Some(Self::Rename),
            26 => Some(Self::Link),
            27 => Some(Self::Symlink),
            28 => Some(Self::Refresh),
            29 => Some(Self::Mkdir),
            30 => Some(Self::Truncate),
            31 => Some(Self::Chmod),
            32 => Some(Self::Chown),
            33 => Some(Self::Sync),
            34 => Some(Self::Encrypt),
            35 => Some(Self::Decrypt),
            36 => Some(Self::List),
            37 => Some(Self::Writetest),
            38 => Some(Self::Stat),
            0xF500 => Some(Self::Ping),
            _ => None,
        }
    }
}

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
    let info = ipc::MessageInfo::new(FsLabel::Open.as_word(), 0, 0, (2 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn close_direct(fs_ep: seL4_CPtr, fd: usize) -> isize {
    ipc::set_mr(0, fd as seL4_Word);
    match ipc::call(fs_ep, ipc::MessageInfo::new(FsLabel::Close.as_word(), 0, 0, 1)) {
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
    let info = ipc::MessageInfo::new(FsLabel::Write.as_word(), 0, 0, (2 + data_words) as seL4_Word);
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
    let info = ipc::MessageInfo::new(FsLabel::Read.as_word(), 0, 0, 2);
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
    let info = ipc::MessageInfo::new(FsLabel::Unlink.as_word(), 0, 0, (1 + path_words) as seL4_Word);
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
    let info = ipc::MessageInfo::new(FsLabel::Rename.as_word(), 0, 0, (2 + path_words) as seL4_Word);
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
    let info = ipc::MessageInfo::new(FsLabel::Link.as_word(), 0, 0, (2 + path_words) as seL4_Word);
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
    let info = ipc::MessageInfo::new(FsLabel::Symlink.as_word(), 0, 0, (2 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn refresh_direct(fs_ep: seL4_CPtr) -> isize {
    match ipc::call(fs_ep, ipc::MessageInfo::new(FsLabel::Refresh.as_word(), 0, 0, 0)) {
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
    let info = ipc::MessageInfo::new(FsLabel::Mkdir.as_word(), 0, 0, (1 + path_words) as seL4_Word);
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
    let info = ipc::MessageInfo::new(FsLabel::Truncate.as_word(), 0, 0, (2 + path_words) as seL4_Word);
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
    let info = ipc::MessageInfo::new(FsLabel::Chmod.as_word(), 0, 0, (2 + path_words) as seL4_Word);
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
    let info = ipc::MessageInfo::new(FsLabel::Chown.as_word(), 0, 0, (3 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

pub fn sync_direct(fs_ep: seL4_CPtr) -> isize {
    match ipc::call(fs_ep, ipc::MessageInfo::new(FsLabel::Sync.as_word(), 0, 0, 0)) {
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
    let info = ipc::MessageInfo::new(FsLabel::Encrypt.as_word(), 0, 0, (1 + path_words) as seL4_Word);
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
    let info = ipc::MessageInfo::new(FsLabel::Decrypt.as_word(), 0, 0, (1 + path_words) as seL4_Word);
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
    let info = ipc::MessageInfo::new(FsLabel::List.as_word(), 0, 0, (1 + path_words) as seL4_Word);
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
    let info = ipc::MessageInfo::new(FsLabel::Stat.as_word(), 0, 0, (1 + path_words) as seL4_Word);
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
    let info = ipc::MessageInfo::new(FsLabel::Writetest.as_word(), 0, 0, (2 + path_words) as seL4_Word);
    match ipc::call(fs_ep, info) {
        Ok(_) => ipc::get_mr(0) as isize,
        Err(_) => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::FsLabel;

    #[test]
    fn fs_label_values_are_stable() {
        // These values are part of the direct fs_server IPC ABI.
        assert_eq!(FsLabel::Open.as_u64(), 20);
        assert_eq!(FsLabel::Read.as_u64(), 21);
        assert_eq!(FsLabel::Write.as_u64(), 22);
        assert_eq!(FsLabel::Close.as_u64(), 23);
        assert_eq!(FsLabel::Unlink.as_u64(), 24);
        assert_eq!(FsLabel::Rename.as_u64(), 25);
        assert_eq!(FsLabel::Link.as_u64(), 26);
        assert_eq!(FsLabel::Symlink.as_u64(), 27);
        assert_eq!(FsLabel::Refresh.as_u64(), 28);
        assert_eq!(FsLabel::Mkdir.as_u64(), 29);
        assert_eq!(FsLabel::Truncate.as_u64(), 30);
        assert_eq!(FsLabel::Chmod.as_u64(), 31);
        assert_eq!(FsLabel::Chown.as_u64(), 32);
        assert_eq!(FsLabel::Sync.as_u64(), 33);
        assert_eq!(FsLabel::Encrypt.as_u64(), 34);
        assert_eq!(FsLabel::Decrypt.as_u64(), 35);
        assert_eq!(FsLabel::List.as_u64(), 36);
        assert_eq!(FsLabel::Writetest.as_u64(), 37);
        assert_eq!(FsLabel::Stat.as_u64(), 38);
        assert_eq!(FsLabel::Ping.as_u64(), 0xF500);
    }

    #[test]
    fn fs_label_roundtrip_via_from_u64() {
        for label in [
            FsLabel::Open,
            FsLabel::Read,
            FsLabel::Write,
            FsLabel::Ping,
        ] {
            let v = label.as_u64();
            assert_eq!(FsLabel::from_u64(v), Some(label));
        }
        assert_eq!(FsLabel::from_u64(99), None);
    }
}

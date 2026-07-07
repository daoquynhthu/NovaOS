use crate::ipc;
use sel4_sys::*;

const IPC_MAX_WORDS: usize = seL4_MsgLimits::seL4_MsgMaxLength as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Error {
    NoError = 0,
    InvalidArgument = 1,
    InvalidCapability = 2,
    IllegalOperation = 3,
    RangeError = 4,
    AlignmentError = 5,
    FailedLookup = 6,
    TruncatedMessage = 7,
    DeleteFirst = 8,
    RevokeFirst = 9,
    NotEnoughMemory = 10,
    Unknown(i32),
}

impl From<seL4_Error> for Error {
    fn from(err: seL4_Error) -> Self {
        unsafe {
            let val = core::mem::transmute::<seL4_Error, i32>(err);
            match val {
                0 => Error::NoError,
                1 => Error::InvalidArgument,
                2 => Error::InvalidCapability,
                3 => Error::IllegalOperation,
                4 => Error::RangeError,
                5 => Error::AlignmentError,
                6 => Error::FailedLookup,
                7 => Error::TruncatedMessage,
                8 => Error::DeleteFirst,
                9 => Error::RevokeFirst,
                10 => Error::NotEnoughMemory,
                _ => Error::Unknown(val),
            }
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// NovaOS syscall label numbers.
///
/// These values are the ABI between the user-space client stubs (this module)
/// and the RootServer syscall dispatch. New labels must be added here first and
/// mirrored in the server before use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SyscallNum {
    Print = 1,
    Exit = 2,
    Brk = 3,
    Yield = 4,
    VmFault = 5,
    GetTime = 6,
    WaitPid = 7,
    Spawn = 8,
    GetPid = 9,
    Sleep = 10,
    ShmAlloc = 11,
    ShmMap = 12,
    Send = 13,
    Fork = 14,
    Kill = 15,
    Open = 20,
    Read = 21,
    Write = 22,
    Close = 23,
    Chmod = 24,
    Chown = 25,
    Symlink = 26,
    Readlink = 27,
    GetUid = 28,
    SetUid = 29,
    ServiceRegister = 30,
    ServiceLookup = 31,
    GetGid = 32,
    SetGid = 33,
    Mkdir = 34,
    Rmdir = 35,
    Unlink = 36,
    Rename = 37,
    MmapShared = 38,
    MunmapShared = 39,
    Link = 40,
    BlockRead = 41,
    BlockWrite = 42,
    BlockInfo = 43,
    GetUnixTime = 44,
    ServiceSetReady = 45,
    FsViewEpoch = 46,
    Shutdown = 50,
}

impl SyscallNum {
    pub const fn as_u64(self) -> u64 {
        self as u64
    }

    pub const fn as_word(self) -> seL4_Word {
        self as u64 as seL4_Word
    }

    pub const fn from_u64(v: u64) -> Option<Self> {
        match v {
            1 => Some(Self::Print),
            2 => Some(Self::Exit),
            3 => Some(Self::Brk),
            4 => Some(Self::Yield),
            5 => Some(Self::VmFault),
            6 => Some(Self::GetTime),
            7 => Some(Self::WaitPid),
            8 => Some(Self::Spawn),
            9 => Some(Self::GetPid),
            10 => Some(Self::Sleep),
            11 => Some(Self::ShmAlloc),
            12 => Some(Self::ShmMap),
            13 => Some(Self::Send),
            14 => Some(Self::Fork),
            15 => Some(Self::Kill),
            20 => Some(Self::Open),
            21 => Some(Self::Read),
            22 => Some(Self::Write),
            23 => Some(Self::Close),
            24 => Some(Self::Chmod),
            25 => Some(Self::Chown),
            26 => Some(Self::Symlink),
            27 => Some(Self::Readlink),
            28 => Some(Self::GetUid),
            29 => Some(Self::SetUid),
            30 => Some(Self::ServiceRegister),
            31 => Some(Self::ServiceLookup),
            32 => Some(Self::GetGid),
            33 => Some(Self::SetGid),
            34 => Some(Self::Mkdir),
            35 => Some(Self::Rmdir),
            36 => Some(Self::Unlink),
            37 => Some(Self::Rename),
            38 => Some(Self::MmapShared),
            39 => Some(Self::MunmapShared),
            40 => Some(Self::Link),
            41 => Some(Self::BlockRead),
            42 => Some(Self::BlockWrite),
            43 => Some(Self::BlockInfo),
            44 => Some(Self::GetUnixTime),
            45 => Some(Self::ServiceSetReady),
            46 => Some(Self::FsViewEpoch),
            50 => Some(Self::Shutdown),
            _ => None,
        }
    }
}

pub fn check_err(err: seL4_Error) -> Result<()> {
    if err == seL4_Error::seL4_NoError {
        Ok(())
    } else {
        Err(Error::from(err))
    }
}

pub fn check_msg_err(info: seL4_MessageInfo) -> Result<()> {
    let label = seL4_MessageInfo_get_label(info) as i32;
    // seL4_Error is i32 compatible
    let err = unsafe { core::mem::transmute::<i32, seL4_Error>(label) };
    check_err(err)
}

pub fn sys_yield(ep: seL4_CPtr) {
    let info = ipc::MessageInfo::new(SyscallNum::Yield.as_word(), 0, 0, 0);
    let _ = ipc::call(ep, info);
}

pub fn sys_exit(ep: seL4_CPtr, code: usize) -> ! {
    ipc::set_mr(0, code as seL4_Word);
    let info = ipc::MessageInfo::new(SyscallNum::Exit.as_word(), 0, 0, 1);
    let _ = ipc::call(ep, info);
    loop {}
}

pub fn sys_print(ep: seL4_CPtr, s: &str) {
    let mut w = ipc::pack::MessageWriter::new(IPC_MAX_WORDS);
    if w.write_usize(s.len()).is_err() || w.write_bytes(s.as_bytes()).is_err() {
        return;
    }
    let info = ipc::MessageInfo::new(SyscallNum::Print.as_word(), 0, 0, w.cursor() as seL4_Word);
    let _ = ipc::call(ep, info);
}

pub fn sys_get_pid(ep: seL4_CPtr) -> usize {
    let info = ipc::MessageInfo::new(SyscallNum::GetPid.as_word(), 0, 0, 0);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as usize
}

pub fn sys_get_time(ep: seL4_CPtr) -> u64 {
    let info = ipc::MessageInfo::new(SyscallNum::GetTime.as_word(), 0, 0, 0);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0)
}

pub fn sys_get_unix_time(ep: seL4_CPtr) -> u64 {
    let info = ipc::MessageInfo::new(SyscallNum::GetUnixTime.as_word(), 0, 0, 0);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0)
}

pub fn sys_service_register(ep: seL4_CPtr, name: &str, service_cap: seL4_CPtr) -> isize {
    let name_bytes = name.as_bytes();
    let len = name_bytes.len();
    if len == 0 || len > 255 {
        return -1;
    }

    let mut w = ipc::pack::MessageWriter::new(seL4_MsgLimits::seL4_MsgMaxLength as usize);
    if w.write_usize(len).is_err() || w.write_bytes(name_bytes).is_err() {
        return -1;
    }
    ipc::set_cap(0, service_cap);

    let info = ipc::MessageInfo::new(SyscallNum::ServiceRegister.as_word(), 0, 1, w.cursor() as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_service_lookup_exists(ep: seL4_CPtr, name: &str) -> bool {
    let name_bytes = name.as_bytes();
    let len = name_bytes.len();
    if len == 0 || len > 255 {
        return false;
    }

    let mut w = ipc::pack::MessageWriter::new(seL4_MsgLimits::seL4_MsgMaxLength as usize);
    if w.write_usize(len).is_err() || w.write_bytes(name_bytes).is_err() {
        return false;
    }
    let info = ipc::MessageInfo::new(SyscallNum::ServiceLookup.as_word(), 0, 0, w.cursor() as seL4_Word);
    match ipc::call(ep, info) {
        Ok(resp) => seL4_MessageInfo_get_extraCaps(resp.inner) > 0,
        Err(_) => false,
    }
}

pub fn sys_service_set_ready(ep: seL4_CPtr, name: &str) -> isize {
    let name_bytes = name.as_bytes();
    let len = name_bytes.len();
    if len == 0 || len > 255 {
        return -1;
    }

    let mut w = ipc::pack::MessageWriter::new(seL4_MsgLimits::seL4_MsgMaxLength as usize);
    if w.write_usize(len).is_err() || w.write_bytes(name_bytes).is_err() {
        return -1;
    }
    let info = ipc::MessageInfo::new(SyscallNum::ServiceSetReady.as_word(), 0, 0, w.cursor() as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_fs_view_epoch(ep: seL4_CPtr) -> u64 {
    let info = ipc::MessageInfo::new(SyscallNum::FsViewEpoch.as_word(), 0, 0, 0);
    if ipc::call(ep, info).is_ok() {
        ipc::get_mr(0)
    } else {
        0
    }
}

pub fn sys_kill(ep: seL4_CPtr, pid: usize, sig: usize) -> isize {
    ipc::set_mr(0, pid as seL4_Word);
    ipc::set_mr(1, sig as seL4_Word);
    let info = ipc::MessageInfo::new(SyscallNum::Kill.as_word(), 0, 0, 2);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_wait(ep: seL4_CPtr, pid: isize, options: usize) -> (isize, usize) {
    ipc::set_mr(0, pid as seL4_Word);
    ipc::set_mr(1, options as seL4_Word);
    let info = ipc::MessageInfo::new(SyscallNum::WaitPid.as_word(), 0, 0, 2);
    let _ = ipc::call(ep, info);
    let ret_pid = ipc::get_mr(0) as isize;
    let status = ipc::get_mr(1) as usize;
    (ret_pid, status)
}

pub fn sys_spawn(ep: seL4_CPtr, path: &str, args: &[&str], envs: &[&str]) -> isize {
    sys_print(ep, "[USER] sys_spawn: new version called\n");
    let path_len = path.len();
    if path_len > 4096 || args.len() > 256 || envs.len() > 256 {
        return -1;
    }

    let mut w = ipc::pack::MessageWriter::new(IPC_MAX_WORDS);
    if w.write_u64(0xCAFEBABE).is_err()        // MR0: canary
        || w.write_usize(path_len).is_err()     // MR1: path_len
        || w.write_usize(args.len()).is_err()   // MR2: args_count
        || w.write_u64(0).is_err()              // MR3: skipped/padding
        || w.write_u64(0).is_err()              // MR4: skipped/padding
        || w.write_usize(envs.len()).is_err()   // MR5: envs_count
        || w.write_bytes(path.as_bytes()).is_err()
    {
        return -1;
    }
    for arg in args {
        if w.write_usize(arg.len()).is_err() || w.write_bytes(arg.as_bytes()).is_err() {
            return -1;
        }
    }
    for env in envs {
        if w.write_usize(env.len()).is_err() || w.write_bytes(env.as_bytes()).is_err() {
            return -1;
        }
    }

    let info = ipc::MessageInfo::new(SyscallNum::Spawn.as_word(), 0, 0, w.cursor() as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_brk(ep: seL4_CPtr, new_brk: usize) -> usize {
    ipc::set_mr(0, new_brk as seL4_Word);
    let info = ipc::MessageInfo::new(SyscallNum::Brk.as_word(), 0, 0, 1);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as usize
}

pub fn sys_mmap_shared(ep: seL4_CPtr, size: usize) -> usize {
    ipc::set_mr(0, size as seL4_Word);
    let info = ipc::MessageInfo::new(SyscallNum::MmapShared.as_word(), 0, 0, 1);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as usize
}

pub fn sys_shm_alloc(ep: seL4_CPtr, size: usize) -> usize {
    ipc::set_mr(0, size as seL4_Word);
    let info = ipc::MessageInfo::new(SyscallNum::ShmAlloc.as_word(), 0, 0, 1);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as usize
}

pub fn sys_shm_map(ep: seL4_CPtr, key: usize, vaddr: usize) -> isize {
    ipc::set_mr(0, key as seL4_Word);
    ipc::set_mr(1, vaddr as seL4_Word);
    let info = ipc::MessageInfo::new(SyscallNum::ShmMap.as_word(), 0, 0, 2);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_munmap_shared(ep: seL4_CPtr, addr: usize, size: usize) -> isize {
    ipc::set_mr(0, addr as seL4_Word);
    ipc::set_mr(1, size as seL4_Word);
    let info = ipc::MessageInfo::new(SyscallNum::MunmapShared.as_word(), 0, 0, 2);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_close(ep: seL4_CPtr, fd: usize) -> isize {
    ipc::set_mr(0, fd as seL4_Word);
    let info = ipc::MessageInfo::new(SyscallNum::Close.as_word(), 0, 0, 1);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

// --- File System Syscalls ---

pub fn sys_open(ep: seL4_CPtr, path: &str, flags: usize) -> isize {
    let len = path.len();
    if len > 255 {
        return -1;
    }

    let mut w = ipc::pack::MessageWriter::new(IPC_MAX_WORDS);
    if w.write_usize(len).is_err()
        || w.write_usize(flags).is_err()
        || w.write_bytes(path.as_bytes()).is_err()
    {
        return -1;
    }

    let info = ipc::MessageInfo::new(SyscallNum::Open.as_word(), 0, 0, w.cursor() as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_read(ep: seL4_CPtr, fd: usize, buf: &mut [u8]) -> isize {
    let len = buf.len();
    if len > 900 {
        return -1;
    }

    ipc::set_mr(0, fd as seL4_Word);
    ipc::set_mr(1, len as seL4_Word);

    let info = ipc::MessageInfo::new(SyscallNum::Read.as_word(), 0, 0, 2);

    match ipc::call(ep, info) {
        Ok(reply) => {
            let mut r = ipc::pack::MessageReader::new(reply.length() as usize);
            let bytes_read = r.read_usize().map(|v| v as isize).unwrap_or(-1);
            if bytes_read < 0 {
                return bytes_read;
            }
            let bytes_read = bytes_read as usize;
            if bytes_read > len {
                return -1;
            }
            if r.read_bytes(&mut buf[..bytes_read]).is_err() {
                return -1;
            }
            bytes_read as isize
        }
        Err(_) => -1,
    }
}

pub fn sys_write(ep: seL4_CPtr, fd: usize, buf: &[u8]) -> isize {
    let len = buf.len();
    if len > 900 {
        return -1;
    }

    let mut w = ipc::pack::MessageWriter::new(IPC_MAX_WORDS);
    if w.write_usize(fd).is_err()
        || w.write_usize(len).is_err()
        || w.write_bytes(buf).is_err()
    {
        return -1;
    }

    let info = ipc::MessageInfo::new(SyscallNum::Write.as_word(), 0, 0, w.cursor() as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

// Alias for sys_write
pub fn sys_file_write(ep: seL4_CPtr, fd: usize, buf: &[u8]) -> isize {
    sys_write(ep, fd, buf)
}

pub fn sys_unlink(ep: seL4_CPtr, path: &str) -> isize {
    let mut w = ipc::pack::MessageWriter::new(IPC_MAX_WORDS);
    if w.write_usize(path.len()).is_err() || w.write_bytes(path.as_bytes()).is_err() {
        return -1;
    }

    let info = ipc::MessageInfo::new(SyscallNum::Unlink.as_word(), 0, 0, w.cursor() as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_link(ep: seL4_CPtr, target_path: &str, link_path: &str) -> isize {
    let target_len = target_path.len();
    let link_len = link_path.len();
    if target_len > 255 || link_len > 255 {
        return -1;
    }

    let mut payload = [0u8; 512];
    payload[..target_len].copy_from_slice(target_path.as_bytes());
    payload[target_len..target_len + link_len].copy_from_slice(link_path.as_bytes());

    let mut w = ipc::pack::MessageWriter::new(IPC_MAX_WORDS);
    if w.write_usize(target_len).is_err()
        || w.write_usize(link_len).is_err()
        || w.write_bytes(&payload[..target_len + link_len]).is_err()
    {
        return -1;
    }

    let info = ipc::MessageInfo::new(SyscallNum::Link.as_word(), 0, 0, w.cursor() as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_symlink(ep: seL4_CPtr, target: &str, link_path: &str) -> isize {
    let target_len = target.len();
    let link_len = link_path.len();
    if target_len > 255 || link_len > 255 {
        return -1;
    }

    let mut payload = [0u8; 512];
    payload[..target_len].copy_from_slice(target.as_bytes());
    payload[target_len..target_len + link_len].copy_from_slice(link_path.as_bytes());

    let mut w = ipc::pack::MessageWriter::new(IPC_MAX_WORDS);
    if w.write_usize(target_len).is_err()
        || w.write_usize(link_len).is_err()
        || w.write_bytes(&payload[..target_len + link_len]).is_err()
    {
        return -1;
    }

    let info = ipc::MessageInfo::new(SyscallNum::Symlink.as_word(), 0, 0, w.cursor() as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_rename(ep: seL4_CPtr, old_path: &str, new_path: &str) -> isize {
    let old_len = old_path.len();
    let new_len = new_path.len();
    if old_len > 255 || new_len > 255 {
        return -1;
    }

    let mut payload = [0u8; 512];
    payload[..old_len].copy_from_slice(old_path.as_bytes());
    payload[old_len..old_len + new_len].copy_from_slice(new_path.as_bytes());

    let mut w = ipc::pack::MessageWriter::new(IPC_MAX_WORDS);
    if w.write_usize(old_len).is_err()
        || w.write_usize(new_len).is_err()
        || w.write_bytes(&payload[..old_len + new_len]).is_err()
    {
        return -1;
    }

    let info = ipc::MessageInfo::new(SyscallNum::Rename.as_word(), 0, 0, w.cursor() as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_block_info(ep: seL4_CPtr) -> Option<(u64, bool)> {
    let info = ipc::MessageInfo::new(SyscallNum::BlockInfo.as_word(), 0, 0, 0);
    let _ = ipc::call(ep, info);
    let sectors = ipc::get_mr(0);
    let rotational = ipc::get_mr(1) != 0;
    if sectors == 0 {
        None
    } else {
        Some((sectors, rotational))
    }
}

pub fn sys_block_read(ep: seL4_CPtr, block_id: u32, buf: &mut [u8; 512]) -> isize {
    ipc::set_mr(0, block_id as seL4_Word);
    let info = ipc::MessageInfo::new(SyscallNum::BlockRead.as_word(), 0, 0, 1);
    match ipc::call(ep, info) {
        Ok(reply) => {
            let mut r = ipc::pack::MessageReader::new(reply.length() as usize);
            let status = r.read_usize().map(|v| v as isize).unwrap_or(-1);
            if status < 0 {
                return status;
            }
            let bytes_read = status as usize;
            if bytes_read != buf.len() {
                return -1;
            }
            if r.read_bytes(buf).is_err() {
                return -1;
            }
            status
        }
        Err(_) => -1,
    }
}

pub fn sys_block_write(ep: seL4_CPtr, block_id: u32, buf: &[u8; 512]) -> isize {
    let mut w = ipc::pack::MessageWriter::new(IPC_MAX_WORDS);
    if w.write_u64(block_id as u64).is_err() || w.write_bytes(buf).is_err() {
        return -1;
    }

    let info = ipc::MessageInfo::new(SyscallNum::BlockWrite.as_word(), 0, 0, w.cursor() as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_print_hex(ep: seL4_CPtr, val: usize) {
    let mut buffer = [0u8; 18];
    buffer[0] = b'0';
    buffer[1] = b'x';

    let digits = b"0123456789ABCDEF";
    for i in 0..16 {
        let nibble = (val >> ((15 - i) * 4)) & 0xF;
        buffer[2 + i] = digits[nibble];
    }

    if let Ok(s) = core::str::from_utf8(&buffer) {
        sys_print(ep, s);
    }
}

pub fn yield_thread() {
    unsafe {
        seL4_Yield();
    }
}

#[cfg(test)]
mod tests {
    use super::SyscallNum;

    #[test]
    fn syscall_num_values_are_stable() {
        // These values are part of the NovaOS syscall ABI; changing them breaks
        // the contract between client stubs and RootServer dispatch.
        assert_eq!(SyscallNum::Print.as_u64(), 1);
        assert_eq!(SyscallNum::Exit.as_u64(), 2);
        assert_eq!(SyscallNum::Brk.as_u64(), 3);
        assert_eq!(SyscallNum::Yield.as_u64(), 4);
        assert_eq!(SyscallNum::VmFault.as_u64(), 5);
        assert_eq!(SyscallNum::GetTime.as_u64(), 6);
        assert_eq!(SyscallNum::WaitPid.as_u64(), 7);
        assert_eq!(SyscallNum::Spawn.as_u64(), 8);
        assert_eq!(SyscallNum::GetPid.as_u64(), 9);
        assert_eq!(SyscallNum::Sleep.as_u64(), 10);
        assert_eq!(SyscallNum::ShmAlloc.as_u64(), 11);
        assert_eq!(SyscallNum::ShmMap.as_u64(), 12);
        assert_eq!(SyscallNum::Send.as_u64(), 13);
        assert_eq!(SyscallNum::Fork.as_u64(), 14);
        assert_eq!(SyscallNum::Kill.as_u64(), 15);
        assert_eq!(SyscallNum::Open.as_u64(), 20);
        assert_eq!(SyscallNum::Read.as_u64(), 21);
        assert_eq!(SyscallNum::Write.as_u64(), 22);
        assert_eq!(SyscallNum::Close.as_u64(), 23);
        assert_eq!(SyscallNum::Chmod.as_u64(), 24);
        assert_eq!(SyscallNum::Chown.as_u64(), 25);
        assert_eq!(SyscallNum::Symlink.as_u64(), 26);
        assert_eq!(SyscallNum::Readlink.as_u64(), 27);
        assert_eq!(SyscallNum::GetUid.as_u64(), 28);
        assert_eq!(SyscallNum::SetUid.as_u64(), 29);
        assert_eq!(SyscallNum::ServiceRegister.as_u64(), 30);
        assert_eq!(SyscallNum::ServiceLookup.as_u64(), 31);
        assert_eq!(SyscallNum::GetGid.as_u64(), 32);
        assert_eq!(SyscallNum::SetGid.as_u64(), 33);
        assert_eq!(SyscallNum::Mkdir.as_u64(), 34);
        assert_eq!(SyscallNum::Rmdir.as_u64(), 35);
        assert_eq!(SyscallNum::Unlink.as_u64(), 36);
        assert_eq!(SyscallNum::Rename.as_u64(), 37);
        assert_eq!(SyscallNum::MmapShared.as_u64(), 38);
        assert_eq!(SyscallNum::MunmapShared.as_u64(), 39);
        assert_eq!(SyscallNum::Link.as_u64(), 40);
        assert_eq!(SyscallNum::BlockRead.as_u64(), 41);
        assert_eq!(SyscallNum::BlockWrite.as_u64(), 42);
        assert_eq!(SyscallNum::BlockInfo.as_u64(), 43);
        assert_eq!(SyscallNum::GetUnixTime.as_u64(), 44);
        assert_eq!(SyscallNum::ServiceSetReady.as_u64(), 45);
        assert_eq!(SyscallNum::FsViewEpoch.as_u64(), 46);
        assert_eq!(SyscallNum::Shutdown.as_u64(), 50);
    }

    #[test]
    fn syscall_num_roundtrip_via_from_u64() {
        for num in [
            SyscallNum::Print,
            SyscallNum::Exit,
            SyscallNum::Spawn,
            SyscallNum::Open,
            SyscallNum::Shutdown,
        ] {
            let v = num.as_u64();
            assert_eq!(SyscallNum::from_u64(v), Some(num));
        }
        assert_eq!(SyscallNum::from_u64(99), None);
    }
}

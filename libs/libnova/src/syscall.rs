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
    let info = ipc::MessageInfo::new(4, 0, 0, 0);
    let _ = ipc::call(ep, info);
}

pub fn sys_exit(ep: seL4_CPtr, code: usize) -> ! {
    ipc::set_mr(0, code as seL4_Word);
    let info = ipc::MessageInfo::new(2, 0, 0, 1);
    let _ = ipc::call(ep, info);
    loop {}
}

pub fn sys_print(ep: seL4_CPtr, s: &str) {
    let mut w = ipc::pack::MessageWriter::new(IPC_MAX_WORDS);
    if w.write_usize(s.len()).is_err() || w.write_bytes(s.as_bytes()).is_err() {
        return;
    }
    let info = ipc::MessageInfo::new(1, 0, 0, w.cursor() as seL4_Word);
    let _ = ipc::call(ep, info);
}

pub fn sys_get_pid(ep: seL4_CPtr) -> usize {
    let info = ipc::MessageInfo::new(9, 0, 0, 0);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as usize
}

pub fn sys_get_time(ep: seL4_CPtr) -> u64 {
    let info = ipc::MessageInfo::new(6, 0, 0, 0);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0)
}

pub fn sys_get_unix_time(ep: seL4_CPtr) -> u64 {
    let info = ipc::MessageInfo::new(44, 0, 0, 0);
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

    let info = ipc::MessageInfo::new(30, 0, 1, w.cursor() as seL4_Word);
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
    let info = ipc::MessageInfo::new(31, 0, 0, w.cursor() as seL4_Word);
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
    let info = ipc::MessageInfo::new(45, 0, 0, w.cursor() as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_fs_view_epoch(ep: seL4_CPtr) -> u64 {
    let info = ipc::MessageInfo::new(46, 0, 0, 0);
    if ipc::call(ep, info).is_ok() {
        ipc::get_mr(0)
    } else {
        0
    }
}

pub fn sys_kill(ep: seL4_CPtr, pid: usize, sig: usize) -> isize {
    ipc::set_mr(0, pid as seL4_Word);
    ipc::set_mr(1, sig as seL4_Word);
    let info = ipc::MessageInfo::new(15, 0, 0, 2);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_wait(ep: seL4_CPtr, pid: isize, options: usize) -> (isize, usize) {
    ipc::set_mr(0, pid as seL4_Word);
    ipc::set_mr(1, options as seL4_Word);
    let info = ipc::MessageInfo::new(7, 0, 0, 2);
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

    let info = ipc::MessageInfo::new(8, 0, 0, w.cursor() as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_brk(ep: seL4_CPtr, new_brk: usize) -> usize {
    ipc::set_mr(0, new_brk as seL4_Word);
    let info = ipc::MessageInfo::new(3, 0, 0, 1);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as usize
}

pub fn sys_mmap_shared(ep: seL4_CPtr, size: usize) -> usize {
    ipc::set_mr(0, size as seL4_Word);
    let info = ipc::MessageInfo::new(38, 0, 0, 1);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as usize
}

pub fn sys_shm_alloc(ep: seL4_CPtr, size: usize) -> usize {
    ipc::set_mr(0, size as seL4_Word);
    let info = ipc::MessageInfo::new(11, 0, 0, 1);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as usize
}

pub fn sys_shm_map(ep: seL4_CPtr, key: usize, vaddr: usize) -> isize {
    ipc::set_mr(0, key as seL4_Word);
    ipc::set_mr(1, vaddr as seL4_Word);
    let info = ipc::MessageInfo::new(12, 0, 0, 2);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_munmap_shared(ep: seL4_CPtr, addr: usize, size: usize) -> isize {
    ipc::set_mr(0, addr as seL4_Word);
    ipc::set_mr(1, size as seL4_Word);
    let info = ipc::MessageInfo::new(39, 0, 0, 2);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_close(ep: seL4_CPtr, fd: usize) -> isize {
    ipc::set_mr(0, fd as seL4_Word);
    let info = ipc::MessageInfo::new(23, 0, 0, 1);
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

    let info = ipc::MessageInfo::new(20, 0, 0, w.cursor() as seL4_Word);
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

    let info = ipc::MessageInfo::new(21, 0, 0, 2);

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

    let info = ipc::MessageInfo::new(22, 0, 0, w.cursor() as seL4_Word);
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

    let info = ipc::MessageInfo::new(36, 0, 0, w.cursor() as seL4_Word);
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

    let info = ipc::MessageInfo::new(40, 0, 0, w.cursor() as seL4_Word);
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

    let info = ipc::MessageInfo::new(26, 0, 0, w.cursor() as seL4_Word);
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

    let info = ipc::MessageInfo::new(37, 0, 0, w.cursor() as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_block_info(ep: seL4_CPtr) -> Option<(u64, bool)> {
    let info = ipc::MessageInfo::new(43, 0, 0, 0);
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
    let info = ipc::MessageInfo::new(41, 0, 0, 1);
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

    let info = ipc::MessageInfo::new(42, 0, 0, w.cursor() as seL4_Word);
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

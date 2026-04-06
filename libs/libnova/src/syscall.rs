use sel4_sys::*;
use crate::ipc;

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
    let len = s.len();
    ipc::set_mr(0, len as seL4_Word);
    
    let mut word_idx = 1;
    let mut byte_idx = 0;
    let mut current_word = 0u64;
    
    for &b in s.as_bytes() {
        current_word |= (b as u64) << (byte_idx * 8);
        byte_idx += 1;
        if byte_idx == 8 {
            ipc::set_mr(word_idx, current_word);
            word_idx += 1;
            byte_idx = 0;
            current_word = 0;
        }
    }
    if byte_idx > 0 {
        ipc::set_mr(word_idx, current_word);
        word_idx += 1;
    }
    
    let info = ipc::MessageInfo::new(1, 0, 0, word_idx as seL4_Word);
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

fn write_packed_bytes(start_word: usize, bytes: &[u8]) -> usize {
    let mut word_idx = start_word;
    let mut i = 0;
    while i < bytes.len() {
        let mut word = 0u64;
        let chunk_end = if i + 8 > bytes.len() { bytes.len() } else { i + 8 };
        for j in i..chunk_end {
            word |= (bytes[j] as u64) << ((j - i) * 8);
        }
        ipc::set_mr(word_idx, word);
        word_idx += 1;
        i += 8;
    }
    word_idx
}

pub fn sys_service_register(ep: seL4_CPtr, name: &str, service_cap: seL4_CPtr) -> isize {
    let name_bytes = name.as_bytes();
    let len = name_bytes.len();
    if len == 0 || len > 255 {
        return -1;
    }

    ipc::set_mr(0, len as seL4_Word);
    let next_word = write_packed_bytes(1, name_bytes);
    ipc::set_cap(0, service_cap);

    let info = ipc::MessageInfo::new(30, 0, 1, next_word as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_service_lookup_exists(ep: seL4_CPtr, name: &str) -> bool {
    let name_bytes = name.as_bytes();
    let len = name_bytes.len();
    if len == 0 || len > 255 {
        return false;
    }

    ipc::set_mr(0, len as seL4_Word);
    let next_word = write_packed_bytes(1, name_bytes);
    let info = ipc::MessageInfo::new(31, 0, 0, next_word as seL4_Word);
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

    ipc::set_mr(0, len as seL4_Word);
    let next_word = write_packed_bytes(1, name_bytes);
    let info = ipc::MessageInfo::new(45, 0, 0, next_word as seL4_Word);
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

    let ipc_buf = unsafe { &mut *seL4_GetIPCBuffer() };
    let max_words = ipc_buf.msg.len();

    let mut total_words = 3 + (path_len + 7) / 8;
    for arg in args {
        total_words += 1 + (arg.len() + 7) / 8;
    }
    for env in envs {
        total_words += 1 + (env.len() + 7) / 8;
    }
    
    // MR0-MR3 are registers (4 words).The rest must fit in IPC buffer.
    if total_words > 4 + max_words {
        return -1;
    }

    // Use standard IPC buffer access
    macro_rules! set_word {
        ($idx:expr, $val:expr) => {
             if $idx < 4 {
                 ipc::set_mr($idx, $val as seL4_Word);
             } else {
                 ipc_buf.msg[$idx] = $val as seL4_Word;
             }
        };
    }

    set_word!(0, 0xCAFEBABE); // Canary
    set_word!(1, path_len as u64);
    set_word!(2, args.len() as u64);
    
    // MR3 skipped (register)
    // MR4 skipped (register/buffer boundary?)
    
    // Place envs_len at MR5
    set_word!(5, envs.len() as u64);

    // Data starts at MR6
    let mut word_idx = 6;
    
    macro_rules! write_bytes {
        ($bytes:expr) => {
            let mut i = 0;
            while i < $bytes.len() {
                let mut word = 0u64;
                let chunk_end = if i + 8 > $bytes.len() { $bytes.len() } else { i + 8 };
                for j in i..chunk_end {
                    word |= ($bytes[j] as u64) << ((j - i) * 8);
                }
                set_word!(word_idx, word);
                word_idx += 1;
                i += 8;
            }
        };
    }

    write_bytes!(path.as_bytes());
    for arg in args {
        set_word!(word_idx, arg.len() as u64);
        word_idx += 1;
        write_bytes!(arg.as_bytes());
    }
    for env in envs {
        set_word!(word_idx, env.len() as u64);
        word_idx += 1;
        write_bytes!(env.as_bytes());
    }

    let info = ipc::MessageInfo::new(8, 0, 0, word_idx as seL4_Word);
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
    if len > 255 { return -1; }
    
    // Use standard IPC buffer access
    macro_rules! set_word {
        ($idx:expr, $val:expr) => {
             ipc::set_mr($idx, $val as seL4_Word);
        };
    }

    set_word!(0, len as u64);
    set_word!(1, flags as u64);
    
    let mut word_idx = 2;
    let mut i = 0;
    while i < len {
        let mut word = 0u64;
        let chunk_end = if i + 8 > len { len } else { i + 8 };
        for j in i..chunk_end {
            word |= (path.as_bytes()[j] as u64) << ((j - i) * 8);
        }
        set_word!(word_idx, word);
        word_idx += 1;
        i += 8;
    }
    
    let path_words = (len + 7) / 8;
    let info = ipc::MessageInfo::new(20, 0, 0, 2 + path_words as u64);
    
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_read(ep: seL4_CPtr, fd: usize, buf: &mut [u8]) -> isize {
    let len = buf.len();
    if len > 900 { return -1; }
    
    ipc::set_mr(0, fd as u64);
    ipc::set_mr(1, len as u64);
    
    let info = ipc::MessageInfo::new(21, 0, 0, 2);
    
    let _ = ipc::call(ep, info);
    let bytes_read = ipc::get_mr(0) as usize;
    
    if bytes_read > len { return -1; } 
    
    unsafe {
        let ipc_buf = &*seL4_GetIPCBuffer();
        let offset = core::mem::size_of::<seL4_Word>();
        let ptr = (ipc_buf.msg.as_ptr() as *const u8).add(offset);
        core::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), bytes_read);
    }
    
    bytes_read as isize
}

pub fn sys_write(ep: seL4_CPtr, fd: usize, buf: &[u8]) -> isize {
    let len = buf.len();
    if len > 900 { return -1; }
    
    // Use standard IPC buffer access
    macro_rules! set_word {
        ($idx:expr, $val:expr) => {
             ipc::set_mr($idx, $val as seL4_Word);
        };
    }

    set_word!(0, fd as u64);
    set_word!(1, len as u64);
    
    let mut word_idx = 2;
    let mut i = 0;
    while i < len {
        let mut word = 0u64;
        let chunk_end = if i + 8 > len { len } else { i + 8 };
        for j in i..chunk_end {
            word |= (buf[j] as u64) << ((j - i) * 8);
        }
        set_word!(word_idx, word);
        word_idx += 1;
        i += 8;
    }
    
    let data_words = (len + 7) / 8;
    let info = ipc::MessageInfo::new(22, 0, 0, 2 + data_words as u64);
    
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

// Alias for sys_write
pub fn sys_file_write(ep: seL4_CPtr, fd: usize, buf: &[u8]) -> isize {
    sys_write(ep, fd, buf)
}

pub fn sys_unlink(ep: seL4_CPtr, path: &str) -> isize {
    let path_len = path.len();
    ipc::set_mr(0, path_len as seL4_Word);
    
    let mut word_idx = 1;
    let mut byte_idx = 0;
    let mut current_word = 0u64;
    
    for &b in path.as_bytes() {
        current_word |= (b as u64) << (byte_idx * 8);
        byte_idx += 1;
        if byte_idx == 8 {
            ipc::set_mr(word_idx, current_word);
            word_idx += 1;
            byte_idx = 0;
            current_word = 0;
        }
    }
    if byte_idx > 0 {
        ipc::set_mr(word_idx, current_word);
        word_idx += 1;
    }
    
    let info = ipc::MessageInfo::new(36, 0, 0, word_idx as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_link(ep: seL4_CPtr, target_path: &str, link_path: &str) -> isize {
    let target_len = target_path.len();
    let link_len = link_path.len();

    ipc::set_mr(0, target_len as seL4_Word);
    ipc::set_mr(1, link_len as seL4_Word);

    let mut word_idx = 2;
    let mut byte_idx = 0;
    let mut current_word = 0u64;

    for &b in target_path.as_bytes() {
        current_word |= (b as u64) << (byte_idx * 8);
        byte_idx += 1;
        if byte_idx == 8 {
            ipc::set_mr(word_idx, current_word);
            word_idx += 1;
            byte_idx = 0;
            current_word = 0;
        }
    }

    for &b in link_path.as_bytes() {
        current_word |= (b as u64) << (byte_idx * 8);
        byte_idx += 1;
        if byte_idx == 8 {
            ipc::set_mr(word_idx, current_word);
            word_idx += 1;
            byte_idx = 0;
            current_word = 0;
        }
    }

    if byte_idx > 0 {
        ipc::set_mr(word_idx, current_word);
        word_idx += 1;
    }

    let info = ipc::MessageInfo::new(40, 0, 0, word_idx as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_symlink(ep: seL4_CPtr, target: &str, link_path: &str) -> isize {
    let target_len = target.len();
    let link_len = link_path.len();

    ipc::set_mr(0, target_len as seL4_Word);
    ipc::set_mr(1, link_len as seL4_Word);

    let mut word_idx = 2;
    let mut byte_idx = 0;
    let mut current_word = 0u64;

    for &b in target.as_bytes() {
        current_word |= (b as u64) << (byte_idx * 8);
        byte_idx += 1;
        if byte_idx == 8 {
            ipc::set_mr(word_idx, current_word);
            word_idx += 1;
            byte_idx = 0;
            current_word = 0;
        }
    }

    for &b in link_path.as_bytes() {
        current_word |= (b as u64) << (byte_idx * 8);
        byte_idx += 1;
        if byte_idx == 8 {
            ipc::set_mr(word_idx, current_word);
            word_idx += 1;
            byte_idx = 0;
            current_word = 0;
        }
    }

    if byte_idx > 0 {
        ipc::set_mr(word_idx, current_word);
        word_idx += 1;
    }

    let info = ipc::MessageInfo::new(26, 0, 0, word_idx as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_rename(ep: seL4_CPtr, old_path: &str, new_path: &str) -> isize {
    let old_len = old_path.len();
    let new_len = new_path.len();
    
    ipc::set_mr(0, old_len as seL4_Word);
    ipc::set_mr(1, new_len as seL4_Word);
    
    let mut word_idx = 2;
    let mut byte_idx = 0;
    let mut current_word = 0u64;
    
    for &b in old_path.as_bytes() {
        current_word |= (b as u64) << (byte_idx * 8);
        byte_idx += 1;
        if byte_idx == 8 {
            ipc::set_mr(word_idx, current_word);
            word_idx += 1;
            byte_idx = 0;
            current_word = 0;
        }
    }
    
    for &b in new_path.as_bytes() {
        current_word |= (b as u64) << (byte_idx * 8);
        byte_idx += 1;
        if byte_idx == 8 {
            ipc::set_mr(word_idx, current_word);
            word_idx += 1;
            byte_idx = 0;
            current_word = 0;
        }
    }
    
    if byte_idx > 0 {
        ipc::set_mr(word_idx, current_word);
        word_idx += 1;
    }
    
    let info = ipc::MessageInfo::new(37, 0, 0, word_idx as seL4_Word);
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
    let _ = ipc::call(ep, info);
    let status = ipc::get_mr(0) as isize;
    if status < 0 {
        return status;
    }

    let bytes_read = status as usize;
    if bytes_read != buf.len() {
        return -1;
    }

    unsafe {
        let ipc_buf = &*seL4_GetIPCBuffer();
        let offset = core::mem::size_of::<seL4_Word>();
        let ptr = (ipc_buf.msg.as_ptr() as *const u8).add(offset);
        core::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), bytes_read);
    }

    status
}

pub fn sys_block_write(ep: seL4_CPtr, block_id: u32, buf: &[u8; 512]) -> isize {
    ipc::set_mr(0, block_id as seL4_Word);

    let mut word_idx = 1usize;
    let mut i = 0usize;
    while i < buf.len() {
        let mut word = 0u64;
        let chunk_end = if i + 8 > buf.len() { buf.len() } else { i + 8 };
        for j in i..chunk_end {
            word |= (buf[j] as u64) << ((j - i) * 8);
        }
        ipc::set_mr(word_idx, word as seL4_Word);
        word_idx += 1;
        i += 8;
    }

    let info = ipc::MessageInfo::new(42, 0, 0, word_idx as seL4_Word);
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
    unsafe { seL4_Yield(); }
}

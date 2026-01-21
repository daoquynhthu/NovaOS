use sel4_sys::*;
use crate::ipc;

#[allow(dead_code)]
const WORD_BYTES: usize = core::mem::size_of::<seL4_Word>();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NoError,
    InvalidArgument,
    InvalidCapability,
    IllegalOperation,
    RangeError,
    AlignmentError,
    FailedLookup,
    TruncatedMessage,
    DeleteFirst,
    RevokeFirst,
    NotEnoughMemory,
    Unknown(seL4_Word),
}

impl From<seL4_Error> for Error {
    fn from(err: seL4_Error) -> Self {
        match err {
            seL4_Error::seL4_NoError => Error::NoError,
            seL4_Error::seL4_InvalidArgument => Error::InvalidArgument,
            seL4_Error::seL4_InvalidCapability => Error::InvalidCapability,
            seL4_Error::seL4_IllegalOperation => Error::IllegalOperation,
            seL4_Error::seL4_RangeError => Error::RangeError,
            seL4_Error::seL4_AlignmentError => Error::AlignmentError,
            seL4_Error::seL4_FailedLookup => Error::FailedLookup,
            seL4_Error::seL4_TruncatedMessage => Error::TruncatedMessage,
            seL4_Error::seL4_DeleteFirst => Error::DeleteFirst,
            seL4_Error::seL4_RevokeFirst => Error::RevokeFirst,
            seL4_Error::seL4_NotEnoughMemory => Error::NotEnoughMemory,
            _ => Error::Unknown(0), 
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

pub fn check_err(err: seL4_Error) -> Result<()> {
    if matches!(err, seL4_Error::seL4_NoError) {
        Ok(())
    } else {
        Err(Error::from(err))
    }
}

pub fn check_msg_err(info: seL4_MessageInfo) -> Result<()> {
    let label = seL4_MessageInfo_get_label(info);
    if label == 0 {
        Ok(())
    } else {
        Err(Error::from(seL4_Error::from(label as i32)))
    }
}

// --- Standard Syscalls ---

pub fn sys_print(ep: seL4_CPtr, s: &str) {
    let len = s.len();
    let bytes = s.as_bytes();
    
    // Simple chunking - send 32 bytes at a time (4 words)
    let mut offset = 0;
    while offset < len {
        let chunk_len = if len - offset > 32 { 32 } else { len - offset };
        
        let mut mr = [0u64; 4];
        for i in 0..chunk_len {
            let word_idx = i / 8;
            let byte_idx = i % 8;
            mr[word_idx] |= (bytes[offset + i] as u64) << (byte_idx * 8);
        }
        
        let msg_len_words = (chunk_len + 7) / 8; // div_ceil(8)
        
        // Use seL4_SetMR for compatibility with standard seL4 libs
        for i in 0..msg_len_words {
            ipc::set_mr(i, mr[i]);
        }
        
        let info = ipc::MessageInfo::new(1, 0, 0, msg_len_words as seL4_Word);
        let _ = ipc::call(ep, info);
        
        offset += chunk_len;
    }
}

pub fn sys_exit(ep: seL4_CPtr, code: usize) -> ! {
    ipc::set_mr(0, code as seL4_Word);
    let info = ipc::MessageInfo::new(2, 0, 0, 1);
    let _ = ipc::call(ep, info);
    loop {}
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
    let path_len = path.len();
    
    // MR0 = path_len
    // MR1 = args_len
    // MR2 = envs_len
    ipc::set_mr(0, path_len as seL4_Word);
    ipc::set_mr(1, args.len() as seL4_Word);
    ipc::set_mr(2, envs.len() as seL4_Word);
    
    // Pack data into a temporary vector to write to IPC buffer
    let mut words = alloc::vec::Vec::new();
    
    // Helper closure
    let pack_bytes = |dest: &mut alloc::vec::Vec<u64>, bytes: &[u8]| {
        let mut i = 0;
        while i < bytes.len() {
            let mut word = 0u64;
            let chunk_end = if i + 8 > bytes.len() { bytes.len() } else { i + 8 };
            for j in i..chunk_end {
                word |= (bytes[j] as u64) << ((j - i) * 8);
            }
            dest.push(word);
            i += 8;
        }
    };
    
    pack_bytes(&mut words, path.as_bytes());
    
    for arg in args {
        words.push(arg.len() as u64);
        pack_bytes(&mut words, arg.as_bytes());
    }

    for env in envs {
        words.push(env.len() as u64);
        pack_bytes(&mut words, env.as_bytes());
    }
    
    // Write words to MRs starting at 3
    for (i, word) in words.iter().enumerate() {
        ipc::set_mr(3 + i, *word);
    }
    
    let info = ipc::MessageInfo::new(8, 0, 0, (3 + words.len()) as seL4_Word);
    let _ = ipc::call(ep, info);
    
    ipc::get_mr(0) as isize
}

pub fn sys_brk(ep: seL4_CPtr, new_brk: usize) -> usize {
    ipc::set_mr(0, new_brk as seL4_Word);
    let info = ipc::MessageInfo::new(3, 0, 0, 1);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as usize
}

pub fn sys_yield(ep: seL4_CPtr) {
    let info = ipc::MessageInfo::new(4, 0, 0, 0);
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

pub fn sys_sleep(ep: seL4_CPtr, ticks: u64) {
    ipc::set_mr(0, ticks);
    let info = ipc::MessageInfo::new(10, 0, 0, 1);
    let _ = ipc::call(ep, info);
}

// --- File System Syscalls ---

pub fn sys_open(ep: seL4_CPtr, path: &str, flags: usize) -> isize {
    let len = path.len();
    if len > 255 { return -1; }
    
    ipc::set_mr(0, len as u64);
    ipc::set_mr(1, flags as u64);
    
    unsafe {
        let ipc_buf = &mut *seL4_GetIPCBuffer();
        let offset = 2 * core::mem::size_of::<seL4_Word>();
        let ptr = (ipc_buf.msg.as_mut_ptr() as *mut u8).add(offset);
        core::ptr::copy_nonoverlapping(path.as_ptr(), ptr, len);
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
    
    ipc::set_mr(0, fd as u64);
    ipc::set_mr(1, len as u64);
    
    unsafe {
        let ipc_buf = &mut *seL4_GetIPCBuffer();
        let offset = 2 * core::mem::size_of::<seL4_Word>();
        let ptr = (ipc_buf.msg.as_mut_ptr() as *mut u8).add(offset);
        core::ptr::copy_nonoverlapping(buf.as_ptr(), ptr, len);
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

pub fn sys_close(ep: seL4_CPtr, fd: usize) -> isize {
    ipc::set_mr(0, fd as u64);
    let info = ipc::MessageInfo::new(23, 0, 0, 1);
    
    let _ = ipc::call(ep, info);
    0
}

pub fn sys_mkdir(ep: seL4_CPtr, path: &str) -> isize {
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
    
    let info = ipc::MessageInfo::new(34, 0, 0, word_idx as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
}

pub fn sys_rmdir(ep: seL4_CPtr, path: &str) -> isize {
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
    
    let info = ipc::MessageInfo::new(35, 0, 0, word_idx as seL4_Word);
    let _ = ipc::call(ep, info);
    ipc::get_mr(0) as isize
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

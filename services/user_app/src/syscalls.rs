#![allow(dead_code)]

pub const SEL4_SYSCALL_CALL: isize = -1;

pub struct MessageInfo {
    pub words: [u64; 1],
}

#[allow(non_snake_case)]
pub fn seL4_MessageInfo_new(label: u64, caps: u64, extra: u64, len: usize) -> MessageInfo {
    MessageInfo {
        words: [ (label << 12) | ((caps & 7) << 9) | ((extra & 3) << 7) | (len as u64 & 0x7f) ]
    }
}

#[allow(non_snake_case)]
pub unsafe fn seL4_Call(dest: usize, info: MessageInfo, mrs: [u64; 4]) -> [u64; 4] {
    let info_val = info.words[0];
    let mut mr0 = mrs[0];
    let mut mr1 = mrs[1];
    let mut mr2 = mrs[2];
    let mut mr3 = mrs[3];
    
    core::arch::asm!(
        "push rbx",
        "mov rbx, rsp",
        "syscall",
        "mov rsp, rbx",
        "pop rbx",
        inout("rdi") dest => _,
        inout("rsi") info_val => _,
        inout("r10") mr0 => mr0,
        inout("r8") mr1 => mr1,
        inout("r9") mr2 => mr2,
        inout("r15") mr3 => mr3,
        in("rdx") SEL4_SYSCALL_CALL,
        lateout("rax") _,
        lateout("rcx") _,
        lateout("r11") _,
    );
    
    [mr0, mr1, mr2, mr3]
}

pub fn sys_print_hex(ep: usize, val: usize) {
    let mut buffer = [0u8; 18]; // "0x" + 16 digits
    buffer[0] = b'0';
    buffer[1] = b'x';
    
    let digits = b"0123456789ABCDEF";
    for i in 0..16 {
        let nibble = (val >> ((15 - i) * 4)) & 0xF;
        buffer[2 + i] = digits[nibble];
    }
    
    // Manual write to avoid alloc
    let s = unsafe { core::str::from_utf8_unchecked(&buffer) };
    sys_write(ep, s);
}

pub fn sys_get_time(ep: usize) -> u64 {
    let info = seL4_MessageInfo_new(6, 0, 0, 0);
    let mrs = [0u64; 4];
    let ret_mrs = unsafe {
        seL4_Call(ep, info, mrs)
    };
    ret_mrs[0]
}

pub fn sys_yield(ep: usize) {
    let info = seL4_MessageInfo_new(4, 0, 0, 0);
    unsafe {
        seL4_Call(ep, info, [0; 4]);
    }
}

pub fn sys_sleep(ep: usize, ticks: u64) {
    // Label 10 (sys_sleep) to avoid conflict with seL4_Fault_VMFault (5) and sys_get_time (6)
    let info = seL4_MessageInfo_new(10, 0, 0, 1);
    let mut mrs = [0u64; 4];
    mrs[0] = ticks;
    unsafe {
        seL4_Call(ep, info, mrs);
    }
}

pub fn sys_write(ep: usize, s: &str) {
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
        
        let msg_len_words = chunk_len.div_ceil(8);
        let info = seL4_MessageInfo_new(1, 0, 0, msg_len_words);
        
        unsafe {
            seL4_Call(ep, info, mr);
        }
        
        offset += chunk_len;
    }
}

pub fn sys_exit(ep: usize) {
    let info = seL4_MessageInfo_new(2, 0, 0, 1);
    unsafe {
        seL4_Call(ep, info, [0; 4]);
    }
}

pub fn sys_brk(ep: usize, new_brk: usize) -> usize {
    let info = seL4_MessageInfo_new(3, 0, 0, 1);
    let mut mrs = [0u64; 4];
    mrs[0] = new_brk as u64;
    
    let ret_mrs = unsafe {
        seL4_Call(ep, info, mrs)
    };
    
    ret_mrs[0] as usize
}

pub fn sys_shutdown(ep: usize) -> ! {
    let info = seL4_MessageInfo_new(50, 0, 0, 0); // Label 50
    unsafe {
        seL4_Call(ep, info, [0; 4]);
    }
    loop {}
}

// File I/O Syscalls

pub fn sys_file_open(ep: usize, path: &str, mode: u8) -> isize {
    // Label 20
    // MR0: len | (mode << 32)
    // MR1..N: Path
    
    let len = path.len();
    let bytes = path.as_bytes();
    let mut mr = [0u64; 4];
    
    mr[0] = (len as u64) | ((mode as u64) << 32);
    
    // Pack path into MR1, MR2, MR3
    for i in 0..len {
        if i >= 24 { break; } // Limit to 24 chars for now
        let word_idx = 1 + (i / 8);
        let byte_idx = i % 8;
        mr[word_idx] |= (bytes[i] as u64) << (byte_idx * 8);
    }
    
    let info = seL4_MessageInfo_new(20, 0, 0, 4);
    let ret_mrs = unsafe {
        seL4_Call(ep, info, mr)
    };
    
    let fd_ret = ret_mrs[0];
    if fd_ret == u64::MAX {
        -1
    } else {
        fd_ret as isize
    }
}

pub fn sys_file_close(ep: usize, fd: usize) -> isize {
    // Label 21
    // MR0: fd
    let mut mr = [0u64; 4];
    mr[0] = fd as u64;
    
    let info = seL4_MessageInfo_new(21, 0, 0, 1);
    let ret_mrs = unsafe {
        seL4_Call(ep, info, mr)
    };
    
    if ret_mrs[0] == 0 { 0 } else { -1 }
}

pub fn sys_file_read(ep: usize, fd: usize, buffer: &mut [u8]) -> isize {
    // Label 22
    // MR0: fd | (len << 32)
    // Returns: MR0 = bytes_read, MR1..N = data
    
    let req_len = buffer.len();
    // Cap request length to what we can receive in MR1..MR3 (24 bytes)
    let len = if req_len > 24 { 24 } else { req_len };
    
    let mut mr = [0u64; 4];
    mr[0] = (fd as u64) | ((len as u64) << 32);
    
    let info = seL4_MessageInfo_new(22, 0, 0, 1);
    let ret_mrs = unsafe {
        seL4_Call(ep, info, mr)
    };
    
    let bytes_read = ret_mrs[0] as usize;
    if bytes_read > len { return -1; }
    
    // Unpack data from MR1..MR3
    for i in 0..bytes_read {
        let word_idx = 1 + (i / 8);
        let byte_idx = i % 8;
        let byte = ((ret_mrs[word_idx] >> (byte_idx * 8)) & 0xFF) as u8;
        buffer[i] = byte;
    }
    
    bytes_read as isize
}

pub fn sys_file_write(ep: usize, fd: usize, buffer: &[u8]) -> isize {
    // Label 23
    // MR0: fd | (len << 32)
    // MR1..N: Data
    
    let req_len = buffer.len();
    // Cap write length to 24 bytes
    let len = if req_len > 24 { 24 } else { req_len };
    
    let mut mr = [0u64; 4];
    mr[0] = (fd as u64) | ((len as u64) << 32);
    
    for i in 0..len {
        let word_idx = 1 + (i / 8);
        let byte_idx = i % 8;
        mr[word_idx] |= (buffer[i] as u64) << (byte_idx * 8);
    }
    
    let info = seL4_MessageInfo_new(23, 0, 0, 4);
    let ret_mrs = unsafe {
        seL4_Call(ep, info, mr)
    };
    
    ret_mrs[0] as isize
}

pub fn sys_send(ep: usize, target: usize, msg: [u64; 3]) -> u64 {
    let info = seL4_MessageInfo_new(7, 0, 0, 4); // Label 7, Length 4 (Target + 3 Data)
    let mut mrs = [0u64; 4];
    mrs[0] = target as u64;
    mrs[1] = msg[0];
    mrs[2] = msg[1];
    mrs[3] = msg[2];
    
    let ret_mrs = unsafe {
        seL4_Call(ep, info, mrs)
    };
    ret_mrs[0] // 0 = Success, 1 = Error
}

pub fn sys_recv(ep: usize) -> (usize, [u64; 3]) {
    let info = seL4_MessageInfo_new(8, 0, 0, 0); // Label 8
    let mrs = [0u64; 4];
    let ret_mrs = unsafe {
        seL4_Call(ep, info, mrs)
    };
    let sender = ret_mrs[0] as usize;
    let msg = [ret_mrs[1], ret_mrs[2], ret_mrs[3]];
    (sender, msg)
}

pub fn sys_get_pid(ep: usize) -> usize {
    let info = seL4_MessageInfo_new(9, 0, 0, 0); // Label 9
    let mrs = [0u64; 4];
    let ret_mrs = unsafe {
        seL4_Call(ep, info, mrs)
    };
    ret_mrs[0] as usize
}

pub fn sys_shm_alloc(ep: usize, size: usize) -> usize {
    let info = seL4_MessageInfo_new(11, 0, 0, 1); // Label 11
    let mut mrs = [0u64; 4];
    mrs[0] = size as u64;
    let ret_mrs = unsafe {
        seL4_Call(ep, info, mrs)
    };
    ret_mrs[0] as usize
}

pub fn sys_shm_map(ep: usize, key: usize, vaddr: usize) -> usize {
    let info = seL4_MessageInfo_new(12, 0, 0, 2); // Label 12
    let mut mrs = [0u64; 4];
    mrs[0] = key as u64;
    mrs[1] = vaddr as u64;
    let ret_mrs = unsafe {
        seL4_Call(ep, info, mrs)
    };
    ret_mrs[0] as usize
}

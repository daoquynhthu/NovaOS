#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

const SEL4_SYSCALL_CALL: isize = -1;

#[no_mangle]
pub extern "C" fn _start(ep_cap: usize) -> ! {
    // Protocol:
    // Write: Label=1, content packed in MRs
    // Exit: Label=2
    
    let msg = "Hello from Rust User App via Syscall!\n";
    sys_write(ep_cap, msg);
    
    // Test Dynamic Memory
    let current_brk = sys_brk(ep_cap, 0);
    
    // Try to expand heap by 4KB
    let new_brk_req = current_brk + 4096;
    let new_brk = sys_brk(ep_cap, new_brk_req);
    
    if new_brk == new_brk_req {
        sys_write(ep_cap, "Heap expansion successful!\n");
        // Try writing to it
        let ptr = current_brk as *mut u8;
        unsafe { *ptr = b'A'; }
        
        // Read back
        if unsafe { *ptr } == b'A' {
             sys_write(ep_cap, "Heap memory write verified!\n");
        } else {
             sys_write(ep_cap, "Heap memory write failed!\n");
        }
    } else {
        sys_write(ep_cap, "Heap expansion failed!\n");
    }
    
    sys_exit(ep_cap);
    
    loop {}
}

fn sys_write(ep: usize, s: &str) {
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
        
        let msg_len_words = (chunk_len + 7) / 8;
        let info = seL4_MessageInfo_new(1, 0, 0, msg_len_words);
        
        unsafe {
            seL4_Call(ep, info, mr);
        }
        
        offset += chunk_len;
    }
}

fn sys_exit(ep: usize) {
    let info = seL4_MessageInfo_new(2, 0, 0, 0);
    unsafe {
        seL4_Call(ep, info, [0; 4]);
    }
}

struct MessageInfo {
    words: [u64; 1],
}

#[allow(non_snake_case)]
fn seL4_MessageInfo_new(label: u64, caps: u64, extra: u64, len: usize) -> MessageInfo {
    MessageInfo {
        words: [ (label << 12) | ((caps & 7) << 9) | ((extra & 3) << 7) | (len as u64 & 0x7f) ]
    }
}

#[allow(non_snake_case)]
unsafe fn seL4_Call(dest: usize, info: MessageInfo, mrs: [u64; 4]) {
    let mut info_val = info.words[0];
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
        in("rdx") SEL4_SYSCALL_CALL,
        inout("rdi") dest => _,
        inout("rsi") info_val,
        inout("r10") mr0,
        inout("r8") mr1,
        inout("r9") mr2,
        inout("r15") mr3,
        out("rcx") _,
        out("r11") _,
    );
    
    // Suppress unused assignment warnings as we are just discarding the reply for now
    let _ = (info_val, mr0, mr1, mr2, mr3);
}

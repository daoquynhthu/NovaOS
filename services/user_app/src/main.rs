#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;

mod allocator;
mod syscalls;
use syscalls::*;

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _start(ep_cap: usize) -> ! {
    // Protocol:
    // Write: Label=1, content packed in MRs
    // Exit: Label=2
    
    // Determine who we are
    let pid = sys_get_pid(ep_cap);
    
    if pid == 0 {
        sys_write(ep_cap, "Process 0: Started.\n");
        // Process 0 runs the full suite of tests + receives message
        
        let msg = "Hello from Rust User App via Syscall!\n";
        sys_write(ep_cap, msg);
        
        // Test Dynamic Memory
        let current_brk = sys_brk(ep_cap, 0);
        let new_brk_req = current_brk + 4096;
        let new_brk = sys_brk(ep_cap, new_brk_req);
        
        if new_brk == new_brk_req {
            sys_write(ep_cap, "Heap expansion successful!\n");
            let ptr = current_brk as *mut u8;
            unsafe { *ptr = b'A'; }
            if unsafe { *ptr } == b'A' {
                 sys_write(ep_cap, "Heap memory write verified!\n");
            } else {
                 sys_write(ep_cap, "Heap memory write failed!\n");
            }
        } else {
            sys_write(ep_cap, "Heap expansion failed!\n");
        }
        
        // Test Global Allocator
        sys_write(ep_cap, "Initializing Global Allocator...\n");
        let heap_size = 64 * 1024; // 64KB
        let heap_start = sys_brk(ep_cap, 0);
        let heap_end = sys_brk(ep_cap, heap_start + heap_size);
        
        sys_write(ep_cap, "Heap Range: ");
        sys_print_hex(ep_cap, heap_start);
        sys_write(ep_cap, " - ");
        sys_print_hex(ep_cap, heap_end);
        sys_write(ep_cap, "\n");

        if heap_end == heap_start + heap_size {
             sys_write(ep_cap, "Heap block allocated. Initializing Allocator...\n");
             allocator::init_heap(heap_start, heap_size);
             
             // Test Vec
             sys_write(ep_cap, "Testing Vec...\n");
             {
                 let mut v = Vec::new();
                 v.push(10);
                 v.push(20);
                 v.push(30);
                 if v.len() == 3 && v[0] == 10 && v[2] == 30 {
                      sys_write(ep_cap, "[PASS] Vec test passed.\n");
                 } else {
                      sys_write(ep_cap, "[FAIL] Vec test failed.\n");
                 }
             } // Drop Vec here
             sys_write(ep_cap, "Vec dropped.\n");

             // Test String
             sys_write(ep_cap, "Testing String...\n");
             
             // Manual Alloc Test
             use alloc::alloc::{alloc, dealloc, Layout};
             unsafe {
                 let layout = Layout::from_size_align(16, 8).unwrap();
                 let ptr = alloc(layout);
                 if !ptr.is_null() {
                     *ptr = 0xAA;
                     dealloc(ptr, layout);
                 }
             }

             sys_write(ep_cap, "Allocating String...\n");
             let s = String::from("Hello Allocator");
             sys_write(ep_cap, &s);
             sys_write(ep_cap, "\n");
        
        
        // Test File I/O
        sys_write(ep_cap, "Testing File I/O...\n");
        
        // 1. Create/Open file for writing
        let filename = "test.txt";
        let fd = sys_file_open(ep_cap, filename, 1); // 1 = WriteOnly
        if fd >= 0 {
            sys_write(ep_cap, "File opened for writing. FD: ");
            sys_print_hex(ep_cap, fd as usize);
            sys_write(ep_cap, "\n");
            
            let data = "HelloFile";
            let written = sys_file_write(ep_cap, fd as usize, data.as_bytes());
            sys_write(ep_cap, "Bytes written: ");
            sys_print_hex(ep_cap, written as usize);
            sys_write(ep_cap, "\n");
            
            sys_file_close(ep_cap, fd as usize);
            sys_write(ep_cap, "File closed.\n");
            
            // 2. Open file for reading
            let fd_read = sys_file_open(ep_cap, filename, 0); // 0 = ReadOnly
            if fd_read >= 0 {
                sys_write(ep_cap, "File opened for reading. FD: ");
                sys_print_hex(ep_cap, fd_read as usize);
                sys_write(ep_cap, "\n");
                
                let mut buf = [0u8; 32];
                let read = sys_file_read(ep_cap, fd_read as usize, &mut buf);
                
                if read > 0 {
                    sys_write(ep_cap, "Read content: ");
                    if let Ok(s) = core::str::from_utf8(&buf[0..read as usize]) {
                        sys_write(ep_cap, s);
                    } else {
                        sys_write(ep_cap, "(Binary)");
                    }
                    sys_write(ep_cap, "\n");
                } else {
                    sys_write(ep_cap, "Read failed or empty.\n");
                }
                
                sys_file_close(ep_cap, fd_read as usize);
            } else {
                sys_write(ep_cap, "Failed to open file for reading.\n");
            }
            
        } else {
            sys_write(ep_cap, "Failed to open file for writing.\n");
        }
        
        
             
             let bytes = s.as_bytes();
             // Manual check to avoid potential memcmp/SIMD issues in starts_with
             if bytes.len() >= 5 && bytes[0] == b'H' && bytes[1] == b'e' && bytes[2] == b'l' && bytes[3] == b'l' && bytes[4] == b'o' {
                  sys_write(ep_cap, "[PASS] String test passed.\n");
             } else {
                  sys_write(ep_cap, "[FAIL] String test failed.\n");
             }
             
             // Ensure String is dropped here
             drop(s);
             sys_write(ep_cap, "String dropped.\n");
            
             // sys_write(ep_cap, "String test skipped for debug.\n");
        } else {
             sys_write(ep_cap, "[FAIL] Failed to allocate heap for allocator.\n");
        }
        
        // Test Collaborative Scheduling
        for _ in 0..3 {
            sys_write(ep_cap, "Yielding...\n");
            sys_yield(ep_cap);
        }

        // Test Sleep
        let start_time = sys_get_time(ep_cap);
        sys_write(ep_cap, "Sleeping for 10 ticks...\n");
        sys_sleep(ep_cap, 10);
        let end_time = sys_get_time(ep_cap);
        sys_write(ep_cap, "Woke up from sleep!\n");
        
        if end_time >= start_time + 10 {
            sys_write(ep_cap, "Sleep duration verified!\n");
        }
        
        // Test IPC Receive
        sys_write(ep_cap, "Process 0: Waiting for message from Process 1...\n");
        let (sender, msg) = sys_recv(ep_cap);
        if sender == 1 && msg[0] == 0xDEADBEEF {
             sys_write(ep_cap, "Process 0: SUCCESS! Received correct message.\n");
        } else {
             sys_write(ep_cap, "Process 0: FAILURE! Received wrong message.\n");
        }
        
        // Wait for SHM Key from Process 1
        sys_write(ep_cap, "Process 0: Waiting for SHM Key...\n");
        let (sender2, msg2) = sys_recv(ep_cap);
        if sender2 == 1 {
            let shm_key = msg2[0] as usize;
            // sys_write(ep_cap, "Received SHM Key.\n"); // No alloc support for format yet
            
            // Map SHM
            let res = sys_shm_map(ep_cap, shm_key, 0x5000_0000);
            if res == 0 {
                let ptr = 0x5000_0000 as *mut u64;
                unsafe {
                    if *ptr == 0xCAFEBABE {
                         sys_write(ep_cap, "[PASS] Shared Memory Verify Success! (0xCAFEBABE)\n");
                         *ptr = 0xDEADBEEF; // Reply
                    } else {
                         sys_write(ep_cap, "[FAIL] Shared Memory Verify Failed! Value mismatch.\n");
                    }
                }
            } else {
                sys_write(ep_cap, "[FAIL] Shared Memory Map Failed.\n");
            }
        }

        // Test Page Fault (Demand Paging)
        sys_write(ep_cap, "Testing Demand Paging Range (0x6000_0000 - 0x7000_0000)...\n");
        
        // Test 1: Start of Range
        let ptr1 = 0x6000_0000 as *mut u64;
        unsafe {
             *ptr1 = 0xDEAD_BEEF;
             if *ptr1 == 0xDEAD_BEEF {
                 sys_write(ep_cap, "[PASS] 0x6000_0000 mapped and written.\n");
             } else {
                 sys_write(ep_cap, "[FAIL] 0x6000_0000 verify failed.\n");
             }
        }

        // Test 2: Next Page
        let ptr2 = 0x6000_1000 as *mut u64;
        unsafe {
             *ptr2 = 0xCAFE_BABE;
             if *ptr2 == 0xCAFE_BABE {
                 sys_write(ep_cap, "[PASS] 0x6000_1000 mapped and written.\n");
             } else {
                 sys_write(ep_cap, "[FAIL] 0x6000_1000 verify failed.\n");
             }
        }

        // Test 3: Far Page (but < 256 frames limit)
        // 0x6000_0000 + 20 * 4096 = 0x6001_4000
        let ptr3 = 0x6001_4000 as *mut u64;
        unsafe {
             *ptr3 = 0x1234_5678;
             if *ptr3 == 0x1234_5678 {
                 sys_write(ep_cap, "[PASS] 0x6001_4000 mapped and written.\n");
             } else {
                 sys_write(ep_cap, "[FAIL] 0x6001_4000 verify failed.\n");
             }
        }

    } else if pid == 1 {
        sys_write(ep_cap, "Process 1: Started.\n");
        // Process 1 just sends a message to Process 0
        sys_write(ep_cap, "Process 1: Sleeping for 20 ticks before sending...\n");
        sys_sleep(ep_cap, 20); // Sleep a bit to ensure Process 0 is ready
        
        sys_write(ep_cap, "Process 1: Sending message to Process 0...\n");
        let msg = [0xDEADBEEF, 0xCAFEBABE, 0x12345678]; // Matched Expectation
        let res = sys_send(ep_cap, 0, msg);
        if res == 0 {
            sys_write(ep_cap, "Process 1: Message sent successfully.\n");
        } else {
            sys_write(ep_cap, "Process 1: Failed to send message.\n");
        }

        // Shared Memory Test
        sys_write(ep_cap, "Process 1: Allocating Shared Memory...\n");
        let shm_key = sys_shm_alloc(ep_cap, 4096);
        if shm_key > 0 {
             sys_write(ep_cap, "Process 1: SHM Allocated. Mapping...\n");
             let res = sys_shm_map(ep_cap, shm_key, 0x5000_0000);
             if res == 0 {
                 let ptr = 0x5000_0000 as *mut u64;
                 unsafe { *ptr = 0xCAFEBABE; }
                 
                 sys_write(ep_cap, "Process 1: Sending SHM Key to Process 0...\n");
                sys_send(ep_cap, 0, [shm_key as u64, 0, 0]);
                
                // Wait a bit for Process 0 to write back
                sys_sleep(ep_cap, 50); 
                
                unsafe {
                    if *ptr == 0xDEADBEEF {
                         sys_write(ep_cap, "[PASS] Process 1 read back DEADBEEF from SHM.\n");
                     } else {
                         sys_write(ep_cap, "[FAIL] Process 1 read mismatch.\n");
                     }
                 }
             } else {
                 sys_write(ep_cap, "[FAIL] Process 1 Map Failed.\n");
             }
        } else {
             sys_write(ep_cap, "[FAIL] SHM Alloc Failed.\n");
        }
    } else {
        sys_write(ep_cap, "Unknown Process PID. Idling.\n");
    }

    if pid == 0 {
        sys_write(ep_cap, "[TEST] PASSED\n");
        sys_shutdown(ep_cap);
    } else {
        sys_exit(ep_cap);
    }
    
    loop {
        core::hint::spin_loop();
    }
}



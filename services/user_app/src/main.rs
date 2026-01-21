#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;

mod allocator;
use libnova::syscall::*;
use libnova::println;
use sel4_sys::{seL4_CPtr, seL4_IPCBuffer};

use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// Define the IPC Buffer symbol required by libsel4/sel4-sys
// The RootServer maps the IPC buffer at 0x3000_0000 for this process.
#[no_mangle]
pub static mut __sel4_ipc_buffer: *mut seL4_IPCBuffer = 0x3000_0000 as *mut seL4_IPCBuffer;

#[no_mangle]
pub extern "C" fn _start(argc: usize, argv: *const *const u8, ep_cap_usize: usize, envp: *const *const u8) -> ! {
    let ep_cap = ep_cap_usize as seL4_CPtr;
    // Initialize libnova console
    libnova::console::init_console(ep_cap_usize);

    println!("Process Entry: argc={}", argc);

    unsafe {
        // Demonstrate Arg iterator usage
        let args_iter = libnova::env::Args::new(argc, argv);
        for (i, arg) in args_iter.enumerate() {
            println!("Arg {}: {}", i, arg);
        }

        // Print Environment Variables
        println!("Environment Variables:");
        if !envp.is_null() {
            let mut curr = envp;
            while !(*curr).is_null() {
                let s_ptr = *curr;
                // simple strlen
                let mut len = 0;
                while *s_ptr.add(len) != 0 {
                    len += 1;
                }
                let s_slice = core::slice::from_raw_parts(s_ptr, len);
                if let Ok(s) = core::str::from_utf8(s_slice) {
                    println!("  {}", s);
                }
                curr = curr.add(1);
            }
        } else {
            println!("  <none>");
        }
    }
    
    // Determine who we are
    let pid = sys_get_pid(ep_cap);
    
    if pid == 0 {
        println!("Process 0: Started.");
        println!("Hello from Rust User App via Syscall!");
        
        // Test File System Syscalls
        println!("Testing File System Syscalls...");
        let filename = "/test_fs.txt";
        // 1 = WriteOnly (Implies Create in our simplified logic for now)
        let fd = sys_open(ep_cap, filename, 1); 
        
        if fd >= 0 {
            println!("File opened successfully. FD: {}", fd);
            let content = b"Hello NovaFS!";
            let written = sys_file_write(ep_cap, fd as usize, content);
            println!("Written {} bytes.", written);
            
            sys_close(ep_cap, fd as usize);
            println!("File closed.");
            
            // Re-open for reading
            let fd_read = sys_open(ep_cap, filename, 0); // 0 = ReadOnly
            if fd_read >= 0 {
                 println!("File re-opened for reading. FD: {}", fd_read);
                 let mut read_buf = [0u8; 32];
                 let read_bytes = sys_read(ep_cap, fd_read as usize, &mut read_buf);
                 if read_bytes > 0 {
                     let read_str = core::str::from_utf8(&read_buf[..read_bytes as usize]).unwrap_or("<invalid utf8>");
                     println!("Read content: {}", read_str);
                     if read_str == "Hello NovaFS!" {
                         println!("FS Test Passed!");
                     } else {
                         println!("FS Test Failed: Content mismatch.");
                     }
                 } else {
                     println!("FS Test Failed: Read returned {}", read_bytes);
                 }
                 sys_close(ep_cap, fd_read as usize);
            } else {
                println!("FS Test Failed: Could not re-open file.");
            }
            
            // Test Rename
            println!("Testing sys_rename...");
            if sys_rename(ep_cap, filename, "/test_renamed.txt") == 0 {
                println!("Rename successful.");
                let fd_renamed = sys_open(ep_cap, "/test_renamed.txt", 0);
                if fd_renamed >= 0 {
                    println!("Renamed file opened successfully.");
                    sys_close(ep_cap, fd_renamed as usize);
                    println!("Rename Test Passed!");
                } else {
                    println!("Rename Test Failed: Could not open renamed file.");
                }
            } else {
                println!("Rename Test Failed: sys_rename returned error.");
            }
        } else {
             println!("FS Test Failed: Could not open file (FD={}).", fd);
        }
        
        // Test Dynamic Memory
        let current_brk = sys_brk(ep_cap, 0);
        let new_brk_req = current_brk + 4096;
        let new_brk = sys_brk(ep_cap, new_brk_req);
        
        if new_brk == new_brk_req {
            println!("Heap expansion successful!");
            let ptr = current_brk as *mut u8;
            unsafe { *ptr = b'A'; }
            if unsafe { *ptr } == b'A' {
                 println!("Heap memory write verified!");
            } else {
                 println!("Heap memory write failed!");
            }
        } else {
            println!("Heap expansion failed!");
        }
        
        // Test Global Allocator
        println!("Initializing Global Allocator...");
        let heap_size = 64 * 1024; // 64KB
        let heap_start = sys_brk(ep_cap, 0);
        let heap_end = sys_brk(ep_cap, heap_start + heap_size);
        
        println!("Heap Range: 0x{:x} - 0x{:x}", heap_start, heap_end);

        if heap_end == heap_start + heap_size {
             println!("Heap block allocated. Initializing Allocator...");
             allocator::init_heap(heap_start, heap_size);
             
             // Test Vec
             println!("Testing Vec...");
             {
                 let mut v = Vec::new();
                 v.push(10);
                 v.push(20);
                 v.push(30);
                 println!("Vec: {:?}", v);
             }
             println!("Vec test passed!");
        } else {
             println!("Failed to allocate heap for allocator!");
        }

        // Test Process Management
        println!("Testing Process Management...");
        // Spawn self as child (will get pid != 0)
        let child_pid = sys_spawn(ep_cap, "/bin/hello", &["arg1", "arg2"], &["TEST_ENV=NovaOS"]);
        if child_pid >= 0 {
            println!("Spawned child PID: {}", child_pid);
            let (wpid, status) = sys_wait(ep_cap, child_pid, 0);
            println!("Waited for child {}, status: {}", wpid, status);
            
            if wpid == child_pid && status == 123 {
                println!("Process Management Test Passed!");
            } else {
                println!("Process Management Test Failed! (Expected status 123, got {})", status);
            }
        } else {
            println!("Failed to spawn child!");
        }

        // Test sys_kill
        println!("Testing sys_kill...");
        let child_pid_kill = sys_spawn(ep_cap, "/bin/hello", &["loop"], &[]);
        if child_pid_kill >= 0 {
             println!("Spawned child to kill PID: {}", child_pid_kill);
             sys_yield(ep_cap);
             
             println!("Killing child {}...", child_pid_kill);
             if sys_kill(ep_cap, child_pid_kill as usize, 9) == 0 {
                 println!("Kill signal sent.");
                 let (wpid, status) = sys_wait(ep_cap, child_pid_kill, 0);
                 println!("Waited for killed child {}, status: {}", wpid, status);
                 
                 // status -1 cast to usize is u64::MAX
                 if wpid == child_pid_kill && (status as isize) == -1 {
                     println!("Kill Test Passed!");
                 } else {
                     println!("Kill Test Failed! Status: {} (Expected -1)", status as isize);
                 }
             } else {
                 println!("Kill Test Failed: sys_kill returned error.");
             }
        }

    } else {
        println!("Process {} (Child) Started!", pid);
        
        // Check if "loop" arg is present
        let args_iter = unsafe { libnova::env::Args::new(argc, argv) };
        let mut loop_mode = false;
        for arg in args_iter {
            if arg == "loop" {
                loop_mode = true;
                break;
            }
        }
        
        if loop_mode {
             println!("Child entering infinite loop...");
             loop {
                 sys_yield(ep_cap);
             }
        } else {
            println!("Child exiting with code 123...");
            sys_exit(ep_cap, 123);
        }
    }
    
    sys_exit(ep_cap, 0);
}

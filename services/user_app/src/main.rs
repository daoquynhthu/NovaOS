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

const SHM_CHILD_VADDR: usize = 0x6FFD_0000;
const SHM_PARENT_VADDR: usize = 0x6FFE_0000;
const SHM_PARENT_MAGIC: u64 = 0xA1B2_C3D4_E5F6_0718;
const SHM_CHILD_MAGIC: u64 = 0x1837_26F5_E4D3_C2B1;

fn usize_to_decimal_str<'a>(mut value: usize, buf: &'a mut [u8; 20]) -> &'a str {
    let mut i = buf.len();
    if value == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while value > 0 && i > 0 {
            i -= 1;
            buf[i] = b'0' + (value % 10) as u8;
            value /= 10;
        }
    }
    unsafe { core::str::from_utf8_unchecked(&buf[i..]) }
}

#[no_mangle]
pub extern "C" fn _start(argc: usize, argv: *const *const u8, ep_cap_usize: usize, envp: *const *const u8) -> ! {
    let ep_cap = ep_cap_usize as seL4_CPtr;
    // Initialize libnova console
    libnova::console::init_console(ep_cap_usize);

    println!("DEBUG: User App Updated");
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
    println!("DEBUG: Got PID {}", pid);
    
    // Only PID 0 should execute the full integration suite.
    // This avoids duplicated destructive setup when extra user_app instances are launched.
    let is_main_suite = pid == 0;

    if is_main_suite {
        println!("Process {}: Started (Main Suite).", pid);
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

        let shrink_brk = sys_brk(ep_cap, current_brk);
        if shrink_brk == current_brk {
            println!("Heap shrink successful!");
        } else {
            println!(
                "Heap shrink failed! expected=0x{:x}, got=0x{:x}",
                current_brk, shrink_brk
            );
        }

        // Test shared mmap baseline (multi-page: 8K).
        println!("Testing sys_mmap_shared...");
        let shared_size = 8192usize;
        let shared_addr = sys_mmap_shared(ep_cap, shared_size);
        if shared_addr != 0 {
            unsafe {
                let p0 = shared_addr as *mut u64;
                let p1 = (shared_addr + 4096) as *mut u64;
                *p0 = 0x1122_3344_5566_7788;
                *p1 = 0x8877_6655_4433_2211;
                if *p0 == 0x1122_3344_5566_7788 && *p1 == 0x8877_6655_4433_2211 {
                    println!("Shared mmap test passed at 0x{:x}.", shared_addr);
                } else {
                    println!("Shared mmap test failed: read-back mismatch.");
                }
            }

            let unmap_ret = sys_munmap_shared(ep_cap, shared_addr, shared_size);
            if unmap_ret == 0 {
                println!("Shared munmap test passed.");
            } else {
                println!("Shared munmap test failed: {}.", unmap_ret);
            }

            let unmap_twice_ret = sys_munmap_shared(ep_cap, shared_addr, shared_size);
            if unmap_twice_ret != 0 {
                println!("Shared munmap double-call protection passed.");
            } else {
                println!("Shared munmap double-call protection failed.");
            }
        } else {
            println!("Shared mmap test failed: syscall returned 0.");
        }

        // Cross-process shared memory regression:
        // parent writes magic, child maps same key and writes back.
        // Child intentionally exits without munmap to verify exit-time detach path.
        println!("Testing cross-process shared memory...");
        let shm_key = sys_shm_alloc(ep_cap, 4096);
        if shm_key == 0 {
            println!("Cross-process SHM test failed: alloc returned 0.");
        } else {
            let parent_map_ret = sys_shm_map(ep_cap, shm_key, SHM_PARENT_VADDR);
            if parent_map_ret != 0 {
                println!("Cross-process SHM test failed: parent map failed.");
            } else {
                unsafe {
                    let p = SHM_PARENT_VADDR as *mut u64;
                    *p = SHM_PARENT_MAGIC;
                }

                let mut key_buf = [0u8; 20];
                let key_arg = usize_to_decimal_str(shm_key, &mut key_buf);
                let shm_child_pid = sys_spawn(ep_cap, "/bin/hello", &["shm_child", key_arg], &[]);
                if shm_child_pid < 0 {
                    println!("Cross-process SHM test failed: child spawn failed.");
                } else {
                    let mut child_status: usize = 0;
                    let mut child_reaped = false;
                    for _ in 0..2000 {
                        let (wpid, status) = sys_wait(ep_cap, shm_child_pid, 1);
                        if wpid == shm_child_pid {
                            child_status = status;
                            child_reaped = true;
                            break;
                        }
                        if wpid < 0 {
                            println!("Cross-process SHM test failed: wait returned {}.", wpid);
                            break;
                        }
                        sys_yield(ep_cap);
                    }

                    if !child_reaped {
                        println!("Cross-process SHM test timeout, trying to kill child...");
                        let _ = sys_kill(ep_cap, shm_child_pid as usize, 9);
                        for _ in 0..256 {
                            let (wpid, status) = sys_wait(ep_cap, shm_child_pid, 1);
                            if wpid == shm_child_pid {
                                child_status = status;
                                child_reaped = true;
                                break;
                            }
                            if wpid < 0 {
                                break;
                            }
                            sys_yield(ep_cap);
                        }
                    }

                    unsafe {
                        let p = SHM_PARENT_VADDR as *mut u64;
                        if child_reaped
                            && child_status == 124
                            && *p == SHM_CHILD_MAGIC
                        {
                            println!("Cross-process SHM test passed.");
                        } else {
                            println!(
                                "Cross-process SHM test failed: reaped={}, status={}, value=0x{:x}.",
                                child_reaped,
                                child_status,
                                *p
                            );
                        }
                    }
                }
            }
        }

        if shm_key != 0 {
            let parent_unmap_ret = sys_munmap_shared(ep_cap, SHM_PARENT_VADDR, 4096);
            if parent_unmap_ret == 0 {
                println!("Cross-process SHM cleanup passed.");
            } else {
                println!(
                    "Cross-process SHM cleanup failed: {}.",
                    parent_unmap_ret
                );
            }
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
    println!("[USER APP] About to call sys_spawn...");
    // Use standard sys_spawn
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
        
        // Parse child execution mode from args
        let args_iter = unsafe { libnova::env::Args::new(argc, argv) };
        let mut loop_mode = false;
        let mut expect_shm_key = false;
        let mut shm_child_key: Option<usize> = None;
        for arg in args_iter {
            if expect_shm_key {
                if let Ok(k) = arg.parse::<usize>() {
                    shm_child_key = Some(k);
                }
                expect_shm_key = false;
                continue;
            }
            if arg == "loop" {
                loop_mode = true;
            }
            if arg == "shm_child" {
                expect_shm_key = true;
            }
        }

        if let Some(key) = shm_child_key {
            println!("Child entering shared-memory verification mode...");
            if sys_shm_map(ep_cap, key, SHM_CHILD_VADDR) != 0 {
                println!("Child SHM map failed.");
                sys_exit(ep_cap, 201);
            }
            unsafe {
                let p = SHM_CHILD_VADDR as *mut u64;
                if *p != SHM_PARENT_MAGIC {
                    println!("Child SHM read mismatch.");
                    sys_exit(ep_cap, 202);
                }
                *p = SHM_CHILD_MAGIC;
            }
            // Intentionally do not call munmap here to verify exit-time detach/reclaim path.
            println!("Child SHM verification passed.");
            sys_exit(ep_cap, 124);
        } else if loop_mode {
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

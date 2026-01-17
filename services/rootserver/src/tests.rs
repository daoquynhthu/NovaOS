#![allow(dead_code, unused_imports)]
use sel4_sys::{
    seL4_BootInfo, seL4_CPtr, seL4_Word, seL4_PageBits, seL4_Error, seL4_CapRights,
    api_object_seL4_TCBObject, seL4_TCBBits,
    api_object_seL4_EndpointObject, seL4_EndpointBits,
};
use sel4_sys::seL4_RootCNodeCapSlots;
use sel4_sys::seL4_X86_VMAttributes;
use crate::memory::{UntypedAllocator, SlotAllocator, ObjectAllocator, FrameAllocator};
use crate::vspace::VSpace;
use crate::process::Process;
use crate::ipc::Endpoint;
use libnova::cap::{CapRights_new, CNode};

// Temporary constant until we confirm sel4_sys export
#[allow(non_upper_case_globals)]
const seL4_X86_4K: seL4_Word = 8;

pub fn run_all(
    boot_info: &seL4_BootInfo,
    allocator: &mut UntypedAllocator,
    slot_allocator: &mut SlotAllocator,
    frame_allocator: &mut FrameAllocator,
) {
    test_allocation(boot_info, allocator, slot_allocator);
    test_vspace_mapping(boot_info, allocator, slot_allocator);
    test_process_management(boot_info, allocator, slot_allocator);
    test_independent_vspace(boot_info, allocator, slot_allocator, frame_allocator);
    // test_process_spawn(boot_info, allocator, slot_allocator);
    test_user_hello_program(boot_info, allocator, slot_allocator, frame_allocator); // Moved back for automated testing
    test_process_manager();
    benchmark_ipc_latency(boot_info, allocator, slot_allocator);
    stress_test_memory_allocation(boot_info, allocator, slot_allocator);
    test_disk_driver();
}

pub fn test_disk_driver() {
    println!("[INFO] Testing Disk Driver (ATA PIO)...");
    use crate::drivers::ata::AtaDriver;
    
    let driver = AtaDriver::new(0x1F0);
    
    // Test Write to Sector 1
    let mut pattern = [0u8; 512];
    for i in 0..512 {
        pattern[i] = (i % 255) as u8;
    }
    pattern[0] = 0xBE;
    pattern[1] = 0xEF;
    
    println!("[DISK] Writing pattern to Sector 1...");
    if let Err(e) = driver.write_sectors(1, &pattern) {
        println!("[ERROR] Disk Write Failed: {}", e);
        return;
    }
    
    // Test Read from Sector 1
    println!("[DISK] Reading back Sector 1...");
    match driver.read_sectors(1, 1) {
        Ok(data) => {
            if data.len() != 512 {
                println!("[ERROR] Read length mismatch: {}", data.len());
                return;
            }
            
            if data[0] == 0xBE && data[1] == 0xEF && data[511] == (511 % 255) as u8 {
                println!("[PASS] Disk Read/Write Verified!");
            } else {
                println!("[ERROR] Disk Content Mismatch! [0]={:x}, [1]={:x}, [511]={:x}", data[0], data[1], data[511]);
            }
        },
        Err(e) => println!("[ERROR] Disk Read Failed: {}", e),
    }
}

#[allow(dead_code)]
fn test_user_hello_program(
    boot_info: &seL4_BootInfo,
    allocator: &mut UntypedAllocator,
    slot_allocator: &mut SlotAllocator,
    frame_allocator: &mut FrameAllocator,
) {
    println!("[INFO] Testing user-mode hello ELF...");

    // Allocate Syscall Endpoint
    let syscall_ep_cap = match allocator.allocate(
        boot_info,
        api_object_seL4_EndpointObject.into(),
        seL4_EndpointBits.into(),
        slot_allocator,
    ) {
        Ok(cap) => cap,
        Err(e) => {
            println!("[ERROR] Failed to allocate syscall endpoint: {:?}", e);
            return;
        }
    };

    println!("[INFO] Spawning process with Syscall Endpoint Cap: {}", syscall_ep_cap);

    let elf_data = crate::filesystem::get_file("hello").expect("hello binary not found");
    let mut process = match Process::spawn(allocator, slot_allocator, frame_allocator, boot_info, elf_data, &[], 100, syscall_ep_cap) {
        Ok(p) => p,
        Err(e) => {
            println!("[ERROR] Failed to spawn hello program: {:?}", e);
            return;
        }
    };

    let syscall_ep = Endpoint::new(syscall_ep_cap);
    println!("[INFO] Process spawned. Entering syscall loop...");

    // First Recv (Client starts with Call, so we must Recv)
    let (mut info, mut sender_badge, mut mrs) = syscall_ep.recv_with_mrs();

    loop {
        let label = info.label();

        match label {
            1 => { // sys_write (debug_print)
                // MR0..MR3 contain string chunks (8 bytes each)
                let mut bytes = [0u8; 32];
                unsafe {
                    let p = bytes.as_mut_ptr() as *mut u64;
                    *p.add(0) = mrs[0];
                    *p.add(1) = mrs[1];
                    *p.add(2) = mrs[2];
                    *p.add(3) = mrs[3];
                }
                for &b in bytes.iter() {
                    if b == 0 { break; }
                    print!("{}", b as char);
                }

                // Reply with success (0) and wait for next
                let (new_info, new_badge, new_mrs) = syscall_ep.reply_recv_with_mrs(
                    libnova::ipc::MessageInfo::new(0, 0, 0, 1),
                    [0, 0, 0, 0]
                );
                info = new_info;
                sender_badge = new_badge;
                mrs = new_mrs;
            }
            2 => { // sys_exit
                println!("[INFO] Process exited with code: {}", mrs[0]);
                break;
            }
            3 => { // sys_brk
                 // Mock sys_brk for test
                 println!("[TEST] sys_brk called. Returning success.");
                 let (new_info, new_badge, new_mrs) = syscall_ep.reply_recv_with_mrs(
                    libnova::ipc::MessageInfo::new(0, 0, 0, 1),
                    [mrs[0], 0, 0, 0] // Return same addr as success
                );
                info = new_info;
                sender_badge = new_badge;
                mrs = new_mrs;
            }
            4 => { // sys_yield
                println!("[TEST] Process yielded.");
                let (new_info, new_badge, new_mrs) = syscall_ep.reply_recv_with_mrs(
                    libnova::ipc::MessageInfo::new(0, 0, 0, 0),
                    [0, 0, 0, 0]
                );
                info = new_info;
                sender_badge = new_badge;
                mrs = new_mrs;
            }
            _ => {
                println!("[INFO] Unknown syscall label: {}. Badge: {}", label, sender_badge);
                break;
            }
        }
    }

    let cnode = seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
    match process.terminate(cnode, slot_allocator, frame_allocator) {
        Ok(()) => println!("[INFO] Hello process terminated."),
        Err(e) => println!("[ERROR] Failed to terminate hello process: {:?}", e),
    }
}

fn test_process_manager() {
    println!("[INFO] Testing ProcessManager (Global)...");
    use crate::process::{Process, get_process_manager};
    
    // Access the global process manager
    let mut pm = get_process_manager();
    
    // Create a dummy process (invalid caps, just for structural test)
    let dummy_process = Process {
        tcb_cap: 999,
        vspace: crate::vspace::VSpace { pml4_cap: 888, paging_caps: [0; 32], paging_cap_count: 0 },
        fault_ep_cap: 0,
        syscall_ep_cap: 0,
        ipc_buffer_cap: 0,
        state: crate::process::ProcessState::Created,
        heap_brk: 0x4000_0000,
        mapped_frames: alloc::vec::Vec::new(),
        wake_at_tick: 0,
        saved_reply_cap: 0,
        mailbox: None,
        fds: alloc::vec![const { None }; crate::process::MAX_FDS],
        priority: 0,
    };
    
    // Test Add
    match pm.add_process(dummy_process) {
        Ok(pid) => {
            println!("[INFO] Added process with PID: {}", pid);
            assert!(pid == 0);
        },
        Err(e) => println!("[ERROR] Failed to add process: {:?}", e),
    }
    
    // Test Get
    if let Some(p) = pm.get_process(0) {
        println!("[INFO] Retrieved process 0, TCB cap: {}", p.tcb_cap);
        assert!(p.tcb_cap == 999);
    } else {
        println!("[ERROR] Failed to get process 0");
    }

    // Test Get Mut
    if let Some(p) = pm.get_process_mut(0) {
        println!("[INFO] Retrieved process 0 (mut), changing TCB cap...");
        p.tcb_cap = 1000;
    }
    
    // Verify Mutation
    if let Some(p) = pm.get_process(0) {
        assert!(p.tcb_cap == 1000);
        println!("[INFO] Mutation verified.");
    }

    // Test Remove
    if let Some(p) = pm.remove_process(0) {
        println!("[INFO] Removed process 0, TCB cap: {}", p.tcb_cap);
        assert!(p.tcb_cap == 1000);
    } else {
        println!("[ERROR] Failed to remove process 0");
    }
    
    // Test Empty
    if pm.get_process(0).is_none() {
        println!("[INFO] Process 0 is indeed gone.");
    } else {
        println!("[ERROR] Process 0 still exists!");
    }
}

fn benchmark_ipc_latency(
    boot_info: &seL4_BootInfo,
    allocator: &mut UntypedAllocator,
    slot_allocator: &mut SlotAllocator,
) {
    println!("[BENCHMARK] Measuring IPC Round-Trip Latency...");
    
    // Setup Thread
    let tcb_obj = api_object_seL4_TCBObject;
    let tcb_bits = seL4_TCBBits;
    let tcb_cap = allocator.allocate(boot_info, tcb_obj.into(), tcb_bits.into(), slot_allocator).expect("TCB Alloc");
    
    let vspace_root = seL4_RootCNodeCapSlots::seL4_CapInitThreadVSpace as seL4_CPtr;
    let mut process = Process::new(tcb_cap, VSpace::new(vspace_root));
    
    // Allocate Stack
    let stack_vaddr = 0x40000000;
    let stack_top = stack_vaddr + 4096;
    let stack_frame_cap = allocator.allocate(boot_info, seL4_X86_4K.into(), seL4_PageBits.into(), slot_allocator).expect("Stack Alloc");
    let rights = CapRights_new(false, false, true, true);
    let attr = seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes;
    process.vspace.map_page(allocator, slot_allocator, boot_info, stack_frame_cap, stack_vaddr, rights, attr).expect("Stack Map");

    // Allocate IPC Buffer
    let ipc_vaddr = 0x50000000;
    let ipc_frame_cap = allocator.allocate(boot_info, seL4_X86_4K.into(), seL4_PageBits.into(), slot_allocator).expect("IPC Alloc");
    process.vspace.map_page(allocator, slot_allocator, boot_info, ipc_frame_cap, ipc_vaddr, rights, attr).expect("IPC Map");
    
    // Endpoint
    let endpoint_cap = allocator.allocate(boot_info, api_object_seL4_EndpointObject.into(), seL4_EndpointBits.into(), slot_allocator).expect("EP Alloc");
    
    // Configure
    let cspace_root = seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
    process.configure(cspace_root, 0, ipc_vaddr as seL4_Word, ipc_frame_cap).expect("Config");
    
    let authority = seL4_RootCNodeCapSlots::seL4_CapInitThreadTCB as seL4_CPtr;
    process.set_priority(authority, 254).expect("Priority");
    
    let rip = benchmark_worker as *const () as usize as seL4_Word;
    let rsp = stack_top as seL4_Word;
    process.write_registers(rip, rsp, 0x202, endpoint_cap).expect("Regs");
    
    process.resume().expect("Resume");
    
    // Measurement Loop
    let endpoint = Endpoint::new(endpoint_cap);
    let iterations = 1000;
    
    // Warmup
    for _ in 0..100 {
        endpoint.call(1);
    }
    
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    for _ in 0..iterations {
        endpoint.call(1);
    }
    let end = unsafe { core::arch::x86_64::_rdtsc() };
    
    let total_cycles = end - start;
    let avg_cycles = total_cycles / iterations;
    println!("[BENCHMARK] Average IPC Call-Reply Latency: {} cycles", avg_cycles);
    
    // Clean up (terminate worker)
    endpoint.call(0); // Signal to exit
    // process.terminate(cspace_root).expect("Terminate"); // Optional cleanup
}

#[no_mangle]
pub extern "C" fn benchmark_worker(endpoint_cap: seL4_CPtr) {
    let endpoint = Endpoint::new(endpoint_cap);
    let (mut msg, _) = endpoint.recv();
    loop {
        if msg == 0 { 
            // Reply to the exit signal to unblock the client
            // reply_recv replies to the current message (0) and waits for next.
            // This unblocks the client. We then break and yield/exit.
            endpoint.reply_recv(0);
            break; 
        }
        let (next_msg, _) = endpoint.reply_recv(msg);
        msg = next_msg;
    }
    loop { unsafe { sel4_sys::seL4_Yield(); } }
}

fn test_process_spawn(
    boot_info: &seL4_BootInfo,
    allocator: &mut UntypedAllocator,
    slot_allocator: &mut SlotAllocator,
    frame_allocator: &mut FrameAllocator,
) {
    println!("[INFO] Testing Process Spawn interface...");
    
    // Dummy ELF Data (just enough to fail parsing gracefully or trigger logic)
    // We pass a small buffer with invalid magic to ensure we don't trigger OOB panic in parser
    let dummy_elf = [0u8; 64]; 
    
    // We expect this to fail at ELF loading stage, but it validates compilation and linkage of spawn()
    match Process::spawn(
        allocator, 
        slot_allocator, 
        frame_allocator,
        boot_info, 
        &dummy_elf, 
        &[],
        100,
        0
    ) {
        Ok(_) => println!("[INFO] Process spawned (unexpectedly success with empty ELF)"),
        Err(e) => println!("[INFO] Process spawn validated (Expected failure for empty ELF: {:?})", e),
    }

    // Verify spawn accepts arguments (compilation check)
    match Process::spawn(
        allocator, 
        slot_allocator, 
        frame_allocator,
        boot_info, 
        &dummy_elf, 
        &["test_arg1", "test_arg2"],
        100,
        0
    ) {
        Ok(_) => println!("[INFO] Process spawned with args (unexpectedly success)"),
        Err(_) => println!("[INFO] Process spawn with args interface validated"),
    }
}

fn stress_test_memory_allocation(
    boot_info: &seL4_BootInfo,
    allocator: &mut UntypedAllocator,
    slot_allocator: &mut SlotAllocator,
) {
    println!("[STRESS] Allocating 1000 frames...");
    let mut caps = [0; 1000];
    for (i, cap_slot) in caps.iter_mut().enumerate() {
        if i % 100 == 0 {
             println!("[STRESS] Progress: {}/1000", i);
        }
        match allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slot_allocator) {
            Ok(cap) => *cap_slot = cap,
            Err(e) => {
                println!("[STRESS] Failed at frame {}: {:?}", i, e);
                break;
            }
        }
    }
    let count = caps.iter().filter(|&&c| c != 0).count();
    println!("[STRESS] Successfully allocated {} frames", count);

    // Check fragmentation stats
    let (total_caps, ram_caps, ram_used, ram_total, _) = allocator.stats(boot_info);
    println!("[STRESS] Memory Stats: Caps={}/{}, RAM Usage={} / {} bytes ({}%)", 
        ram_caps, total_caps, ram_used, ram_total, 
        if ram_total > 0 { (ram_used * 100) / ram_total } else { 0 }
    );
}

fn test_allocation(
    boot_info: &seL4_BootInfo,
    allocator: &mut UntypedAllocator,
    slot_allocator: &mut SlotAllocator,
) {
    println!("[INFO] Testing allocation of 5 x 4KB Frames...");
    for i in 0..5 {
        match allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slot_allocator) {
           Ok(slot) => println!("[INFO] Allocated 4KB Frame #{} in slot {}", i + 1, slot),
           Err(e) => println!("[ERROR] Allocation #{} failed with error: {:?}", i + 1, e),
        }
    }
}

fn test_vspace_mapping(
    boot_info: &seL4_BootInfo,
    allocator: &mut UntypedAllocator,
    slot_allocator: &mut SlotAllocator,
) {
    println!("[INFO] Testing VSpace Mapping...");
    let pml4_cap = seL4_RootCNodeCapSlots::seL4_CapInitThreadVSpace as seL4_CPtr;
    let mut vspace = VSpace::new(pml4_cap);
    
    println!("[INFO] Allocating frame for mapping...");
    match allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slot_allocator) {
        Ok(frame_cap) => {
            println!("[INFO] Frame allocated at slot {}. Mapping to 0x10000000...", frame_cap);
            let vaddr = 0x10000000;
            let rights = CapRights_new(false, false, true, true); // Read | Write
            let attr = seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes;
            
            match vspace.map_page(allocator, slot_allocator, boot_info, frame_cap, vaddr, rights, attr) {
                Ok(_) => {
                     println!("[INFO] Page mapped successfully at 0x{:x}", vaddr);
                     let ptr = vaddr as *mut u64;
                     unsafe { *ptr = 0xDEADBEEF; }
                     println!("[INFO] Write to 0x{:x} succeeded. Value: 0x{:x}", vaddr, unsafe { *ptr });
                },
                Err(e) => println!("[ERROR] Page map failed: {:?}", e),
            }
        },
        Err(e) => println!("[ERROR] Frame allocation failed: {:?}", e),
    }
}

fn test_process_management(
    boot_info: &seL4_BootInfo,
    allocator: &mut UntypedAllocator,
    slot_allocator: &mut SlotAllocator,
) {
    println!("[INFO] Testing Process Management...");
    
    let tcb_obj = api_object_seL4_TCBObject;
    let tcb_bits = seL4_TCBBits;
    let mut tcb_cap = 0;
    
    match allocator.allocate(boot_info, tcb_obj.into(), tcb_bits.into(), slot_allocator) {
        Ok(cap) => {
            tcb_cap = cap;
            println!("[INFO] Allocated TCB at slot {}", tcb_cap);
        },
        Err(e) => println!("[ERROR] Failed to allocate TCB: {:?}", e),
    }

    if tcb_cap != 0 {
        let vspace_root = seL4_RootCNodeCapSlots::seL4_CapInitThreadVSpace as seL4_CPtr;
        let mut process = Process::new(tcb_cap, VSpace::new(vspace_root));
        
        let stack_vaddr = 0x20000000;
        let stack_top = stack_vaddr + 4096;
        let mut stack_frame_cap = 0;
        
        match allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slot_allocator) {
             Ok(cap) => {
                 stack_frame_cap = cap;
                 let rights = CapRights_new(false, false, true, true);
                 let attr = seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes;
                 match process.vspace.map_page(allocator, slot_allocator, boot_info, cap, stack_vaddr, rights, attr) {
                     Ok(_) => println!("[INFO] Mapped stack at 0x{:x}", stack_vaddr),
                     Err(e) => println!("[ERROR] Failed to map stack: {:?}", e),
                 }
             },
             Err(e) => println!("[ERROR] Failed to allocate stack frame: {:?}", e),
        }
        
        let ipc_vaddr = 0x30000000;
        let mut ipc_frame_cap = 0;
        
        match allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slot_allocator) {
             Ok(cap) => {
                 ipc_frame_cap = cap;
                 let rights = CapRights_new(false, false, true, true);
                 let attr = seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes;
                 match process.vspace.map_page(allocator, slot_allocator, boot_info, cap, ipc_vaddr, rights, attr) {
                     Ok(_) => println!("[INFO] Mapped IPC Buffer at 0x{:x}", ipc_vaddr),
                     Err(e) => println!("[ERROR] Failed to map IPC Buffer: {:?}", e),
                 }
             },
             Err(e) => println!("[ERROR] Failed to allocate IPC frame: {:?}", e),
        }
        
        if stack_frame_cap != 0 && ipc_frame_cap != 0 {
            let mut endpoint_cap = 0;
            match allocator.allocate(boot_info, api_object_seL4_EndpointObject.into(), seL4_EndpointBits.into(), slot_allocator) {
                Ok(cap) => {
                    endpoint_cap = cap;
                    println!("[INFO] Allocated Endpoint at slot {}", endpoint_cap);
                },
                Err(e) => println!("[ERROR] Failed to allocate Endpoint: {:?}", e),
            }

            if endpoint_cap != 0 {
                let mut badged_endpoint_cap = 0;
                if let Ok(slot) = slot_allocator.alloc() {
                    badged_endpoint_cap = slot;
                    let root_cap = seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                    let root_cnode = CNode::new(root_cap, 64); // 64-bit CNode
                    let badge = 0xBEEF;
                    
                    let rights = libnova::cap::CapRights_new(true, false, true, true);
                    match root_cnode.mint(
                        badged_endpoint_cap,
                        &root_cnode,
                        endpoint_cap,
                        rights,
                        badge
                    ) {
                        Ok(_) => println!("[INFO] Minted Badged Endpoint (Badge=0x{:x}) at slot {}", badge, badged_endpoint_cap),
                        Err(e) => {
                            println!("[ERROR] Failed to mint badged cap: {:?}", e);
                            badged_endpoint_cap = 0;
                        }
                    }
                }

                let cspace_root = seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                
                // For this test, we don't strictly need a fault endpoint as it's running in same vspace (thread)
                // But we can pass 0 for now or create one.
                match process.configure(cspace_root, 0, ipc_vaddr as seL4_Word, ipc_frame_cap) {
                    Ok(_) => println!("[INFO] TCB Configured."),
                    Err(e) => println!("[ERROR] TCB Configure failed: {:?}", e),
                }
                
                let authority = seL4_RootCNodeCapSlots::seL4_CapInitThreadTCB as seL4_CPtr;
                match process.set_priority(authority, 254) {
                     Ok(_) => println!("[INFO] Priority Set."),
                     Err(e) => println!("[ERROR] Set Priority failed: {:?}", e),
                }
                
                let rip = worker_thread as *const () as usize as seL4_Word;
                let rsp = stack_top as seL4_Word;
                match process.write_registers(rip, rsp, 0x202, endpoint_cap) {
                     Ok(_) => println!("[INFO] Registers Written. RIP=0x{:x}, RSP=0x{:x}, ARG1={}", rip, rsp, endpoint_cap),
                     Err(e) => println!("[ERROR] Write Registers failed: {:?}", e),
                }
                
                match process.resume() {
                     Ok(_) => println!("[INFO] Thread Resumed!"),
                     Err(e) => println!("[ERROR] Resume failed: {:?}", e),
                }
                
                let client_cap = if badged_endpoint_cap != 0 { badged_endpoint_cap } else { endpoint_cap };
                let endpoint = Endpoint::new(client_cap);
                println!("[MAIN] Sending IPC message to worker using cap {}...", client_cap);
                let response = endpoint.call(0x12345678);
                println!("[MAIN] Received response: 0x{:x}", response);
                
                if response == 0x87654321 {
                    println!("[MAIN] IPC Test SUCCESS!");
                } else {
                    println!("[MAIN] IPC Test FAILED!");
                }
            }
        }
    }
}

fn test_independent_vspace(
    boot_info: &seL4_BootInfo,
    allocator: &mut UntypedAllocator,
    slot_allocator: &mut SlotAllocator,
    frame_allocator: &mut FrameAllocator,
) {
    println!("[INFO] Testing Independent VSpace Creation & Isolation & Fault Handling...");
    
    let asid_pool = seL4_RootCNodeCapSlots::seL4_CapInitThreadASIDPool as seL4_CPtr;
    
    match allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slot_allocator) {
        Ok(code_frame_cap) => {
             println!("[INFO] Allocated frame for Child Code at slot {}", code_frame_cap);

             let root_vaddr = 0x500000;
             let rights_all = libnova::cap::CapRights_new(false, false, true, true);
             let attr = seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes;
             
             let root_pml4 = seL4_RootCNodeCapSlots::seL4_CapInitThreadVSpace as seL4_CPtr;
             let mut root_vspace = VSpace::new(root_pml4);
             
             if root_vspace.map_page(allocator, slot_allocator, boot_info, code_frame_cap, root_vaddr, rights_all, attr).is_ok() {
                  unsafe {
                      let ptr = root_vaddr as *mut u8;
                      // Write UD2 instruction (0x0F, 0x0B) to trigger fault
                      *ptr = 0x0F;
                      *(ptr.add(1)) = 0x0B;
                  }
                  println!("[INFO] Code written to frame via Root VSpace (UD2 instruction).");
                  
                  let mut child_code_frame_cap = 0;
                  match slot_allocator.alloc() {
                      Ok(slot) => {
                          child_code_frame_cap = slot;
                          let cnode_cap = seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                          let root_cnode = CNode::new(cnode_cap, 64);
                           if let Err(e) = root_cnode.copy(
                               child_code_frame_cap,
                               &root_cnode,
                               code_frame_cap,
                               rights_all
                           ) {
                              println!("[ERROR] Failed to copy code frame cap: {:?}", e);
                              child_code_frame_cap = 0;
                          }
                      }
                      Err(_) => println!("[ERROR] Failed to allocate slot for copy"),
                  }

                  let child_vaddr = 0x400000;

                  match Process::create(allocator, slot_allocator, boot_info, asid_pool) {
                    Ok(mut child_process) => {
                        if child_code_frame_cap != 0 {
                             match child_process.vspace.map_page(allocator, slot_allocator, boot_info, child_code_frame_cap, child_vaddr, rights_all, attr) {
                                 Ok(_) => println!("[INFO] Mapped code frame to Child VSpace at 0x{:x}", child_vaddr),
                                 Err(e) => println!("[ERROR] Failed to map in new VSpace: {:?}", e),
                             }
                          }

                          if let Ok(cap) = allocator.allocate(boot_info, seL4_X86_4K.into(), seL4_PageBits.into(), slot_allocator) {
                              let ipc_frame_cap = cap;
                              let ipc_vaddr = 0x600000;
                              let _ = child_process.vspace.map_page(allocator, slot_allocator, boot_info, cap, ipc_vaddr, rights_all, attr);
                              
                              let cspace_root = seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                              
                              // Create Fault Endpoint
                              let mut fault_ep_cap = 0;
                              if let Ok(ep) = allocator.allocate(boot_info, api_object_seL4_EndpointObject.into(), seL4_EndpointBits.into(), slot_allocator) {
                                  fault_ep_cap = ep;
                                  println!("[INFO] Allocated Fault Endpoint at slot {}", fault_ep_cap);
                              }

                              match child_process.configure(cspace_root, fault_ep_cap, ipc_vaddr as seL4_Word, ipc_frame_cap) {
                                  Ok(_) => {
                                      println!("[INFO] Child TCB Configured.");
                                      let authority = seL4_RootCNodeCapSlots::seL4_CapInitThreadTCB as seL4_CPtr;
                                      let _ = child_process.set_priority(authority, 100);

                                      match child_process.write_registers(child_vaddr as seL4_Word, 0, 0x202, 0) {
                                          Ok(_) => println!("[INFO] Child Registers Set."),
                                          Err(e) => println!("[ERROR] Failed to set registers: {:?}", e),
                                      }

                                      match child_process.resume() {
                                          Ok(_) => println!("[INFO] Child Thread Resumed! (Should Fault)"),
                                          Err(e) => println!("[ERROR] Resume failed: {:?}", e),
                                      }
                                      
                                      // Listen for Fault
                                      if fault_ep_cap != 0 {
                                          println!("[INFO] Waiting for fault on endpoint {}...", fault_ep_cap);
                                          let fault_ep = Endpoint::new(fault_ep_cap);
                                          // Blocking recv to let child run
                                           let (msg, sender) = fault_ep.recv();
                                           println!("[INFO] Received Fault Message! Data: 0x{:x}, Badge: {}", msg, sender);
                                           
                                           // Terminate Process
                                           let cnode = seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
                                           match child_process.terminate(cnode, slot_allocator, frame_allocator) {
                                               Ok(_) => println!("[INFO] Child Process Terminated successfully."),
                                               Err(e) => println!("[ERROR] Failed to terminate child: {:?}", e),
                                           }
                                       }
                                   },
                                  Err(e) => println!("[ERROR] Child Configure failed: {:?}", e),
                              }
                          }
                      },
                      Err(e) => println!("[ERROR] Failed to create child process: {:?}", e),
                  }
             }
        },
        Err(e) => println!("[ERROR] Frame alloc failed: {:?}", e),
    }
}

#[no_mangle]
pub extern "C" fn worker_thread(endpoint_cap: seL4_CPtr) {
    println!("\n[WORKER] Hello from the second thread!");
    println!("[WORKER] I am running in the same address space.");
    println!("[WORKER] Endpoint Cap: {}", endpoint_cap);
    
    let endpoint = Endpoint::new(endpoint_cap);
    
    println!("[WORKER] Waiting for message...");
    let (msg, sender) = endpoint.recv();
    println!("[WORKER] Received: 0x{:x} from badge/cap {}", msg, sender);
    
    let reply_val = 0x87654321;
    println!("[WORKER] Replying with 0x{:x}", reply_val);
    endpoint.reply_recv(reply_val);
    
    println!("[WORKER] Done.");
    loop {
        unsafe { sel4_sys::seL4_Yield(); }
    }
}

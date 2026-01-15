use sel4_sys::{
    seL4_BootInfo, seL4_CPtr, seL4_Word, seL4_PageBits,
    seL4_X86_VMAttributes_seL4_X86_Default_VMAttributes,
    seL4_RootCNodeCapSlots_seL4_CapInitThreadVSpace,
    seL4_RootCNodeCapSlots_seL4_CapInitThreadCNode,
    seL4_RootCNodeCapSlots_seL4_CapInitThreadTCB,
    seL4_RootCNodeCapSlots_seL4_CapInitThreadASIDPool,
    api_object_seL4_TCBObject, seL4_TCBBits,
    api_object_seL4_EndpointObject, seL4_EndpointBits,
};
use crate::memory::{UntypedAllocator, SlotAllocator, ObjectAllocator};
use crate::vspace::VSpace;
use crate::process::Process;
use crate::ipc::Endpoint;
use crate::println;

use crate::utils::{seL4_CapRights_new, seL4_X86_4K, copy_cap};

pub fn run_all(
    boot_info: &seL4_BootInfo,
    allocator: &mut UntypedAllocator,
    slot_allocator: &mut SlotAllocator,
) {
    test_allocation(boot_info, allocator, slot_allocator);
    test_vspace_mapping(boot_info, allocator, slot_allocator);
    test_process_management(boot_info, allocator, slot_allocator);
    test_independent_vspace(boot_info, allocator, slot_allocator);
    stress_test_memory_allocation(boot_info, allocator, slot_allocator);
}

fn stress_test_memory_allocation(
    boot_info: &seL4_BootInfo,
    allocator: &mut UntypedAllocator,
    slot_allocator: &mut SlotAllocator,
) {
    println!("[STRESS] Allocating 1000 frames...");
    let mut caps = [0; 1000];
    for i in 0..1000 {
        match allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slot_allocator) {
            Ok(cap) => caps[i] = cap,
            Err(e) => {
                println!("[STRESS] Failed at frame {}: {:?}", i, e);
                break;
            }
        }
    }
    let count = caps.iter().filter(|&&c| c != 0).count();
    println!("[STRESS] Successfully allocated {} frames", count);
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
    let pml4_cap = seL4_RootCNodeCapSlots_seL4_CapInitThreadVSpace as seL4_CPtr;
    let mut vspace = VSpace::new(pml4_cap);
    
    println!("[INFO] Allocating frame for mapping...");
    match allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slot_allocator) {
        Ok(frame_cap) => {
            println!("[INFO] Frame allocated at slot {}. Mapping to 0x10000000...", frame_cap);
            let vaddr = 0x10000000;
            let rights = seL4_CapRights_new(0, 0, 1, 1); // Read | Write
            let attr = seL4_X86_VMAttributes_seL4_X86_Default_VMAttributes;
            
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
        let vspace_root = seL4_RootCNodeCapSlots_seL4_CapInitThreadVSpace as seL4_CPtr;
        let mut process = Process::new(tcb_cap, VSpace::new(vspace_root));
        
        let stack_vaddr = 0x20000000;
        let stack_top = stack_vaddr + 4096;
        let mut stack_frame_cap = 0;
        
        match allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slot_allocator) {
             Ok(cap) => {
                 stack_frame_cap = cap;
                 let rights = seL4_CapRights_new(0, 0, 1, 1);
                 let attr = seL4_X86_VMAttributes_seL4_X86_Default_VMAttributes;
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
                 let rights = seL4_CapRights_new(0, 0, 1, 1);
                 let attr = seL4_X86_VMAttributes_seL4_X86_Default_VMAttributes;
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
                    let root = seL4_RootCNodeCapSlots_seL4_CapInitThreadCNode as seL4_CPtr;
                    let badge = 0xBEEF;
                    
                    unsafe {
                        let err = sel4_sys::seL4_CNode_Mint(
                            root, badged_endpoint_cap, 64,
                            root, endpoint_cap, 64,
                            seL4_CapRights_new(1, 0, 1, 1),
                            badge
                        );
                        if err != 0.into() {
                            println!("[ERROR] Failed to mint badged cap: {:?}", err);
                            badged_endpoint_cap = 0;
                        } else {
                            println!("[INFO] Minted Badged Endpoint (Badge=0x{:x}) at slot {}", badge, badged_endpoint_cap);
                        }
                    }
                }

                let cspace_root = seL4_RootCNodeCapSlots_seL4_CapInitThreadCNode as seL4_CPtr;
                
                // For this test, we don't strictly need a fault endpoint as it's running in same vspace (thread)
                // But we can pass 0 for now or create one.
                match process.configure(cspace_root, 0, ipc_vaddr as seL4_Word, ipc_frame_cap) {
                    Ok(_) => println!("[INFO] TCB Configured."),
                    Err(e) => println!("[ERROR] TCB Configure failed: {:?}", e),
                }
                
                let authority = seL4_RootCNodeCapSlots_seL4_CapInitThreadTCB as seL4_CPtr;
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
) {
    println!("[INFO] Testing Independent VSpace Creation & Isolation & Fault Handling...");
    
    let asid_pool = seL4_RootCNodeCapSlots_seL4_CapInitThreadASIDPool as seL4_CPtr;
    
    match allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slot_allocator) {
        Ok(code_frame_cap) => {
             println!("[INFO] Allocated frame for Child Code at slot {}", code_frame_cap);

             let root_vaddr = 0x500000;
             let rights_all = seL4_CapRights_new(0, 0, 1, 1);
             let attr = seL4_X86_VMAttributes_seL4_X86_Default_VMAttributes;
             
             let root_pml4 = seL4_RootCNodeCapSlots_seL4_CapInitThreadVSpace as seL4_CPtr;
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
                          let cnode = seL4_RootCNodeCapSlots_seL4_CapInitThreadCNode as seL4_CPtr;
                           unsafe {
                               let err = copy_cap(
                                   cnode, child_code_frame_cap, 64,
                                   cnode, code_frame_cap, 64,
                                   rights_all
                               );
                               if err != 0.into() {
                                  println!("[ERROR] Failed to copy code frame cap: {:?}", err);
                                  child_code_frame_cap = 0;
                              }
                          }
                      }
                      Err(_) => println!("[ERROR] Failed to allocate slot for copy"),
                  }

                  let child_vaddr = 0x400000;

                  match Process::create(allocator, slot_allocator, boot_info, asid_pool) {
                    Ok(mut child_process) => {
                        if child_code_frame_cap != 0 {
                             child_process.code_frame_cap = child_code_frame_cap;
                             match child_process.vspace.map_page(allocator, slot_allocator, boot_info, child_code_frame_cap, child_vaddr, rights_all, attr) {
                                 Ok(_) => println!("[INFO] Mapped code frame to Child VSpace at 0x{:x}", child_vaddr),
                                 Err(e) => println!("[ERROR] Failed to map in new VSpace: {:?}", e),
                             }
                          }

                          if let Ok(cap) = allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slot_allocator) {
                              let ipc_frame_cap = cap;
                              let ipc_vaddr = 0x600000;
                              let _ = child_process.vspace.map_page(allocator, slot_allocator, boot_info, cap, ipc_vaddr, rights_all, attr);
                              
                              let cspace_root = seL4_RootCNodeCapSlots_seL4_CapInitThreadCNode as seL4_CPtr;
                              
                              // Create Fault Endpoint
                              let mut fault_ep_cap = 0;
                              if let Ok(ep) = allocator.allocate(boot_info, api_object_seL4_EndpointObject.into(), seL4_EndpointBits.into(), slot_allocator) {
                                  fault_ep_cap = ep;
                                  println!("[INFO] Allocated Fault Endpoint at slot {}", fault_ep_cap);
                              }

                              match child_process.configure(cspace_root, fault_ep_cap, ipc_vaddr as seL4_Word, ipc_frame_cap) {
                                  Ok(_) => {
                                      println!("[INFO] Child TCB Configured.");
                                      let authority = seL4_RootCNodeCapSlots_seL4_CapInitThreadTCB as seL4_CPtr;
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
                                           let cnode = seL4_RootCNodeCapSlots_seL4_CapInitThreadCNode as seL4_CPtr;
                                           match child_process.terminate(cnode) {
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

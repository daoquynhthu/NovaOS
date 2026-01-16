use sel4_sys::*;
use crate::memory::{ObjectAllocator, SlotAllocator};
use crate::vspace::VSpace;
use crate::println;
use crate::utils::{seL4_CapRights_new, seL4_X86_4K};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Created,
    Loaded,
    Configured,
    Running,
    Suspended,
    Terminated,
}

#[derive(Debug, Clone, Copy)]
pub struct Process {
    pub tcb_cap: seL4_CPtr,
    pub vspace: VSpace,
    pub fault_ep_cap: seL4_CPtr,
    pub syscall_ep_cap: seL4_CPtr,
    pub ipc_buffer_cap: seL4_CPtr,
    pub code_frame_cap: seL4_CPtr,
    pub state: ProcessState,
    pub heap_brk: usize,
    pub heap_frames: [seL4_CPtr; MAX_HEAP_PAGES],
    pub heap_frame_count: usize,
}

pub const MAX_PROCESSES: usize = 32;
pub const MAX_HEAP_PAGES: usize = 128;
const HEAP_START: usize = 0x4000_0000;

static mut PROCESS_MANAGER: ProcessManager = ProcessManager::new();

pub fn get_process_manager() -> &'static mut ProcessManager {
    #[allow(static_mut_refs)]
    unsafe { &mut PROCESS_MANAGER }
}

pub struct ProcessManager {
    pub processes: [Option<Process>; MAX_PROCESSES],
}

impl ProcessManager {
    pub const fn new() -> Self {
        ProcessManager {
            processes: [None; MAX_PROCESSES],
        }
    }

    pub fn allocate_pid(&self) -> Result<usize, seL4_Error> {
        for (pid, slot) in self.processes.iter().enumerate() {
            if slot.is_none() {
                return Ok(pid);
            }
        }
        Err(seL4_Error::seL4_NotEnoughMemory)
    }

    pub fn add_process(&mut self, process: Process) -> Result<usize, seL4_Error> {
        let pid = self.allocate_pid()?;
        self.processes[pid] = Some(process);
        Ok(pid)
    }

    pub fn get_process(&self, pid: usize) -> Option<&Process> {
        if pid < MAX_PROCESSES {
            self.processes[pid].as_ref()
        } else {
            None
        }
    }

    pub fn get_process_mut(&mut self, pid: usize) -> Option<&mut Process> {
        if pid < MAX_PROCESSES {
            self.processes[pid].as_mut()
        } else {
            None
        }
    }
    
    pub fn remove_process(&mut self, pid: usize) -> Option<Process> {
        if pid < MAX_PROCESSES {
            self.processes[pid].take()
        } else {
            None
        }
    }
}

use crate::utils::check_syscall_result;

impl Process {
    pub fn create<A: ObjectAllocator>(
        allocator: &mut A,
        slots: &mut SlotAllocator,
        boot_info: &seL4_BootInfo,
        asid_pool: seL4_CPtr,
    ) -> Result<Self, seL4_Error> {
        // 1. Create VSpace
        let vspace = VSpace::new_from_scratch(allocator, slots, boot_info, asid_pool)?;
        
        // 2. Create TCB
        let tcb_cap = allocator.allocate(boot_info, api_object_seL4_TCBObject.into(), seL4_TCBBits.into(), slots)?;
        
        println!("[Process] Created Process: TCB={}, PML4={}", tcb_cap, vspace.pml4_cap);
        
        Ok(Process {
            tcb_cap,
            vspace,
            fault_ep_cap: 0,
            syscall_ep_cap: 0,
            ipc_buffer_cap: 0,
            code_frame_cap: 0,
            state: ProcessState::Created,
            heap_brk: HEAP_START,
            heap_frames: [0; MAX_HEAP_PAGES],
            heap_frame_count: 0,
        })
    }

    pub fn new(tcb_cap: seL4_CPtr, vspace: VSpace) -> Self {
        Process { 
            tcb_cap, 
            vspace, 
            fault_ep_cap: 0, 
            syscall_ep_cap: 0,
            ipc_buffer_cap: 0, 
            code_frame_cap: 0,
            state: ProcessState::Created, 
            heap_brk: HEAP_START,
            heap_frames: [0; MAX_HEAP_PAGES],
            heap_frame_count: 0,
        }
    }

    pub fn configure(
        &mut self,
        cspace_root: seL4_CPtr,
        fault_ep: seL4_CPtr,
        ipc_buffer_addr: seL4_Word,
        ipc_buffer_cap: seL4_CPtr,
    ) -> Result<(), seL4_Error> {
        // Update tracked caps
        self.fault_ep_cap = fault_ep;
        self.ipc_buffer_cap = ipc_buffer_cap;

        unsafe {
            let info = seL4_MessageInfo_new(
                invocation_label_TCBConfigure as seL4_Word,
                0, // 0 unwraped caps
                3, // 3 extra caps: CSpace, VSpace, Buffer
                4, // 4 arguments: FaultEP (MR0), CSpaceData (MR1), VSpaceData (MR2), BufferAddr (MR3)
            );

            // MR0: Fault Endpoint
            seL4_SetMR(0, fault_ep);
            // MR1: CSpace Root Data (Guard) - 0
            seL4_SetMR(1, 0);
            // MR2: VSpace Root Data - 0
            seL4_SetMR(2, 0);
            // MR3: IPC Buffer Address
            seL4_SetMR(3, ipc_buffer_addr);

            // Formal verification: Check caps are valid
            debug_assert!(cspace_root != 0, "CSpace Root cannot be 0");
            debug_assert!(self.vspace.pml4_cap != 0, "VSpace Root cannot be 0");

            // Extra Caps
            // Cap 0: CSpace Root
            seL4_SetCap_My(0, cspace_root);
            // Cap 1: VSpace Root
            seL4_SetCap_My(1, self.vspace.pml4_cap);
            // Cap 2: IPC Buffer Frame
            seL4_SetCap_My(2, ipc_buffer_cap);

            let resp = seL4_Call(self.tcb_cap, info);
            check_syscall_result(resp)?;
            
            self.state = ProcessState::Configured;
            // Invariant: Active TCB must have valid VSpace Root
            debug_assert!(self.vspace.pml4_cap != 0, "Invariant: VSpace Root Valid");
            
            Ok(())
        }
    }

    pub fn load_image<A: ObjectAllocator>(
        &mut self,
        allocator: &mut A,
        slots: &mut SlotAllocator,
        boot_info: &seL4_BootInfo,
        image_data: &[u8],
    ) -> Result<usize, seL4_Error> {
        let loader = crate::elf_loader::ElfLoader::new(boot_info);
        let entry = loader.load_elf(allocator, slots, &mut self.vspace, image_data)?;
        self.state = ProcessState::Loaded;
        Ok(entry)
    }

    pub fn spawn<A: ObjectAllocator>(
        allocator: &mut A,
        slots: &mut SlotAllocator,
        boot_info: &seL4_BootInfo,
        image_data: &[u8],
        priority: seL4_Word,
        endpoint_cap: seL4_CPtr, // New argument: Endpoint Capability
    ) -> Result<Self, seL4_Error> {
        let asid_pool = seL4_RootCNodeCapSlots_seL4_CapInitThreadASIDPool as seL4_CPtr;
        let cspace_root = seL4_RootCNodeCapSlots_seL4_CapInitThreadCNode as seL4_CPtr;
        let authority = seL4_RootCNodeCapSlots_seL4_CapInitThreadTCB as seL4_CPtr;

        let mut process = Self::create(allocator, slots, boot_info, asid_pool)?;

        let entry = process.load_image(allocator, slots, boot_info, image_data)?;

        let rights_rw = seL4_CapRights_new(0, 0, 1, 1);
        let default_attr = seL4_X86_VMAttributes_seL4_X86_Default_VMAttributes;

        let stack_vaddr: usize = 0x2000_0000;
        let stack_top: usize = stack_vaddr + 4096;
        let stack_frame_cap = allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slots)?;
        process.vspace.map_page(
            allocator,
            slots,
            boot_info,
            stack_frame_cap,
            stack_vaddr,
            rights_rw,
            default_attr,
        )?;

        let ipc_vaddr: usize = 0x3000_0000;
        let ipc_frame_cap = allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slots)?;
        process.vspace.map_page(
            allocator,
            slots,
            boot_info,
            ipc_frame_cap,
            ipc_vaddr,
            rights_rw,
            default_attr,
        )?;

        let fault_ep_cap = allocator.allocate(
            boot_info,
            api_object_seL4_EndpointObject.into(),
            seL4_EndpointBits.into(),
            slots,
        )?;

        // Use the passed endpoint capability for syscalls
        process.syscall_ep_cap = endpoint_cap;

        process.configure(cspace_root, fault_ep_cap, ipc_vaddr as seL4_Word, ipc_frame_cap)?;
        process.set_priority(authority, priority)?;
        process.write_registers(entry as seL4_Word, stack_top as seL4_Word, 0x202, endpoint_cap as seL4_Word)?;
        process.resume()?;

        println!("[Process] Spawned process successfully!");

        Ok(process)
    }

    pub fn set_priority(&self, authority: seL4_CPtr, priority: seL4_Word) -> Result<(), seL4_Error> {
        unsafe {
            let info = seL4_MessageInfo_new(
                invocation_label_TCBSetPriority as seL4_Word,
                0,
                1, // Authority cap
                1, // Priority (MR0)
            );

            seL4_SetMR(0, priority);
            seL4_SetCap_My(0, authority);

            let resp = seL4_Call(self.tcb_cap, info);
            check_syscall_result(resp)?;
            Ok(())
        }
    }

    pub fn write_registers(
        &self,
        rip: seL4_Word,
        rsp: seL4_Word,
        rflags: seL4_Word,
        rdi: seL4_Word, // Argument 1
    ) -> Result<(), seL4_Error> {
        unsafe {
            // Context structure (x86_64)
            // seL4_UserContext:
            // rip, rsp, rflags, rax, rbx, rcx, rdx, rsi, rdi, rbp, r8-r15, fs_base, gs_base
            // Note: The order depends on seL4_UserContext definition.
            // On x64, typically:
            // 0: rip, 1: rsp, 2: rflags, 3: rax, 4: rbx, 5: rcx, 6: rdx, 7: rsi, 8: rdi, 9: rbp, ...
            
            let mut regs = [0u64; 20];
            regs[0] = rip;
            regs[1] = rsp;
            regs[2] = rflags;
            regs[8] = rdi; // Set RDI (First argument in System V AMD64 ABI)
            // Rest are 0

            let num_regs = 20;

            let info = seL4_MessageInfo_new(
                invocation_label_TCBWriteRegisters as seL4_Word,
                0,
                0,
                (num_regs + 2) as seL4_Word, // flags, num_regs, regs...
            );

            seL4_SetMR(0, 0); // flags (0=Restart, 1=Resume?) No, 0 usually.
            seL4_SetMR(1, num_regs as seL4_Word);

            for (i, &reg) in regs.iter().enumerate().take(num_regs) {
                seL4_SetMR(i + 2, reg);
            }

            let resp = seL4_Call(self.tcb_cap, info);
            check_syscall_result(resp)?;
            Ok(())
        }
    }

    pub fn resume(&mut self) -> Result<(), seL4_Error> {
        // Pre-condition: Must be Configured or Suspended
        debug_assert!(
            self.state == ProcessState::Configured || self.state == ProcessState::Suspended,
            "Process must be Configured or Suspended to Resume"
        );

        unsafe {
            let info = seL4_MessageInfo_new(
                invocation_label_TCBResume as seL4_Word,
                0, 0, 0
            );
            let resp = seL4_Call(self.tcb_cap, info);
            check_syscall_result(resp)?;
            
            self.state = ProcessState::Running;
            Ok(())
        }
    }

    pub fn suspend(&mut self) -> Result<(), seL4_Error> {
        unsafe {
            let info = seL4_MessageInfo_new(
                invocation_label_TCBSuspend as seL4_Word,
                0, 0, 0
            );
            let resp = seL4_Call(self.tcb_cap, info);
            check_syscall_result(resp)?;
            
            self.state = ProcessState::Suspended;
            Ok(())
        }
    }

    pub fn brk<A: ObjectAllocator>(
        &mut self,
        allocator: &mut A,
        slots: &mut SlotAllocator,
        boot_info: &seL4_BootInfo,
        new_brk: usize,
    ) -> Result<usize, seL4_Error> {
        // If addr is 0, return current break
        if new_brk == 0 {
            return Ok(self.heap_brk);
        }

        // Align new_brk to page boundary (round up)
        let aligned_new_brk = (new_brk + 4095) & !4095;
        
        if aligned_new_brk <= self.heap_brk {
             // Shrinking not supported yet, return current
             return Ok(self.heap_brk);
        }
        
        // Calculate needed pages
        let current_brk = self.heap_brk;
        let required_size = aligned_new_brk - current_brk;
        let required_pages = required_size / 4096;
        
        if self.heap_frame_count + required_pages > MAX_HEAP_PAGES {
            println!("[Process] Heap limit exceeded. Max pages: {}, Used: {}, Requested: {}", 
                MAX_HEAP_PAGES, self.heap_frame_count, required_pages);
            return Err(seL4_Error::seL4_NotEnoughMemory);
        }
        
        // Allocate and map pages
        let mut vaddr = current_brk;
        while vaddr < aligned_new_brk {
             let frame_cap = allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slots)?;
             
             let rights_rw = seL4_CapRights_new(0, 0, 1, 1);
             let default_attr = seL4_X86_VMAttributes_seL4_X86_Default_VMAttributes;
             
             match self.vspace.map_page(allocator, slots, boot_info, frame_cap, vaddr, rights_rw, default_attr) {
                Ok(_) => {},
                Err(e) => {
                    // TODO: Rollback on failure?
                    println!("[Process] Failed to map heap page at {:x}: {:?}", vaddr, e);
                    return Err(e);
                }
             }
             
             self.heap_frames[self.heap_frame_count] = frame_cap;
             self.heap_frame_count += 1;
             vaddr += 4096;
        }
        
        self.heap_brk = aligned_new_brk;
        println!("[Process] Heap expanded to {:x} ({} pages)", self.heap_brk, self.heap_frame_count);
        Ok(self.heap_brk)
    }

    pub fn terminate(&mut self, cnode: seL4_CPtr) -> Result<(), seL4_Error> {
        // Invariant: Cannot terminate an already terminated process
        debug_assert!(self.state != ProcessState::Terminated, "Double termination detected");

        unsafe {
            // Suspend first
            let _ = self.suspend();

            // Delete TCB
            let mut err = crate::utils::seL4_CNode_Delete(cnode, self.tcb_cap, 64);
            if err != 0.into() {
                 return Err(err);
            }
            
            // Delete VSpace (PML4)
            err = crate::utils::seL4_CNode_Delete(cnode, self.vspace.pml4_cap, 64);
            if err != 0.into() {
                 return Err(err);
            }

            // Delete Paging Structures (Resource Leak Fix)
            for i in 0..self.vspace.paging_cap_count {
                let cap = self.vspace.paging_caps[i];
                if cap != 0 {
                    let err = crate::utils::seL4_CNode_Delete(cnode, cap, 64);
                    if err != 0.into() {
                        println!("[WARN] Failed to delete Paging Structure Cap {}: {:?}", cap, err);
                    }
                }
            }

            // Delete Heap Frames
            for i in 0..self.heap_frame_count {
                let cap = self.heap_frames[i];
                if cap != 0 {
                    let err = crate::utils::seL4_CNode_Delete(cnode, cap, 64);
                    if err != 0.into() {
                        println!("[WARN] Failed to delete Heap Frame Cap {}: {:?}", cap, err);
                    }
                }
            }

            // Delete Fault Endpoint if present
            if self.fault_ep_cap != 0 {
                err = crate::utils::seL4_CNode_Delete(cnode, self.fault_ep_cap, 64);
                if err != 0.into() {
                     println!("[WARN] Failed to delete Fault EP: {:?}", err);
                }
            }

            // Delete Syscall Endpoint Cap (Badged) if present
            if self.syscall_ep_cap != 0 {
                err = crate::utils::seL4_CNode_Delete(cnode, self.syscall_ep_cap, 64);
                if err != 0.into() {
                     println!("[WARN] Failed to delete Syscall EP Cap: {:?}", err);
                }
            }

            // Delete IPC Buffer Frame if present
            if self.ipc_buffer_cap != 0 {
                err = crate::utils::seL4_CNode_Delete(cnode, self.ipc_buffer_cap, 64);
                if err != 0.into() {
                     println!("[WARN] Failed to delete IPC Buffer Cap: {:?}", err);
                }
            }

            // Delete Code Frame if present
            if self.code_frame_cap != 0 {
                err = crate::utils::seL4_CNode_Delete(cnode, self.code_frame_cap, 64);
                if err != 0.into() {
                     println!("[WARN] Failed to delete Code Frame Cap: {:?}", err);
                }
            }
            
            self.state = ProcessState::Terminated;
            
            println!("[Process] Terminated (Caps deleted: TCB={}, PML4={}, FaultEP={}, IPCBuf={}, CodeFrame={})", 
                self.tcb_cap, self.vspace.pml4_cap, self.fault_ep_cap, self.ipc_buffer_cap, self.code_frame_cap);
            Ok(())
        }
    }
}

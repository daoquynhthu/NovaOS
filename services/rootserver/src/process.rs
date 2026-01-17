use sel4_sys::{
    seL4_BootInfo, seL4_CPtr, seL4_Error, seL4_Word,
    seL4_MessageInfo_new, seL4_SetMR, seL4_Call, seL4_SetCap_My,
    seL4_PageBits,
    invocation_label_TCBSetPriority, invocation_label_TCBWriteRegisters,
    invocation_label_TCBResume, invocation_label_TCBSuspend,
    invocation_label_TCBConfigure, api_object_seL4_TCBObject, seL4_TCBBits,
    seL4_RootCNodeCapSlots, seL4_X86_VMAttributes,
};
use crate::memory::{ObjectAllocator, SlotAllocator};
use crate::vspace::VSpace;
use crate::println;
use crate::utils::{seL4_CapRights_new, seL4_X86_4K};

#[derive(Debug, Clone, Copy)]
pub struct IpcMessage {
    pub sender_pid: usize,
    pub content: [u64; 4],
    #[allow(dead_code)]
    pub len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Created,
    Loaded,
    Configured,
    Running,
    Sleeping,
    Suspended,
    Terminated,
    BlockedOnRecv,
    #[allow(dead_code)]
    BlockedOnInput,
}

pub const MAX_PROCESSES: usize = 32;
pub const MAX_MAPPED_FRAMES: usize = 256;
pub const MAX_FDS: usize = 16;
const HEAP_START: usize = 0x4000_0000;

#[derive(Debug, Clone)]
pub struct FileDescriptor {
    pub path: alloc::string::String,
    pub offset: usize,
    pub mode: FileMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileMode {
    ReadOnly = 0,
    WriteOnly = 1,
    ReadWrite = 2,
    Append = 3,
}

#[derive(Debug, Clone)]
pub struct Process {
    pub tcb_cap: seL4_CPtr,
    pub vspace: VSpace,
    pub fault_ep_cap: seL4_CPtr,
    pub syscall_ep_cap: seL4_CPtr,
    pub ipc_buffer_cap: seL4_CPtr,
    pub state: ProcessState,
    pub heap_brk: usize,
    pub mapped_frames: alloc::vec::Vec<seL4_CPtr>,
    pub mapped_frame_count: usize,
    pub wake_at_tick: u64,
    pub saved_reply_cap: seL4_CPtr,
    pub mailbox: Option<IpcMessage>,
    pub fds: alloc::vec::Vec<Option<FileDescriptor>>,
    pub priority: seL4_Word,
}

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
            processes: [const { None }; MAX_PROCESSES],
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
            state: ProcessState::Created,
            heap_brk: HEAP_START,
            mapped_frames: alloc::vec![0; MAX_MAPPED_FRAMES],
            mapped_frame_count: 0,
            wake_at_tick: 0,
            saved_reply_cap: 0,
            mailbox: None,
            fds: alloc::vec![const { None }; MAX_FDS],
            priority: 0,
        })
    }

    pub fn new(tcb_cap: seL4_CPtr, vspace: VSpace) -> Self {
        Process { 
            tcb_cap, 
            vspace, 
            fault_ep_cap: 0, 
            syscall_ep_cap: 0,
            ipc_buffer_cap: 0, 
            state: ProcessState::Created, 
            heap_brk: HEAP_START,
            mapped_frames: alloc::vec![0; MAX_MAPPED_FRAMES],
            mapped_frame_count: 0,
            wake_at_tick: 0,
            saved_reply_cap: 0,
            mailbox: None,
            fds: alloc::vec![const { None }; MAX_FDS],
            priority: 0,
        }
    }

    pub fn save_caller(&mut self, cnode: seL4_CPtr, slots: &mut SlotAllocator) -> Result<(), seL4_Error> {
        if self.saved_reply_cap == 0 {
            self.saved_reply_cap = slots.alloc().map_err(|_| seL4_Error::seL4_NotEnoughMemory)?;
        } else {
             // Try to delete just in case it's occupied (ignore error)
             unsafe {
                let _ = crate::utils::seL4_CNode_Delete(cnode, self.saved_reply_cap, 64);
             }
        }
        unsafe {
             let err = crate::utils::seL4_CNode_SaveCaller(cnode, self.saved_reply_cap, 64);
             if err == seL4_Error::seL4_NoError {
                 println!("[Process] SaveCaller success. Saved to cap {}", self.saved_reply_cap);
                 Ok(())
             } else {
                 println!("[Process] SaveCaller FAILED for cap {}: {:?}", self.saved_reply_cap, err);
                 Err(err)
             }
        }
    }

    pub fn track_frame(&mut self, cap: seL4_CPtr) -> Result<(), seL4_Error> {
        if self.mapped_frame_count >= MAX_MAPPED_FRAMES {
            return Err(seL4_Error::seL4_NotEnoughMemory);
        }
        self.mapped_frames[self.mapped_frame_count] = cap;
        self.mapped_frame_count += 1;
        Ok(())
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
        let entry = loader.load_elf(
            allocator, 
            slots, 
            &mut self.vspace, 
            image_data,
            &mut self.mapped_frames,
            &mut self.mapped_frame_count
        )?;
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
        let asid_pool = seL4_RootCNodeCapSlots::seL4_CapInitThreadASIDPool as seL4_CPtr;
        let cspace_root = seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
        let authority = seL4_RootCNodeCapSlots::seL4_CapInitThreadTCB as seL4_CPtr;

        let mut process = Self::create(allocator, slots, boot_info, asid_pool)?;

        // Wrap initialization in a closure to handle cleanup on failure
        let mut initialize = || -> Result<(), seL4_Error> {
            let entry = process.load_image(allocator, slots, boot_info, image_data)?;

            let rights_rw = seL4_CapRights_new(0, 0, 1, 1);
            let default_attr = seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes;

            let stack_vaddr: usize = 0x2000_0000;
            let stack_pages = 4; // 16KB stack
            let stack_top: usize = stack_vaddr + (stack_pages * 4096);
            
            for i in 0..stack_pages {
                let stack_frame_cap = allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slots)?;
                process.vspace.map_page(
                    allocator,
                    slots,
                    boot_info,
                    stack_frame_cap,
                    stack_vaddr + (i * 4096),
                    rights_rw,
                    default_attr,
                )?;
                process.track_frame(stack_frame_cap)?;
            }

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
            process.track_frame(ipc_frame_cap)?;

            // let fault_ep_cap = allocator.allocate(
            //     boot_info,
            //     api_object_seL4_EndpointObject.into(),
            //     seL4_EndpointBits.into(),
            //     slots,
            // )?;

            // Use the passed endpoint capability for syscalls and faults
            process.syscall_ep_cap = endpoint_cap;
            let fault_ep_cap = endpoint_cap;

            process.configure(cspace_root, fault_ep_cap, ipc_vaddr as seL4_Word, ipc_frame_cap)?;
            process.set_priority(authority, priority)?;
            process.write_registers(entry as seL4_Word, stack_top as seL4_Word, 0x202, endpoint_cap as seL4_Word)?;
            process.resume()?;
            
            Ok(())
        };

        if let Err(e) = initialize() {
            println!("[Process] Spawn failed, cleaning up...");
            let _ = process.terminate(cspace_root, slots);
            return Err(e);
        }

        println!("[Process] Spawned process successfully!");

        Ok(process)
    }

    pub fn set_priority(&mut self, authority: seL4_CPtr, priority: seL4_Word) -> Result<(), seL4_Error> {
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
            self.priority = priority;
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
            regs[0] = rip.try_into().unwrap();
            regs[1] = rsp.try_into().unwrap();
            regs[2] = rflags.try_into().unwrap();
            regs[3] = 0; // rbp
            regs[4] = 0; // rbx
            regs[5] = 0; // r12
            regs[6] = 0; // r13
            regs[7] = 0; // r14
            regs[8] = rdi.try_into().unwrap(); // Set RDI (First argument in System V AMD64 ABI)
            regs[9] = 0; // r15
            regs[10] = 0; // rax

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
                seL4_SetMR(i + 2, reg.try_into().unwrap());
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
        
        // Safety: Check for reasonable user space limit (2GB)
        if aligned_new_brk >= 0x8000_0000 {
            println!("[Process] Heap limit exceeded (2GB). Request: {:x}", aligned_new_brk);
            return Err(seL4_Error::seL4_NotEnoughMemory);
        }
        
        // Calculate needed pages
        let current_brk = self.heap_brk;
        let required_size = aligned_new_brk - current_brk;
        let required_pages = required_size / 4096;
        
        if self.mapped_frame_count + required_pages > MAX_MAPPED_FRAMES {
            println!("[Process] Heap limit exceeded. Max pages: {}, Used: {}, Requested: {}", 
                MAX_MAPPED_FRAMES, self.mapped_frame_count, required_pages);
            return Err(seL4_Error::seL4_NotEnoughMemory);
        }
        
        // Allocate and map pages
        let mut vaddr = current_brk;
        while vaddr < aligned_new_brk {
             let frame_cap = allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slots)?;
             
             let rights_rw = seL4_CapRights_new(0, 0, 1, 1);
             let default_attr = seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes;
             
             match self.vspace.map_page(allocator, slots, boot_info, frame_cap, vaddr, rights_rw, default_attr) {
                Ok(_) => {},
                Err(e) => {
                    // TODO: Rollback on failure?
                    println!("[Process] Failed to map heap page at {:x}: {:?}", vaddr, e);
                    return Err(e);
                }
             }
             
             self.track_frame(frame_cap)?;
             vaddr += 4096;
        }
        
        self.heap_brk = aligned_new_brk;
        println!("[Process] Heap expanded to {:x} ({} frames total)", self.heap_brk, self.mapped_frame_count);
        Ok(self.heap_brk)
    }

    pub fn terminate(&mut self, cnode: seL4_CPtr, slots: &mut SlotAllocator) -> Result<(), seL4_Error> {
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
            slots.free(self.tcb_cap);
            
            // Delete VSpace (PML4)
            err = crate::utils::seL4_CNode_Delete(cnode, self.vspace.pml4_cap, 64);
            if err != 0.into() {
                 return Err(err);
            }
            slots.free(self.vspace.pml4_cap);

            // Delete Paging Structures (Resource Leak Fix)
            for i in 0..self.vspace.paging_cap_count {
                let cap = self.vspace.paging_caps[i];
                if cap != 0 {
                    let err = crate::utils::seL4_CNode_Delete(cnode, cap, 64);
                    if err != 0.into() {
                        println!("[WARN] Failed to delete Paging Structure Cap {}: {:?}", cap, err);
                    }
                    slots.free(cap);
                }
            }

            // Delete Mapped Frames (Heap, Stack, IPC, Code)
            for i in 0..self.mapped_frame_count {
                let cap = self.mapped_frames[i];
                if cap != 0 {
                    let err = crate::utils::seL4_CNode_Delete(cnode, cap, 64);
                    if err != 0.into() {
                        println!("[WARN] Failed to delete Mapped Frame Cap {}: {:?}", cap, err);
                    }
                    slots.free(cap);
                }
            }

            // Delete Fault Endpoint if present
            if self.fault_ep_cap != 0 {
                err = crate::utils::seL4_CNode_Delete(cnode, self.fault_ep_cap, 64);
                if err != 0.into() {
                     println!("[WARN] Failed to delete Fault EP: {:?}", err);
                }
                slots.free(self.fault_ep_cap);
            }

            // Delete Syscall Endpoint Cap (Badged) if present
            // Note: If fault_ep and syscall_ep are the same (common in unified setup),
            // we must not free it twice.
            if self.syscall_ep_cap != 0 && self.syscall_ep_cap != self.fault_ep_cap {
                err = crate::utils::seL4_CNode_Delete(cnode, self.syscall_ep_cap, 64);
                if err != 0.into() {
                     println!("[WARN] Failed to delete Syscall EP Cap: {:?}", err);
                }
                slots.free(self.syscall_ep_cap);
            }

            self.state = ProcessState::Terminated;
            
            println!("[Process] Terminated (Caps deleted: TCB={}, PML4={}, FaultEP={}, IPCBuf={})", 
                self.tcb_cap, self.vspace.pml4_cap, self.fault_ep_cap, self.ipc_buffer_cap);
            Ok(())
        }
    }
}

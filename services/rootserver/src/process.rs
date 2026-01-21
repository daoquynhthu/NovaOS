#[allow(unused_imports)]
use sel4_sys::{
    seL4_BootInfo, seL4_CPtr, seL4_Word, seL4_CapRights,
    api_object_seL4_TCBObject, seL4_TCBBits,
    api_object_seL4_EndpointObject, seL4_EndpointBits,
    seL4_RootCNodeCapSlots, seL4_X86_VMAttributes,
    seL4_UserContext,
};
use crate::memory::{ObjectAllocator, SlotAllocator, FrameAllocator};
use crate::vspace::VSpace;
use libnova::cap::{CNode, cap_rights_new};
use libnova::syscall::{Result, Error};
use libnova::tcb::Tcb;

// Helper to write data to a frame by mapping it into RootServer temporarily
fn write_to_frame<A: ObjectAllocator>(
    allocator: &mut A,
    slots: &mut SlotAllocator,
    boot_info: &seL4_BootInfo,
    frame_cap: seL4_CPtr,
    offset: usize,
    data: &[u8]
) -> Result<()> {
    let root_pml4 = seL4_RootCNodeCapSlots::seL4_CapInitThreadVSpace as seL4_CPtr;
    // Create a VSpace wrapper for the current RootServer
    // Note: VSpace::new(pml4) creates a wrapper, doesn't allocate new PML4
    let mut root_vspace = VSpace::new(root_pml4);
    
    // Use a unique address to avoid conflicts (similar to elf_loader)
    // We can use the same COPY_WINDOW_ADDR base, offset by frame_cap
    let window = crate::elf_loader::COPY_WINDOW_ADDR + (frame_cap as usize * 4096);
    
    // FIX: Use a copy of the capability for mapping to RootServer
    let copy_cap = slots.alloc().map_err(|_| Error::NotEnoughMemory)?;
    let root_cnode_cap = seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
    let root_cnode = CNode::new(root_cnode_cap, 64);
    
    root_cnode.copy(copy_cap, &root_cnode, frame_cap, cap_rights_new(false, false, true, true))
        .map_err(|e| {
            slots.free(copy_cap);
            Error::from(e)
        })?;

    // Map the frame to the window address
    let map_res = root_vspace.map_page(
        allocator,
        slots,
        boot_info,
        copy_cap,
        window,
        cap_rights_new(false, false, true, true), // RW
        seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes,
    ).map_err(Error::from);

    if let Err(e) = map_res {
        root_cnode.delete(copy_cap).ok();
        slots.free(copy_cap);
        return Err(e);
    }
    
    // Copy data
    unsafe {
        let ptr = (window + offset) as *mut u8;
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
    }
    
    // Unmap to clean up
    let unmap_res = root_vspace.unmap_page(copy_cap).map_err(Error::from);
    let delete_res = root_cnode.delete(copy_cap).map_err(Error::from);
    slots.free(copy_cap);
    
    unmap_res?;
    delete_res?;
    
    Ok(())
}

// Temporary constant until we confirm sel4_sys export
#[allow(dead_code, non_upper_case_globals)]
const seL4_X86_4K: seL4_Word = 8;

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
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
    BlockedOnWait,
    #[allow(dead_code)]
    BlockedOnInput,
}

pub const MAX_PROCESSES: usize = 32;
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
    pub name: alloc::string::String,
    pub tcb_cap: seL4_CPtr,
    pub vspace: VSpace,
    pub fault_ep_cap: seL4_CPtr,
    pub syscall_ep_cap: seL4_CPtr,
    pub ipc_buffer_cap: seL4_CPtr,
    pub state: ProcessState,
    pub heap_brk: usize,
    pub mapped_frames: alloc::vec::Vec<seL4_CPtr>,
    pub wake_at_tick: u64,
    pub saved_reply_cap: seL4_CPtr,
    pub mailbox: Option<IpcMessage>,
    pub fds: alloc::vec::Vec<Option<FileDescriptor>>,
    pub priority: seL4_Word,
    pub uid: u32,
    pub gid: u32,
    pub ppid: usize,
    pub children: alloc::vec::Vec<usize>,
    pub waiting_for_child: Option<usize>, // PID of child we are waiting for, or None (any)
    pub exit_code: Option<isize>,
}

use spin::Mutex;

static PROCESS_MANAGER: Mutex<ProcessManager> = Mutex::new(ProcessManager::new());

pub fn get_process_manager() -> spin::MutexGuard<'static, ProcessManager> {
    PROCESS_MANAGER.lock()
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

    pub fn allocate_pid(&self) -> Result<usize> {
        for (pid, slot) in self.processes.iter().enumerate() {
            if slot.is_none() {
                return Ok(pid);
            }
        }
        Err(Error::NotEnoughMemory)
    }

    pub fn add_process(&mut self, process: Process) -> Result<usize> {
        let pid = self.allocate_pid()?;
        let ppid = process.ppid;
        
        // Update parent's children list
        if ppid != pid && ppid < MAX_PROCESSES {
             if let Some(parent) = self.get_process_mut(ppid) {
                 parent.children.push(pid);
             }
        }

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

    pub fn wait_for_child(&mut self, parent_pid: usize, child_pid: isize) -> Result<Option<(usize, isize)>> {
        let mut found_child = false;
        let mut found_zombie: Option<(usize, isize)> = None;

        for i in 0..MAX_PROCESSES {
            if let Some(p) = &self.processes[i] {
                if p.ppid == parent_pid {
                    if child_pid == -1 || (child_pid as usize) == i {
                        found_child = true;
                        if p.state == ProcessState::Terminated {
                            if let Some(code) = p.exit_code {
                                found_zombie = Some((i, code));
                                break;
                            }
                        }
                    }
                }
            }
        }

        if let Some((pid, code)) = found_zombie {
            self.remove_process(pid);
            if let Some(parent) = self.get_process_mut(parent_pid) {
                parent.children.retain(|&c| c != pid);
            }
            return Ok(Some((pid, code)));
        }

        if !found_child {
            return Err(Error::InvalidArgument);
        }

        if let Some(parent) = self.get_process_mut(parent_pid) {
            parent.state = ProcessState::BlockedOnWait;
            parent.waiting_for_child = if child_pid == -1 { None } else { Some(child_pid as usize) };
        }

        Ok(None)
    }

    pub fn exit_process(
        &mut self,
        pid: usize,
        exit_code: isize,
        cnode: seL4_CPtr,
        slots: &mut SlotAllocator,
        frame_allocator: &mut FrameAllocator
    ) -> Result<()> {
        let ppid = self.get_process(pid).ok_or(Error::InvalidArgument)?.ppid;
        
        if let Some(p) = self.get_process_mut(pid) {
            // Only terminate if not already terminated
            if p.state != ProcessState::Terminated {
                p.exit_code = Some(exit_code);
                let _ = p.terminate(cnode, slots, frame_allocator);
            }
        }

        let mut parent_waiting = false;
        let mut parent_exists = false;
        let mut parent_reply_cap = 0;
        
        if let Some(parent) = self.get_process(ppid) {
            parent_exists = true;
            if parent.state == ProcessState::BlockedOnWait {
                if parent.waiting_for_child.is_none() || parent.waiting_for_child == Some(pid) {
                    parent_waiting = true;
                    parent_reply_cap = parent.saved_reply_cap;
                }
            }
        }

        if parent_waiting {
            self.remove_process(pid);
            
            if let Some(parent) = self.get_process_mut(ppid) {
                parent.children.retain(|&c| c != pid);
                parent.state = ProcessState::Running;
                parent.waiting_for_child = None;
            }

            if parent_reply_cap != 0 {
                unsafe {
                    let info = sel4_sys::seL4_MessageInfo_new(0, 0, 0, 2);
                    sel4_sys::seL4_SetMR(0, pid as seL4_Word);
                    sel4_sys::seL4_SetMR(1, exit_code as seL4_Word);
                    sel4_sys::seL4_Send(parent_reply_cap, info);
                }
            }
        } else if !parent_exists {
            // Orphan process (parent died or non-existent) - reap immediately
            println!("[Process] Reaping orphan process {} (Parent {} not found)", pid, ppid);
            self.remove_process(pid);
        }
        
        Ok(())
    }
}


impl Process {
    #[allow(dead_code)]
    pub fn is_child_of(&self, potential_ppid: usize) -> bool {
        self.ppid == potential_ppid
    }

    pub fn can_control(&self, target: &Process) -> bool {
        // Root (UID 0) can control any process
        if self.uid == 0 {
            return true;
        }
        // Users can only control their own processes
        self.uid == target.uid
    }

    pub fn create<A: ObjectAllocator>(
        allocator: &mut A,
        slots: &mut SlotAllocator,
        boot_info: &seL4_BootInfo,
        asid_pool: seL4_CPtr,
        name: &str,
        uid: u32,
        gid: u32,
    ) -> Result<Self> {
        // 1. Create VSpace
        let vspace = VSpace::new_from_scratch(allocator, slots, boot_info, asid_pool).map_err(Error::from)?;
        
        // 2. Create TCB
        let tcb_cap = allocator.allocate(boot_info, api_object_seL4_TCBObject.into(), seL4_TCBBits.into(), slots).map_err(Error::from)?;
        
        println!("[Process] Created Process: TCB={}, PML4={}, UID={}, GID={}", tcb_cap, vspace.pml4_cap, uid, gid);
        
        Ok(Process {
            name: alloc::string::String::from(name),
            tcb_cap,
            vspace,
            fault_ep_cap: 0,
            syscall_ep_cap: 0,
            ipc_buffer_cap: 0,
            state: ProcessState::Created,
            heap_brk: HEAP_START,
            mapped_frames: alloc::vec::Vec::new(),
            wake_at_tick: 0,
            saved_reply_cap: 0,
            mailbox: None,
            fds: alloc::vec![const { None }; MAX_FDS],
            priority: 0,
            uid,
            gid,
            ppid: 0,
            children: alloc::vec::Vec::new(),
            waiting_for_child: None,
            exit_code: None,
        })
    }

    pub fn new(tcb_cap: seL4_CPtr, vspace: VSpace) -> Self {
        Process { 
            name: alloc::string::String::from("unknown"),
            tcb_cap, 
            vspace, 
            fault_ep_cap: 0, 
            syscall_ep_cap: 0,
            ipc_buffer_cap: 0, 
            state: ProcessState::Created, 
            heap_brk: HEAP_START,
            mapped_frames: alloc::vec::Vec::new(),
            wake_at_tick: 0,
            saved_reply_cap: 0,
            mailbox: None,
            fds: alloc::vec![const { None }; MAX_FDS],
            priority: 0,
            uid: 0,
            gid: 0,
            ppid: 0,
            children: alloc::vec::Vec::new(),
            waiting_for_child: None,
            exit_code: None,
        }
    }

    pub fn save_caller(&mut self, cnode: seL4_CPtr, slots: &mut SlotAllocator) -> Result<()> {
        let root = CNode::new(cnode, 64);
        if self.saved_reply_cap == 0 {
            self.saved_reply_cap = slots.alloc().map_err(|_| Error::NotEnoughMemory)?;
        } else {
             // Try to delete just in case it's occupied (ignore error)
             let _ = root.delete(self.saved_reply_cap);
        }
        
        match root.save_caller(self.saved_reply_cap) {
             Ok(_) => {
                 println!("[Process] SaveCaller success. Saved to cap {}", self.saved_reply_cap);
                 Ok(())
             },
             Err(e) => {
                 println!("[Process] SaveCaller FAILED for cap {}: {:?}", self.saved_reply_cap, e);
                 Err(e)
             }
        }
    }

    pub fn track_frame(&mut self, frame_cap: seL4_CPtr) -> Result<()> {
        self.mapped_frames.push(frame_cap);
        Ok(())
    }

    pub fn configure(
        &mut self,
        cspace_root: seL4_CPtr,
        fault_ep: seL4_CPtr,
        ipc_buffer_addr: seL4_Word,
        ipc_buffer_cap: seL4_CPtr,
    ) -> Result<()> {
        // Update tracked caps
        self.fault_ep_cap = fault_ep;
        self.ipc_buffer_cap = ipc_buffer_cap;

        // Formal verification: Check caps are valid
        debug_assert!(cspace_root != 0, "CSpace Root cannot be 0");
        debug_assert!(self.vspace.pml4_cap != 0, "VSpace Root cannot be 0");

        Tcb::new(self.tcb_cap).configure(
            cspace_root,
            self.vspace.pml4_cap,
            fault_ep,
            ipc_buffer_addr,
            ipc_buffer_cap,
        )?;
        
        self.state = ProcessState::Configured;
        // Invariant: Active TCB must have valid VSpace Root
        debug_assert!(self.vspace.pml4_cap != 0, "Invariant: VSpace Root Valid");
        
        Ok(())
    }

    pub fn load_image<A: ObjectAllocator>(
        &mut self,
        allocator: &mut A,
        slots: &mut SlotAllocator,
        frame_allocator: &mut FrameAllocator,
        boot_info: &seL4_BootInfo,
        image_data: &[u8],
    ) -> Result<usize> {
        let loader = crate::elf_loader::ElfLoader::new(boot_info);
        let entry = loader.load_elf(
            allocator, 
            slots, 
            frame_allocator,
            &mut self.vspace, 
            image_data,
            &mut self.mapped_frames,
        ).map_err(Error::from)?;
        self.state = ProcessState::Loaded;
        Ok(entry)
    }

    pub fn spawn<A: ObjectAllocator>(
        allocator: &mut A,
        slots: &mut SlotAllocator,
        frame_allocator: &mut FrameAllocator,
        boot_info: &seL4_BootInfo,
        name: &str,
        image_data: &[u8],
        args: &[&str],
        env: &[&str],
        priority: seL4_Word,
        endpoint_cap: seL4_CPtr,
        ppid: usize,
        uid: u32,
        gid: u32,
    ) -> Result<Self> {
        let asid_pool = seL4_RootCNodeCapSlots::seL4_CapInitThreadASIDPool as seL4_CPtr;
        let cspace_root = seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
        let authority = seL4_RootCNodeCapSlots::seL4_CapInitThreadTCB as seL4_CPtr;

        let mut process = Self::create(allocator, slots, boot_info, asid_pool, name, uid, gid)?;
        process.ppid = ppid;

        // Wrap initialization in a closure to handle cleanup on failure
        let mut initialize = || -> Result<()> {
            let entry = process.load_image(allocator, slots, frame_allocator, boot_info, image_data)?;

            let rights_rw = cap_rights_new(false, false, true, true);
            let default_attr = seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes;

            let stack_vaddr: usize = 0x2000_0000;
            let stack_pages = 4; // 16KB stack
            let stack_top: usize = stack_vaddr + (stack_pages * 4096);
            
            let mut top_stack_frame_cap = 0;

            for i in 0..stack_pages {
                let stack_frame_cap = frame_allocator.alloc(allocator, boot_info, slots).map_err(Error::from)?;
                process.vspace.map_page(
                    allocator,
                    slots,
                    boot_info,
                    stack_frame_cap,
                    stack_vaddr + (i * 4096),
                    rights_rw,
                    default_attr,
                ).map_err(Error::from)?;
                process.track_frame(stack_frame_cap)?;
                if i == stack_pages - 1 {
                    top_stack_frame_cap = stack_frame_cap;
                }
            }

            // Setup Stack with Args and Env
            let mut sp = stack_top;
            
            // 1. Strings (Args + Env)
            let mut arg_string_pointers = alloc::vec::Vec::new();
            let mut env_string_pointers = alloc::vec::Vec::new();
            let mut data_block = alloc::vec::Vec::new();
            
            // Push Args strings
            for arg in args {
                 let bytes = arg.as_bytes();
                 data_block.extend_from_slice(bytes);
                 data_block.push(0);
            }
            // Push Env strings
            for e in env {
                 let bytes = e.as_bytes();
                 data_block.extend_from_slice(bytes);
                 data_block.push(0);
            }
            
            let strings_start_vaddr = sp - data_block.len();
            sp = strings_start_vaddr;
            
            let mut current_vaddr = strings_start_vaddr;
            for arg in args {
                 arg_string_pointers.push(current_vaddr);
                 current_vaddr += arg.len() + 1;
            }
            for e in env {
                 env_string_pointers.push(current_vaddr);
                 current_vaddr += e.len() + 1;
            }
            
            // 2. Arrays
            // Envp: [ptr0, ..., NULL]
            let envp_size = (env.len() + 1) * 8;
            sp -= envp_size;
            sp = sp & !0xF;
            let envp_start_vaddr = sp;
            
            // Argv: [ptr0, ..., NULL]
            let argv_size = (args.len() + 1) * 8;
            sp -= argv_size;
            sp = sp & !0xF;
            let argv_start_vaddr = sp;
            
            // Construct Data
            let mut argv_data = alloc::vec::Vec::new();
            for ptr in arg_string_pointers {
                 argv_data.extend_from_slice(&(ptr as u64).to_le_bytes());
            }
            argv_data.extend_from_slice(&0u64.to_le_bytes());

            let mut envp_data = alloc::vec::Vec::new();
            for ptr in env_string_pointers {
                 envp_data.extend_from_slice(&(ptr as u64).to_le_bytes());
            }
            envp_data.extend_from_slice(&0u64.to_le_bytes());
            
            // Write to top stack page
            if stack_top - sp > 4096 {
                println!("[Process] Args+Env too large for single stack page!");
                return Err(Error::NotEnoughMemory);
            }

            // Write Strings
            let strings_offset = strings_start_vaddr % 4096;
            write_to_frame(allocator, slots, boot_info, top_stack_frame_cap, strings_offset, &data_block)?;
            
            // Write Envp
            let envp_offset = envp_start_vaddr % 4096;
            write_to_frame(allocator, slots, boot_info, top_stack_frame_cap, envp_offset, &envp_data)?;

            // Write Argv
            let argv_offset = argv_start_vaddr % 4096;
            write_to_frame(allocator, slots, boot_info, top_stack_frame_cap, argv_offset, &argv_data)?;

            let ipc_vaddr: usize = 0x3000_0000;
            let ipc_frame_cap = frame_allocator.alloc(allocator, boot_info, slots).map_err(Error::from)?;
            process.vspace.map_page(
                allocator,
                slots,
                boot_info,
                ipc_frame_cap,
                ipc_vaddr,
                rights_rw,
                default_attr,
            ).map_err(Error::from)?;
            process.track_frame(ipc_frame_cap)?;

            // Use the passed endpoint capability for syscalls and faults
            process.syscall_ep_cap = endpoint_cap;
            let fault_ep_cap = endpoint_cap;

            process.configure(cspace_root, fault_ep_cap, ipc_vaddr as seL4_Word, ipc_frame_cap)?;
            process.set_priority(authority, priority)?;
            
            // RDI = argc, RSI = argv, RDX = endpoint_cap, RCX = envp
            println!("[Process] Setting registers: Entry={:x}, SP={:x}, Argc={}, Argv={:x}, EP={}, Envp={:x}", 
                entry, sp, args.len(), argv_start_vaddr, endpoint_cap, envp_start_vaddr);

            process.write_registers_ext(
                entry as seL4_Word, 
                sp as seL4_Word, 
                0x202, 
                args.len() as seL4_Word, 
                argv_start_vaddr as seL4_Word, 
                endpoint_cap as seL4_Word,
                envp_start_vaddr as seL4_Word
            )?;
            process.resume()?;
            
            Ok(())
        };

        if let Err(e) = initialize() {
            println!("[Process] Spawn failed, cleaning up...");
            let _ = process.terminate(cspace_root, slots, frame_allocator);
            return Err(e);
        }

        println!("[Process] Spawned process successfully!");

        Ok(process)
    }

    pub fn set_priority(&mut self, authority: seL4_CPtr, priority: seL4_Word) -> Result<()> {
        Tcb::new(self.tcb_cap).set_priority(authority, priority)?;
        self.priority = priority;
        Ok(())
    }

    pub fn write_registers(
        &self,
        rip: seL4_Word,
        rsp: seL4_Word,
        rflags: seL4_Word,
        rdi: seL4_Word, // Argument 1
    ) -> Result<()> {
        Tcb::new(self.tcb_cap).write_registers(rip, rsp, rflags, rdi)
    }

    pub fn write_registers_ext(
        &self,
        rip: seL4_Word,
        rsp: seL4_Word,
        rflags: seL4_Word,
        rdi: seL4_Word,
        rsi: seL4_Word,
        rdx: seL4_Word,
        rcx: seL4_Word,
    ) -> Result<()> {
        unsafe {
            // Standard x86_64 seL4 register order
            let mut regs = [0u64; 20];
            regs[0] = rip;
            regs[1] = rsp;
            regs[2] = rflags;
            regs[5] = rcx;
            regs[6] = rdx;
            regs[7] = rsi;
            regs[8] = rdi;

            let num_regs = 20;

            let info = sel4_sys::seL4_MessageInfo_new(
                sel4_sys::invocation_label_TCBWriteRegisters as seL4_Word,
                0,
                0,
                (num_regs + 2) as seL4_Word,
            );

            sel4_sys::seL4_SetMR(0, 0); // flags: 0=Restart
            sel4_sys::seL4_SetMR(1, num_regs as seL4_Word);

            for (i, &reg) in regs.iter().enumerate() {
                sel4_sys::seL4_SetMR(i + 2, reg);
            }

            let resp = sel4_sys::seL4_Call(self.tcb_cap, info);
            if sel4_sys::seL4_MessageInfo_get_label(resp) != 0 {
                 return Err(Error::Unknown(0));
            }
        }
        Ok(())
    }

    pub fn resume(&mut self) -> Result<()> {
        // Pre-condition: Must be Configured or Suspended
        debug_assert!(
            self.state == ProcessState::Configured || self.state == ProcessState::Suspended,
            "Process must be Configured or Suspended to Resume"
        );

        Tcb::new(self.tcb_cap).resume()?;
        
        self.state = ProcessState::Running;
        Ok(())
    }

    pub fn suspend(&mut self) -> Result<()> {
        Tcb::new(self.tcb_cap).suspend()?;
        
        self.state = ProcessState::Suspended;
        Ok(())
    }

    pub fn brk<A: ObjectAllocator>(
        &mut self,
        allocator: &mut A,
        slots: &mut SlotAllocator,
        frame_allocator: &mut FrameAllocator,
        boot_info: &seL4_BootInfo,
        new_brk: usize,
    ) -> Result<usize> {
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
            return Err(Error::NotEnoughMemory);
        }
        
        // Calculate needed pages
        let current_brk = self.heap_brk;
        
        // Allocate and map pages with rollback support
        let mut vaddr = current_brk;
        let mut allocated_caps = alloc::vec::Vec::new();
        
        while vaddr < aligned_new_brk {
             // 1. Allocate Frame
             let frame_cap = match frame_allocator.alloc(allocator, boot_info, slots) {
                 Ok(cap) => cap,
                 Err(e) => {
                     println!("[Process] Heap expansion failed (Alloc): {:?}", e);
                     // Rollback previous allocations
                     for (cap, _va) in allocated_caps {
                         let _ = self.vspace.unmap_page(cap);
                         frame_allocator.free(cap);
                     }
                     return Err(Error::from(e));
                 }
             };
             
             let rights_rw = cap_rights_new(false, false, true, true);
             let default_attr = seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes;
             
             // 2. Map Frame
             match self.vspace.map_page(allocator, slots, boot_info, frame_cap, vaddr, rights_rw, default_attr) {
                Ok(_) => {
                    allocated_caps.push((frame_cap, vaddr));
                },
                Err(e) => {
                    println!("[Process] Heap expansion failed (Map) at {:x}: {:?}", vaddr, e);
                    // Rollback this frame
                    frame_allocator.free(frame_cap);
                    
                    // Rollback previous frames
                    for (cap, _va) in allocated_caps {
                        // Best effort unmap
                        let _ = self.vspace.unmap_page(cap); 
                        frame_allocator.free(cap);
                        // Note: We don't remove from mapped_frames because we haven't added them yet.
                    }
                    return Err(Error::from(e));
                }
             }
             
             vaddr += 4096;
        }
        
        // Commit: Add all successfully mapped frames to tracking
        for (cap, _) in allocated_caps {
            self.track_frame(cap)?;
        }
        
        self.heap_brk = aligned_new_brk;
        println!("[Process] Heap expanded to {:x} ({} frames total)", self.heap_brk, self.mapped_frames.len());
        Ok(self.heap_brk)
    }

    pub fn terminate(
        &mut self, 
        cnode: seL4_CPtr, 
        slots: &mut SlotAllocator, 
        frame_allocator: &mut FrameAllocator
    ) -> Result<()> {
        // Invariant: Cannot terminate an already terminated process
        debug_assert!(self.state != ProcessState::Terminated, "Double termination detected");

        let root = CNode::new(cnode, 64);

        // Suspend first
        let _ = self.suspend();

        // Delete TCB
        root.delete(self.tcb_cap)?;
        slots.free(self.tcb_cap);
        
        // Delete VSpace (PML4)
        root.delete(self.vspace.pml4_cap)?;
        slots.free(self.vspace.pml4_cap);

        // Delete Paging Structures (Resource Leak Fix)
        for i in 0..self.vspace.paging_cap_count {
            if let Some(paging_cap) = self.vspace.paging_caps[i] {
                let cap = paging_cap.cap;
                if let Err(e) = root.delete(cap) {
                    println!("[WARN] Failed to delete Paging Structure Cap {}: {:?}", cap, e);
                }
                slots.free(cap);
            }
        }

        // Recycle Frames (Resource Leak Fix)
        while let Some(cap) = self.mapped_frames.pop() {
            frame_allocator.free(cap);
        }

        // Delete Fault EP
        if self.fault_ep_cap != 0 {
            root.delete(self.fault_ep_cap)?;
            slots.free(self.fault_ep_cap);
        }

        // Delete Syscall EP
        if self.syscall_ep_cap != 0 && self.syscall_ep_cap != self.fault_ep_cap {
            root.delete(self.syscall_ep_cap)?;
            slots.free(self.syscall_ep_cap);
        }

        // Delete IPC Buffer Frame (if separate)
        if self.ipc_buffer_cap != 0 {
             // Check if it was already recycled in mapped_frames?
             // Usually IPC buffer is allocated separately or part of mapped_frames.
             // If it's not in mapped_frames, we should free it.
             // But for now, we assume it's tracked or we let it leak (small leak).
             // To be safe, we don't double-free.
        }

        self.state = ProcessState::Terminated;

        println!("[Process] Terminated (Caps deleted: TCB={}, PML4={}, FaultEP={}, IPCBuf={})", 
            self.tcb_cap, self.vspace.pml4_cap, self.fault_ep_cap, self.ipc_buffer_cap);
        Ok(())
    }
}

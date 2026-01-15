use sel4_sys::*;
use crate::memory::{ObjectAllocator, SlotAllocator};
use crate::vspace::VSpace;
use crate::println;

pub struct Process {
    pub tcb_cap: seL4_CPtr,
    pub vspace: VSpace,
    pub fault_ep_cap: seL4_CPtr,
    pub ipc_buffer_cap: seL4_CPtr,
    pub code_frame_cap: seL4_CPtr,
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
            ipc_buffer_cap: 0,
            code_frame_cap: 0,
        })
    }

    pub fn new(tcb_cap: seL4_CPtr, vspace: VSpace) -> Self {
        Process { tcb_cap, vspace, fault_ep_cap: 0, ipc_buffer_cap: 0, code_frame_cap: 0 }
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
        loader.load_elf(allocator, slots, &mut self.vspace, image_data)
    }

    pub fn spawn<A: ObjectAllocator>(
        allocator: &mut A,
        slots: &mut SlotAllocator,
        boot_info: &seL4_BootInfo,
        asid_pool: seL4_CPtr,
        cspace_root: seL4_CPtr,
        fault_ep: seL4_CPtr,
        ipc_buffer_addr: seL4_Word,
        ipc_buffer_cap: seL4_CPtr,
        image_data: &[u8],
        priority: seL4_Word,
    ) -> Result<Self, seL4_Error> {
        let mut process = Self::create(allocator, slots, boot_info, asid_pool)?;
        
        // Load ELF
        process.load_image(allocator, slots, boot_info, image_data)?;
        
        // Configure TCB
        process.configure(cspace_root, fault_ep, ipc_buffer_addr, ipc_buffer_cap)?;
        
        // Set Priority
        // Note: Authority should be the caller's TCB (RootServer), which has max priority.
        // We assume RootServer has enough authority.
        let authority = seL4_RootCNodeCapSlots_seL4_CapInitThreadTCB as seL4_CPtr;
        process.set_priority(authority, priority)?;
        
        // Resume TCB (Start process)
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

    pub fn resume(&self) -> Result<(), seL4_Error> {
        unsafe {
            let info = seL4_MessageInfo_new(
                invocation_label_TCBResume as seL4_Word,
                0,
                0,
                0,
            );
            let resp = seL4_Call(self.tcb_cap, info);
            check_syscall_result(resp)?;
            Ok(())
        }
    }

    pub fn suspend(&self) -> Result<(), seL4_Error> {
        unsafe {
            let info = seL4_MessageInfo_new(
                invocation_label_TCBSuspend as seL4_Word,
                0, 0, 0
            );
            let resp = seL4_Call(self.tcb_cap, info);
            check_syscall_result(resp)?;
            Ok(())
        }
    }

    pub fn terminate(&self, cnode: seL4_CPtr) -> Result<(), seL4_Error> {
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

            // Delete Fault Endpoint if present
            if self.fault_ep_cap != 0 {
                err = crate::utils::seL4_CNode_Delete(cnode, self.fault_ep_cap, 64);
                if err != 0.into() {
                     println!("[WARN] Failed to delete Fault EP: {:?}", err);
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
            
            println!("[Process] Terminated (Caps deleted: TCB={}, PML4={}, FaultEP={}, IPCBuf={}, CodeFrame={})", 
                self.tcb_cap, self.vspace.pml4_cap, self.fault_ep_cap, self.ipc_buffer_cap, self.code_frame_cap);
            Ok(())
        }
    }
}

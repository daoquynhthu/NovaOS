use sel4_sys::*;
use crate::syscall::{check_msg_err, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tcb {
    pub cptr: seL4_CPtr,
}

impl Tcb {
    pub fn new(cptr: seL4_CPtr) -> Self {
        Tcb { cptr }
    }

    pub fn configure(
        &self,
        cspace_root: seL4_CPtr,
        vspace_root: seL4_CPtr,
        fault_ep: seL4_CPtr,
        ipc_buffer_addr: seL4_Word,
        ipc_buffer_cap: seL4_CPtr,
    ) -> Result<()> {
        unsafe {
            let info = seL4_MessageInfo_new(
                invocation_label_TCBConfigure as seL4_Word,
                0, // 0 unwrapped caps
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

            // Extra Caps
            // Cap 0: CSpace Root
            seL4_SetCap_My(0, cspace_root);
            // Cap 1: VSpace Root
            seL4_SetCap_My(1, vspace_root);
            // Cap 2: IPC Buffer Frame
            seL4_SetCap_My(2, ipc_buffer_cap);

            let resp = seL4_Call(self.cptr, info);
            check_msg_err(resp)
        }
    }

    pub fn set_priority(&self, authority: seL4_CPtr, priority: seL4_Word) -> Result<()> {
        unsafe {
            let info = seL4_MessageInfo_new(
                invocation_label_TCBSetPriority as seL4_Word,
                0,
                1, // Authority cap
                1, // Priority (MR0)
            );

            seL4_SetMR(0, priority);
            seL4_SetCap_My(0, authority);

            let resp = seL4_Call(self.cptr, info);
            check_msg_err(resp)
        }
    }

    pub fn resume(&self) -> Result<()> {
        unsafe {
            let info = seL4_MessageInfo_new(
                invocation_label_TCBResume as seL4_Word,
                0, 0, 0
            );
            let resp = seL4_Call(self.cptr, info);
            check_msg_err(resp)
        }
    }

    pub fn suspend(&self) -> Result<()> {
        unsafe {
            let info = seL4_MessageInfo_new(
                invocation_label_TCBSuspend as seL4_Word,
                0, 0, 0
            );
            let resp = seL4_Call(self.cptr, info);
            check_msg_err(resp)
        }
    }

    pub fn write_registers(
        &self,
        rip: seL4_Word,
        rsp: seL4_Word,
        rflags: seL4_Word,
        rdi: seL4_Word,
    ) -> Result<()> {
        unsafe {
            // Context structure (x86_64)
            // 0: rip, 1: rsp, 2: rflags, ..., 8: rdi
            
            let mut regs = [0u64; 20];
            regs[0] = rip.try_into().unwrap();
            regs[1] = rsp.try_into().unwrap();
            regs[2] = rflags.try_into().unwrap();
            regs[8] = rdi.try_into().unwrap(); 

            let num_regs = 20;

            let info = seL4_MessageInfo_new(
                invocation_label_TCBWriteRegisters as seL4_Word,
                0,
                0,
                (num_regs + 2) as seL4_Word, // flags, num_regs, regs...
            );

            seL4_SetMR(0, 0); // flags (0=Restart)
            seL4_SetMR(1, num_regs as seL4_Word);

            for (i, &reg) in regs.iter().enumerate().take(num_regs) {
                seL4_SetMR(i + 2, reg.try_into().unwrap());
            }

            let resp = seL4_Call(self.cptr, info);
            check_msg_err(resp)
        }
    }
}

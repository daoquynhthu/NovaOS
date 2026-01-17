#![allow(dead_code)]
use sel4_sys::seL4_BootInfo;
use crate::memory::{UntypedAllocator, SlotAllocator};
use crate::arch::acpi::AcpiContext;

// Invocation label for X86IRQIssueIRQHandlerIOAPIC
// Based on typical seL4 x86 generation:
// 1: IRQIssueIRQHandler (Generic)
// 2: X86IRQIssueIRQHandlerIOAPIC
// 3: X86IRQIssueIRQHandlerMSI
// Note: Calculated based on X86_IO_PORT_OUT8 = 49 (in port_io.rs) + 3 = 52
pub const X86_IRQ_ISSUE_IRQ_HANDLER_IOAPIC: usize = 52;
pub const IRQ_ACK_IRQ: usize = 27;
pub const IRQ_SET_IRQ_HANDLER: usize = 28;

pub fn ack_irq(irq_handler: usize) -> Result<(), usize> {
    let info = libnova::ipc::MessageInfo::new((IRQ_ACK_IRQ as u64).try_into().unwrap(), 0, 0, 0);
    let resp = libnova::ipc::call(irq_handler.try_into().unwrap(), info);
    let label = resp.label();
    if label == 0 { Ok(()) } else { Err(label as usize) }
}

pub fn set_irq_handler(irq_handler: usize, notification: usize) -> Result<(), usize> {
    libnova::ipc::set_cap(0, (notification as u64).try_into().unwrap());
    
    let info = libnova::ipc::MessageInfo::new((IRQ_SET_IRQ_HANDLER as u64).try_into().unwrap(), 0, 1, 0);
    let resp = libnova::ipc::call(irq_handler.try_into().unwrap(), info);
    let label = resp.label();
    if label == 0 { Ok(()) } else { Err(label as usize) }
}

pub struct IoApic {
    base_vaddr: usize,
}

impl IoApic {
    pub unsafe fn new(base_vaddr: usize) -> Self {
        Self { base_vaddr }
    }

    pub unsafe fn read(&self, reg: u32) -> u32 {
        let volatile_ptr = self.base_vaddr as *mut u32;
        // IOREGSEL is at offset 0x00
        core::ptr::write_volatile(volatile_ptr, reg);
        // IOWIN is at offset 0x10
        let data_ptr = (self.base_vaddr + 0x10) as *const u32;
        core::ptr::read_volatile(data_ptr)
    }

    #[allow(dead_code)]
    pub unsafe fn write(&mut self, reg: u32, value: u32) {
        let volatile_ptr = self.base_vaddr as *mut u32;
        core::ptr::write_volatile(volatile_ptr, reg);
        let data_ptr = (self.base_vaddr + 0x10) as *mut u32;
        core::ptr::write_volatile(data_ptr, value);
    }
    
    pub fn id(&self) -> u8 {
        unsafe { ((self.read(0x00) >> 24) & 0xF) as u8 }
    }
    
    pub fn version(&self) -> u8 {
        unsafe { (self.read(0x01) & 0xFF) as u8 }
    }
    
    pub fn max_redirection_entry(&self) -> u8 {
        unsafe { ((self.read(0x01) >> 16) & 0xFF) as u8 }
    }
}

/// Manually invoke X86IRQIssueIRQHandlerIOAPIC because bindings are missing
#[allow(clippy::too_many_arguments)]
pub fn get_ioapic_handler(
    irq_control: usize,
    ioapic: usize,
    pin: usize,
    level: usize,
    polarity: usize,
    root: usize,
    index: usize,
    depth: usize,
    vector: usize,
) -> Result<(), usize> {
    
    // Set extra cap (root CNode) at index 0
    libnova::ipc::set_cap(0, (root as u64).try_into().unwrap());
    
    // Set Message Registers based on kernel/seL4/src/arch/x86/object/interrupt.c
    // Arg 0: index
    libnova::ipc::set_mr(0, (index as u64).try_into().unwrap());
    // Arg 1: depth
    libnova::ipc::set_mr(1, (depth as u64).try_into().unwrap());
    // Arg 2: ioapic
    libnova::ipc::set_mr(2, (ioapic as u64).try_into().unwrap());
    
    // Arg 3: pin
    libnova::ipc::set_mr(3, (pin as u64).try_into().unwrap());

    // Arg 4: level (trigger mode)
    libnova::ipc::set_mr(4, (level as u64).try_into().unwrap());

    // Arg 5: polarity
    libnova::ipc::set_mr(5, (polarity as u64).try_into().unwrap());

    // Arg 6: vector
    libnova::ipc::set_mr(6, (vector as u64).try_into().unwrap());

    let info = libnova::ipc::MessageInfo::new(
        (X86_IRQ_ISSUE_IRQ_HANDLER_IOAPIC as u64).try_into().unwrap(), // label
        0,
        1, // extra caps
        7  // MRs
    );
    
    let resp = libnova::ipc::call(irq_control.try_into().unwrap(), info);
    let label = resp.label();
    
    if label == 0 {
        Ok(())
    } else {
        Err(label as usize)
    }
}

pub fn init(
    boot_info: &seL4_BootInfo,
    paddr: usize,
    allocator: &mut UntypedAllocator,
    slots: &mut SlotAllocator,
    context: &mut AcpiContext,
) -> Option<IoApic> {
    println!("[IOAPIC] Initializing IOAPIC at paddr 0x{:x}...", paddr);
    
    match crate::arch::acpi::map_phys(boot_info, paddr, 0, allocator, slots, context) {
        Ok(vaddr) => {
            println!("[IOAPIC] Mapped IOAPIC to vaddr 0x{:x}", vaddr);
            let ioapic = unsafe { IoApic::new(vaddr) };
            
            let id = ioapic.id();
            let ver = ioapic.version();
            let max_entries = ioapic.max_redirection_entry();
            
            println!("[IOAPIC] ID: {}, Version: 0x{:x}, Max Redirection Entries: {}", id, ver, max_entries);
            Some(ioapic)
        },
        Err(e) => {
            println!("[IOAPIC] Failed to map IOAPIC: {:?}", e);
            None
        }
    }
}

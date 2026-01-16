use crate::acpi::AcpiContext;
use crate::memory::{SlotAllocator, UntypedAllocator};
use sel4_sys::seL4_BootInfo;
use crate::println;

pub struct LocalApic {
    base_vaddr: usize,
}

impl LocalApic {
    pub unsafe fn new(base_vaddr: usize) -> Self {
        Self { base_vaddr }
    }

    pub unsafe fn read(&self, reg: u32) -> u32 {
        let ptr = (self.base_vaddr + reg as usize) as *const u32;
        core::ptr::read_volatile(ptr)
    }

    pub unsafe fn write(&mut self, reg: u32, value: u32) {
        let ptr = (self.base_vaddr + reg as usize) as *mut u32;
        core::ptr::write_volatile(ptr, value);
    }

    pub fn id(&self) -> u32 {
        unsafe { self.read(0x020) }
    }

    pub fn version(&self) -> u32 {
        unsafe { self.read(0x030) }
    }

    pub fn enable(&mut self) {
        // Set Spurious Interrupt Vector Register (SVR)
        // Bit 8: Enable APIC
        // Bits 0-7: Vector number (e.g., 0xFF for spurious vector)
        unsafe {
            let svr = self.read(0xF0);
            // Enable bit 8, set vector to 0xFF
            self.write(0xF0, svr | 0x100 | 0xFF);
        }
        println!("[APIC] Local APIC Enabled (SVR=0x{:x})", unsafe { self.read(0xF0) });
    }
}

pub fn init(
    boot_info: &seL4_BootInfo,
    paddr: usize,
    allocator: &mut UntypedAllocator,
    slots: &mut SlotAllocator,
    context: &mut AcpiContext,
) -> Option<LocalApic> {
    println!("[APIC] Initializing Local APIC at paddr 0x{:x}...", paddr);
    
    // Map the APIC page
    match crate::acpi::map_phys(boot_info, paddr, 0, allocator, slots, context) {
        Ok(vaddr) => {
            println!("[APIC] Mapped Local APIC to vaddr 0x{:x}", vaddr);
            let mut apic = unsafe { LocalApic::new(vaddr) };
            
            let id = apic.id();
            let version = apic.version();
            println!("[APIC] ID: 0x{:x}, Version: 0x{:x}", id, version);
            
            apic.enable();
            Some(apic)
        },
        Err(e) => {
            println!("[APIC] Local APIC mapping unavailable in user space on seL4 x86 ({:?}); continuing.", e);
            None
        }
    }
}

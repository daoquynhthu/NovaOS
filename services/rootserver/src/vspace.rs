use sel4_sys::*;
use crate::memory::{ObjectAllocator, SlotAllocator};
use crate::println;
use crate::utils::check_syscall_result;

// x86_64 mapping constants
const SEL4_MAPPING_LOOKUP_LEVEL: usize = 2;
const SEL4_MAPPING_LOOKUP_NO_PT: seL4_Word = 21;
const SEL4_MAPPING_LOOKUP_NO_PD: seL4_Word = 30;
const SEL4_MAPPING_LOOKUP_NO_PDPT: seL4_Word = 39;

// Object Types (from bindings.rs constants)
const SE_L4_X86_PAGE_TABLE_OBJECT: seL4_Word = 10;
const SE_L4_X86_PAGE_DIRECTORY_OBJECT: seL4_Word = 11;
const SE_L4_X86_PDPT_OBJECT: seL4_Word = 5; // _mode_object_seL4_X86_PDPTObject

// Invocation Labels (from bindings.rs)
const ARCH_INVOCATION_LABEL_X86_PDPT_MAP: seL4_Word = 31;
const ARCH_INVOCATION_LABEL_X86_PAGE_DIRECTORY_MAP: seL4_Word = 33;
const ARCH_INVOCATION_LABEL_X86_PAGE_TABLE_MAP: seL4_Word = 35;
const ARCH_INVOCATION_LABEL_X86_PAGE_MAP: seL4_Word = 39;
#[allow(dead_code)]
const ARCH_INVOCATION_LABEL_X86_PAGE_UNMAP: seL4_Word = 40;

const ARCH_INVOCATION_LABEL_X86_ASID_POOL_ASSIGN: seL4_Word = 44; // Correct value for x86_64 with IOMMU=ON, VTX=OFF
const SE_L4_X64_PML4_OBJECT: seL4_Word = 6; // Mode-specific object type for PML4
#[allow(dead_code)]
const SE_L4_X86_ASID_POOL_OBJECT: seL4_Word = 12; // Generic object type for ASID Pool (if needed)

const MAX_PAGING_CAPS: usize = 32;

#[derive(Debug, Clone, Copy)]
pub struct VSpace {
    pub pml4_cap: seL4_CPtr,
    pub paging_caps: [seL4_CPtr; MAX_PAGING_CAPS],
    pub paging_cap_count: usize,
}

impl VSpace {
    pub fn new(pml4_cap: seL4_CPtr) -> Self {
        VSpace { 
            pml4_cap,
            paging_caps: [0; MAX_PAGING_CAPS],
            paging_cap_count: 0,
        }
    }

    /// Allocate a new VSpace (PML4) and assign it to an ASID
    pub fn new_from_scratch<A: ObjectAllocator>(
        allocator: &mut A,
        slots: &mut SlotAllocator,
        boot_info: &seL4_BootInfo,
        asid_pool: seL4_CPtr,
    ) -> Result<Self, seL4_Error> {
        // Formal verification: Pre-condition checks
        debug_assert!(asid_pool != 0, "ASID Pool cap cannot be 0");

        // 1. Allocate PML4 Object
        let pml4_cap = allocator.allocate(boot_info, SE_L4_X64_PML4_OBJECT, 12, slots)?;
        debug_assert!(pml4_cap != 0, "Allocated PML4 cap cannot be 0");

        // 2. Assign ASID
        unsafe {
            let info = seL4_MessageInfo_new(ARCH_INVOCATION_LABEL_X86_ASID_POOL_ASSIGN, 0, 1, 0);
            seL4_SetCap_My(0, pml4_cap);
            
            let dest_info = seL4_Call(asid_pool, info);
            if let Err(e) = check_syscall_result(dest_info) {
                println!("[VSpace] ASID Pool Assign failed: {:?}", e);
                return Err(e);
            }
        }
        
        println!("[VSpace] Created new VSpace with PML4 cap {}", pml4_cap);
        Ok(VSpace::new(pml4_cap))
    }

    /// Unmap a frame
    #[allow(dead_code)]
    pub fn unmap_page(&self, frame_cap: seL4_CPtr) -> Result<(), seL4_Error> {
        unsafe {
            let info = seL4_MessageInfo_new(ARCH_INVOCATION_LABEL_X86_PAGE_UNMAP, 0, 0, 0);
            let resp = seL4_Call(frame_cap, info);
            check_syscall_result(resp)
        }
    }

    /// Map a 4K page at a specific virtual address
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::manual_is_multiple_of)]
    pub fn map_page<A: ObjectAllocator>(
        &mut self,
        allocator: &mut A,
        slots: &mut SlotAllocator,
        boot_info: &seL4_BootInfo,
        frame_cap: seL4_CPtr,
        vaddr: usize,
        rights: seL4_CapRights,
        attr: seL4_X86_VMAttributes,
    ) -> Result<(), seL4_Error> {
        debug_assert!(vaddr % 4096 == 0, "Virtual address must be page aligned");
        loop {
            match self.map_page_syscall(frame_cap, vaddr, rights, attr) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if e != seL4_Error::seL4_FailedLookup {
                        println!("[VSpace] Map failed with error: {:?}", e);
                        return Err(e);
                    }
                    // Handle failed lookup (missing paging structures)
                    self.handle_map_error(allocator, slots, boot_info, vaddr)?;
                }
            }
        }
    }

    fn map_page_syscall(
        &self,
        frame_cap: seL4_CPtr,
        vaddr: usize,
        rights: seL4_CapRights,
        attr: seL4_X86_VMAttributes,
    ) -> Result<(), seL4_Error> {
        unsafe {
            let info = seL4_MessageInfo_new(ARCH_INVOCATION_LABEL_X86_PAGE_MAP, 0, 1, 3);
            seL4_SetMR(0, vaddr as seL4_Word);
            seL4_SetMR(1, rights.words[0]); // Access inner word
            seL4_SetMR(2, attr as seL4_Word);
            seL4_SetCap_My(0, self.pml4_cap);
            
            let dest_info = seL4_Call(frame_cap, info);
            check_syscall_result(dest_info)
        }
    }

    fn handle_map_error<A: ObjectAllocator>(
        &mut self,
        allocator: &mut A,
        slots: &mut SlotAllocator,
        boot_info: &seL4_BootInfo,
        vaddr: usize,
    ) -> Result<(), seL4_Error> {
        let failed_bits = unsafe { seL4_GetMR(SEL4_MAPPING_LOOKUP_LEVEL) };
        
        match failed_bits {
            SEL4_MAPPING_LOOKUP_NO_PT => {
                self.map_paging_structure(allocator, slots, boot_info, vaddr, SE_L4_X86_PAGE_TABLE_OBJECT, ARCH_INVOCATION_LABEL_X86_PAGE_TABLE_MAP)
            }
            SEL4_MAPPING_LOOKUP_NO_PD => {
                self.map_paging_structure(allocator, slots, boot_info, vaddr, SE_L4_X86_PAGE_DIRECTORY_OBJECT, ARCH_INVOCATION_LABEL_X86_PAGE_DIRECTORY_MAP)
            }
            SEL4_MAPPING_LOOKUP_NO_PDPT => {
                self.map_paging_structure(allocator, slots, boot_info, vaddr, SE_L4_X86_PDPT_OBJECT, ARCH_INVOCATION_LABEL_X86_PDPT_MAP)
            }
            _ => {
                println!("[VSpace] Unexpected lookup failure bits: {}", failed_bits);
                Err(seL4_Error::seL4_FailedLookup)
            }
        }
    }

    fn map_paging_structure<A: ObjectAllocator>(
        &mut self,
        allocator: &mut A,
        slots: &mut SlotAllocator,
        boot_info: &seL4_BootInfo,
        vaddr: usize,
        type_: seL4_Word,
        map_label: seL4_Word,
    ) -> Result<(), seL4_Error> {
        // Check if we have space to track the new cap
        if self.paging_cap_count >= MAX_PAGING_CAPS {
            println!("[VSpace] Max paging structures limit reached!");
            return Err(seL4_Error::seL4_NotEnoughMemory);
        }

        // Retype Untyped Memory to Paging Structure
        // All paging structures are 4KB (12 bits)
        let cap = allocator.allocate(boot_info, type_, 12, slots)?;

        // Map the structure
        unsafe {
            // X86PageTableMap, X86PageDirectoryMap, X86PDPTMap all take:
            // - Caps: [PML4 (root)]
            // - Args: [vaddr, attr]
            let info = seL4_MessageInfo_new(map_label, 0, 1, 2);
            seL4_SetMR(0, vaddr as seL4_Word);
            seL4_SetMR(1, seL4_X86_VMAttributes_seL4_X86_Default_VMAttributes as seL4_Word);
            seL4_SetCap_My(0, self.pml4_cap);

            let dest_info = seL4_Call(cap, info);
            if let Err(e) = check_syscall_result(dest_info) {
                println!("[VSpace] Failed to map paging structure (type={}): {:?}", type_, e);
                return Err(e);
            }
        }

        // Track the capability
        self.paging_caps[self.paging_cap_count] = cap;
        self.paging_cap_count += 1;
        // println!("[VSpace] Mapped paging structure (type={}) at 0x{:x}, cap={}", type_, vaddr, cap);
        Ok(())
    }
}

use sel4_sys::{
    seL4_BootInfo, seL4_CPtr, seL4_CapRights, seL4_Error, seL4_Word,
    seL4_X86_VMAttributes,
};
use crate::memory::{ObjectAllocator, SlotAllocator};
use libnova::syscall::check_msg_err;

// x86_64 mapping constants
// const SEL4_MAPPING_LOOKUP_LEVEL: usize = 2; // Unused
const SEL4_MAPPING_LOOKUP_NO_PT: seL4_Word = 21;
const SEL4_MAPPING_LOOKUP_NO_PD: seL4_Word = 30;
const SEL4_MAPPING_LOOKUP_NO_PDPT: seL4_Word = 39;

// Temporary constants until we confirm sel4_sys export
#[allow(non_upper_case_globals)]
const seL4_X86_PageTableObject: seL4_Word = 10;
#[allow(non_upper_case_globals)]
const seL4_X86_PageDirectoryObject: seL4_Word = 11;
#[allow(non_upper_case_globals)]
const seL4_X86_PDPTObject: seL4_Word = 5;

// Object Types (from bindings.rs constants)
const SE_L4_X86_PAGE_TABLE_OBJECT: seL4_Word = seL4_X86_PageTableObject;
const SE_L4_X86_PAGE_DIRECTORY_OBJECT: seL4_Word = seL4_X86_PageDirectoryObject;
const SE_L4_X86_PDPT_OBJECT: seL4_Word = seL4_X86_PDPTObject;

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

fn to_sel4_error(e: libnova::syscall::Error) -> seL4_Error {
    match e {
        libnova::syscall::Error::NoError => seL4_Error::seL4_NoError,
        libnova::syscall::Error::InvalidArgument => seL4_Error::seL4_InvalidArgument,
        libnova::syscall::Error::InvalidCapability => seL4_Error::seL4_InvalidCapability,
        libnova::syscall::Error::IllegalOperation => seL4_Error::seL4_IllegalOperation,
        libnova::syscall::Error::RangeError => seL4_Error::seL4_RangeError,
        libnova::syscall::Error::AlignmentError => seL4_Error::seL4_AlignmentError,
        libnova::syscall::Error::FailedLookup => seL4_Error::seL4_FailedLookup,
        libnova::syscall::Error::TruncatedMessage => seL4_Error::seL4_TruncatedMessage,
        libnova::syscall::Error::DeleteFirst => seL4_Error::seL4_DeleteFirst,
        libnova::syscall::Error::RevokeFirst => seL4_Error::seL4_RevokeFirst,
        libnova::syscall::Error::NotEnoughMemory => seL4_Error::seL4_NotEnoughMemory,
        _ => seL4_Error::seL4_IllegalOperation,
    }
}

impl VSpace {
    pub fn new(pml4_cap: seL4_CPtr) -> Self {
        VSpace { 
            pml4_cap,
            paging_caps: [0; MAX_PAGING_CAPS],
            paging_cap_count: 0,
        }
    }

    /// Assign ASID
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
        {
            let info = libnova::ipc::MessageInfo::new(ARCH_INVOCATION_LABEL_X86_ASID_POOL_ASSIGN, 0, 1, 0);
            libnova::ipc::set_cap(0, pml4_cap);
            
            let dest_info = libnova::ipc::call(asid_pool, info).expect("ASID Pool Assign IPC failed");
            if let Err(e) = check_msg_err(dest_info.inner) {
                println!("[VSpace] ASID Pool Assign failed: {:?}", e);
                return Err(to_sel4_error(e));
            }
        }
        
        println!("[VSpace] Created new VSpace with PML4 cap {}", pml4_cap);
        Ok(VSpace::new(pml4_cap))
    }

    /// Unmap a frame
    #[allow(dead_code)]
    pub fn unmap_page(&self, frame_cap: seL4_CPtr) -> Result<(), seL4_Error> {
        let info = libnova::ipc::MessageInfo::new(ARCH_INVOCATION_LABEL_X86_PAGE_UNMAP, 0, 0, 0);
        libnova::ipc::call(frame_cap, info).map(|_| ())
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
        
        let mut attempts = 0;
        const MAX_ATTEMPTS: usize = 3; // PML4 -> PDPT -> PD -> PT

        loop {
            match self.map_page_syscall(frame_cap, vaddr, rights, attr) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if e != seL4_Error::seL4_FailedLookup {
                        println!("[VSpace] Map syscall failed for frame {} at 0x{:x} with error: {:?}", frame_cap, vaddr, e);
                        return Err(e);
                    }
                    
                    // Immediately read failed bits to avoid them being overwritten
                    let failed_bits = libnova::ipc::get_mr(0);

                    if attempts >= MAX_ATTEMPTS {
                        println!("[VSpace] Max mapping attempts reached for 0x{:x}", vaddr);
                        return Err(seL4_Error::seL4_FailedLookup);
                    }

                    // println!("[VSpace] Lookup failed for 0x{:x}, allocating paging structures (Attempt {})...", vaddr, attempts + 1);
                    self.handle_map_error(allocator, slots, boot_info, vaddr, failed_bits)?;
                    attempts += 1;
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
        if frame_cap == 0 {
             println!("[VSpace] map_page_syscall called with frame_cap=0");
             return Err(seL4_Error::seL4_InvalidCapability);
        }

        let info = libnova::ipc::MessageInfo::new(ARCH_INVOCATION_LABEL_X86_PAGE_MAP, 0, 1, 3);
        libnova::ipc::set_mr(0, vaddr as seL4_Word);
        libnova::ipc::set_mr(1, rights.words[0]); // Access inner word
        libnova::ipc::set_mr(2, attr as seL4_Word);
        libnova::ipc::set_cap(0, self.pml4_cap);
        
        let dest_info = libnova::ipc::call(frame_cap, info);
        dest_info.map(|_| ()).map_err(|e| {
             if e == seL4_Error::seL4_InvalidCapability {
                  println!("[VSpace] Page Map InvalidCapability. frame_cap={}, pml4_cap={}, vaddr={:x}", 
                      frame_cap, self.pml4_cap, vaddr);
             }
             e
        })
    }

    fn handle_map_error<A: ObjectAllocator>(
        &mut self,
        allocator: &mut A,
        slots: &mut SlotAllocator,
        boot_info: &seL4_BootInfo,
        vaddr: usize,
        failed_bits: seL4_Word,
    ) -> Result<(), seL4_Error> {
        // Cache to support larger address space
        if self.paging_cap_count >= MAX_PAGING_CAPS {
            return Err(seL4_Error::seL4_NotEnoughMemory);
        }
        
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
        {
            // X86PageTableMap, X86PageDirectoryMap, X86PDPTMap all take:
            // - Caps: [PML4 (root)]
            // - Args: [vaddr, attr]
            let info = libnova::ipc::MessageInfo::new(map_label, 0, 1, 2);
            libnova::ipc::set_mr(0, vaddr as seL4_Word);
            libnova::ipc::set_mr(1, seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes as seL4_Word);
            libnova::ipc::set_cap(0, self.pml4_cap);

            let dest_info = libnova::ipc::call(cap, info);
            if let Err(e) = dest_info {
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

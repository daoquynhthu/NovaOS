use sel4_sys::{
    seL4_BootInfo, seL4_CPtr, seL4_CapRights, seL4_Error, seL4_Word,
    seL4_X86_VMAttributes,
};
use crate::memory::{ObjectAllocator, SlotAllocator};

// x86_64 mapping constants
// const SEL4_MAPPING_LOOKUP_LEVEL: usize = 2; // Unused
#[allow(dead_code)]
const SEL4_MAPPING_LOOKUP_NO_PT: seL4_Word = 21;
#[allow(dead_code)]
const SEL4_MAPPING_LOOKUP_NO_PD: seL4_Word = 30;
#[allow(dead_code)]
const SEL4_MAPPING_LOOKUP_NO_PDPT: seL4_Word = 39;

// Temporary constants until we confirm sel4_sys export
// Correct values for x86_64 (seL4 12.0+ with HugePage)
// seL4_X86_PDPTObject = 5
// seL4_X64_PML4Object = 6
// seL4_X64_HugePageObject = 7
// seL4_X86_4K = 8
// seL4_X86_LargePageObject = 9
// seL4_X86_PageTableObject = 10
// seL4_X86_PageDirectoryObject = 11

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
pub struct PagingCap {
    pub cap: seL4_CPtr,
    pub vaddr: usize,
    pub level: usize, // 3=PDPT, 2=PD, 1=PT
}

#[derive(Debug, Clone, Copy)]
pub struct VSpace {
    pub pml4_cap: seL4_CPtr,
    pub paging_caps: [Option<PagingCap>; MAX_PAGING_CAPS],
    pub paging_cap_count: usize,
}

#[allow(dead_code)]
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
            paging_caps: [None; MAX_PAGING_CAPS],
            paging_cap_count: 0,
        }
    }

    pub fn new_from_scratch<A: ObjectAllocator>(
        allocator: &mut A,
        slots: &mut SlotAllocator,
        boot_info: &seL4_BootInfo,
        asid_pool: seL4_CPtr,
    ) -> Result<Self, seL4_Error> {
        // Allocate PML4
        let pml4_cap = allocator.allocate(boot_info, SE_L4_X64_PML4_OBJECT, 12, slots)?;

        // Assign ASID
        // seL4_X86_ASIDPool_Assign takes 1 capability (PML4) and 0 data words.
        // MessageInfo::new(label, caps_unwrapped, extra_caps, length)
        let info = libnova::ipc::MessageInfo::new(ARCH_INVOCATION_LABEL_X86_ASID_POOL_ASSIGN, 0, 1, 0);
        libnova::ipc::set_cap(0, pml4_cap);
        libnova::ipc::call(asid_pool, info)?;
        
        Ok(VSpace::new(pml4_cap))
    }

    fn get_level(type_: seL4_Word) -> usize {
        match type_ {
            SE_L4_X86_PDPT_OBJECT => 3,
            SE_L4_X86_PAGE_DIRECTORY_OBJECT => 2,
            SE_L4_X86_PAGE_TABLE_OBJECT => 1,
            _ => 0,
        }
    }

    fn get_cap(&self, vaddr: usize, level: usize) -> Result<seL4_CPtr, seL4_Error> {
        if level == 4 {
            return Ok(self.pml4_cap);
        }
        
        let mask = match level {
            3 => !((1 << 39) - 1), // PDPT (covers 512GB)
            2 => !((1 << 30) - 1), // PD (covers 1GB)
            1 => !((1 << 21) - 1), // PT (covers 2MB)
            _ => return Err(seL4_Error::seL4_InvalidArgument),
        };

        let target_base = vaddr & mask;

        for i in 0..self.paging_cap_count {
            if let Some(cap_info) = self.paging_caps[i] {
                if cap_info.level == level && (cap_info.vaddr & mask) == target_base {
                    return Ok(cap_info.cap);
                }
            }
        }
        Err(seL4_Error::seL4_FailedLookup)
    }

    fn ensure_pt_exists<A: ObjectAllocator>(
        &mut self,
        allocator: &mut A,
        slots: &mut SlotAllocator,
        boot_info: &seL4_BootInfo,
        vaddr: usize,
    ) -> Result<(), seL4_Error> {
        // Level 1: PT
        if self.get_cap(vaddr, 1).is_ok() {
            return Ok(());
        }

        // Level 2: PD
        if self.get_cap(vaddr, 2).is_err() {
            // Level 3: PDPT
            if self.get_cap(vaddr, 3).is_err() {
                 // Map PDPT (Level 3) into PML4 (Level 4)
                 self.map_paging_structure(allocator, slots, boot_info, vaddr, SE_L4_X86_PDPT_OBJECT, ARCH_INVOCATION_LABEL_X86_PDPT_MAP)?;
            }
            // Map PD (Level 2) into PDPT (Level 3)
            self.map_paging_structure(allocator, slots, boot_info, vaddr, SE_L4_X86_PAGE_DIRECTORY_OBJECT, ARCH_INVOCATION_LABEL_X86_PAGE_DIRECTORY_MAP)?;
        }
        
        // Map PT (Level 1) into PD (Level 2)
        self.map_paging_structure(allocator, slots, boot_info, vaddr, SE_L4_X86_PAGE_TABLE_OBJECT, ARCH_INVOCATION_LABEL_X86_PAGE_TABLE_MAP)?;
        
        Ok(())
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
        
        self.ensure_pt_exists(allocator, slots, boot_info, vaddr)?;

        let info = libnova::ipc::MessageInfo::new(ARCH_INVOCATION_LABEL_X86_PAGE_MAP, 0, 1, 3);
        libnova::ipc::set_mr(0, vaddr as seL4_Word);
        libnova::ipc::set_mr(1, rights.words[0]); // Access inner word
        libnova::ipc::set_mr(2, attr as seL4_Word);
        // On x86_64, map operations take the PML4 as the target cap, not the immediate parent
        libnova::ipc::set_cap(0, self.pml4_cap);
        
        // println!("[VSpace] map_page: cap={} vaddr={:x} pml4={} rights={:?}", frame_cap, vaddr, self.pml4_cap, rights);

        let dest_info = libnova::ipc::call(frame_cap, info);
        dest_info.map(|_| ()).map_err(|e| {
             println!("[VSpace] Page Map Failed! Error={:?} frame_cap={}, pml4={}, vaddr={:x}", 
                  e, frame_cap, self.pml4_cap, vaddr);
             e
        })
    }

    /// Unmap a page
    pub fn unmap_page(&mut self, frame_cap: seL4_CPtr) -> Result<(), seL4_Error> {
        let info = libnova::ipc::MessageInfo::new(ARCH_INVOCATION_LABEL_X86_PAGE_UNMAP, 0, 0, 0);
        libnova::ipc::call(frame_cap, info).map(|_| ()).map_err(|e| e)
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

        let level = Self::get_level(type_);
        // On x86_64, map operations take the PML4 as the target cap
        let parent_cap = self.pml4_cap;

        // Retype Untyped Memory to Paging Structure
        // All paging structures are 4KB (12 bits)
        let cap = allocator.allocate(boot_info, type_, 12, slots)?;

        // Map the structure
        {
            // X86PageTableMap, X86PageDirectoryMap, X86PDPTMap all take:
            // - Caps: [Parent Cap (PML4)]
            // - Args: [vaddr, attr]
            let info = libnova::ipc::MessageInfo::new(map_label, 0, 1, 2);
            libnova::ipc::set_mr(0, vaddr as seL4_Word);
            libnova::ipc::set_mr(1, seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes as seL4_Word);
            libnova::ipc::set_cap(0, parent_cap);

            let dest_info = libnova::ipc::call(cap, info);
            if let Err(e) = dest_info {
                if e != seL4_Error::seL4_DeleteFirst {
                    println!("[VSpace] Map Paging Structure Failed: {:?} for cap {} at {:x}", e, cap, vaddr);
                    return Err(e);
                }
                // If DeleteFirst, we ignore the error (structure already exists)
                // We still track it in paging_caps so we don't try to map it again in this VSpace instance.
            }
        }

        // Track the capability
        self.paging_caps[self.paging_cap_count] = Some(PagingCap {
            cap,
            vaddr, // We rely on get_cap to mask this correctly when searching
            level,
        });
        self.paging_cap_count += 1;
        // println!("[VSpace] Mapped paging structure (type={}, level={}) at 0x{:x}, cap={}", type_, level, vaddr, cap);
        Ok(())
    }
}

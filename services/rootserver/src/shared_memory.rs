use sel4_sys::{seL4_CPtr, seL4_Error, seL4_Word};
use libnova::cap::CapRights_new;
use crate::memory::{ObjectAllocator, SlotAllocator, MemoryRegion};
use crate::process::Process;

pub struct SharedMemoryManager {
    regions: [Option<MemoryRegion>; 32],
}

impl SharedMemoryManager {
    pub const fn new() -> Self {
        SharedMemoryManager {
            regions: [None; 32],
        }
    }

    pub fn create_shared_region<A: ObjectAllocator>(
        &mut self,
        allocator: &mut A,
        slot_allocator: &mut SlotAllocator,
        boot_info: &sel4_sys::seL4_BootInfo,
        _size: usize,
    ) -> Result<usize, seL4_Error> {
        // Find free slot
        let mut idx = 0;
        let mut found = false;
        while idx < self.regions.len() {
            if self.regions[idx].is_none() {
                found = true;
                break;
            }
            idx += 1;
        }

        if !found {
            return Err(seL4_Error::seL4_NotEnoughMemory);
        }

        // Allocate frame (assuming 4K for now regardless of size, or handling size)
        // For simplicity, support only 4K requests or single frame
        const SE_L4_X86_4K: seL4_Word = 8;
        let frame_cap = allocator.allocate(boot_info, SE_L4_X86_4K, sel4_sys::seL4_PageBits.into(), slot_allocator)?;
        
        self.regions[idx] = Some(MemoryRegion {
            frame_cap,
            size_bits: 12,
        });

        Ok(idx)
    }

    pub fn map_shared_region<A: ObjectAllocator>(
        &mut self,
        key: usize,
        process: &mut Process,
        allocator: &mut A,
        slot_allocator: &mut SlotAllocator,
        boot_info: &sel4_sys::seL4_BootInfo,
        vaddr: usize,
    ) -> Result<(), seL4_Error> {
        if key >= self.regions.len() || self.regions[key].is_none() {
            return Err(seL4_Error::seL4_FailedLookup);
        }

        let region = self.regions[key].unwrap();
        
        // Copy cap to process cspace
        let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
        let cnode_depth = sel4_sys::seL4_WordBits as u8;

        let copy_cap_slot = slot_allocator.alloc()?;
        let root_node = libnova::cap::CNode::new(root_cnode, cnode_depth); 
        
        let rights = CapRights_new(false, false, true, true); // RW
        let err = root_node.copy(
            copy_cap_slot,
            &root_node,
            region.frame_cap,
            rights,
        );
            
        if err.is_err() {
             return Err(seL4_Error::seL4_DeleteFirst);
        }

        // Map into VSpace
        let res = process.vspace.map_page(
            allocator,
            slot_allocator,
            boot_info,
            copy_cap_slot,
            vaddr,
            CapRights_new(false, true, true, true),
            sel4_sys::seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes
        );

        if res.is_ok() {
            let _ = process.track_frame(copy_cap_slot);
            Ok(())
        } else {
             let _ = root_node.delete(copy_cap_slot);
             slot_allocator.free(copy_cap_slot);
             Err(seL4_Error::seL4_FailedLookup)
        }
    }
}

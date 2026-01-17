use sel4_sys::{
    seL4_BootInfo, seL4_CPtr, seL4_Error, seL4_PageBits,
    seL4_RootCNodeCapSlots, seL4_X86_VMAttributes,
};
use crate::memory::{ObjectAllocator, SlotAllocator};
use crate::utils::{seL4_CapRights_new, copy_cap, seL4_CNode_Delete, seL4_X86_4K};

pub const MAX_SHARED_REGIONS: usize = 16;

#[derive(Clone, Copy)]
pub struct SharedRegion {
    pub key: usize,
    pub frame_cap: seL4_CPtr,
    #[allow(dead_code)]
    pub size: usize,
}

pub struct SharedMemoryManager {
    regions: [Option<SharedRegion>; MAX_SHARED_REGIONS],
    next_key: usize,
}

impl SharedMemoryManager {
    pub const fn new() -> Self {
        SharedMemoryManager {
            regions: [None; MAX_SHARED_REGIONS],
            next_key: 100, // Start keys at 100
        }
    }

    pub fn create_shared_region<T: ObjectAllocator>(
        &mut self,
        allocator: &mut T,
        slot_allocator: &mut SlotAllocator,
        boot_info: &seL4_BootInfo,
        size_bytes: usize,
    ) -> Result<usize, seL4_Error> {
        // Only support 4K pages for now
        if size_bytes != 4096 {
            return Err(seL4_Error::seL4_InvalidArgument);
        }

        // Find free slot
        let mut idx = None;
        for i in 0..MAX_SHARED_REGIONS {
            if self.regions[i].is_none() {
                idx = Some(i);
                break;
            }
        }

        if idx.is_none() {
            return Err(seL4_Error::seL4_NotEnoughMemory);
        }

        let idx = idx.unwrap();
        let key = self.next_key;
        self.next_key += 1;

        // Allocate Frame
        let frame_cap = allocator.allocate(boot_info, seL4_X86_4K, seL4_PageBits.into(), slot_allocator)
            .map_err(|_| seL4_Error::seL4_NotEnoughMemory)?;

        self.regions[idx] = Some(SharedRegion {
            key,
            frame_cap,
            size: size_bytes,
        });

        crate::println!("[SHM] Created shared region Key={} Cap={}", key, frame_cap);
        Ok(key)
    }

    pub fn map_shared_region<T: ObjectAllocator>(
        &self,
        key: usize,
        process: &mut crate::process::Process,
        allocator: &mut T,
        slot_allocator: &mut SlotAllocator,
        boot_info: &seL4_BootInfo,
        vaddr: usize,
    ) -> Result<(), seL4_Error> {
        // Find region
        let region = self.regions.iter().find(|r| r.map_or(false, |x| x.key == key));
        if region.is_none() {
             return Err(seL4_Error::seL4_InvalidArgument);
        }
        let region = region.unwrap().unwrap();

        // 1. Allocate a new slot for the copy
        let copy_cap_slot = slot_allocator.alloc()?;

        // 2. Copy the cap
        let root_cnode = seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
        unsafe {
            let err = copy_cap(
                root_cnode,
                copy_cap_slot,
                64, // Depth
                root_cnode,
                region.frame_cap,
                64,
                seL4_CapRights_new(0, 1, 1, 1) // RW
            );
            if err != seL4_Error::seL4_NoError {
                 slot_allocator.free(copy_cap_slot);
                 return Err(err);
            }
        }

        // 3. Map into VSpace
        let res = process.vspace.map_page(
            allocator,
            slot_allocator,
            boot_info,
            copy_cap_slot,
            vaddr,
            seL4_CapRights_new(0, 1, 1, 1),
            seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes
        );

        if res.is_ok() {
            // Track the frame so it gets deleted when process dies
            // Note: This deletes the COPY, not the original.
            let _ = process.track_frame(copy_cap_slot);
            crate::println!("[SHM] Mapped Key={} to PID={} VAddr=0x{:x} (CopyCap={})", key, 0, vaddr, copy_cap_slot); // PID 0 is placeholder
            Ok(())
        } else {
            // Cleanup copy
             unsafe { let _ = seL4_CNode_Delete(root_cnode, copy_cap_slot, 64); }
             slot_allocator.free(copy_cap_slot);
             Err(seL4_Error::seL4_FailedLookup)
        }
    }
}

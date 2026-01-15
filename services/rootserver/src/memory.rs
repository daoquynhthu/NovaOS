use sel4_sys::{
    seL4_BootInfo, seL4_Error, seL4_Word, seL4_CPtr,
    seL4_Call, seL4_MessageInfo_new, seL4_SetMR, seL4_MessageInfo_get_label, seL4_SetCap_My,
};
use crate::println;

const SE_L4_UNTYPED_RETYPE: seL4_Word = 1;
const SE_L4_CAP_INIT_THREAD_CNODE: seL4_CPtr = 2;

const MAX_CSPACE_SLOTS: usize = 4096;
const BITMAP_SIZE: usize = MAX_CSPACE_SLOTS / 64;

/// Allocator for CSpace slots (CNode indices) using a Bitmap
/// Supports alloc and free operations.
pub struct SlotAllocator {
    pub start: usize,
    pub end: usize,
    bitmap: [u64; BITMAP_SIZE],
}

impl SlotAllocator {
    pub fn new(boot_info: &seL4_BootInfo) -> Self {
        let mut allocator = SlotAllocator {
            start: boot_info.empty.start as usize,
            end: boot_info.empty.end as usize,
            bitmap: [0; BITMAP_SIZE],
        };

        // Mark all slots before 'start' as allocated
        for i in 0..allocator.start {
            allocator.mark(i);
        }
        
        // Mark all slots after 'end' as allocated (if any)
        for i in allocator.end..MAX_CSPACE_SLOTS {
            allocator.mark(i);
        }

        allocator
    }

    fn mark(&mut self, slot: usize) {
        // Formal verification: Check bounds
        debug_assert!(slot < MAX_CSPACE_SLOTS, "Slot index out of bounds");
        if slot < MAX_CSPACE_SLOTS {
            let idx = slot / 64;
            let bit = slot % 64;
            self.bitmap[idx] |= 1 << bit;
        }
    }

    fn clear(&mut self, slot: usize) {
        // Formal verification: Check bounds
        debug_assert!(slot < MAX_CSPACE_SLOTS, "Slot index out of bounds");
        if slot < MAX_CSPACE_SLOTS {
            let idx = slot / 64;
            let bit = slot % 64;
            self.bitmap[idx] &= !(1 << bit);
        }
    }

    fn is_allocated(&self, slot: usize) -> bool {
        if slot >= MAX_CSPACE_SLOTS {
            return true;
        }
        let idx = slot / 64;
        let bit = slot % 64;
        (self.bitmap[idx] & (1 << bit)) != 0
    }

    pub fn alloc(&mut self) -> Result<seL4_CPtr, seL4_Error> {
        // Search for a free bit starting from self.start
        for i in self.start..self.end {
            if !self.is_allocated(i) {
                self.mark(i);
                // Post-condition: Slot must be marked allocated
                debug_assert!(self.is_allocated(i), "Slot should be marked allocated after alloc");
                return Ok(i as seL4_CPtr);
            }
        }
        Err(seL4_Error::seL4_NotEnoughMemory)
    }

    pub fn free(&mut self, slot: seL4_CPtr) {
        self.clear(slot as usize);
    }
}

/// Trait for allocating kernel objects from untyped memory
pub trait ObjectAllocator {
    fn allocate(
        &mut self,
        boot_info: &seL4_BootInfo,
        type_: seL4_Word,
        size_bits: seL4_Word,
        slots: &mut SlotAllocator,
    ) -> Result<seL4_CPtr, seL4_Error>;
}

/// Allocator for Physical Memory (Untyped Capabilities)
/// Renamed from BumpAllocator to reflect its nature
pub struct UntypedAllocator {
    untyped_start: usize,
    untyped_end: usize,
    // We keep track of which untyped cap we are currently using
    last_used_idx: usize,
}

impl UntypedAllocator {
    pub fn new(boot_info: &seL4_BootInfo) -> Self {
        let len = boot_info.untyped.end - boot_info.untyped.start;
        println!("[Alloc] Initializing UntypedAllocator with {} untyped slots", len);

        UntypedAllocator {
            untyped_start: boot_info.untyped.start as usize,
            untyped_end: boot_info.untyped.end as usize,
            last_used_idx: 0,
        }
    }

    /// Retypes an untyped capability into a new object
    #[allow(clippy::too_many_arguments)]
    unsafe fn untyped_retype(
        service: seL4_CPtr,
        type_: seL4_Word,
        size_bits: seL4_Word,
        root: seL4_CPtr,
        node_index: seL4_Word,
        node_depth: seL4_Word,
        node_offset: seL4_Word,
        num_objects: seL4_Word,
    ) -> seL4_Error {
        // Label=1 (UntypedRetype), Caps=1 (root), Length=7
        let info = seL4_MessageInfo_new(SE_L4_UNTYPED_RETYPE, 0, 1, 7);
        seL4_SetMR(0, type_);
        seL4_SetMR(1, size_bits);
        seL4_SetCap_My(0, root);
        seL4_SetMR(2, node_index);
        seL4_SetMR(3, node_depth);
        seL4_SetMR(4, node_offset);
        seL4_SetMR(5, num_objects);
        
        let dest_info = seL4_Call(service, info);
        seL4_Error::from(seL4_MessageInfo_get_label(dest_info) as i32)
    }

    pub fn print_info(&self, boot_info: &seL4_BootInfo) {
        println!("[Alloc] Untyped memory info:");
        let list_ptr = boot_info.untypedList.as_ptr();
        println!("[Alloc] UntypedList Addr: {:p}", list_ptr);
        
        let start = self.untyped_start;
        let end = self.untyped_end;
        let len = end - start;
        
        println!("[Alloc] Scanning untyped slots {} to {}", start, end);
        
        // Print all untyped slots, summarizing devices
        for i in 0..len {
             let idx = i; 
             let slot = start + i;
             if idx < boot_info.untypedList.len() {
                 let desc = boot_info.untypedList[idx];
                 let type_str = if desc.isDevice != 0 { "Device" } else { "RAM" };
                 
                 // Always print RAM, limit Device printing
                 if desc.isDevice == 0 || i < 15 {
                    println!("[Alloc] Slot {}: PAddr={:#x}, SizeBits={}, Type={}", 
                        slot, desc.paddr, desc.sizeBits, type_str);
                 }
             }
        }
    }
}

impl ObjectAllocator for UntypedAllocator {
    fn allocate(
        &mut self,
        boot_info: &seL4_BootInfo,
        type_: seL4_Word,
        size_bits: seL4_Word,
        slots: &mut SlotAllocator,
    ) -> Result<seL4_CPtr, seL4_Error> {
        let dest_slot = slots.alloc()?; 

        // Iterate through untyped caps starting from last used
        let count = self.untyped_end - self.untyped_start;
        
        for i in 0..count {
            let idx = (self.last_used_idx + i) % count;
            let untyped_cptr = self.untyped_start + idx;
            
            let desc_idx = idx; 
            if desc_idx >= boot_info.untypedList.len() {
                continue;
            }
            let desc = boot_info.untypedList[desc_idx];

            if (desc.sizeBits as seL4_Word) < size_bits {
                continue;
            }
            if desc.isDevice != 0 {
                continue;
            }

            let root = SE_L4_CAP_INIT_THREAD_CNODE;
            let node_index = 0; 
            let node_depth = 0; 
            let node_offset = dest_slot; 
            let num_objects = 1;

            println!("[Alloc] Attempting retype: Untyped={} (Size={}) -> Slot={} (Type={}, Size={})", 
               untyped_cptr, desc.sizeBits, dest_slot, type_, size_bits);

            let err = unsafe {
                Self::untyped_retype(
                    untyped_cptr as seL4_CPtr,
                    type_,
                    size_bits,
                    root,
                    node_index,
                    node_depth,
                    node_offset,
                    num_objects,
                )
            };

            if err == seL4_Error::seL4_NoError {
                println!("[Alloc] Success: Retyped Untyped={} into Slot {}", untyped_cptr, dest_slot);
                self.last_used_idx = idx;
                return Ok(dest_slot);
            } else {
                println!("[Alloc] Retype failed for Untyped Slot {} (Type={}, Size={}): {:?}", 
                     untyped_cptr, 
                     if desc.isDevice != 0 { "Device" } else { "RAM" },
                     desc.sizeBits,
                     err);
            }
        }

        // If we reach here, we failed to allocate. Free the slot.
        slots.free(dest_slot);

        println!("[Alloc] Failed to allocate memory of size_bits {}", size_bits);
        Err(seL4_Error::seL4_NotEnoughMemory)
    }
}

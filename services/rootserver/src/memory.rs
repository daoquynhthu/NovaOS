use alloc::vec::Vec;
use sel4_sys::{
    seL4_BootInfo, seL4_Error, seL4_Word, seL4_CPtr,
};

const SE_L4_UNTYPED_RETYPE: seL4_Word = 1;
const SE_L4_CAP_INIT_THREAD_CNODE: seL4_CPtr = 2;

const MAX_CSPACE_SLOTS: usize = 4096;
const BITMAP_SIZE: usize = MAX_CSPACE_SLOTS / 64;
const MAX_UNTYPED_CAPS: usize = 256;

/// Represents a region of memory backed by a frame capability
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub frame_cap: seL4_CPtr,
    #[allow(dead_code)]
    pub size_bits: usize,
}

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
        
        // Invariant: start <= end <= MAX_SLOTS
        debug_assert!(allocator.start <= allocator.end, "Invariant: start <= end");
        debug_assert!(allocator.end <= MAX_CSPACE_SLOTS, "Invariant: end <= MAX_SLOTS");

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
                // Pre-condition: Slot must be free
                debug_assert!(!self.is_allocated(i), "Slot must be free before allocation");
                
                self.mark(i);
                
                // Post-condition: Slot must be marked allocated
                debug_assert!(self.is_allocated(i), "Slot must be marked allocated after alloc");
                return Ok(i as seL4_CPtr);
            }
        }
        Err(seL4_Error::seL4_NotEnoughMemory)
    }

    pub fn free(&mut self, slot: seL4_CPtr) {
        let slot_idx = slot as usize;
        // Pre-condition: Slot must be allocated
        // Note: In some cases double-free might happen safely if we just clear, 
        // but for strict verification we assert it was allocated.
        debug_assert!(self.is_allocated(slot_idx), "Double free or freeing unallocated slot");
        
        self.clear(slot_idx);
        
        // Post-condition: Slot must be free
        debug_assert!(!self.is_allocated(slot_idx), "Slot must be free after release");
    }

    pub fn stats(&self) -> (usize, usize, usize) {
        let total = self.end.saturating_sub(self.start);
        let mut free = 0usize;
        for i in self.start..self.end {
            if !self.is_allocated(i) {
                free += 1;
            }
        }
        (total, total - free, free)
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
    // Track usage of each untyped cap to simulate kernel's internal allocator state
    usage: [usize; MAX_UNTYPED_CAPS],
}

impl UntypedAllocator {
    pub fn new(boot_info: &seL4_BootInfo) -> Self {
        // let len = boot_info.untyped.end - boot_info.untyped.start;
        // println!("[Alloc] Initializing UntypedAllocator with {} untyped slots", len);

        UntypedAllocator {
            untyped_start: boot_info.untyped.start as usize,
            untyped_end: boot_info.untyped.end as usize,
            last_used_idx: 0,
            usage: [0; MAX_UNTYPED_CAPS],
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
        let info = libnova::ipc::MessageInfo::new(SE_L4_UNTYPED_RETYPE, 0, 1, 7);
        libnova::ipc::set_mr(0, type_);
        libnova::ipc::set_mr(1, size_bits);
        libnova::ipc::set_cap(0, root);
        libnova::ipc::set_mr(2, node_index);
        libnova::ipc::set_mr(3, node_depth);
        libnova::ipc::set_mr(4, node_offset);
        libnova::ipc::set_mr(5, num_objects);
        
        let dest_info = libnova::ipc::call(service, info);
        seL4_Error::from(dest_info.expect("Untyped retype IPC failed").label() as i32)
    }

    pub fn print_info(&self, boot_info: &seL4_BootInfo) {
        println!("[Alloc] Untyped memory info:");
        let list_ptr = boot_info.untypedList.as_ptr();
        println!("[Alloc] UntypedList Addr: {:p}", list_ptr);
        
        let start = self.untyped_start;
        let end = self.untyped_end;
        // let len = end - start;
        
        println!("[Alloc] Scanning untyped slots {} to {}", start, end);
        
        // Print all untyped slots, summarizing devices
        /*
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
        */
    }

    pub fn stats(&self, boot_info: &seL4_BootInfo) -> (usize, usize, u64, u64, usize) {
        let mut total_caps = self.untyped_end.saturating_sub(self.untyped_start);
        let max = core::cmp::min(boot_info.untypedList.len(), MAX_UNTYPED_CAPS);
        total_caps = core::cmp::min(total_caps, max);

        let mut ram_caps = 0usize;
        let mut ram_total_bytes = 0u64;
        let mut ram_used_bytes = 0u64;

        for idx in 0..total_caps {
            let desc = &boot_info.untypedList[idx];
            if desc.isDevice != 0 {
                continue;
            }
            ram_caps += 1;
            if desc.sizeBits < 63 {
                ram_total_bytes = ram_total_bytes.saturating_add(1u64 << desc.sizeBits);
            }
            ram_used_bytes = ram_used_bytes.saturating_add(self.usage[idx] as u64);
        }

        (total_caps, ram_caps, ram_used_bytes, ram_total_bytes, self.last_used_idx)
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

        // Best-fit allocation strategy with usage tracking
        let count = self.untyped_end - self.untyped_start;
        let mut best_idx: Option<usize> = None;
        let mut best_size_diff = u8::MAX;

        // 1. First pass: find the best fitting untyped memory that has enough space
        for i in 0..count {
            let idx = i;
            if idx >= boot_info.untypedList.len() {
                continue;
            }
            // Bounds check for usage array
            if idx >= MAX_UNTYPED_CAPS {
                break;
            }

            let desc = &boot_info.untypedList[idx];

            // Skip device memory and too small blocks
            if desc.isDevice != 0 || (desc.sizeBits as seL4_Word) < size_bits {
                continue;
            }

            // Check if we have enough space left (accounting for alignment)
            let current_usage = self.usage[idx];
            let alignment = 1 << size_bits;
            // Align up the current usage
            let start_offset = (current_usage + alignment - 1) & !(alignment - 1);
            let end_offset = start_offset + (1 << size_bits);
            
            if end_offset > (1 << desc.sizeBits) {
                // Not enough space in this block
                continue;
            }

            let size_diff = desc.sizeBits.saturating_sub(size_bits as u8);
            if size_diff < best_size_diff {
                best_size_diff = size_diff;
                best_idx = Some(idx);
                // Optimization: if exact match, break early
                if best_size_diff == 0 {
                    break;
                }
            }
        }

        // 2. Try to allocate from the best candidate
        if let Some(idx) = best_idx {
            let untyped_cptr = self.untyped_start + idx;
            let _desc = &boot_info.untypedList[idx];
            
            // Calculate offset again for the chosen block
            let current_usage = self.usage[idx];
            let alignment = 1 << size_bits;
            let start_offset = (current_usage + alignment - 1) & !(alignment - 1);
            
            // Perform retype
             unsafe {
                let err = UntypedAllocator::untyped_retype(
                    untyped_cptr.try_into().unwrap(),
                    type_,
                    size_bits,
                    SE_L4_CAP_INIT_THREAD_CNODE,
                    0,
                    0, // node_depth 0 = root cnode
                    dest_slot,
                    1,
                );
                
                if err != seL4_Error::seL4_NoError {
                    println!("[Alloc] Retype failed: {:?}", err);
                    slots.free(dest_slot);
                    return Err(err);
                }
            }
            
            // Update usage
            self.usage[idx] = start_offset + (1 << size_bits);
            self.last_used_idx = idx;
            
            return Ok(dest_slot);
        }

        println!("[Alloc] No suitable untyped memory found for size_bits {}", size_bits);
        slots.free(dest_slot);
        Err(seL4_Error::seL4_NotEnoughMemory)
    }
}

/// Allocator specifically for 4K Frames, supporting reuse
pub struct FrameAllocator {
    free_frames: Vec<seL4_CPtr>,
}

impl FrameAllocator {
    pub fn new() -> Self {
        FrameAllocator {
            free_frames: Vec::new(),
        }
    }

    pub fn alloc<A: ObjectAllocator>(
        &mut self,
        allocator: &mut A,
        boot_info: &seL4_BootInfo,
        slots: &mut SlotAllocator,
    ) -> Result<seL4_CPtr, seL4_Error> {
        // TEMP DEBUG: Disable recycling to test if frame 567 is corrupt
        // if let Some(cap) = self.free_frames.pop() {
        //    return Ok(cap);
        // }
        // No free frames, allocate new one
        // 4K Frame = size_bits 12, type = seL4_X86_4K (value 8)
        allocator.allocate(boot_info, 8, 12, slots)
    }

    pub fn free(&mut self, frame_cap: seL4_CPtr) {
        self.free_frames.push(frame_cap);
    }
}

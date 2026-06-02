use alloc::vec::Vec;
use sel4_sys::{
    seL4_BootInfo, seL4_Error, seL4_Word, seL4_CPtr,
};

const SE_L4_UNTYPED_RETYPE: seL4_Word = 1;
const SE_L4_CAP_INIT_THREAD_CNODE: seL4_CPtr = 2;

const MAX_CSPACE_SLOTS: usize = 4096;
const BITMAP_SIZE: usize = MAX_CSPACE_SLOTS / 64;
const MAX_UNTYPED_CAPS: usize = 256;
const MIN_REUSABLE_FRAGMENT_BITS: u8 = 12; // 4K
const FRAGMENTATION_GUARD_GAP_BITS: u8 = 6; // avoid burning very large untyped for tiny objects

pub const MAX_REGION_PAGES: usize = 16;

/// Represents a contiguous virtual memory region backed by 4K frame capabilities.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub frame_caps: [seL4_CPtr; MAX_REGION_PAGES],
    pub page_count: usize,
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

    pub fn free_slots(&self) -> usize {
        let (_, _, free) = self.stats();
        free
    }

    pub fn can_allocate_with_reserve(&self, needed: usize, reserve: usize) -> bool {
        self.free_slots() >= needed.saturating_add(reserve)
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
    oom_events: usize,
    last_oom_size_bits: seL4_Word,
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
            oom_events: 0,
            last_oom_size_bits: 0,
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
        log_debug!(libnova::log::DOM_ALLOC, "[Alloc] Untyped memory info:");
        let list_ptr = boot_info.untypedList.as_ptr();
        log_debug!(libnova::log::DOM_ALLOC, "[Alloc] UntypedList Addr: {:p}", list_ptr);
        
        let start = self.untyped_start;
        let end = self.untyped_end;
        // let len = end - start;
        
        log_debug!(libnova::log::DOM_ALLOC, "[Alloc] Scanning untyped slots {} to {}", start, end);
        
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

    pub fn oom_stats(&self) -> (usize, seL4_Word) {
        (self.oom_events, self.last_oom_size_bits)
    }

    pub fn free_ram_bytes(&self, boot_info: &seL4_BootInfo) -> u64 {
        let (_, _, used, total, _) = self.stats(boot_info);
        total.saturating_sub(used)
    }

    pub fn fragmentation_bytes(&self, boot_info: &seL4_BootInfo) -> u64 {
        let max = core::cmp::min(
            self.untyped_end.saturating_sub(self.untyped_start),
            core::cmp::min(boot_info.untypedList.len(), MAX_UNTYPED_CAPS),
        );
        let reusable_threshold = 1usize << MIN_REUSABLE_FRAGMENT_BITS;
        let mut stranded = 0u64;

        for idx in 0..max {
            let desc = &boot_info.untypedList[idx];
            if desc.isDevice != 0 {
                continue;
            }
            let cap_size = match 1usize.checked_shl(desc.sizeBits as u32) {
                Some(v) => v,
                None => continue,
            };
            let used = self.usage[idx];
            if used >= cap_size {
                continue;
            }
            let remaining = cap_size - used;
            if remaining > 0 && remaining < reusable_threshold {
                stranded = stranded.saturating_add(remaining as u64);
            }
        }

        stranded
    }

    fn select_candidate(
        &self,
        boot_info: &seL4_BootInfo,
        size_bits: seL4_Word,
        avoid_large_gaps: bool,
    ) -> Option<usize> {
        let count = self.untyped_end.saturating_sub(self.untyped_start);
        let mut best_idx: Option<usize> = None;
        let mut best_gap = u8::MAX;
        let mut best_tail_penalty = u8::MAX;
        let mut best_remaining = usize::MAX;

        for idx in 0..count {
            if idx >= boot_info.untypedList.len() || idx >= MAX_UNTYPED_CAPS {
                break;
            }

            let desc = &boot_info.untypedList[idx];
            if desc.isDevice != 0 || (desc.sizeBits as seL4_Word) < size_bits {
                continue;
            }

            let gap = desc.sizeBits.saturating_sub(size_bits as u8);
            if avoid_large_gaps && gap > FRAGMENTATION_GUARD_GAP_BITS {
                continue;
            }

            let alignment = match 1usize.checked_shl(size_bits as u32) {
                Some(v) => v,
                None => continue,
            };
            let cap_size = match 1usize.checked_shl(desc.sizeBits as u32) {
                Some(v) => v,
                None => continue,
            };

            let current_usage = self.usage[idx];
            let start_offset = (current_usage + alignment - 1) & !(alignment - 1);
            let end_offset = match start_offset.checked_add(alignment) {
                Some(v) => v,
                None => continue,
            };
            if end_offset > cap_size {
                continue;
            }

            let remaining = cap_size - end_offset;
            let tail_penalty = if remaining > 0 && remaining < (1usize << MIN_REUSABLE_FRAGMENT_BITS)
            {
                1
            } else {
                0
            };

            let better = best_idx.is_none()
                || gap < best_gap
                || (gap == best_gap && tail_penalty < best_tail_penalty)
                || (gap == best_gap
                    && tail_penalty == best_tail_penalty
                    && remaining < best_remaining);

            if better {
                best_idx = Some(idx);
                best_gap = gap;
                best_tail_penalty = tail_penalty;
                best_remaining = remaining;
            }
        }

        best_idx
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

        // Fragmentation-aware allocation strategy:
        // 1) avoid consuming very large untyped for small objects when possible
        // 2) among candidates, prefer minimal size gap and minimal stranded tail
        let best_idx = self
            .select_candidate(boot_info, size_bits, true)
            .or_else(|| self.select_candidate(boot_info, size_bits, false));

        // 2. Try to allocate from the best candidate
        if let Some(idx) = best_idx {
            let untyped_cptr = self.untyped_start + idx;
            let desc = &boot_info.untypedList[idx];
            
            // Calculate offset again for the chosen block
            let current_usage = self.usage[idx];
            let alignment = 1usize << size_bits;
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

            // Best-effort warning when this allocation leaves a tiny tail fragment.
            let cap_size = 1usize.checked_shl(desc.sizeBits as u32).unwrap_or(0);
            let remaining = cap_size.saturating_sub(self.usage[idx]);
            if remaining > 0 && remaining < (1usize << MIN_REUSABLE_FRAGMENT_BITS) {
                println!(
                    "[Alloc] Warning: untyped idx {} left tiny fragment {} bytes",
                    idx, remaining
                );
            }
            
            return Ok(dest_slot);
        }

        self.oom_events = self.oom_events.saturating_add(1);
        self.last_oom_size_bits = size_bits;
        let free_ram = self.free_ram_bytes(boot_info);
        let fragmented = self.fragmentation_bytes(boot_info);
        println!(
            "[Alloc] OOM: no suitable untyped for size_bits {} (free_ram={} bytes, fragmented_tail={} bytes, oom_events={})",
            size_bits, free_ram, fragmented, self.oom_events
        );
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
    ) -> Result<(seL4_CPtr, bool), seL4_Error> {
        // Recycle frames if available
        if let Some(cap) = self.free_frames.pop() {
           return Ok((cap, true));
        }
        // No free frames, allocate new one
        // 4K Frame = size_bits 12, type = seL4_X86_4K (value 8)
        let cap = allocator.allocate(boot_info, 8, 12, slots)?;
        Ok((cap, false))
    }

    pub fn free(&mut self, frame_cap: seL4_CPtr) {
        self.free_frames.push(frame_cap);
    }

    pub fn free_count(&self) -> usize {
        self.free_frames.len()
    }
}

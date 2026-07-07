use crate::memory::{MemoryRegion, ObjectAllocator, SlotAllocator, MAX_REGION_PAGES};
use crate::process::Process;
use libnova::cap::{cap_rights_new, CNode};
use sel4_sys::{seL4_CPtr, seL4_Error, seL4_Word};

const MAX_SHARED_REGIONS: usize = 32;
const MAX_SHARED_MAPPINGS: usize = 128;
const PAGE_SIZE: usize = 4096;

#[derive(Clone, Copy)]
struct SharedMapping {
    pid: usize,
    key: usize,
    base_vaddr: usize,
    page_count: usize,
    in_use: bool,
}

impl SharedMapping {
    const fn empty() -> Self {
        SharedMapping {
            pid: 0,
            key: 0,
            base_vaddr: 0,
            page_count: 0,
            in_use: false,
        }
    }
}

pub struct SharedMemoryManager {
    regions: [Option<MemoryRegion>; MAX_SHARED_REGIONS],
    ref_counts: [usize; MAX_SHARED_REGIONS],
    mappings: [SharedMapping; MAX_SHARED_MAPPINGS],
}

impl SharedMemoryManager {
    pub const fn new() -> Self {
        SharedMemoryManager {
            regions: [None; MAX_SHARED_REGIONS],
            ref_counts: [0; MAX_SHARED_REGIONS],
            mappings: [SharedMapping::empty(); MAX_SHARED_MAPPINGS],
        }
    }

    fn rollback_mapped_pages(
        process: &mut Process,
        slot_allocator: &mut SlotAllocator,
        root_node: &CNode,
        mapped_caps: &[seL4_CPtr; MAX_REGION_PAGES],
        mapped_count: usize,
    ) {
        let mut i = 0;
        while i < mapped_count {
            let cap = mapped_caps[i];
            let _ = process.vspace.unmap_page(cap);
            let _ = root_node.delete(cap);
            slot_allocator.free(cap);
            i += 1;
        }
    }

    fn has_external_frame_at(process: &Process, vaddr: usize) -> bool {
        let mut i = 0;
        while i < process.mapped_frames.len() {
            let frame = process.mapped_frames[i];
            if frame.vaddr == vaddr && !frame.reclaim_to_frame_allocator {
                return true;
            }
            i += 1;
        }
        false
    }

    fn take_external_frame_cap(process: &mut Process, vaddr: usize) -> Option<seL4_CPtr> {
        let mut i = 0;
        while i < process.mapped_frames.len() {
            let frame = process.mapped_frames[i];
            if frame.vaddr == vaddr && !frame.reclaim_to_frame_allocator {
                process.mapped_frames.swap_remove(i);
                return Some(frame.cap);
            }
            i += 1;
        }
        None
    }

    fn register_mapping(
        &mut self,
        pid: usize,
        key: usize,
        base_vaddr: usize,
        page_count: usize,
    ) -> Result<(), seL4_Error> {
        let mut i = 0;
        while i < self.mappings.len() {
            if !self.mappings[i].in_use {
                self.mappings[i] = SharedMapping {
                    pid,
                    key,
                    base_vaddr,
                    page_count,
                    in_use: true,
                };
                self.ref_counts[key] += 1;
                return Ok(());
            }
            i += 1;
        }
        Err(seL4_Error::seL4_NotEnoughMemory)
    }

    fn release_region(
        &mut self,
        key: usize,
        slot_allocator: &mut SlotAllocator,
    ) -> Result<(), seL4_Error> {
        if key >= self.regions.len() || self.regions[key].is_none() {
            return Err(seL4_Error::seL4_FailedLookup);
        }

        let region = self.regions[key].unwrap();
        let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
        let root_node = CNode::new(root_cnode, sel4_sys::seL4_WordBits as u8);

        let mut first_error = seL4_Error::seL4_NoError;
        let mut i = 0;
        while i < region.page_count {
            let cap = region.frame_caps[i];
            match root_node.delete(cap) {
                Ok(_) => {
                    slot_allocator.free(cap);
                }
                Err(e) => {
                    if first_error == seL4_Error::seL4_NoError {
                        let _ = e;
                        first_error = seL4_Error::seL4_DeleteFirst;
                    }
                }
            }
            i += 1;
        }

        self.regions[key] = None;
        self.ref_counts[key] = 0;

        if first_error == seL4_Error::seL4_NoError {
            Ok(())
        } else {
            Err(first_error)
        }
    }

    pub fn destroy_unmapped_region(
        &mut self,
        key: usize,
        slot_allocator: &mut SlotAllocator,
    ) -> Result<(), seL4_Error> {
        if key >= self.regions.len() || self.regions[key].is_none() {
            return Err(seL4_Error::seL4_FailedLookup);
        }
        if self.ref_counts[key] != 0 {
            return Err(seL4_Error::seL4_DeleteFirst);
        }
        self.release_region(key, slot_allocator)
    }

    pub fn detach_process(
        &mut self,
        pid: usize,
        slot_allocator: &mut SlotAllocator,
    ) -> Result<(), seL4_Error> {
        let mut touched = [false; MAX_SHARED_REGIONS];
        let mut i = 0;
        while i < self.mappings.len() {
            let m = self.mappings[i];
            if m.in_use && m.pid == pid {
                self.mappings[i].in_use = false;
                if self.ref_counts[m.key] > 0 {
                    self.ref_counts[m.key] -= 1;
                }
                touched[m.key] = true;
            }
            i += 1;
        }

        let mut first_error = seL4_Error::seL4_NoError;
        let mut key = 0;
        while key < MAX_SHARED_REGIONS {
            if touched[key] && self.ref_counts[key] == 0 && self.regions[key].is_some() {
                if let Err(e) = self.release_region(key, slot_allocator) {
                    if first_error == seL4_Error::seL4_NoError {
                        first_error = e;
                    }
                }
            }
            key += 1;
        }

        if first_error == seL4_Error::seL4_NoError {
            Ok(())
        } else {
            Err(first_error)
        }
    }

    pub fn create_shared_region<A: ObjectAllocator>(
        &mut self,
        allocator: &mut A,
        slot_allocator: &mut SlotAllocator,
        boot_info: &sel4_sys::seL4_BootInfo,
        size: usize,
    ) -> Result<usize, seL4_Error> {
        if size == 0 {
            return Err(seL4_Error::seL4_InvalidArgument);
        }
        let page_count = (size + (PAGE_SIZE - 1)) / PAGE_SIZE;
        if page_count > MAX_REGION_PAGES {
            return Err(seL4_Error::seL4_RangeError);
        }

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

        const SE_L4_X86_4K: seL4_Word = 8;
        let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
        let root_node = CNode::new(root_cnode, sel4_sys::seL4_WordBits as u8);

        let mut region = MemoryRegion {
            frame_caps: [0; MAX_REGION_PAGES],
            page_count: 0,
        };

        let mut i = 0;
        while i < page_count {
            match allocator.allocate(
                boot_info,
                SE_L4_X86_4K,
                sel4_sys::seL4_PageBits.into(),
                slot_allocator,
            ) {
                Ok(frame_cap) => {
                    region.frame_caps[i] = frame_cap;
                    region.page_count += 1;
                }
                Err(e) => {
                    let mut j = 0;
                    while j < region.page_count {
                        let cap = region.frame_caps[j];
                        let _ = root_node.delete(cap);
                        slot_allocator.free(cap);
                        j += 1;
                    }
                    return Err(e);
                }
            }
            i += 1;
        }

        self.regions[idx] = Some(region);
        self.ref_counts[idx] = 0;
        Ok(idx)
    }

    pub fn map_shared_region<A: ObjectAllocator>(
        &mut self,
        key: usize,
        pid: usize,
        process: &mut Process,
        allocator: &mut A,
        slot_allocator: &mut SlotAllocator,
        boot_info: &sel4_sys::seL4_BootInfo,
        vaddr: usize,
    ) -> Result<(), seL4_Error> {
        if key >= self.regions.len() || self.regions[key].is_none() {
            return Err(seL4_Error::seL4_FailedLookup);
        }
        if vaddr & 0xFFF != 0 {
            return Err(seL4_Error::seL4_AlignmentError);
        }

        let region = self.regions[key].unwrap();
        let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
        let root_node = CNode::new(root_cnode, sel4_sys::seL4_WordBits as u8);
        let copy_rights = cap_rights_new(false, false, true, true);
        let map_rights = cap_rights_new(false, true, true, true);
        let attr = sel4_sys::seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes;

        let mut mapped_caps = [0; MAX_REGION_PAGES];
        let mut mapped_count = 0usize;

        let mut i = 0;
        while i < region.page_count {
            let page_vaddr = match vaddr.checked_add(i * PAGE_SIZE) {
                Some(addr) => addr,
                None => {
                    Self::rollback_mapped_pages(
                        process,
                        slot_allocator,
                        &root_node,
                        &mapped_caps,
                        mapped_count,
                    );
                    return Err(seL4_Error::seL4_RangeError);
                }
            };

            let copy_cap_slot = match slot_allocator.alloc() {
                Ok(slot) => slot,
                Err(e) => {
                    Self::rollback_mapped_pages(
                        process,
                        slot_allocator,
                        &root_node,
                        &mapped_caps,
                        mapped_count,
                    );
                    return Err(e);
                }
            };

            if root_node
                .copy(copy_cap_slot, &root_node, region.frame_caps[i], copy_rights)
                .is_err()
            {
                slot_allocator.free(copy_cap_slot);
                Self::rollback_mapped_pages(
                    process,
                    slot_allocator,
                    &root_node,
                    &mapped_caps,
                    mapped_count,
                );
                return Err(seL4_Error::seL4_DeleteFirst);
            }

            match process.vspace.map_page(
                allocator,
                slot_allocator,
                boot_info,
                copy_cap_slot,
                page_vaddr,
                map_rights,
                attr,
            ) {
                Ok(_) => {
                    mapped_caps[mapped_count] = copy_cap_slot;
                    mapped_count += 1;
                }
                Err(e) => {
                    let _ = root_node.delete(copy_cap_slot);
                    slot_allocator.free(copy_cap_slot);
                    Self::rollback_mapped_pages(
                        process,
                        slot_allocator,
                        &root_node,
                        &mapped_caps,
                        mapped_count,
                    );
                    return Err(e);
                }
            }

            i += 1;
        }

        if let Err(e) = self.register_mapping(pid, key, vaddr, region.page_count) {
            Self::rollback_mapped_pages(
                process,
                slot_allocator,
                &root_node,
                &mapped_caps,
                mapped_count,
            );
            return Err(e);
        }

        i = 0;
        while i < mapped_count {
            let page_vaddr = vaddr + (i * PAGE_SIZE);
            let _ = process.track_external_frame(mapped_caps[i], page_vaddr, map_rights, attr);
            i += 1;
        }

        Ok(())
    }

    pub fn unmap_shared_region(
        &mut self,
        pid: usize,
        process: &mut Process,
        slot_allocator: &mut SlotAllocator,
        vaddr: usize,
        size: usize,
    ) -> Result<(), seL4_Error> {
        if size == 0 {
            return Err(seL4_Error::seL4_InvalidArgument);
        }
        if vaddr & 0xFFF != 0 {
            return Err(seL4_Error::seL4_AlignmentError);
        }

        let aligned_size = (size + (PAGE_SIZE - 1)) & !(PAGE_SIZE - 1);
        let page_count = aligned_size / PAGE_SIZE;

        let mut mapping_idx = None;
        let mut i = 0;
        while i < self.mappings.len() {
            let m = self.mappings[i];
            if m.in_use && m.pid == pid && m.base_vaddr == vaddr {
                mapping_idx = Some(i);
                break;
            }
            i += 1;
        }

        let idx = match mapping_idx {
            Some(v) => v,
            None => return Err(seL4_Error::seL4_FailedLookup),
        };

        let mapping = self.mappings[idx];
        if mapping.page_count != page_count {
            return Err(seL4_Error::seL4_RangeError);
        }

        i = 0;
        while i < mapping.page_count {
            let page_vaddr = vaddr + (i * PAGE_SIZE);
            if !Self::has_external_frame_at(process, page_vaddr) {
                return Err(seL4_Error::seL4_FailedLookup);
            }
            i += 1;
        }

        let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as seL4_CPtr;
        let root_node = CNode::new(root_cnode, sel4_sys::seL4_WordBits as u8);
        let mut first_error = seL4_Error::seL4_NoError;

        i = 0;
        while i < mapping.page_count {
            let page_vaddr = vaddr + (i * PAGE_SIZE);
            if let Some(cap) = Self::take_external_frame_cap(process, page_vaddr) {
                if let Err(e) = process.vspace.unmap_page(cap) {
                    if first_error == seL4_Error::seL4_NoError {
                        first_error = e;
                    }
                }
                if let Err(e) = root_node.delete(cap) {
                    if first_error == seL4_Error::seL4_NoError {
                        let _ = e;
                        first_error = seL4_Error::seL4_DeleteFirst;
                    }
                } else {
                    slot_allocator.free(cap);
                }
            }
            i += 1;
        }

        self.mappings[idx].in_use = false;
        if self.ref_counts[mapping.key] > 0 {
            self.ref_counts[mapping.key] -= 1;
        }

        if self.ref_counts[mapping.key] == 0 {
            if let Err(e) = self.release_region(mapping.key, slot_allocator) {
                if first_error == seL4_Error::seL4_NoError {
                    first_error = e;
                }
            }
        }

        if first_error == seL4_Error::seL4_NoError {
            Ok(())
        } else {
            Err(first_error)
        }
    }
}

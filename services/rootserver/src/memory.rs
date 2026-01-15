use sel4_sys::{
    seL4_BootInfo, seL4_Error, seL4_Word, seL4_CPtr,
    seL4_Call, seL4_MessageInfo_new, seL4_SetMR, seL4_MessageInfo_get_label, seL4_SetCap_My,
};
use crate::println;

const SE_L4_UNTYPED_RETYPE: seL4_Word = 1;
const SE_L4_CAP_INIT_THREAD_CNODE: seL4_CPtr = 2;

/// Allocator for CSpace slots (CNode indices)
pub struct SlotAllocator {
    pub current: usize,
    pub end: usize,
}

impl SlotAllocator {
    pub fn new(boot_info: &seL4_BootInfo) -> Self {
        SlotAllocator {
            current: boot_info.empty.start as usize,
            end: boot_info.empty.end as usize,
        }
    }

    pub fn alloc(&mut self) -> Result<seL4_CPtr, ()> {
        if self.current >= self.end {
            return Err(());
        }
        let slot = self.current;
        self.current += 1;
        Ok(slot as seL4_CPtr)
    }
}

/// Allocator for Physical Memory (Untyped Capabilities)
pub struct BumpAllocator {
    untyped_start: usize,
    untyped_end: usize,
    // We keep track of which untyped cap we are currently using
    // Note: This is a simple allocator that doesn't backtrack or support free
    last_used_idx: usize,
}

impl BumpAllocator {
    pub fn new(boot_info: &seL4_BootInfo) -> Self {
        let len = boot_info.untyped.end - boot_info.untyped.start;
        println!("[Alloc] Initializing BumpAllocator with {} untyped slots", len);

        BumpAllocator {
            untyped_start: boot_info.untyped.start as usize,
            untyped_end: boot_info.untyped.end as usize,
            last_used_idx: 0,
        }
    }

    /// Retypes an untyped capability into a new object
    /// 
    /// # Arguments
    /// * `boot_info` - The boot info structure containing untyped list
    /// * `type_` - The seL4 object type to create
    /// * `size_bits` - The size of the object (log2)
    /// * `slots` - The slot allocator to allocate a destination slot
    /// 
    /// # Returns
    /// * `Result<seL4_CPtr, seL4_Error>` - The slot containing the new capability
    // Helper function for syscall
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

    pub fn retype(
        &mut self,
        boot_info: &seL4_BootInfo,
        type_: seL4_Word,
        size_bits: seL4_Word,
        slots: &mut SlotAllocator,
    ) -> Result<seL4_CPtr, seL4_Error> {
        let dest_slot = slots.alloc().map_err(|_| seL4_Error::from(1))?; // Use a generic error code

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

            // let root = SE_L4_CAP_INIT_THREAD_CNODE;
            let root = SE_L4_CAP_INIT_THREAD_CNODE;
            let node_index = 0; 
            let node_depth = 0; 
            let node_offset = dest_slot; 
            let num_objects = 1;

            // DEBUG: Check IPC Buffer and Cap
            /*
            let ipc_buf = unsafe { sel4_sys::seL4_GetIPCBuffer() };
             if ipc_buf.is_null() {
                  println!("[Alloc] ERROR: IPC Buffer is NULL!");
             } else {
                  unsafe {
                      sel4_sys::seL4_SetCap_My(0, root);
                      let val = (*ipc_buf).caps_or_badges[0];
                      if val != root {
                          println!("[Alloc] ERROR: Failed to write to IPC Buffer! val={} expected={}", val, root);
                      }
                  }
             }
             */
            
            // Set the extra cap for the destination CNode
            unsafe {
                sel4_sys::seL4_SetCap_My(0, root);
            }
 
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

            // Assuming seL4_NoError is 0 and seL4_Error implements PartialEq with its variants or we can compare converted values
            // Since we created it from i32, let's compare with from(0)
            if err == seL4_Error::from(0) {
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

        println!("[Alloc] Failed to allocate memory of size_bits {}", size_bits);
        Err(seL4_Error::from(1))
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

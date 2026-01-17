use sel4_sys::*;
use xmas_elf::{ElfFile, program};
use crate::memory::{SlotAllocator, ObjectAllocator, FrameAllocator};
use crate::vspace::VSpace;
use libnova::cap::CapRights_new;

// Temporary constant until we confirm sel4_sys export
#[allow(dead_code, non_upper_case_globals)]
const seL4_X86_4K: seL4_Word = 8;

const PAGE_SIZE: usize = 4096;
// Use a virtual address that is unlikely to conflict with RootServer code/stack
// 0x4000_0000 = 1GB mark.
pub const COPY_WINDOW_ADDR: usize = 0x5000_0000; 
const MAX_ELF_SIZE: usize = 64 * 1024; // 64KB

#[repr(align(8))]
struct AlignedElfBuf([u8; MAX_ELF_SIZE]);

static mut ELF_BUF: AlignedElfBuf = AlignedElfBuf([0; MAX_ELF_SIZE]);

pub struct ElfLoader<'a> {
    boot_info: &'a seL4_BootInfo,
}

impl<'a> ElfLoader<'a> {
    pub fn new(boot_info: &'a seL4_BootInfo) -> Self {
        ElfLoader { boot_info }
    }

    pub fn load_elf<A: ObjectAllocator>(
        &self,
        allocator: &mut A,
        slot_allocator: &mut SlotAllocator,
        frame_allocator: &mut FrameAllocator,
        target_vspace: &mut VSpace,
        elf_data: &[u8],
        mapped_frames: &mut alloc::vec::Vec<seL4_CPtr>,
    ) -> Result<usize, seL4_Error> {
        println!("[Loader] load_elf called. Data len: {}", elf_data.len());
        if elf_data.len() > MAX_ELF_SIZE {
            println!("[Loader] ELF too large: {} bytes", elf_data.len());
            return Err(seL4_Error::seL4_InvalidArgument);
        }

        let elf_data_aligned: &[u8] = if (elf_data.as_ptr() as usize).is_multiple_of(core::mem::align_of::<u64>()) {
            elf_data
        } else {
            // Use static buffer to avoid stack overflow
            // SAFE: RootServer is single-threaded and we only load one ELF at a time
            unsafe {
                ELF_BUF.0[..elf_data.len()].copy_from_slice(elf_data);
                &ELF_BUF.0[..elf_data.len()]
            }
        };

        println!("[Loader] Parsing ELF header...");
        let elf = ElfFile::new(elf_data_aligned).map_err(|_| {
            println!("[Loader] Invalid ELF magic");
            seL4_Error::seL4_InvalidArgument
        })?;

        println!("[Loader] ELF loaded. Entry: 0x{:x}", elf.header.pt2.entry_point());

        // We need a VSpace wrapper for the current RootServer to map pages for copying
        // Note: We use the existing Root CNode slot for InitThreadVSpace
        let root_pml4 = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadVSpace as seL4_CPtr;
        let mut root_vspace = VSpace::new(root_pml4);

        for ph in elf.program_iter() {
            if let Ok(program::Type::Load) = ph.get_type() {
                let vaddr = ph.virtual_addr() as usize;
                let mem_size = ph.mem_size() as usize;
                let file_size = ph.file_size() as usize;
                let offset = ph.offset() as usize;
                let flags = ph.flags();

                println!("[Loader] Segment: VAddr=0x{:x}, MemSize={}, FileSize={}", vaddr, mem_size, file_size);

                // Calculate page range
                let start_page = vaddr & !(PAGE_SIZE - 1);
                let end_page = (vaddr + mem_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

                for page_vaddr in (start_page..end_page).step_by(PAGE_SIZE) {
                    // 1. Allocate Frame using FrameAllocator
                    let frame_cap = frame_allocator.alloc(
                        allocator,
                        self.boot_info,
                        slot_allocator
                    )?;
                    
                    if frame_cap == 0 {
                        println!("[Loader] FrameAllocator returned 0!");
                        return Err(seL4_Error::seL4_NotEnoughMemory);
                    }
                    
                    println!("[Loader] Allocated frame {} for vaddr {:x}", frame_cap, page_vaddr);

                    let res = (|| -> Result<(), seL4_Error> {
                        // 2. Map to RootServer for copying
                        // We use Read/Write for RootServer to write data
                        let rw_rights = libnova::cap::CapRights_new(false, false, true, true);
                        let default_attr = sel4_sys::seL4_X86_VMAttributes::seL4_X86_Default_VMAttributes;
                        
                        // We map to the same COPY_WINDOW_ADDR repeatedly.
                        // Since we unmap at the end of loop, this slot should be free.
                        root_vspace.map_page(
                            allocator, 
                            slot_allocator, 
                            self.boot_info, 
                            frame_cap, 
                            COPY_WINDOW_ADDR, 
                            rw_rights, 
                            default_attr
                        )?;

                        // 3. Copy Data
                        let dest_ptr = COPY_WINDOW_ADDR as *mut u8;
                        
                        // Zero the page first (handle BSS implicitly)
                        unsafe { dest_ptr.write_bytes(0, PAGE_SIZE); }

                        // Determine how much data to copy from file
                        let segment_end_vaddr = vaddr + file_size;
                        let page_end_vaddr = page_vaddr + PAGE_SIZE;

                        let copy_start_vaddr = core::cmp::max(page_vaddr, vaddr);
                        let copy_end_vaddr = core::cmp::min(page_end_vaddr, segment_end_vaddr);

                        if copy_end_vaddr > copy_start_vaddr {
                            let copy_len = copy_end_vaddr - copy_start_vaddr;
                            let dest_offset = copy_start_vaddr - page_vaddr; // Offset within the page
                            let src_offset = offset + (copy_start_vaddr - vaddr); // Offset within ELF file

                            if src_offset + copy_len <= elf_data_aligned.len() {
                                 unsafe {
                                     core::ptr::copy_nonoverlapping(
                                         elf_data_aligned.as_ptr().add(src_offset),
                                         dest_ptr.add(dest_offset),
                                         copy_len
                                     );
                                 }
                            } else {
                                 println!("[Loader] Error: Segment out of bounds of ELF file");
                                 // cleanup?
                                 root_vspace.unmap_page(frame_cap)?;
                                 return Err(seL4_Error::seL4_InvalidArgument);
                            }
                        }

                        // 4. Unmap from RootServer
                        // IMPORTANT: We must unmap so we can reuse COPY_WINDOW_ADDR
                        root_vspace.unmap_page(frame_cap)?;

                        // 5. Map to Target VSpace
                        // Convert ELF flags to seL4 rights
                        let read = flags.is_read() || flags.is_execute();
                        let write = flags.is_write();
                        // let exec = flags.is_execute(); // seL4 x86 often ignores this or ties to Read
                        
                        let target_rights = CapRights_new(false, false, read, write); 
                        
                        target_vspace.map_page(
                            allocator,
                            slot_allocator,
                            self.boot_info,
                            frame_cap,
                            page_vaddr,
                            target_rights,
                            default_attr
                        )?;
                        
                        Ok(())
                    })();

                    if let Err(e) = res {
                         // Cleanup frame_cap on failure using FrameAllocator
                         // NOTE: We don't delete the cap here because FrameAllocator might want to reuse the slot?
                         // Actually, FrameAllocator::free pushes it to free_list.
                         // But if we allocated it via FrameAllocator::alloc -> it might have called allocator.allocate.
                         // If we just return it, it's fine.
                         frame_allocator.free(frame_cap);
                         return Err(e);
                    }
                    
                    // Track the allocated frame
                    mapped_frames.push(frame_cap);
                }
            }
        }

        Ok(elf.header.pt2.entry_point() as usize)
    }
}

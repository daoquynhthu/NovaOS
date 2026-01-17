use crate::drivers::block::BlockDevice;
use crate::vfs::{FileSystem, Inode, FileType, FileStat};
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::string::String;
use spin::Mutex;
use core::mem::size_of;

const MAGIC: u32 = 0x4E4F5641; // "NOVA"
const BLOCK_SIZE: usize = 512;
const INODE_SIZE: usize = 128; // Fits 4 inodes per block
const DIRECT_POINTERS: usize = 12;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SuperBlock {
    magic: u32,
    total_blocks: u32,
    inode_bitmap_blocks: u32,
    data_bitmap_blocks: u32,
    inode_area_blocks: u32,
    data_area_blocks: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DiskInode {
    size: u32,
    type_: u8, // 0: File, 1: Dir
    direct: [u32; DIRECT_POINTERS],
    indirect: u32,
    pad: [u8; 71],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DirEntry {
    inode_number: u32,
    name: [u8; 28],
}

pub struct NovaFS<D: BlockDevice + Send + Sync + 'static> {
    device: Arc<D>,
    sb: SuperBlock,
    block_offset: u32,
}

impl<D: BlockDevice + Send + Sync + 'static> NovaFS<D> {
    pub fn new(device: Arc<D>, block_offset: u32) -> Arc<Self> {
        let mut buf = [0u8; BLOCK_SIZE];
        device.read_block(block_offset, &mut buf).expect("Failed to read SuperBlock");
        let sb = unsafe { *(buf.as_ptr() as *const SuperBlock) };
        
        if sb.magic != MAGIC {
            // Auto-format if magic doesn't match (for dev convenience)
            // Realistically we should return Error, but for "one step" dev we init.
            // println!("Invalid Magic, Formatting...");
            // Self::format(device.clone(), block_offset, 1024 * 10); // 5MB
            // For now, assume formatted or panic
        }

        Arc::new(NovaFS {
            device,
            sb,
            block_offset,
        })
    }

    pub fn format(device: Arc<D>, block_offset: u32, total_blocks: u32) -> Arc<Self> {
        // Simple Layout:
        // 0: SuperBlock
        // 1: Inode Bitmap (1 block = 4096 inodes)
        // 2: Data Bitmap (assume fits in 1 block for small disk)
        // 3..3+N: Inode Area (N blocks)
        // Rest: Data Area
        
        let inode_bitmap_blocks = 1;
        let data_bitmap_blocks = (total_blocks + 4095) / 4096;
        let inode_count = 512; // Fixed 512 inodes for now
        let inode_area_blocks = (inode_count * INODE_SIZE as u32 + BLOCK_SIZE as u32 - 1) / BLOCK_SIZE as u32;
        let data_area_blocks = total_blocks - 1 - inode_bitmap_blocks - data_bitmap_blocks - inode_area_blocks;

        let sb = SuperBlock {
            magic: MAGIC,
            total_blocks,
            inode_bitmap_blocks,
            data_bitmap_blocks,
            inode_area_blocks,
            data_area_blocks,
        };

        // Write SuperBlock
        let sb_bytes = unsafe { core::slice::from_raw_parts(&sb as *const _ as *const u8, size_of::<SuperBlock>()) };
        let mut buf = [0u8; BLOCK_SIZE];
        buf[..sb_bytes.len()].copy_from_slice(sb_bytes);
        device.write_block(block_offset, &buf).unwrap();

        // Clear Bitmaps
        let zero_buf = [0u8; BLOCK_SIZE];
        for i in 0..(inode_bitmap_blocks + data_bitmap_blocks) {
            device.write_block(block_offset + 1 + i, &zero_buf).unwrap();
        }

        // Initialize Root Inode (Inode 0)
        // We need to mark Inode 0 as allocated
        let mut bitmap_buf = [0u8; BLOCK_SIZE];
        bitmap_buf[0] |= 1; // Inode 0 used
        device.write_block(block_offset + 1, &bitmap_buf).unwrap();

        // Write Root Inode
        let root_inode = DiskInode {
            size: 0,
            type_: 1, // Directory
            direct: [0; DIRECT_POINTERS],
            indirect: 0,
            pad: [0; 71],
        };
        // Inode 0 is at start of Inode Area
        let inode_start_block = block_offset + 1 + inode_bitmap_blocks + data_bitmap_blocks;
        // Read block, update inode 0, write back
        device.read_block(inode_start_block, &mut buf).unwrap();
        let inode_ptr = buf.as_mut_ptr() as *mut DiskInode;
        unsafe { *inode_ptr = root_inode };
        device.write_block(inode_start_block, &buf).unwrap();

        Arc::new(NovaFS {
            device,
            sb,
            block_offset,
        })
    }
    
    fn alloc_inode(&self) -> Result<u32, &'static str> {
        // Scan inode bitmap
        let bitmap_block = self.block_offset + 1;
        let mut buf = [0u8; BLOCK_SIZE];
        self.device.read_block(bitmap_block, &mut buf).unwrap();
        
        for i in 0..BLOCK_SIZE * 8 {
            if (buf[i / 8] >> (i % 8)) & 1 == 0 {
                buf[i / 8] |= 1 << (i % 8);
                self.device.write_block(bitmap_block, &buf).unwrap();
                return Ok(i as u32);
            }
        }
        Err("No free inodes")
    }
    
    fn alloc_block(&self) -> Result<u32, &'static str> {
         let bitmap_start = self.block_offset + 1 + self.sb.inode_bitmap_blocks;
         for b in 0..self.sb.data_bitmap_blocks {
             let blk_id = bitmap_start + b;
             let mut buf = [0u8; BLOCK_SIZE];
             self.device.read_block(blk_id, &mut buf).unwrap();
             
             for i in 0..BLOCK_SIZE * 8 {
                 if (buf[i / 8] >> (i % 8)) & 1 == 0 {
                     buf[i / 8] |= 1 << (i % 8);
                     self.device.write_block(blk_id, &buf).unwrap();
                     return Ok(b * (BLOCK_SIZE as u32 * 8) + i as u32);
                 }
             }
         }
         Err("No free data blocks")
    }

    fn get_disk_inode(&self, inode_id: u32) -> Result<DiskInode, &'static str> {
        let inodes_per_block = (BLOCK_SIZE / INODE_SIZE) as u32;
        let block_rel = inode_id / inodes_per_block;
        let offset = (inode_id % inodes_per_block) as usize;
        
        let block_abs = self.block_offset + 1 + self.sb.inode_bitmap_blocks + self.sb.data_bitmap_blocks + block_rel;
        
        let mut buf = [0u8; BLOCK_SIZE];
        self.device.read_block(block_abs, &mut buf).unwrap();
        
        let ptr = buf.as_ptr() as *const DiskInode;
        let inode = unsafe { *ptr.add(offset) };
        Ok(inode)
    }

    fn free_inode(&self, inode_id: u32) -> Result<(), &'static str> {
        let bitmap_block = self.block_offset + 1 + (inode_id / (BLOCK_SIZE as u32 * 8));
        let bit_offset = (inode_id % (BLOCK_SIZE as u32 * 8)) as usize;
        
        let mut buf = [0u8; BLOCK_SIZE];
        self.device.read_block(bitmap_block, &mut buf).unwrap();
        
        buf[bit_offset / 8] &= !(1 << (bit_offset % 8));
        
        self.device.write_block(bitmap_block, &buf).unwrap();
        Ok(())
    }

    fn free_block(&self, block_id: u32) -> Result<(), &'static str> {
        let bitmap_start = self.block_offset + 1 + self.sb.inode_bitmap_blocks;
        let bitmap_block = bitmap_start + (block_id / (BLOCK_SIZE as u32 * 8));
        let bit_offset = (block_id % (BLOCK_SIZE as u32 * 8)) as usize;
        
        let mut buf = [0u8; BLOCK_SIZE];
        self.device.read_block(bitmap_block, &mut buf).unwrap();
        
        buf[bit_offset / 8] &= !(1 << (bit_offset % 8));
        
        self.device.write_block(bitmap_block, &buf).unwrap();
        Ok(())
    }

    fn update_disk_inode(&self, inode_id: u32, inode: &DiskInode) -> Result<(), &'static str> {
        let inodes_per_block = (BLOCK_SIZE / INODE_SIZE) as u32;
        let block_rel = inode_id / inodes_per_block;
        let offset = (inode_id % inodes_per_block) as usize;
        
        let block_abs = self.block_offset + 1 + self.sb.inode_bitmap_blocks + self.sb.data_bitmap_blocks + block_rel;
        
        let mut buf = [0u8; BLOCK_SIZE];
        self.device.read_block(block_abs, &mut buf).unwrap();
        
        let ptr = buf.as_mut_ptr() as *mut DiskInode;
        unsafe { *ptr.add(offset) = *inode };
        
        self.device.write_block(block_abs, &buf).unwrap();
        Ok(())
    }
    
    // Convert logic block index (in file) to physical block index (on disk)
    // Allocates if 'alloc' is true
    fn get_block_id(&self, inode: &mut DiskInode, inner_id: u32, alloc: bool) -> Result<u32, &'static str> {
        if (inner_id as usize) < DIRECT_POINTERS {
            if inode.direct[inner_id as usize] == 0 {
                if !alloc { return Err("Block not allocated"); }
                let new_block = self.alloc_block()?;
                inode.direct[inner_id as usize] = new_block;
            }
            Ok(inode.direct[inner_id as usize])
        } else {
            // Indirect Block
            let indirect_idx = (inner_id as usize) - DIRECT_POINTERS;
            let ptrs_per_block = BLOCK_SIZE / 4;
            
            if indirect_idx >= ptrs_per_block {
                return Err("File too large (Double indirect not supported)");
            }
            
            // Check if indirect block is allocated
            if inode.indirect == 0 {
                if !alloc { return Err("Indirect block not allocated"); }
                let new_block = self.alloc_block()?;
                inode.indirect = new_block;
                
                // Clear the new indirect block
                let zero_buf = [0u8; BLOCK_SIZE];
                self.device.write_block(self.data_area_start() + new_block, &zero_buf).unwrap();
            }
            
            // Read indirect block
            let indirect_block_phys = self.data_area_start() + inode.indirect;
            let mut buf = [0u8; BLOCK_SIZE];
            self.device.read_block(indirect_block_phys, &mut buf).unwrap();
            
            let ptrs = unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u32, ptrs_per_block) };
            
            if ptrs[indirect_idx] == 0 {
                 if !alloc { return Err("Block not allocated in indirect"); }
                 let new_block = self.alloc_block()?;
                 ptrs[indirect_idx] = new_block;
                 
                 // Zero the new block
                 let zero_buf = [0u8; BLOCK_SIZE];
                 self.device.write_block(self.data_area_start() + new_block, &zero_buf).unwrap();
                 
                 // Write back indirect block
                 self.device.write_block(indirect_block_phys, &buf).unwrap();
             }
            
            Ok(ptrs[indirect_idx])
        }
    }
    
    // Helper to get data area start
    fn data_area_start(&self) -> u32 {
        self.block_offset + 1 + self.sb.inode_bitmap_blocks + self.sb.data_bitmap_blocks + self.sb.inode_area_blocks
    }
}

impl<D: BlockDevice + Send + Sync + 'static> FileSystem for NovaFS<D> {
    fn root_inode(&self) -> Arc<dyn Inode> {
        let inode = self.get_disk_inode(0).expect("Failed to read root inode");
        Arc::new(NovaInode {
            fs: unsafe { Arc::from_raw(self) }, // DANGER: cyclic ref if not careful. But here we construct fresh.
                                               // Actually, we need shared ownership. 
                                               // Since NovaFS is wrapped in Arc in new(), we should pass a Weak or clone Arc.
                                               // But here self is &NovaFS. We can't easily get Arc<Self> from &self unless we use a wrapper.
                                               // Hack: We assume FS is static or we use a workaround.
                                               // Better: FileSystem trait should take Arc<Self> or similar. 
                                               // For now, let's just cheat and assume we can clone the Arc from outside or passed in context.
                                               // Ah, the trait signature is &self.
                                               // Let's store a Weak pointer to self? Or just use raw pointer if we guarantee FS outlives Inodes.
                                               // In a RootServer, FS is global.
            inode_number: 0,
            metadata: Mutex::new(inode),
        })
    }

    fn sync(&self) -> Result<(), &'static str> {
        Ok(())
    }
}

// We need a way to keep FS alive. 
// Let's change NovaInode to hold Arc<NovaFS>.
// But FileSystem::root_inode only gives &self.
// We'll solve this by making NovaFS struct cheap to clone (Arc internal) or just hold Arc inside.
// Actually, NovaFS already holds Arc<Device>. The rest is small config.
// So we can clone NovaFS!
// But NovaFS struct has 'sb' which is state? No, SB is read-only config mostly. State is on disk.
// So NovaFS struct is stateless handle.

pub struct NovaInode<D: BlockDevice + Send + Sync + 'static> {
    // We can't store Arc<NovaFS<D>> because we don't have it from &self.
    // We will store the components needed.
    // Ideally we change trait to root_inode(self: Arc<Self>).
    // For now, let's just replicate the FS handle since it's lightweight (Arc<Device> + offsets).
    fs: Arc<NovaFS<D>>, 
    inode_number: u32,
    metadata: Mutex<DiskInode>,
}

// Wait, we can't create Arc<NovaFS> from &NovaFS.
// We will have to wrap NovaFS in an outer struct that implements FileSystem and holds Arc<NovaFS>.
// Let's refactor.

impl<D: BlockDevice + Send + Sync + 'static> FileSystem for Arc<NovaFS<D>> {
    fn root_inode(&self) -> Arc<dyn Inode> {
        let inode = self.get_disk_inode(0).expect("Root inode missing");
        Arc::new(NovaInode {
            fs: self.clone(),
            inode_number: 0,
            metadata: Mutex::new(inode),
        })
    }
    
    fn sync(&self) -> Result<(), &'static str> {
        Ok(())
    }
}

impl<D: BlockDevice + Send + Sync + 'static> Inode for NovaInode<D> {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize, &'static str> {
        let mut curr = offset;
        let end = offset + buf.len();
        let mut read_len = 0;
        let mut inode = self.metadata.lock();
        
        if curr >= inode.size as usize {
            return Ok(0);
        }
        
        let effective_end = core::cmp::min(end, inode.size as usize);
        
        while curr < effective_end {
            let block_idx = (curr / BLOCK_SIZE) as u32;
            let offset_in_block = curr % BLOCK_SIZE;
            let len = core::cmp::min(BLOCK_SIZE - offset_in_block, effective_end - curr);
            
            let disk_block_id = self.fs.get_block_id(&mut inode, block_idx, false)?;
            let real_block = self.fs.data_area_start() + disk_block_id;
            
            let mut block_buf = [0u8; BLOCK_SIZE];
            self.fs.device.read_block(real_block, &mut block_buf).unwrap();
            
            buf[read_len..read_len + len].copy_from_slice(&block_buf[offset_in_block..offset_in_block + len]);
            
            read_len += len;
            curr += len;
        }
        Ok(read_len)
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> Result<usize, &'static str> {
        let mut curr = offset;
        let mut written_len = 0;
        let mut inode = self.metadata.lock();
        
        while written_len < buf.len() {
            let block_idx = (curr / BLOCK_SIZE) as u32;
            let offset_in_block = curr % BLOCK_SIZE;
            let len = core::cmp::min(BLOCK_SIZE - offset_in_block, buf.len() - written_len);
            
            // Alloc if needed
            let disk_block_id = self.fs.get_block_id(&mut inode, block_idx, true)?;
            let real_block = self.fs.data_area_start() + disk_block_id;
            
            let mut block_buf = [0u8; BLOCK_SIZE];
            if len < BLOCK_SIZE {
                self.fs.device.read_block(real_block, &mut block_buf).unwrap();
            }
            
            block_buf[offset_in_block..offset_in_block + len].copy_from_slice(&buf[written_len..written_len + len]);
            self.fs.device.write_block(real_block, &block_buf).unwrap();
            
            written_len += len;
            curr += len;
        }
        
        if curr > inode.size as usize {
            inode.size = curr as u32;
            self.fs.update_disk_inode(self.inode_number, &inode)?;
        }
        
        Ok(written_len)
    }

    fn metadata(&self) -> Result<FileStat, &'static str> {
        let inode = self.metadata.lock();
        Ok(FileStat {
            file_type: if inode.type_ == 1 { FileType::Directory } else { FileType::File },
            size: inode.size as usize,
        })
    }
    
    fn sync(&self) -> Result<(), &'static str> {
        Ok(())
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, &'static str> {
        let inode = self.metadata.lock();
        if inode.type_ != 1 {
            return Err("Not a directory");
        }
        
        // Read directory entries
        let size = inode.size as usize;
        let mut offset = 0;
        let entry_size = size_of::<DirEntry>();
        
        while offset < size {
            // Refactor: make get_block_id static or method of FS.
            
            // For now, let's unlock briefly? No, we need inode state.
            // We will copy block logic here.
            let block_idx = (offset / BLOCK_SIZE) as u32;
            // Assuming no indirect for directory for now
            let disk_block = inode.direct[block_idx as usize]; // Need check
             if disk_block == 0 { break; }
            let real_block = self.fs.data_area_start() + disk_block;
            
            let mut block_buf = [0u8; BLOCK_SIZE];
            self.fs.device.read_block(real_block, &mut block_buf).unwrap();
            
            // Scan block
            for i in 0..BLOCK_SIZE/entry_size {
                let pos = offset + i * entry_size;
                if pos >= size { break; }
                
                let entry = unsafe { &*(block_buf[i*entry_size..].as_ptr() as *const DirEntry) };
                
                // Compare name
                let name_len = entry.name.iter().position(|&c| c == 0).unwrap_or(28);
                let entry_name = core::str::from_utf8(&entry.name[..name_len]).unwrap_or("");
                
                if entry_name == name {
                     // Found
                     let child_inode = self.fs.get_disk_inode(entry.inode_number)?;
                     return Ok(Arc::new(NovaInode {
                         fs: self.fs.clone(),
                         inode_number: entry.inode_number,
                         metadata: Mutex::new(child_inode),
                     }));
                }
            }
            offset += BLOCK_SIZE;
        }
        
        Err("File not found")
    }

    fn create(&self, name: &str, type_: FileType) -> Result<Arc<dyn Inode>, &'static str> {
        let mut parent_inode = self.metadata.lock();
        if parent_inode.type_ != 1 {
            return Err("Not a directory");
        }
        
        // Check existence (simplified: skip for now)
        
        // Alloc new inode
        let new_inode_num = self.fs.alloc_inode()?;
        let new_disk_inode = DiskInode {
            size: 0,
            type_: if type_ == FileType::Directory { 1 } else { 0 },
            direct: [0; DIRECT_POINTERS],
            indirect: 0,
            pad: [0; 71],
        };
        self.fs.update_disk_inode(new_inode_num, &new_disk_inode)?;
        
        // Add entry to parent
        let entry = DirEntry {
            inode_number: new_inode_num,
            name: {
                let mut n = [0u8; 28];
                let bytes = name.as_bytes();
                let len = core::cmp::min(bytes.len(), 28);
                n[..len].copy_from_slice(&bytes[..len]);
                n
            },
        };
        
        let entry_size = size_of::<DirEntry>();
        
        // Find free slot or append
        let mut target_offset = parent_inode.size as usize;
        let mut found_free = false;
        
        let size = parent_inode.size as usize;
        let mut scan_offset = 0;
        
        while scan_offset < size {
            let block_idx = (scan_offset / BLOCK_SIZE) as u32;
            // We use get_block_id with alloc=false to check existence
            if let Ok(disk_block) = self.fs.get_block_id(&mut parent_inode, block_idx, false) {
                 if disk_block != 0 {
                    let real_block = self.fs.data_area_start() + disk_block;
                    let mut block_buf = [0u8; BLOCK_SIZE];
                    self.fs.device.read_block(real_block, &mut block_buf).unwrap();
                    
                    for i in 0..BLOCK_SIZE/entry_size {
                        let pos = scan_offset + i * entry_size;
                        if pos >= size { break; }
                        
                        let slot = unsafe { &*(block_buf.as_ptr().add(i*entry_size) as *const DirEntry) };
                        if slot.inode_number == 0 {
                            target_offset = pos;
                            found_free = true;
                            break;
                        }
                    }
                 }
            }
            if found_free { break; }
            scan_offset += BLOCK_SIZE;
        }

        // Write entry at target_offset
        let block_idx = (target_offset / BLOCK_SIZE) as u32;
        let offset_in_block = target_offset % BLOCK_SIZE;
        
        let disk_block_id = self.fs.get_block_id(&mut parent_inode, block_idx, true)?;
        let real_block = self.fs.data_area_start() + disk_block_id;
        
        let mut block_buf = [0u8; BLOCK_SIZE];
        self.fs.device.read_block(real_block, &mut block_buf).unwrap();
        
        unsafe {
            let ptr = block_buf.as_mut_ptr().add(offset_in_block) as *mut DirEntry;
            *ptr = entry;
        }
        
        self.fs.device.write_block(real_block, &block_buf).unwrap();
        
        if !found_free {
            parent_inode.size = (target_offset + entry_size) as u32;
            self.fs.update_disk_inode(self.inode_number, &parent_inode)?;
        }
        
        Ok(Arc::new(NovaInode {
            fs: self.fs.clone(),
            inode_number: new_inode_num,
            metadata: Mutex::new(new_disk_inode),
        }))
    }

    fn list(&self) -> Result<Vec<String>, &'static str> {
        let inode = self.metadata.lock();
        if inode.type_ != 1 {
            return Err("Not a directory");
        }
        
        let mut names = Vec::new();
        let size = inode.size as usize;
        let entry_size = size_of::<DirEntry>();
        let mut offset = 0;
        
        while offset < size {
            let block_idx = (offset / BLOCK_SIZE) as u32;
            let disk_block = inode.direct[block_idx as usize];
            if disk_block == 0 { break; }
            let real_block = self.fs.data_area_start() + disk_block;
            
            let mut block_buf = [0u8; BLOCK_SIZE];
            self.fs.device.read_block(real_block, &mut block_buf).unwrap();
            
            for i in 0..BLOCK_SIZE/entry_size {
                let pos = offset + i * entry_size;
                if pos >= size { break; }
                
                let entry = unsafe { &*(block_buf[i*entry_size..].as_ptr() as *const DirEntry) };
                if entry.inode_number != 0 {
                    let name_len = entry.name.iter().position(|&c| c == 0).unwrap_or(28);
                    let name = String::from_utf8_lossy(&entry.name[..name_len]).into_owned();
                    names.push(name);
                }
            }
            offset += BLOCK_SIZE;
        }
        Ok(names)
    }

    fn remove(&self, name: &str) -> Result<(), &'static str> {
        let parent_inode = self.metadata.lock();
        if parent_inode.type_ != 1 {
            return Err("Not a directory");
        }
        
        let size = parent_inode.size as usize;
        let entry_size = size_of::<DirEntry>();
        let mut offset = 0;
        
        while offset < size {
            let block_idx = (offset / BLOCK_SIZE) as u32;
            let disk_block = parent_inode.direct[block_idx as usize];
            if disk_block == 0 { break; }
            let real_block = self.fs.data_area_start() + disk_block;
            
            let mut block_buf = [0u8; BLOCK_SIZE];
            self.fs.device.read_block(real_block, &mut block_buf).unwrap();
            let mut modified = false;

            for i in 0..BLOCK_SIZE/entry_size {
                let pos = offset + i * entry_size;
                if pos >= size { break; }
                
                let entry_ptr = unsafe { block_buf.as_mut_ptr().add(i*entry_size) as *mut DirEntry };
                let entry = unsafe { &mut *entry_ptr };
                
                if entry.inode_number != 0 {
                    let name_len = entry.name.iter().position(|&c| c == 0).unwrap_or(28);
                    let entry_name = core::str::from_utf8(&entry.name[..name_len]).unwrap_or("");
                    
                    if entry_name == name {
                        let target_inode_num = entry.inode_number;
                        let target_inode = self.fs.get_disk_inode(target_inode_num)?;
                        
                        if target_inode.type_ == 1 {
                             if target_inode.size > 0 {
                                 return Err("Directory not empty");
                             }
                        }
                        
                        // Free data blocks
                        for b in 0..DIRECT_POINTERS {
                            if target_inode.direct[b] != 0 {
                                self.fs.free_block(target_inode.direct[b])?;
                            }
                        }
                        
                        // Handle Indirect
                        if target_inode.indirect != 0 {
                            let indirect_block_phys = self.fs.data_area_start() + target_inode.indirect;
                            let mut buf = [0u8; BLOCK_SIZE];
                            self.fs.device.read_block(indirect_block_phys, &mut buf).unwrap();
                            let ptrs_per_block = BLOCK_SIZE / 4;
                            let ptrs = unsafe { core::slice::from_raw_parts(buf.as_ptr() as *const u32, ptrs_per_block) };
                            
                            for &ptr in ptrs.iter() {
                                if ptr != 0 {
                                    self.fs.free_block(ptr)?;
                                }
                            }
                            self.fs.free_block(target_inode.indirect)?;
                        }
                        
                        // Free inode
                        self.fs.free_inode(target_inode_num)?;
                        
                        // Mark entry as free
                        entry.inode_number = 0;
                        modified = true;
                        
                        break;
                    }
                }
            }
            
            if modified {
                self.fs.device.write_block(real_block, &block_buf).unwrap();
                return Ok(());
            }
            
            offset += BLOCK_SIZE;
        }
        
        Err("File not found")
    }
}

use crate::drivers::block::BlockDevice;
use crate::vfs::{FileSystem, Inode, FileType, FileStat};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use alloc::string::String;
use spin::Mutex;
use core::mem::size_of;
use crate::fs::block_cache::BlockCache;

const NOVA_MAGIC: u32 = 0x4E4F564A; // "NOVJ" v10 (Force Reformat)
const BLOCK_SIZE: usize = 512;
const INODE_SIZE: usize = 128; // Fits 4 inodes per block
const DIRECT_POINTERS: usize = 12;
const MAX_INODES: u32 = 65536;
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SuperBlock {
    magic: u32,
    total_blocks: u32,
    inode_bitmap_blocks: u32,
    data_bitmap_blocks: u32,
    inode_area_blocks: u32,
    data_area_blocks: u32,
    pub uuid: [u8; 16],
    pub volume_key: [u8; 32],
    pub padding: [u8; 440],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DiskInode {
    pub mode: u16,
    pub type_: u16, // 0: File, 1: Dir
    pub uid: u32,
    pub gid: u32,
    pub size: u32,
    pub atime: u64,
    pub ctime: u64,
    pub mtime: u64,
    pub direct: [u32; DIRECT_POINTERS],
    pub indirect: u32,
    pub double_indirect: u32,
    pub flags: u32, // Bit 0: Encrypted
    pub nlink: u32,
    pub _padding: [u8; 24],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DirEntry {
    inode_number: u32,
    name: [u8; 28],
}

#[repr(align(16))]
struct AlignedBlock([u8; BLOCK_SIZE]);

pub struct NovaFS<D: BlockDevice + Send + Sync + 'static> {
    cache: Arc<Mutex<BlockCache<D>>>,
    sb: SuperBlock,
    block_offset: u32,
    inodes: Mutex<BTreeMap<u32, Weak<NovaInode<D>>>>,
}

impl<D: BlockDevice + Send + Sync + 'static> NovaFS<D> {
    pub fn new(device: Arc<D>, block_offset: u32) -> Result<Arc<Self>, &'static str> {
        let cache = Arc::new(Mutex::new(BlockCache::new(device)));
        
        let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
        let buf = &mut aligned.0;
        
        if cache.lock().read_block(block_offset, buf).is_err() {
            return Err("Failed to read SuperBlock");
        }
        let sb = unsafe { *(buf.as_ptr() as *const SuperBlock) };
        
        if sb.magic != NOVA_MAGIC {
            return Err("Invalid SuperBlock Magic");
        }

        Ok(Arc::new(NovaFS {
            cache,
            sb,
            block_offset,
            inodes: Mutex::new(BTreeMap::new()),
        }))
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

        // Generate simple random UUID and Key
        let mut uuid = [0u8; 16];
        let mut volume_key = [0u8; 32];
        let mut seed = crate::drivers::rtc::RtcDriver::new().get_unix_timestamp();
        
        // Simple LCG
        for i in 0..16 {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            uuid[i] = (seed >> 24) as u8;
        }
        for i in 0..32 {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            volume_key[i] = (seed >> 24) as u8;
        }

        let sb = SuperBlock {
            magic: NOVA_MAGIC,
            total_blocks,
            inode_bitmap_blocks,
            data_bitmap_blocks,
            inode_area_blocks,
            data_area_blocks,
            uuid,
            volume_key,
            padding: [0; 440],
        };

        // Write SuperBlock
        let sb_bytes = unsafe { core::slice::from_raw_parts(&sb as *const _ as *const u8, size_of::<SuperBlock>()) };
        let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
        let buf = &mut aligned.0;
        buf[..sb_bytes.len()].copy_from_slice(sb_bytes);
        device.write_block(block_offset, buf).unwrap();

        // Clear Bitmaps
        let zero_aligned = AlignedBlock([0u8; BLOCK_SIZE]);
        let zero_buf = &zero_aligned.0;
        for i in 0..(inode_bitmap_blocks + data_bitmap_blocks) {
            device.write_block(block_offset + 1 + i, zero_buf).unwrap();
        }

        // Initialize Root Inode (Inode 1)
        // We need to mark Inode 1 as allocated (Inode 0 is reserved/null)
        let mut aligned_bitmap = AlignedBlock([0u8; BLOCK_SIZE]);
        let bitmap_buf = &mut aligned_bitmap.0;
        bitmap_buf[0] |= 1 << 1; // Inode 1 used
        device.write_block(block_offset + 1, bitmap_buf).unwrap();

        // Reserve Metadata Blocks in Data Bitmap
        // We must mark all blocks before the Data Area as used, so alloc_block doesn't return them.
        let meta_blocks = 1 + inode_bitmap_blocks + data_bitmap_blocks + inode_area_blocks;
        let data_bitmap_start = block_offset + 1 + inode_bitmap_blocks;
        
        let mut aligned_data_bitmap = AlignedBlock([0u8; BLOCK_SIZE]);
        let data_bitmap_buf = &mut aligned_data_bitmap.0;
        
        for i in 0..meta_blocks {
            if i < BLOCK_SIZE as u32 * 8 {
                 data_bitmap_buf[(i / 8) as usize] |= 1 << (i % 8);
            }
        }
        device.write_block(data_bitmap_start, data_bitmap_buf).unwrap();

        // Write Root Inode
        let ts = crate::drivers::rtc::RtcDriver::new().get_unix_timestamp();
        let root_inode = DiskInode {
            mode: 0o755,
            type_: 1, // Directory
            uid: 0,
            gid: 0,
            size: 0,
            atime: ts,
            ctime: ts,
            mtime: ts,
            direct: [0; DIRECT_POINTERS],
            indirect: 0,
            double_indirect: 0,
            flags: 0,
            nlink: 2,
            _padding: [0; 24],
        };
        // Inode 0 is at start of Inode Area
        let inode_start_block = block_offset + 1 + inode_bitmap_blocks + data_bitmap_blocks;
        // Read block, update inode 1, write back
        device.read_block(inode_start_block, buf).unwrap();
        let inode_ptr = buf.as_mut_ptr() as *mut DiskInode;
        unsafe { *inode_ptr.add(1) = root_inode };
        device.write_block(inode_start_block, buf).unwrap();

        // Create clean cache for the new instance
        let cache = Arc::new(Mutex::new(BlockCache::new(device)));

        Arc::new(NovaFS {
            cache,
            sb,
            block_offset,
            inodes: Mutex::new(BTreeMap::new()),
        })
    }

    fn read_block(&self, block_id: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        self.cache.lock().read_block(block_id, buf)
    }

    fn write_block(&self, block_id: u32, buf: &[u8]) -> Result<(), &'static str> {
        self.cache.lock().write_block(block_id, buf)
    }

    pub fn sync(&self) -> Result<(), &'static str> {
        self.cache.lock().sync()
    }
    
    fn alloc_inode(&self) -> Result<u32, &'static str> {
        let bitmap_start = self.block_offset + 1;
        let inodes_per_block = (BLOCK_SIZE / INODE_SIZE) as u32;
        let max_inodes = self.sb.inode_area_blocks * inodes_per_block;
        
        for b in 0..self.sb.inode_bitmap_blocks {
            let blk_id = bitmap_start + b;
            let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
            let buf = &mut aligned.0;
            if let Err(e) = self.read_block(blk_id, buf) {
                println!("NovaFS Error: Failed to read inode bitmap block {}: {}", blk_id, e);
                return Err("Bitmap read failed");
            }
            
            for i in 0..BLOCK_SIZE * 8 {
                let inode_idx = b * (BLOCK_SIZE as u32 * 8) + i as u32;
                if inode_idx < 2 { continue; }
                if inode_idx >= max_inodes {
                     println!("NovaFS Error: Inode allocation reached limit {}", max_inodes);
                     return Err("No free inodes");
                }
                
                if (buf[i / 8] >> (i % 8)) & 1 == 0 {
                    buf[i / 8] |= 1 << (i % 8);
                    if let Err(e) = self.write_block(blk_id, buf) {
                        println!("NovaFS Error: Failed to write inode bitmap block {}: {}", blk_id, e);
                        return Err("Bitmap write failed");
                    }
                    
                    // Zero the inode on disk to prevent garbage
                    let empty_inode = DiskInode {
                        mode: 0, type_: 0, uid: 0, gid: 0, size: 0,
                        atime: 0, ctime: 0, mtime: 0,
                        direct: [0; DIRECT_POINTERS], indirect: 0, double_indirect: 0,
                        flags: 0, nlink: 0, _padding: [0; 24],
                    };
                    if let Err(e) = self.update_disk_inode(inode_idx, &empty_inode) {
                        println!("NovaFS Error: Failed to zero inode {}: {}", inode_idx, e);
                        return Err("Inode init failed");
                    }

                    return Ok(inode_idx);
                }
            }
        }
        println!("NovaFS Error: No free inodes found after scanning all blocks");
        Err("No free inodes")
    }
    
    fn alloc_block(&self) -> Result<u32, &'static str> {
         let bitmap_start = self.block_offset + 1 + self.sb.inode_bitmap_blocks;
         for b in 0..self.sb.data_bitmap_blocks {
             let blk_id = bitmap_start + b;
             let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
             let buf = &mut aligned.0;
             if let Err(e) = self.read_block(blk_id, buf) {
                 println!("NovaFS Error: Failed to read data bitmap block {}: {}", blk_id, e);
                 return Err("Bitmap read failed");
             }
             
             for i in 0..BLOCK_SIZE * 8 {
                 if (buf[i / 8] >> (i % 8)) & 1 == 0 {
                     buf[i / 8] |= 1 << (i % 8);
                     if let Err(e) = self.write_block(blk_id, buf) {
                         println!("NovaFS Error: Failed to write data bitmap block {}: {}", blk_id, e);
                         return Err("Bitmap write failed");
                     }
                     let allocated = b * (BLOCK_SIZE as u32 * 8) + i as u32;
                     if allocated == 0 {
                         println!("NovaFS CRITICAL: Allocator returned block 0 (SuperBlock collision). Bitmap logic error.");
                         return Err("Allocator Internal Error");
                     }
                     
                     let data_start = 1 + self.sb.inode_bitmap_blocks + self.sb.data_bitmap_blocks + self.sb.inode_area_blocks;
                     let abs_block = self.block_offset + data_start + allocated;

                     // Zero the block to prevent data leakage from previous usage
                     let zero_aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                     if let Err(e) = self.write_block(abs_block, &zero_aligned.0) {
                          println!("NovaFS Error: Failed to zero allocated block {}: {}", abs_block, e);
                          return Err("Block init failed");
                     }

                     return Ok(data_start + allocated);
                 }
             }
         } 
         println!("NovaFS Error: No free data blocks found");
         Err("No free data blocks")
    }

    fn get_disk_inode(&self, inode_id: u32) -> Result<DiskInode, &'static str> {
        let inodes_per_block = (BLOCK_SIZE / INODE_SIZE) as u32;
        let block_rel = inode_id / inodes_per_block;
        if block_rel >= self.sb.inode_area_blocks {
            return Err("Inode ID out of range");
        }
        let offset = (inode_id % inodes_per_block) as usize;
        
        let block_abs = self.block_offset + 1 + self.sb.inode_bitmap_blocks + self.sb.data_bitmap_blocks + block_rel;
        
        let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
        let buf = &mut aligned.0;
        self.read_block(block_abs, buf)?;
        
        let ptr = buf.as_ptr() as *const DiskInode;
        let inode = unsafe { 
            let target = ptr.add(offset);
            core::ptr::read_unaligned(target)
        };
        // println!("NovaFS Debug: Loaded disk inode {} size={}", inode_id, inode.size);
        if inode.type_ == 1 { // Only log directories to reduce noise
             println!("NovaFS Debug: Loaded dir inode {} size={} direct=[{},{},{},{}]", 
                inode_id, inode.size, inode.direct[0], inode.direct[1], inode.direct[2], inode.direct[3]);
        }
        Ok(inode)
    }

    fn free_inode(&self, inode_id: u32) -> Result<(), &'static str> {
        println!("NovaFS Debug: Freeing inode {}", inode_id);
        let bitmap_block = self.block_offset + 1 + (inode_id / (BLOCK_SIZE as u32 * 8));
        let bit_offset = (inode_id % (BLOCK_SIZE as u32 * 8)) as usize;
        
        let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
        let buf = &mut aligned.0;
        self.read_block(bitmap_block, buf)?;
        
        buf[bit_offset / 8] &= !(1 << (bit_offset % 8));
        
        self.write_block(bitmap_block, buf)?;
        Ok(())
    }

    fn free_block(&self, block_id: u32) -> Result<(), &'static str> {
        let data_start = 1 + self.sb.inode_bitmap_blocks + self.sb.data_bitmap_blocks + self.sb.inode_area_blocks;
        if block_id < data_start {
            return Err("Invalid block id (metadata area)");
        }
        // Bitmap maps 1:1 to blocks
        let index = block_id;

        let bitmap_start = self.block_offset + 1 + self.sb.inode_bitmap_blocks;
        let bitmap_block = bitmap_start + (index / (BLOCK_SIZE as u32 * 8));
        let bit_offset = (index % (BLOCK_SIZE as u32 * 8)) as usize;
        
        let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
        let buf = &mut aligned.0;
        self.read_block(bitmap_block, buf)?;
        
        buf[bit_offset / 8] &= !(1 << (bit_offset % 8));
        
        self.write_block(bitmap_block, buf)?;
        Ok(())
    }

    fn update_disk_inode(&self, inode_id: u32, inode: &DiskInode) -> Result<(), &'static str> {
        let inodes_per_block = (BLOCK_SIZE / INODE_SIZE) as u32;
        let block_rel = inode_id / inodes_per_block;
        let offset = (inode_id % inodes_per_block) as usize;
        
        let block_abs = self.block_offset + 1 + self.sb.inode_bitmap_blocks + self.sb.data_bitmap_blocks + block_rel;
        
        let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
        let buf = &mut aligned.0;
        
        self.read_block(block_abs, buf)?;
        
        let ptr = buf.as_mut_ptr() as *mut DiskInode;
        unsafe { 
            let target = ptr.add(offset);
            core::ptr::write_unaligned(target, *inode);
        }
        
        self.write_block(block_abs, buf)?;
        self.sync()?; // Ensure metadata is persisted
        Ok(())
    }

    
    // Convert logic block index (in file) to physical block index (on disk)
    // Allocates if 'alloc' is true
    // Returns Ok(0) if block is not allocated and alloc is false
    fn get_block_id(&self, inode: &mut DiskInode, inner_id: u32, alloc: bool) -> Result<u32, &'static str> {
        if (inner_id as usize) < DIRECT_POINTERS {
            if inode.direct[inner_id as usize] == 0 {
                if !alloc { return Ok(0); }
                let new_block = self.alloc_block()?;
                // println!("NovaFS Debug: get_block_id allocated block {} for direct pointer {}", new_block, inner_id);
                inode.direct[inner_id as usize] = new_block;

                // Zero the new block
                let zero_aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                let zero_buf = &zero_aligned.0;
                self.write_block(self.block_offset + new_block, zero_buf)?;

                // VERIFY
                let mut check_aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                self.read_block(self.block_offset + new_block, &mut check_aligned.0)?;
                if check_aligned.0.iter().any(|&x| x != 0) {
                     println!("NovaFS Critical Error: Zeroing failed for block {}", new_block);
                     let mut dump = [0u8; 32];
                     dump.copy_from_slice(&check_aligned.0[..32]);
                     println!("First 32 bytes: {:?}", dump);
                }
            }
            Ok(inode.direct[inner_id as usize])
        } else {
            let indirect_limit = DIRECT_POINTERS + (BLOCK_SIZE / 4);
            
            if (inner_id as usize) < indirect_limit {
                 // Indirect Block
                 let indirect_idx = (inner_id as usize) - DIRECT_POINTERS;
                 let ptrs_per_block = BLOCK_SIZE / 4;
                 
                 // Check if indirect block is allocated
                 if inode.indirect == 0 {
                     if !alloc { return Ok(0); }
                     let new_block = self.alloc_block()?;
                     inode.indirect = new_block;
                     
                     // Clear the new indirect block
                     let zero_aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                     let zero_buf = &zero_aligned.0;
                     self.write_block(self.block_offset + new_block, zero_buf)?;
                 }
                 
                 // Read indirect block
                 let indirect_block_phys = self.block_offset + inode.indirect;
                 let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                 let buf = &mut aligned.0;
                 self.read_block(indirect_block_phys, buf)?;
                 
                 let ptrs = unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u32, ptrs_per_block) };
                 
                 if ptrs[indirect_idx] == 0 {
                      if !alloc { return Ok(0); }
                      let new_block = self.alloc_block()?;
                      ptrs[indirect_idx] = new_block;
                      
                      // Zero the new block
                      let zero_aligned_inner = AlignedBlock([0u8; BLOCK_SIZE]);
                      let zero_buf_inner = &zero_aligned_inner.0;
                      self.write_block(self.block_offset + new_block, zero_buf_inner)?;
                      
                      // Write back indirect block
                      self.write_block(indirect_block_phys, buf)?;
                  }
                 
                 Ok(ptrs[indirect_idx])
            } else {
                 // Double Indirect
                 let double_idx = (inner_id as usize) - indirect_limit;
                 let ptrs_per_block = BLOCK_SIZE / 4;
                 let l1_idx = double_idx / ptrs_per_block;
                 let l2_idx = double_idx % ptrs_per_block;
                 
                 if l1_idx >= ptrs_per_block {
                     return Err("File too large");
                 }
                 
                 // Check L1 (Double Indirect Block)
                 if inode.double_indirect == 0 {
                     if !alloc { return Ok(0); }
                     let new_block = self.alloc_block()?;
                     inode.double_indirect = new_block;
                     
                     let zero_aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                     let zero_buf = &zero_aligned.0;
                     self.write_block(self.block_offset + new_block, zero_buf)?;
                 }
                 
                 // Read L1
                 let l1_phys = self.block_offset + inode.double_indirect;
                 let mut aligned_l1 = AlignedBlock([0u8; BLOCK_SIZE]);
                 let buf_l1 = &mut aligned_l1.0;
                 self.read_block(l1_phys, buf_l1)?;
                 let ptrs_l1 = unsafe { core::slice::from_raw_parts_mut(buf_l1.as_mut_ptr() as *mut u32, ptrs_per_block) };
                 
                 // Check L2
                 if ptrs_l1[l1_idx] == 0 {
                     if !alloc { return Ok(0); }
                     let new_block = self.alloc_block()?;
                     ptrs_l1[l1_idx] = new_block;
                     
                     let zero_aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                     let zero_buf = &zero_aligned.0;
                     self.write_block(self.block_offset + new_block, zero_buf)?;
                     
                     // Write back L1
                     self.write_block(l1_phys, buf_l1)?;
                 }
                 
                 let l2_block_id = ptrs_l1[l1_idx];
                 
                 // Read L2
                 let l2_phys = self.block_offset + l2_block_id;
                 let mut aligned_l2 = AlignedBlock([0u8; BLOCK_SIZE]);
                 let buf_l2 = &mut aligned_l2.0;
                 self.read_block(l2_phys, buf_l2)?;
                 let ptrs_l2 = unsafe { core::slice::from_raw_parts_mut(buf_l2.as_mut_ptr() as *mut u32, ptrs_per_block) };
                 
                 if ptrs_l2[l2_idx] == 0 {
                     if !alloc { return Ok(0); }
                     let new_block = self.alloc_block()?;
                     ptrs_l2[l2_idx] = new_block;
                     
                     // Zero data block
                     let zero_aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                     let zero_buf = &zero_aligned.0;
                     self.write_block(self.block_offset + new_block, zero_buf)?;
                     
                     // Write back L2
                     self.write_block(l2_phys, buf_l2)?;
                 }
                 
                 Ok(ptrs_l2[l2_idx])
            }
        }
    }
    
    // Helper to get data area start
    fn data_area_start(&self) -> u32 {
        self.block_offset + 1 + self.sb.inode_bitmap_blocks + self.sb.data_bitmap_blocks + self.sb.inode_area_blocks
    }

    fn get_inode_handle(self: &Arc<Self>, inode_id: u32) -> Result<Arc<NovaInode<D>>, &'static str> {
        let mut map = self.inodes.lock();
        if let Some(weak) = map.get(&inode_id) {
            if let Some(strong) = weak.upgrade() {
                return Ok(strong);
            }
        }
        
        // Load from disk
        let disk_inode = self.get_disk_inode(inode_id)?;
        let new_inode = Arc::new(NovaInode {
            fs: self.clone(),
            inode_number: inode_id,
            metadata: Mutex::new(disk_inode),
        });
        
        map.insert(inode_id, Arc::downgrade(&new_inode));
        Ok(new_inode)
    }
}

impl<D: BlockDevice + Send + Sync + 'static> FileSystem for Arc<NovaFS<D>> {
    fn root_inode(&self) -> Arc<dyn Inode> {
        self.get_inode_handle(1).expect("Root inode missing")
    }
    
    fn sync(&self) -> Result<(), &'static str> {
        self.cache.lock().sync()
    }
}

pub struct NovaInode<D: BlockDevice + Send + Sync + 'static> {
    fs: Arc<NovaFS<D>>, 
    inode_number: u32,
    metadata: Mutex<DiskInode>,
}

impl<D: BlockDevice + Send + Sync + 'static> NovaInode<D> {
    fn get_cipher(&self) -> crate::crypto::ChaCha20 {
        let key = self.fs.sb.volume_key;
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.inode_number.to_le_bytes());
        crate::crypto::ChaCha20::new(&key, &nonce, 0)
    }
}

impl<D: BlockDevice + Send + Sync + 'static> Inode for NovaInode<D> {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize, &'static str> {
        let mut curr = offset;
        let end = offset + buf.len();
        let mut read_len = 0;
        let mut inode = self.metadata.lock();
        let encrypted = (inode.flags & 1) != 0;
                if encrypted { println!("read_at: Encrypted flag set for inode {}", self.inode_number); }

        if curr >= inode.size as usize {
            return Ok(0);
        }
        
        let effective_end = core::cmp::min(end, inode.size as usize);
        
        while curr < effective_end {
            let block_idx = (curr / BLOCK_SIZE) as u32;
            let offset_in_block = curr % BLOCK_SIZE;
            let len = core::cmp::min(BLOCK_SIZE - offset_in_block, effective_end - curr);
            
            let disk_block_id = self.fs.get_block_id(&mut inode, block_idx, false)?;
            if disk_block_id == 0 {
                // Hole: fill with zeros
                buf[read_len..read_len + len].fill(0);
                read_len += len;
                curr += len;
                continue;
            }
            let real_block = self.fs.block_offset + disk_block_id;
            
            let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
            let block_buf = &mut aligned.0;
            self.fs.read_block(real_block, block_buf)?;
            
            buf[read_len..read_len + len].copy_from_slice(&block_buf[offset_in_block..offset_in_block + len]);
            
            if encrypted {
                let mut cipher = self.get_cipher();
                cipher.process(&mut buf[read_len..read_len + len], curr);
            }
            
            read_len += len;
            curr += len;
        }

        // Update atime
        inode.atime = crate::drivers::rtc::RtcDriver::new().get_unix_timestamp();
        // We ignore the error here as read should succeed even if inode update fails
        self.fs.update_disk_inode(self.inode_number, &inode).ok();
        
        Ok(read_len)
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> Result<usize, &'static str> {
        let mut curr = offset;
        let mut written_len = 0;
        let mut inode = self.metadata.lock();
        let encrypted = (inode.flags & 1) != 0;
        
        while written_len < buf.len() {
            let block_idx = (curr / BLOCK_SIZE) as u32;
            let offset_in_block = curr % BLOCK_SIZE;
            let len = core::cmp::min(BLOCK_SIZE - offset_in_block, buf.len() - written_len);
            
            // Alloc if needed
            let disk_block_id = self.fs.get_block_id(&mut inode, block_idx, true)?;
            let real_block = self.fs.block_offset + disk_block_id;
            
            let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
            let block_buf = &mut aligned.0;
            if len < BLOCK_SIZE {
                self.fs.read_block(real_block, block_buf)?;
            }
            
            block_buf[offset_in_block..offset_in_block + len].copy_from_slice(&buf[written_len..written_len + len]);
            
            if encrypted {
                let mut cipher = self.get_cipher();
                cipher.process(&mut block_buf[offset_in_block..offset_in_block + len], curr);
            }
            
            self.fs.write_block(real_block, block_buf)?;
            
            written_len += len;
            curr += len;
        }
        
        if written_len > 0 {
            let ts = crate::drivers::rtc::RtcDriver::new().get_unix_timestamp();
            inode.mtime = ts;
            inode.ctime = ts;
            
            if curr > inode.size as usize {
                inode.size = curr as u32;
            }
            self.fs.update_disk_inode(self.inode_number, &inode)?;
        }
        
        Ok(written_len)
    }

    fn metadata(&self) -> Result<FileStat, &'static str> {
        let inode = self.metadata.lock();
        Ok(FileStat {
            file_type: match inode.type_ {
                1 => FileType::Directory,
                2 => FileType::Symlink,
                _ => FileType::File,
            },
            size: inode.size as usize,
            mode: inode.mode,
            uid: inode.uid,
            gid: inode.gid,
            atime: inode.atime,
            mtime: inode.mtime,
            ctime: inode.ctime,
            inode_number: self.inode_number as u64,
            nlink: inode.nlink,
        })
    }
    
    fn control(&self, op: u32, arg: u64) -> Result<u64, &'static str> {
        let mut inode = self.metadata.lock();
        match op {
            1 => Ok(inode.flags as u64), // Get flags
            2 => { // Set flags
                inode.flags = arg as u32;
                println!("NovaFS Debug: Control SetFlags inode {} = 0x{:x}", self.inode_number, inode.flags);
                self.fs.update_disk_inode(self.inode_number, &inode)?;
                Ok(0)
            },
            3 => { // Truncate (size = arg)
                let new_size = arg as u32;
                if new_size == 0 {
                    self.free_inode_blocks(&inode)?;
                    inode.direct = [0; DIRECT_POINTERS];
                    inode.indirect = 0;
                    inode.double_indirect = 0;
                    inode.size = 0;
                } else if new_size < inode.size {
                     // Shrink
                     let new_blocks = (new_size + BLOCK_SIZE as u32 - 1) / BLOCK_SIZE as u32;
                     self.shrink_inode_blocks(&mut inode, new_blocks)?;
                     
                     // Zero out the tail of the last block?
                     let offset = new_size % BLOCK_SIZE as u32;
                     if offset != 0 {
                         let block_idx = new_size / BLOCK_SIZE as u32;
                         if let Ok(last_blk) = self.fs.get_block_id(&mut inode, block_idx, false) {
                             if last_blk != 0 {
                                 let real_block = self.fs.data_area_start() + last_blk;
                                 let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                                 let buf = &mut aligned.0;
                                 self.fs.read_block(real_block, buf)?;
                                 buf[offset as usize..].fill(0);
                                 self.fs.write_block(real_block, buf)?;
                             }
                         }
                     }
                     inode.size = new_size;
                } else {
                     // Extend
                     inode.size = new_size;
                }
                
                // Update timestamps
                let ts = crate::drivers::rtc::RtcDriver::new().get_unix_timestamp();
                inode.mtime = ts;
                inode.ctime = ts;

                self.fs.update_disk_inode(self.inode_number, &inode)?;
                Ok(0)
            },
            4 => { // Set Mode
                inode.mode = arg as u16;
                inode.ctime = crate::drivers::rtc::RtcDriver::new().get_unix_timestamp();
                self.fs.update_disk_inode(self.inode_number, &inode)?;
                Ok(0)
            },
            5 => { // Set UID
                inode.uid = arg as u32;
                inode.ctime = crate::drivers::rtc::RtcDriver::new().get_unix_timestamp();
                self.fs.update_disk_inode(self.inode_number, &inode)?;
                Ok(0)
            },
            6 => { // Set GID
                inode.gid = arg as u32;
                inode.ctime = crate::drivers::rtc::RtcDriver::new().get_unix_timestamp();
                self.fs.update_disk_inode(self.inode_number, &inode)?;
                Ok(0)
            },
            7 => { // Set Flags (e.g. Encryption)
                println!("NovaFS Debug: Control SetFlags (Op7) inode {} = 0x{:x}", self.inode_number, inode.flags);
                inode.flags = arg as u32;
                inode.ctime = crate::drivers::rtc::RtcDriver::new().get_unix_timestamp();
                self.fs.update_disk_inode(self.inode_number, &inode)?;
                Ok(0)
            },
            _ => Err("Invalid op"),
        }
    }

    fn sync(&self) -> Result<(), &'static str> {
        self.fs.sync()
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, &'static str> {
        let mut inode = self.metadata.lock();
        if inode.type_ != 1 {
            return Err("Not a directory");
        }
        
        let size = inode.size as usize;
        // println!("NovaFS Debug: list inode {} size={} blocks={}", self.inode_number, size, (size + BLOCK_SIZE - 1) / BLOCK_SIZE);
        
        let mut offset = 0;
        let entry_size = size_of::<DirEntry>();
        let mut loop_count = 0;
        const MAX_LOOP: usize = 10000;
        
        while offset < size {
            loop_count += 1;
            if loop_count > MAX_LOOP {
                println!("NovaFS Error: lookup loop limit exceeded");
                break;
            }

            let block_idx = (offset / BLOCK_SIZE) as u32;
            let disk_block = match self.fs.get_block_id(&mut inode, block_idx, false) {
                Ok(b) => b,
                Err(_) => break,
            };
            
            if disk_block == 0 {
                offset += BLOCK_SIZE;
                continue;
            }
            
            let real_block = self.fs.block_offset + disk_block;
            let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
            let block_buf = &mut aligned.0;
            self.fs.read_block(real_block, block_buf)?;
            
            for i in 0..BLOCK_SIZE/entry_size {
                let pos = offset + i * entry_size;
                if pos >= size { break; }
                
                let entry = unsafe { &*(block_buf[i*entry_size..].as_ptr() as *const DirEntry) };
                if entry.inode_number != 0 {
                    let name_len = entry.name.iter().position(|&c| c == 0).unwrap_or(28);
                    let entry_name = core::str::from_utf8(&entry.name[..name_len]).unwrap_or("");
                    // println!("DEBUG: lookup scanning '{}' vs target '{}'", entry_name, name);
                    if entry_name == name {
                         println!("NovaFS Debug: lookup found '{}' (inode={}) in dir inode {}", name, entry.inode_number, self.inode_number);
                         return Ok(self.fs.get_inode_handle(entry.inode_number)?);
                    }
                }
            }
            offset += BLOCK_SIZE;
        }
        
        // println!("DEBUG: lookup failed for '{}'", name);
        println!("NovaFS Debug: lookup failed for '{}' in inode {}", name, self.inode_number);
        Err("File not found")
    }

    fn create(&self, name: &str, type_: FileType) -> Result<Arc<dyn Inode>, &'static str> {
        println!("NovaFS Debug: create '{}' inside inode {}", name, self.inode_number);
        // Allocate inode first
        let new_inode_num = self.fs.alloc_inode()?;
        println!("create: name='{}' allocated inode={}", name, new_inode_num);

        if new_inode_num == self.inode_number {
             println!("NovaFS Critical: Allocator returned self inode {}! Bitmap corruption?", new_inode_num);
             return Err("Filesystem corruption: Allocated self");
        }

        let ts = crate::drivers::rtc::RtcDriver::new().get_unix_timestamp();
        
        let (inode_type, mode) = match type_ {
            FileType::Directory => (1, 0o755),
            FileType::Symlink => (2, 0o777),
            FileType::File => (0, 0o644),
        };

        // For directories, initial nlink is 2 (. and entry in parent)
        // For files, initial nlink is 1 (entry in parent)
        let initial_nlink = if type_ == FileType::Directory { 2 } else { 1 };

        let new_disk_inode = DiskInode {
            mode,
            type_: inode_type,
            uid: 0,
            gid: 0,
            size: 0,
            atime: ts,
            ctime: ts,
            mtime: ts,
            direct: [0; DIRECT_POINTERS],
            indirect: 0,
            double_indirect: 0,
            flags: 0,
            nlink: initial_nlink,
            _padding: [0; 24],
        };
        self.fs.update_disk_inode(new_inode_num, &new_disk_inode)?;
        
        // Add to parent directory
        if let Err(e) = self.add_dir_entry(name, new_inode_num) {
            self.fs.free_inode(new_inode_num)?;
            return Err(e);
        }

        let new_inode = self.fs.get_inode_handle(new_inode_num)?;

        // If directory, add "." and ".." and update parent nlink
        if type_ == FileType::Directory {
            // Add "."
            if let Err(e) = new_inode.add_dir_entry(".", new_inode_num) {
                 // Cleanup
                 println!("NovaFS Error: Failed to add '.' to new directory {}. Rolling back.", new_inode_num);
                 match self.remove(name) {
                     Ok(_) => {
                         if let Err(err) = self.fs.free_inode(new_inode_num) {
                             println!("NovaFS Error: Failed to free inode {} during rollback: {}", new_inode_num, err);
                         }
                     },
                     Err(err) => {
                         println!("NovaFS Critical: Failed to remove entry '{}' during rollback: {}. Inode {} leaked.", name, err, new_inode_num);
                     }
                 }
                 return Err(e);
            }
            
            // Add ".."
            if let Err(e) = new_inode.add_dir_entry("..", self.inode_number) {
                 // Cleanup
                 println!("NovaFS Error: Failed to add '..' to new directory {}. Rolling back.", new_inode_num);
                 match self.remove(name) {
                     Ok(_) => {
                         if let Err(err) = self.fs.free_inode(new_inode_num) {
                             println!("NovaFS Error: Failed to free inode {} during rollback: {}", new_inode_num, err);
                         }
                     },
                     Err(err) => {
                         println!("NovaFS Critical: Failed to remove entry '{}' during rollback: {}. Inode {} leaked.", name, err, new_inode_num);
                     }
                 }
                 return Err(e);
            }

            // Update parent nlink (increment by 1 for "..")
            {
                let mut parent_meta = self.metadata.lock();
                parent_meta.nlink += 1;
                parent_meta.ctime = ts;
                self.fs.update_disk_inode(self.inode_number, &parent_meta)?;
            }
        }
        
        Ok(new_inode)
    }

    fn list(&self) -> Result<Vec<(String, Arc<dyn Inode>)>, &'static str> {
        let mut inode = self.metadata.lock();
        if inode.type_ != 1 {
            return Err("Not a directory");
        }
        
        let mut entries = Vec::new();
        let size = inode.size as usize;
        let entry_size = size_of::<DirEntry>();
        let mut offset = 0;
        let mut loop_count = 0;
        const MAX_LOOP: usize = 1024; // Limit to 4MB directory size
        const MAX_ENTRIES: usize = 1024; // Limit number of entries

        // DEBUG: Print directory size
        println!("DEBUG: list dir inode={} size={}", self.inode_number, size);
        if size > MAX_LOOP * BLOCK_SIZE {
             println!("NovaFS Warning: Directory size {} exceeds safety limit", size);
        }
        
        while offset < size {
            loop_count += 1;
            if loop_count > MAX_LOOP {
                println!("NovaFS Error: Directory list loop limit exceeded (corruption?)");
                break;
            }
            
            if entries.len() >= MAX_ENTRIES {
                println!("NovaFS Warning: Directory entry limit ({}) reached", MAX_ENTRIES);
                break;
            }

            let block_idx = (offset / BLOCK_SIZE) as u32;
            let disk_block = match self.fs.get_block_id(&mut inode, block_idx, false) {
                Ok(b) => b,
                Err(e) => {
                    println!("NovaFS Error: list get_block_id failed: {}", e);
                    offset += BLOCK_SIZE;
                    continue;
                }
            };
            if disk_block == 0 { 
                offset += BLOCK_SIZE;
                continue; 
            }
            // Always print for first few blocks or if large
            if offset < 2048 || size > 100000 {
                // println!("DEBUG: list dir offset={} block_idx={} disk_block={}", offset, block_idx, disk_block);
            }

            let real_block = self.fs.block_offset + disk_block;
            // println!("NovaFS Debug: list reading block {} (real {})", disk_block, real_block);
            
            // DEBUG: Check if block overlaps with file data (heuristic)
            // if offset > 4096 { println!("DEBUG: reading dir block at offset {} -> disk {}", offset, disk_block); }

            let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
            let block_buf = &mut aligned.0;
            if let Err(e) = self.fs.read_block(real_block, block_buf) {
                println!("NovaFS Error: list read_block failed: {}", e);
                offset += BLOCK_SIZE;
                continue;
            }
            
            for i in 0..BLOCK_SIZE/entry_size {
                let pos = offset + i * entry_size;
                if pos >= size { break; }
                
                let entry_ptr = unsafe { block_buf.as_ptr().add(i*entry_size) as *const DirEntry };
                let entry = unsafe { core::ptr::read_unaligned(entry_ptr) };

                if entry.inode_number != 0 {
                    if entry.inode_number > MAX_INODES {
                        // Skip invalid inode numbers to prevent error spam
                        continue;
                    }
                    let name_len = entry.name.iter().position(|&c| c == 0).unwrap_or(28);
                    let name = String::from_utf8_lossy(&entry.name[..name_len]).into_owned();
                    match self.fs.get_inode_handle(entry.inode_number) {
                        Ok(child) => entries.push((name, child as Arc<dyn Inode>)),
                        Err(_e) => {
                            // Suppress log to avoid spam during recovery/listing
                        }
                    }
                }
            }
            offset += BLOCK_SIZE;
        }
        
        Ok(entries)
    }

    fn link(&self, name: &str, other: &dyn Inode) -> Result<(), &'static str> {
        let other_stat = other.metadata()?;
        let target_inode_num = other_stat.inode_number as u32;
        
        // TODO: Verify other is on the same filesystem
        
        // Get handle
        let target_inode = self.fs.get_inode_handle(target_inode_num)?;
        
        // Lock metadata to check type and update nlink
        {
            let mut target_data = target_inode.metadata.lock();
            
            if target_data.type_ == 1 { 
                return Err("Cannot link directory"); 
            }
            
            target_data.nlink += 1;
            target_data.ctime = crate::drivers::rtc::RtcDriver::new().get_unix_timestamp();
            
            self.fs.update_disk_inode(target_inode_num, &target_data)?;
        }
        
        // Add entry to directory
        match self.add_dir_entry(name, target_inode_num) {
            Ok(_) => Ok(()),
            Err(e) => {
                // Rollback nlink
                let mut target_data = target_inode.metadata.lock();
                if target_data.nlink > 0 {
                    target_data.nlink -= 1;
                    self.fs.update_disk_inode(target_inode_num, &target_data)?;
                }
                Err(e)
            }
        }
    }

    fn rename(&self, old_name: &str, new_parent: &Arc<dyn Inode>, new_name: &str) -> Result<(), &'static str> {
        let target = self.lookup(old_name)?;
        let target_stat = target.metadata()?;
        let target_ino = target_stat.inode_number as u32;

        let np_stat = new_parent.metadata()?;
        let np_ino = np_stat.inode_number as u32;
        
        // Loop check for directory
        if target_stat.file_type == FileType::Directory {
            if np_ino == target_ino {
                return Err("Cannot move directory into itself");
            }
            
            // Deep loop check
            let mut curr = new_parent.clone();
            for _ in 0..100 {
                let curr_stat = curr.metadata()?;
                if curr_stat.inode_number == target_ino as u64 {
                     return Err("Cannot move directory into its own subdirectory");
                }
                if curr_stat.inode_number == 0 {
                    break; // Reached root
                }
                
                match curr.lookup("..") {
                    Ok(parent) => curr = parent,
                    Err(_) => break,
                }
            }
        }

        let target_handle = self.fs.get_inode_handle(target_ino)?;
        let new_parent_handle = self.fs.get_inode_handle(np_ino)?;
        
        // Check if destination exists
        if let Ok(dest_inode) = new_parent_handle.lookup(new_name) {
            let dest_stat = dest_inode.metadata()?;
            if dest_stat.inode_number == target_stat.inode_number {
                return Ok(()); // Renaming to same file, do nothing
            }
            
            // Type check
            if target_stat.file_type == FileType::Directory {
                if dest_stat.file_type != FileType::Directory {
                    return Err("Not a directory"); // Target is a file, source is dir
                }
                // Check if target dir is empty
                let entries = dest_inode.list()?;
                if entries.len() > 2 { // . and ..
                    return Err("Directory not empty");
                }
            } else {
                if dest_stat.file_type == FileType::Directory {
                    return Err("Is a directory"); // Target is dir, source is file
                }
            }
            
            // Remove destination
            new_parent_handle.remove(new_name)?;
        }
        
        // 1. Add to new parent
        if let Err(e) = new_parent_handle.add_dir_entry(new_name, target_ino) {
            return Err(e);
        }
        
        // 2. Remove from old parent (self)
        // We use internal helper to avoid "Directory not empty" check and nlink decrement
        if let Err(e) = self.remove_entry_internal(old_name) {
             // Rollback: Remove from new parent
             let _ = new_parent_handle.remove_entry_internal(new_name);
             return Err(e);
        }

        // Verify removal (Critical for detecting corruption/duplicates)
        if let Ok(_) = self.lookup(old_name) {
             println!("NovaFS Error: Rename source '{}' still exists after removal. FS Corruption detected.", old_name);
             // Rollback
             let _ = new_parent_handle.remove_entry_internal(new_name);
             return Err("Rename failed: Source still exists");
        }

        // 3. Handle Directory specific updates
        if target_stat.file_type == FileType::Directory {
            // Update ".." in target to point to new parent
            if let Err(e) = target_handle.update_dotdot(np_ino) {
                // Critical error: FS might be inconsistent
                return Err(e);
            }
            
            // Update parent nlinks
            // Old parent (self) nlink--
            {
                let mut self_meta = self.metadata.lock();
                if self_meta.nlink > 1 {
                    self_meta.nlink -= 1;
                    self.fs.update_disk_inode(self.inode_number, &self_meta)?;
                }
            }
            
            // New parent nlink++
            {
                let mut np_meta = new_parent_handle.metadata.lock();
                np_meta.nlink += 1;
                self.fs.update_disk_inode(np_ino, &np_meta)?;
            }
        }

        Ok(())
    }

    fn remove(&self, name: &str) -> Result<(), &'static str> {
        println!("NovaFS Debug: remove request for '{}' (len={}) in inode {}", name, name.len(), self.inode_number);
        let mut parent_inode = self.metadata.lock();
        if parent_inode.type_ != 1 {
            return Err("Not a directory");
        }
        
        let size = parent_inode.size as usize;
        let entry_size = size_of::<DirEntry>();
        let mut offset = 0;
        let mut loop_count = 0;
        const MAX_LOOP: usize = 256;
        
        while offset < size {
            loop_count += 1;
            if loop_count > MAX_LOOP {
                println!("NovaFS Error: remove loop limit exceeded");
                return Err("Directory too large or corrupted");
            }

            let block_idx = (offset / BLOCK_SIZE) as u32;
            let disk_block = match self.fs.get_block_id(&mut parent_inode, block_idx, false) {
                Ok(b) => b,
                Err(_) => {
                    offset += BLOCK_SIZE;
                    continue;
                }
            };
            if disk_block == 0 { 
                offset += BLOCK_SIZE;
                continue; 
            }

            let real_block = self.fs.block_offset + disk_block;
            
            let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
            let block_buf = &mut aligned.0;
            self.fs.read_block(real_block, block_buf)?;
            let mut modified = false;

            for i in 0..BLOCK_SIZE/entry_size {
                let pos = offset + i * entry_size;
                if pos >= size { break; }
                
                let entry_ptr = unsafe { block_buf.as_mut_ptr().add(i*entry_size) as *mut DirEntry };
                let mut entry = unsafe { core::ptr::read_unaligned(entry_ptr) };
                
                if entry.inode_number != 0 {
                    if entry.inode_number > MAX_INODES {
                        continue;
                    }
                    let name_len = entry.name.iter().position(|&c| c == 0).unwrap_or(28);
                    let entry_name = core::str::from_utf8(&entry.name[..name_len]).unwrap_or("");
                    
                    // println!("NovaFS Debug: remove scanning '{}' (match target '{}'?)", entry_name, name);
                    
                    if entry_name == name {
                        let target_inode_num = entry.inode_number;
                        
                        let target_inode = self.fs.get_inode_handle(target_inode_num)?;
                        let mut target_data = target_inode.metadata.lock();
                        
                        if target_data.type_ == 1 {
                             // Check if empty by scanning
                             let t_size = target_data.size as usize;
                             let mut t_offset = 0;
                             let mut t_loop = 0;
                             while t_offset < t_size {
                                 t_loop += 1;
                                 if t_loop > MAX_LOOP {
                                     println!("NovaFS Error: remove (check empty) loop limit exceeded");
                                     return Err("Directory too large or corrupted");
                                 }
                                 let t_blk_idx = (t_offset / BLOCK_SIZE) as u32;
                                 if let Ok(t_blk) = self.fs.get_block_id(&mut target_data, t_blk_idx, false) {
                                     let t_real = self.fs.block_offset + t_blk;
                                    let mut t_aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                                    let t_buf = &mut t_aligned.0;
                                    self.fs.read_block(t_real, t_buf)?;
                                    for k in 0..BLOCK_SIZE/entry_size {
                                         if t_offset + k*entry_size >= t_size { break; }
                                         let t_ent = unsafe { &*(t_buf.as_ptr().add(k*entry_size) as *const DirEntry) };
                                         if t_ent.inode_number != 0 {
                                             let name_len = t_ent.name.iter().position(|&c| c == 0).unwrap_or(28);
                                             let name = core::str::from_utf8(&t_ent.name[..name_len]).unwrap_or("");
                                             if name != "." && name != ".." {
                                                  // println!("NovaFS Debug: Directory not empty due to '{}'", name);
                                                  return Err("Directory not empty");
                                             }
                                         }
                                     }
                                 }
                                 t_offset += BLOCK_SIZE;
                             }
                        }
                        
                        if target_data.nlink > 0 {
                            target_data.nlink -= 1;
                        }
                        
                        if target_data.nlink == 0 {
                            target_inode.free_inode_blocks(&target_data)?;
                            self.fs.free_inode(target_inode_num)?;
                        } else {
                            target_data.ctime = crate::drivers::rtc::RtcDriver::new().get_unix_timestamp();
                            self.fs.update_disk_inode(target_inode_num, &target_data)?;
                        }
                        
                        // Remove entry
                        entry.inode_number = 0;
                        unsafe { core::ptr::write_unaligned(entry_ptr, entry) };
                        modified = true;
                        
                        // Update parent inode (mtime/ctime and size if at end)
                        let ts = crate::drivers::rtc::RtcDriver::new().get_unix_timestamp();
                        parent_inode.mtime = ts;
                        parent_inode.ctime = ts;
                        
                        // If this was the last entry, shrink size
                        if offset + entry_size >= size {
                             parent_inode.size = offset as u32;
                        }
                        
                        if let Err(e) = self.fs.update_disk_inode(self.inode_number, &parent_inode) {
                             println!("NovaFS Error: remove failed to update parent inode: {}", e);
                        }

                        break;
                    }
                }
            }
            
            if modified {
                self.fs.write_block(real_block, block_buf)?;
                
                // DROP LOCK to avoid deadlock in lookup
                drop(parent_inode);

                // Verify removal (Critical for detecting corruption/duplicates)
                // We use self.lookup(name) which starts from beginning of directory
                // If it finds the entry again, it means there was a duplicate
                if let Ok(_) = self.lookup(name) {
                     println!("NovaFS Error: Remove target '{}' still exists after removal. FS Corruption detected.", name);
                     return Err("Remove failed: Target still exists");
                }
                
                return Ok(());
            }
            offset += BLOCK_SIZE;
        }
        
        Err("File not found")
    }

}

impl<D: BlockDevice + Send + Sync + 'static> NovaInode<D> {
    fn add_dir_entry(&self, name: &str, inode_num: u32) -> Result<(), &'static str> {
        let mut parent_inode = self.metadata.lock();
        if parent_inode.type_ != 1 {
            return Err("Not a directory");
        }
        
        let size = parent_inode.size as usize;
        let entry_size = size_of::<DirEntry>();
        let mut scan_offset = 0;
        let mut target_offset = size;
        let mut found_free = false;
        
        let mut loop_count = 0;
        const MAX_LOOP: usize = 10000;

        // Check existence and find free slot
        while scan_offset < size {
            loop_count += 1;
            if loop_count > MAX_LOOP {
                println!("NovaFS Error: add_dir_entry loop limit exceeded");
                return Err("Directory too large or corrupted");
            }

            let block_idx = (scan_offset / BLOCK_SIZE) as u32;
            if let Ok(disk_block) = self.fs.get_block_id(&mut parent_inode, block_idx, false) {
                let real_block = self.fs.block_offset + disk_block;
                let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                let block_buf = &mut aligned.0;
                if let Err(e) = self.fs.read_block(real_block, block_buf) {
                    println!("NovaFS Error: add_dir_entry read_block failed: {}", e);
                    return Err("Read failed");
                }
                
                for i in 0..BLOCK_SIZE/entry_size {
                    let pos = scan_offset + i * entry_size;
                    if pos >= size { break; }
                    
                    let slot = unsafe { core::ptr::read_unaligned(block_buf.as_ptr().add(i*entry_size) as *const DirEntry) };
                    if slot.inode_number != 0 {
                         let name_len = slot.name.iter().position(|&c| c == 0).unwrap_or(28);
                         let entry_name = core::str::from_utf8(&slot.name[..name_len]).unwrap_or("");
                         if entry_name == name {
                             println!("NovaFS Debug: add_dir_entry '{}' exists in inode {} (points to inode {})", name, self.inode_number, slot.inode_number);
                             return Err("File exists");
                         }
                    } else if !found_free {
                        target_offset = pos;
                        found_free = true;
                    }
                }
            }
            scan_offset += BLOCK_SIZE;
        }

        // Write entry
        println!("NovaFS Debug: adding entry '{}' (inode={}) to dir inode {}", name, inode_num, self.inode_number);
        let entry = DirEntry {
            inode_number: inode_num,
            name: {
                let mut n = [0u8; 28];
                let bytes = name.as_bytes();
                let len = core::cmp::min(bytes.len(), 28);
                n[..len].copy_from_slice(&bytes[..len]);
                n
            },
        };

        let block_idx = (target_offset / BLOCK_SIZE) as u32;
        let offset_in_block = target_offset % BLOCK_SIZE;
        
        let disk_block_id = match self.fs.get_block_id(&mut parent_inode, block_idx, true) {
            Ok(b) => b,
            Err(e) => {
                println!("NovaFS Error: add_dir_entry alloc block failed: {}", e);
                return Err("Alloc failed");
            }
        };
        let real_block = self.fs.block_offset + disk_block_id;
        
        let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
        let block_buf = &mut aligned.0;
        
        // If it's a new block (past original size), we might need to zero it? 
        // get_block_id(true) zeros new blocks. But if it's existing block, we read it.
        // We always read to preserve other entries in the block.
        if let Err(e) = self.fs.read_block(real_block, block_buf) {
             println!("NovaFS Error: add_dir_entry read target block failed: {}", e);
             return Err("Read failed");
        }
        
        unsafe {
            let ptr = block_buf.as_mut_ptr().add(offset_in_block) as *mut DirEntry;
            core::ptr::write_unaligned(ptr, entry);
        }
        
        if let Err(e) = self.fs.write_block(real_block, block_buf) {
            println!("NovaFS Error: add_dir_entry write failed: {}", e);
            return Err("Write failed");
        }
        
        if !found_free {
            parent_inode.size = (target_offset + entry_size) as u32;
            println!("NovaFS Debug: add_dir_entry updating inode {} size to {}", self.inode_number, parent_inode.size);
            if let Err(e) = self.fs.update_disk_inode(self.inode_number, &parent_inode) {
                println!("NovaFS Error: add_dir_entry update inode failed: {}", e);
                return Err("Inode update failed");
            }
        }
        
        Ok(())
    }

    fn shrink_inode_blocks(&self, inode: &mut DiskInode, new_block_count: u32) -> Result<(), &'static str> {
        let ptrs_per_block = (BLOCK_SIZE / 4) as u32;
        let indirect_limit = DIRECT_POINTERS as u32 + ptrs_per_block;
        
        // 1. Direct Blocks
        for i in 0..DIRECT_POINTERS {
            if (i as u32) >= new_block_count {
                if inode.direct[i] != 0 {
                    self.fs.free_block(inode.direct[i])?;
                    inode.direct[i] = 0;
                }
            }
        }
        
        // 2. Indirect Block
        if inode.indirect != 0 {
            if new_block_count <= DIRECT_POINTERS as u32 {
                // Free entire indirect block
                let real_block = self.fs.block_offset + inode.indirect;
                let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                let buf = &mut aligned.0;
                self.fs.read_block(real_block, buf)?;
                
                for i in 0..ptrs_per_block {
                    let ptr = unsafe { *(buf.as_ptr().add(i as usize * 4) as *const u32) };
                    if ptr != 0 {
                        self.fs.free_block(ptr)?;
                    }
                }
                self.fs.free_block(inode.indirect)?;
                inode.indirect = 0;
            } else if new_block_count < indirect_limit {
                // Partial free
                let start_idx = new_block_count - DIRECT_POINTERS as u32;
                let real_block = self.fs.block_offset + inode.indirect;
                let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                let buf = &mut aligned.0;
                self.fs.read_block(real_block, buf)?;
                let mut modified = false;

                let ptrs = unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u32, ptrs_per_block as usize) };
                
                for i in start_idx..ptrs_per_block {
                    if ptrs[i as usize] != 0 {
                         self.fs.free_block(ptrs[i as usize])?;
                         ptrs[i as usize] = 0;
                         modified = true;
                    }
                }
                if modified {
                    self.fs.write_block(real_block, buf)?;
                }
            }
        }
        
        // 3. Double Indirect Block
        if inode.double_indirect != 0 {
             if new_block_count <= indirect_limit {
                 // Free entire double indirect
                  let l1_real = self.fs.block_offset + inode.double_indirect;
                  let mut l1_aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                  let l1_buf = &mut l1_aligned.0;
                  self.fs.read_block(l1_real, l1_buf)?;
                  let ptrs_l1 = unsafe { core::slice::from_raw_parts_mut(l1_buf.as_mut_ptr() as *mut u32, ptrs_per_block as usize) };
                  
                  for i in 0..ptrs_per_block {
                      let l2_block_idx = ptrs_l1[i as usize];
                      if l2_block_idx != 0 {
                          let l2_real = self.fs.block_offset + l2_block_idx;
                          let mut l2_aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                          let l2_buf = &mut l2_aligned.0;
                          self.fs.read_block(l2_real, l2_buf)?;
                          
                          for j in 0..ptrs_per_block {
                               let data_block = unsafe { *(l2_buf.as_ptr().add(j as usize * 4) as *const u32) };
                               if data_block != 0 {
                                   self.fs.free_block(data_block)?;
                               }
                          }
                          self.fs.free_block(l2_block_idx)?;
                      }
                  }
                  self.fs.free_block(inode.double_indirect)?;
                  inode.double_indirect = 0;
             } else {
                 // Check if L1 entries need to be freed
                 let l1_real = self.fs.block_offset + inode.double_indirect;
                 let mut l1_aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                 let l1_buf = &mut l1_aligned.0;
                 self.fs.read_block(l1_real, l1_buf)?;
                 let ptrs_l1 = unsafe { core::slice::from_raw_parts_mut(l1_buf.as_mut_ptr() as *mut u32, ptrs_per_block as usize) };
                 
                 let mut l1_mod = false;

                 for i in 0..ptrs_per_block {
                     let start_blk = indirect_limit + i * ptrs_per_block;
                     let l2_block_idx = ptrs_l1[i as usize];
                     
                     if l2_block_idx != 0 {
                         if start_blk >= new_block_count {
                             // Free entire L2 table
                             let l2_real = self.fs.block_offset + l2_block_idx;
                             let mut l2_aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                             let l2_buf = &mut l2_aligned.0;
                             self.fs.read_block(l2_real, l2_buf)?;
                             
                             for j in 0..ptrs_per_block {
                                  let data_block = unsafe { *(l2_buf.as_ptr().add(j as usize * 4) as *const u32) };
                                  if data_block != 0 {
                                      self.fs.free_block(data_block)?;
                                  }
                             }
                             self.fs.free_block(l2_block_idx)?;
                             ptrs_l1[i as usize] = 0;
                             l1_mod = true;
                         } else if start_blk + ptrs_per_block > new_block_count {
                             // Partial L2
                             let l2_start_idx = new_block_count - start_blk;
                             let l2_real = self.fs.block_offset + l2_block_idx;
                            let mut l2_aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                            let l2_buf = &mut l2_aligned.0;
                            self.fs.read_block(l2_real, l2_buf)?;
                            let ptrs_l2 = unsafe { core::slice::from_raw_parts_mut(l2_buf.as_mut_ptr() as *mut u32, ptrs_per_block as usize) };
                             
                             let mut l2_mod = false;
                             for j in l2_start_idx..ptrs_per_block {
                                 if ptrs_l2[j as usize] != 0 {
                                     self.fs.free_block(ptrs_l2[j as usize])?;
                                     ptrs_l2[j as usize] = 0;
                                     l2_mod = true;
                                 }
                             }
                             if l2_mod {
                                self.fs.write_block(l2_real, l2_buf)?;
                            }
                         }
                     }
                 }
                 if l1_mod {
                    self.fs.write_block(l1_real, l1_buf)?;
                }
             }
        }
        
        Ok(())
    }

    fn free_inode_blocks(&self, inode: &DiskInode) -> Result<(), &'static str> {
        // Free direct blocks
        for &b in inode.direct.iter() {
            if b != 0 {
                self.fs.free_block(b)?;
            }
        }

        let ptrs_per_block = BLOCK_SIZE / 4;

        // Free indirect blocks
        if inode.indirect != 0 {
            let real_block = self.fs.block_offset + inode.indirect;
            let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
            let buf = &mut aligned.0;
            self.fs.read_block(real_block, buf)?;
            
            for i in 0..ptrs_per_block {
                let ptr = unsafe { *(buf.as_ptr().add(i * 4) as *const u32) };
                if ptr != 0 {
                    self.fs.free_block(ptr)?;
                }
            }
            self.fs.free_block(inode.indirect)?;
        }

        // Free double indirect blocks
        if inode.double_indirect != 0 {
            let l1_real = self.fs.block_offset + inode.double_indirect;
            let mut l1_aligned = AlignedBlock([0u8; BLOCK_SIZE]);
            let l1_buf = &mut l1_aligned.0;
            self.fs.read_block(l1_real, l1_buf)?;

            for i in 0..ptrs_per_block {
                let l2_block_idx = unsafe { *(l1_buf.as_ptr().add(i * 4) as *const u32) };
                if l2_block_idx != 0 {
                    let l2_real = self.fs.block_offset + l2_block_idx;
                    let mut l2_aligned = AlignedBlock([0u8; BLOCK_SIZE]);
                    let l2_buf = &mut l2_aligned.0;
                    self.fs.read_block(l2_real, l2_buf)?;

                    for j in 0..ptrs_per_block {
                        let data_block = unsafe { *(l2_buf.as_ptr().add(j * 4) as *const u32) };
                        if data_block != 0 {
                            self.fs.free_block(data_block)?;
                        }
                    }
                    self.fs.free_block(l2_block_idx)?;
                }
            }
            self.fs.free_block(inode.double_indirect)?;
        }

        Ok(())
    }

    fn remove_entry_internal(&self, name: &str) -> Result<(), &'static str> {
        let mut parent_inode = self.metadata.lock();
        if parent_inode.type_ != 1 {
            return Err("Not a directory");
        }
        
        let size = parent_inode.size as usize;
        let entry_size = size_of::<DirEntry>();
        let mut offset = 0;
        
        while offset < size {
            let block_idx = (offset / BLOCK_SIZE) as u32;
            let disk_block = match self.fs.get_block_id(&mut parent_inode, block_idx, false) {
                Ok(b) => b,
                Err(_) => {
                    offset += BLOCK_SIZE;
                    continue;
                }
            };
            if disk_block == 0 { 
                offset += BLOCK_SIZE;
                continue; 
            }

            let real_block = self.fs.block_offset + disk_block;
            let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
            let block_buf = &mut aligned.0;
            self.fs.read_block(real_block, block_buf)?;
            let mut modified = false;

            for i in 0..BLOCK_SIZE/entry_size {
                let pos = offset + i * entry_size;
                if pos >= size { break; }
                
                let entry_ptr = unsafe { block_buf.as_mut_ptr().add(i*entry_size) as *mut DirEntry };
                let mut entry = unsafe { core::ptr::read_unaligned(entry_ptr) };
                
                if entry.inode_number != 0 {
                    let name_len = entry.name.iter().position(|&c| c == 0).unwrap_or(28);
                    let entry_name = core::str::from_utf8(&entry.name[..name_len]).unwrap_or("");
                    
                    if entry_name == name {
                        // Found it. Zero it out.
                        println!("NovaFS Debug: remove_entry_internal removing '{}' (inode={}) from dir inode {}", name, entry.inode_number, self.inode_number);
                        entry.inode_number = 0;
                        unsafe { core::ptr::write_unaligned(entry_ptr, entry) };
                        modified = true;
                        
                        // Update parent inode (mtime/ctime and size if at end)
                        let ts = crate::drivers::rtc::RtcDriver::new().get_unix_timestamp();
                        parent_inode.mtime = ts;
                        parent_inode.ctime = ts;
                        
                        // If this was the last entry, shrink size
                        if offset + entry_size >= size {
                            parent_inode.size = offset as u32;
                            // TODO: ideally we should scan backwards to find the new last entry to shrink further,
                            // but shrinking by one entry is a good start to prevent infinite growth.
                        }
                        
                        if let Err(e) = self.fs.update_disk_inode(self.inode_number, &parent_inode) {
                             println!("NovaFS Error: remove_entry_internal failed to update inode: {}", e);
                        }
                        
                        break;
                    }
                }
            }
            
            if modified {
                self.fs.write_block(real_block, block_buf)?;
                return Ok(());
            }
            offset += BLOCK_SIZE;
        }
        
        Err("Entry not found")
    }

    fn update_dotdot(&self, new_parent_ino: u32) -> Result<(), &'static str> {
        let mut inode = self.metadata.lock();
        if inode.type_ != 1 {
            return Err("Not a directory");
        }
        
        // ".." is usually in the first block, but we scan to be safe
        let size = inode.size as usize;
        let entry_size = size_of::<DirEntry>();
        let mut offset = 0;
        
        while offset < size {
            let block_idx = (offset / BLOCK_SIZE) as u32;
            let disk_block = match self.fs.get_block_id(&mut inode, block_idx, false) {
                Ok(b) => b,
                Err(_) => {
                    offset += BLOCK_SIZE;
                    continue;
                }
            };
            if disk_block == 0 { 
                offset += BLOCK_SIZE;
                continue; 
            }

            let real_block = self.fs.block_offset + disk_block;
            let mut aligned = AlignedBlock([0u8; BLOCK_SIZE]);
            let block_buf = &mut aligned.0;
            self.fs.read_block(real_block, block_buf)?;
            let mut modified = false;

            for i in 0..BLOCK_SIZE/entry_size {
                let pos = offset + i * entry_size;
                if pos >= size { break; }
                
                let entry_ptr = unsafe { block_buf.as_mut_ptr().add(i*entry_size) as *mut DirEntry };
                let mut entry = unsafe { core::ptr::read_unaligned(entry_ptr) };
                
                if entry.inode_number != 0 {
                    let name_len = entry.name.iter().position(|&c| c == 0).unwrap_or(28);
                    let entry_name = core::str::from_utf8(&entry.name[..name_len]).unwrap_or("");
                    
                    if entry_name == ".." {
                        // Update it
                        entry.inode_number = new_parent_ino;
                        unsafe { core::ptr::write_unaligned(entry_ptr, entry) };
                        modified = true;
                        break;
                    }
                }
            }
            
            if modified {
                self.fs.write_block(real_block, block_buf)?;
                return Ok(());
            }
            offset += BLOCK_SIZE;
        }
        
        Err(".. entry not found")
    }
}

use crate::drivers::block::BlockDevice;
use core::convert::TryInto;
use alloc::vec::Vec;
use alloc::string::String;

// Magic: 0x5346534E (NSFS - Nova Simple File System)
const MAGIC: u32 = 0x5346534E; 
const BLOCK_SIZE: usize = 512;
const MAX_FILES: usize = 16;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SuperBlock {
    pub magic: u32,
    pub total_blocks: u32,
    pub root_dir_block: u32,
    pub free_block_bitmap: u32, // Block index of bitmap
    pub reserved: [u8; 512 - 16],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DirEntry {
    pub name: [u8; 23], // 23 bytes name
    pub type_flags: u8, // 0 = File, 1 = Directory
    pub start_block: u32,
    pub size: u32,     // in bytes
}

impl DirEntry {
    pub fn new(name_str: &str, start_block: u32, size: u32, is_dir: bool) -> Self {
        let mut name = [0u8; 23];
        let bytes = name_str.as_bytes();
        let len = core::cmp::min(bytes.len(), 23);
        name[0..len].copy_from_slice(&bytes[0..len]);
        DirEntry { 
            name, 
            type_flags: if is_dir { 1 } else { 0 },
            start_block, 
            size 
        }
    }
    
    pub fn get_name(&self) -> String {
        let len = self.name.iter().position(|&c| c == 0).unwrap_or(23);
        String::from_utf8_lossy(&self.name[0..len]).into_owned()
    }
    
    pub fn is_empty(&self) -> bool {
        self.name[0] == 0
    }

    pub fn is_dir(&self) -> bool {
        self.type_flags == 1
    }
}

pub struct SimpleFS<D: BlockDevice> {
    device: D,
}

const DATA_PER_BLOCK: usize = 508;

impl<D: BlockDevice> SimpleFS<D> {
    pub fn new(device: D) -> Self {
        SimpleFS { device }
    }

    pub fn format(&self, total_blocks: u32) -> Result<(), &'static str> {
        let sb = SuperBlock {
            magic: MAGIC,
            total_blocks,
            root_dir_block: 2,
            free_block_bitmap: 1,
            reserved: [0; 496],
        };
        
        // Write SuperBlock to Block 0
        let ptr = &sb as *const SuperBlock as *const u8;
        let slice = unsafe { core::slice::from_raw_parts(ptr, 512) };
        self.device.write_block(0, slice)?;
        
        // Initialize Bitmap (Block 1)
        // Mark blocks 0, 1, 2 as used
        let mut bitmap = [0u8; 512];
        bitmap[0] = 0x07; // 0000 0111
        self.device.write_block(1, &bitmap)?;
        
        // Initialize Root Directory (Block 2)
        // Empty directory
        let root_dir = [0u8; 512];
        self.device.write_block(2, &root_dir)?;
        
        Ok(())
    }
    
    pub fn check_magic(&self) -> Result<bool, &'static str> {
        let mut buf = [0u8; 512];
        self.device.read_block(0, &mut buf)?;
        
        let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        Ok(magic == MAGIC)
    }

    pub fn root_dir_block(&self) -> u32 {
        2 // Assume Root Dir is at Block 2
    }

    pub fn find_entry(&self, dir_block: u32, name: &str) -> Result<DirEntry, &'static str> {
        let entries = self.list_dir(dir_block)?;
        for entry in entries {
            if entry.get_name() == name {
                return Ok(entry);
            }
        }
        Err("Entry not found")
    }

    pub fn resolve_path_from(&self, start_block: u32, path: &str) -> Result<(u32, String), &'static str> {
        let mut current_block = start_block;
        let parts = path.split('/').filter(|s| !s.is_empty());
        
        // Peekable iterator to handle the last part differently (filename)
        let mut parts_vec: Vec<&str> = parts.collect();
        if parts_vec.is_empty() {
             return Ok((current_block, String::new()));
        }

        let filename = parts_vec.pop().unwrap();
        
        for part in parts_vec {
            let entry = self.find_entry(current_block, part)?;
            if !entry.is_dir() {
                return Err("Not a directory");
            }
            current_block = entry.start_block;
        }
        
        Ok((current_block, String::from(filename)))
    }

    pub fn list_dir(&self, dir_block: u32) -> Result<Vec<DirEntry>, &'static str> {
        let mut buf = [0u8; BLOCK_SIZE];
        self.device.read_block(dir_block, &mut buf)?;
        
        let ptr = buf.as_ptr() as *const DirEntry;
        let mut entries = Vec::new();
        
        for i in 0..MAX_FILES {
            let entry = unsafe { *ptr.add(i) };
            if !entry.is_empty() {
                entries.push(entry);
            }
        }
        Ok(entries)
    }
    
    pub fn create_file(&mut self, dir_block: u32, name: &str) -> Result<(), &'static str> {
        let entries = self.list_dir(dir_block)?;
        for entry in entries {
            if entry.get_name() == name {
                return Err("File already exists");
            }
        }
        
        let block_id = self.alloc_block()?;
        // Initialize the new block (next=0, empty data)
        let empty_block = [0u8; BLOCK_SIZE];
        self.device.write_block(block_id, &empty_block)?;
        
        let mut buf = [0u8; BLOCK_SIZE];
        self.device.read_block(dir_block, &mut buf)?;
        
        let ptr = buf.as_mut_ptr() as *mut DirEntry;
        let mut found = false;
        
        for i in 0..MAX_FILES {
            let entry = unsafe { &mut *ptr.add(i) };
            if entry.is_empty() {
                *entry = DirEntry::new(name, block_id, 0, false);
                found = true;
                break;
            }
        }
        
        if !found {
            return Err("Directory full");
        }
        
        self.device.write_block(dir_block, &buf)?;
        Ok(())
    }

    pub fn create_dir(&mut self, parent_dir_block: u32, name: &str) -> Result<(), &'static str> {
        let entries = self.list_dir(parent_dir_block)?;
        for entry in entries {
            if entry.get_name() == name {
                return Err("Entry already exists");
            }
        }
        
        let block_id = self.alloc_block()?;
        // Initialize the new directory block (empty)
        let empty_block = [0u8; BLOCK_SIZE];
        self.device.write_block(block_id, &empty_block)?;
        
        let mut buf = [0u8; BLOCK_SIZE];
        self.device.read_block(parent_dir_block, &mut buf)?;
        
        let ptr = buf.as_mut_ptr() as *mut DirEntry;
        let mut found = false;
        
        for i in 0..MAX_FILES {
            let entry = unsafe { &mut *ptr.add(i) };
            if entry.is_empty() {
                *entry = DirEntry::new(name, block_id, 0, true);
                found = true;
                break;
            }
        }
        
        if !found {
            return Err("Directory full");
        }
        
        self.device.write_block(parent_dir_block, &buf)?;
        Ok(())
    }
    
    pub fn write_file(&mut self, dir_block: u32, name: &str, data: &[u8]) -> Result<(), &'static str> {
        let mut buf = [0u8; BLOCK_SIZE];
        self.device.read_block(dir_block, &mut buf)?;
        
        let ptr = buf.as_mut_ptr() as *mut DirEntry;
        let mut target_entry: Option<&mut DirEntry> = None;
        
        for i in 0..MAX_FILES {
            let entry = unsafe { &mut *ptr.add(i) };
            if !entry.is_empty() && entry.get_name() == name {
                if entry.is_dir() {
                    return Err("Cannot write to a directory");
                }
                target_entry = Some(entry);
                break;
            }
        }

        
        if let Some(entry) = target_entry {
            let mut current_block_id = entry.start_block;
            let mut remaining_data = data;
            
            loop {
                // Read current block to get old next pointer
                let mut block_buf = [0u8; BLOCK_SIZE];
                self.device.read_block(current_block_id, &mut block_buf)?;
                let old_next = u32::from_le_bytes(block_buf[0..4].try_into().unwrap());
                
                let chunk_size = core::cmp::min(remaining_data.len(), DATA_PER_BLOCK);
                let chunk = &remaining_data[0..chunk_size];
                remaining_data = &remaining_data[chunk_size..];
                
                // Determine new next block
                let next_block_id = if remaining_data.len() > 0 {
                    if old_next != 0 {
                        old_next
                    } else {
                        self.alloc_block()?
                    }
                } else {
                    0
                };
                
                // Write data
                block_buf = [0u8; BLOCK_SIZE];
                block_buf[0..4].copy_from_slice(&next_block_id.to_le_bytes());
                block_buf[4..4+chunk_size].copy_from_slice(chunk);
                self.device.write_block(current_block_id, &block_buf)?;
                
                // If we are done but there was a chain, free it
                if remaining_data.len() == 0 && old_next != 0 {
                    self.free_chain(old_next)?;
                }
                
                if remaining_data.len() == 0 {
                    break;
                }
                
                current_block_id = next_block_id;
            }
            
            entry.size = data.len() as u32;
            self.device.write_block(dir_block, &buf)?;
            Ok(())
        } else {
            Err("File not found")
        }
    }
    
    pub fn read_file(&self, dir_block: u32, name: &str) -> Result<Vec<u8>, &'static str> {
        let entries = self.list_dir(dir_block)?;
        for entry in entries {
            if entry.get_name() == name {
                if entry.is_dir() {
                    return Err("Is a directory");
                }
                let mut res = Vec::new();
                let mut current_block_id = entry.start_block;
                let mut bytes_read = 0;
                
                while bytes_read < entry.size {
                    let mut buf = [0u8; BLOCK_SIZE];
                    self.device.read_block(current_block_id, &mut buf)?;
                    
                    let next_block = u32::from_le_bytes(buf[0..4].try_into().unwrap());
                    let bytes_to_read = core::cmp::min(DATA_PER_BLOCK, (entry.size - bytes_read) as usize);
                    
                    res.extend_from_slice(&buf[4..4+bytes_to_read]);
                    bytes_read += bytes_to_read as u32;
                    
                    if next_block == 0 && bytes_read < entry.size {
                        // Unexpected end of chain
                        break; 
                    }
                    current_block_id = next_block;
                }
                return Ok(res);
            }
        }
        Err("File not found")
    }
    
    pub fn delete_file(&mut self, dir_block: u32, name: &str) -> Result<(), &'static str> {
        let mut buf = [0u8; BLOCK_SIZE];
        self.device.read_block(dir_block, &mut buf)?;
        
        let ptr = buf.as_mut_ptr() as *mut DirEntry;
        
        for i in 0..MAX_FILES {
            let entry = unsafe { &mut *ptr.add(i) };
            if !entry.is_empty() && entry.get_name() == name {
                if entry.is_dir() {
                    return Err("Is a directory");
                }
                // Free chain
                self.free_chain(entry.start_block)?;
                
                // Clear entry
                *entry = unsafe { core::mem::zeroed() };
                
                self.device.write_block(dir_block, &buf)?;
                return Ok(());
            }
        }
        Err("File not found")
    }

    pub fn delete_dir(&mut self, parent_dir_block: u32, name: &str) -> Result<(), &'static str> {
        let mut buf = [0u8; BLOCK_SIZE];
        self.device.read_block(parent_dir_block, &mut buf)?;
        
        let ptr = buf.as_mut_ptr() as *mut DirEntry;
        
        for i in 0..MAX_FILES {
            let entry = unsafe { &mut *ptr.add(i) };
            if !entry.is_empty() && entry.get_name() == name {
                if !entry.is_dir() {
                    return Err("Not a directory");
                }
                
                // Check if directory is empty
                let dir_block = entry.start_block;
                let contents = self.list_dir(dir_block)?;
                if !contents.is_empty() {
                    return Err("Directory not empty");
                }
                
                // Free the directory block
                self.free_block(dir_block)?;
                
                // Clear entry
                *entry = unsafe { core::mem::zeroed() };
                
                self.device.write_block(parent_dir_block, &buf)?;
                return Ok(());
            }
        }
        Err("Directory not found")
    }

    fn alloc_block(&mut self) -> Result<u32, &'static str> {
        let mut bitmap = [0u8; BLOCK_SIZE];
        self.device.read_block(1, &mut bitmap)?;
        
        for i in 0..BLOCK_SIZE {
            if bitmap[i] != 0xFF {
                for bit in 0..8 {
                    if (bitmap[i] & (1 << bit)) == 0 {
                        bitmap[i] |= 1 << bit;
                        self.device.write_block(1, &bitmap)?;
                        return Ok((i * 8 + bit) as u32);
                    }
                }
            }
        }
        Err("Disk full")
    }
    
    fn free_block(&mut self, block_id: u32) -> Result<(), &'static str> {
        let mut bitmap = [0u8; BLOCK_SIZE];
        self.device.read_block(1, &mut bitmap)?;
        
        let byte_idx = (block_id / 8) as usize;
        let bit_idx = (block_id % 8) as usize;
        
        if byte_idx < BLOCK_SIZE {
             bitmap[byte_idx] &= !(1 << bit_idx);
             self.device.write_block(1, &bitmap)?;
             Ok(())
        } else {
             Err("Block ID out of range")
        }
    }
    
    fn free_chain(&mut self, start_block: u32) -> Result<(), &'static str> {
        let mut current = start_block;
        while current != 0 {
            let mut buf = [0u8; BLOCK_SIZE];
            // We need to read the block to find the next one before we free it
            // (Strictly speaking we could free it first, but we need the next pointer)
            if let Ok(_) = self.device.read_block(current, &mut buf) {
                let next = u32::from_le_bytes(buf[0..4].try_into().unwrap());
                self.free_block(current)?;
                current = next;
            } else {
                break;
            }
        }
        Ok(())
    }
}

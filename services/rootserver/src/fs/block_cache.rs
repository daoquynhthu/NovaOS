use alloc::vec::Vec;
use alloc::sync::Arc;
use crate::drivers::block::BlockDevice;
use crate::fs::strategy::{IOStrategy, create_strategy};

const CACHE_SIZE: usize = 32; // 32 * 512B = 16KB
const BLOCK_SIZE: usize = 512;

struct CacheEntry {
    block_id: u32,
    data: [u8; BLOCK_SIZE],
    dirty: bool,
    valid: bool,
    last_used: u64,
}

impl CacheEntry {
    fn new() -> Self {
        Self {
            block_id: 0,
            data: [0u8; BLOCK_SIZE],
            dirty: false,
            valid: false,
            last_used: 0,
        }
    }
}

pub struct BlockCache<D: BlockDevice + Send + Sync + 'static> {
    entries: Vec<CacheEntry>,
    device: Arc<D>,
    tick: u64,
    strategy: alloc::boxed::Box<dyn IOStrategy>,
}

impl<D: BlockDevice + Send + Sync + 'static> BlockCache<D> {
    pub fn new(device: Arc<D>) -> Self {
        let mut entries = Vec::with_capacity(CACHE_SIZE);
        for _ in 0..CACHE_SIZE {
            entries.push(CacheEntry::new());
        }
        
        let is_rotational = device.is_rotational();
        let strategy = create_strategy(is_rotational);
        println!("[BlockCache] Using Strategy: {}", strategy.name());
        
        Self {
            entries,
            device,
            tick: 0,
            strategy,
        }
    }

    pub fn read_block(&mut self, block_id: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        self.tick += 1;
        
        // 1. Search in cache
        if let Some(idx) = self.find_index(block_id) {
            self.entries[idx].last_used = self.tick;
            buf.copy_from_slice(&self.entries[idx].data);
            return Ok(());
        }

        // 2. Cache Miss
        let idx = self.find_victim();
        
        // Write back if dirty
        if self.entries[idx].valid && self.entries[idx].dirty {
            self.device.write_block(self.entries[idx].block_id, &self.entries[idx].data)?;
            self.entries[idx].dirty = false;
        }

        // Load new block
        self.device.read_block(block_id, &mut self.entries[idx].data)?;
        self.entries[idx].block_id = block_id;
        self.entries[idx].valid = true;
        self.entries[idx].dirty = false;
        self.entries[idx].last_used = self.tick;
        
        buf.copy_from_slice(&self.entries[idx].data);
        Ok(())
    }

    pub fn write_block(&mut self, block_id: u32, buf: &[u8]) -> Result<(), &'static str> {
        self.tick += 1;

        // 1. Search in cache
        if let Some(idx) = self.find_index(block_id) {
            self.entries[idx].last_used = self.tick;
            self.entries[idx].data.copy_from_slice(buf);
            self.entries[idx].dirty = true;
            return Ok(());
        }

        // 2. Cache Miss - Find victim
        let idx = self.find_victim();
        
        if self.entries[idx].valid && self.entries[idx].dirty {
            self.device.write_block(self.entries[idx].block_id, &self.entries[idx].data)?;
        }
        
        // We overwrite the data completely, so no need to read from disk (assuming full block write)
        self.entries[idx].block_id = block_id;
        self.entries[idx].data.copy_from_slice(buf);
        self.entries[idx].valid = true;
        self.entries[idx].dirty = true;
        self.entries[idx].last_used = self.tick;
        
        Ok(())
    }

    pub fn sync(&mut self) -> Result<(), &'static str> {
        let mut dirty_blocks = Vec::new();
        for entry in &self.entries {
            if entry.valid && entry.dirty {
                dirty_blocks.push(entry.block_id);
            }
        }
        
        if dirty_blocks.is_empty() {
            return Ok(());
        }

        let scheduled_blocks = self.strategy.schedule(&dirty_blocks);
        
        for block_id in scheduled_blocks {
             if let Some(idx) = self.find_index(block_id) {
                 if self.entries[idx].valid && self.entries[idx].dirty {
                     self.device.write_block(block_id, &self.entries[idx].data)?;
                     self.entries[idx].dirty = false;
                 }
             }
        }
        Ok(())
    }


    fn find_index(&self, block_id: u32) -> Option<usize> {
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.valid && entry.block_id == block_id {
                return Some(i);
            }
        }
        None
    }

    fn find_victim(&self) -> usize {
        // Find entry with smallest last_used
        let mut min_tick = u64::MAX;
        let mut victim_idx = 0;
        
        // First pass: look for invalid entries
        for (i, entry) in self.entries.iter().enumerate() {
            if !entry.valid {
                return i;
            }
            if entry.last_used < min_tick {
                min_tick = entry.last_used;
                victim_idx = i;
            }
        }
        victim_idx
    }
}

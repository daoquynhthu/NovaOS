pub trait BlockDevice {
    fn read_block(&self, block_id: u32, buf: &mut [u8]) -> Result<(), &'static str>;
    fn write_block(&self, block_id: u32, buf: &[u8]) -> Result<(), &'static str>;
    fn is_rotational(&self) -> bool {
        true
    } // Default to HDD
}

#[cfg(any(test, feature = "std"))]
/// In-memory block device for host-native testing.
pub struct MockBlockDevice {
    blocks: spin::Mutex<alloc::vec::Vec<[u8; 512]>>,
    rotational: bool,
}

#[cfg(any(test, feature = "std"))]
impl MockBlockDevice {
    pub fn new(num_blocks: usize) -> Self {
        let mut blocks = alloc::vec::Vec::with_capacity(num_blocks);
        for _ in 0..num_blocks {
            blocks.push([0u8; 512]);
        }
        Self {
            blocks: spin::Mutex::new(blocks),
            rotational: false,
        }
    }

    pub fn with_rotational(num_blocks: usize, rotational: bool) -> Self {
        let mut dev = Self::new(num_blocks);
        dev.rotational = rotational;
        dev
    }

    pub fn snapshot(&self) -> alloc::vec::Vec<[u8; 512]> {
        self.blocks.lock().clone()
    }

    pub fn from_snapshot(blocks: alloc::vec::Vec<[u8; 512]>) -> Self {
        Self {
            blocks: spin::Mutex::new(blocks),
            rotational: false,
        }
    }
}

#[cfg(any(test, feature = "std"))]
impl BlockDevice for MockBlockDevice {
    fn read_block(&self, block_id: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        let blocks = self.blocks.lock();
        let idx = block_id as usize;
        if idx >= blocks.len() {
            return Err("MockBlockDevice: block out of range");
        }
        if buf.len() != 512 {
            return Err("MockBlockDevice: buffer size must be 512");
        }
        buf.copy_from_slice(&blocks[idx]);
        Ok(())
    }

    fn write_block(&self, block_id: u32, buf: &[u8]) -> Result<(), &'static str> {
        let mut blocks = self.blocks.lock();
        let idx = block_id as usize;
        if idx >= blocks.len() {
            return Err("MockBlockDevice: block out of range");
        }
        if buf.len() != 512 {
            return Err("MockBlockDevice: buffer size must be 512");
        }
        blocks[idx].copy_from_slice(buf);
        Ok(())
    }

    fn is_rotational(&self) -> bool {
        self.rotational
    }
}

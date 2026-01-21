pub trait BlockDevice {
    fn read_block(&self, block_id: u32, buf: &mut [u8]) -> Result<(), &'static str>;
    fn write_block(&self, block_id: u32, buf: &[u8]) -> Result<(), &'static str>;
    fn is_rotational(&self) -> bool { true } // Default to HDD
}

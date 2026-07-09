//! ATA PIO disk driver implementing `BlockDevice`.
//!
//! Uses `libnova::arch::x86_64::port_io` for port I/O. The ATA I/O port
//! capability must be installed in the process's CNode and `port_io::init()`
//! must be called before using this driver.

use crate::block_device::BlockDevice;

// Relative port offsets from port_base (typically 0x1F0)
const ATA_DATA: u16 = 0;
#[allow(dead_code)]
const ATA_ERROR: u16 = 1;
const ATA_SECTOR_COUNT: u16 = 2;
const ATA_LBA_LOW: u16 = 3;
const ATA_LBA_MID: u16 = 4;
const ATA_LBA_HIGH: u16 = 5;
const ATA_DRIVE_HEAD: u16 = 6;
const ATA_STATUS: u16 = 7;
const ATA_COMMAND: u16 = 7;

const ATA_CMD_READ_PIO: u8 = 0x20;
const ATA_CMD_WRITE_PIO: u8 = 0x30;
#[allow(dead_code)]
const ATA_CMD_CACHE_FLUSH: u8 = 0xE7;

const STATUS_BSY: u8 = 0x80;
#[allow(dead_code)]
const STATUS_DRQ: u8 = 0x08;
const STATUS_ERR: u8 = 0x01;

pub struct AtaBlockDevice {
    pub port_base: u16,
    pub sector_count: u64,
}

impl AtaBlockDevice {
    pub fn new(port_base: u16) -> Self {
        Self {
            port_base,
            sector_count: 0,
        }
    }

    pub fn detect(&mut self) -> Result<(), &'static str> {
        self.identify()
    }

    fn identify(&mut self) -> Result<(), &'static str> {
        self.write(ATA_DRIVE_HEAD, 0xE0);
        self.write(ATA_SECTOR_COUNT, 0);
        self.write(ATA_LBA_LOW, 0);
        self.write(ATA_LBA_MID, 0);
        self.write(ATA_LBA_HIGH, 0);
        self.command(ATA_CMD_IDENTIFY);

        if self.read(ATA_STATUS) == 0 {
            return Err("No ATA drive found");
        }

        self.poll(false)?;

        let mut buf = [0u16; 256];
        for i in 0..256 {
            buf[i] = self.readw(ATA_DATA);
        }

        self.sector_count = u64::from(buf[61]) << 16 | u64::from(buf[60]);
        Ok(())
    }

    fn read(&self, port: u16) -> u8 {
        libnova::arch::x86_64::port_io::inb(self.port_base + port)
    }

    fn readw(&self, port: u16) -> u16 {
        libnova::arch::x86_64::port_io::inw(self.port_base + port)
    }

    fn write(&self, port: u16, value: u8) {
        libnova::arch::x86_64::port_io::outb(self.port_base + port, value);
    }

    fn command(&self, cmd: u8) {
        libnova::arch::x86_64::port_io::outb(self.port_base + ATA_COMMAND, cmd);
    }

    fn poll(&self, check_for_error: bool) -> Result<(), &'static str> {
        for _ in 0..100 {
            let status = self.read(ATA_STATUS);
            if status & STATUS_BSY == 0 {
                if check_for_error && status & STATUS_ERR != 0 {
                    return Err("ATA error");
                }
                return Ok(());
            }
        }
        Err("ATA timeout")
    }

    fn read_sectors(&self, lba: u32, count: u8, buf: &mut [u8]) -> Result<(), &'static str> {
        self.write(ATA_DRIVE_HEAD, 0xE0 | ((lba >> 24) & 0x0F) as u8);
        self.write(ATA_SECTOR_COUNT, count);
        self.write(ATA_LBA_LOW, (lba & 0xFF) as u8);
        self.write(ATA_LBA_MID, ((lba >> 8) & 0xFF) as u8);
        self.write(ATA_LBA_HIGH, ((lba >> 16) & 0xFF) as u8);
        self.command(ATA_CMD_READ_PIO);

        for sector in 0..count as usize {
            self.poll(true)?;
            for i in 0..256 {
                let word = self.readw(ATA_DATA);
                let offset = sector * 512 + i * 2;
                if offset + 1 < buf.len() {
                    buf[offset] = (word & 0xFF) as u8;
                    if offset + 1 < buf.len() {
                        buf[offset + 1] = ((word >> 8) & 0xFF) as u8;
                    }
                }
            }
        }
        Ok(())
    }

    fn write_sectors(&self, lba: u32, count: u8, buf: &[u8]) -> Result<(), &'static str> {
        self.write(ATA_DRIVE_HEAD, 0xE0 | ((lba >> 24) & 0x0F) as u8);
        self.write(ATA_SECTOR_COUNT, count);
        self.write(ATA_LBA_LOW, (lba & 0xFF) as u8);
        self.write(ATA_LBA_MID, ((lba >> 8) & 0xFF) as u8);
        self.write(ATA_LBA_HIGH, ((lba >> 16) & 0xFF) as u8);
        self.command(ATA_CMD_WRITE_PIO);

        for sector in 0..count as usize {
            self.poll(false)?;
            for i in 0..256 {
                let offset = sector * 512 + i * 2;
                let low = if offset < buf.len() { buf[offset] } else { 0 };
                let high = if offset + 1 < buf.len() { buf[offset + 1] } else { 0 };
                let word = u16::from(low) | (u16::from(high) << 8);
                libnova::arch::x86_64::port_io::outw(self.port_base + ATA_DATA, word);
            }
        }
        Ok(())
    }
}

impl BlockDevice for AtaBlockDevice {
    fn read_block(&self, block_id: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        if buf.len() != 512 {
            return Err("Buffer size must be 512 bytes");
        }
        self.read_sectors(block_id, 1, buf)
    }

    fn write_block(&self, block_id: u32, buf: &[u8]) -> Result<(), &'static str> {
        if buf.len() != 512 {
            return Err("Buffer size must be 512 bytes");
        }
        self.write_sectors(block_id, 1, buf)
    }

    fn is_rotational(&self) -> bool {
        true
    }
}

const ATA_CMD_IDENTIFY: u8 = 0xEC;

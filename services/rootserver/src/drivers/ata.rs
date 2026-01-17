use crate::arch::port_io::{inb, outb, inw, outw};
use alloc::vec::Vec;

#[allow(dead_code)]
const ATA_DATA: u16 = 0x1F0;
#[allow(dead_code)]
const ATA_ERROR: u16 = 0x1F1;
#[allow(dead_code)]
const ATA_SECTOR_COUNT: u16 = 0x1F2;
#[allow(dead_code)]
const ATA_LBA_LOW: u16 = 0x1F3;
#[allow(dead_code)]
const ATA_LBA_MID: u16 = 0x1F4;
#[allow(dead_code)]
const ATA_LBA_HIGH: u16 = 0x1F5;
#[allow(dead_code)]
const ATA_DRIVE_HEAD: u16 = 0x1F6;
#[allow(dead_code)]
const ATA_STATUS: u16 = 0x1F7;
#[allow(dead_code)]
const ATA_COMMAND: u16 = 0x1F7;

const ATA_CMD_READ_PIO: u8 = 0x20;
const ATA_CMD_WRITE_PIO: u8 = 0x30;
const ATA_CMD_CACHE_FLUSH: u8 = 0xE7;
#[allow(dead_code)]
const ATA_CMD_IDENTIFY: u8 = 0xEC;

const STATUS_BSY: u8 = 0x80;
const STATUS_DRQ: u8 = 0x08;
const STATUS_ERR: u8 = 0x01;

pub struct AtaDriver {
    pub port_base: u16,
    pub sector_count: u64, // Detected via IDENTIFY
    pub model: [u8; 40],
}

use crate::drivers::block::BlockDevice;

impl BlockDevice for AtaDriver {
    fn read_block(&self, block_id: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        if block_id as u64 >= self.sector_count && self.sector_count > 0 {
             return Err("Block ID out of range");
        }
        self.read_sectors_into(block_id, 1, buf)
    }

    fn write_block(&self, block_id: u32, buf: &[u8]) -> Result<(), &'static str> {
        if block_id as u64 >= self.sector_count && self.sector_count > 0 {
             return Err("Block ID out of range");
        }
        if buf.len() != 512 {
            return Err("Buffer size must be 512 bytes");
        }
        self.write_sectors(block_id, buf)
    }
}

impl AtaDriver {
    pub fn new(port_base: u16) -> Self {
        AtaDriver { 
            port_base,
            sector_count: 0,
            model: [0; 40],
        }
    }
    
    pub fn init(&mut self) -> Result<(), &'static str> {
        self.identify()
    }

    fn identify(&mut self) -> Result<(), &'static str> {
        // Select Drive (Master)
        outb(self.port_base + 6, 0xA0);
        // Zero Sector Count and LBA
        outb(self.port_base + 2, 0);
        outb(self.port_base + 3, 0);
        outb(self.port_base + 4, 0);
        outb(self.port_base + 5, 0);
        
        // Send IDENTIFY
        outb(self.port_base + 7, ATA_CMD_IDENTIFY);
        
        let status = inb(self.port_base + 7);
        if status == 0 {
            return Err("Drive does not exist");
        }
        
        self.wait_bsy()?;
        
        let status2 = inb(self.port_base + 7);
        if status2 & STATUS_ERR != 0 {
             return Err("Drive Error after IDENTIFY");
        }
        
        self.wait_drq()?;
        
        // Read 256 words
        let mut data = [0u16; 256];
        for i in 0..256 {
            data[i] = inw(self.port_base);
        }
        
        // Extract Model (words 27-46)
        for i in 0..20 {
            let word = data[27 + i];
            // Swap bytes for ASCII string
            self.model[i * 2] = (word >> 8) as u8;
            self.model[i * 2 + 1] = (word & 0xFF) as u8;
        }
        
        // Extract LBA28 sectors (word 60-61)
        let lba28_sectors = (data[60] as u32) | ((data[61] as u32) << 16);
        // Extract LBA48 sectors (word 100-103) if supported
        let supports_lba48 = (data[83] & (1 << 10)) != 0;
        
        if supports_lba48 {
            let lba48_sectors = (data[100] as u64) | 
                                ((data[101] as u64) << 16) | 
                                ((data[102] as u64) << 32) | 
                                ((data[103] as u64) << 48);
            self.sector_count = lba48_sectors;
        } else {
            self.sector_count = lba28_sectors as u64;
        }
        
        println!("[ATA] Drive Identified: Model='{}', Sectors={}, Size={}MB", 
            core::str::from_utf8(&self.model).unwrap_or("Unknown").trim(),
            self.sector_count,
            (self.sector_count * 512) / 1024 / 1024
        );
        
        Ok(())
    }

    fn wait_bsy(&self) -> Result<(), &'static str> {
        // Simple spin wait with timeout
        for _ in 0..100000000 {
            if inb(self.port_base + 7) & STATUS_BSY == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err("ATA BSY Timeout")
    }

    fn wait_drq(&self) -> Result<(), &'static str> {
        for _ in 0..100000000 {
            let status = inb(self.port_base + 7);
            if status & STATUS_ERR != 0 {
                return Err("ATA Error");
            }
            if status & STATUS_DRQ != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err("ATA DRQ Timeout")
    }

    fn delay_400ns(&self) {
        inb(self.port_base + 7);
        inb(self.port_base + 7);
        inb(self.port_base + 7);
        inb(self.port_base + 7);
    }

    pub fn read_sectors_into(&self, lba: u32, sectors: u8, buf: &mut [u8]) -> Result<(), &'static str> {
        if buf.len() != sectors as usize * 512 {
            return Err("Buffer size mismatch");
        }

        self.wait_bsy()?;
        
        // Select Drive (Master) and LBA bits 24-27
        outb(self.port_base + 6, 0xE0 | ((lba >> 24) as u8 & 0x0F));
        
        outb(self.port_base + 2, sectors);
        outb(self.port_base + 3, lba as u8);
        outb(self.port_base + 4, (lba >> 8) as u8);
        outb(self.port_base + 5, (lba >> 16) as u8);
        
        outb(self.port_base + 7, ATA_CMD_READ_PIO);
        self.delay_400ns();

        let mut buf_idx = 0;
        for _ in 0..sectors {
            self.wait_bsy()?;
            self.wait_drq()?;
            
            // Read 256 words
            for _ in 0..256 {
                let word = inw(self.port_base);
                buf[buf_idx] = (word & 0xFF) as u8;
                buf[buf_idx+1] = (word >> 8) as u8;
                buf_idx += 2;
            }
        }
        Ok(())
    }

    pub fn read_sectors(&self, lba: u32, sectors: u8) -> Result<Vec<u8>, &'static str> {
        let mut data = alloc::vec![0u8; sectors as usize * 512];
        self.read_sectors_into(lba, sectors, &mut data)?;
        Ok(data)
    }

    pub fn write_sectors(&self, lba: u32, data: &[u8]) -> Result<(), &'static str> {
        let sectors = (data.len() / 512) as u8;
        if sectors == 0 { return Ok(()); }
        if data.len() % 512 != 0 { return Err("Data length must be multiple of 512"); }

        self.wait_bsy()?;
        
        outb(self.port_base + 6, 0xE0 | ((lba >> 24) as u8 & 0x0F));
        outb(self.port_base + 2, sectors);
        outb(self.port_base + 3, lba as u8);
        outb(self.port_base + 4, (lba >> 8) as u8);
        outb(self.port_base + 5, (lba >> 16) as u8);
        
        outb(self.port_base + 7, ATA_CMD_WRITE_PIO);
        self.delay_400ns();

        for i in 0..sectors as usize {
            self.wait_bsy()?;
            self.wait_drq()?;

            for j in 0..256 {
                let offset = i * 512 + j * 2;
                let word = (data[offset] as u16) | ((data[offset+1] as u16) << 8);
                outw(self.port_base, word);
            }
        }
        
        outb(self.port_base + 7, ATA_CMD_CACHE_FLUSH);
        self.wait_bsy()?;
        
        Ok(())
    }
}

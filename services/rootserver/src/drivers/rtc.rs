use crate::arch::port_io::{outb, inb};
use super::{Driver, DriverEvent};

// CMOS Ports
const CMOS_ADDRESS: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

pub struct RtcDriver {
}

impl RtcDriver {
    pub fn new() -> Self {
        RtcDriver {}
    }

    fn read_register(&self, reg: u8) -> u8 {
        outb(CMOS_ADDRESS, reg);
        inb(CMOS_DATA)
    }

    fn get_update_in_progress_flag(&self) -> bool {
        (self.read_register(0x0A) & 0x80) != 0
    }

    pub fn read_time(&self) -> (u8, u8, u8) {
        // Wait for update to finish
        while self.get_update_in_progress_flag() {}

        let mut second = self.read_register(0x00);
        let mut minute = self.read_register(0x02);
        let mut hour = self.read_register(0x04);
        
        let register_b = self.read_register(0x0B);

        // Convert BCD to binary if needed
        if (register_b & 0x04) == 0 {
            second = (second & 0x0F) + ((second / 16) * 10);
            minute = (minute & 0x0F) + ((minute / 16) * 10);
            hour = ((hour & 0x0F) + (((hour & 0x70) / 16) * 10)) | (hour & 0x80);
        }

        // Convert 12 hour to 24 hour if needed
        if (register_b & 0x02) == 0 && (hour & 0x80) != 0 {
            hour = ((hour & 0x7F) + 12) % 24;
        }
        
        (hour, minute, second)
    }
    
    pub fn read_date(&self) -> (u8, u8, u16) {
         while self.get_update_in_progress_flag() {}
         
         let mut day = self.read_register(0x07);
         let mut month = self.read_register(0x08);
         let mut year = self.read_register(0x09);
         let register_b = self.read_register(0x0B);
         
         if (register_b & 0x04) == 0 {
            day = (day & 0x0F) + ((day / 16) * 10);
            month = (month & 0x0F) + ((month / 16) * 10);
            year = (year & 0x0F) + ((year / 16) * 10);
         }
         
         // Century register? ACPI FADT has it.
         // Assume 20xx for now.
         let full_year = 2000 + year as u16;
         
         (day, month, full_year)
    }

    pub fn get_unix_timestamp(&self) -> u64 {
        let (d, m, y) = self.read_date();
        let (h, min, s) = self.read_time();
        
        // Simple conversion to unix timestamp
        // 1970-01-01 00:00:00 UTC
        
        let mut days = 0u64;
        
        // Years
        for curr_y in 1970..y {
            if (curr_y % 4 == 0 && curr_y % 100 != 0) || (curr_y % 400 == 0) {
                days += 366;
            } else {
                days += 365;
            }
        }
        
        // Months
        let is_leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        let days_in_month = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        
        for i in 1..m {
            if i == 2 && is_leap {
                days += 29;
            } else {
                days += days_in_month[i as usize];
            }
        }
        
        days += (d - 1) as u64;
        
        let total_seconds = days * 86400 + h as u64 * 3600 + min as u64 * 60 + s as u64;
        total_seconds
    }
}

impl Driver for RtcDriver {
    fn name(&self) -> &str {
        "CMOS RTC"
    }

    fn init(&mut self) -> Result<(), &'static str> {
        // We could enable IRQ 8 here
        Ok(())
    }

    fn handle_irq(&mut self, _irq: u8) -> alloc::vec::Vec<DriverEvent> {
        // If we enabled IRQ 8, we would read Register C to clear it.
        // self.read_register(0x0C);
        alloc::vec::Vec::new()
    }
}

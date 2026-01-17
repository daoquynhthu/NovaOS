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
}

impl Driver for RtcDriver {
    fn name(&self) -> &str {
        "CMOS RTC"
    }

    fn init(&mut self) -> Result<(), &'static str> {
        // We could enable IRQ 8 here
        Ok(())
    }

    fn handle_irq(&mut self, _irq: u8) -> DriverEvent {
        // If we enabled IRQ 8, we would read Register C to clear it.
        // self.read_register(0x0C);
        DriverEvent::None
    }
}

use crate::arch::serial::SerialPort;
use super::{Driver, DriverEvent};
use crate::arch::ioapic;

pub struct SerialDriver {
    port: SerialPort,
    irq_cap: usize,
}

impl SerialDriver {
    pub const unsafe fn new(base: u16, irq_cap: usize) -> Self {
        SerialDriver {
            port: SerialPort::new(base),
            irq_cap,
        }
    }

    #[allow(dead_code)]
    pub fn send(&self, data: u8) {
        self.port.send(data);
    }
}

impl Driver for SerialDriver {
    fn name(&self) -> &str {
        "Serial Port"
    }

    fn init(&mut self) -> Result<(), &'static str> {
        self.port.init();
        Ok(())
    }

    fn handle_irq(&mut self, _irq: u8) -> alloc::vec::Vec<DriverEvent> {
        let mut events = alloc::vec::Vec::new();
        
        // Read all available bytes
        while let Some(byte) = self.port.receive() {
            events.push(DriverEvent::SerialInput(byte));
        }
        
        if let Err(_) = ioapic::ack_irq(self.irq_cap) {
             // Log?
        }
        
        events
    }
}

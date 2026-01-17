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

    fn handle_irq(&mut self, _irq: u8) -> DriverEvent {
        if let Some(byte) = self.port.receive() {
            if let Err(_) = ioapic::ack_irq(self.irq_cap) {
                 // Log?
            }
            return DriverEvent::SerialInput(byte);
        }
        
        // Even if no data (spurious?), we should probably ACK? 
        // But usually serial IRQ is raised when data is available.
        // If we don't ACK, we won't get more.
        if let Err(_) = ioapic::ack_irq(self.irq_cap) {
             // Log?
        }
        
        DriverEvent::None
    }
}

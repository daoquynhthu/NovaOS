use super::{Driver, DriverEvent};
use crate::arch::ioapic;

pub struct TimerDriver {
    irq_cap: usize,
}

impl TimerDriver {
    pub fn new(irq_cap: usize) -> Self {
        TimerDriver { irq_cap }
    }
}

impl Driver for TimerDriver {
    fn name(&self) -> &str {
        "PIT Timer"
    }

    fn init(&mut self) -> Result<(), &'static str> {
        Ok(())
    }

    fn handle_irq(&mut self, _irq: u8) -> alloc::vec::Vec<DriverEvent> {
        // ACK is handled by the driver
        if ioapic::ack_irq(self.irq_cap).is_err() {
            // Log error?
        }
        alloc::vec![DriverEvent::Tick]
    }
}

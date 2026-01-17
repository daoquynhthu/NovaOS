use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub mod keyboard;
pub mod serial;
pub mod timer;
pub mod rtc;
pub mod ata;
pub mod block;

#[derive(Debug, Clone)]
pub enum DriverEvent {
    None,
    KeyboardInput(keyboard::Key),
    SerialInput(u8),
    Tick,
}

pub trait Driver: Send {
    fn name(&self) -> &str;
    fn init(&mut self) -> Result<(), &'static str>;
    fn handle_irq(&mut self, irq: u8) -> DriverEvent;
}

pub struct DriverManager {
    drivers: BTreeMap<u64, Box<dyn Driver>>, // Badge -> Driver
}

impl DriverManager {
    pub fn new() -> Self {
        DriverManager {
            drivers: BTreeMap::new(),
        }
    }

    pub fn register_irq_driver(&mut self, badge: u64, driver: Box<dyn Driver>) {
        self.drivers.insert(badge, driver);
    }

    pub fn init_all(&mut self) {
        for driver in self.drivers.values_mut() {
            println!("[Kernel] Initializing driver: {}", driver.name());
            if let Err(e) = driver.init() {
                 println!("[Kernel] Failed to initialize driver {}: {}", driver.name(), e);
            }
        }
    }

    pub fn handle_interrupt(&mut self, badge_mask: u64) -> Vec<DriverEvent> {
        let mut events = Vec::new();
        for (driver_badge, driver) in self.drivers.iter_mut() {
            if (badge_mask & *driver_badge) != 0 {
                let event = driver.handle_irq(0);
                if !matches!(event, DriverEvent::None) {
                    events.push(event);
                }
            }
        }
        events
    }
    
    #[allow(dead_code)]
    pub fn get_driver_by_badge(&mut self, badge: u64) -> Option<&mut Box<dyn Driver>> {
        self.drivers.get_mut(&badge)
    }
}

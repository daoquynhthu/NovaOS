use crate::arch::port_io::{outb, inb};

const COM1: u16 = 0x3F8;

pub struct SerialPort {
    port: u16,
}

impl SerialPort {
    pub const unsafe fn new(port: u16) -> Self {
        SerialPort { port }
    }

    pub fn init(&self) {
        unsafe {
            outb(self.port + 1, 0x00);    // Disable all interrupts
            outb(self.port + 3, 0x80);    // Enable DLAB (set baud rate divisor)
            outb(self.port, 0x03);    // Set divisor to 3 (lo byte) 38400 baud
            outb(self.port + 1, 0x00);    //                  (hi byte)
            outb(self.port + 3, 0x03);    // 8 bits, no parity, one stop bit
            outb(self.port + 2, 0xC7);    // Enable FIFO, clear them, with 14-byte threshold
            outb(self.port + 4, 0x0B);    // IRQs enabled, RTS/DSR set
        }
    }

    #[allow(dead_code)]
    fn is_transmit_empty(&self) -> bool {
        unsafe { inb(self.port + 5) & 0x20 != 0 }
    }

    #[allow(dead_code)]
    pub fn send(&self, data: u8) {
        while !self.is_transmit_empty() {}
        unsafe {
            outb(self.port, data);
        }
    }
}

pub static COM1_PORT: SerialPort = unsafe { SerialPort::new(COM1) };

pub fn init() {
    COM1_PORT.init();
}

#[allow(dead_code)]
pub fn send_char(c: char) {
    COM1_PORT.send(c as u8);
}

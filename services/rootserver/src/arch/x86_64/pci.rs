use crate::arch::port_io::{outl, inl};
use alloc::vec::Vec;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

#[derive(Debug, Clone, Copy)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

#[derive(Debug, Clone)]
pub struct PciDevice {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_id: u8,
    pub subclass_id: u8,
    pub prog_if: u8,
    pub revision_id: u8,
    pub header_type: u8,
}

pub fn pci_read_32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let address = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC);

    outl(CONFIG_ADDRESS, address);
    inl(CONFIG_DATA)
}

pub fn pci_read_16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    let val = pci_read_32(bus, device, function, offset);
    if (offset & 2) != 0 {
        (val >> 16) as u16
    } else {
        (val & 0xFFFF) as u16
    }
}

pub fn pci_read_8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    let val = pci_read_32(bus, device, function, offset);
    ((val >> ((offset & 3) * 8)) & 0xFF) as u8
}

#[allow(dead_code)]
pub fn pci_write_32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let address = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC);

    outl(CONFIG_ADDRESS, address);
    outl(CONFIG_DATA, value);
}

#[allow(dead_code)]
pub fn pci_write_16(bus: u8, device: u8, function: u8, offset: u8, value: u16) {
    let aligned_offset = offset & 0xFC;
    let shift = (offset & 3) * 8;
    let mask = 0xFFFF << shift;
    let old_val = pci_read_32(bus, device, function, aligned_offset);
    let new_val = (old_val & !mask) | ((value as u32) << shift);
    pci_write_32(bus, device, function, aligned_offset, new_val);
}

impl PciDevice {
    pub fn read_bar(&self, index: u8) -> u32 {
         // BARs are at 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24
         // index 0..5
         if index > 5 { return 0; }
         pci_read_32(self.address.bus, self.address.device, self.address.function, 0x10 + (index * 4))
    }
    
    #[allow(dead_code)]
    pub fn enable_bus_mastering(&self) {
        let command = pci_read_16(self.address.bus, self.address.device, self.address.function, 0x04);
        pci_write_16(self.address.bus, self.address.device, self.address.function, 0x04, command | 0x04);
    }
}

pub fn scan_bus() -> Vec<PciDevice> {
    let mut devices = Vec::new();

    for bus in 0..=255 {
        for device in 0..32 {
            if let Some(dev) = check_device(bus, device) {
                devices.push(dev.clone());
                // Handle multi-function
                if dev.header_type & 0x80 != 0 {
                     for function in 1..8 {
                         if let Some(fdev) = check_function(bus, device, function) {
                             devices.push(fdev);
                         }
                     }
                }
            }
        }
    }
    devices
}

fn check_device(bus: u8, device: u8) -> Option<PciDevice> {
    check_function(bus, device, 0)
}

fn check_function(bus: u8, device: u8, function: u8) -> Option<PciDevice> {
    let vendor_id = pci_read_16(bus, device, function, 0x00);
    if vendor_id == 0xFFFF {
        return None;
    }

    let device_id = pci_read_16(bus, device, function, 0x02);
    let class_id = pci_read_8(bus, device, function, 0x0B);
    let subclass_id = pci_read_8(bus, device, function, 0x0A);
    let prog_if = pci_read_8(bus, device, function, 0x09);
    let revision_id = pci_read_8(bus, device, function, 0x08);
    let header_type = pci_read_8(bus, device, function, 0x0E);

    Some(PciDevice {
        address: PciAddress { bus, device, function },
        vendor_id,
        device_id,
        class_id,
        subclass_id,
        prog_if,
        revision_id,
        header_type,
    })
}

pub fn init() {
    println!("[PCI] Scanning PCI Bus...");
    let devices = scan_bus();
    println!("[PCI] Found {} devices.", devices.len());
    for dev in devices {
        println!("[PCI] {:02x}:{:02x}.{:x} Vendor={:04x} Device={:04x} Class={:02x} Subclass={:02x} ProgIF={:02x} Rev={:02x}",
            dev.address.bus, dev.address.device, dev.address.function,
            dev.vendor_id, dev.device_id, dev.class_id, dev.subclass_id, dev.prog_if, dev.revision_id);
            
        // Print BARs
        for i in 0..6 {
            let bar = dev.read_bar(i);
            if bar != 0 {
                println!("[PCI]   BAR{}: 0x{:08x}", i, bar);
            }
        }
    }
}

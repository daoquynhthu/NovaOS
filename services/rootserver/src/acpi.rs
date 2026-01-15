use sel4_sys::{seL4_BootInfo, seL4_BootInfoHeader};
use core::mem::size_of;
use core::str;
use crate::println;

const SEL4_BOOTINFO_HEADER_X86_ACPI_RSDP: u64 = 3;
const SEL4_BOOTINFOFRAME_SIZE: usize = 4096;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct Rsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct AcpiTableHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Rsdt {
    pub header: AcpiTableHeader,
    // Variable length array of u32 pointers follows
}

pub fn init(boot_info: &seL4_BootInfo) {
    println!("[INFO] Probing ACPI Tables...");

    if boot_info.extraLen == 0 {
        println!("[WARN] No extra boot info found. ACPI RSDP not available.");
        return;
    }

    // The extra info starts at the offset seL4_BootInfoFrameSize (4KB) from the start of boot_info
    let boot_info_addr = boot_info as *const _ as usize;
    let mut current_offset = SEL4_BOOTINFOFRAME_SIZE;
    // Cast extraLen (u64) to usize
    let end_offset = SEL4_BOOTINFOFRAME_SIZE + (boot_info.extraLen as usize);

    println!("[INFO] Scanning extra boot info (len: {})", boot_info.extraLen);

    while current_offset < end_offset {
        let header_ptr = (boot_info_addr + current_offset) as *const seL4_BootInfoHeader;
        
        // Safety: We assume the extra info is mapped and readable in the RootServer's VSpace.
        // The kernel maps the boot info frame and extra pages contiguously.
        let header = unsafe { &*header_ptr };
        
        let id = header.id;
        let len = header.len;

        if len == 0 {
            println!("[ERROR] Invalid chunk length 0 at offset {}. Aborting scan.", current_offset);
            break;
        }

        if id == SEL4_BOOTINFO_HEADER_X86_ACPI_RSDP {
             println!("[INFO] Found ACPI RSDP Chunk at offset 0x{:x}", current_offset);
             
             // The RSDP structure follows immediately after the header
             // struct seL4_BootInfoHeader is 2 * sizeof(seL4_Word) = 16 bytes on 64-bit
             let header_size = size_of::<seL4_BootInfoHeader>();
             let rsdp_ptr = (boot_info_addr + current_offset + header_size) as *const Rsdp;
             
             let rsdp = unsafe { &*rsdp_ptr };
             
             // RSDP Signature is 8 bytes "RSD PTR "
             if let Ok(sig_str) = str::from_utf8(&rsdp.signature) {
                 println!("[INFO] RSDP Signature: {:?}", sig_str);
                 if sig_str == "RSD PTR " {
                     println!("[INFO] ACPI RSDP validated.");
                     
                     let revision = rsdp.revision;
                     let rsdt_address = rsdp.rsdt_address;
                     let xsdt_address = rsdp.xsdt_address;

                     println!("[INFO] RSDP Revision: {}", revision);
                     println!("[INFO] RSDT Address: 0x{:x}", rsdt_address);
                     
                     if revision >= 2 {
                         println!("[INFO] XSDT Address: 0x{:x}", xsdt_address);
                     }

                     // Find the untyped cap covering RSDT
                     find_rsdt_cap(boot_info, rsdt_address as usize);
                 }
             } else {
                 println!("[WARN] Invalid RSDP Signature bytes: {:?}", rsdp.signature);
             }
             return;
        }

        // Move to next chunk
        current_offset += len as usize;
    }
    
    println!("[WARN] ACPI RSDP not found in boot info.");
}

fn find_rsdt_cap(boot_info: &seL4_BootInfo, rsdt_paddr: usize) {
    let count = boot_info.untyped.end - boot_info.untyped.start;
    println!("[INFO] Searching for RSDT (paddr=0x{:x}) in {} untyped caps...", rsdt_paddr, count);

    for i in 0..count {
        let desc_idx = i as usize;
        // Check bounds just in case, though untypedList is usually large enough
        if desc_idx >= boot_info.untypedList.len() {
            break;
        }
        let desc = boot_info.untypedList[desc_idx];
        let paddr = desc.paddr as usize;
        let size_bits = desc.sizeBits as usize;
        let size_bytes = 1 << size_bits;

        if rsdt_paddr >= paddr && rsdt_paddr < paddr + size_bytes {
            let cap_idx = boot_info.untyped.start + i;
            println!("[INFO] Found RSDT in Untyped Cap #{} (paddr=0x{:x}, size=2^{}, isDevice={})", 
                     cap_idx, paddr, size_bits, desc.isDevice);
            return;
        }
    }
    println!("[WARN] RSDT physical address not found in any Untyped Cap.");
}

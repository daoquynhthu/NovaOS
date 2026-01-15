use sel4_sys::{
    seL4_BootInfo, seL4_BootInfoHeader, seL4_CPtr, seL4_Error,
    seL4_RootCNodeCapSlots_seL4_CapInitThreadCNode as seL4_CapInitThreadCNode,
    seL4_RootCNodeCapSlots_seL4_CapInitThreadVSpace as seL4_CapInitThreadPML4,
    seL4_X86_VMAttributes_seL4_X86_Default_VMAttributes as seL4_X86_Default_VMAttributes,
};
use core::mem::size_of;
use core::str;
use crate::println;
use crate::memory::{SlotAllocator, UntypedAllocator};
use crate::vspace::VSpace;
use crate::utils::{seL4_X86_4K, untyped_retype, seL4_CapRights_new};

const SEL4_BOOTINFO_HEADER_X86_ACPI_RSDP: u64 = 3;
const SEL4_BOOTINFOFRAME_SIZE: usize = 4096;
const MAX_MAPPED_CAPS: usize = 16;

#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub struct MappedCap {
    pub cap_index: usize, // Index in boot_info.untypedList
    pub cap_cptr: seL4_CPtr, // The capability itself
    pub paddr_start: usize,
    pub size_bits: usize,
    pub vaddr_start: usize,
    pub mapped_limit: usize, // Bytes from start that are mapped
}

#[derive(Debug)]
pub struct AcpiContext {
    pub mapped_caps: [Option<MappedCap>; MAX_MAPPED_CAPS],
    pub next_vaddr: usize,
}

impl AcpiContext {
    pub fn new() -> Self {
        Self {
            mapped_caps: [None; MAX_MAPPED_CAPS],
            next_vaddr: 0x8000_0000,
        }
    }
}

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
#[allow(dead_code)]
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
#[allow(dead_code)]
pub struct Rsdt {
    pub header: AcpiTableHeader,
    // Variable length array of u32 pointers follows
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub struct Madt {
    pub header: AcpiTableHeader,
    pub local_apic_address: u32,
    pub flags: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MadtEntryHeader {
    pub entry_type: u8,
    pub record_length: u8,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MadtLocalApic {
    pub header: MadtEntryHeader,
    pub processor_id: u8,
    pub apic_id: u8,
    pub flags: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MadtIoApic {
    pub header: MadtEntryHeader,
    pub io_apic_id: u8,
    pub reserved: u8,
    pub io_apic_address: u32,
    pub global_system_interrupt_base: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MadtIso {
    pub header: MadtEntryHeader,
    pub bus_source: u8,
    pub irq_source: u8,
    pub gsi: u32,
    pub flags: u16,
}

#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub struct AcpiInfo {
    pub rsdt_paddr: usize,
    pub rsdt_cap: seL4_CPtr,
    pub rsdt_cap_paddr: usize,
    pub cap_size_bits: usize,
}

pub fn init(boot_info: &seL4_BootInfo) -> Option<AcpiInfo> {
    println!("[INFO] Probing ACPI Tables...");

    if boot_info.extraLen == 0 {
        println!("[WARN] No extra boot info found. ACPI RSDP not available.");
        return None;
    }

    // The extra info starts at the offset seL4_BootInfoFrameSize (4KB) from the start of boot_info
    let boot_info_addr = boot_info as *const _ as usize;
    let mut current_offset = SEL4_BOOTINFOFRAME_SIZE;
    // Cast extraLen (u64) to usize
    let end_offset = SEL4_BOOTINFOFRAME_SIZE + (boot_info.extraLen as usize);

    println!("[INFO] Scanning extra boot info (len: {})", boot_info.extraLen);

    while current_offset < end_offset {
        let header_ptr = (boot_info_addr + current_offset) as *const seL4_BootInfoHeader;
        let header = unsafe { &*header_ptr };
        let id = header.id;
        let len = header.len;

        if len == 0 {
            println!("[ERROR] Invalid chunk length 0 at offset {}. Aborting scan.", current_offset);
            break;
        }

        if id == SEL4_BOOTINFO_HEADER_X86_ACPI_RSDP {
             println!("[INFO] Found ACPI RSDP Chunk at offset 0x{:x}", current_offset);
             let header_size = size_of::<seL4_BootInfoHeader>();
             let rsdp_ptr = (boot_info_addr + current_offset + header_size) as *const Rsdp;
             let rsdp = unsafe { &*rsdp_ptr };
             
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
                     return find_rsdt_cap(boot_info, rsdt_address as usize);
                 }
             }
             return None;
        }
        current_offset += len as usize;
    }
    println!("[WARN] ACPI RSDP not found in boot info.");
    None
}

fn find_rsdt_cap(boot_info: &seL4_BootInfo, rsdt_paddr: usize) -> Option<AcpiInfo> {
    let count = boot_info.untyped.end - boot_info.untyped.start;
    println!("[INFO] Searching for RSDT (paddr=0x{:x}) in {} untyped caps...", rsdt_paddr, count);

    for i in 0..count {
        let desc_idx = i as usize;
        if desc_idx >= boot_info.untypedList.len() { break; }
        let desc = boot_info.untypedList[desc_idx];
        let paddr = desc.paddr as usize;
        let size_bits = desc.sizeBits as usize;
        let size_bytes = 1 << size_bits;

        if rsdt_paddr >= paddr && rsdt_paddr < paddr + size_bytes {
            let cap_idx = boot_info.untyped.start + i;
            println!("[INFO] Found RSDT in Untyped Cap #{} (paddr=0x{:x}, size=2^{}, isDevice={})", 
                     cap_idx, paddr, size_bits, desc.isDevice);
            
            return Some(AcpiInfo {
                rsdt_paddr,
                rsdt_cap: cap_idx,
                rsdt_cap_paddr: paddr,
                cap_size_bits: size_bits,
            });
        }
    }
    println!("[WARN] RSDT physical address not found in any Untyped Cap.");
    None
}

pub fn map_rsdt(
    boot_info: &seL4_BootInfo,
    info: &AcpiInfo,
    allocator: &mut UntypedAllocator,
    slots: &mut SlotAllocator,
    context: &mut AcpiContext,
) -> Result<*const Rsdt, seL4_Error> {
    // map_phys handles the complexity now
    let vaddr = map_phys(boot_info, info.rsdt_paddr, 0, allocator, slots, context)?;
    Ok(vaddr as *const Rsdt)
}

fn find_untyped_for_paddr(boot_info: &seL4_BootInfo, paddr: usize) -> Option<(seL4_CPtr, usize, usize, usize)> {
    let count = boot_info.untyped.end - boot_info.untyped.start;
    for i in 0..count {
        let desc_idx = i as usize;
        if desc_idx >= boot_info.untypedList.len() { break; }
        let desc = boot_info.untypedList[desc_idx];
        let cap_paddr = desc.paddr as usize;
        let size_bits = desc.sizeBits as usize;
        let size_bytes = 1 << size_bits;

        if paddr >= cap_paddr && paddr < cap_paddr + size_bytes {
            let cap_idx = boot_info.untyped.start + i;
            return Some((cap_idx, cap_paddr, i as usize, size_bits)); // Return untyped list index and size_bits too
        }
    }
    
    // Debug: Print available device untypeds if not found
            /*
            println!("[ACPI] Debug: Untyped lookup failed for paddr 0x{:x}. Available device caps:", paddr);
            for i in 0..count {
                let desc = boot_info.untypedList[i as usize];
                if desc.isDevice != 0 {
                     let cap_paddr = desc.paddr as usize;
                     let size_bits = desc.sizeBits as usize;
                     let size_bytes = 1 << size_bits;
                     println!("  [Device] Cap #{}: paddr=0x{:x}-0x{:x} (size=2^{})", 
                        boot_info.untyped.start + i, cap_paddr, cap_paddr + size_bytes, size_bits);
                }
            }
            */
            
            None
}

pub fn map_phys(
    boot_info: &seL4_BootInfo,
    paddr: usize,
    _suggested_vaddr: usize,
    allocator: &mut UntypedAllocator,
    slots: &mut SlotAllocator,
    context: &mut AcpiContext,
) -> Result<usize, seL4_Error> {
    if let Some((cap, cap_paddr, list_idx, size_bits)) = find_untyped_for_paddr(boot_info, paddr) {
        
        // Check if we already have this cap in context
        let mut mapped_idx = None;
        for i in 0..MAX_MAPPED_CAPS {
            if let Some(ref mc) = context.mapped_caps[i] {
                if mc.cap_index == list_idx {
                    mapped_idx = Some(i);
                    break;
                }
            }
        }

        // If not found, add it
        if mapped_idx.is_none() {
            for i in 0..MAX_MAPPED_CAPS {
                if context.mapped_caps[i].is_none() {
                    let size_bytes = 1 << size_bits;
                    // Reserve vspace
                    let vaddr_start = context.next_vaddr;
                    // Align up next_vaddr based on size
                    context.next_vaddr += size_bytes; 
                    
                    context.mapped_caps[i] = Some(MappedCap {
                        cap_index: list_idx,
                        cap_cptr: cap,
                        paddr_start: cap_paddr,
                        size_bits,
                        vaddr_start,
                        mapped_limit: 0,
                    });
                    mapped_idx = Some(i);
                    println!("[ACPI] Registered new mapped cap: index={}, paddr=0x{:x}, vaddr=0x{:x}, size={}", 
                        list_idx, cap_paddr, vaddr_start, size_bytes);
                    break;
                }
            }
        }

        let idx = mapped_idx.ok_or(seL4_Error::seL4_NotEnoughMemory)?;
        
        // Map the required page(s) if not already mapped
        let offset = paddr - cap_paddr;
        let page_offset = offset & !(4096 - 1);
        let target_limit = page_offset + 4096;
        
        let mut mc = context.mapped_caps[idx].unwrap();
        
        if target_limit > mc.mapped_limit {
            // Need to map more pages
            let current_limit = mc.mapped_limit;
            let bytes_needed = target_limit - current_limit;
            let pages_needed = bytes_needed / 4096;
            
            // println!("[ACPI] Mapping {} more pages for cap {} (current limit: 0x{:x}, target: 0x{:x})", 
            //    pages_needed, list_idx, current_limit, target_limit);

            for i in 0..pages_needed {
                 let slot = slots.alloc().map_err(|_| seL4_Error::seL4_NotEnoughMemory)?;
                 let err = unsafe {
                     untyped_retype(
                         mc.cap_cptr,
                         seL4_X86_4K,
                         12,
                         seL4_CapInitThreadCNode as seL4_CPtr,
                         0,
                         0,
                         slot,
                         1
                     )
                 };
                 if err != seL4_Error::seL4_NoError {
                     return Err(err);
                 }
                 
                 let page_vaddr = mc.vaddr_start + current_limit + (i * 4096);
                 let mut vspace = VSpace::new(seL4_CapInitThreadPML4 as seL4_CPtr);
                 
                 vspace.map_page(
                    allocator,
                    slots,
                    boot_info,
                    slot,
                    page_vaddr,
                    seL4_CapRights_new(0, 1, 1, 1),
                    seL4_X86_Default_VMAttributes
                )?;
            }
            mc.mapped_limit = target_limit;
            context.mapped_caps[idx] = Some(mc);
        }

        Ok(mc.vaddr_start + offset)
    } else {
        // println!("[ACPI] Failed to find untyped cap for paddr 0x{:x}", paddr);
        Err(seL4_Error::seL4_FailedLookup)
    }
}

pub fn walk_madt(madt_ptr: *const Madt) {
    let madt = unsafe { &*madt_ptr };
    let length = madt.header.length as usize;
    let madt_start = madt_ptr as usize;
    let mut offset = core::mem::size_of::<Madt>();
    
    println!("[ACPI] Walking MADT (Length: {})", length);
    
    while offset < length {
        let entry_ptr = (madt_start + offset) as *const MadtEntryHeader;
        let entry = unsafe { &*entry_ptr };
        let record_len = entry.record_length as usize;
        
        if record_len < 2 {
            println!("[ACPI] Error: Invalid MADT record length {}", record_len);
            break;
        }

        match entry.entry_type {
            0 => { // Processor Local APIC
                let lapic = unsafe { &*(entry_ptr as *const MadtLocalApic) };
                let pid = lapic.processor_id;
                let aid = lapic.apic_id;
                let flags = lapic.flags;
                println!("[ACPI] MADT Type 0: Local APIC (CPU ID: {}, APIC ID: {}, Flags: 0x{:x})", 
                    pid, aid, flags);
            },
            1 => { // IO APIC
                let ioapic = unsafe { &*(entry_ptr as *const MadtIoApic) };
                let id = ioapic.io_apic_id;
                let addr = ioapic.io_apic_address;
                let gsi_base = ioapic.global_system_interrupt_base;
                println!("[ACPI] MADT Type 1: IO APIC (ID: {}, Addr: 0x{:x}, GSI Base: {})", 
                    id, addr, gsi_base);
            },
            2 => { // Interrupt Source Override
                let iso = unsafe { &*(entry_ptr as *const MadtIso) };
                let bus = iso.bus_source;
                let irq = iso.irq_source;
                let gsi = iso.gsi;
                let flags = iso.flags;
                println!("[ACPI] MADT Type 2: ISO (Bus: {}, Source: {}, GSI: {}, Flags: 0x{:x})", 
                    bus, irq, gsi, flags);
            },
            t => {
                println!("[ACPI] MADT Type {}: Skipped (Length: {})", t, record_len);
            }
        }
        
        offset += record_len;
    }
}

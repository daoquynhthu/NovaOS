use sel4_sys::*;

// Temporary constant until we confirm sel4_sys export
#[allow(non_upper_case_globals)]
const seL4_X86_4K: seL4_Word = 8;
#[allow(non_upper_case_globals)]
const seL4_X86_PageTableObject: seL4_Word = 10;
#[allow(non_upper_case_globals)]
const seL4_X86_PageDirectoryObject: seL4_Word = 11;
#[allow(non_upper_case_globals)]
const seL4_X86_PDPTObject: seL4_Word = 5;

#[allow(dead_code)]
pub fn check_constants() {
    let _ = seL4_X64_PML4Object;
    let _ = seL4_X86_PDPTObject;
    let _ = seL4_X86_PageDirectoryObject;
    let _ = seL4_X86_PageTableObject;
    let _ = seL4_X86_4K;
}

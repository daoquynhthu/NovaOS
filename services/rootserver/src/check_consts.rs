use sel4_sys::*;

#[allow(dead_code)]
pub fn check_constants() {
    let _ = seL4_X64_PML4Object;
    let _ = seL4_X86_PDPTObject;
    let _ = seL4_X86_PageDirectoryObject;
    let _ = seL4_X86_PageTableObject;
    let _ = seL4_X86_4K;
}

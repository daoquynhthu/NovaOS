#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

// Include generated bindings
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// Helper types
pub type SeL4Error = seL4_Error;
pub type SeL4Result = Result<(), SeL4Error>;

// BootInfo wrapper
#[repr(C)]
pub struct BootInfo {
    // To be populated from bindings
}

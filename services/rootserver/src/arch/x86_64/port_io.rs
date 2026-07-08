//! Port I/O — re-exported from `libnova::arch::x86_64::port_io`.
//!
//! This compat module exists so existing `crate::arch::port_io::*` imports
//! continue to work. New code should use `libnova::arch::x86_64::port_io`.

pub use libnova::arch::x86_64::port_io::{
    inb, inl, inw, outb, outl, outw, init, issue_ioport_cap,
};

//! RootServer syscall handlers.
//!
//! This module breaks the giant `match label` dispatch in `main.rs` into
//! per-syscall handler functions. Input validation helpers are imported from
//! `libnova::validate`.

use alloc::sync::Arc;
use sel4_sys::{seL4_BootInfo, seL4_CPtr};

pub mod core;
pub mod fs;
pub mod metadata;
pub mod service;

/// Mutable context passed to syscall handlers.
///
/// Grouping the common references avoids 10+ argument handler functions and
/// keeps the dispatch loop readable.
#[allow(dead_code)]
pub struct SyscallContext<'a> {
    pub pid: usize,
    pub info: &'a libnova::ipc::MessageInfo,
    pub mrs: &'a [u64; 4],
    pub boot_info: &'a seL4_BootInfo,
    pub syscall_ep_cap: seL4_CPtr,
    pub fs_service_ep_cap: seL4_CPtr,
    pub test_service_slot: seL4_CPtr,
    pub syscall_recv_slot: seL4_CPtr,
    pub slot_allocator: &'a mut crate::memory::SlotAllocator,
    pub allocator: &'a mut crate::memory::UntypedAllocator,
    pub frame_allocator: &'a mut crate::memory::FrameAllocator,
    pub ata: &'a Arc<crate::drivers::ata::AtaDriver>,
    pub shell: &'a mut crate::shell::Shell,
    pub deferred_services_spawned: &'a mut bool,
}

//! Allocator types — re-exported from `libnova::allocator`.
//!
//! This compat module exists so existing `crate::memory::*` imports continue to
//! work without modification. New code should import directly from
//! `libnova::allocator`.

pub use libnova::allocator::{
    FrameAllocator, MAX_REGION_PAGES, MemoryRegion, ObjectAllocator, SlotAllocator,
    UntypedAllocator,
};

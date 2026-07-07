// NovaOS Rust-side log level control
// Mirrors the C-side NOVA_BOOT_TRACE_LEVEL design:
//   - Global numeric level (0=off, 1=info, 2=verbose, 3=trace)
//   - Per-domain bitmask for fine-grained control
//   - Zero-cost when disabled: atomic load + branch only
use core::sync::atomic::{AtomicU32, Ordering};

// ── Global numeric level ────────────────────────────────────────────
// 0 = Off (no debug output; critical errors and test signals still print)
// 1 = Info (default: basic operational messages)
// 2 = Verbose (domain-specific debug traces)
// 3 = Trace (all debug output, maximum detail)
static LOG_LEVEL: AtomicU32 = AtomicU32::new(1);

// ── Domain bitflags ─────────────────────────────────────────────────
// For fine-grained control, set DOMAIN_MASK to filter specific domains.
// Default: all domains enabled (0xFFFF_FFFF).
pub const DOM_FS: u32 = 1 << 0; // NovaFS internal debug
pub const DOM_LOADER: u32 = 1 << 1; // ELF loader frame-by-frame map
pub const DOM_ACPI: u32 = 1 << 2; // ACPI table parsing
pub const DOM_PROCESS: u32 = 1 << 3; // Process lifecycle detail
pub const DOM_MEM: u32 = 1 << 4; // Memory allocation/stats
pub const DOM_VSPACE: u32 = 1 << 5; // Virtual address space
pub const DOM_WORKER: u32 = 1 << 6; // Worker thread events
pub const DOM_ALLOC: u32 = 1 << 7; // Allocator internal detail
pub const DOM_SECURITY: u32 = 1 << 8; // Security checks
pub const DOM_SHELL: u32 = 1 << 9; // Shell debug
pub const DOM_STRESS: u32 = 1 << 10; // Stress test detail
pub const DOM_BENCH: u32 = 1 << 11; // Benchmarks
pub const DOM_APIC: u32 = 1 << 12; // APIC/IOAPIC config
pub const DOM_PCI: u32 = 1 << 13; // PCI enumeration
pub const DOM_DISK: u32 = 1 << 14; // Disk/ATA I/O
pub const DOM_IPC: u32 = 1 << 15; // IPC tracing
pub const DOM_PAGING: u32 = 1 << 16; // Demand paging / page faults

// Domain mask (enables/disables specific domains)
static DOMAIN_MASK: AtomicU32 = AtomicU32::new(0xFFFF_FFFF);

// ── Public API ──────────────────────────────────────────────────────

pub fn set_log_level(level: u32) {
    LOG_LEVEL.store(level, Ordering::Relaxed);
}

pub fn set_domain_mask(mask: u32) {
    DOMAIN_MASK.store(mask, Ordering::Relaxed);
}

pub fn get_log_level() -> u32 {
    LOG_LEVEL.load(Ordering::Relaxed)
}

/// Check whether output is enabled for the given domain and minimum level.
/// Zero-cost when disabled: the caller's `if` branch is never entered.
#[inline]
pub fn check(domain: u32, min_level: u32) -> bool {
    let mask = DOMAIN_MASK.load(Ordering::Relaxed);
    if (mask & domain) == 0 {
        return false;
    }
    LOG_LEVEL.load(Ordering::Relaxed) >= min_level
}

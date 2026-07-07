#![cfg_attr(not(feature = "std"), no_std)]

//! libnova: NovaOS 核心抽象库
//! 提供基于权能的系统调用封装和异步 IPC 接口
//! Force Rebuild 1

extern crate alloc;

pub mod cap;
pub mod console;
pub mod env;
pub mod fs_ipc;
pub mod ipc;
pub mod log;
pub mod syscall;
pub mod tcb;
pub mod validate;

pub const PROT_READ: usize = 0x1;
pub const PROT_WRITE: usize = 0x2;
pub const PROT_EXEC: usize = 0x4;

pub const MAP_SHARED: usize = 0x01;
pub const MAP_PRIVATE: usize = 0x02;

// ── Gated log macros ────────────────────────────────────────────────
// Usage: log_debug!(libnova::log::DOM_FS, "NovaFS: found inode {}", ino);
// When log level is below the threshold or domain is masked, this compiles
// to nothing (atomic load + branch, formatting never evaluated).

#[macro_export]
macro_rules! log_debug {
    ($domain:expr, $($arg:tt)*) => {
        if $crate::log::check($domain, 2) {
            $crate::println!($($arg)*);
        }
    };
}

#[macro_export]
macro_rules! log_trace {
    ($domain:expr, $($arg:tt)*) => {
        if $crate::log::check($domain, 3) {
            $crate::println!($($arg)*);
        }
    };
}

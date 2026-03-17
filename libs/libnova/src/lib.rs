#![no_std]

//! libnova: NovaOS 核心抽象库
//! 提供基于权能的系统调用封装和异步 IPC 接口
//! Force Rebuild 1

extern crate alloc;

pub mod syscall;
pub mod cap;
pub mod ipc;
pub mod tcb;
pub mod console;
pub mod env;
pub mod fs_ipc;

pub const PROT_READ: usize = 0x1;
pub const PROT_WRITE: usize = 0x2;
pub const PROT_EXEC: usize = 0x4;

pub const MAP_SHARED: usize = 0x01;
pub const MAP_PRIVATE: usize = 0x02;

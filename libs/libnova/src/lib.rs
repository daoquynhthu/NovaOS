#![no_std]

//! libnova: NovaOS 核心抽象库
//! 提供基于权能的系统调用封装和异步 IPC 接口

pub mod syscall;
pub mod cap;
pub mod ipc;
pub mod tcb;
pub mod console;
pub mod env;

pub fn init() {
    // 初始化 libnova 环境
}

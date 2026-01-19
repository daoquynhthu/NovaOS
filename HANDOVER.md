# NovaOS RootServer 开发任务交接文档

## 1. 项目概况
本项目旨在基于 **seL4 microkernel (x86_64)** 开发一个 **Rust 编写的 RootServer**。
RootServer 是 seL4 启动后的第一个用户态进程，负责接管系统资源（Untyped Memory, CSpace, VSpace）并初始化操作系统环境。

### 当前版本: v0.0.7-alpha (2026-01-18)
**最新状态**: 驱动层、文件系统层、系统调用层已代码完成，但受限于环境问题（QEMU 缺失）尚未进行最终运行时验证。

## 2. 最新核心进展 (2026-01-18)

### 2.1 文件系统系统调用 (FS Syscalls) - **已实现 (Implemented)**
在 `services/rootserver/src/main.rs` 中实现了以下系统调用，暴露 NovaFS 给用户态：
- **sys_open (Label 20)**: 解析路径，分配文件描述符 (FD)，存入 `Process.fds` 表。
- **sys_read (Label 21)**: 从 FD 读取数据，通过 IPC Buffer 返回给用户。
- **sys_write (Label 22)**: 从 IPC Buffer 获取数据，写入 FD。
- **sys_close (Label 23)**: 释放 FD。
- **安全机制**: 实现了 IPC Buffer 边界检查 (Path < 256 bytes, Data < 900 bytes)。

### 2.2 虚拟内存管理修复 (VSpace Fixes) - **已修复 (Fixed)**
- **PagingCap**: 在 `services/rootserver/src/vspace.rs` 中引入 `PagingCap` 结构，明确记录分页结构的层级 (Level 1-3) 和虚拟地址。
- **ensure_pt_exists**: 实现了自动分页结构分配逻辑，解决了映射 Frame 时因缺页表导致的 `seL4_InvalidCapability` 错误。
- **资源清理**: 修复了 `process.rs` 中 `PagingCap` 的删除逻辑。

### 2.3 进程管理增强
- **文件描述符表**: `Process` 结构体新增 `fds: Vec<Option<FileDescriptor>>`，支持每个进程独立管理打开的文件。
- **堆栈优化**: 修复了 `Process` 结构体过大导致的栈溢出问题，关键数组已迁移至 `Vec`。

## 3. 当前阻碍与待修复问题 (Critical Issues)

### 🔴 环境问题 (Environment)
- **QEMU 缺失**: 运行 `test.ps1` 时报错 `qemu-system-x86_64: command not found`。
  - **影响**: 无法进行任何运行时测试（Disk I/O, Process Spawn, IPC）。
  - **解决**: 需在开发环境中安装 QEMU 或将 `qemu-system-x86_64` 添加到 PATH 环境变量。

### 🟠 驱动初始化 (Driver Init)
- **ATA Driver**: 在之前的运行中观察到 `drivers/ata.rs` 初始化失败 (Line 192)。
  - **推测**: 可能是 QEMU 的磁盘镜像参数未正确传递，或 PIO 状态轮询超时。
  - **行动**: 修复 QEMU 环境后，需优先调试 ATA 驱动的 `identify` 流程。

### 🟡 运行时验证 (Verification Pending)
- **FS Syscalls**: 代码已写好，但从未在真实 UserApp 中运行过。需验证 `sys_open` -> `sys_write` -> `sys_read` 的完整链路。

## 4. 核心架构与功能索引
### 4.1 目录结构
- `services/rootserver/src/`
    - `main.rs`: 主循环，包含 Syscall Handler (Line 800+)。
    - `vspace.rs`: 核心页表管理，关注 `ensure_pt_exists` 和 `map_page`。
    - `fs/novafs.rs`: NovaFS 文件系统实现。
    - `drivers/ata.rs`: ATA PIO 磁盘驱动。
    - `process.rs`: 进程控制块 (TCB, VSpace, FDs)。

### 4.2 常用命令
- **构建**: `powershell -ExecutionPolicy Bypass -File .\build.ps1`
- **测试**: `powershell -ExecutionPolicy Bypass -File .\test.ps1`

## 5. 接下来的工作建议 (Next Steps)
1.  **修复环境**: 解决 QEMU 路径问题，确保 `test.ps1` 能启动模拟器。
2.  **调试驱动**: 运行 RootServer，观察 ATA 驱动初始化日志。如果失败，检查 `drivers/ata.rs` 中的 `wait_bsy` 和 `wait_drq` 逻辑。
3.  **验证 FS Syscalls**:
    - 编译并运行 `user_app`。
    - 在 UserApp 中调用 `open("/home/test.txt", "w")`，写入数据，关闭，再读取。
    - 观察串口输出，确认数据一致性。
4.  **扩展 Shell**: 在 Shell 中实现 `cp` (复制) 和 `cat` (基于 syscall) 命令，进一步验证文件系统稳定性。

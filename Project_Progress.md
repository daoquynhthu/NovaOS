# NovaOS 项目进度书 (Project Progress)

> 本文档用于记录项目里程碑、已完成任务以及下一步计划。每次重大变更后必须更新。

## 📅 当前状态
- **日期**: 2026-01-17
- **阶段**: 0.6.1 - VMM 增强 (VMM Enhancements)
- **版本**: `v0.0.5-alpha`

## ✅ 已完成任务 (Completed)

### 2026-01-17: 系统关机功能 (System Shutdown)
- [x] **ACPI 电源管理**:
    - 实现了 ACPI FADT 表的解析与 ACPI Enable 序列。
    - 实现了 S5 (Soft Off) 状态的关机逻辑。
- [x] **双重关机策略**:
    - 优先尝试 QEMU 特定的端口关机 (Port 0x604)。
    - 失败则回退至 ACPI PM1a/PM1b 寄存器关机。
- [x] **系统集成**:
    - 实现了 `sys_shutdown` (Label 50) 系统调用，允许特权进程请求关机。
    - Shell 新增 `shutdown` 命令。
    - 解决了 Port I/O 权限与 Capabilities 管理问题，实现了 `inw`/`outw` 接口。
- [x] **验证通过**:
    - `test.ps1` 自动化测试成功触发关机并正确退出。

### 2026-01-17: 文件系统 I/O 与描述符 (File System I/O & Descriptors)
- [x] **文件 I/O 系统调用**:
    - 实现了 `sys_file_open` (Label 20): 支持只读、只写、读写、追加模式打开文件。
    - 实现了 `sys_file_close` (Label 21): 关闭文件描述符，释放资源。
    - 实现了 `sys_file_read` (Label 22): 从文件描述符读取数据到用户缓冲区。
    - 实现了 `sys_file_write` (Label 23): 将用户缓冲区数据写入文件描述符。
- [x] **进程文件描述符表 (FD Table)**:
    - 在 `Process` 结构体中新增 `fds` 数组，支持每进程最多 16 个打开文件。
    - 定义了 `FileDescriptor` 结构和 `FileMode` 枚举。
- [x] **用户态集成**:
    - 更新 `user_app` 的 `syscalls.rs`，封装了文件 I/O 系统调用接口。
    - 更新 `user_app` 的 `main.rs`，新增文件创建、写入、读取的完整测试用例。
    - 验证通过：用户态程序成功创建 `test.txt`，写入数据并重新读取校验。
    - **已修复 (Fixed)**: RootServer `Process::spawn` 崩溃问题已解决。通过将 `Process` 结构体中的大数组 (`mapped_frames`, `fds`) 移至堆 (`Vec`)，消除了栈溢出风险。
    - **已修复 (Fixed)**: 文件 I/O 写入失败问题已解决。修正了 RootServer 端 `sys_file_read` 和 `sys_file_write` 对 IPC 消息的解包逻辑，使其与 UserApp 协议一致。
    - **当前状态 (Status)**: `test.ps1` 完美通过。系统功能（进程管理、内存管理、IPC、文件系统）均验证正常。

### 2026-01-17: 虚拟文件系统 (VFS Implementation)
- [x] **VFS 核心实现**:
    - 实现了基于内存的虚拟文件系统 (RamFS)，支持文件与目录结构。
    - 支持文件/目录的创建、读取、写入(追加)、删除操作。
    - 实现了线程安全的全局 VFS 实例 (`spin::Mutex`)。
- [x] **VFS 集成**:
    - 在 RootServer 启动时初始化 VFS，并挂载 `/home` 和 `/bin` 目录。
    - 将静态文件 (`filesystem.rs`) 自动迁移至 VFS 的 `/bin` 目录。
- [x] **Shell 深度集成**:
    - Shell 新增 `cwd` (当前工作目录) 状态追踪。
    - 实现了 `cd`, `pwd`, `mkdir`, `touch`, `rm` 命令。
    - 适配了 `ls`, `cat`, `exec`, `runhello` 命令以使用 VFS。
    - Shell 提示符更新为显示当前路径 (`NovaOS:/home>`)。
    - 增强了 Tab 补全功能，支持根据当前路径动态补全文件名和目录名。

### 2026-01-17: Shell 现代化改造 (Modern Shell)
- [x] **命令行交互增强**:
    - 实现了 **Tab 键自动补全** (Tab Completion)：支持命令补全和 `exec` 文件名补全。
    - 实现了 **彩色提示符** (Colored Prompt)：使用 ANSI 转义序列显示绿色的 `NovaOS>`。
    - 优化了光标移动和行编辑逻辑。
- [x] **命令列表**:
    - 整理了所有可用命令为 `COMMANDS` 常量，方便维护和补全。
    - 支持 `help`, `clear`, `echo`, `whoami`, `status`, `bootinfo`, `alloc`, `meminfo`, `ps`, `ls`, `kill`, `exec`, `history`, `post`, `runhello`。

### 2026-01-17: 用户态内存管理 (User-Space Memory Management)
- [x] **用户态堆分配器 (Global Allocator)**:
    - 引入 `linked_list_allocator` crate。
    - 实现了 `#[global_allocator]`，支持 `Vec`, `String`, `Box` 等动态数据结构。
    - 在 `user_app` 初始化时使用 64KB 堆空间 (0x4000_1000 - 0x4001_1000)。
- [x] **安全性与稳定性**:
    - 修复了 `sys_brk` 扩展堆时的地址校验逻辑。
    - 修复了 `Vec` 作用域结束时的 Drop 资源释放问题。
    - 验证通过：`Vec<i32>` 动态扩容与 `String` 字符串操作均正常工作。

### 2026-01-17: 虚拟内存管理增强 (VMM Enhancements)
- [x] **按需分页范围扩展 (Extended Demand Paging)**:
    - 扩展了缺页处理范围至 `0x4000_0000 - 0x7000_0000` (768MB)。
    - 支持该范围内任意 4K 对齐地址的自动映射 (包括 Heap 和测试区域)。
- [x] **共享内存机制 (Shared Memory)**:
    - 实现了 `sys_shm_alloc` (分配) 和 `sys_shm_map` (映射) 系统调用。
    - 支持跨进程的内存共享与 Capability 安全传递。
    - 实现了基于 Key 的共享区域查找与引用计数管理（基础版）。
    - 验证通过：`user_app` 成功访问起始页 (`0x6000_0000`)、连续页 (`0x6000_1000`) 和远端页 (`0x6001_4000`)。

### 2026-01-17: 异常处理与系统稳定性 (Exception Handling & Stability)
- [x] **缺页异常处理 (Page Fault Handler)**:
    - 实现了 `seL4_Fault_VMFault` (Label 5) 的处理逻辑。
    - 实现了按需分页 (Demand Paging) 机制：当用户态访问未映射地址 (如 `0x6000_0000`) 时，自动分配并映射 4K 页帧。
    - 验证通过：`user_app` 成功触发并从缺页异常中恢复，完成内存写入。
- [x] **系统调用与异常路由修复**:
    - 解决了 `sys_sleep` 与 `seL4_Fault_VMFault` 的 Label 冲突 (sys_sleep 迁移至 Label 10)。
    - 统一了系统调用 (Syscall) 和 异常 (Fault) 的 Endpoint 路由，简化了 IPC 通道管理。
- [x] **稳定性修复**:
    - 修复了 RootServer 在进程终止时的 `Double Free` Panic (SlotAllocator 重复释放 unified endpoint)。
    - 修复了 `sys_sleep` 唤醒逻辑，验证了 100 滴答的睡眠与唤醒。
    - 验证了多进程 IPC 通信 (Process 0 <-> Process 1) 的稳定性。

### 2026-01-17: Shell 增强与多任务调度 (Shell Enhancements & Multi-task Scheduling)
- [x] **Shell 功能完善**:
    - 增强了 `ps` 命令，显示堆使用情况 (Heap)、已映射页帧数 (Frames) 和优先级 (Prio)。
    - 实现了 `Esc` 键清空当前行，`F1` 键显示帮助。
    - 修复了键盘驱动中的 Shift/Alt 键状态追踪，支持更多控制键。
- [x] **多任务调度优化**:
    - ProcessManager 新增优先级支持 (`priority` 字段)。
    - 实现了 `set_priority` 接口。
    - 实现了简单的优先级调度逻辑（为后续抢占式调度打基础）。

## 📊 OS 现状评估与路线图 (OS Evaluation & Roadmap)

### 当前状态评估 (Status Assessment)
- **开发阶段**: **Alpha 0.3 - 原型验证阶段 (Prototype Phase)**
    - 核心服务层 (RootServer) 已具备基础功能：进程管理、内存管理、虚拟文件系统 (RamFS)、Shell。
    - 实现了基础驱动：PS/2 键盘、Port I/O。
    - 用户态环境初步成型：支持动态内存分配、基础系统调用。
- **主要短板 (Key Deficiencies)**:
    - **缺乏持久化存储**: 文件系统纯基于内存，重启即丢失。
    - **缺乏标准库**: 用户态程序需手动封装系统调用，开发效率低。
    - **驱动支持有限**: 仅有基础输入和调试输出，无显示驱动、无块设备驱动。

### 路线图 (Roadmap)

#### Phase 1: 基础架构巩固 (Current)
- [x] 完善 Shell 功能 (文件操作、进程查看)。
- [x] 实现基础 VFS 和 RamFS。
- [x] 优化多任务调度 (优先级队列)。
- [ ] **创建标准用户库 (`libnova`)**: 封装系统调用，提供类似 std 的接口。

#### Phase 2: 持久化与扩展 (Next)
- [ ] **块设备驱动**: 实现基础 ATA/IDE 驱动。
- [ ] **持久化文件系统**: 实现 FAT16 或 SimpleFS，挂载硬盘分区。
- [ ] **ELF 加载增强**: 支持向进程传递参数 (`argc`, `argv`)。

#### Phase 3: 交互与网络 (Future)
- [ ] **图形界面 (GUI)**: 帧缓冲驱动 (Framebuffer) + 窗口管理器。
- [ ] **网络栈**: 网卡驱动 + TCP/IP 协议栈。

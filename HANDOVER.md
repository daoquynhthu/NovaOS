# NovaOS RootServer 开发任务交接文档

## 1. 项目概况
本项目旨在基于 **seL4 microkernel (x86_64)** 开发一个 **Rust 编写的 RootServer**。
RootServer 是 seL4 启动后的第一个用户态进程，负责接管系统资源（Untyped Memory, CSpace, VSpace）并初始化操作系统环境。

### 当前版本: v0.0.3-alpha (2026-01-17)

## 2. 核心架构与已实现功能
### 2.1 进程管理 (`process.rs`)
- **TCB & VSpace**: 支持创建独立的页表 (PML4) 和线程控制块 (TCB)。
- **ELF 加载**: 自研 `ElfLoader`，支持解析静态链接的 ELF 文件并加载到独立地址空间。
- **资源追踪**: 使用 RAII 模式管理 Caps (CNode, VSpace, Frames)，支持进程终止时的资源自动回收。
- **状态机**: 进程状态包括 `Ready`, `Running`, `Sleeping`。

### 2.2 内存管理 (`memory.rs`)
- **UntypedAllocator**: 使用 Best-Fit 策略从 seL4 的 Untyped Memory 分配对象。
- **动态堆 (Heap)**: 实现了 `sys_brk`，支持用户态进程动态申请内存 (4KB 粒度)。

### 2.3 系统调用 (Syscalls)
基于 `seL4_Call` 的同步 IPC 协议，RootServer 监听 Badged Endpoint。
- **Label 1 (Write)**: 调试输出。
- **Label 2 (Exit)**: 进程退出。
- **Label 3 (Brk)**: 调整堆大小。
- **Label 4 (Yield)**: 协作式调度让出。
- **Label 5 (Sleep)**: (WIP) 睡眠指定 Ticks。

### 2.4 驱动与中断 (`acpi.rs`, `ioapic.rs`)
- **ACPI**: 解析 RSDP/RSDT/MADT，处理 ISO (Interrupt Source Override) 映射。
- **IOAPIC**: 动态获取 IOAPIC Cap，配置 IRQ 重定向。
- **Timer**: 使用 PIT (8254) 作为系统时钟源，映射到 Vector 40。

## 3. 当前阻碍与待修复问题 (Critical Issues)

### 🔴 `sys_sleep` 唤醒失败
- **现象**: 运行 `test.ps1` 时，User App 输出 "Sleeping for 100 ticks..." 后不再有响应。测试脚本最终超时失败。
- **分析**:
  - 代码逻辑位于 `services/rootserver/src/main.rs` 的事件循环中。
  - 可能性 A: IOAPIC 配置的 Vector 40 中断未被 CPU/seL4 接收（需检查 `seL4_IRQHandler_SetNotification` 绑定）。
  - 可能性 B: 中断发生但 RootServer 未正确 Ack，导致后续中断被屏蔽。
  - 可能性 C: 逻辑错误导致 `process.wake_at_tick` 条件从未满足。
- **复现**: 运行 `.\test.ps1`。

## 4. 环境与构建
- **构建**: `.\build.ps1` (编译 Kernel + RootServer + UserApp)
- **测试**: `.\test.ps1` (启动 QEMU 并验证串口输出)
- **依赖**: Rust (Stable/Nightly), QEMU, Python, CMake, Ninja.

## 5. 接下来的工作建议 (Next Steps)
1. **修复时钟中断**:
   - 在 `main.rs` 的 Timer 分支添加调试打印，确认是否收到 Badge 为 1 (或其他 Timer Badge) 的通知。
   - 确认 `seL4_IRQHandler_Ack` 是否被调用。
2. **完善 IPC**:
   - 实现 `sys_send` / `sys_recv`，支持进程间通信。
3. **文件系统**:
   - 引入 InitRD，支持从内存加载文件。

## 6. 关键文件索引
- `services/rootserver/src/main.rs`: 主事件循环，中断与 Syscall 分发。
- `services/rootserver/src/process.rs`: 进程控制块与状态管理。
- `services/user_app/src/main.rs`: 用户态测试程序。
- `test.ps1`: 自动化测试入口。

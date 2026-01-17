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

### 🟠 RootServer 重构验证
- **状态**: 刚刚完成了从裸 seL4 接口到 `libnova` 抽象的大规模迁移。
- **风险**: 虽然编译错误已基本解决，但需重点关注运行时回归测试，特别是：
  - 进程创建 (`Process::spawn`) 时的 Capability 复制与 Mint 操作。
  - 异常处理 (`sys_reply_recv`) 的参数传递是否正确。
- **行动**: 运行 `test.ps1` 进行全量回归测试。

## 4. 环境与构建
- **构建**: `.\build.ps1` (编译 Kernel + RootServer + UserApp)
- **测试**: `.\test.ps1` (启动 QEMU 并验证串口输出)
- **依赖**: Rust (Stable/Nightly), QEMU, Python, CMake, Ninja.

## 5. 接下来的工作建议 (Next Steps)
1. **完成重构收尾**:
   - `services/rootserver/src/elf_loader.rs` 和 `shell.rs` 中仍有少量直接的 `sel4_sys` 调用，建议将其替换为 `libnova` 调用。
   - 运行完整测试套件，确保重构没有引入 Regression。
2. **修复时钟中断**:
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

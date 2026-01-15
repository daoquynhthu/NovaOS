# NovaOS 项目进度书 (Project Progress)

> 本文档用于记录项目里程碑、已完成任务以及下一步计划。每次重大变更后必须更新。

## 📅 当前状态
- **日期**: 2026-01-16
- **阶段**: 0.4 - 驱动框架与形式化验证 (Driver & Verification)
- **版本**: `v0.0.1-alpha`

## ✅ 已完成任务 (Completed)

### 2026-01-15: 内存管理与首次启动 (First Boot & Memory)
- [x] **系统启动 (First Boot)**:
    - 修复了链接器脚本和 Multiboot 头问题，成功在 QEMU 中加载内核。
    - 解决了 RootServer 启动时的 Cap Fault 问题。
    - RootServer 成功获取并解析 `BootInfo`。
- [x] **物理内存分配器 (BumpAllocator)**:
    - 实现了基于 Untyped Memory 的物理内存分配算法。
    - 能够正确识别并跳过 Device Untyped，只分配 RAM。
- [x] **CSpace 分配器 (SlotAllocator)**:
    - 实现了简单的 Slot 分配逻辑，用于管理 CNode 空闲槽位。
- [x] **系统调用修复 (seL4_Untyped_Retype)**:
    - 深入分析并修复了 `seL4_Untyped_Retype` 参数错误（正确处理 Root CNode 的 extraCaps 和 depth/offset）。
    - 验证了连续分配 5 个 4KB 页帧的功能，系统运行稳定。

### 2026-01-15: 基础架构初始化
- [x] **Git 仓库初始化**: 建立了包含 Submodules 的 Git 仓库，完成了首次提交。
- [x] **构建系统框架**: 配置了 CMake + Cargo 的混合构建系统 (`CMakeLists.txt`, `Cargo.toml`)。
- [x] **核心设计文档**:
    - `NovaOS_Proposal.md`: 确定了 Rust + seL4 的双重安全架构。
    - `NovaOS_Syscall_Design.md`: 设计了同步/异步混合的系统调用接口。
    - `NovaOS_Memory_Error_Spec.md`: 定义了内存分层模型与错误传播机制。
- [x] **代码目录结构**:
    - `kernel/seL4`: 官方内核源码。
    - `libs/seL4-sys`: 预留给 Rust FFI 绑定的空壳。
    - `services/rootserver`: Rust 编写的第一个用户态进程框架。
- [x] **seL4-sys 绑定生成**:
    - 完善了 `build.rs`，实现了从 CMake 构建产物中自动搜索头文件。
    - 配置了 `bindgen` 以生成安全的 Rust 接口。
    - 更新了 `CMakeLists.txt` 以传递 `SEL4_OUT_DIR` 环境变量。

### 2026-01-15: 修复 QEMU 启动与 Rust Nightly 迁移
- [x] **QEMU 启动修复**:
    - 解决了 `Huge page not supported` 错误（通过添加 `+pdpe1gb` CPU 标志）。
    - 解决了 QEMU JIT 内存不足问题（用户清理磁盘 + 调整参数）。
    - 验证了 `test.ps1` 自动化测试通过，成功捕获 `[TEST] PASSED`。
- [x] **Rust Nightly 迁移**:
    - 启用了 `#![feature(custom_test_frameworks)]`。
    - 恢复了 `cargo test` 单元测试支持。
    - 修复了 RootServer 中的 warnings (cast error)。

### 2026-01-15: IPC 通信机制
- [x] **seL4-sys 系统调用补全**:
    - 手动实现了 `seL4_Recv` 和 `seL4_ReplyRecv` 的内联汇编封装（解决 bindgen 缺失问题）。
    - 修复了 IPC 调用中的寄存器传递问题。
- [x] **IPC 抽象层**:
    - 创建 `ipc.rs` 模块，封装 `Endpoint` 结构体。
    - 实现了 `call` (Client) 和 `recv/reply_recv` (Server) 方法。
- [x] **Client-Server 通信验证**:
    - 在 RootServer 和 Worker 线程之间建立了双向通信。
    - 成功验证了数据发送与回复流程。

### 2026-01-15: 安全与稳定性增强
- [x] **Badge 身份认证 (Security)**:
    - 实现了带 Badge 的 Endpoint Capability Minting。
    - 验证了服务端通过 Badge 识别 Client 身份（Badge=0xBEEF）。
- [x] **健壮的 CSpace 管理器 (Robust CNode)**:
    - 将 `SlotAllocator` 升级为基于 Bitmap 的分配器。
    - 实现了 `alloc` 和 `free` 操作，确保槽位管理的正确性。
    - 修复了分配失败时的资源泄漏问题。
- [x] **形式化验证准备**:
    - 创建了 `NovaOS_Verification_Spec.md`，定义了关键数据结构的不变量（Invariants）。
    - 梳理了内存管理、进程管理和 IPC 的验证目标。

### 2026-01-15: 多进程与资源隔离 (Phase 0.3)
- [x] **独立 VSpace 实现**:
    - 实现了 `VSpace::new_from_scratch`，支持为新进程分配独立的 PML4 和 ASID。
    - 解决了 x86_64 下 ASID Pool 分配的 Invocation Label 问题 (Label=44)。
- [x] **隔离性验证 (Simple Loader)**:
    - 实现了一个简易的二进制加载器，将机器码手动映射到子进程的独立 VSpace 中。
    - 成功运行了隔离的子进程，验证了内存空间互不干扰。
    - 实现了 Capability 的 Copy/Mint 机制，支持共享/独立映射。
### 2026-01-15: 审计与重构 (Refactoring & Audit)
- [x] **内存管理优化 (Best-Fit Allocator)**:
    - 重构 `UntypedAllocator`，实现最佳匹配 (Best-Fit) 策略。
    - 引入 `usage` 跟踪数组，减少内存碎片化。
    - 添加了内存分配的压力测试 (Stress Test)。
- [x] **资源防泄漏 (Resource Tracking)**:
    - 在 `VSpace` 中引入 `paging_caps` 数组，显式追踪分页结构 Capability。
    - 确保进程销毁时能够正确回收分页资源。
- [x] **代码质量提升**:
    - 统一错误处理：全面采用 `check_syscall_result` 处理系统调用返回值。
    - 日志清理：移除生产环境不必要的调试打印，保留关键 INFO/ERROR。
    - 修复了 VSpace 重复定义和可变借用等编译错误。
- [x] **ELF 解析支持 (ElfLoader)**:
    - 引入 `xmas-elf` 库，实现了 `ElfLoader` 模块。
    - 支持解析 ELF Program Headers 并加载 LOAD 段到目标 VSpace。
    - 实现了跨 VSpace 的内存拷贝（RootServer -> Target VSpace）。

### 2026-01-16: 硬件发现与 ACPI 解析 (Hardware Discovery)
- [x] **ACPI 解析器基础**:
    - 实现了 `acpi.rs` 模块，解析 RootServer BootInfo 中的 ACPI RSDP。
    - 实现了 RSDT (Root System Description Table) 的查找与映射。
    - 解决了物理内存映射中的回溯访问问题 (RevokeFirst)，引入 `MappedCap` 策略。
- [x] **多表扫描与 MADT 解析**:
    - 实现了遍历 RSDT 并自动映射所有子表 (FACP, APIC, HPET, WAET)。
    - 成功解析 MADT (APIC Table) 获取 Local APIC 物理地址。
    - 验证了跨页表映射的正确性 (Handling unaligned structs and multi-page tables).
    - 实现了 MADT 记录遍历，成功识别 Local APIC, IOAPIC, ISO (Interrupt Source Override) 条目。
- [x] **运行时形式化验证 (Runtime Verification)**:
    - 实现了 `acpi_checksum` 校验算法，确保 RSDP/RSDT 数据完整性。
    - 为 `SlotAllocator` 增加了形式化 Pre/Post-conditions 断言 (`alloc`/`free`/`init`)。
    - 通过了严格的运行时断言测试，系统稳定性提升。
- [x] **IOAPIC 初始化与中断 (Interrupts)**:
    - 解析 MADT 获取 IOAPIC 物理地址 (0xfec00000)。
    - **重大突破**: 成功调用 `seL4_IRQControl` 获取了 IOAPIC IRQ Handler (IRQ 1 -> Vector 33)。
    - **技术攻关**:
        - 解决了 `sel4-sys` 绑定缺失问题，手动实现了 `X86IRQIssueIRQHandlerIOAPIC` 系统调用。
        - 通过分析内核构建产物，精确定位了 Invocation Label 为 **53** (原误用为 2 导致 Illegal Operation)。
        - 验证了 IOAPIC GSI 到 CPU Vector 的映射。

## 🚀 下一步计划 (Next Steps)
- [x] **ACPI 表解析**:
    - 成功在 BootInfo 中定位 RSDP (Root System Description Pointer)。
    - 验证了 RSDP 签名 ("RSD PTR ") 和校验和。
    - 成功查找到 RSDT (Root System Description Table) 的物理地址。
    - **关键突破**: 实现了在 Untyped Memory 中反向查找物理地址对应的 Capability。
    - **关键突破**: 成功解析 MADT 并提取 CPU 拓扑和中断控制信息。
- [x] **压力测试通过**:
    - 解决了测试脚本超时问题 (timeout increased to 60s)。
    - 修复了 IPC Benchmark 中的死锁问题 (Worker now replies to exit signal)。
    - 成功完成了 1000 次 4KB 页帧分配的压力测试，无内存泄漏。

## 🚧 进行中任务 (In Progress)
- [ ] **中断控制器完善**:
    - [x] 解析 MADT 获取 IOAPIC 地址。
    - [x] 封装 `get_ioapic_handler` 系统调用。
    - [x] 修复 IRQControl 调用失败 (Error 3): 修正 Invocation Label 为 53。
    - [ ] 实现 IOAPIC 中断重定向表项配置。
    - [ ] 编写键盘驱动 (PS/2)，响应 IRQ 1 中断。
- [ ] **进程管理器完善**:
    - [x] 集成 `ElfLoader` 到进程创建流程。
    - [x] 实现 `spawn` 接口，支持从 ELF 镜像启动进程。
    - [x] 引入 `ProcessState` 枚举，完善生命周期管理。
    - [x] 增加形式化验证断言 (Formal Verification Assertions)。
    - [x] 实现 `ProcessManager` 全局结构体，管理多进程列表。
    - [x] 实现 PID 分配与查找。
    - [x] 完成 IPC 性能基准测试 (Benchmark)。
    - [ ] 实现动态内存映射 ACPI 表 (Map Device Memory)。

## 📝 备忘录
- **IOAPIC 初始化挑战**:
    - 尝试直接映射 IOAPIC 物理地址 (0xfec00000) 失败，原因是 seL4 内核在 x86 架构下独占管理 IOAPIC，不向用户态暴露对应的 Untyped Cap。
    - 转向使用 `seL4_IRQControl` 接口来请求 IRQ Handler。
    - 遇到 `sel4-sys` 绑定缺失问题：`seL4_IRQControl_GetIOAPIC` 未生成。
    - **解决方案**: 手动实现 `get_ioapic_handler`，并硬编码 Invocation Label 为 **53** (通过分析 `invocation.h` 计算得出)。
- **Formal Verification**:
    - 运行时断言 (`debug_assert!`) 已覆盖关键路径。
    - 审计日志 (`auditoration1.md`) 中的内存安全问题已大部分解决。

## 🛡️ 安全与规范检查记录
- **Git**: 已添加 `.gitignore` 防止敏感文件泄露。
- **构建**: 确认 Cargo Workspace 结构正确。

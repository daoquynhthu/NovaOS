# NovaOS 项目进度书 (Project Progress)

> 本文档用于记录项目里程碑、已完成任务以及下一步计划。每次重大变更后必须更新。

## 📅 当前状态
- **日期**: 2026-01-16
- **阶段**: 0.5 - 用户态进程与系统调用 (User Process & Syscall)
- **版本**: `v0.0.2-alpha`

## ✅ 已完成任务 (Completed)

### 2026-01-16: 构建修复与错误解决 (Build Fixes & Error Resolution)
- [x] **sel4-sys 构建修复**:
    - 解决了 `seL4_X86_VMAttributes` 枚举大小在 x86_64 Windows 环境下的编译断言错误。
    - 通过在 `build.rs` 中检测环境并定义 `_WIN32` 宏，强制使用 64 位枚举以匹配内核 ABI。
- [x] **RootServer 编译错误修复**:
    - 修复了 `main.rs` 中缺失的 `seL4_TCB_BindNotification` 和 `seL4_SetCap` 函数调用。
    - 替换为 `seL4_Call` + `invocation_label` 的手动实现，并使用 `seL4_SetCap_My`。
    - 解决了类型不匹配 (usize vs u64, seL4_Error vs int) 和格式化输出问题。
    - 清理了多余的 `unsafe` 块和未使用代码警告。
- [x] **集成测试修复与验证**:
    - 修复了 `test.ps1` 脚本的超时与成功判定逻辑，确保其能正确捕获 User App 的输出。
    - 在 RootServer 的 Syscall 处理中添加了测试通过标记 `[TEST] PASSED`。
    - 验证了 `test.ps1` 自动化测试全流程通过 (TEST RESULT: PASSED)。

### 2026-01-16: 动态内存与事件循环 (Dynamic Memory & Event Loop)
- [x] **统一事件循环 (Unified Event Loop)**:
    - 重构了 RootServer 的 `main` 循环，将中断处理 (Notification) 和系统调用处理 (IPC) 合并。
    - 实现了非阻塞的 Shell 交互，Shell 可在后台进程运行时响应键盘输入。
    - 引入了 Badged Endpoint 机制，用于区分中断 (Badge=0) 和不同进程 (Badge=PID+100) 的请求。
- [x] **动态内存支持 (sys_brk)**:
    - 实现了 `sys_brk` (Label 3) 系统调用，支持用户态进程动态调整堆大小。
    - 在 `Process` 结构中实现了堆帧 (Heap Frames) 的分配、映射与追踪。
    - 在 `user_app` 中实现了堆内存分配测试，验证了内存读写正确性。
- [x] **资源清理完善**:
    - 增强了 `terminate` 方法，确保在进程退出时释放所有堆内存页 (Heap Frames) 和分页结构 (Paging Structures)，防止内存泄漏。

### 2026-01-16: 用户态进程与系统调用 (User Process & Syscall)
- [x] **User App 框架**:
    - 创建了独立的 `user_app` crate，支持 no_std 环境。
    - 实现了用户态入口点 (`_start`) 和栈初始化。
    - 解决了 User App 的编译配置与链接问题。
- [x] **Syscall 协议实现**:
    - 定义了基于寄存器的 IPC 协议 (Label 1=Write, Label 2=Exit)。
    - 在 RootServer 中实现了 Syscall 处理循环 (`test_user_hello_program`)。
    - 在 `user_app` 中封装了 `seL4_Call` 汇编接口，修复了寄存器约束 (`inout`) 问题。
- [x] **集成测试自动化**:
    - 更新 `test.ps1` 支持 User App 的构建与验证。
    - RootServer 启动时自动加载并运行 User App。
    - 成功验证 "Hello from Rust User App via Syscall!" 输出。
- [x] **工程规范化 (Engineering Rigor)**:
    - 消除了 User App 和 RootServer 的所有编译警告 (Dead code, Unused variables, Non-snake case)。
    - 统一了代码风格，增强了运行时断言 (`debug_assert!`)。

### 2026-01-16: I/O 端口能力修复与安全加固 (IO Port Capability)
- [x] **seL4_X86_IOPort_Issue 修复**:
    - 修正 Root CNode extraCaps 的 cptr/depth 语义，解决 `Lookup of extra caps failed`。
    - 成功获取 0x0000-0xFFFF 全范围的 IOPort Capability，并写入 Root CNode 指定槽位。
- [x] **port_io 安全硬化**:
    - 移除临时的 Untyped/汇编 I/O fallback，所有端口访问必须通过 IOPort Capability。
    - 当 IOPort Capability 未初始化时进入安全等待（Yield），避免越权 I/O。
- [x] **零警告与回归验证**:
    - `cargo clippy --workspace --target x86_64-unknown-none` 无警告。
    - `test.ps1` 回归通过，捕获 `[TEST] PASSED`。

### 2026-01-16: 硬件发现与 ACPI 解析 (Hardware Discovery)
- [x] **ACPI 表解析**:
    - 实现了 RSDP -> RSDT -> MADT 的完整解析流程。
    - 成功映射并解析了 RSDT 和 MADT 表，获取了 Local APIC 和 IOAPIC 的物理地址。
    - 修复了 ACPI 表映射时的物理地址对齐问题。
- [x] **IOAPIC 初始化**:
    - 成功解析 ACPI MADT 表，定位 IOAPIC 地址。
    - 使用 `seL4_IRQControl_GetIOAPIC` 获取了 IOAPIC 的 IRQ Handler Capability。
    - 解决了 x86_64 下 `GetIOAPIC` 的 Invocation Label 问题 (Label=53)。
- [x] **中断处理框架**:
    - 实现了 Notification Object 的分配与绑定 (`seL4_IRQHandler_SetNotification`)。
    - 实现了 `ack_irq` (`seL4_IRQHandler_Ack`) 以发送 EOI。
    - 手动实现了 `seL4_Wait` 系统调用封装。
    - 验证了中断等待循环 (Interrupt Loop) 的基本逻辑。

### 2026-01-15: 基础架构与内存管理 (Phase 0.1 - 0.3)
- [x] **系统启动**: Multiboot 引导，Long Mode 进入，RootServer 启动。
- [x] **内存管理**: UntypedAllocator (Best-Fit), SlotAllocator (Bitmap), VSpace (Independent Paging)。
- [x] **进程管理**: TCB/VSpace 抽象，ELF 加载，Process Spawn。
- [x] **IPC**: 基础 Endpoint 通信，Badge 身份认证。

## 🚀 下一步计划 (Next Steps)
- [ ] **调度器完善**:
    - 实现协作式调度 (`sys_yield`)。
    - 将临时进程纳入全局 `ProcessManager` 管理。
- [ ] **文件系统基础**:
    - 设计简单的 InitRD 或内存文件系统。
    - 支持按文件名加载程序 (exec)。
- [ ] **错误恢复机制**:
    - 处理进程崩溃 (Fault Endpoint)，避免 RootServer Panic。

## 🚧 进行中任务 (In Progress)
- [ ] **中断控制器完善**:
    - [x] 解析 MADT 获取 IOAPIC 地址。
    - [x] 封装 `get_ioapic_handler` 系统调用。
    - [ ] 实现 IOAPIC 中断重定向表项配置。
- [ ] **文件系统基础**:
    - [ ] 设计简单的 InitRD 或内存文件系统。

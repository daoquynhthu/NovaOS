# NovaOS 项目进度书 (Project Progress)

> 本文档用于记录项目里程碑、已完成任务以及下一步计划。每次重大变更后必须更新。

## 📅 当前状态
- **日期**: 2026-01-15
- **阶段**: 0.1 - 基础架构搭建 (Foundation)
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

### 2026-01-15: RootServer 与测试框架集成
- [x] **RootServer 运行时**:
    - 实现了 `PanicHandler`，确保崩溃时有迹可循。
    - 实现了基于 `seL4_DebugPutChar` 的串口输出，支持 `println!` 宏。
- [x] **系统启动逻辑**:
    - 在 `_start` 中成功调用 `seL4_GetBootInfo`。
    - 打印了系统关键参数（Untyped Memory 槽位范围、CNode 大小）。
- [x] **测试框架集成**:
    - 引入了 Rust 的 `custom_test_frameworks`。
    - 实现了 `no_std` 环境下的测试运行器 (`test_runner`)。

## 🚧 进行中任务 (In Progress)
- [ ] **第一次构建验证**: 尝试编译整个系统并在 QEMU 中运行。

## 📝 下一步计划 (Next Steps)

### 阶段 0.2: 第一次启动 (First Boot)
1.  **实现 `seL4-sys` 构建逻辑**:
    - 从 CMake 构建产物中提取 `kernel_header` 路径。
    - 使用 `bindgen` 生成 Rust 结构体定义。
2.  **完善 `RootServer`**:
    - 读取并解析 `BootInfo`。
    - 打印系统启动横幅 (Banner) 到串口。
3.  **QEMU 仿真测试**:
    - 成功在 QEMU 中加载内核与 RootServer。
    - 验证串口输出正常。

## 🛡️ 安全与规范检查记录
- **Git**: 已添加 `.gitignore` 防止敏感文件泄露。
- **构建**: 确认 Cargo Workspace 结构正确。

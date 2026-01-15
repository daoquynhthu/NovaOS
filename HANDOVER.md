# NovaOS RootServer 开发任务交接文档

## 1. 项目概况
本项目旨在基于 **seL4 microkernel (x86_64)** 开发一个 **Rust 编写的 RootServer**。
RootServer 是 seL4 启动后的第一个用户态进程，负责接管系统资源（Untyped Memory, CSpace, VSpace）并初始化操作系统环境。

### 核心目标
- 验证 seL4 在 x86_64 下的启动流程。
- 构建基于 Rust 的系统服务基础（内存管理、线程管理、进程加载）。
- 实现自动化测试流程（QEMU + Unit Tests）。

## 2. 环境配置
- **操作系统**: Windows (PowerShell)
- **依赖工具**:
  - Rust (目前使用 Stable，建议切换至 Nightly 以支持 `custom_test_frameworks`)
  - CMake & Ninja (用于构建 seL4 内核)
  - QEMU (x86_64)
  - Python (sel4-deps)
  - GCC/LD (MinGW 或 x86_64-elf 工具链)

## 3. 构建与运行
### 脚本说明
- `build.ps1`: 核心构建脚本。
  - 编译 seL4 内核 (CMake)。
  - 编译 RootServer (Cargo)。
  - 生成 `build/images/rootserver.elf`。
- `test.ps1`: **(开发中)** 自动化测试脚本。
  - 尝试启动 QEMU 并捕获串口输出以验证 `[TEST] PASSED` 标记。
- `init_env.ps1`: 环境检查脚本。

### 常用命令
```powershell
# 完整构建
.\build.ps1

# 运行测试 (目前存在 QEMU 内存问题)
.\test.ps1
```

## 4. 当前开发进度 (Status)
### 已完成功能
1.  **内核引导**: 成功引导 seL4 kernel 并进入 RootServer `rust_main`。
2.  **运行时基础**:
    -   实现了 Panic Handler。
    -   实现了串口打印 (`println!`)。
    -   解析 `BootInfo`。
3.  **内存管理 (`memory.rs`)**:
    -   定义了 `ObjectAllocator` trait。
    -   实现了 `UntypedAllocator` (Bump Pointer 风格)，支持从 Untyped Memory 分配内核对象。
    -   **注意**: 之前修复了 `retype` 方法缺失问题，现在统一使用 `allocate` 接口。
4.  **地址空间 (`vspace.rs`)**:
    -   实现了基本的页表映射 (Map/Unmap)。
5.  **线程管理 (`process.rs`)**:
    -   可以创建 TCB (Thread Control Block) 并配置优先级。

### 进行中的任务 (WIP)
1.  **单元测试集成**:
    -   目标：在 `no_std` 环境下运行 Rust 单元测试 (`#[test]`)。
    -   现状：由于 Stable Channel 不支持 `#![feature(custom_test_frameworks)]`，暂时移除了 `main.rs` 中的测试入口代码。
2.  **自动化测试脚本 (`test.ps1`)**:
    -   目标：一键编译并运行 QEMU，根据串口输出判断测试通过/失败。
    -   现状：脚本逻辑已完成，但 QEMU 在当前 Windows 环境下运行时报 `jit buffer` 内存分配错误。

## 5. 已知问题与阻碍 (Issues)
### 1. QEMU JIT Buffer 内存不足
- **现象**: 运行 `test.ps1` 时 QEMU 报错：
  `allocate 1073741824 bytes for jit buffer: 页面文件太小，无法完成操作`
- **原因**: QEMU 的 TCG (Tiny Code Generator) 默认请求 1GB 的 JIT 缓存，而当前开发机的 Windows 页面文件/内存配额不足。
- **尝试过的修复**: 尝试设置 `-accel tcg,tb-size=32` (32MB)，但仍未完全解决或导致其他 panic。

### 2. Rust Stable vs Nightly
- **现象**: 为了支持 `#[test]` 和自定义测试运行器 (`test_runner`)，需要 Rust Nightly 特性。当前为了保持编译通过，回退到了纯业务代码状态。
- **影响**: 无法方便地编写和运行细粒度的单元测试。

### 3. Linker Warnings
- **现象**: `ld.lld: warning: ... refers to a non-alloc section at ...` (在 `head.S` 中)。
- **状态**: 暂时忽略，不影响运行，但未来需要修复 Multiboot 头部的段属性。

## 6. 接下来的工作建议 (Next Steps)
1.  **解决 QEMU 运行问题**:
    -   尝试增加 Windows 虚拟内存（页面文件）。
    -   或者在支持虚拟化的机器上使用 `-accel haxm` 或 `-accel whpx` 代替 TCG。
    -   调整 QEMU 参数以大幅降低内存占用 (e.g., `-m 64M` 配合正确的 `tb-size`)。
2.  **切换到 Rust Nightly**:
    -   执行 `rustup override set nightly`。
    -   在 `main.rs` 中恢复 `#![feature(custom_test_frameworks)]` 和 `test_runner` 相关代码。
    -   参考: `#[test_case]` 和 `crate::test_runner` 的实现。
3.  **完善内存分配器测试**:
    -   在测试框架就绪后，编写针对 `UntypedAllocator` 的边界测试（如内存耗尽、重复释放）。
4.  **实现 IPC**:
    -   下一步核心功能是实现进程间通信 (IPC)，这是微内核系统的基础。

## 7. 关键代码位置
- 入口点: `services/rootserver/src/main.rs`
- 内存分配: `services/rootserver/src/memory.rs`
- 启动汇编 (Kernel): `kernel/seL4/src/arch/x86/64/head.S`
- 构建脚本: `build.ps1`, `test.ps1`

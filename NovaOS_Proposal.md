# NovaOS 项目设计提案：构建下一代高安全性微内核操作系统

## 1. 项目愿景
NovaOS 旨在构建一个基于 seL4 微内核的、完全原创的、兼具极致性能与数学级安全性的现代化操作系统。通过吸取 x86_64 的历史教训以及 Linux/macOS 的架构痛点，NovaOS 将采用全新的能力导向（Capability-based）架构，而非传统的 POSIX 模型。

## 2. 核心架构原则
- **基于 seL4 的形式化验证基座**：利用 seL4 的数学证明保证内核无漏洞、强隔离。
- **纯粹的能力导向安全 (Object-based Security)**：系统中不存在全局命名空间，所有资源访问必须持有显式的“权能（Capability）”。
- **混合 IPC 模型**：
    - **同步 `seL4_Call`**：用于元数据操作、低延迟控制流。
    - **异步环形缓冲区 (Ring Buffer)**：用于高吞吐量大块数据传输（网络、磁盘）。
- **能力目录服务 (Capability Directory Service)**：在纯能力模型之上，提供受限的、受信任的服务查询机制，避免“能力传递地狱”。
- **WASM 辅助运行时**：WASM 定位为“不可信代码”的隔离环境，而非首选应用格式。原生应用首选 Rust 直接调用 `libnova`。

## 3. 对现有平台的改进方案

### 3.1 针对 x86_64 / 现代硬件
- **消除历史包袱**：仅支持 64 位模式，彻底废弃实模式切换、复杂的段管理等冗余机制。
- **硬件辅助隔离**：强制要求并利用 IOMMU、VT-d/AMD-Vi，确保外设 DMA 无法破坏内存隔离。
- **中断路由优化**：采用 MSI-X 中断路由，直接将硬件中断映射为内核通知对象。

### 3.2 针对 Linux/macOS 的经验教训
- **非 POSIX 原生 API**：废弃 `fork()`、全局 `errno` 等过时设计，采用基于 `Promise/Future` 的异步系统调用接口。
- **零拷贝设计**：所有大块数据传输（如网络包、磁盘块）通过共享内存引用传递，避免内核与用户态间的内存拷贝。
- **确定性调度**：利用 seL4 的调度上下文，为关键组件提供时间预算保证，防止 CPU 饥饿。

## 4. 技术路线图 (Roadmap)

### 阶段一：基础基座 (Foundation)
- **自定义 seL4-Rust 绑定**：建立与特定 seL4 版本匹配的、类型安全的 Rust 接口层。
- **RootServer 核心实现 (NovaInit)**：
    - 解析 `seL4_BootInfo`。
    - 建立初始 `CSpace` 与 `VSpace`。
    - 硬件发现（DeviceTree/ACPI）。
    - Untyped 内存管理池。
- **NovaConsole**：基础的串口驱动与调试日志系统。

### 阶段二：核心服务 (Core Services)
- **VSpace Manager**：管理虚拟地址空间分配。
- **CapStore**：分布式的权能存储与管理服务。
- **Async IPC Manager**：基于共享内存的异步通信框架。

### 阶段三：驱动与 I/O (I/O Framework)
- 实现 **VirtIO** 标准驱动集（Block, Net, Console）。
- 建立驱动隔离模型（Driver Sandbox）。

### 阶段四：应用运行环境 (Runtime)
- 集成 **NovaWasm**：自研或集成的轻量级 WASM 运行时。
- 开发 **libnova**：为 C/Rust 提供的原生系统调用封装库。

## 5. 编程语言策略与构建标准

### 5.1 语言选择：Rust 优先
为了实现“极致安全”的目标，NovaOS 决定在用户态系统服务层全面采用 **Rust**。
- **双重安全保证**：seL4 提供内核级的空间隔离，Rust 提供语言级的内存安全（消除缓冲区溢出、悬空指针等）。
- **零成本抽象**：Rust 的性能足以胜任驱动开发与系统核心组件。
- **内核接口**：seL4 内核保持使用 C 语言（为了维持形式化验证的有效性），通过自动生成的 Rust 绑定（FFI）进行交互。

### 5.2 严苛的构建标准
- **零警告策略**：所有代码必须在 `deny(warnings)` 下编译。
- **强制静态分析**：集成 Clippy, Miri 等工具进行代码质量与并发模型验证。
- **统一代码风格**：使用 `rustfmt` 和特定 lint 规则强制规范代码。
- **自动化测试**：每个系统服务必须包含单元测试，并在 QEMU 模拟环境中进行集成测试。

## 6. 开发环境与工具
- **内核**：seL4 (Verified C)
- **系统服务与驱动**：Rust (Stable/Nightly depending on requirements)
- **构建系统**：CMake + Cargo (通过 `Corrosion` 等工具集成)
- **目标架构**：x86_64 (首选，考虑到工具链成熟度与 seL4 稳定性), RISC-V 64 (作为长期研究目标)。
- **调试**：GDB + QEMU + 串口跟踪

---
*NovaOS: The future of secure computing starts here.*

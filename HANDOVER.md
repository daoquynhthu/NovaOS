# NovaOS RootServer 开发任务交接文档

## 1. 项目概况
本项目基于 **seL4 microkernel (x86_64)** 开发，目标是构建一个 **通用操作系统 (General Purpose OS)** 的 RootServer。
RootServer 作为 seL4 启动后的首个用户态进程，负责接管系统资源、初始化硬件驱动、提供文件系统服务及进程管理功能。

### 当前版本: v0.0.9-alpha (2026-01-21)
**状态**: 系统调用接口标准化完成，权限控制体系初步建立。文件系统核心功能（NovaFS）趋于稳定。
**最近更新**: 修复了 `mv` 命令静默失败的潜在 Bug (NovaFS lookup logic)，对齐了所有文件系统相关的 Syscall。

## 2. 核心功能进展 (已完成)

### 2.1 系统调用与 IPC 标准化 (Syscalls)
- **ID 对齐**: 严格对齐 libnova 与 Kernel 的 Syscall ID (Open=20, Read=21, Write=22, Close=23, Rename=37)。
- **协议规范**: 统一使用 `MessageInfo` 传递参数长度，`MR0-MRn` 传递数据。
- **稳定性**: 修复了 `sys_write` 数据解包错误和返回值丢失问题，确保大数据量写入稳定。

### 2.2 权限控制体系 (Permission Control)
- **UID/GID 模型**: `Process` 结构体包含 `uid`, `gid`。
- **检查机制**: 实现了 `process::can_control(target, actor)`。
- **集成**:
  - `sys_kill`: 仅允许 Owner 或 Root 发送信号。
  - `sys_rename`: 检查源目录和目标目录的写权限。
  - `sys_open/write`: 基础的文件所有权检查。

### 2.3 NovaFS 文件系统
位于 `services/rootserver/src/fs/novafs.rs`。
- **核心修复**: 修复了 `lookup` 函数在遇到稀疏文件 (Hole) 时错误读取 SuperBlock 的严重 Bug。
- **特性**:
  - **透明加密**: ChaCha20 Poly1305。
  - **重命名**: `sys_rename` 支持原子移动，包含回滚机制。
  - **稀疏文件**: 支持大文件空洞。
  - **健壮性**: `remove` 和 `rename` 包含自校验逻辑，防止静默失败。

### 2.4 Shell 工具链
- **新增**: `mv` (重命名), `sys_kill` 测试。
- **修复**: `sleep` 命令语法错误。

## 3. 待验证与已知问题 (Pending Verification & Issues)

### � NovaFS 重命名校验 (Rename Verification)
- **状态**: 刚刚修复了 `lookup` 中的稀疏块处理 Bug。
- **现象**: 之前 `mv` 命令可能出现源文件未删除的现象（静默失败）。
- **验证**: 需重新运行 `test.ps1` 中的 `mv` 测试用例，确认源文件是否被正确删除。

### 🟡 权限控制覆盖率
- **状态**: 框架已建立，但部分边缘 Case 需测试。
- **任务**: 验证不同 UID 用户对文件的访问控制是否生效。

## 4. 接手工作建议 (Next Steps)

1.  **运行集成测试**:
    - 执行 `powershell -File .\test.ps1`。
    - 重点关注 `Rename Test` 章节的输出。

2.  **完善进程管理**:
    - 实现 `sys_fork` 和 `sys_exec`，目前仅有 `sys_spawn`。
    - 完善 `waitpid` 的阻塞逻辑 (目前部分为忙等待)。

3.  **代码清理**:
    - `rootserver/src/main.rs` 中的 Syscall Handler 随着功能增加变得庞大，建议按模块拆分。

## 5. 项目结构索引
- **构建**: `powershell -ExecutionPolicy Bypass -File .\build.ps1`
- **测试**: `powershell -ExecutionPolicy Bypass -File .\test.ps1`
- **关键路径**:
  - `libs/libnova/src/syscall.rs`: 用户态系统调用封装。
  - `services/rootserver/src/main.rs`: 内核 Syscall 分发逻辑。
  - `services/rootserver/src/fs/novafs.rs`: 文件系统核心。

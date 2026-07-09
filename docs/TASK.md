# TASK.md — NovaOS 当前执行计划

> **定位**: 当前阶段的动态执行计划。基于 [PLAN.md](./PLAN.md) 拆解。  
> **状态**: `🟡 执行中`  
> **对应阶段**: Phase 4 — 微内核化推进  
> **引用**: 子任务编号 `[TASK-N]` 可被 ISSUE.md 和 PROGRESS.md 引用。  
> **门禁**: 每个子任务必须通过 `cargo check --workspace --target x86_64-unknown-none` 才能标记完成。

---

## 前置状态

- Phase 0–3 已全部完成。
- P4.1（独立 CSpace）✅ / P4.2（ATA 能力转移）✅ / P4.3（死锁解除）✅ / P4.6（IPC 校验）✅
- 详情见 [PROGRESS.md](./PROGRESS.md) 与 [INDEX.md](./INDEX.md)。

---

## 线性执行计划

| # | 任务 | PLAN | 优先级 | 依赖 | 状态 |
|---|------|------|--------|------|------|
| 1 | Shell 迁移到 fs_server | P4.4 (new) | P1 | P4.2 | ⏳ |
| 2 | RootServer 降权收口 | P4.5 (new) | P2 | P4.3, P4.4 | ⏳ |
| 3 | 关闭 debug syscall | P4.7 (new) | P1 | P4.5 | ⏳ |
| D1 | QEMU 回归验证 | P4 债务 | P0 | 全部修复 | ✅ |
| D2 | clippy 债务削减 | P4 债务 | P1 | — | ⏳ |
| D3 | ISSUE-83 决策 | P4 债务 | P3 | — | ⏳ |

---

## 任务 1: Shell 命令 FS 操作全部迁移到 fs_server（P4.4 new）

**目标**: 将所有 Shell 命令的本地 NovaFS 操作替换为 fs_server IPC 调用，消除"双 NovaFS 实例"架构风险。Shell UI 保留在 RootServer（它是个 shell，不是文件系统），但所有文件操作直接走 fs_server IPC，不再经过本地 NovaFS。

**架构约束（AGENT.md §4-2）**：禁止一次性删除回退路径。在迁移过程中保留 `spawn_fs_helper` + LOCAL_VFS fallback 的回退链，最后在所有 IPC 路径验证通过后统一删除。

**核心架构要求**：
- fs_server 成为唯一 NovaFS 数据面权威
- RootServer 停止挂载本地 NovaFS
- epoch 刷新机制可移除（单数据源后不需要）
- Shell UI、进程管理、allocator 访问留在 RootServer

**参考实现**: `encrypt`/`decrypt` 命令已经示范了直接 IPC 模式：通过 `crate::services::lookup_latest_ready("fs")` 获取 fs_server endpoint，然后调用 `libnova::fs_ipc::*_direct()`。

### 第一阶段：添加 fs_server IPC fallback（RED→GREEN）

为每个有 LOCAL_VFS fallback 的命令添加直接的 fs_server IPC 调用作为新的首选路径。保留 `spawn_fs_helper` 和 LOCAL_VFS 作为第二/第三 fallback。

### 第二阶段：验证 IPC 路径覆盖所有操作

运行 QEMU smoke 测试确认所有 Shell 命令能通过 fs_server 工作。

### 第三阶段：移除 RootServer 本地 NovaFS 挂载

确认 fs_server IPC 覆盖所有文件操作后，移除 RootServer 的 `DISK_FS` 和 `novafs_core::VFS` 本地实例。RootServer 不再拥有 NovaFS 数据面。

### 第二阶段：exec 二进制加载迁移 & 移除本地 NovaFS

| # | 子任务 | 状态 | 类型 | 说明 |
|---|--------|------|------|------|
| 1.6 | 迁移 `exec`、`runhello` 二进制加载到 IPC | ✅ | RED→GREEN | `open_direct + read_direct` 替代 `VFS::read_file`，保留 VFS fallback |
| 1.8 | 移除 RootServer 本地 NovaFS 挂载 | ⬜ | 清理 | 确认 fs_server IPC 覆盖全部 FS 操作后删除 `DISK_FS` / `novafs_core::VFS` |
| 1.9 | `cargo check --workspace` + QEMU smoke | ⬜ | 门禁 | 全绿通过 |

---

## 任务 2: RootServer 降权收口（P4.5 new）

**目标**: RootServer 仅保留最小编排职责：进程创建/终止 + 服务注册 + 能力分配。移除文件操作、Shell、块设备访问。

### 子任务

| # | 子任务 | 状态 | 说明 |
|---|--------|------|------|
| 2.1 | Boot 流程去掉本地 NovaFS 格式化/安装 | ✅ | 替换为 `create_deprecated_local_fs()` 弃用桩 |
| 2.2 | fs_server 接管磁盘初始化（自动格式化） | ✅ | fs_server mount 失败时自动 format；local FS 安装二进制供旧 syscall 使用 |
| 2.3 | Shell 命令中移除 LOCAL_VFS fallback | ⬜ | 仅保留 IPC + spawn_fs_helper |
| 2.4 | RootServer 移除 ATA 驱动 | ⬜ | |
| 2.5 | 移除文件 syscall handler | ⬜ | 转发到 fs_server |
| 2.6 | `cargo check --workspace` + QEMU smoke | ⬜ | |

---

## 任务 3: 关闭 debug syscall（P4.7 new）

**目标**: 在生产配置中禁用 `seL4_SysDebugHalt` 等调试 syscall，或添加编译时门控。攻击面缩小。

### 子任务

| # | 子任务 | 状态 | 说明 |
|---|--------|------|------|
| 3.1 | 识别所有 debug syscall 调用点（seL4_DebugPutChar 等） | ⬜ | 排除必要 console 输出 |
| 3.2 | 添加编译时门控（`cfg(debug_assertions)` 或 feature flag） | ⬜ | |
| 3.3 | `cargo check --workspace` + 单元测试 | ⬜ | |

---

## 债务任务 D1: QEMU 回归验证

**目标**: 验证 10+ TASK 的变更不影响系统启动。当前自 Phase 1 构建规范调整以来未在 QEMU 中测试过系统。

**现状风险**: 根因是 Windows 无法构建 seL4 kernel，需要在 WSL/Linux 上编译，Windows 上 `cargo check` 只能验证 Rust 层。以下变更路径未经 QEMU 验证：
- TASK-4 handler 拆分（dispatch 逻辑重构）
- TASK-5 IPC 打包统一（MR 读写逻辑变更）
- TASK-6 枚举替换魔术数字（dispatch 逻辑重构）
- TASK-7 分配器移动（memory.rs re-export）
- P4.1~P4.6 所有变更

### 子任务

| # | 子任务 | 状态 | 说明 |
|---|--------|------|------|
| D1.1 | 在 WSL/Linux 上构建完整 QEMU 镜像 | ⬜ | `cmake -B build -S .` + `ninja` |
| D1.2 | 运行 `test.ps1 -Smoke`（5 stage 快速回归） | ⬜ | 验证 kernel boot + 基本功能 |
| D1.3 | 如有失败，定位并修复回归 | ⬜ | |
| D1.4 | 运行 `test.ps1` 完整回归（~50 stage） | ⬜ | Blocking 前可先跑 Smoke |

---

## 债务任务 D2: clippy 债务削减

**目标**: 将 `cargo clippy -p rootserver --target x86_64-unknown-none` 从 ~64+ error 降至 ~10 以下，为 Phase 5 安全审计做准备。

### 子任务

| # | 子任务 | 状态 | 说明 |
|---|--------|------|------|
| D2.1 | 分类统计 clippy error 来源（按模块） | ⬜ | 识别高密度区域 |
| D2.2 | 优先修复 handlers/ 与 main.rs dispatch 区域的 clippy error | ⬜ | |
| D2.3 | 修复完成后 `cargo clippy -p rootserver --target x86_64-unknown-none` 确认 | ⬜ | |
| D2.4 | 将 clippy 检查纳入 CI（`cargo clippy --workspace -- -D warnings`） | ⬜ | |

---

## 债务任务 D3: ISSUE-83 决策 — PLAN.md 权限位范围

**问题**: PLAN.md P4.6 描述包含"权限位验证"，但实际交付范围只有消息长度检查和 capability 索引检查。

**结果**: 
- PLAN.md P4.6 已修正，移除"权限位"描述
- 明确分层：IPC entry 校验消息合法性 → handler 内部 `check_permission` 做文件权限 → P4.5 做 syscall 级授权
- ISSUE-83 ⚪ 已关闭

**状态**: ✅ 已完成

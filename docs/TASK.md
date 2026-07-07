# TASK.md — NovaOS 当前执行计划

> **定位**: 当前阶段的动态执行计划。基于 [PLAN.md](./PLAN.md) 拆解。  
> **状态**: `🟡 执行中`  
> **对应阶段**: Phase 4 — 微内核化推进  
> **引用**: 子任务编号 `[TASK-N]` 可被 ISSUE.md 和 PROGRESS.md 引用。  
> **门禁**: 每个子任务必须通过 `cargo check --workspace --target x86_64-unknown-none` 与新增 host 测试才能标记完成。

---

## 前置状态

- Phase 0–3 已全部完成。
- 当前 FS 架构：RootServer 同时持有 ATA 块设备驱动、NovaFS 数据面、syscall 分发、Shell 和服务编排角色。
- fs_server 为"持久代理"模式，通过 `RemoteBlockDevice`（内部调用 `sys_block_read/write` 回 RootServer）持有 NovaFS，依赖 epoch-based lazy refresh。
- 同步死锁 `FS_SYNC_FORWARD_ENABLED=false` 表明 RootServer 不能同步 Call fs_server。
- 详情见 [PROGRESS.md](./PROGRESS.md) 与 [INDEX.md](./INDEX.md)。

---

## 当前任务总览

| ID | 任务 | 对应 PLAN | 说明 | 状态 |
|----|------|-----------|------|------|
| P4.1 | fs_server 直接持有块设备 + NovaFS 实例 | P4.1 | 将块设备能力/访问权移入 fs_server，消除 epoch refresh 依赖 | 🟡 执行中 |

---

## P3.1: sync + 重启 + 一致性校验回归测试

**目标**: 在 `novafs_host.rs` 中添加持久化（format→write→sync→remount→verify）、一致性检查（bitmap 与 inode 目录项交叉校验）、以及异常中断恢复行为的 host 测试。

**对应 PLAN**: [PLAN-P3.1](./PLAN.md#phase-3-novafs-耐久性与一致性)

**涉及文件**:
- `libs/novafs-core/src/novafs.rs` — 一致性检查 API（新增 `pub fn check_consistency(&self) -> Result<...>`）
- `libs/novafs-core/tests/novafs_host.rs` — 新增持久化与一致性测试

**核心设计约束**:
- 一致性检查必须遍历 bitmap、inode 表、目录项并交叉验证。
- 重启测试使用 `MockBlockDevice` 保存/恢复快照模拟 reboot。
- `cargo check --workspace --target x86_64-unknown-none` 必须全绿。

### 子任务

| # | 子任务 | 状态 | RED test | GREEN test |
|---|--------|------|----------|------------|
| 3.1.1 | 在 `NovaFS` 上实现 `check_consistency()`：遍历 inode bitmap → 交叉验证 dir 条目、数据块引用 | ✅ | 无此方法 | `check_consistency()` 存在，支持 bitmap ↔ inode ↔ dir_entry 交叉验证 |
| 3.1.2 | 在 `novafs_host.rs` 添加写入→sync→快照→重启→验证测试 | ✅ | 无此测试 | `sync_and_reboot` 通过 |
| 3.1.3 | 在 `novafs_host.rs` 添加一致性检查回归测试（正常 FS + 空 FS） | ✅ | 无此测试 | `consistency_check_ok`、`consistency_check_empty` 通过 |
| 3.1.4 | `cargo test -p novafs-core --features std` | ✅ | — | 7 项全部通过 |

---

## P4.1: fs_server 直接持有块设备 + NovaFS 实例

**目标**: 让 fs_server 直接持有块设备访问权（不再通过 `RemoteBlockDevice` 回调 RootServer），直接实例化 NovaFS，消除 epoch-based lazy refresh 模式。这是解除 `FS_SYNC_FORWARD_ENABLED=false` 死锁的前提。

**现状**（代码探索结论）:
- ATA 块设备驱动在 `services/rootserver/src/drivers/ata.rs`，仅 RootServer 持有。
- fs_server 通过 `RemoteBlockDevice` 调用 `sys_block_read/write` 回 RootServer 完成块 I/O。
- 若 RootServer 同步 Call fs_server（如 `try_forward_fs_call`），而 fs_server 又 Call 回 RootServer 做块 I/O，则同一线程死锁。
- RootServer 的 `DISK_FS`（NovaFS 实例）与 fs_server 的 `LOCAL_FS` 通过 epoch 同步，存在两套 FS 状态。
- 当前 `FS_READ_PREFER_SERVER=true` 优先让 fs_server 处理读操作，但写操作仍走 RootServer 本地 FS。

**对应 PLAN**: [PLAN-P4.1](./PLAN.md#phase-4-微内核化推进)

**涉及文件**:
- `services/fs_server/src/main.rs` — 移除 `RemoteBlockDevice`，改为真实块设备 + 本地 NovaFS 实例
- `services/rootserver/src/main.rs` — 启动时向 fs_server 传递块设备能力/访问信息
- `libs/novafs-core/src/block_device.rs` — 需要共享内存块设备或直接 ATA 包装

**核心设计约束**:
- 不破坏 QEMU 集成回归（现有 test.ps1 各 stage 必须通过）。
- RootServer 上的 NovaFS 数据面逐步降权为“只读兼容备份”。
- 块 I/O 路径：fs_server → (ATA/共享内存) → 物理块，不再经过 RootServer syscall。
- `FS_SYNC_FORWARD_ENABLED` 仍保持 `false`，但打通 fs_server 数据面独立路径后，后续可设为 `true`。

### 子任务

| # | 子任务 | 状态 | 说明 |
|---|--------|------|------|
| 4.1.1 | 移除 fs_server 的 epoch-based lazy refresh：删除 `ensure_local_fs_fresh`、`refresh_local_fs`、`LOCAL_FS_EPOCH` | ✅ | fs_server 从 boot 起直接持有 NovaFS，无需 epoch 同步 |
| 4.1.2 | 在 `libnova` 或 `novafs-core` 中创建共享内存块设备，使 fs_server 与 RootServer 共享同一块设备数据 | ⬜ | 需要 `SharedMemoryBlockDevice` 或直接内存映射块设备 |
| 4.1.3 | 将 fs_server 的 `RemoteBlockDevice` 替换为真实块设备，移除 `sys_block_read/write` 回调 | ⬜ | fs_server 直接持有块设备实例 |
| 4.1.4 | 从 fs_server 移除 `Refresh` 标签处理器 | ✅ | 已删除（无 client 端影响，返回 not-implemented） |
| 4.1.5 | `cargo check --workspace --target x86_64-unknown-none` 与回归测试 | 🟡 | 当前全绿通过 |

**风险与依赖**:
- ATA PIO 驱动在 RootServer 地址空间中运行，能力向 fs_server 转移需要 CSpace 操作。
- 当前 test.ps1 有 ~50 个 stage 依赖于 RootServer 数据面；逐步降权时要确保每个 stage 通过。
- P4.1.1（共享内存块设备）是关键技术基础，可能需要独立的共享内存分配机制。

---

## P3.4: 日志分级治理 — Demand Paging 节流

**目标**: 将 RootServer demand paging 处理中的 verbose `println!` 迁移到 gated `log_debug!` 宏，使用专门的 `DOM_PAGING` 域，使其可通过 `NOVA_LOG_LEVEL` 环境变量控制。

**对应 PLAN**: [PLAN-P3.4](./PLAN.md#phase-3-novafs-耐久性与一致性)

**涉及文件**:
- `libs/libnova/src/log.rs` — 新增 `DOM_PAGING` 域常量
- `services/rootserver/src/main.rs` — demand paging `println!` 改为 `log_debug!`

### 子任务

| # | 子任务 | 状态 | 说明 |
|---|--------|------|------|
| 3.4.1 | 在 `log.rs` 添加 `DOM_PAGING` 域 | ✅ | 已添加 |
| 3.4.2 | 将 `main.rs` demand paging `println!` 改为 `log_debug!(DOM_PAGING, ...)` | ✅ | 已替换 |
| 3.4.3 | `cargo check --workspace --target x86_64-unknown-none` | ✅ | 全绿通过 |

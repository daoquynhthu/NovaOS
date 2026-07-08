# TASK.md — NovaOS 当前执行计划

> **定位**: 当前阶段的动态执行计划。基于 [PLAN.md](./PLAN.md) 拆解。  
> **状态**: `🟡 执行中`  
> **对应阶段**: Phase 4 — 微内核化推进  
> **引用**: 子任务编号 `[TASK-N]` 可被 ISSUE.md 和 PROGRESS.md 引用。  
> **门禁**: 每个子任务必须通过 `cargo check --workspace --target x86_64-unknown-none` 与新增 host 测试才能标记完成。

---

## 前置状态

- Phase 0–3 已全部完成。
- P4.1 进展：
  - ✅ fs_server epoch-based lazy refresh 移除
  - ✅ `SharedMemoryBlockDevice` 类型就绪
  - ⏳ `RemoteBlockDevice` 替换阻塞于 seL4 共享内存帧机制（纳入后续独立阶段）
- 详情见 [PROGRESS.md](./PROGRESS.md) 与 [INDEX.md](./INDEX.md)。

---

## 线性执行计划

参照 PLAN.md 修正后的依赖链：

| # | 任务 | PLAN | 优先级 | 依赖 | 状态 |
|---|------|------|--------|------|------|
| 1 | 独立派生 CSpace（实现阶段） | P4.1 (new) | P0 | — | ✅ |
| 2 | fs_server 持有块设备 | P4.2 (new) | P0 | P4.1 | ⏳ |
| 3 | 解除 FS_SYNC_FORWARD 死锁 | P4.3 (new) | P0 | P4.2 | ⏳ |
| 4 | Shell 迁移到 fs_server | P4.4 (new) | P1 | P4.2 | ⏳ |
| 5 | RootServer 降权收口 | P4.5 (new) | P2 | P4.3 | ⏳ |
| 6 | IPC 入口校验（剩余 1.3） | P4.6 (new) | P1 | — | 🟡 |
| 7 | 关闭 debug syscall | P4.7 (new) | P1 | P4.5 | ⏳ |

---

## 任务 6: IPC 入口统一校验（P4.6 new）

**目标**: 在 RootServer 的所有 IPC 处理入口（syscall dispatch + fs_server 协议分发 + 服务注册查询）添加统一的消息长度检查、能力索引范围检查、以及权限位验证，确保每个 IPC 消息在进入 handler 前被严格校验。

**现状**:
- `libnova::validate` 已提供 `validate_message_length`、`validate_mr_index`、`validate_cap_index`、`validate_payload_fits`。
- TASK-4.9 已将这些校验加到了 RootServer `handlers/*` 中。
- fs_server 当前无系统性的 IPC 入口校验。
- `docs/SERVICE_CONTRACTS.md` 已定义请求/响应格式。

**对应 PLAN**: [PLAN-P4.6](./PLAN.md#phase-4-微内核化推进)

**涉及文件**:
- `libs/libnova/src/validate.rs` — 可能新增校验函数
- `services/fs_server/src/main.rs` — IPC 分发入口添加校验
- `services/rootserver/src/handlers/*.rs` — 检查现有校验完整性

### 子任务

| # | 子任务 | 状态 | 说明 |
|---|--------|------|------|
| 1.1 | 在 `validate.rs` 添加 `validate_fs_request_min()` 和 `fs_min_words()` 函数 | ✅ | 按 label 校验最小消息字数 |
| 1.2 | 在 `fs_server/src/main.rs` 主循环添加集中式消息长度校验 | ✅ | 在 `match FsLabel` 之前拒绝 format 错误的请求 |
| 1.3 | 审查 RootServer 现有 `handlers/*.rs` 校验覆盖 | ⬜ | 确保每个 syscall handler 调用所有适用的 validate 函数 |
| 1.4 | `cargo check --workspace --target x86_64-unknown-none` 与 host 测试 | ✅ | 全绿通过 |

---

## 任务 1: 独立派生 CSpace 实现（P4.1 new）

**目标**: 将 Phase 4.5 设计阶段的 `DerivedCNode` API 模型落实到 `Process::spawn` 中，使每个新进程获得独立派生 CNode 而非共享根 CNode。

**前置**: Phase 4.5 设计阶段已完成（`docs/CAPABILITY_MODEL.md` §10 + `libnova::cap::DerivedCNode`）。

**对应 PLAN**: [PLAN-P4.1 (new)](./PLAN.md#phase-4-微内核化推进)

### 子任务

| # | 子任务 | 状态 | 说明 |
|---|--------|------|------|
| 1.1 | 更新 `docs/CAPABILITY_MODEL.md`，明确独立 CSpace 后的条目布局变化 | ✅ | Phase 4.5 设计阶段完成 |
| 1.2 | 定义 `libnova::cap::DerivedCNode` API（创建、安装能力） | ✅ | struct + `new` + `install` + `cnode_cptr` |
| 1.3 | 在 `Process::spawn` 中落实独立 CNode 创建与条目安装 | ✅ | CNode 分配 + `cspace_cap` 字段 + `configure` 使用独立 CSpace |
| 1.4 | `cargo check --workspace --target x86_64-unknown-none` 与回归测试 | ✅ | 全绿通过 |

---

## 任务 3+: 后续阻塞任务

| # | 任务 | 入口条件 |
|---|------|----------|
| 3 | fs_server 持有块设备 | 需要 seL4 共享帧映射机制（P4.5 实现后提供能力转移基础） |
| 4 | 解除 FS_SYNC_FORWARD_ENABLED 死锁 | P4.1 完成后 |
| 5 | Shell 迁移到 fs_server | P4.1 完成后 |
| 6 | RootServer 降权收口 | P4.2 完成后 |
| 7 | 关闭 debug syscall | P4.4 完成后 |

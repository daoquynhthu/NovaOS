# TASK.md — NovaOS 当前执行计划

> **定位**: 当前阶段的动态执行计划。基于 [PLAN.md](./PLAN.md) 拆解。  
> **状态**: `🟡 执行中`  
> **对应阶段**: Phase 2 — 代码结构去债务与安全基线  
> **引用**: 子任务编号 `[TASK-N]` 可被 ISSUE.md 和 PROGRESS.md 引用。  
> **门禁**: 每个子任务必须通过 `cargo check --workspace --target x86_64-unknown-none` 与新增 host 测试才能标记完成。

---

## 前置状态

- Phase 0 已完成（仓库卫生）。
- Phase 1 已完成（构建系统统一化）。
- Phase 1.5 与 Phase 2 并行推进中：
  - `novafs-core` 已抽取（TASK-1）
  - `libnova` host-native 测试已启用（TASK-2）
  - NovaFS `MockBlockDevice` 测试已就位（TASK-3）
  - RootServer syscall dispatch 已拆分并通过三轮审计零 issue 闭环（TASK-4）
  - IPC 字节打包已统一到 `libnova::ipc::pack` 并通过两次审计零 issue 闭环（TASK-5）
- 历史完成详情见 [PROGRESS.md](./PROGRESS.md)；审计问题与修复见 [ISSUE.md](./ISSUE.md)。

---

## 当前任务总览

| ID | 任务 | 对应 PLAN | 说明 | 状态 |
|----|------|-----------|------|------|
| TASK-5 | 统一 IPC 字节打包到 `libnova::ipc` | P2.3 | 已完成，审计闭环 | ✅ |
| TASK-6 | 定义 `SyscallNum` 枚举 | P2.4 | 替代 client/server 中分散的魔术数字 | ✅ 已完成 |
| TASK-7 | 共享分配器模块到 `libnova::allocator` | P2.5 | RootServer/fs_server 共用同一套 allocator 抽象 | ⬜ 待开始 |
| TASK-8 | 移除 fs_server `#![allow(dead_code)]` | P2.6 | crate 级豁免已移除；函数级豁免待后续清理 | ✅ 已完成 |
| TASK-9 | NovaOS 权能模型文档 | P2.7 | 定义每个服务/进程拥有的 CSpace 条目清单 | ⬜ 待开始 |
| TASK-10 | 服务接口契约文档 | P2.8 | fs_server/serial_server/user_app 的请求/响应/不变量 | ⬜ 待开始 |
| TASK-11 | `test.ps1` 支持 `-StageRange` | P1.5.3 | 拆分快速 smoke 与完整回归 | ⬜ 待开始 |
| TASK-12 | 分配器逻辑测试 | P1.5.4 | SlotAllocator/UntypedAllocator/FrameAllocator bitmap 逻辑 | ⬜ 待开始 |

---

## TASK-6: 定义 `SyscallNum` 枚举

**目标**: 用 `#[repr(u64)]` 枚举替代 `libnova::syscall` client stubs、`libnova::fs_ipc` FS 协议常量、RootServer `main.rs` syscall dispatch 以及 `user_app` helper 中分散的 syscall/FS 标签魔术数字，减少不一致风险并为 TASK-10 接口契约文档提供单一真相源。

**对应 PLAN**: [PLAN-P2.4](./PLAN.md#phase-2-代码结构去债务与安全基线)

**涉及文件**:
- `libs/libnova/src/syscall.rs` — client stubs 当前硬编码标签（如 `MessageInfo::new(20, ...)`）
- `libs/libnova/src/fs_ipc.rs` — FS 协议标签常量（`FS_LABEL_OPEN=20` 等）
- `services/rootserver/src/main.rs` — syscall dispatch `match label`
- `services/user_app/src/main.rs` — helper binary 中直接调用的 syscall/FS 标签（如有）
- `docs/INDEX.md` — 标签映射表

**核心设计约束**:
- 枚举值必须与当前运行时的标签数值完全一致（ABI 兼容）。
- 定义位置：`libnova::syscall::SyscallNum` 用于 syscall 标签；`libnova::fs_ipc::FsLabel` 用于 FS 协议标签。两者可都基于一个底层 `#[repr(u64)]` 类型，或分开定义。
- 所有替换必须让 `cargo check --workspace --target x86_64-unknown-none` 保持全绿。
- 不修改任何 syscall/FS 消息布局或语义。

### 子任务

| # | 子任务 | 状态 | RED test | GREEN test |
|---|--------|------|----------|------------|
| 6.1 | 在 `libnova` 中定义 `SyscallNum` 与 `FsLabel` `#[repr(u64)]` 枚举，覆盖所有当前标签 | ✅ | 无枚举 | 枚举存在，含 `as_u64`/`as_word`/`from_u64` |
| 6.2 | 替换 `libnova/src/syscall.rs` client stubs 中的魔术数字 | ✅ | stubs 使用魔术数字 | 全部使用 `SyscallNum::*` |
| 6.3 | 替换 `libnova/src/fs_ipc.rs` 中的 `FS_LABEL_*` 常量 | ✅ | 常量存在 | 全部使用 `FsLabel::*` |
| 6.4 | 替换 RootServer `main.rs`/`tests.rs`、fs_server `main.rs`、rootserver `services.rs`/`handlers/fs.rs` 中的魔术数字 | ✅ | dispatch 使用魔术数字 | 全部使用枚举 |
| 6.5 | 更新 `docs/INDEX.md` 标签映射，引用枚举定义 | ✅ | 映射使用裸数字 | 引用 `SyscallNum`/`FsLabel` |
| 6.6 | `cargo check --workspace --target x86_64-unknown-none` 与 host 测试 | ✅ | — | `cargo check --workspace` 全绿；`cargo test -p libnova` 21 passed |

### Step-4 审计结论

> **审计时间**: 2026-07-07  
> **结果**: TASK-6 审计零问题。ABI 数值完全保留，所有 syscall/FS dispatch 点均已改用 `SyscallNum` / `FsLabel` 枚举，无遗留魔术 dispatch 标签；新增枚举值稳定性与 roundtrip 测试；相关文档已同步。详见 `docs/ISSUE.md`「TASK-6 审计详情」。

### 风险与依赖

- `SyscallNum`/`FsLabel` 的数值必须与现有运行时一致，否则 QEMU 集成回归会失败。
- RootServer dispatch 中某些 label（如 VM fault 5、`sys_send` 13）可能不在常规 syscall 范畴，需要决定是否纳入枚举。
- 与 TASK-5 相邻，可合并一次回归验证。

---

## 下一阶段候选

完成 TASK-6 并通过审计闭环后，优先继续 Phase 2 的 **TASK-7**（共享分配器模块到 `libnova::allocator`），因为它与 TASK-6 同属 libnova 内部重构，回归范围可控。

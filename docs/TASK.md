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
  - `SyscallNum`/`FsLabel` 枚举已替代魔术数字并通过审计零问题闭环（TASK-6）
- 历史完成详情见 [PROGRESS.md](./PROGRESS.md)；审计问题与修复见 [ISSUE.md](./ISSUE.md)。

---

## 当前任务总览

| ID | 任务 | 对应 PLAN | 说明 | 状态 |
|----|------|-----------|------|------|
| TASK-7 | 共享分配器模块到 `libnova::allocator` | P2.5 | RootServer/fs_server 共用同一套 allocator 抽象 | ✅ 已完成 |
| TASK-9 | NovaOS 权能模型文档 | P2.7 | 定义每个服务/进程拥有的 CSpace 条目清单 | ✅ |
| TASK-10 | 服务接口契约文档 | P2.8 | fs_server/serial_server/user_app 的请求/响应/不变量 | ✅ |
| TASK-11 | `test.ps1` 支持 `-StageRange` | P1.5.3 | 拆分快速 smoke 与完整回归 | ⬜ 待开始 |
| TASK-12 | 分配器逻辑测试 | P1.5.4 | SlotAllocator/UntypedAllocator/FrameAllocator bitmap 逻辑 | ⬜ 待开始 |

---

## TASK-9: NovaOS 权能模型文档

**目标**: 定义 NovaOS 当前已实现的权能分配模型，涵盖 RootServer、fs_server、serial_server、user_app 的 CSpace 条目清单，为 Phase 4 能力隔离做准备。

**对应 PLAN**: [PLAN-P2.7](./PLAN.md#phase-2-代码结构去债务与安全基线)

**涉及文件**:
- `docs/CAPABILITY_MODEL.md` — 新文档

**核心设计约束**:
- 必须引用 `ARCH-NOVAOS-PROPOSAL-001` 中的安全原则。
- 必须与当前代码实现一致（反映实际 CSpace 布局，而非理想设计）。
- 属于纯文档类别，无需 RED/GREEN。

### 子任务

| # | 子任务 | 状态 | 说明 |
|---|--------|------|------|
| 9.1 | 创建 `docs/CAPABILITY_MODEL.md`，覆盖 RootServer/fs_server/serial_server/user_app 的 CSpace 条目 | 🟡 | 已创建，含当前所有服务的能力清单 |
| 9.2 | 文档引用 `ARCH-NOVAOS-PROPOSAL-001` 安全原则 | ✅ | 已引用 |

---

## TASK-7: 共享分配器模块到 `libnova::allocator`

**目标**: 将 `services/rootserver/src/memory.rs` 中的 `SlotAllocator`、`ObjectAllocator` trait、`UntypedAllocator`、`FrameAllocator` 及关联常量移动到 `libs/libnova/src/allocator.rs`，使 RootServer 和 fs_server（及未来服务）共用同一套 allocator 抽象，消除重复。

**对应 PLAN**: [PLAN-P2.5](./PLAN.md#phase-2-代码结构去债务与安全基线)

**涉及文件**:
- `libs/libnova/src/allocator.rs` — 新文件
- `libs/libnova/src/lib.rs` — 添加 `pub mod allocator`
- `services/rootserver/src/memory.rs` — 改为 re-export 层（或直接删除，待迁入 libnova 后更新所有 import）
- 间接：所有使用 `crate::memory::*` 的 rootserver 文件（无需修改，因 memory.rs 会 re-export）

**核心设计约束**:
- 不修改任何分配器行为或 API 签名。
- `cargo check --workspace --target x86_64-unknown-none` 必须保持全绿。
- 移动后 `memory.rs` 保持作为 re-export 兼容层，避免一处改多处 import。

### 子任务

| # | 子任务 | 状态 | 说明 |
|---|--------|------|------|
| 7.1 | 在 `libnova` 中创建 `allocator.rs`，移入 SlotAllocator/ObjectAllocator/UntypedAllocator/FrameAllocator 及相关常量 | ✅ | `libs/libnova/src/allocator.rs` 已创建，包含全部分配器类型 |
| 7.2 | 将 `libnova::lib.rs` 添加 `pub mod allocator` | ✅ | `lib.rs` 已添加 |
| 7.3 | 将 `memory.rs` 改为 re-export `libnova::allocator::*` 兼容层 | ✅ | `services/rootserver/src/memory.rs` 已改为 re-export |
| 7.4 | `cargo check --workspace --target x86_64-unknown-none` | ✅ | 全绿通过；`cargo test -p libnova` 21 passed |

### 风险与依赖

- `memory.rs` 中的 `MemoryRegion` 结构体也在移动范围内，因为 `shared_memory.rs` 依赖它。
- 保持 re-export 兼容层避免一次改多处 import，但这属于增量清理。
- 移动后 `TASK-12`（分配器逻辑测试）可直接针对 `libnova::allocator` 编写。

---

## 后续任务候选

完成 TASK-7 并通过审计闭环后，优先继续 Phase 2 的 **TASK-9**（权能模型文档）或 Phase 1.5 的 **TASK-11**（test.ps1 StageRange），取决于哪个对当前迭代最有利。

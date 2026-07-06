# TASK.md — NovaOS 当前执行计划

> **定位**: 当前阶段的动态执行计划。基于 [PLAN.md](./PLAN.md) 拆解。  
> **状态**: `🟡 执行中`  
> **对应阶段**: Phase 0 收尾 + Phase 1 启动  
> **引用**: 子任务编号 `[TASK-N]` 可被 ISSUE.md 和 PROGRESS.md 引用。  
> **门禁**: 每个子任务必须通过 `cargo check --workspace --target x86_64-unknown-none` 才能标记完成。

---

## TASK-1: 文档体系建设

**目标**: 完成六份顶层文档的创建和架构文档归档。

| # | 子任务 | 状态 | RED test | GREEN test | 备注 |
|---|--------|------|----------|------------|------|
| 1.1 | 删除 HANDOVER.md | ✅ | — | `git rm` 成功 | 已执行 |
| 1.2 | 架构文档添加 ARCH-ID | ✅ | — | 4 文件全部添加 | 已执行 |
| 1.3 | 创建 AGENT.md | ✅ | — | 文件存在 + 规则完整 | 已执行 |
| 1.4 | 创建 PLAN.md | ✅ | — | 文件存在 + 7 阶段完整 | 已执行 |
| 1.5 | 创建 TASK.md | 🔄 | — | 文件存在 + 符合 AGENT.md 格式 | 当前 |
| 1.6 | 创建 ISSUE.md | ⬜ | — | 文件存在 + 审计产出归档 | — |
| 1.7 | 创建 PROGRESS.md | ⬜ | — | 文件存在 + 纯完成摘要 | — |
| 1.8 | 验证 `cargo check` 通过 | ⬜ | `cargo check` 失败 | `cargo check` 全绿 | — |

**RED test 1.8**: `cargo check` 应当通过（文档变更不涉及代码，所以 RED = 变更前原本预期通过）。

## TASK-2: 代码状态冻结与基线锁定

**目标**: 验证当前代码库在文档体系建立后仍然是可编译、可测试的。

| # | 子任务 | 状态 | RED test | GREEN test |
|---|--------|------|----------|------------|
| 2.1 | `cargo build --workspace --release` | ⬜ | 确保无失败 | 编译成功 |
| 2.2 | 确认 INDEX.md 与代码一致 | ⬜ | — | 行号校验无偏差 |
| 2.3 | 运行 QEMU 回归基线 | ⬜ | — | `test.ps1` 120s 通过 |

---

## 当前焦点

**TASK-1.5**: 创建本文件（已完成）→ 继续创建 ISSUE.md 和 PROGRESS.md → 然后验证编译。

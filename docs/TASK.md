# TASK.md — NovaOS 当前执行计划

> **定位**: 当前阶段的动态执行计划。基于 [PLAN.md](./PLAN.md) 拆解。  
> **状态**: `🟡 执行中`  
> **对应阶段**: Phase 5 — 安全强化与审计  
> **引用**: 子任务编号 `[TASK-N]` 可被 ISSUE.md 和 PROGRESS.md 引用。  
> **门禁**: 每个子任务必须通过 `cargo check --workspace --target x86_64-unknown-none` 才能标记完成；功能性代码先 RED test。

---

## 前置状态

- Phase 0–4 已全部完成。
- D1（QEMU 回归）✅ / D2（clippy 清零）✅ / D3（PLAN.md 修正）✅
- 详情见 [PROGRESS.md](./PROGRESS.md) 与 [INDEX.md](./INDEX.md)。

---

## 线性执行计划

| # | 任务 | PLAN | 优先级 | 依赖 | 状态 |
|---|------|------|--------|------|------|
| 1 | 替换自定义 ChaCha20 | P5.1 | P0 | P4.1 | ⏳ |
| 2 | 每文件独立随机 nonce | P5.2 | P0 | P5.1 | ⏳ |
| 3 | NovaFS 并发锁保护 | P5.3 | P1 | P4.1 | ⏳ |
| 4 | fork fd 表隔离 | P5.4 | P1 | P4.6 | ⏳ |
| 5 | IPC fuzz 测试 | P5.5 | P1 | P1.5.2 | ⏳ |
| 6 | 安全审计清单 | P5.6 | P2 | P5.1 | ⏳ |

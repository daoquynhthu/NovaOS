# TASK.md — NovaOS 当前执行计划

> **定位**: 当前阶段的动态执行计划。基于 [PLAN.md](./PLAN.md) 拆解。  
> **状态**: `🟡 执行中`  
> **对应阶段**: Phase 3 — NovaFS 耐久性与一致性  
> **引用**: 子任务编号 `[TASK-N]` 可被 ISSUE.md 和 PROGRESS.md 引用。  
> **门禁**: 每个子任务必须通过 `cargo check --workspace --target x86_64-unknown-none` 与新增 host 测试才能标记完成。

---

## 前置状态

- Phase 0 已完成（仓库卫生）。
- Phase 1 已完成（构建系统统一化）。
- Phase 1.5（测试基础设施）与 Phase 2（代码结构去债务与安全基线）已全部完成。
- 历史完成详情见 [PROGRESS.md](./PROGRESS.md)；审计问题与修复见 [ISSUE.md](./ISSUE.md)。

---

## 当前任务总览

| ID | 任务 | 对应 PLAN | 说明 | 状态 |
|----|------|-----------|------|------|
| P3.1 | sync + 重启 + 一致性校验回归测试 | P3.1 | 持久化、重启恢复、一致性检查 host 测试 | ✅ |
| P3.2 | 目录项/位图/inode 一致性检查 | P3.2 | 通过 P3.1 的 `check_consistency()` 实现，已完成 | ✅ |
| P3.3 | 异常中断后恢复验证 | P3.3 | 在 `novafs_host.rs` 中添加 crash + snapshot 回滚测试 | ✅ |
| P3.4 | 日志分级治理 | P3.4 | 为 RootServer demand paging 场景配置日志分级 | ⬜ 待开始 |

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

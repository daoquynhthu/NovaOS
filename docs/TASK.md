# TASK.md — NovaOS 当前执行计划

> **定位**: 当前阶段的动态执行计划。基于 [PLAN.md](./PLAN.md) 拆解。  
> **状态**: `⚪ 已完成`  
> **对应阶段**: Phase 1 P0 已完成，等待规划 Phase 1 P1  
> **引用**: 子任务编号 `[TASK-N]` 可被 ISSUE.md 和 PROGRESS.md 引用。  
> **门禁**: 每个子任务必须通过 `cargo check --workspace --target x86_64-unknown-none` 才能标记完成。

---

Phase 1 P0（构建目录统一 + CMake 公共脚本）已完成并审计通过。
下一个可执行块：Phase 1 P1 项（P1.3 `--manifest-path`、P1.4 QEMU PATH、P1.5 CMake Rust 服务、P1.6 workspace.dependencies、P1.7 .gitattributes、P1.8 nightly pin）。

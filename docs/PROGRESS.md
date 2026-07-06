# PROGRESS.md — NovaOS 项目进度摘要

> **定位**: 项目唯一的进度真相源。只记录已完成事实（过去时），不写"打算做什么"。  
> **格式**: `YYYY-MM-DD: [摘要] — 完成项 / 验证结果 / 关联 ISSUE`  
> **维护**: 每个子任务完成后由执行代理更新。

---

## 2026-07-06: 文档体系建立 + 仓库卫生 Phase 0

**完成项**：
- 建立文档体系：AGENT.md / PLAN.md / TASK.md / ISSUE.md / PROGRESS.md / INDEX.md
- 架构文档归档：四份 docs/*.md 添加 ARCH-ID 可引用编号
- 删除 `docs/HANDOVER.md`（历史交接文档，内容已过时）
- 删除 `docs/Project_Progress.md`（旧格式，已替换为 PROGRESS.md）
- 清理根目录：脚本迁入 `scripts/`，文档迁入 `docs/`，根目录从 26 文件降至 8 文件
- `test_output.txt` 移出 git 追踪并删除磁盘残留
- 删除 `services/user_app/.cargo/config.toml`（与工作区级重复）
- 删除 `auditoration1.md`、`output.txt`、`*.log`、`disk.img`、`.ninja_*` 等磁盘垃圾
- 创建 `.env.example`（不含敏感信息）

**验证**：`cargo check --workspace --target x86_64-unknown-none` — 全绿通过  
**关联**：`ISSUE-1/2/4/5/6/7/8/10/11/12/14/15/16/17/18/19/20/21/22/23/25/26/27/28/30` 归档

## 2026-07-06: Workspace Lint 激活

**完成项**：
- 6 个 member crate 全部添加 `[lints] workspace = true`
- `rootserver/build.rs` 中 `unwrap()` 改为 `expect()`（共 1 处）
- `seL4-sys/build.rs` 中 `unwrap()` 改为 `expect()`（共 2 处）
- 3 个 crate 补充 `edition = "2021"`（user_app, serial_server, fs_server）
- 3 个 crate 补充缺失 metadata（authors + description）
- `CMakeLists.txt` LLD 条件化：Windows 跳过 `-fuse-ld=lld`（MinGW LLVM 不兼容）

**验证**：`cargo build --workspace --target x86_64-unknown-none --release` — 全绿通过  
**关联**：`ISSUE-1` 临时豁免 fs_server `dead_code`，关联 `PLAN-P2.1` 解决

## 2026-07-06: 路线调整 — 安全与微内核化并行

**完成项**：
- 确认战略：先完成微内核化演进，安全强化紧随其后，但在拆分服务时同步定义能力边界
- 更新 `docs/PLAN.md`：Phase 2 升级为“代码结构去债务与安全基线”，Phase 4 增加能力隔离任务，新增 Phase 5“安全强化与审计”，原 Phase 5/6 顺延为 Phase 6/7
- 同步更新 `docs/ISSUE.md` 中 [PLAN-P5.x] → [PLAN-P6.x] 的引用
- 同步更新 `docs/TASK.md` 中“6 阶段完整”→“7 阶段完整”

**验证**：PLAN.md / ISSUE.md / TASK.md 内部引用一致，无死链  
**关联**：安全审计 13 项发现待后续按新 Phase 5 归档

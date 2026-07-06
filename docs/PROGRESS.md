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

## 2026-07-06: Phase 1 P0 — 构建目录统一与 CMake 公共脚本

**完成项**：
- 调整 `docs/AGENT.md`：明确 RED/GREEN 仅适用于功能性代码；审计改为在 TASK.md 全部完成后执行
- 将 `scripts/build.sh`、`scripts/test.sh`、`scripts/run_qemu.sh` 默认构建目录从 `build-linux` 改为 `build`
- 更新 `scripts/init_env.sh` 提示文本使用 `build`
- 创建 `scripts/cmake-common.sh`，抽取三份 `.sh` 脚本重复的 CMake 配置与 trace 参数构建逻辑
- `build.sh` / `test.sh` / `run_qemu.sh` 改为 source `cmake-common.sh`
- 更新 `docs/INDEX.md`：新增 `scripts/cmake-common.sh` 条目，修正 Documentation 章节（删除已移除文件的引用）
- 关闭 `ISSUE-20`、`ISSUE-21`、`ISSUE-22`、`ISSUE-31`、`ISSUE-32`、`ISSUE-33`、`ISSUE-34`、`ISSUE-35`

**验证**：
- `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
- `bash -n scripts/cmake-common.sh && bash -n scripts/build.sh && bash -n scripts/test.sh && bash -n scripts/run_qemu.sh` — 无输出（语法通过）
- 独立子 Agent 审计 + 二次审计通过，无剩余新增问题

**关联**：`ISSUE-20/21/22/31/32/33/34/35`

## 2026-07-06: Phase 1 P1 — 脚本/CMake/Cargo 配置统一

**完成项**：
- `scripts/build.ps1` / `scripts/test.ps1` 改用 `--manifest-path`，移除 `Set-Location services/*` 反模式
- `scripts/test.ps1` QEMU 路径改为依赖 PATH，移除 `C:\Program Files\qemu` 硬编码
- `CMakeLists.txt` 扩展为构建全部四个 Rust 服务，目标重命名为 `nova_rust_services`
- 统一 CMake 与 PowerShell 的 Rust 构建输出目录为 workspace `target/`，移除 `CARGO_TARGET_DIR` 覆盖
- 根 `Cargo.toml` 新增 `[workspace.dependencies]`；各 member crate 改用 `workspace = true`
- 创建 `.gitattributes`，规范 LF 行尾与二进制文件处理
- `rust-toolchain.toml` 固定为 `nightly-2026-01-14`
- 更新 `docs/INDEX.md` 行号与新增条目
- 关闭 `ISSUE-7`、`ISSUE-8`、`ISSUE-9`、`ISSUE-10`、`ISSUE-11`、`ISSUE-30`、`ISSUE-36`、`ISSUE-37`、`ISSUE-38`、`ISSUE-39`

**验证**：
- `cargo check --workspace --target x86_64-unknown-none`（配合 `SEL4_OUT_DIR` / `SEL4_KERNEL_DIR`）— 全绿通过
- 独立子 Agent 审计 + 二次审计通过，无剩余新增问题

**关联**：`ISSUE-7/8/9/10/11/30/36/37/38/39`

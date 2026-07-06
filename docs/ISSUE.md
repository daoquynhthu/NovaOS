# ISSUE.md — NovaOS 已知问题归档

> **定位**: 审计产出的已知问题，按优先级归档。  
> **格式**: `ISSUE-N: [Priority] [Category] Title — 来源`  
> **优先级**: P0（阻塞）→ P1（严重）→ P2（一般）→ P3（建议）  
> **状态**: 🔴 待修复 / 🟡 修复中 / 🟢 已修复 / ⚪ 已关闭（非修复）  
> **引用**: 关联 TASK.md 子任务编号如 `[TASK-1.2]`

---

## P0 — 阻塞

| ID | 问题 | 状态 | 来源 | 关联 |
|----|------|------|------|------|
| ISSUE-1 | `fs_server` 通过 `include!()` 共享 rootserver 源码，导致 `dead_code` lint 冲突，fs_server 已用 `#![allow(dead_code)]` 豁免 | 🟡 临时豁免 | 初步审计 | [TASK-1.2], PLAN P2.1 解决 |
| ISSUE-2 | `build.ps1` 漏构建 `serial_server` 和 `fs_server`，只编 `user_app` + `rootserver` | 🔴 待修复 | 构建审计 | [PLAN-P1.3] |
| ISSUE-3 | 3 个 crate 缺失 `edition = "2021"` 导致 2015 edition 编译失败 | 🟢 已修复 | 编译审计 | 已在 Phase 0 修复 |

## P1 — 严重

| ID | 问题 | 状态 | 来源 |
|----|------|------|------|
| ISSUE-4 | 工作区 lint `[workspace.lints.clippy]` 需运行 `cargo clippy` 才能生效，`cargo check` 只检查 `[workspace.lints.rust]`；当前无人运行 clippy | 🔴 待修复 | 初步审计 |
| ISSUE-5 | 全局尾部空白：33+ 个 `.rs` 文件存在 trailing whitespace | 🔴 待修复 | 格式审计 |
| ISSUE-6 | 5 个文件 CRLF 行尾（`rustfmt.toml` 声明 Unix）：`CMakeLists.txt`, `libs/libnova/src/env.rs`, `services/*/allocator.rs` ×3 | 🔴 待修复 | 格式审计 |
| ISSUE-7 | `rust-toolchain.toml` 未固定 nightly 日期，夜间变动可能 break build | 🟢 已修复 | 构建审计 [TASK-6.1] |
| ISSUE-8 | 缺少 `.gitattributes`，行尾无规范控制 | 🟢 已修复 | 构建审计 [TASK-5.1] |
| ISSUE-9 | `build.ps1` 使用 `Set-Location "services/user_app"` 切目录后再 `Set-Location "../.."` 返回，路径语义隐晦 | 🟢 已修复 | 构建审计 [TASK-1.1] |
| ISSUE-10 | QEMU 路径硬编码 `C:\Program Files\qemu\...`，非标准安装失败 | 🟢 已修复 | 构建审计 [TASK-2.1] |
| ISSUE-11 | CMake 只构建 rootserver Rust 目标，未包含 fs_server/serial_server/user_app | 🟢 已修复 | 构建审计 [TASK-3.1] |
| ISSUE-12 | 3 个子模块（`seL4_tools`, `util_libs`）追踪 `heads/master` 未 pin 到发布 tag | 🔴 待修复 | 子模块审计 |
| ISSUE-13 | `INDEX.md` 需要持续与代码同步（AGENT.md Step 7 要求） | 🟢 已初始创建 | 文档审计 |
| ISSUE-31 | [P1] `AGENT.md` 被代理修改，违反“仅仓库维护者可更新”与单次变更单一意图约束 | ⚪ 已关闭 | 审计 [TASK-1]/[TASK-2]；经用户明确授权调整 AGENT.md 表述 |
| ISSUE-32 | [P1] shell 构建脚本功能性变更未提交 RED test，违反 AGENT.md RED/GREEN 规则 | ⚪ 已关闭 | 审计 [TASK-1]/[TASK-2]；用户明确 RED/GREEN 仅适用于功能性代码，构建脚本重构不适用 |

## P2 — 一般

| ID | 问题 | 状态 | 来源 |
|----|------|------|------|
| ISSUE-14 | `syscall.rs` 中 `sys_file_write` 是 `sys_write` 的等义别名（`syscall.rs:422`），应删除或标记 deprecation | 🔴 待修复 | 代码审计 [PLAN-P2.4] |
| ISSUE-15 | `seL4_X86_4K` 常量在 `main.rs:43` 和 `tests.rs:17` 重复定义 | 🔴 待修复 | 代码审计 |
| ISSUE-16 | `syscall.rs` 行 117-131 的 `write_packed_bytes` 与 `fs_ipc.rs` 的 `write_bytes_to_msg` 功能重复 | 🔴 待修复 | 代码审计 [PLAN-P2.3] |
| ISSUE-17 | `libnova` 零单元测试（纯函数层 `Error::from`、字节打包等可测但未测） | 🔴 待修复 | 测试审计 [PLAN-P2.7] |
| ISSUE-18 | `tests.rs` 线性运行 12 个测试，无隔离，基准测试与功能测试混合 | 🔴 待修复 | 测试审计 [PLAN-P2.8] |
| ISSUE-19 | `init_env.sh` 仅支持 Ubuntu/Debian（`apt install`），无跨平台支持 | 🔴 待修复 | 构建审计 |
| ISSUE-20 | `.sh` 脚本三份重复 ~40 行 CMake 设置 | 🟢 已修复 | 构建审计 [PLAN-P1.2]；已抽取 `scripts/cmake-common.sh` |
| ISSUE-21 | 默认构建目录分裂：Windows `build` vs Linux `build-linux` | 🟢 已修复 | 构建审计 [PLAN-P1.1]；Linux 脚本默认已改为 `build` |
| ISSUE-22 | `docs/Project_Progress.md` 需要迁移到新格式（成为 `PROGRESS.md`） | ⚪ 已关闭 | 文档审计；旧文件已删除，`PROGRESS.md` 已创建 |
| ISSUE-23 | `services/README.md` 描述 fs_server/serial_server 为 "(Planned)" 但已实现，过时 | 🔴 待修复 | 文档审计 |
| ISSUE-24 | 3 个 crate 缺 `edition = "2021"`，已完成补全 | 🟢 已修复 | 编译审计 |
| ISSUE-33 | [P2] `INDEX.md` 未随脚本重构更新（行号错误且未收录 `scripts/cmake-common.sh`） | 🟢 已修复 | 审计 [TASK-2.1]-[TASK-2.4]；已更新 Build & Config 与 Documentation 章节 |
| ISSUE-34 | [P2] `ISSUE-20`/`ISSUE-21` 未在 TASK-1/TASK-2 完成后标记为已修复 | 🟢 已修复 | 审计 [TASK-1]/[TASK-2]；已关闭相关 issue |
| ISSUE-35 | [P2] `scripts/cmake-common.sh` 在被 source 时全局设置 `set -euo pipefail`，影响调用方 shell 选项 | 🟢 已修复 | 审计 [TASK-2.1]；已从 `cmake-common.sh` 移除该设置，调用方脚本保留 |
| ISSUE-36 | [P2] PowerShell 脚本与 CMake 的 Rust 构建输出目录不一致 | 🟢 已修复 | 审计 [TASK-3.1]；CMake 不再覆盖 `CARGO_TARGET_DIR`，统一使用 workspace `target/` |
| ISSUE-37 | [P2] INDEX.md 未随 Phase 1 P1 变更同步更新 | 🟢 已修复 | 审计 [TASK-1]-[TASK-6]；已更新行号、新增 `.gitattributes`、`nova_rust_services` 说明 |

## P3 — 建议

| ID | 问题 | 状态 | 来源 |
|----|------|------|------|
| ISSUE-25 | CI/CD 缺失（GitHub Actions） | 🔴 待推进 | 基础设施审计 [PLAN-P6.1] |
| ISSUE-26 | `.editorconfig` 缺失 | 🔴 待推进 | 基础设施审计 [PLAN-P6.2] |
| ISSUE-27 | `cargo-deny` / 依赖审计未配置 | 🔴 待推进 | 基础设施审计 [PLAN-P6.3] |
| ISSUE-28 | 缺少 Docker 构建环境 | 🔴 待推进 | 基础设施审计 [PLAN-P6.4] |
| ISSUE-29 | `.env.example` 已创建但脚本未支持 `.env` 加载 | 🟢 已创建 | 环境审计 |
| ISSUE-30 | 工作区依赖版本 `linked_list_allocator` 和 `spin` 在多个 Cargo.toml 中独立声明 | 🟢 已修复 | 构建审计 [TASK-4.1] |
| ISSUE-38 | [P3] CMakeLists.txt 中定义了未使用的 *_SRC 变量 | 🟢 已修复 | 审计 [TASK-3.1]；已移除 `ROOTSERVER_SRC` 等未使用变量 |
| ISSUE-39 | [P3] Phase 1 P1 二次审计通过，无新增问题 | ⚪ 已关闭 | 二次审计 [TASK-1]-[TASK-6]；ISSUE-36/37/38 已修复，cargo check 通过 |

---

## 汇总

| 优先级 | 总数 | 🔴 待修复 | 🟡 修复中 | 🟢 已修复 | ⚪ 已关闭 |
|--------|------|-----------|-----------|-----------|-----------|
| P0 | 3 | 1 | 1 | 1 | 0 |
| P1 | 12 | 4 | 0 | 6 | 2 |
| P2 | 16 | 7 | 0 | 8 | 1 |
| P3 | 8 | 4 | 0 | 3 | 1 |
| **合计** | **39** | **16** | **1** | **18** | **4** |

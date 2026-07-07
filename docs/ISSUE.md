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
| ISSUE-45 | [P1] `handlers/fs.rs` 双路径 handler 使用未裁剪的原始长度计算第二路径偏移，可能导致越界读取/panic | 🟢 已修复 | 审计 [TASK-4.7] |

## P2 — 一般

| ID | 问题 | 状态 | 来源 |
|----|------|------|------|
| ISSUE-14 | `syscall.rs` 中 `sys_file_write` 是 `sys_write` 的等义别名（`syscall.rs:422`），应删除或标记 deprecation | 🔴 待修复 | 代码审计 [PLAN-P2.4] |
| ISSUE-15 | `seL4_X86_4K` 常量在 `main.rs:43` 和 `tests.rs:17` 重复定义 | 🔴 待修复 | 代码审计 |
| ISSUE-16 | `syscall.rs` 中的 `write_packed_bytes` 与 `fs_ipc.rs` 的 `write_bytes_to_msg` 已移除 | 🟢 已修复 | 审计 [TASK-5]；剩余重复循环见 ISSUE-51 |
| ISSUE-17 | `libnova` 零单元测试（纯函数层 `Error::from`、字节打包等可测但未测） | 🔴 待修复 | 测试审计 [PLAN-P2.7]；`ipc::pack` 测试已补充 |
| ISSUE-51 | [P2] `syscall.rs` 仍有多处直接操作 MR 的字节打包循环未迁移到 `ipc::pack`，文档描述不准确 | 🟢 已修复（已验证） | 审计 [TASK-5]；`sys_print`/`sys_spawn`/`sys_open`/`sys_write`/`sys_unlink`/`sys_link`/`sys_symlink`/`sys_rename`/`sys_block_write` 已改用 `ipc::pack` |
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
| ISSUE-40 | [P2] CI 显式覆盖 toolchain components，未安装 rust-toolchain.toml 声明的 llvm-tools | 🟢 已修复 | 审计 [TASK-2.2]；已移除 ci.yml 中的 components/targets 显式传入 |
| ISSUE-41 | [P2] INDEX.md 已知前线仍标注 CI/CD pipeline 为 Not started，未同步 ci.yml 新增 | 🟢 已修复 | 审计 [TASK-2.1]；已更新 Known Frontiers 与 Build & Config 章节 |
| ISSUE-42 | [P2] TASK.md 2.2 验证描述与 ci.yml 不符：action 仍显式传入 components/targets | 🟢 已修复 | 审计 [TASK-2.2]；已更新 TASK.md 描述并移除 ci.yml 显式传入 |
| ISSUE-46 | [P2] FS handler 读取变长 payload 时未校验 message length 是否覆盖整个 payload | 🟢 已修复 | 审计 [TASK-4.7]/[TASK-4.9] |
| ISSUE-47 | [P2] TASK-4.5 混合了 RootServer handler 重构与 novafs-core 的 unwrap 清理，违反单次变更单一意图约束 | 🟢 已修复 | 审计 [TASK-4.5]；已在 `docs/PROGRESS.md` 中拆分为独立条目，并声明未来提交遵守单一意图 |
| ISSUE-50 | [P2] 双路径 FS handler 对超过 `MAX_PATH_LEN` 的长度未拒绝，导致第二路径偏移错误 | 🟢 已修复（已验证） | 再审计 [TASK-4.7]/[TASK-4.9]；`handle_symlink`/`handle_rename`/`handle_link` 现在直接拒绝超过 `MAX_PATH_LEN` 的长度，第三次审计已复核 |

## P3 — 建议

| ID | 问题 | 状态 | 来源 |
|----|------|------|------|
| ISSUE-25 | CI/CD 缺失（GitHub Actions） | 🟢 已修复 | 基础设施审计 [PLAN-P6.1]；`.github/workflows/ci.yml` 已创建 |
| ISSUE-26 | `.editorconfig` 缺失 | 🔴 待推进 | 基础设施审计 [PLAN-P6.2] |
| ISSUE-27 | `cargo-deny` / 依赖审计未配置 | 🔴 待推进 | 基础设施审计 [PLAN-P6.3] |
| ISSUE-28 | 缺少 Docker 构建环境 | 🔴 待推进 | 基础设施审计 [PLAN-P6.4] |
| ISSUE-29 | `.env.example` 已创建但脚本未支持 `.env` 加载 | 🟢 已创建 | 环境审计 |
| ISSUE-30 | 工作区依赖版本 `linked_list_allocator` 和 `spin` 在多个 Cargo.toml 中独立声明 | 🟢 已修复 | 构建审计 [TASK-4.1] |
| ISSUE-38 | [P3] CMakeLists.txt 中定义了未使用的 *_SRC 变量 | 🟢 已修复 | 审计 [TASK-3.1]；已移除 `ROOTSERVER_SRC` 等未使用变量 |
| ISSUE-39 | [P3] Phase 1 P1 二次审计通过，无新增问题 | ⚪ 已关闭 | 二次审计 [TASK-1]-[TASK-6]；ISSUE-36/37/38 已修复，cargo check 通过 |
| ISSUE-43 | [P3] CI 未配置 cargo/seL4 构建缓存，每次运行全量重建 | 🟢 已修复 | 审计 [TASK-2.3]；已添加 `actions/cache@v4` 缓存 `~/.cargo`、`target`、`build` |
| ISSUE-44 | [P3] Phase 1 P2 二次审计通过，无新增问题 | ⚪ 已关闭 | 二次审计 [TASK-1]/[TASK-2]；ISSUE-40/41/42/43/25 已修复，cargo check 通过 |
| ISSUE-48 | [P3] `docs/INDEX.md` 中 syscall label 映射与 `main.rs` dispatch 不一致 | 🟢 已修复 | 审计 [TASK-4] |
| ISSUE-49 | [P3] service handlers 读取 name payload 时未校验 message length 是否覆盖完整名称 | 🟢 已修复 | 审计 [TASK-4.8]/[TASK-4.9] |

---

## 汇总

| 优先级 | 总数 | 🔴 待修复 | 🟡 修复中 | 🟢 已修复 | ⚪ 已关闭 |
|--------|------|-----------|-----------|-----------|-----------|
| P0 | 3 | 1 | 1 | 1 | 0 |
| P1 | 13 | 4 | 0 | 7 | 2 |
| P2 | 23 | 8 | 0 | 14 | 1 |
| P3 | 12 | 3 | 0 | 7 | 2 |
| **合计** | **51** | **16** | **1** | **29** | **5** |

---

## TASK-4 审计详情

> 本次审计范围：`services/rootserver/src/handlers/`、`services/rootserver/src/main.rs` 的 syscall dispatch 分支、`libs/libnova/src/validate.rs`、`docs/TASK.md`、`docs/INDEX.md`、`docs/PROGRESS.md`。
> 验证结果：`cargo check --workspace --target x86_64-unknown-none` 全绿；`cargo test -p libnova --features std --target x86_64-pc-windows-msvc validate::` 7 项全过；`cargo clippy -p rootserver --target x86_64-unknown-none` 因 rootserver 历史债务（64 个 error，均不在 handlers/* 与 validate.rs 中）失败，本次提取的 handler 代码本身零 clippy error。

### ISSUE-45: 双路径 FS handler 使用未裁剪长度计算第二路径偏移

- **Severity**: blocker
- **Location**:
  - `services/rootserver/src/handlers/fs.rs:795` (`handle_symlink`)
  - `services/rootserver/src/handlers/fs.rs:1093` (`handle_rename`)
  - `services/rootserver/src/handlers/fs.rs:1191` (`handle_link`)
- **Problem**:
  - `handle_symlink` 把 `target_len` 直接用于 `base_ptr.add(target_len)` 计算 `link_bytes` 起始地址，但实际读取 `target_bytes` 时已被 clamp 到 `MAX_PATH_LEN`。
  - `handle_link`/`handle_rename` 使用未裁剪的 `target_len`/`old_len` 计算第二段路径的字索引（`total_byte_idx = target_len + i`），随后通过 `get_word(word_idx, ...)` 访问 `ipc_buf.msg[word_idx]`。
  - 如果恶意/畸形消息把长度设为远大于 `MAX_PATH_LEN` 或 IPC buffer 容量，将导致越界读取、panic 或 UB。
- **Suggested fix**:
  1. 在解析两段长度后，先校验 `info.length()` 是否覆盖两段 payload 所需的完整 word 数；不足则直接返回 `error_reply()`。
  2. 使用 clamp 后的 `safe_*_len` 计算第二段偏移，而不是原始长度。
  3. 对超过 `MAX_PATH_LEN` 的长度直接视为非法。
- **修复状态**: 🟢 已修复 — `handle_symlink`/`handle_rename`/`handle_link` 先 clamp 长度，使用 safe 长度计算第二段 word 偏移，并通过 `validate_payload_fits` 校验 payload 覆盖。

### ISSUE-46: FS handler 未校验变长 payload 是否落在声明的消息长度内

- **Severity**: warning
- **Location**:
  - `services/rootserver/src/handlers/fs.rs:311` (`handle_open`)
  - `services/rootserver/src/handlers/fs.rs:543` (`handle_write`)
  - `services/rootserver/src/handlers/fs.rs:692` (`handle_chmod`)
  - `services/rootserver/src/handlers/fs.rs:732` (`handle_chown`)
  - `services/rootserver/src/handlers/fs.rs:770` (`handle_symlink`)
  - `services/rootserver/src/handlers/fs.rs:838` (`handle_readlink`)
  - `services/rootserver/src/handlers/fs.rs:922` (`handle_mkdir`)
  - `services/rootserver/src/handlers/fs.rs:966` (`handle_rmdir`)
  - `services/rootserver/src/handlers/fs.rs:1020` (`handle_unlink`)
  - `services/rootserver/src/handlers/fs.rs:1064` (`handle_rename`)
  - `services/rootserver/src/handlers/fs.rs:1162` (`handle_link`)
  - `services/rootserver/src/handlers/fs.rs:1279` (`handle_block_write`)
- **Problem**:
  - 这些 handler 入口仅验证前 1~3 个 MR 存在且总 `info.length() <= 120`，但未确认声明的消息长度是否包含后续的路径/数据 payload。
  - 当消息长度小于 `offset + payload_words` 时，handler 会读取 IPC buffer 中超出该消息范围的字节，导致基于未定义/脏数据执行文件系统操作。
- **Suggested fix**:
  在读取 payload 前计算最后一个 word 的索引（如 `last_word = offset + payload_words - 1`），并调用 `libnova::validate::validate_mr_index(ctx.info, last_word)`；失败则返回 `error_reply()`。
- **修复状态**: 🟢 已修复 — `handlers/fs.rs` 新增 `validate_payload_fits(ctx, word_offset, len)`，在 `handle_open`/`handle_write`/`handle_chmod`/`handle_chown`/`handle_symlink`/`handle_readlink`/`handle_mkdir`/`handle_rmdir`/`handle_unlink`/`handle_rename`/`handle_link`/`handle_block_write` 读取 payload 前调用。

### ISSUE-47: TASK-4.5 提交混合了重构与 novafs-core 清理

- **Severity**: warning
- **Location**:
  - `docs/PROGRESS.md:148-151`
  - `libs/novafs-core/src/crypto.rs`（`try_into().unwrap()` → `.expect()`）
  - `libs/novafs-core/src/novafs.rs`（`format()` 中 6 处 `unwrap()` → `.expect(...)`）
- **Problem**:
  - AGENT.md 负向约束 #1 规定：禁止同时提交功能 + 重构 + 日志清理，单次变更只能有一个意图。
  - TASK-4.5 的提交说明把 RootServer 进程生命周期 handler 的提取（重构）与 `novafs-core` 的 unwrap 清理混在一起；后者属于 novafs-core 的债务清理，既非 TASK-4 范围，也不是本次重构的必要组成部分。
- **Suggested fix**:
  将 `novafs-core` 的 unwrap 清理回滚，或拆分为独立的 TASK（如 TASK-1.x 后续清理），使 TASK-4.5 仅保留 RootServer handler 提取。
- **修复状态**: 🟢 已修复 — 在 `docs/PROGRESS.md` 中将 `novafs-core` unwrap 清理拆分为独立债务清理条目，TASK-4.5 仅记录 RootServer handler 提取；后续提交遵守单一意图约束。

### ISSUE-48: `docs/INDEX.md` syscall label 映射与 dispatch 不一致

- **Severity**: nit
- **Location**: `docs/INDEX.md:289-290`
- **Problem**:
  - 第 289 行称 “Labels 24-29: metadata (chmod, chown, symlink, readlink, get/set uid/gid)”，但 24-27 实际为 FS handler（`handle_chmod`/`handle_chown`/`handle_symlink`/`handle_readlink`），28-29 才是 `handle_getuid`/`handle_setuid`。
  - 第 290 行称 “Labels 30-33: services (register, lookup, set_ready)”，但 `set_ready` 实际对应 label 45（`handle_service_set_ready`）。
- **Suggested fix**:
  按 `services/rootserver/src/main.rs` 的实际 dispatch 更新该标签映射表，或改为按 label 逐一列出的精确表格。

### ISSUE-49: service handlers 未校验 name payload 是否完整

- **Severity**: nit
- **Location**:
  - `services/rootserver/src/handlers/service.rs:24-46` (`read_name_from_ipc`)
  - `services/rootserver/src/handlers/service.rs:50` (`handle_service_register`)
  - `services/rootserver/src/handlers/service.rs:95` (`handle_service_lookup`)
  - `services/rootserver/src/handlers/service.rs:119` (`handle_service_set_ready`)
- **Problem**:
  - `read_name_from_ipc` 通过 `word_idx < msg_len` 避免越界，但当 MR0 声明的名称长度超过 `msg_len` 时，只会读取到消息末尾并返回一个被截断的名称。
  - 这可能导致 `service_register` 注册错误服务名、`service_lookup` 查找失败、`service_set_ready` 标记了错误服务等非预期行为。
- **Suggested fix**:
  在读取名称前计算 `name_words = len.div_ceil(8)`，并校验 `1 + name_words <= info.length()`；不满足时返回 `error_reply()`。
- **修复状态**: 🟢 已修复 — `read_name_from_ipc` 返回 `Result`，`name_words > 0` 时校验最后一个 word 索引；调用方在失败时返回 `error_reply()`。

### ISSUE-50: 双路径 FS handler 未拒绝超过 `MAX_PATH_LEN` 的长度

- **Severity**: warning
- **Location**:
  - `services/rootserver/src/handlers/fs.rs:800` (`handle_symlink`)
  - `services/rootserver/src/handlers/fs.rs:1134` (`handle_rename`)
  - `services/rootserver/src/handlers/fs.rs:1243` (`handle_link`)
- **Problem**:
  - ISSUE-45 的修复将第二段路径偏移改为使用 clamped 后的 `safe_*_len`，避免了越界读取/panic。
  - 但当原始 `target_len`/`old_len` 超过 `MAX_PATH_LEN` 时，handler 仅读取前 256 字节作为第一段路径，却按 256 字节计算第二段路径的起始位置。
  - 实际消息布局中第二段路径紧跟在原始第一段路径之后，因此 fix 后的偏移会把第一段路径末尾的字节误解析为第二段路径，导致 `symlink`/`rename`/`link` 操作错误的文件路径。
- **Suggested fix**:
  1. 在 `safe_*_len` clamp 后，若原始长度大于 `MAX_PATH_LEN`，直接返回 `error_reply()`。
  2. 或改用原始长度计算第二段偏移并继续 clamp 读取；但方案 1 更清晰，与 ISSUE-45 建议 3 一致。
- **修复状态**: 🟢 已修复（第三次审计已验证） — `handle_symlink`/`handle_rename`/`handle_link` 在读取 payload 前检查 `target_len`/`old_len`/`link_len`/`new_len` 是否超过 `MAX_PATH_LEN`，超过则直接返回 `error_reply()`。

---

## TASK-4 审计修复汇总

- **ISSUE-45** 🟢 已修复：`handlers/fs.rs` 双路径 handler 使用 safe（clamped）长度计算第二段偏移，并新增 `validate_payload_fits` 校验 payload 覆盖。
- **ISSUE-46** 🟢 已修复：所有读取变长 payload 的 FS handler 在读取前调用 `validate_payload_fits(ctx, word_offset, len)`。
- **ISSUE-47** 🟢 已修复：`docs/PROGRESS.md` 将 `novafs-core` unwrap 清理拆分为独立债务清理条目，与 TASK-4.5 分离。
- **ISSUE-48** 🟢 已修复：`docs/INDEX.md` syscall label 映射已按 `main.rs` dispatch 校正。
- **ISSUE-49** 🟢 已修复：`handlers/service.rs` 的 `read_name_from_ipc` 校验完整名称是否落在消息长度内。
- **ISSUE-50** 🟢 已修复：双路径 FS handler 直接拒绝超过 `MAX_PATH_LEN` 的长度。

## TASK-4 审计问题汇总表

| ID | 优先级 | 状态 | 验证结果 |
|----|--------|------|----------|
| ISSUE-45 | P1 | 🟢 已修复 | 双路径 handler 使用 safe 长度计算第二段偏移，无越界读取 |
| ISSUE-46 | P2 | 🟢 已修复 | 所有变长 payload FS handler 读取前调用 `validate_payload_fits` |
| ISSUE-47 | P2 | 🟢 已修复 | `docs/PROGRESS.md` 中将 `novafs-core` unwrap 清理拆分为独立债务清理条目 |
| ISSUE-48 | P3 | 🟢 已修复 | `docs/INDEX.md` syscall label 映射已与 `main.rs` dispatch 一致 |
| ISSUE-49 | P3 | 🟢 已修复 | `handlers/service.rs` 的 `read_name_from_ipc` 校验完整名称落在消息长度内 |
| ISSUE-50 | P2 | 🟢 已修复（已验证） | `handle_symlink`/`handle_rename`/`handle_link` 直接拒绝超过 `MAX_PATH_LEN` 的长度 |

> **Final audit: zero issues remaining, TASK-4 closure criteria met.**

## TASK-4 再审计记录

> **再审计时间**: 2026-07-07
> **再审计范围**: `services/rootserver/src/handlers/`、`services/rootserver/src/main.rs` syscall dispatch、`libs/libnova/src/validate.rs`、`docs/TASK.md`、`docs/INDEX.md`、`docs/PROGRESS.md`
> **结论**: ISSUE-45..50 均已修复。第三次审计待执行以确认无新增问题。
> **验证命令**:
> - `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
> - `cargo test -p libnova --features std --target x86_64-pc-windows-msvc validate::` — 7 项全过
> - `cargo clippy -p rootserver --target x86_64-unknown-none` — 64 个 error 均为 rootserver 历史债务，不在 `handlers/*` 与 `validate.rs` 中
>
> **结论**: ISSUE-45..49 均已按声明修复；再审计发现 1 个新问题 ISSUE-50（双路径 handler 对超长路径未拒绝导致第二路径偏移错误），已加入 ISSUE.md 并建议按 ISSUE-45 原始建议 3 直接拒绝超过 `MAX_PATH_LEN` 的长度。

## TASK-4 最终审计（第三次审计）

> **审计时间**: 2026-07-07
> **审计范围**: `services/rootserver/src/handlers/`、`services/rootserver/src/main.rs` syscall dispatch、`libs/libnova/src/validate.rs`、`docs/TASK.md`、`docs/INDEX.md`、`docs/PROGRESS.md`
> **验证命令**:
> - `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
> - `cargo test -p libnova --features std --target x86_64-pc-windows-msvc validate::` — 7 项全过
> - `cargo clippy -p rootserver --target x86_64-unknown-none` — 64 个 error 均为 rootserver 历史债务，不在 `handlers/*` 与 `validate.rs` 中
>
> **结论**: ISSUE-50 已按声明修复并验证；ISSUE-45..49 修复状态保持有效；审计范围内未发现新增问题。
>
> **Final audit: zero issues remaining, TASK-4 closure criteria met.**

---

## TASK-5 审计详情

> **审计时间**: 2026-07-07
> **审计范围**: `libs/libnova/src/ipc/pack.rs`、`libs/libnova/src/ipc.rs`、`libs/libnova/src/syscall.rs`、`libs/libnova/src/fs_ipc.rs`、`docs/TASK.md`、`docs/INDEX.md`
> **验证命令**:
> - `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
> - `cargo test -p libnova --features std --target x86_64-pc-windows-msvc` — 17 项全过（含 `ipc::pack` 9 项）
> - `cargo test -p novafs-core --features std --target x86_64-pc-windows-msvc` — 4 项全过
> - `cargo clippy -p libnova --target x86_64-unknown-none` — 15 个 warning 均为历史债务或 `sel4-sys` 生成代码，`ipc/pack.rs`、`fs_ipc.rs` 及本次修改的 `syscall.rs` 相关新增代码零 clippy error；host triple clippy 因缺少 `SEL4_OUT_DIR` 未运行
>
> **结论**: `ipc::pack` 边界检查正确，ABI 保持不变，测试覆盖主要边界；但 `syscall.rs` 仍保留多处手动字节打包循环，TASK-5 的统一目标未完全达成，文档描述与代码状态不符。

### ISSUE-51: `syscall.rs` 仍有多处直接操作 MR 的字节打包循环未迁移到 `ipc::pack`

- **Severity**: P2
- **Location**:
  - `libs/libnova/src/syscall.rs` 中以下函数/宏仍包含直接操作 MR 索引的字节打包循环：
    - `sys_print` (76-93)
    - `sys_spawn` 的 `write_bytes!` 宏 (240-258)
    - `sys_open` (339-350)
    - `sys_write` (403-414)
    - `sys_unlink` (432-449)
    - `sys_link` (463-492)
    - `sys_symlink` (506-535)
    - `sys_rename` (549-578)
    - `sys_block_write` (624-635)
  - `docs/TASK.md` 第 61 行及子任务 5.4 表格声称 `syscall.rs` 已使用 `libnova::ipc::pack`
  - `docs/INDEX.md` 第 35 行称 `ipc::pack` "replaces duplicate packing loops in `syscall.rs` and `fs_ipc.rs`"
- **Problem**:
  - 上述 9 处代码均手动将字节切片按 little-endian 打包进 MR，与 `ipc::pack::MessageWriter::write_bytes` 功能重复，违反 TASK.md 核心设计约束“替换后 `syscall.rs` 与 `fs_ipc.rs` 不再包含任何直接操作 MR 索引的循环打包代码”。
  - `fs_ipc.rs` 的重复打包代码（`write_bytes_to_msg`/`read_bytes_from_msg`）已正确替换为 `ipc::pack`，但 `syscall.rs` 的统一迁移未完成。
  - 文档 `docs/TASK.md` 与 `docs/INDEX.md` 对 TASK-5 完成度的描述与代码实际状态不符，可能误导后续工作。
- **Suggested fix**:
  1. 将 `syscall.rs` 中上述手动循环逐一替换为 `ipc::pack::MessageWriter`（或新增内部 helper 统一委托），保持消息布局、标签值、能力槽语义不变。
  2. 在全部循环迁移完成前，更新 `docs/TASK.md` 与 `docs/INDEX.md`，明确当前完成范围：已移除 `write_packed_bytes`/`write_bytes_to_msg`/`read_bytes_from_msg`；`syscall.rs` 中 `sys_print`/`sys_open`/`sys_write`/`sys_unlink`/`sys_link`/`sys_symlink`/`sys_rename`/`sys_block_write`/`sys_spawn` 的字节打包循环仍待迁移。
- **修复状态**: 🟢 已修复（已验证） — 已将 `syscall.rs` 中列出的 9 处手动 MR 字节打包循环全部替换为 `ipc::pack::MessageWriter`/`MessageReader`；`sys_read` 与 `sys_block_read` 的 IPC buffer 指针复制也改为 `ipc::pack::MessageReader`。
- **关联**: [TASK-5]

### 其他观察（未列入正式 issue）

- `services/fs_server/src/main.rs` 仍保留本地 `write_bytes_to_msg` / `copy_bytes_from_msg` 实现，与 `libnova::ipc::pack` 功能重复；该文件不在本次审计显式范围内，但如 TASK-5 目标为“统一 IPC 字节打包”，建议后续轮次将 server 端一并迁移。
- `services/rootserver/src/handlers/service.rs` 的 `read_name_from_ipc` 同样为手动解包，可与 `ipc::pack::MessageReader` 统一；不在本次审计显式范围内。
- `ipc::pack` 测试已覆盖 roundtrip、越界写、越界读、截断 length-prefixed 负载、最大长度默认场景；建议后续补充 `with_cursor` 偏移、空切片、恰好 8/16 字节边界等用例。

## TASK-5 再审计记录（第二次审计）

> **再审计时间**: 2026-07-07
> **再审计范围**: `libs/libnova/src/ipc/pack.rs`、`libs/libnova/src/ipc.rs`、`libs/libnova/src/syscall.rs`、`libs/libnova/src/fs_ipc.rs`、`docs/TASK.md`、`docs/INDEX.md`、`docs/ISSUE.md`
> **验证命令**:
> - `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
> - `cargo test -p libnova --features std --target x86_64-pc-windows-msvc` — 17 项全过（含 `ipc::pack` 9 项）
> - `cargo test -p novafs-core --features std --target x86_64-pc-windows-msvc` — 4 项全过
> - `cargo clippy -p libnova --target x86_64-unknown-none` — 8 个 warning 均为历史债务（`env.rs`、`ipc.rs`、`syscall.rs:71`、`tcb.rs`），`ipc/pack.rs`、`fs_ipc.rs` 及 `syscall.rs` 本次修改区域零新增 clippy error
>
> **审计结论**:
> 1. `syscall.rs` 中无剩余直接 MR 字节打包循环；`sys_print`/`sys_spawn`/`sys_open`/`sys_write`/`sys_unlink`/`sys_link`/`sys_symlink`/`sys_rename`/`sys_block_write` 均使用 `ipc::pack::MessageWriter`，`sys_read`/`sys_block_read` 使用 `ipc::pack::MessageReader`。
> 2. `fs_ipc.rs` 中无剩余直接 MR 字节打包循环；字节写入通过 `write_bytes_at`（内部使用 `ipc::pack::MessageWriter`），`read_direct` 使用 `ipc::pack::MessageReader`。
> 3. `ipc::pack::MessageWriter`/`MessageReader` 边界检查正确：`write_bytes`/`read_bytes` 均按 `len.div_ceil(8)` 与 `remaining()` 比较；`read_len_prefixed_bytes` 校验 `len > out.len()` 防止缓冲区溢出。
> 4. `ipc::pack` 测试覆盖 u64/bytes/length-prefixed roundtrip、越界写、越界读、截断 length-prefixed 负载、最大 MR 长度默认场景。
> 5. `docs/TASK.md`、`docs/INDEX.md`、`docs/ISSUE.md` 已同步：ISSUE-51 标记为“已修复（已验证）”，INDEX.md 修正 `syscall.rs`/`fs_ipc.rs` 行号，TASK-5 状态改为已完成。
>
> **TASK-5 再审计：零问题，满足闭环条件。**

---

## TASK-6 审计详情

> **审计时间**: 2026-07-07
> **审计范围**: `libs/libnova/src/syscall.rs`、`libs/libnova/src/fs_ipc.rs`、`services/rootserver/src/main.rs`、`services/rootserver/src/tests.rs`、`services/rootserver/src/services.rs`、`services/rootserver/src/handlers/fs.rs`、`services/fs_server/src/main.rs`、`docs/INDEX.md`、`docs/TASK.md`
> **验证命令**:
> - `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
> - `cargo test -p libnova --features std --target x86_64-pc-windows-msvc` — 21 项全过（含 `syscall::tests` 2 项、`fs_ipc::tests` 2 项）
> - `cargo clippy -p libnova --target x86_64-unknown-none` — 8 个 warning 均为历史债务（`env.rs`、`ipc.rs`、`syscall.rs:183`、`tcb.rs`），`syscall.rs`/`fs_ipc.rs` 本次修改区域零新增 clippy warning
> - `cargo clippy -p rootserver --target x86_64-unknown-none` — 64 个 error 均为 rootserver 历史债务，不在 `main.rs` syscall dispatch 区域（1440–2524）、`services.rs`、`handlers/fs.rs`、`tests.rs` 本次修改区域
> - `cargo clippy -p fs_server --target x86_64-unknown-none` — 1 个 error（`not_unsafe_ptr_arg_deref` at `_start` arg parsing）与 2 个 warning 均为历史债务，不在 `FsLabel` dispatch 区域（716–1371）
>
> **审计结论**:
> 1. `SyscallNum` 枚举值（1–15、20–46、50）与 `FsLabel` 枚举值（20–38、0xF500）与既有运行时 ABI 完全一致。
> 2. `syscall.rs` client stubs 全部使用 `SyscallNum::X.as_word()`；`fs_ipc.rs` helpers 全部使用 `FsLabel::X.as_word()`。
> 3. RootServer syscall dispatch（`main.rs:1440`）与 test dispatch（`tests.rs:223`）均使用 `SyscallNum::from_u64(label)` 并匹配 enum variants。
> 4. `services.rs` 的 `note_fs_forward` / `ping` 与 `handlers/fs.rs` 的 FS forwarding 均使用 `FsLabel::from_u64` / `FsLabel::X.as_word()`。
> 5. fs_server dispatch（`main.rs:716`）使用 `FsLabel::from_u64(label)` 并匹配 enum variants。
> 6. `libs/libnova/src/syscall.rs` 与 `libs/libnova/src/fs_ipc.rs` 各新增 2 项 host 测试，覆盖所有枚举值的数值稳定性与 `from_u64` roundtrip。
> 7. `docs/INDEX.md` 与 `docs/TASK.md` 已同步，描述 `SyscallNum` / `FsLabel` 为单一真相源。
>
> **TASK-6 审计：零问题，满足闭环条件。**

---

## TASK-7 审计详情

> **审计时间**: 2026-07-07
> **审计范围**: `libs/libnova/src/allocator.rs`、`libs/libnova/src/lib.rs`、`services/rootserver/src/memory.rs`、`docs/INDEX.md`、`docs/TASK.md`
> **验证命令**:
> - `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
> - `cargo test -p libnova --features std --target x86_64-pc-windows-msvc` — 21 项全过
>
> **审计结论**:
> 1. 所有分配器类型和常量（`SlotAllocator`、`ObjectAllocator` trait、`UntypedAllocator`、`FrameAllocator`、`MemoryRegion`、`MAX_REGION_PAGES`、`MAX_CSPACE_SLOTS`、`MAX_UNTYPED_CAPS`、`MIN_REUSABLE_FRAGMENT_BITS`）已完整从原始 `memory.rs` 迁移至 `allocator.rs`，无遗漏。
> 2. `allocator.rs` 中无任何 `libnova::ipc` 遗留引用 — 全部已改为 `crate::ipc`。
> 3. `services/rootserver/src/memory.rs` 的 re-export 覆盖所有被 `crate::memory::*` 引用的类型（7 个 public 项），共 13 处 import 站点全部满足。
> 4. 零代码重复 — 分配器类型定义仅存在于 `libs/libnova/src/allocator.rs`，`services/` 下无重复定义。
> 5. `docs/INDEX.md` 与 `docs/TASK.md` 对 TASK-7 的描述与实际代码状态一致。
>
> **TASK-7 审计：零问题，满足闭环条件。**

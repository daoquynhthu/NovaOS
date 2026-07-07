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

## 2026-07-06: Phase 1 P2 — Toolchain components 与 GitHub Actions CI

**完成项**：
- `rust-toolchain.toml` components 增加 `clippy`、`rustfmt`、`llvm-tools`
- 验证 `cargo fmt --check` 与 `cargo clippy --workspace --target x86_64-unknown-none` 可运行
- 创建 `.github/workflows/ci.yml`：
  - Linux job：安装系统依赖 → 读取 `rust-toolchain.toml` 安装 Rust → 缓存 cargo/seL4 构建 → 构建 seL4 kernel → 运行 fmt/check/clippy
  - Windows job：读取 `rust-toolchain.toml` → 运行 `cargo fmt --check`
- 更新 `docs/INDEX.md`：新增 CI workflow 条目，Known Frontiers 中 CI/CD 状态更新
- 关闭 `ISSUE-25`、`ISSUE-40`、`ISSUE-41`、`ISSUE-42`、`ISSUE-43`、`ISSUE-44`

**验证**：
- `cargo check --workspace --target x86_64-unknown-none`（配合 `SEL4_OUT_DIR` / `SEL4_KERNEL_DIR`）— 全绿通过
- 独立子 Agent 审计 + 二次审计通过，无剩余新增问题

**关联**：`ISSUE-25/40/41/42/43/44`

## 2026-07-07: Phase 1.5+2 — novafs-core 抽取与 host-native 测试

**完成项**：
- 完成 `TASK-1`：从 `services/rootserver/src/fs/` 抽取 `libs/novafs-core/` 独立 crate
  - `rootserver` 与 `fs_server` 均通过 crate 依赖使用 `novafs-core`
  - 删除 `fs_server` 中的 `include!()` 与 `#![allow(dead_code)]`
- 完成 `TASK-2`：`libnova` 支持 host-native 测试
  - 为 `libnova`/`sel4-sys`/`novafs-core` 添加 `std` 特性门控
  - 在 `sel4-sys` 的 `std` 特性下提供 `__sel4_ipc_buffer` host-test stub
  - 新增 `cap::tests::cap_rights_bits` 作为首个 host 单元测试
- 完成 `TASK-3`：`novafs-core` host-native 测试
  - 新增 `MockBlockDevice`（`Vec<[u8; 512]>`）
  - 新增 4 个集成测试：`format_and_read_write_file`、`mkdir_and_list`、`link_rename_truncate`、`encrypted_roundtrip`
- 修复 NovaFS `alloc_block` 数据块号计算 bug：返回的块号重复加了 `data_start`，导致分配超出小容量设备范围

**验证**：
- `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
- `cargo test -p libnova --features std --target x86_64-pc-windows-msvc` — 1 passed
- `cargo test -p novafs-core --features std --target x86_64-pc-windows-msvc` — 4 passed

**关联**：`TASK-1`、`TASK-2`、`TASK-3`

## 2026-07-07: TASK-4 — RootServer syscall dispatch 拆分启动

**完成项**：
- 重新细化 `docs/TASK.md` 中 TASK-4 的子任务，使其可直接落地
- 创建 `services/rootserver/src/handlers/` 模块骨架（`mod.rs` / `core.rs` / `fs.rs` / `metadata.rs` / `service.rs`）
- 定义 `SyscallContext<'a>` 以聚合 handler 所需的共享可变引用
- 把 syscall 输入校验 helpers 下沉到 `libnova::validate`，覆盖 message length / MR index / capability index 边界检查，并通过 host-native 测试
- 已提取到 `handlers/core.rs` 的 handler：`sys_yield`、`sys_get_pid`、`sys_sleep`、`sys_waitpid`、`sys_kill`
- 这些 handler 入口已调用 `libnova::validate` 进行输入边界检查

**验证**：
- `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
- `cargo test -p libnova --features std --target x86_64-pc-windows-msvc validate::` — 7 passed

**关联**：`TASK-4.1`、`TASK-4.2`、`TASK-4.3`、`TASK-4.4`、`TASK-4.5`（部分）

## 2026-07-07: TASK-4.5 完成 — process-lifecycle handlers 全提取

**完成项**：
- 把 `sys_exit`、`sys_spawn`、`sys_fork` 从 `main.rs` 提取到 `handlers/core.rs`
- `sys_wait`、`sys_kill` 保持已提取状态
- 为 `handle_exit`/`handle_spawn`/`handle_fork` 接入 `SyscallContext`
- 将 `main.rs` 中的 `deny_if_memory_pressure`、`refresh_local_fs_view`、`spawn_boot_process` 改为 `pub(crate)` 以便 handler 调用
- 顺手修复 `handlers/core.rs` 本次新增/涉及代码的 clippy 错误：替换 `(len + 7) / 8` 为 `len.div_ceil(8)`，消除索引循环变量警告，移除多余 `as usize`
- 运行 `cargo fmt` 一次

**验证**：
- `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
- `cargo test -p libnova --features std --target x86_64-pc-windows-msvc validate::` — 7 passed
- `cargo clippy -p rootserver --target x86_64-unknown-none` — `handlers/core.rs` 零 error；剩余 ~79 个 error 为 rootserver 历史债务

**关联**：`TASK-4.5`

## 2026-07-07: 独立债务清理 — novafs-core unwrap 转 expect

**完成项**：
- `libs/novafs-core/src/crypto.rs`：两个 `try_into().unwrap()` 改为 `.expect()`
- `libs/novafs-core/src/novafs.rs`：`format()` 中 6 处 `unwrap()` 改为 `.expect("format: ...")`

**说明**：
- 本次清理属于 `novafs-core` 独立债务清理，与 TASK-4.5 RootServer handler 提取分属不同意图，已在文档中拆分记录。
- 未来提交继续遵守 AGENT.md 单次变更单一意图约束。

**验证**：
- `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
- `cargo test -p novafs-core --features std --target x86_64-pc-windows-msvc` — 4 passed

**关联**：技术债务清理（非 TASK-4 子任务）

## 2026-07-07: TASK-4.6 完成 — memory handlers 全提取

**完成项**：
- 把 `sys_brk`、`sys_shm_alloc`、`sys_shm_map`、`sys_mmap_shared`、`sys_munmap_shared` 从 `main.rs` 提取到 `handlers/core.rs`
- 全部通过 `SyscallContext` 访问进程管理器、分配器、`SHARED_MEMORY_MANAGER`
- `handlers/core.rs` 保持零 clippy error；`cargo fmt` 已执行

**验证**：
- `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
- `cargo test -p libnova --features std --target x86_64-pc-windows-msvc validate::` — 7 passed
- `cargo clippy -p rootserver --target x86_64-unknown-none` 中 `handlers/core.rs` 零 error

**关联**：`TASK-4.6`

## 2026-07-07: TASK-4.7 完成 — FS handlers 全提取

**完成项**：
- 创建 `services/rootserver/src/handlers/fs.rs`，包含：
  - `handle_open`/`handle_read`/`handle_write`/`handle_close`
  - `handle_mkdir`/`handle_rmdir`/`handle_unlink`/`handle_rename`/`handle_link`/`handle_symlink`/`handle_readlink`
  - `handle_chmod`/`handle_chown`
  - `handle_block_read`/`handle_block_write`/`handle_block_info`
- 将 FS 相关的转发 helper（`try_forward_fs_*`、`resolve_fs_service_endpoint`、`copy_bytes_to_ipc_after_mr0` 等）从 `main.rs` 移到 `handlers/fs.rs`
- `main.rs` 中对应 syscall label（20-23、24-27、34-37、40-43）全部改为调用 `handlers::fs::*`
- FS handlers 返回 `(info, mrs, need_reply, manual_reply)` 4 元组，dispatch 循环正确设置 `manual_reply`

**验证**：
- `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
- `cargo test -p libnova --features std --target x86_64-pc-windows-msvc validate::` — 7 passed
- `cargo test -p novafs-core --features std --target x86_64-pc-windows-msvc` — 4 passed
- `cargo clippy -p rootserver --target x86_64-unknown-none` 中 `handlers/fs.rs` 零 error

**说明**：
- TASK-4.7 列表中的 `stat`/`list`/`truncate`/`encrypt`/`decrypt` 不在 RootServer syscall dispatch 中，它们由 `fs_server` 通过 FS IPC 协议直接处理（labels 30/31/32/34/35/36/38），因此本次未在 RootServer 提取。

**关联**：`TASK-4.7`

## 2026-07-07: TASK-4.8 完成 — metadata/service handlers 全提取

**完成项**：
- `services/rootserver/src/handlers/metadata.rs`：
  - `handle_getuid` / `handle_setuid` / `handle_getgid` / `handle_setgid`
- `services/rootserver/src/handlers/service.rs`：
  - `handle_service_register` / `handle_service_lookup` / `handle_service_set_ready`
  - `handle_fs_view_epoch` / `handle_get_time` / `handle_get_unix_time` / `handle_shutdown`
- `SyscallContext` 新增 `syscall_recv_slot`，供 `handle_service_register` 移动接收到的 cap
- `main.rs` 中对应 syscall label（6、28、29、30、31、32、33、44、45、46、50）全部改为调用 `handlers::metadata::*` / `handlers::service::*`

**验证**：
- `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
- `cargo test -p libnova --features std --target x86_64-pc-windows-msvc validate::` — 7 passed
- `cargo test -p novafs-core --features std --target x86_64-pc-windows-msvc` — 4 passed
- `cargo clippy -p rootserver --target x86_64-unknown-none` 中 `handlers/metadata.rs` 与 `handlers/service.rs` 零 error

**说明**：
- `chmod`/`chown`/`symlink`/`readlink` 已在 TASK-4.7 中作为 FS handlers 提取到 `handlers/fs.rs`，因此 TASK-4.8 的 metadata 部分只包含 uid/gid。

**关联**：`TASK-4.8`

## 2026-07-07: TASK-4.9 完成 — handler 输入校验

**完成项**：
- 在 `handlers/core.rs` 的 `handle_exit`/`handle_spawn`/`handle_brk`/`handle_shm_alloc`/`handle_shm_map`/`handle_mmap_shared`/`handle_munmap_shared`/`handle_sleep`/`handle_wait`/`handle_kill` 入口加入 `libnova::validate` 校验
- 在 `handlers/fs.rs` 的所有 FS handler 入口加入校验（`validate_one_mr`/`validate_two_mrs`/`validate_message_only`）
- 在 `handlers/metadata.rs` 的 `handle_setuid`/`handle_setgid` 入口加入校验
- 在 `handlers/service.rs` 的 `handle_service_register`（含 cap 校验）/`handle_service_lookup`/`handle_service_set_ready` 入口加入校验
- `handle_service_register` 调用 `validate_cap_index(ctx.info, 0)` 确认 extra cap 存在
- `handle_sleep` 改为接收 `&mut SyscallContext`，在 handler 内部读取 ticks 并校验 MR0

**验证**：
- `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
- `cargo test -p libnova --features std --target x86_64-pc-windows-msvc validate::` — 7 passed
- `cargo test -p novafs-core --features std --target x86_64-pc-windows-msvc` — 4 passed
- `cargo clippy -p rootserver --target x86_64-unknown-none` 中所有 handler 模块零 error

**关联**：`TASK-4.9`

## 2026-07-07: TASK-4 闭环 — 三次审计零 issue

**完成项**：
- 完成 RootServer syscall dispatch 拆分（4.1–4.8）与输入校验（4.9）
- 完成三轮独立子 Agent 审计：
  - 首次审计：产出 ISSUE-45..49
  - 再审计：验证 ISSUE-45..49 已修复，发现 ISSUE-50
  - 最终审计：验证 ISSUE-50 已修复，TASK-4 范围内零剩余 issue
- `docs/ISSUE.md` 已更新审计状态与修复汇总

**验证**：
- `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
- `cargo test -p libnova --features std --target x86_64-pc-windows-msvc validate::` — 7 passed
- `cargo test -p novafs-core --features std --target x86_64-pc-windows-msvc` — 4 passed
- `cargo clippy -p rootserver --target x86_64-unknown-none` — handler 模块与 `libnova::validate` 零 error；剩余 64 个 error 为 rootserver 历史债务，不在 TASK-4 范围

**说明**：
- 按照 `AGENT.md` Step 4–6，TASK-4 已完成审计闭环。
- 下一步按 `AGENT.md` Step 7：清空 `docs/TASK.md`，进入 `PLAN.md` 下一阶段（Phase 2 下一个 TASK 或 Phase 3）。

**关联**：`TASK-4` 全部子任务

## 2026-07-07: TASK-5 闭环 — 统一 IPC 字节打包

**完成项**：
- 在已有 `libnova::ipc` 原语层之上新增 `libnova::ipc::pack` 子模块，提供 `BoundError`、`MessageWriter`、`MessageReader`。
- 按 AGENT.md RED/GREEN 规则编写 9 个单元测试：先写 RED 测试（6 个失败），再实现 API 使 9 个全部通过。
- 替换 `libs/libnova/src/syscall.rs` 中所有手动 MR 字节打包循环（`sys_print`、`sys_spawn`、`sys_open`、`sys_write`、`sys_unlink`、`sys_link`、`sys_symlink`、`sys_rename`、`sys_block_write`）。
- 替换 `libs/libnova/src/syscall.rs` 中 IPC buffer 指针复制读取（`sys_read`、`sys_block_read`）为 `MessageReader`。
- 替换 `libs/libnova/src/fs_ipc.rs` 中 `write_bytes_to_msg`/`read_bytes_from_msg` 为 `ipc::pack`。
- 经过两次独立子 Agent 审计：首次发现 ISSUE-51，修复后再审计零问题。

**验证**：
- `cargo check --workspace --target x86_64-unknown-none` — 全绿通过
- `cargo test -p libnova --features std --target x86_64-pc-windows-msvc` — 17 passed
- `cargo test -p novafs-core --features std --target x86_64-pc-windows-msvc` — 4 passed
- `cargo clippy -p libnova --target x86_64-unknown-none` — 无新增 error；`ipc/pack.rs`、`fs_ipc.rs` 及本次修改区域零新增 clippy 告警

**说明**：
- 按照 `AGENT.md` Step 4–6，TASK-5 已完成审计闭环。
- 审计观察项（非正式 issue）：`services/fs_server/src/main.rs` 与 `services/rootserver/src/handlers/service.rs` 仍有本地打包/解包 helper，建议作为后续 TASK（TASK-6 或独立小任务）继续迁移，以完整实现"统一 IPC 字节打包"愿景。

**关联**：`TASK-5` 全部子任务

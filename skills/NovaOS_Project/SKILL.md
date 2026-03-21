---
name: NovaOS_Project
description: Use this skill when developing or reviewing NovaOS. The primary goal is end-to-end NovaFS development (correctness, durability, operability, performance); microkernel service split is a supporting strategy, not the sole goal.
metadata:
  short-description: NovaFS full-development playbook
---

# NovaOS / NovaFS Skill

## 1) Project North Star

本项目主线是 **NovaFS 完整开发**。

完成标准是：
- 功能完整：目录树、大文件、权限、链接、重命名、truncate/sparse、加密、同步。
- 行为可靠：异常输入、权限边界、并发与崩溃场景可预测。
- 数据可信：写入可持久、元数据一致、回归可复现。
- 可演进：从 RootServer 迁移到 `fs_server` 时，语义不漂移。

微内核化（RootServer 降权、FS 服务化）是为了达成上述目标的架构路径，不是目标替代品。

## 2) Current Reality (2026-03-20)

- 现有可用且通过回归的 NovaFS 主数据面仍在 RootServer（`services/rootserver/src/fs/novafs.rs`）。
- `fs_server` 已有 `open/read/write/close/ping` IPC 回路，但当前是内存 shadow data plane（重启不持久）。
- RootServer 的文件 syscall 已进入混合转发（`open/read/write/close` 有远端映射与回退）。
- `services::ping("fs")` 仍为非阻塞探针语义（返回 RootServer 观测计数），不是严格远端阻塞健康检查。
- 内存治理已具备 OOM 准入与碎片观测（`deny_if_memory_pressure` + `meminfo` 指标）。

## 3) Source-of-Truth Files

- 进度与路线：`Project_Progress.md`
- 交接总览：`HANDOVER.md`
- 核心 FS 实现：`services/rootserver/src/fs/novafs.rs`
- VFS 抽象：`services/rootserver/src/vfs.rs`
- syscall 中枢：`services/rootserver/src/main.rs`
- Shell 命令面：`services/rootserver/src/shell.rs`
- FS 服务：`services/fs_server/src/main.rs`
- 协议常量：`libs/libnova/src/fs_ipc.rs`
- 回归脚本：`test.ps1`
- 最新串口日志：`latest_test_run.log`

## 4) Must-Pass Gates

每次改动至少通过：

```powershell
cargo check --workspace --target x86_64-unknown-none
$env:NOVA_TEST_TIMEOUT_SECONDS='120'
./test.ps1
```

约束：
- 2 分钟是当前团队时限基线，不允许用延长超时掩盖不稳定。
- 默认清理 `disk.img`，保证回归确定性（除非显式设置 `NOVA_TEST_KEEP_DISK=1`）。

## 5) Execution Rules

1. 优先守住 NovaFS 行为语义，再推进架构迁移。
2. 不可在同一变更中同时移除“回退路径 + 可观测性”。
3. 任何 FS 迁移必须保持错误码与权限行为一致（尤其 `EBADF/ENOENT/EPERM`）。
4. 新能力先加测试，再切主路径；失败时必须可回退。
5. 进度书必须同步更新，避免“代码已落地但文档未标记”。

## 6) Recommended Next Work Queue

按优先级执行：

1. **P0: NovaFS 一致性与耐久性收口**
- 先补 durability/consistency 测试（sync 后重启、目录项/位图一致性、异常中断恢复）。
- 将当前 `latest_test_run.log` 中大量 demand paging 噪声分级，避免淹没真实错误。

2. **P1: fs_server 从 shadow 到持久数据面**
- 将 `fs_server` 接到真实块设备与 NovaFS 语义层（至少先实现持久 `open/read/write/close`）。
- 完成重启后句柄失效策略与可恢复策略测试。

3. **P2: Shell 文件命令服务化**
- `cat/touch/ls/mkdir/rm/mv` 分批迁移到 `fs_server`，逐项加回归。
- 完成后再下线 RootServer 对应本地路径。

4. **P3: 性能与可观测**
- Demand paging 日志节流与采样。
- FS 请求延迟、错误码分布、回退触发率统计。

## 7) Quick Triage Checklist

遇到回归优先检查：
- 是否因 IPC Buffer 覆写导致读写 payload 异常。
- `remote_fd` 是否丢失或错配（`process.rs` + `main.rs` open/close/read/write 路径）。
- `fs_server` 返回码是否被错误当作成功。
- 目录操作后父目录 `size/mtime` 是否同步。
- 共享内存映射/回收是否残留外部 frame 引用。

## 8) Common Error Patterns (Must Watch)

- 将 `fs_server` 内存态行为误当成“已持久化完成”。
- 只改转发路径，不补错误码一致性（`EBADF/ENOENT/EPERM` 漂移）。
- 一次提交同时移除“回退路径 + 观测埋点”，导致无法定位回归。
- 增加新能力但不补自动化回归（尤其 durability/重启场景）。
- 跳过 `Project_Progress.md` 更新，造成“代码状态与计划状态”脱节。

## 9) Coding Standards (Repo-Specific)

- 小步提交：每个变更只做一个语义目标（功能/修复/重构分离）。
- 先测后切：先加测试，再切换主路径；迁移期保留 fallback。
- 错误显式：禁止吞错，保留日志上下文（label/fd/path/pid）。
- 接口不漂移：syscall 行为对用户态保持稳定，避免 silent behavior change。
- 文档同更：涉及架构或阶段推进，必须更新 `Project_Progress.md`；`HANDOVER.md` 建议按阶段或关键架构变化同步。

## 10) Definition of Success for This Repo

当以下条件成立，可认为“NovaFS 主线阶段性完成”：
- NovaFS 关键功能在用户态回归全绿且可重复；
- FS 主数据面已从 RootServer 平滑迁入 `fs_server`；
- 崩溃/重启下数据一致性和恢复策略有自动化验证；
- RootServer 不再承担文件系统上帝进程职责，仅保留最小编排与保护逻辑。

# NovaOS Handover (NovaFS-Centric)

Last updated: 2026-03-20  
Workspace: `e:\System`  
Branch: `main`  
HEAD: `fdb684f`

## 1. Executive Direction

本项目主目标是 **NovaFS 的完整开发与落地**。  
微内核化（RootServer 降权、`fs_server` 服务化）是实现路径与长期结构优化，不是目标替代品。

当前交接原则：
- 一切改造以 NovaFS 语义正确性和可回归性为先。
- 架构演进必须服务于“可持久、可验证、可维护”的文件系统目标。

## 2. Current Architecture Reality

### 2.1 RootServer 仍是 FS 主数据面

关键文件：`services/rootserver/src/main.rs`、`services/rootserver/src/fs/novafs.rs`

- 本地 NovaFS 是当前真实持久化路径（磁盘 + inode/bitmap/目录项）。
- Shell 文件命令主体（`ls/cat/touch/mkdir/rm/mv/truncate/encrypt/decrypt/ln/chmod/chown/sync`）仍依赖本地 FS 路径。
- syscall `open/read/write/close` 已进入“本地 + 服务转发”混合阶段。

### 2.2 fs_server 是迁移桥，不是最终权威

关键文件：`services/fs_server/src/main.rs`

- 已实现 `FS_LABEL_OPEN/READ/WRITE/CLOSE/PING` 协议处理。
- `open/read/write/close` 已从纯内存 shadow 切到 **syscall-backed persistent proxy**：由 `fs_server` 维护远端 FD 映射，但真实读写走 RootServer 当前 NovaFS syscall 后端。
- 这意味着 `fs_server` 已具备持久语义，但仍未直接拥有块设备/NovaFS 核心实现，尚未替代 RootServer 的磁盘权威数据面。

### 2.3 服务发现与观测

关键文件：`services/rootserver/src/services.rs`

- Name Service 支持版本回退解析（如 `serial -> serial.v1`）。
- `fsping` 目前是非阻塞探针模式，回传 RootServer 观测的转发计数（open/read/write/close），未强制阻塞 IPC 健康事务。

## 3. NovaFS Capability Snapshot

已落地（主线可用）：
- 目录树与路径解析（含 `.`/`..` 与绝对/相对路径）。
- 大文件支持（含双重间接块）。
- 透明加密开关（inode flags）。
- truncate + sparse 文件路径。
- hard link / symlink。
- rename（含目录重命名场景）。
- chmod / chown / UID-GID 权限校验。
- block cache + sync 机制。

仍在收口：
- fs_server 持久数据面替换。
- 服务崩溃/重启后的句柄与恢复语义。
- durability/consistency 的系统化故障回归（不只功能回归）。

## 4. Memory Management State

关键文件：`services/rootserver/src/memory.rs`、`services/rootserver/src/shared_memory.rs`、`services/rootserver/src/main.rs`

已具备能力：
- `sys_shm_alloc/sys_shm_map` 和 `sys_mmap_shared/sys_munmap_shared`。
- 引用计数回收、进程退出自动 detach 清理。
- OOM 准入与碎片观测：`deny_if_memory_pressure`、`fragmentation_bytes`、`oom_stats`。
- `meminfo` 可观测：free RAM、fragment tail、OOM 事件、frame cache。

剩余建议：
- 增强 mmap/shm 压力用例覆盖（随机映射/解映射 + 进程反复创建销毁）。
- 将内存治理指标纳入自动化回归判定阈值。

## 5. Regression Gate (Non-Negotiable)

每次合并前至少通过：

```powershell
cargo check --workspace --target x86_64-unknown-none
$env:NOVA_TEST_TIMEOUT_SECONDS='120'
./test.ps1
```

说明：
- 120 秒是团队约束；不通过延长超时掩盖回归。
- `test.ps1` 默认重建 `disk.img`，用于确定性回归。

## 6. Key Code Entry Points

- `services/rootserver/src/main.rs`
  - syscall dispatch
  - FS 混合转发路径（open/read/write/close）
  - SHM/MMAP/OOM 准入
- `services/rootserver/src/fs/novafs.rs`
  - 磁盘 NovaFS 核心实现（超级块、inode、bitmap、目录项、分配回收）
- `services/rootserver/src/shell.rs`
  - 文件与系统命令主入口，当前是回归敏感面
- `services/rootserver/src/process.rs`
  - `FileDescriptor.remote_fd`、`mmap_top`、进程生命周期
- `services/fs_server/src/main.rs`
  - `fs.v1` 服务循环、内存 shadow 数据面
- `libs/libnova/src/fs_ipc.rs`
  - FS IPC label 与协议常量

## 7. Known Risk Boundaries

1. **双栈语义漂移风险**  
RootServer 本地 FS + fs_server shadow 同时存在，需持续保证返回码与偏移推进一致。

2. **持久化完成错觉风险**  
fs_server 现在已有持久语义代理，但仍是 RootServer-backed proxy，不能误判为“FS 已完全服务化完成”。

3. **日志噪声掩盖风险**  
`latest_test_run.log` 中 demand paging 高频日志会淹没关键错误，建议分级与节流。

4. **迁移顺序风险**  
禁止一次性删除回退路径和观测埋点，必须分步推进。

## 8. Common Errors (Frequent in This Repo)

- **把代理数据面当成最终完成**：`fs_server` 当前虽已具备持久语义，但仍不是直接块设备/NovaFS owner，不能等同于最终服务化完成。
- **错误码语义漂移**：迁移后 `open/read/write/close` 返回行为与旧路径不一致。
- **IPC 载荷覆盖**：MR/IPC Buffer 读写顺序错误导致数据被覆盖或长度错乱。
- **`remote_fd` 生命周期错配**：本地 FD 与远端 FD 映射失配，触发随机读写失败。
- **测试通过但耐久性未验证**：只做功能回归，缺失重启/一致性验证。
- **只改代码不改进度书**：导致协作时认知分叉。

## 9. Coding Standards (Mandatory)

- 单变更单目标：避免在同一提交混入功能、重构、日志清理三类动作。
- 迁移必须可回退：任何服务化切换都保留 fallback，直到回归稳定。
- 错误码与权限语义保持兼容：禁止 silent behavior change。
- 日志可定位：关键路径日志必须包含 `pid/fd/path/label` 中至少两个维度。
- 测试门禁前置：未过 `cargo check` + `test.ps1(120s)` 不得宣称完成。
- 文档同步规则：里程碑推进后必须更新 `Project_Progress.md`；`HANDOVER.md` 建议在阶段切换或架构变化时更新。

## 10. Practical Next Steps (Execution Order)

### Step A: NovaFS 一致性/耐久性先补齐

- 增加测试：sync 后重启校验、目录项与位图一致性、异常中断后恢复验证。
- 将这类用例加入 `test.ps1` 或并行的 durability 套件。

### Step B: fs_server 进入持久数据面

- 当前已完成第一步：`open/read/write/close` 通过 syscall-backed proxy 接入真实 NovaFS 持久语义。
- 下一步目标不是停留在代理层，而是让 `fs_server` 进一步接入真实块设备与 NovaFS 核心实现。
- 在此基础上再扩展目录类操作，并持续保留 fallback。

### Step C: Shell 文件命令分批服务化

- 第一批：`cat/touch`
- 第二批：`ls/mkdir/rm`
- 第三批：`mv/ln/chmod/chown/truncate/encrypt/decrypt/sync`
- 每一批都要有“服务成功路径 + 回退路径”回归。

### Step D: RootServer 降权收口

- 当 fs_server 持久路径和故障恢复充分验证后，逐步下线 RootServer 本地 FS 执行路径。
- 保留最小编排与保护职责，完成“从上帝进程到协调进程”的演进。

## 11. Working Tree Note

当前仓库为活跃开发态（dirty worktree）。  
提交时按文件意图核对，不要用破坏性命令清空现场。

## 12. Handover Contract

接手者默认遵守：
- 先保证 NovaFS 主线质量，再做架构动作；
- 每步变更都可回退、可观测、可测试；
- 每次关键进展都必须同步 `Project_Progress.md`（不允许跳过）；
- 架构状态变化时建议同步本文件，避免交接信息过期。

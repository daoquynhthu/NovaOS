# PLAN.md — NovaOS 路线图

> **定位**: 从当下到成熟的总路线，宏观阶段划分。  
> **引用关系**: 本文件中的阶段编号 `[PLAN-Px]` 可被 TASK.md 引用。  
> **更新规则**: 仅当路线方向变更时更新，由仓库维护者执行。代理不得修改此文件。

---

## Phase 0: 仓库卫生 ✅（已完成）

**目标**: 清除非必要文件、激活 lint、统一构建目录，建立文档体系。

| 子项 | 状态 | 说明 |
|------|------|------|
| 工作区 lint 激活 | ✅ | 6 个 member crate 全部 `[lints] workspace = true` |
| `.gitignore` 修复 | ✅ | `test_output.txt` 移出追踪 |
| 无用文件清理 | ✅ | 日志、构建产物、重复配置文件 |
| 文档体系建立 | ✅ | AGENT.md / PLAN.md / TASK.md / ISSUE.md / PROGRESS.md / INDEX.md |
| 架构文档归档 | ✅ | 四份 docs/*.md 加 ARCH-ID |
| `test_output.txt` 清理 | ✅ | git rm + .gitignore |

## Phase 1: 构建系统统一化

**目标**: 消除跨平台脚本碎片、统一构建目录、补齐基础设施配置。

| ID | 项 | 优先级 | 依赖 |
|----|-----|--------|------|
| P1.1 | 统一默认构建目录（Win/Linux 都用 `build`） | P0 | — |
| P1.2 | 提取 `scripts/cmake-common.sh`，消除 `.sh` 脚本重复 | P0 | P1.1 |
| P1.3 | `build.ps1` / `test.ps1` 的 `Set-Location` 改为 `--manifest-path` | P1 | — |
| P1.4 | 硬编码 QEMU 路径改为 PATH 搜索 | P1 | — |
| P1.5 | CMake 扩展构建所有 Rust 服务 | P1 | — |
| P1.6 | 工作区依赖版本集中到 `[workspace.dependencies]` | P1 | — |
| P1.7 | 新建 `.gitattributes` | P1 | — |
| P1.8 | `rust-toolchain.toml` 固定 nightly 日期 | P1 | — |
| P1.9 | 补全 `components`（clippy, rustfmt, llvm-tools） | P2 | — |
| P1.10 | 搭建 CI/CD（GitHub Actions 基础） | P2 | P1.6 |

## Phase 1.5: 测试基础设施

**目标**: 从 QEMU-only 回归演进为分层测试金字塔，让底层模块可独立验证。

**动机**: 当前所有验证依赖 QEMU 集成测试（120s），迭代慢、噪声大、底层逻辑变更无法快速反馈。分层测试可将反馈周期从分钟级降至毫秒级。

```
         ┌──────────────────────────┐
         │     QEMU 集成回归        │  少数关键路径，120s
         │   (test.ps1 ~50 stages)  │
         ├──────────────────────────┤
         │   NovaFS 模拟块设备测试   │  新增，< 1s
         │   (MockBlockDevice + FS) │
         ├──────────────────────────┤
         │   libnova 纯函数单元测试   │  新增，< 0.1s
         │   (Error/字节打包/Crypto) │
         ├──────────────────────────┤
         │   分配器逻辑测试          │  新增，< 0.1s
         │   (SlotAllocator/Bitmap) │
         └──────────────────────────┘
         cargo test (host native)   → 秒级反馈
         QEMU regression (test.ps1) → 最终门禁
```

| ID | 项 | 优先级 | 依赖 | 估算 |
|----|-----|--------|------|------|
| P1.5.1 | libnova 添加 host-native 测试支持 + 纯函数层测试（`Error`、字节打包、`cap_rights_new`、`CNode` 操作） | P0 | — | 0.5d |
| P1.5.2 | NovaFS MockBlockDevice（`Vec<[u8;512]>` 实现 `BlockDevice` trait）+ host 测试套件：`format`→`mkdir`→`write`→`read`→`link`→`rename`→`truncate`→校验磁盘结构 | P0 | P1.5.1 | 2d |
| P1.5.3 | `test.ps1` 支持 `-StageRange N-M` 参数选择阶段范围，分拆快速 smoke（~5 stage）与完整回归（~50 stage） | P1 | — | 0.5d |
| P1.5.4 | `SlotAllocator` / `UntypedAllocator` / `FrameAllocator` 纯逻辑测试（bitmap 分配/释放/碎片化） | P2 | — | 0.5d |

验证方式：`cargo test`（host native）+ `cargo check --target x86_64-unknown-none`

## Phase 2: 代码结构去债务与安全基线

**目标**: 消除 `include!()` 共享模式、拆分巨型 main.rs、统一 IPC 打包，并在每个新边界处定义安全契约。

**原则**: 重构不是安全中立的。拆出模块的同时就要定义它的最小权限边界，避免先造出“高权限临时结构”再回头修补。

| ID | 项 | 优先级 | 依赖 |
|----|-----|--------|------|
| P2.1 | 抽取 `libs/novafs-core/` 库 crate，消除 fs_server 的 `include!()` | P0 | — |
| P2.2 | 拆分 `main.rs` syscall dispatch 为独立函数，每个 handler 做输入长度/类型校验 | P0 | — |
| P2.3 | 统一 IPC 字节打包到 `libnova::ipc`，所有反序列化带 `BoundError` 检查 | P1 | — |
| P2.4 | 定义 `SyscallNum` 枚举替代魔术数字 | P1 | — |
| P2.5 | 共享分配器模块到 `libnova::allocator` | P1 | — |
| P2.6 | 移除 fs_server 的 `#![allow(dead_code)]` 豁免 | P1 | P2.1 |
| P2.7 | 定义 NovaOS 权能模型文档：每个未来服务拥有的 CSpace 条目清单 | P1 | — |
| P2.8 | 为 `fs_server`、`serial_server`、`user_app` 编写接口契约（请求/响应/不变量） | P1 | P2.3 |

## Phase 3: NovaFS 耐久性与一致性

**目标**: NovaFS 功能完整的基础上，补齐耐久性保证与故障恢复。

| ID | 项 | 优先级 | 依赖 |
|----|-----|--------|------|
| P3.1 | sync + 重启 + 一致性校验回归测试 | P0 | — |
| P3.2 | 目录项/位图/inode 一致性检查 | P0 | — |
| P3.3 | 异常中断后恢复验证 | P1 | P3.1 |
| P3.4 | 日志分级治理（demand paging 节流） | P1 | — |

## Phase 4: 微内核化推进

**目标**: fs_server 真正持有 NovaFS 数据面，解决同步死锁；**同步落实能力隔离**。

| ID | 项 | 优先级 | 依赖 |
|----|-----|--------|------|
| P4.1 | fs_server 直接持有块设备 + NovaFS 实例 | P0 | P2.1 |
| P4.2 | 解除 FS_SYNC_FORWARD_ENABLED=false 死锁 | P0 | P4.1 |
| P4.3 | Shell 命令全部迁移到 fs_server | P1 | P4.1 |
| P4.4 | RootServer 降权收口（仅保留最小编排职责） | P2 | P4.2 |
| P4.5 | 每个用户态进程/服务获得独立派生 CSpace，不再共享根 CNode | P0 | P2.7 |
| P4.6 | IPC 入口统一校验：消息长度、 capability 索引范围、权限位 | P1 | P2.8 |
| P4.7 | 关闭或过滤内核 debug syscall（`seL4_SysDebugHalt` 等） | P1 | P4.4 |

## Phase 5: 安全强化与审计

**目标**: 在架构边界稳定后，系统性地消除密码学、并发与配置层面的残余风险。

**原则**: 本阶段不改动架构大结构，只修复 Phase 2/4 边界确定后的具体漏洞。

| ID | 项 | 优先级 | 依赖 |
|----|-----|--------|------|
| P5.1 | 替换自定义 ChaCha20 为 `chacha20poly1305` 审计实现 | P0 | P4.1 |
| P5.2 | 每文件独立随机 nonce，替换 inode 派生 nonce | P0 | P5.1 |
| P5.3 | NovaFS 多操作并发锁保护（inode bitmap、superblock race） | P1 | P4.1 |
| P5.4 | `fork` 不继承父进程 fd 表，子进程重新初始化 | P1 | P4.6 |
| P5.5 | IPC 消息解析 fuzz 测试 + 边界覆盖 | P1 | P1.5.2 |
| P5.6 | 安全审计清单：CSpace、IPC、加密、并发、debug syscall | P2 | P5.1 |

## Phase 6: 基础设施补齐

**目标**: CI、编辑器配置、依赖审计、Docker 化。

| ID | 项 | 优先级 | 依赖 |
|----|-----|--------|------|
| P6.1 | CI/CD GitHub Actions（check + fmt + clippy + QEMU smoke） | P0 | P1.10 |
| P6.2 | `.editorconfig` | P1 | — |
| P6.3 | `cargo-deny` 配置 | P1 | — |
| P6.4 | Docker 构建环境 | P2 | — |

## Phase 7: 长期演进

**目标**: 达到可用 OS 的完整功能集。

| ID | 项 | 优先级 |
|----|-----|--------|
| P7.1 | VirtIO 驱动（net/block） | P1 |
| P7.2 | 真机启动（x86_64 PC） | P1 |
| P7.3 | 网络栈（lwIP 或 smoltcp） | P2 |
| P7.4 | AHCI/NVMe 驱动 | P2 |
| P7.5 | RISC-V 移植探索 | P3 |
| P7.6 | PIE/ASLR 支持 | P3 |
| P7.7 | 用户态异步运行时 | P3 |

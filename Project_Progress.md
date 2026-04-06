# NovaOS 项目进度书 (Project Progress)

> 文档定位：这是项目唯一的进度事实源（single source of truth），用于记录阶段状态、已完成里程碑、风险与下一步执行。

## 0. 硬性写入条款 (Mandatory Update Policy)

以下条款为强制执行，不可跳过：

1. 任何“可见进展”都必须更新本文件，否则该任务视为**未完成**。  
可见进展包括：代码合并、测试基线变化、架构路径变化、风险结论变化。

2. 每次更新至少要写清 5 个字段：  
`日期` / `改动范围` / `验证结果` / `风险` / `下一步`。

3. 未通过门禁测试时，禁止写“完成”；必须写“阻塞”并附阻塞原因。  
门禁：`cargo check --workspace --target x86_64-unknown-none` + `NOVA_TEST_TIMEOUT_SECONDS=120 ./test.ps1`。

4. 任何变更若影响架构或执行路径，必须更新 `Project_Progress.md`；  
`HANDOVER.md` 建议在阶段切换或关键架构变化时同步更新（非强制）。

5. 禁止只记录“做了什么”而不记录“如何验证”。  
无验证记录的条目视为无效进度。

## 1. 当前快照 (2026-03-20)

- 版本：`v0.1.0-alpha`
- 阶段：`0.8.0`（稳定回归 + NovaFS 主线推进 + 微内核迁移进行中）
- 项目主线：**NovaFS 完整开发**（功能、正确性、耐久性、可运维性）
- 架构策略：微内核化是支撑路径，不是目标替代
- 基线健康度：主线构建可通过，`test.ps1` 可在 120s 基线下通过

## 2. 总体执行路径图 (NovaFS-First)

### P0 稳定基线锁定（持续）
- 目标：回归全绿、可回退、可观测
- 状态：`进行中（持续守护）`

### P1 NovaFS 正确性与耐久性收口
- 目标：功能正确 + 元数据一致 + 重启后可验证
- 状态：`进行中`
- 备注：功能面已较完整，durability/consistency 自动化仍需系统补齐

### P2 fs_server 从 Shadow 到持久数据面
- 目标：`fs_server` 成为真实文件数据面（非内存影子）
- 状态：`进行中`
- 备注：当前 `open/read/write/close` 已有 shadow 实现，仍非持久化权威

### P3 Shell 文件命令服务化
- 目标：`ls/cat/touch/mkdir/rm/mv/...` 分批转入 `fs_server`
- 状态：`待推进`

### P4 RootServer 降权收口
- 目标：RootServer 退出 FS 上帝进程角色，仅保留最小编排职责
- 状态：`待推进`

## 3. 里程碑看板 (By Stream)

## 3.1 NovaFS 功能增强
- 状态：`大部分完成`
- 已完成：
  - 目录树、路径规范化（`.`/`..`）
  - 大文件（双重间接块）
  - truncate + sparse
  - rename（含目录重命名）
  - hardlink/symlink
  - chmod/chown + UID/GID 权限检查
  - 透明加密（inode flag）
  - block cache + sync
- 待收口：
  - durability/一致性故障回归（重启、异常中断、位图与目录项一致性）

## 3.2 内存管理增强
- 状态：`基本完成，持续压测`
- 已完成：
  - `sys_shm_alloc/sys_shm_map`
  - `sys_mmap_shared/sys_munmap_shared`
  - 引用计数回收、进程退出自动 detach
  - OOM 准入保护 + 碎片观测（`fragmentation_bytes`/`oom_stats`）
- 待推进：
  - 更强随机压力用例与长稳测试

## 3.3 微内核化演进（FS 方向）
- 状态：`进行中`
- 已完成：
  - `fs.v1` 协议常量与服务发现链路
  - RootServer 与 `fs_server` 独立 service endpoint 解耦
  - `open/read/write/close` 混合转发骨架 + `remote_fd` 映射
  - `fs_server` 从纯 shadow data plane 演进为 syscall-backed persistent proxy
  - `sys_read` 优先服务端、失败回退本地路径
- 待完成：
  - `fs_server` 从 persistent proxy 继续演进为直接持有块设备/NovaFS 的持久数据面
  - shell 文件命令分批服务化
  - 服务崩溃/重启恢复闭环

## 4. 近期进展日志（精简版）

### 2026-03-20
- 完成 Linux bring-up 第一阶段：
  - 安装并验证 `qemu-system-x86_64`、`pwsh`、`rustup`、nightly + `x86_64-unknown-none` target。
  - 顶层 `CMakeLists.txt` 改为自动发现 `llvm-objcopy/objcopy`，去除 Windows 固定路径。
  - 新增 `build.sh` / `test.sh` / `run_qemu.sh` / `init_env.sh`，并支持 `NOVA_BUILD_DIR=build-linux`，避免复用 Windows `build/` 缓存。
  - `build.ps1` / `test.ps1` / `run_qemu.ps1` 改为跨平台路径处理；`test.ps1` 去除 `fsutil` 依赖并在 Linux 上优先使用 KVM。
- 验证：
  - `cmake -S . -B build-linux -G Ninja -DKernelSel4Arch=x86_64 -DKernelPlatform=pc99` 通过。
  - `cmake --build build-linux` 通过。
  - `cargo check --workspace --target x86_64-unknown-none` 在 `SEL4_OUT_DIR=build-linux/kernel` / `SEL4_KERNEL_DIR=kernel/seL4` 下通过。
  - `NOVA_BUILD_DIR=build-linux ./test.sh` 已打通 QEMU + PowerShell 串口链路，并进入 `Booting seL4...`。
- 风险：
  - Linux 下集成测试仍在 `Booting seL4...` 后静默超时，说明剩余问题已从“工具链/脚本不通”收敛到“启动时引导/运行时路径未完全闭环”。
- 下一步：
  - 对比 Linux 新产物与既有 Windows 产物的引导差异，优先排查内核 32 位转换结果、`-initrd` 装载路径与 QEMU 启动参数差异。

- 完成 M2 第十一步：`sys_read` 切换为“优先 fs_server，失败回退本地”，保留权限与错误语义。
- 完成项目主线对齐：明确 NovaFS-first，重写 `HANDOVER.md` 与 `skills/NovaOS_Project/SKILL.md`。
- 验证：`cargo check` 通过；`NOVA_TEST_TIMEOUT_SECONDS=120 ./test.ps1` 通过。
- 风险：`fs_server` 仍为 shadow 内存态，持久语义尚未接管。

### 2026-03-19
- 完成 M2 控制面加固：`remote_fd` 引入并用于 open/close/read/write 语义对齐。
- 完成 runhello 稳定性修复（避免误触发 PID0 主套件）。
- 验证：120s 基线回归通过。

### 2026-03-17 ~ 2026-03-16
- 完成 M1 端点解耦、服务注册可观测、Name Service 版本回退。
- 稳定化处理：共享端点竞争问题回退，恢复可重复回归。

### 2026-03-15
- `serial_server` / `fs_server` 纳入 workspace 并打通启动链路。
- 服务注册 SDK 与服务观测命令（`services`/`svc`）接入。

## 5. 历史里程碑（归档摘要）

### 2026-01（核心能力奠基）
- 完成 FS syscall 主干（open/read/write/close）。
- 完成 NovaFS 核心增强：大文件、目录树、truncate/sparse、加密、rename、链接、权限。
- 完成关键稳定性修复：IPC buffer 读写偏移、DiskInode 对齐、回收链路一致性等。
- 完成自动化回归链路初版并持续迭代。

## 6. 当前风险与阻塞

1. `fs_server` 仍非持久化数据面，易被误判为“服务化已完成”。
2. 双路径（本地 + 远端）迁移期间存在语义漂移风险。
3. `latest_test_run.log` demand paging 高频日志会稀释真实异常信号。
4. durability 场景回归覆盖度仍不足（功能绿不等于耐久正确）。

## 7. 下一步执行计划（按优先级）

1. **补耐久性测试（P1）**  
新增 `sync + 重启 + 一致性校验` 场景，覆盖目录项/位图/inode 的一致性。

2. **推进 fs_server 持久数据面（P2）**  
先闭环持久 `open/read/write/close`，再扩展目录类操作，保持 fallback。

3. **分批迁移 Shell 文件命令（P3）**  
`cat/touch` -> `ls/mkdir/rm` -> `mv/ln/chmod/chown/truncate/encrypt/decrypt/sync`。

4. **日志分级治理（P0）**  
为 demand paging 引入节流/采样，提升故障可见性。

## 8. 进度更新模板（复制后填写）

```markdown
### YYYY-MM-DD: <标题>

- 改动范围：
  - ...
- 验证结果：
  - cargo check: pass/fail
  - test.ps1 (120s): pass/fail
  - 其他专项测试：...
- 风险与已知问题：
  - ...
- 下一步：
  - ...
```

---

维护说明：本文件由执行者在每次实质进展后实时更新；若缺失更新，按流程视为任务未闭环。

### 2026-03-22: fs_server 本地 NovaFS 数据面继续推进（进行中）

- 改动范围：
  - `fs_server` 继续向真实 NovaFS 数据面收敛，当前已直接挂载共享块设备上的 NovaFS，并本地处理 `open/read/write/close/unlink/rename/link/symlink`。
  - 修复 NovaFS 目录项持久化缺口：当目录项复用空槽时，`add_dir_entry()` 之前不会强制刷盘，导致 `fs_server` 新建文件后 RootServer 重挂载仍可能看不到；现已在目录块写回后显式 `sync()`。
  - 对称修复目录删除路径：`remove()` 在写回目录块后也补充 `sync()`，避免删除仅停留在本地 cache。
  - 新增 `fs_server` 侧 `FS_LABEL_REFRESH` 协议，用于过渡期显式刷新服务端的 NovaFS 视图。
  - RootServer shell 本地变更路径（`mkdir` / `encrypt` / `decrypt` / `writetest` / `echo > file`）在成功后会调用 `fs_server` refresh，作为“双 owner 迁移期”的一致性桥。
- 验证结果：
  - `NOVA_BUILD_DIR=build-linux ./build.sh`：pass。
  - Linux 集成回归实测已跨过之前的关键 blocker：`touch meta.txt` 之后执行 `ls meta.txt`，RootServer 已能再次看到 `/meta.txt`，说明目录项复用空槽时的落盘问题已修正。
  - 额外做了最小交互验证尝试，用 TCP serial 直连 QEMU 复现 `touch/encrypt/echo/cat`；由于系统启动阶段仍夹杂主测试进程输出，脚本化最小复现尚未稳定收口，不能作为本轮最终门禁结论。
- 风险与已知问题：
  - 当前已经从“`fs_server` 写后 RootServer 看不到”推进到更深一层的过渡期一致性问题：RootServer 本地写之后，`fs_server` 的本地 NovaFS cache 需要显式刷新才能观测到变化。
  - `FS_LABEL_REFRESH` 是迁移期桥接机制，不是最终形态；它说明当前系统仍处在双 owner 过渡态，而非单一真实 owner 完成态。
  - 本轮尚未重新拿到完整 `test.sh` 全绿结论，必须继续追后续阶段是否还有新的 mixed-path 可见性问题。
- 下一步：
  - 继续针对 `encrypt/decrypt + echo + cat` 这条 mixed-path 链路做专项验证，确认服务端 refresh 后透明读语义稳定。
  - 若仍有后续卡点，优先补更精确的阶段日志/专用回归，而不是退回到 RootServer 本地路径。
  - 在该桥接稳定后，再继续收缩 RootServer 本地 fallback，把更多写路径纳入服务端主数据面。

### 2026-03-22: echo 重定向切入 fs_server helper（进行中）

- 改动范围：
  - `user_app` 新增 `fs_write` helper 早期参数解析与执行分支，直接通过 `fs_server` 完成 `open + write + close`。
  - shell `echo > file` 现在优先走 `fs_write` helper，失败时再回退到 RootServer 本地 `write_file()`。
  - 这使 `touch/cat/rm/cp/mv/ln` 之外，再新增一条常见写路径默认优先经过 `fs_server`。
- 验证结果：
  - `NOVA_BUILD_DIR=build-linux ./build.sh`：pass。
  - `NOVA_TEST_TIMEOUT_SECONDS=180 ./test.sh`：fail，但当前失败表现为总时限耗尽，最近缓冲区停在 `mkdir /home` 阶段，并未直接暴露新的 `echo` 语义错误。
  - `NOVA_TEST_TIMEOUT_SECONDS=300 ./test.sh` 已继续推进验证，但本轮未等到完整全绿结论。
- 风险与已知问题：
  - 随着 helper 路径和日志增长，Linux 侧端到端回归节拍明显变慢，当前 180s 门禁预算已不再稳妥。
  - 这一步尚未独立证明 `encrypt/decrypt + fs_write + fs_cat` 已完全闭环，只能确认代码路径已接通且编译通过。
- 下一步：
  - 为 `fs_write` 补一条最小专用回归，绕开整套大门禁的时间预算干扰，先单点验证 mixed-path 是否闭环。
  - 再决定是继续降噪/提速，还是把 Linux 主门禁拆成“快速 smoke + 完整长回归”两档。

### 2026-03-20: Linux/KVM bring-up 调试收敛

- 改动范围：
  - Linux 测试脚本新增 `NOVA_QEMU_ACCEL` / `NOVA_QEMU_CPU` / `NOVA_QEMU_MACHINE` 覆盖能力，便于快速切换 KVM/TCG/机器参数。
  - 在 seL4 x86/x86_64 启动、调度、异常、syscall、APIC 定时器路径补充串口级 boot traces。
  - 追加一个诊断性实验：仅对 initial thread 首次进入用户态时清 `IF`，用于区分“首线程根本没跑”与“返回用户态后被 timer 抢占”。
- 验证结果：
  - Linux 默认 KVM 路径仍未通过完整门禁，但定位已明显收敛。
  - 已确认 `int 0x9d` 即 `pc99` 平台 `int_timer`，RootServer 首线程在返回用户态后会被 timer 持续抢占。
  - 已确认 RootServer 并非完全未执行：诊断实验下至少走到了首个 `SysDebugPutChar('[')`，说明 `rust_main` 已开始执行。
  - APIC 周期定时器校准值正常可见：`apic_khz=0x000f422c`，`tick_ms=0x2`，`initial_count=0x001e8458`，不是“initial count 被写成 0”的简单故障。
  - `TCG` 对照目前不可直接替代 Linux 默认路径：当前 CPU/内核配置依赖 `PCID`，而本机 QEMU TCG 不满足。
- 风险与已知问题：
  - 问题已从“工具链/脚本不兼容”收敛为“KVM 下 seL4 x86 timer/调度出口导致首线程饥饿”，但根修复尚未完成。
  - 诊断性 `IF` 修改仅用于定位，不可直接作为正式提交方案。
  - 当前工作树含较多调试日志，后续在根因明确后需要分层清理。
- 下一步：
  - 继续在 timer tick / scheduler chooseThread 路径补日志，确认 RootServer 为什么在首个 debug syscall 后没有被重新选回。
  - 优先验证是否存在 KVM 特定 APIC/irq 行为假设需要通过 QEMU 参数或 seL4 x86 timer 策略规避。
  - 在原因坐实后，决定是做 Linux 临时兼容模式，还是直接修 timer/调度根因。

### 2026-03-20: Linux/KVM 启动窗口兼容修复（进行中）

- 改动范围：
  - 显式固定 Linux 新构建目录的 seL4 配置为 `KernelVerificationBuild=OFF`、`KernelDebugBuild=ON`、`KernelPrinting=ON`，避免新环境默认落入 `verified + no printing`。
  - 将 initial thread 的 `IF` 清除从纯诊断实验收敛为兼容路径的一部分，并在 `restore_user_context()` 的 syscall 返回路径中自动恢复 `IF`。
  - 下调 syscall 级 boot trace 噪声，便于继续观察 RootServer 高层初始化阶段。
- 验证结果：
  - 已确认前一轮的 unknown-syscall/double-fault 并非 KVM 根因，而是 Linux 新建构建目录默认关闭 `CONFIG_PRINTING` 所致；修正配置后该问题消失。
  - 未清 `IF` 时，initial thread 会在 `iret` 回到 `0x2000000 (_start)` 前被 `int_timer(0x9d)` 持续抢占，RIP 长时间不前进。
  - 清 `IF` 后，RootServer 可稳定进入 `_start` 并开始连续执行 `SysDebugPutChar`，证明 ELF 装载、入口映射、用户态代码本身均正常。
  - 在新的兼容逻辑下，首个 syscall 后已能观察到 timer IRQ 重新出现，说明 `IF` 会被自动恢复，后续用户态执行重新具备可抢占性。
- 风险与已知问题：
  - 当前方案已明显改善 Linux/KVM 启动，但仍需进一步验证是否能稳定到达 Shell/完整测试门禁。
  - boot trace 仍偏多，待最终根因和兼容策略稳定后需要系统性清理。
- 下一步：
  - 继续用降噪后的日志验证 RootServer 是否可稳定进入更高层初始化里程碑（heap/vfs/shell）。
  - 若该兼容路径稳定，再决定是否保留为 Linux/KVM 默认方案，或继续追查更底层的 LAPIC 初始抢占行为。

### 2026-03-20: Linux test.ps1 全流程打通

- 改动范围：
  - `test.ps1` 的 Stage 35 改为累计命中 `services/svc/fsping/env/runhello` 标记，而不是依赖单个滚动缓冲区同时保留全部子串。
  - `test.ps1` 的串口滚动缓冲区从 4KB 提升到 32KB，并在超时时输出 Stage 35 部分命中状态，便于复盘。
  - 关闭 `c_handle_syscall` 高频 boot trace，并将 `scheduleTCB` 的“current thread became non-schedulable”串口日志节流到前几次，避免干扰 shell 交互和测试匹配。
- 验证结果：
  - Linux `NOVA_BUILD_DIR=build-linux NOVA_TEST_TIMEOUT_SECONDS=240 pwsh -File ./test.ps1` 已完整通过，外层命令退出码为 `0`。
  - 关键里程碑均在同一轮日志中出现：`[TEST] PS Headers Verified`、`[TEST] Service Registry + Env + runhello Verified`、`[TEST] Directory Rename Executed`、`[TEST] Sync Verified`、`All Tests Passed`。
  - 说明当前 Linux/KVM 路径下，RootServer 启动、Shell 交互、NovaFS 命令链、服务注册发现、`runhello`、目录重命名、加密/截断/sync 流程已能贯通。
- 风险与已知问题：
  - 仍保留了一部分 bring-up 期调试痕迹，后续合并前需要继续清理不再必要的 boot trace。
  - 当前验证集中在 `pc99 + x86_64 + KVM` 路径，`TCG` 和其他机器参数仍建议单独回归。
- 下一步：
  - 将剩余诊断日志继续分级收敛，保留真正有助于定位故障的低频信号。
  - 补一条 Linux 专用的构建/测试使用说明，避免后续 bring-up 重复踩脚本和环境变量约定。

### 2026-03-20: boot trace 分级参数化

- 改动范围：
  - 顶层 [CMakeLists.txt](/media/elowen/463E592E3E59186F/System/CMakeLists.txt) 新增 `NOVA_BOOT_TRACE_LEVEL` 以及 `BOOT/APIC/TRAP/RESTORE/SCHED` 五个域级别覆盖参数，并在配置输出中回显最终生效值。
  - Linux 包装脚本 [build.sh](/media/elowen/463E592E3E59186F/System/build.sh)、[test.sh](/media/elowen/463E592E3E59186F/System/test.sh)、[run_qemu.sh](/media/elowen/463E592E3E59186F/System/run_qemu.sh) 会自动把同名环境变量透传给 CMake。
  - seL4 x86 bring-up 期 trace 点改为按级别生效，而不是直接删除，覆盖启动、APIC、trap、restore、scheduler 五类日志。
- 验证结果：
  - 默认低噪级别下，Linux `./test.sh` 全流程通过，退出码 `0`。
  - `build-linux-trace-smoke` 配置验证了参数覆盖链路：`NOVA_BOOT_TRACE_LEVEL=0`、`NOVA_BOOT_TRACE_TRAP_LEVEL=3`、`NOVA_BOOT_TRACE_SCHED_LEVEL=2` 时，CMake 正确回显 `Trace Level: 0 (boot=0, apic=0, trap=3, restore=0, sched=2)`。
  - 默认级别日志中已不再出现大量 syscall/scheduler boot 噪声，串口输出以业务测试和少量必要诊断为主。
- 风险与已知问题：
  - 现阶段“Linux 全量通过”是指当前主支持路径：`x86_64 + pc99 + KVM + build-linux + test.ps1/test.sh` 已通过；并不等价于所有机器参数、所有 QEMU 加速模式和所有宿主发行版都已逐一穷尽验证。
  - NovaFS 自身仍带有较多业务调试输出，这一层不属于本次 boot trace 参数化范围。
- 下一步：
  - 如需进一步降噪，可继续把 NovaFS/RootServer 业务调试也纳入相同的分级控制体系。
  - 补 Linux 使用说明时同步列出推荐的 trace 级别组合，例如“日常回归”和“trap 深挖”两套模板。

### 2026-03-20: fs_server 切换为 persistent proxy

- 改动范围：
  - `services/fs_server/src/main.rs` 不再维护文件内容 shadow map，改为通过 `sys_open/sys_read/sys_file_write/sys_close` 代理到当前真实 NovaFS 后端，只保留 service-fd 到 local-fd 的映射。
  - `services/rootserver/src/process.rs` 为进程增加 `fs_forwarding_enabled` 标记。
  - `services/rootserver/src/main.rs` 对 `fs_server` 进程关闭 FS 转发，避免 `fs_server -> syscall -> RootServer -> fs_server` 的递归回环。
  - 同步更新 `HANDOVER.md`，明确架构现实已从“内存 shadow”变为“RootServer-backed persistent proxy”。
- 验证结果：
  - `cargo check --workspace --target x86_64-unknown-none` 通过。
  - Linux `NOVA_TEST_TIMEOUT_SECONDS=120 ./test.sh` 全流程通过，退出码 `0`。
  - 测试日志中 `PS Headers / services / fsping / runhello / Directory Rename / All Tests Passed` 均正常出现，说明主线回归未被这次架构推进打断。
- 风险与已知问题：
  - 当前 `fsping` 计数在既有门禁里仍可能是 `0`，因为 shell 文件命令尚未服务化，现有 120s 门禁还没有强制覆盖新的 persistent proxy 数据路径。
  - `fs_server` 现在具备持久语义，但仍不是直接块设备/NovaFS owner；RootServer 的本地 FS 权限和执行职责仍较重。
- 下一步：
  - 给门禁补一条真正命中 `fs_server` persistent proxy 的最小用例，避免“路径已改但自动化没覆盖”。
  - 在 persistent proxy 稳定的前提下，按计划推进第一批 shell 文件命令服务化（优先 `cat/touch`）。

### 2026-03-20: fs_server 直连门禁推进与当前 blocker

- 改动范围：
  - `test.ps1` Stage 35 改为以 `[FS_PROXY] PASS` 作为 `fs_server` 数据面 smoke 的核心判据，不再把 RootServer 观察到的 forwarding 计数当作唯一成功条件。
  - `services/rootserver/src/shell.rs` 在 `runhello` 生成的环境变量中追加 `NOVA_FS_SERVICE_EP=<slot>`，让用户态 smoke 可以直接调用 `fs.v1` endpoint。
  - `services/user_app/src/main.rs` 新增 `fs_proxy_smoke` 直连客户端：通过 `FS_LABEL_OPEN/WRITE/READ/CLOSE` 直接对 `fs_server` 发 IPC，不再经过 RootServer 同步转发链。
  - `services/rootserver/src/main.rs` 暂时关闭 RootServer 的同步 FS forward（`FS_SYNC_FORWARD_ENABLED=false`），避免 `RootServer -> fs_server -> RootServer` 的同步回调死锁。
  - `services/fs_server/src/main.rs` 已改成固定 fd 表与固定缓冲区，去掉 BTreeMap/Vec 依赖，先排除堆分配器引入的不确定性。
- 验证结果：
  - `cargo check --workspace --target x86_64-unknown-none` 通过。
  - Linux 主线回归仍能进入 Stage 35，服务列表、`svc serial`、环境变量传递、`runhello fs_proxy_smoke` 进程拉起都成功。
  - `runhello fs_proxy_smoke` 已确认拿到 `NOVA_FS_SERVICE_EP`，并且进入了直连 `fs_server` 的 smoke 起点。
- 当前 blocker：
  - 在直连 `fs_server` 的第一笔真实文件请求上，`fs_server` 触发：
    - `[KERNEL] Demand Paging(pid=3): Mapping 0x40000000 (IP: 0x40000000, Prefetch: true) for fault at 0x40000000`
    - `[KERNEL] Unhandled VM Fault at 0x0 (IP: 0x40000000). Terminating.`
  - 这说明当前阻塞点已经从“RootServer 同步转发死锁”收敛为“fs_server 自身在直连数据面首个请求中跳转/执行到了 0x40000000”，属于 `fs_server` 运行时/控制流问题，而不是 Linux 脚本或测试状态机问题。
- 风险与已知问题：
  - 目前不能再把 `fs_server` 误认为只是“协议壳”；它已经进入真实数据面 smoke 阶段，但直连路径还未稳定。
  - RootServer 同步 forward 现已显式关闭，后续若重新开启，必须先解决同步回调死锁问题。
- 下一步：
  - 继续定位 `fs_server` 为什么会在首个直连请求中把 `IP` 跳到 `0x40000000`。
  - 优先检查 `fs_server` 请求处理路径中的控制流破坏点，而不是再回头调 Linux/QEMU/test 脚本。

### 2026-03-21: 服务二进制统一改为非 PIE，fs_server 直连门禁打通

- 改动范围：
  - 新增工作区级 [`.cargo/config.toml`](/media/elowen/463E592E3E59186F/System/.cargo/config.toml)，统一为 `x86_64-unknown-none` 目标追加：
    - `-C link-arg=-no-pie`
    - `-C relocation-model=static`
  - 这样 `fs_server`、`serial_server` 与 `user_app` 一致，都会产出固定虚拟地址布局的 `EXEC` ELF，而不是 RootServer 当前加载器无法处理的 `DYN/PIE`。
  - `services/fs_server/src/main.rs` 保持 fixed-fd-table + fixed-buffer 的无堆请求路径，继续作为直连 smoke 的稳定服务端。
- 验证结果：
  - `readelf -lW target/x86_64-unknown-none/release/fs_server` 现在显示 `Elf file type is EXEC`，入口为 `0x20193e`。
  - `readelf -lW target/x86_64-unknown-none/release/serial_server` 现在也显示 `Elf file type is EXEC`。
  - Linux `./test.sh` 已重新完整通过，外层退出码 `0`。
  - Stage 35 关键里程碑重新打通：
    - `[TEST] PS Headers Verified`
    - `[SVC] fs ping ok (proto v1) open=0 read=0 write=0 close=0`
    - `[RUN] Process spawned successfully (PID 1).`
    - `[FS_PROXY] PASS`
    - `All Tests Passed`
- 根因结论：
  - 先前 `fs_server`/`serial_server` 启动即崩并不是协议逻辑本身，而是服务二进制被链成了 `DYN (PIE)`，导致 RootServer 的当前 ELF 加载路径在没有做 PIE relocation 的前提下把服务进程装到了错误的地址语义上。
  - `user_app` 之所以一直正常，是因为它原本就有自己的 `.cargo/config.toml` 强制 `-no-pie + relocation-model=static`。
- 风险与已知问题：
  - 这次修复依赖当前 RootServer 加载器“固定地址 ELF”假设，后续如果要支持 PIE/ASLR，需要单独扩展 loader，而不是撤回这份工作区级配置。
  - `fsping` 目前仍是非阻塞健康检查；真实服务数据面覆盖依赖 `[FS_PROXY] PASS` 这条直连 smoke。
- 下一步：
  - 在 `fs_server` 直连门禁稳定的前提下，继续推进 shell 文件命令的分批服务化。
  - 如需继续增强架构完成度，下一步应优先考虑 `cat/touch` 走直连服务端，而不是重新打开 RootServer 的同步 forward。

### 2026-03-21: 第一批 shell 文件命令服务化，cat/touch 接入 fs_server

- 改动范围：
  - `services/rootserver/src/shell.rs`
    - 为 shell 增加 `load_hello_binary/build_child_env/spawn_fs_helper` 辅助路径。
    - `cat` 与 `touch` 在 `fs.v1` 可用时，优先委托给 `/bin/hello fs_cat <path>` / `/bin/hello fs_touch <path>`。
    - 新增 `pending_prompt_pid`，让异步 helper 退出前暂缓 shell prompt，避免 `cat` 输出被新 prompt 提前打断。
  - `services/rootserver/src/main.rs`
    - 在 `sys_exit` 处理里调用 `shell.on_process_exit(pid)`，让 shell 能在 helper 退出后恢复 prompt。
  - `libs/libnova/src/fs_ipc.rs`
    - 补充通用 direct-call helper：`open_direct/read_direct/write_direct/close_direct`，让用户态服务客户端不再在各处重复拼 IPC 报文。
  - `services/user_app/src/main.rs`
    - 新增 `fs_touch` / `fs_cat` 子模式，作为 shell 文件命令的第一批服务化 helper。
    - 修复 child 模式解析：不再在启动后期二次遍历原始 `argv`，而是在 `_start` 早期一次性把模式和路径拷贝到固定缓冲，避免初始栈参数被后续栈帧覆盖。
  - `test.ps1`
    - 对几处 `touch` 后立刻串下一条命令的阶段适当放宽等待窗口，避免 helper 启动窗口被误判成失败。
- 根因与关键结论：
  - 这轮真正的 blocker 不是 `fs_server` 协议逻辑，而是 child helper 在第二次解析 `argv` 时读到了已被后续栈帧污染的初始参数区，导致命令模式分支无法稳定命中。
  - 一旦把 child 参数解析提前并改成固定缓冲保存，`shell -> helper -> fs_server -> RootServer(NovaFS)` 这条链路就稳定打通了。
- 验证结果：
  - Linux `./test.sh` 全流程通过，退出码 `0`。
  - 日志已确认第一批命令真实走到了服务端：
    - `[FS_CMD] touch begin /meta.txt`
    - `[FS_SERVER] open path=/meta.txt mode=1`
    - `[FS_CMD] touch ok /meta.txt`
    - `[FS_CMD] cat ok /link_dest.txt`
    - `[FS_PROXY] PASS`
    - `All Tests Passed`
  - 这说明当前主门禁已经不仅覆盖 `runhello fs_proxy_smoke`，也实际覆盖了 shell 侧 `cat/touch` 的服务化执行路径。
- 风险与已知问题：
  - 当前 `cat/touch` 仍通过用户态 helper 异步委托，不是“shell 线程直接同步 call fs_server”；这是有意为之，用来避开 `fs_server -> syscall -> RootServer` 期间的同步死锁风险。
  - 为缩短定位时间，这轮在 `user_app/fs_server` 保留了少量 `FS_CMD/FS_SERVER` 诊断日志；后续应考虑并入统一的分级日志控制，而不是长期裸打印。
- 下一步：
  - 继续按同样模式推进下一批 shell 文件命令服务化，优先评估 `cp/mv/rm` 中哪些适合先通过 helper 切到 `fs_server`。
  - 在命令面继续下沉的同时，逐步减少 RootServer 本地 VFS fallback 的覆盖范围。

### 2026-03-21: 下一批命令推进，cp 接入服务化，rm 完成协议准备

- 改动范围：
  - `libs/libnova/src/fs_ipc.rs`
    - 新增 `FS_LABEL_UNLINK` 与 `unlink_direct()`，补齐用户态对 `fs_server` 的删除请求能力。
  - `services/fs_server/src/main.rs`
    - 新增 `FS_LABEL_UNLINK` 处理，内部通过 `sys_unlink()` 代理到当前真实 NovaFS 后端。
  - `services/user_app/src/main.rs`
    - 新增 `fs_cp` helper：通过 `open/read/write/close` 在用户态完成文件复制。
    - 新增 `fs_rm` helper：通过 `unlink_direct()` 命中 `fs_server` 的删除路径。
    - child 早期参数解析已扩展到 `fs_cp/fs_rm`，继续保持“固定缓冲 + 无堆依赖”的模式。
  - `services/rootserver/src/shell.rs`
    - `cp` 已默认委托给 `/bin/hello fs_cp <src> <dest>`。
    - `rm` 的 shell 默认切换在本轮末尾暂时撤回，仍走 RootServer 本地路径；原因不是协议不通，而是当前测试里存在多处“同一阶段连续 cleanup 命令”模式，异步 helper 会与其节拍发生冲突。
  - `test.ps1`
    - 调整了部分 rename/symlink cleanup 阶段的等待窗口，避免把异步 helper 启动窗口误当成失败。
- 验证结果：
  - Linux `./build.sh` 通过。
  - Linux `./test.sh` 再次全流程通过，退出码 `0`。
  - 当前门禁继续稳定覆盖 `cat/touch` 服务化路径，并且没有因为本轮扩展把后续 `rename/service registry/truncate/sync` 阶段打回去。
- 真实状态说明：
  - `cp` 的服务化执行路径已经接入 shell，但当前主门禁尚未专门命中 `cp`。
  - `rm` 的 `fs_server` 协议、helper 和运行链都已经打通并通过局部日志验证，但 shell 默认仍先保留本地 `rm`，作为对现有测试节拍的稳定性保护。
- 下一步：
  - 给 `cp` 增加一条最小自动化覆盖，避免“实现已进代码但门禁没命中”。
  - 若要重新打开 shell 默认 `rm -> fs_server`，建议先把测试里的多命令 cleanup 段改成显式等待 helper 完成，再切换默认路径。

### 2026-03-21: shell 默认 rm 切到 fs_server，第一批命令服务化闭环

- 改动范围：
  - `services/rootserver/src/shell.rs`
    - shell 默认 `rm` 现已优先委托给 `/bin/hello fs_rm <path>`，只有在 helper 无法启动时才回落到 RootServer 本地 VFS 路径。
  - `test.ps1`
    - 新增 `Send-TestCommand` 辅助函数，统一封装串口命令发送与命令后等待窗口。
    - 所有 `rm` 测试发送点已切换到该辅助函数，默认给 helper 型删除命令更稳定的完成窗口，而不是散落的 `GetBytes + foreach + 200ms/1200ms`。
- 验证结果：
  - Linux `NOVA_BUILD_DIR=build-linux ./build.sh` 通过。
  - Linux `timeout 480s env NOVA_BUILD_DIR=build-linux NOVA_TEST_TIMEOUT_SECONDS=180 ./test.sh` 通过，退出码 `0`。
  - 日志确认当前主门禁已经真实命中：
    - 非空目录删除失败：`[KERNEL] sys_unlink: failed: Directory not empty`
    - helper 删除路径：`[FS_CMD] rm begin` / `[FS_CMD] rm ok`
    - 复制 helper：`[FS_CMD] cp ok`
    - 服务烟测：`[FS_PROXY] PASS`
    - 总门禁：`All Tests Passed`
- 当前状态：
  - 第一批 shell 文件命令里，`cat`、`touch`、`cp`、`rm` 已默认优先走 `fs_server` helper 路径。
  - Linux 主门禁继续全量通过，说明“命令服务化 + Linux 兼容主线”当前是同时成立的。
- 下一步：
  - 开始评估下一批命令，优先看 `mv` 是否适合沿同样模式继续下沉到服务侧。
  - 把当前 `FS_CMD/FS_SERVER` 诊断输出并入统一日志分级，减少长期裸打印。

### 2026-03-21: mv 服务化完成，rename 门禁已真实覆盖 helper 路径

- 改动范围：
  - `libs/libnova/src/fs_ipc.rs`
    - 新增 `FS_LABEL_RENAME` 与 `rename_direct()`，补齐用户态对 `fs_server` 的 rename 请求。
  - `services/fs_server/src/main.rs`
    - 新增 `FS_LABEL_RENAME` 处理，内部通过 `sys_rename()` 代理到当前真实 NovaFS 后端。
  - `services/user_app/src/main.rs`
    - 新增 `fs_mv` helper 与对应早期参数解析，避免 child 启动后再重扫原始 `argv`。
    - helper 成功时继续打印兼容旧门禁的 `Renamed '<src>' to '<dest>'`，同时附带 `[FS_CMD] mv ok` 诊断标记。
  - `services/rootserver/src/shell.rs`
    - shell 默认 `mv` 现已优先委托给 `/bin/hello fs_mv <src> <dest>`。
    - 目标是目录时，仍在 shell 侧先做“补最终文件名”的路径规范化，再交给 helper。
  - `test.ps1`
    - rename / symlink-rename 阶段的成功判据已扩展为兼容 helper 输出，不再依赖单一的字面串匹配。
- 验证结果：
  - Linux `NOVA_BUILD_DIR=build-linux ./build.sh` 通过。
  - Linux `timeout 480s env NOVA_BUILD_DIR=build-linux NOVA_TEST_TIMEOUT_SECONDS=180 ./test.sh` 通过，退出码 `0`。
  - 日志确认当前主门禁已经真实命中：
    - 文件重命名：`[FS_CMD] mv begin /old_name -> /new_name` 与 `[FS_SERVER] rename /old_name -> /new_name`
    - 符号链接重命名：`[FS_CMD] mv begin /link_old -> /link_new` 与 `[FS_SERVER] rename /link_old -> /link_new`
    - 其他已接入命令继续命中：`[FS_CMD] rm ok`、`[FS_CMD] cp ok`、`[FS_PROXY] PASS`
    - 总门禁：`All Tests Passed`
- 当前状态：
  - 第一批 shell 文件命令里，`cat`、`touch`、`cp`、`rm`、`mv` 已默认优先走 `fs_server` helper 路径。
  - Linux 主门禁继续全量通过，说明当前“命令服务化推进 + Linux 兼容主线”仍然保持闭环。
- 下一步：
  - 评估是否继续把 `ln` 相关能力也下沉到服务侧，或者开始收缩 RootServer 本地 VFS fallback。
  - 把当前 `FS_CMD/FS_SERVER` 诊断输出并入统一日志分级，减少长期裸打印。

### 2026-03-21: ln 服务化完成，hard link / symlink 创建已命中 fs_server

- 改动范围：
  - `libs/libnova/src/syscall.rs`
    - 新增 `sys_link()` 与 `sys_symlink()` 用户态 syscall 封装。
  - `services/rootserver/src/main.rs`
    - 新增 `sys_link` 处理分支，补齐 hard link 的 RootServer syscall 闭环。
  - `libs/libnova/src/fs_ipc.rs`
    - 新增 `FS_LABEL_LINK`、`FS_LABEL_SYMLINK`，以及 `link_direct()`、`symlink_direct()`。
  - `services/fs_server/src/main.rs`
    - 新增 `FS_LABEL_LINK` / `FS_LABEL_SYMLINK` 处理，内部分别代理到 `sys_link()` / `sys_symlink()`。
  - `services/user_app/src/main.rs`
    - 新增 `fs_link` / `fs_symlink` helper 与对应早期参数解析。
    - helper 成功时继续打印兼容旧门禁的 `Created hard link ...` / `Created symbolic link ...`，同时附带 `[FS_CMD] link ok` / `[FS_CMD] symlink ok`。
  - `services/rootserver/src/shell.rs`
    - shell 默认 `ln` 现已优先委托给 helper：
      - hard link: `/bin/hello fs_link <target> <link>`
      - symlink: `/bin/hello fs_symlink <target> <link>`
- 验证结果：
  - Linux `NOVA_BUILD_DIR=build-linux ./build.sh` 通过。
  - Linux `timeout 480s env NOVA_BUILD_DIR=build-linux NOVA_TEST_TIMEOUT_SECONDS=180 ./test.sh` 通过，退出码 `0`。
  - 日志确认当前主门禁已经真实命中：
    - hard link：`[FS_CMD] link begin` / `[FS_CMD] link ok`
    - symlink：`[FS_CMD] symlink begin /sym_link` / `[FS_CMD] symlink ok /sym_link`
    - symlink rename 链继续成立：`[FS_CMD] symlink ok /link_old` 后接 `[FS_CMD] mv ok /link_old`
    - 其他已接入命令继续命中：`[FS_CMD] rm ok`、`[FS_CMD] cp ok`、`[FS_PROXY] PASS`
    - 总门禁：`All Tests Passed`
- 当前状态：
  - shell 文件命令里，`cat`、`touch`、`cp`、`rm`、`mv`、`ln` 已默认优先走 `fs_server` helper 路径。
  - Linux 主门禁继续全量通过，说明当前“命令服务化推进 + Linux 兼容主线”仍然保持闭环。
- 下一步：
  - 开始系统性收缩 RootServer 本地 VFS fallback，明确哪些命令还必须留在本地。
  - 把当前 `FS_CMD/FS_SERVER` 诊断输出并入统一日志分级，减少长期裸打印。

### 2026-03-21: 通用 FS syscall 服务化推进受阻，确认 proxy 架构下的同步转发死锁边界

- 目标：
  - 尝试把普通用户进程的 `open/read/write/close` 主路径，也从“RootServer 本地执行”推进到“RootServer 同步转发到 fs_server”。
  - 这一步比 shell helper 更接近真正的微内核化，因为它触及的是通用 syscall 主路径，而不是命令面包装。
- 本轮动作：
  - 修正 `services/rootserver/src/services.rs` 中 `fsping` 观测，返回真实的 open/read/write/close 转发计数，而不是固定 0。
  - 在 `services/user_app/src/main.rs` 新增 `fs_syscall_smoke` 诊断模式：只走 `sys_open/sys_write/sys_read/sys_close`，不直连 `fs_server`。
  - 尝试开启 `services/rootserver/src/main.rs` 里的 `FS_SYNC_FORWARD_ENABLED`，并将该 smoke 接入 `test.ps1`，用于验证“普通 syscall 是否已走服务链路”。
- 发现的 blocker：
  - 该路线在当前架构下会死锁，不能直接打开。
  - 原因是：当前 `fs_server` 仍是 **syscall-backed proxy**。当 RootServer 的 syscall 处理线程同步 `call fs_server` 时，`fs_server` 又会同步 `call` 回 RootServer 的 syscall endpoint，请求真实 NovaFS 操作，形成同线程等待链。
  - 这不是简单 timing 问题，而是当前代理架构下的同步调用拓扑不成立。
- 结论：
  - `FS_SYNC_FORWARD_ENABLED` 必须继续保持关闭；本轮已恢复为关闭态，并在代码注释中明确标出死锁原因。
  - 在当前阶段，安全成立的路径仍然是：
    - shell / helper 直连 `fs_server`
    - `fs_server` 再通过 syscall 代理到 RootServer 本地 NovaFS
  - 如果要继续推进“通用 syscall 也走服务链路”，必须先满足以下其一：
    - `fs_server` 直接拥有 NovaFS/块设备真实数据面，不再回调 RootServer syscall
    - RootServer 引入可并发处理 syscall 的独立转发工作线程/架构，而不是当前单线程同步等待
- 验证状态：
  - 已将门禁恢复到稳定主线，Linux `./build.sh` 通过。
  - `fs_syscall_smoke` 诊断模式代码保留，可作为未来重新推进该方向时的最小验证器。
- 下一步建议：
  - 不再尝试直接打开 `FS_SYNC_FORWARD_ENABLED`。
  - 把精力转向更本质的两条路：
    - 让 `fs_server` 接管真实 NovaFS 数据面
    - 或设计 RootServer <-> fs_server 的异步/并发转发机制

### 2026-03-22: Linux 回归变慢诊断与测试效率优化（进行中）

- 诊断结论：
  - Linux 回归变慢不是单一原因，而是两个因素叠加：
    - 默认 boot/scheduler/interrupt trace 仍然过于吵，串口被大量调试输出占用。
    - `test.ps1` 仍沿用大量固定 `Start-Sleep` 和 prompt 驱动的状态机，导致在 `fs_server` 延后启动后容易把“服务未就绪”误判成“需要继续盲等”。
  - 额外确认了一个脚本层老问题：`StreamReader.Read()` 会阻塞，从而让 `NOVA_TEST_TIMEOUT_SECONDS` 不能准确生效，出现“看起来卡死但其实没有超时判定”的假象。
- 本轮动作：
  - 将 Linux 包装脚本的默认 trace 级别统一收敛为 `0`，并显式覆盖各域 trace，避免旧 `build-linux` cache 继续带着 noisy 配置运行。
  - 给 `test.sh`/`test.ps1` 增加可调参数：
    - `NOVA_TEST_SLEEP_SCALE`
    - `NOVA_TEST_CHAR_DELAY_MS`
    - `NOVA_TEST_DEFAULT_POST_DELAY_MS`
    - `NOVA_TEST_RM_POST_DELAY_MS`
    - `NOVA_TEST_POLL_DELAY_MS`
    - `NOVA_TEST_BULK_SEND`
    - `NOVA_TEST_STAGE_TIMING`
  - 为 `test.ps1` 增加阶段计时输出和串口读超时处理，让超时能精确定位到 stage，而不是无限挂住。
  - 将 `Process 0 exited -> mkdir /home` 的盲等 1 秒改成“等待 `fs_server` 真正 ready 再继续”，减少 deferred service bring-up 对门禁节拍的影响。
- 当前验证结果：
  - 优化后，门禁已能稳定越过过去最容易被 noisy trace 吃掉预算的前置阶段。
  - 60 秒专项回归现在会明确在 `Stage 4` 超时，而不是无限阻塞。
  - `Stage 4` 对应 `mkdir /home` 之后的大文件 `writetest big.bin 200` 路径，说明当前瓶颈已经收敛到“真正的长耗时操作/命令交互”，而不是前面的脚本噪声。
- 当前判断：
  - 这轮优化已经把“回归慢”的表层噪声压下去，并把问题缩小到一个明确阶段。
  - 但 Linux 快速门禁还没有重新恢复到全绿；目前最重的点仍是 stage 4 大文件写入路径。
- 下一步：
  - 继续验证 stage 4 是“命令未被 shell 消费”还是“大文件写入本身过慢”。
  - 如果确认只是回归效率问题，可把大文件写入量做成参数化，两档运行：
    - 快速 smoke：较小写入量
    - 完整回归：保留 200KB 压力路径

### 2026-03-22: 引入服务 readiness 状态，拆开“已注册”和“已就绪”

- 背景：
  - 之前 `services::register()` 只记录 endpoint，不区分服务只是“名字已占位”还是“已经真的可用”。
  - `test.ps1` 和 shell 某些路径只能靠日志与 sleep 猜服务时机，这和当前微内核化方向不匹配。
- 本轮动作：
  - 将 `services` registry 从 `name -> endpoint` 升级为 `name -> { endpoint, state }`，状态分为：
    - `bootstrapping`
    - `ready`
  - 新增 `lookup_ready()` / `lookup_latest_ready()`，让调用方可显式只拿 ready 服务。
  - 新增 `sys_service_set_ready`，由服务进程主动向 RootServer 上报 readiness。
  - `fs_server` 在挂载远端 NovaFS 成功后主动上报 `fs.v1` ready。
  - `serial_server` 在启动完成后也通过同一机制上报 `serial.v1` ready。
  - shell 的 `services` / `svc` 输出新增 state 展示；fs helper 注入和 refresh 桥仅使用 ready 的 `fs` endpoint。
  - `test.ps1` 的 deferred fs 阶段不再等“可能相关”的挂载日志，而是显式等 `Service 'fs.v1' marked ready`。
- 验证：
  - `./build.sh` 通过。
  - 60 秒 Linux 短回归中已观察到：
    - `[KERNEL] Service 'fs.v1' marked ready.`
    - `[FS_SERVER] service marked ready.`
    - 测试随后按 ready 信号推进到后续 stage。
- 当前结论：
  - “服务已注册”和“服务已就绪”现在已经在系统里有了正式区分。
  - 这一步先解决的是鲁棒性边界，不是完整性能闭环；当前快速门禁的下一瓶颈仍是 stage 4 大文件写入路径。

### 2026-03-22: 将 RootServer->fs_server 的同步 refresh 桥替换为 epoch 驱动的懒刷新

- 根因定位：
  - RootServer shell 在本地写路径成功后同步调用 `refresh_fs_service_view()`，而 `fs_server` 的 `refresh` 实现会回头通过 syscall 请求块设备信息和块读。
  - 由于 RootServer 发起这次同步 IPC 时自己正阻塞等待 `fs_server` 回复，`fs_server -> RootServer` 的 syscall 会形成结构性死锁，表现为：
    - `mkdir /home` 已打印成功
    - 但 prompt 不再回来
    - 后续测试命令不再被消费
- 本轮动作：
  - 为 RootServer 引入 `FS_VIEW_EPOCH`，本地写路径不再同步 refresh，而是仅 bump epoch。
  - 新增 `sys_fs_view_epoch`，让 `fs_server` 能查询当前 RootServer 视图版本。
  - `fs_server` 在 mount 后记录本地 epoch；对 `open/unlink/rename/link/symlink` 等路径在处理请求前比对 epoch，不一致时再懒刷新本地 NovaFS 视图。
  - shell 中原先的 `refresh_fs_service_view()` 已改为非阻塞的 dirty/epoch 标记。
- 后续定位补充：
  - 修复了一个二次问题：`fs_server` 如果在解析请求 payload 之前先做 `ensure_local_fs_fresh()`，内部 syscall 会覆盖当前 IPC buffer，导致 `unlink/rename/link/symlink` 的路径参数被污染。
  - 现在路径类请求会先把 payload 拷到本地，再判断是否需要 refresh。
- 测试脚本同步优化：
  - `Send-TestCommand` 改为只发送单个 `CR`，避免 RootServer 将 `CRLF` 识别成两次 `Enter`，减少双 prompt 和命令重入。
  - stage 2-5 改成“信号出现后进入 pending，再等待串口 quiet window 后发送下一条命令”，不再在同一块输出里一边读一边立即塞入后续命令。
- 当前验证结果：
  - `./build.sh` 持续通过。
  - Linux 短回归已多次稳定越过：
    - `mkdir /home`
    - `cd /home`
    - `writetest big.bin`
    - `ls`
  - 但全量 Linux 门禁仍未恢复为稳定通过，当前仍存在串口命令发送偶发被截断的抖动，具体表现在 stage 2/3/7 会随机重现。
- 当前判断：
  - 架构级死锁已经修掉，方向正确。
  - 剩余 blocker 已收敛为“串口输入/测试驱动节拍”问题，而不再是 `fs_server` refresh 设计本身。

### 2026-03-22: 收口 Linux 串口节拍与门禁判据，恢复 180s 主回归通过

- 根因定位：
  - RootServer 原先把串口 `LF` 也映射成 `Enter`，测试脚本若混入 `CRLF`，会造成重复回车和 prompt 噪声。
  - `test.ps1` 里虽然已经有统一的 `Send-TestCommand`，但很多阶段仍保留手写 `GetBytes(...\`r\`n)`，导致不同命令走了不同节拍策略。
  - 另外，Linux 快速模式把全局 `Start-Sleep` 做了缩放，连串口字符间隔和命令后等待也被一起压缩，直接导致 stage 2 出现 `mkdi` 这类“命令只回显前几个字符”的截断现象。
  - 后续继续跑通后又发现两处门禁判据落后于 helper 输出：
    - stage 29 只接受旧式 `File not found`
    - stage 35 的 `cpSeedWrite` 只接受旧式 `Written to /cp_src.txt`
- 本轮动作：
  - RootServer 串口输入只把 `CR` 映射为 `Enter`，明确忽略 `LF`。
  - `test.ps1` 中剩余的裸 `CRLF` 发送全部改为 `Send-TestCommand`，统一串口发送路径。
  - 引入 `Invoke-TestIoSleepMs`，让字符间隔与命令后等待使用“未缩放”的原始毫秒值，不再被 Linux 快速模式误伤。
  - 将 Linux 默认 `NOVA_TEST_CHAR_DELAY_MS` 从 `2` 提升到 `4`，给串口一条更稳的默认节拍。
  - stage 29 兼容 helper 风格的 `open failed ... old_name`。
  - stage 35 的 `cpSeedWrite` 改为同时接受：
    - `Written to ... cp_src.txt`
    - `[FS_CMD] write ok ... cp_src.txt`
- 验证：
  - `pwsh` 语法解析通过。
  - `./build.sh` 通过。
  - `timeout 320s env NOVA_BUILD_DIR=build-linux NOVA_TEST_TIMEOUT_SECONDS=180 ./test.sh` 通过，最终出现：
    - `All Tests Passed`
  - 本轮可确认：
    - Linux 串口早期命令截断已明显收敛
    - `cat/touch/rm/cp/mv/ln/fs_proxy_smoke` 相关服务化路径在 180s 主回归中持续命中
- 当前结论：
  - Linux 主回归现在已经重新回到通过状态。
  - 当前主要收益不只是“把超时调大”，而是把串口输入链和门禁状态机重新对齐到了更一致、更鲁棒的模型上。

### 2026-03-22: 确认 120s Linux 快速回归也已恢复通过

- 本轮目标：
  - 在 180s 主回归恢复后，进一步验证 Linux 快速门禁是否也已经真实恢复，而不是继续依赖更宽的超时窗口。
- 验证动作：
  - 执行：
    - `timeout 240s env NOVA_BUILD_DIR=build-linux NOVA_TEST_TIMEOUT_SECONDS=120 NOVA_TEST_STAGE_TIMING=1 ./test.sh`
- 验证结果：
  - 快速档已通过，命令退出码为 `0`。
  - 从阶段计时看，完整回归大约在 30 多秒内跑完，远低于 120 秒预算。
  - 说明前一轮修复的收益不只是“让 180s 能过”，而是确实把 Linux 串口交互和门禁判据恢复到了足够稳定的状态。
- 额外观察：
  - Linux 包装脚本 [test.sh](/media/elowen/463E592E3E59186F/System/test.sh) 当前默认仍导出 `NOVA_TEST_CHAR_DELAY_MS=1`，并未使用 `test.ps1` 中更保守的 `4ms` 默认值。
  - 在当前代码状态下，这个 `1ms` 包装层默认值已经足够让 120s 快速档通过，因此暂不额外放慢默认节拍，避免无意义增加回归时间。
- 当前结论：
  - Linux 侧现在可以更准确地分成两档：
    - 快速档：`120s`，已通过
    - 主回归：`180s`，已通过

### 2026-03-22: 继续收缩 RootServer 本地 fallback，新增 `mkdir/truncate/chmod/chown/sync` 服务化路径

- 本轮目标：
  - 沿着既有 `cat/touch/rm/cp/mv/ln/echo` 的 helper-first 路线，继续把一批仍由 RootServer 本地执行的 shell 文件命令下沉到 `fs_server`。
- 本轮动作：
  - `libnova::fs_ipc` 新增 `fs.v1` IPC：
    - `mkdir`
    - `truncate`
    - `chmod`
    - `chown`
    - `sync`
  - `fs_server` 新增对应本地 NovaFS 处理逻辑：
    - `local_mkdir`
    - `local_truncate`
    - `local_chmod`
    - `local_chown`
    - `local_sync`
  - `/bin/hello` 新增 helper 模式：
    - `fs_mkdir`
    - `fs_truncate`
    - `fs_chmod`
    - `fs_chown`
    - `fs_sync`
  - shell 侧改成 helper 优先、RootServer 本地 fallback 保底：
    - `mkdir`
    - `truncate`
    - `chmod`
    - `chown`
    - `sync`
- 中途定位出的真实问题：
  - `truncate` 实际已经通过 `fs_server` 执行成功，但 `test.ps1` stage 42/44/46 仍只接受旧的本地 shell 输出，helper 输出里的控制字符会导致旧 regex 假失配，从而卡成 timeout。
- 修复：
  - `test.ps1` 的 truncate 阶段判据改成同时接受：
    - 旧式 `Truncated '...' to ... bytes`
    - helper 成功标记 `[FS_CMD] truncate ok`
  - 由于后续仍有 `ls`/`cat` 尺寸与内容校验，这个调整属于门禁兼容，不是放松真实验证强度。
- 验证：
  - `NOVA_BUILD_DIR=build-linux ./build.sh` 通过。
  - `timeout 240s env NOVA_BUILD_DIR=build-linux NOVA_TEST_TIMEOUT_SECONDS=120 ./test.sh` 通过。
  - 最终日志出现：
    - `Extend Verified`
    - `Sparse Size Verified`
    - `Sync Verified`
    - `All Tests Passed`
- 当前意义：
  - 微内核化迁移已经不再只覆盖常见读写/链接命令。
  - `truncate` 与 `sync` 这类更偏元数据/持久化语义的路径，也已经进入 `fs_server` helper 主链并受 Linux 快速门禁覆盖。

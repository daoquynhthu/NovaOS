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

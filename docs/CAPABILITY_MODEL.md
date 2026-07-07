[//]: # (ARCH-ID: ARCH-CAPABILITY-MODEL-001 | NovaOS 权能模型)
[//]: # (引用: ARCH-NOVAOS-PROPOSAL-001 Section 2 — 纯粹的能力导向安全)

# NovaOS 权能模型

> **定位**: 定义 NovaOS 当前已实现的权能（Capability）分配模型，涵盖 RootServer、fs_server、serial_server、user_app 的 CSpace 条目清单。  
> **状态**: 草案 — 反映当前代码实现（2026-07-07），待 Phase 4 能力隔离时修订。  
> **参考**: `ARCH-NOVAOS-PROPOSAL-001`（能力导向安全原则）、`libs/libnova/src/cap.rs`（CNode 操作）、`libs/libnova/src/allocator.rs`（SlotAllocator）。

---

## 1. seL4 能力类型

NovaOS 使用 seL4 提供的能力类型：

| 能力类型 | seL4 常量 | 用途 |
|----------|-----------|------|
| Untyped | `seL4_UntypedObject` | 原始物理内存，可 retype 为其他对象 |
| TCB | `seL4_TCBObject` | 线程控制块，表示一个执行上下文 |
| CNode | `seL4_CNodeObject` | 能力空间节点，容纳 2^n 个能力槽 |
| VSpace (Page Table) | `seL4_X86_PageTableObject` | x86_64 页表，管理虚拟地址空间 |
| Frame (4K Page) | `seL4_X86_4K` | 4K 物理页，映射到 VSpace |
| Endpoint | `seL4_EndpointObject` | IPC 端点，用于进程间通信 |
| IRQ Control | `seL4_IRQControl` | 中断控制权能 |
| IRQ Handler | `seL4_IRQHandler` | 具体中断源的处理权能 |
| Scheduling Context | `seL4_SchedContextObject` | 调度上下文，控制时间预算 |
| I/O Port | `seL4_X86_IOPort` | x86 I/O 端口访问权能 |

---

## 2. CSpace 结构与容量

- 初始 CNode 大小：2^12 = 4096 个槽（`MAX_CSPACE_SLOTS`）。
- 初始 CNode 位于槽 0（`seL4_CapInitThreadCNode`）。
- 所有进程共享根 CNode（Phase 4 计划改为每个进程独立派生 CSpace）。
- 槽分配由 `SlotAllocator`（bitmap）管理，起始偏移由 `seL4_BootInfo.empty.start` / `.end` 确定。

---

## 3. RootServer CSpace 条目清单

RootServer 是初始用户态进程（PID 0），持有以下能力：

| 槽范围 | 能力 | 来源 | 说明 |
|--------|------|------|------|
| 0 | 初始 CNode | 内核 | `seL4_CapInitThreadCNode` — 自身 CSpace 根 |
| 1 | 初始 TCB | 内核 | `seL4_CapInitThreadTCB` — RootServer 的线程控制块 |
| 2 | 初始 VSpace | 内核 | `seL4_CapInitThreadVSpace` — 根页目录 |
| 3 | 初始 ASID 池 | 内核 | `seL4_CapInitThreadASIDPool` — 地址空间 ID |
| 4 | 初始 IPC 缓冲区帧 | 内核 | 映射 `seL4_IPCBuffer` 到固定虚拟地址 |
| 5+ | 空闲槽 | SlotAllocator | 由 `boot_info.empty` 范围确定，动态分配 |

动态分配的能力包括：
- 从 Untyped retype 得到的 Frame、Endpoint、TCB、CNode、VSpace 等对象。
- 用户进程的 IPC 端点（badge = 100 + pid）。
- 共享内存区域。

### RootServer 持有的重要能力

| 能力 | 槽（示例） | 说明 |
|------|------------|------|
| Syscall endpoint | 动态分配 | 用户进程通过此端点发起 syscall（badge = pid 标识发送者） |
| fs_server IPC endpoint | 动态分配 | 用于向 fs_server 转发请求（`try_forward_fs_call`） |
| Block device IRQ handler | 动态分配 | ATA PIO IRQ 处理 |
| Serial IRQ handler | 动态分配 | 串口 IRQ 处理 |
| ATA command registers | 固定 PIO 端口 | I/O 端口能力 |
| RootServer 自身 frame 映射 | 动态分配 | 代码/数据/堆栈页面 |

---

## 4. 进程 CSpace 条目清单

通过 `sys_spawn`（label 8）创建的进程（PID > 0）：

| 能力 | 分配方式 | 说明 |
|------|----------|------|
| Syscall endpoint | 动态分配，badge = 100 + pid | 进程通过此端点向 RootServer 发起 syscall |
| TCB | `UntypedAllocator::allocate` retype | 进程的线程控制块 |
| CNode（派生） | `UntypedAllocator::allocate` retype | 子进程的专用 CNode（当前每进程一个派生 CNode） |
| VSpace | `UntypedAllocator::allocate` retype | 子进程的页目录 |
| IPC buffer frame | `UntypedAllocator::allocate` retype | 映射到固定地址 `0x3000_0000` |
| Code/data pages | 动态映射 | ELF 加载 + 堆栈 |

**Fork 行为**（`sys_fork`，label 14）：
- 子进程复制父进程的 VSpace（页表复制）和 CSpace（能力槽复制）。
- 子进程获得独立的 TCB 和派生 CNode。
- fd 表共享（同文件描述符指向同一已打开 inode）。

---

## 5. fs_server CSpace

fs_server 通过 `sys_spawn` 启动，作为独立用户态进程（PID 通常为 2-3）。

| 能力 | 分配方式 | 说明 |
|------|----------|------|
| Syscall endpoint | slot allocator | RootServer syscall 通信 |
| 自身 IPC endpoint | slot allocator | 注册为 `fs.v1`，客户端直接调用 |
| Block device endpoint | 动态分配 | 向 RootServer 转发块设备请求 |
| NovaFS inode 操作 | 无直接持有 | 当前通过 RootServer syscall 间接操作（`sys_block_*`） |
| Shared memory | SlotAllocator | 与 RootServer 共享块设备数据 |

**架构限制**：fs_server 当前为"持久代理"模式，**不直接持有** 块设备能力和 NovaFS 实例。真正的数据面仍由 RootServer 持有（`main.rs:65: FS_SYNC_FORWARD_ENABLED=false`）。

---

## 6. serial_server CSpace

serial_server 是最简服务（~45 行），PID 通常为 1。

| 能力 | 分配方式 | 说明 |
|------|----------|------|
| Syscall endpoint | slot allocator | RootServer syscall 通信 |
| 自身 IPC endpoint | slot allocator | 注册为 `serial.v1` |

无实际串口 I/O 能力（未实现串口能力转发）。

---

## 7. user_app CSpace

user_app（`/bin/hello`）是多模式 binary，PID 0 模式下运行测试套件，子模式下运行 FS helper。

| 能力 | 分配方式 | 说明 |
|------|----------|------|
| Syscall endpoint | slot allocator | RootServer syscall 通信 |
| fs_server IPC endpoint | 从进程参数中接收 | 直接调用 fs_server 的 `fs.v1` endpoint |

user_app 不直接持有块设备能力或异常处理能力。

---

## 8. 权能访问控制

### 8.1 能力权限位

libnova 使用 seL4 标准权限掩码（`seL4_CapRights`）：

| 位 | 用途 | 枚举 |
|----|------|------|
| 1 | 允许读 | `cap_rights_new(false, true, true, true)` |
| 2 | 允许写 | |
| 3 | 允许授权 | |
| 4 | 允许派生 | |

**当前使用**：`cap_rights_new(false, true, true, true)` — 读、写、授权、派生全部启用。

### 8.2 最小权限原则现状

| 服务 | 当前权限 | 应收缩为 | 阻碍 |
|------|----------|----------|------|
| RootServer | 全能力 | 调度管理器 | 当前承担全角色（调度 + FS + shell + 服务编排） |
| fs_server | 无直接能力 | 块设备 + NovaFS | `FS_SYNC_FORWARD_ENABLED=false` 架构死锁 |
| serial_server | 无直接能力 | 串口 I/O 端口 | 无实际 I/O 能力转发 |
| user_app | 仅 fs_server IPC + syscall | 仅必要 IPC | 需 Phase 4 IPC 入口校验 |

---

## 9. 权能回收（Revocation）

- **显式释放**：进程退出时 `Process::terminate` 回收所有分配的能力槽（slot_allocator 标记空闲）。
- **帧回收**：`FrameAllocator` 维护回收池 → `free_frames: Vec<seL4_CPtr>`，进程退出时 frame 返回回收池。
- **未实现**：seL4 的 `CNode_Revoke` 级联撤销机制（目前无权能派生树追踪）。

---

## 10. 未来计划（Phase 4）

| 项 | 计划 |
|----|------|
| 独立 CSpace | 每个进程获得独立派生 CNode，不再共享根 CNode |
| 能力隔离 | fs_server 直接持有块设备 + NovaFS，RootServer 降权为编排角色 |
| IPC 入口校验 | 统一检查消息长度、能力索引范围、权限位 |
| 派生树追踪 | 建立权能派生链，支持级联撤销 |

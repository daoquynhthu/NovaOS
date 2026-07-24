[//]: # (ARCH-ID: ARCH-CAPABILITY-MODEL-001 | NovaOS 权能模型)
[//]: # (引用: ARCH-NOVAOS-PROPOSAL-001 Section 2 — 纯粹的能力导向安全)

# NovaOS 权能模型

> **定位**: 定义 NovaOS 当前已实现的权能（Capability）分配模型，涵盖 RootServer、fs_server、serial_server、user_app 的 CSpace 条目清单。  
> **状态**: 草案 — 反映当前代码实现（2026-07-09），Phase 4 能力隔离完成，独立 CNode + ATA 直接持有已落地。  
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

fs_server 通过 `sys_spawn` 启动，作为独立用户态进程（PID 通常为 2-3）。P4.2 已为其安装 ATA I/O 端口能力，P4.3 解除死锁后 fs_server 直接持有块设备。

| 能力 | 分配方式 | 说明 |
|------|----------|------|
| Syscall endpoint | slot allocator | RootServer syscall 通信 |
| 自身 IPC endpoint | slot allocator | 注册为 `fs.v1`，客户端直接调用 |
| ATA I/O 端口 (CMD) | 安装在独立 CNode slot 1 | `port_io::outb`/`inb` 直接操作 ATA 命令寄存器 |
| ATA I/O 端口 (DATA) | 安装在独立 CNode slot 2 | `port_io::inw` 直接读取 ATA 数据端口 |
| NovaFS inode 操作 | fs_server 内部持有 | 使用 `AtaBlockDevice` 在本地执行 |
| Shared memory | SlotAllocator | 与 RootServer 共享块设备数据（备选） |

**架构状态（P4.3 后）**：fs_server 直接持有块设备能力（ATA I/O 端口），本地运行 NovaFS 实例，不再向 RootServer 转发 I/O。`RemoteBlockDevice` 作为 ATA 能力不可用时的回退路径（`cspace_cap == 0` 根 CNode fallback 场景）。

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

## 10. 独立 CSpace 设计（Phase 4.5）

### 10.1 动机

当前所有进程共享 RootServer 的根 CNode（slot 0）。这意味着：
- 一个进程可以意外释放另一个进程的能力（如果知道 slot 索引）。
- 进程退出后 slot 回收可能影响其他进程的能力映射。
- RootServer 的 CSpace 槽位可能被耗尽（4096 个槽 — 其中约 2000+ 已用于运行中进程）。

### 10.2 设计

每个进程在创建时获得一个**独立派生 2 级 CNode**：

```
Root CNode (size=12, 4096 槽)
  ├── [0..N-1] RootServer 内部能力
  ├── [slot_X] 子进程 1 的 CNode (2^8 = 256 槽)
  │   ├── [0] Syscall endpoint
  │   ├── [1] TCB
  │   ├── [2] VSpace
  │   ├── [3] IPC buffer frame
  │   ├── [4..127] 已映射帧
  │   └── [128..255] 空闲槽
  ├── [slot_Y] 子进程 2 的 CNode
  │   └── ...
  └── ...
```

### 10.3 条目布局

每个独立 CNode 的槽布局（256 槽 = 2^8）：

| 槽 | 能力 | 说明 |
|----|------|------|
| 0 | Syscall endpoint (badged) | 回调 RootServer |
| 1 | ATA I/O 端口 (CMD) | fs_server 直接操作 ATA 命令寄存器（仅 fs_server 使用） |
| 2 | ATA I/O 端口 (DATA) | fs_server 直接读取 ATA 数据端口（仅 fs_server 使用） |
| 3 | TCB | 自身线程控制块 |
| 4 | VSpace (Page Table) | 自身页目录 |
| 5 | IPC buffer frame | 映射到 `0x3000_0000` |
| 6–9 | 保留（前 4K 页） | ELF 加载 |
| 10–127 | 动态帧映射 | mmap / heap / stack |
| 128–255 | 空闲槽 | 可动态分配 |

> 注：非 fs_server 进程的 slot 1-2 用途可能不同（如 serial_server 可复用为串口 I/O 端口）。当 `cspace_cap == 0`（根 CNode fallback）时，slot 布局不适用，进程共享根 CNode。

### 10.4 创建流程

```
Process::spawn:
  1. 从 UntypedAllocator 分配一个新的 CNode (2^8 槽)
  2. 将新 CNode 安装到 RootServer 的 CNode (slot = slot_allocator.alloc())
  3. 在新 CNode 中创建条目: Endpoint, TCB, VSpace, IPC buffer
  4. 子进程的门禁 cptr = 派生 CNode 的 slot 编号
```

### 10.5 API 模型

`libnova::cap::DerivedCNode` 封装子进程的 CNode：

```rust
pub struct DerivedCNode {
    root_cnode: CNode,     // RootServer 的根 CNode
    cnode_cptr: seL4_CPtr, // 子进程 CNode 在根 CNode 中的 slot
    slot_bits: u8,         // 子进程 CNode 的大小位数 (8 → 256 槽)
}
```

方法：
- `new(root, cptr, slot_bits)` — 创建包装
- `install(src_root, src_index, dest_slot, rights)` — 从指定源复制能力到派生 CNode
- `list_installed()` — 遍历已安装的能力条目（仅文档，非功能）

---

## 11. 修订记录

| 日期 | 版本 | 变更 |
|------|------|------|
| 2026-07-09 | 1.1 | §5 更新为 fs_server 直接持有块设备；§10.3 slot 布局添加 ATA 端口 slot 1-2、TCB/VSpace/IPC buffer 顺延；添加 fallback 说明 |

## 12. 未来计划（Phase 4 剩余）

| 项 | 计划 |
|----|------|
| 能力隔离 | fs_server 直接持有块设备 + NovaFS，RootServer 降权为编排角色 |
| IPC 入口校验 | 统一检查消息长度、能力索引范围、权限位 |
| 派生树追踪 | 建立权能派生链，支持级联撤销 |
| 独立 CSpace 实现 | 将 10.2 的设计落实到 `Process::spawn` 中 |

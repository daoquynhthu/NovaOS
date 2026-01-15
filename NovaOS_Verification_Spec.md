# NovaOS 形式化验证规格说明书 (Verification Spec)

本文档定义了 NovaOS 关键组件的形式化验证目标、不变量 (Invariants) 和安全属性。

## 1. 内存管理验证 (Memory Management)

### 1.1 CSpace 分配器 (SlotAllocator)
**目标**: 确保 CNode 槽位分配的正确性和唯一性。

**状态模型**:
- `start`: 初始空闲起始索引
- `end`: 初始空闲结束索引
- `bitmap`: 位图，长度 `N` (N=4096)

**不变量 (Invariants)**:
1.  **范围合法性**: `start <= end <= MAX_SLOTS`.
2.  **分配唯一性**: 对于任意索引 `i`, 如果 `bitmap[i] == 1`，则该槽位被视为 "已分配"，不能再次被分配，直到被释放。
3.  **初始状态**: 在初始化后，所有 `i < start` 和 `i >= end` 的槽位必须标记为已分配 (`bitmap[i] == 1`)。
4.  **操作后置条件**:
    - `alloc()`: 返回 `Ok(slot)` 蕴含 `old_bitmap[slot] == 0 && new_bitmap[slot] == 1`。
    - `free(slot)`: 蕴含 `new_bitmap[slot] == 0`。

### 1.2 物理内存分配器 (UntypedAllocator)
**目标**: 确保物理内存资源的互斥访问和正确类型转换。

**状态模型**:
- `untyped_list`: 系统提供的 Untyped Capability 列表
- `last_used`: 上次使用的索引

**不变量 (Invariants)**:
1.  **非重叠分配**: 任意两个通过 `allocate` 返回的 Capability 指向的物理内存区域不得重叠（除非显式共享，但在 RootServer 初始阶段应保证隔离）。
2.  **类型安全**: `Retype` 操作必须符合 seL4 内核的类型转换规则（如不能从 Device Untyped 创建 RAM 对象）。
3.  **资源守恒**: 分配出的对象总大小 <= 原始 Untyped 总大小。

## 2. 进程管理验证 (Process Management)

### 2.1 进程控制块 (Process/TCB)
**目标**: 确保进程配置的原子性和安全性。

**不变量 (Invariants)**:
1.  **CSpace 绑定**: 每个活跃 TCB 必须绑定有效的 CSpace Root。
2.  **VSpace 绑定**: 每个活跃 TCB 必须绑定有效的 VSpace Root (PML4)。
3.  **IPC 缓冲区**: 如果配置了 IPC Buffer，其虚拟地址必须在 VSpace 中有效映射。

## 3. IPC 通信验证 (Inter-Process Communication)

### 3.1 Badge 身份认证
**目标**: 确保服务端能够通过 Badge 准确识别调用者。

**安全属性 (Security Properties)**:
1.  **不可伪造性**: Client 无法自行修改 Endpoint 上的 Badge。
2.  **唯一性**: 服务端接收到的 Badge 必须与 Mint 时赋予该 Client 的 Badge 一致。
3.  **完整性**: IPC 消息内容在传递过程中不被篡改（由内核保证）。

**形式化模型 (Abstract Model)**:
```tla
VARIABLE messages

TypeOK == messages \in [Client -> Server]

(* Client c sends m to Server s with badge b *)
Send(c, s, m, b) == 
    /\ CanSend(c, s)
    /\ messages' = messages \cup {<<c, s, m, b>>}

(* Server s receives m from c with badge b *)
Receive(s) ==
    \E c, m, b:
        /\ <<c, s, m, b>> \in messages
        /\ CheckBadge(s, c, b) (* Must match minted badge *)
```

## 4. 验证计划 (Verification Plan)

### 阶段 1: 运行时断言 (Runtime Assertions)
- 在 Rust 代码中引入 `debug_assert!` 检查上述不变量。
- 在关键状态变更前后验证 bitmap 一致性。

### 阶段 2: 模型检测 (Model Checking)
- 使用 TLA+ 对 IPC 协议进行建模，验证死锁自由 (Deadlock Freedom) 和 活性 (Liveness)。
- 验证 Badge 传递机制的安全性。

### 阶段 3: 代码级验证 (Code Verification)
- 探索使用 Verus 或 Kani (Rust 模型检测器) 对 `SlotAllocator` 进行形式化证明。

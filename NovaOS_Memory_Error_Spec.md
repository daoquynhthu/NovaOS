# NovaOS 内存模型与错误传播规范

## 1. 内存模型 (Memory Model)

NovaOS 的内存管理遵循 seL4 的 `Untyped` 资源模型，但在用户态进行了抽象。

### 1.1 分层分配
1.  **Untyped Pool (RootServer)**：掌握所有物理内存。
2.  **Memory Server (MemSrv)**：从 RootServer 获取大块 Untyped 内存，负责将其划分为 `Frames` 并在不同进程间分配。
3.  **Local Allocator**：每个进程内部的 `heap` 分配器，通过向 MemSrv 请求新的 Frame 来扩展空间。

### 1.2 共享内存 (Shared Memory)
- **Grant 机制**：进程 A 可以将其拥有的某个 Frame 的权能“授予”进程 B。
- **Zero-copy**：异步 I/O 环形缓冲区建立在 A 和 B 共享的 Frame 之上。

## 2. 错误传播机制 (Error Propagation)

在微内核架构中，错误可能跨越多个服务边界。

### 2.1 递归错误类型 (Recursive Error Types)
每个服务定义的错误码应包含“来源”信息。
```rust
pub enum NovaError {
    Local(LocalError),          // 本地逻辑错误
    Service(ServiceId, u32),    // 远程服务返回的错误码
    Kernel(seL4_Error),         // 内核级错误
    Transport(IPCError),        // 通信链路错误
}
```

### 2.2 故障恢复 (Fault Recovery)
- **监督者模式 (Supervisor Pattern)**：核心服务（如 MemSrv）由 RootServer 监督。如果崩溃，RootServer 负责重启并恢复其关键状态（从 CapStore 重新同步）。
- **死信通知**：如果一个进程持有的 Endpoint 权能对应的服务端已崩溃，内核会发送 `seL4_Fault_IPC` 通知客户端。

## 3. 资源撤销 (Revocation)
- **级联撤销**：利用 seL4 的 `CNode_Revoke` 机制。撤销父权能会自动使所有派生的子权能失效。
- **引用计数**：CapStore 维护权能的引用计数，仅当最后一个引用消失时才回收底层 Untyped 内存。

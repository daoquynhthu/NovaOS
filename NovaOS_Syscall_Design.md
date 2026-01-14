# NovaOS 原生系统调用接口设计 (Syscall Design)

## 1. 核心哲学：权能即一切 (Capabilities are Everything)
NovaOS 摒弃了 POSIX 的全局资源视图。所有的系统调用不再操作“路径”或“全局 ID”，而是操作“权能句柄 (Capability Handles)”。

## 2. 系统调用模型：同步与异步平衡

NovaOS 不再盲目追求全异步。我们根据操作的性质选择最合适的通信方式：

### 2.1 同步微调用 (Synchronous Micro-calls)
对于延迟极其敏感的控制流（如查询权能状态、简单的命名服务查找），直接映射到 `seL4_Call`。
- **优点**：零调度开销，直接上下文切换。
- **场景**：元数据操作、权能派生、权限验证。

### 2.2 异步批处理队列 (Asynchronous Batch Queues)
对于吞吐量敏感的操作（如磁盘 I/O、网卡 DMA），采用环形缓冲区机制。
- **优点**：减少内核进入次数，支持零拷贝大数据传输。
- **场景**：大文件读写、网络数据包流。

## 3. 核心 API 示例 (Rust 伪代码)

### 3.1 权能操作 (Capability Operations)
```rust
// 并非通过路径打开文件，而是从父权能中派生/获取
let file_cap = parent_cap.derive(offset, size, Permissions::READ)?;

// 撤销权能
file_cap.revoke()?;
```

### 3.2 异步 I/O 与类型安全 (Async I/O with Phantom Types)
利用 Rust 的幽灵类型确保 `Ticket` 在编译期就能对应正确的结果类型。
```rust
pub struct Ticket<T> {
    id: u64,
    _phantom: PhantomData<T>,
}

// 提交一个异步读取请求，返回 Ticket<ReadResult>
let ticket: Ticket<ReadResult> = executor.submit(read_req).await;

// 只有类型匹配才能正确获取结果
let result: ReadResult = ticket.await?; 
```

### 3.3 IPC (基于 Endpoint)
NovaOS 的 IPC 是强类型的。
```rust
let endpoint = Endpoint::create()?;
endpoint.send(Message::new(data))?;
```

## 4. 与 seL4 的映射关系
- **seL4_Call**: 用于同步的、低延迟的微小消息。
- **Shared Buffer + Notification**: 用于大数据量、高吞吐的异步 I/O。
- **CNode**: NovaOS 的 `CapStore` 服务将负责管理用户的 CNode 树，简化原始 seL4 的复杂操作。

## 5. 错误处理
 NovaOS 不使用 `errno`。每个系统调用返回一个显式的 `Result<T, Error>`，其中 `Error` 是经过分类的强类型枚举，例如：
 - `PermissionDenied`: 权能不足。
 - `ResourceExhausted`: 内存或配额耗尽。
 - `InvalidCapability`: 句柄已过期或无效。

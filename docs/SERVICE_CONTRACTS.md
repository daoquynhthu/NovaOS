[//]: # (ARCH-ID: ARCH-SERVICE-CONTRACTS-001 | 服务接口契约)
[//]: # (引用: PLAN.md Phase 2 P2.8)

# NovaOS 服务接口契约

> **定位**: 定义 NovaOS 各用户态服务之间的 IPC 协议约定：请求/响应消息寄存器布局、能力传递语义、不变量与错误处理。  
> **状态**: 草案 — 反映当前代码实现（2026-07-07）。  
> **引用**: `libnova::fs_ipc::FsLabel`（FS 协议标签）、`libnova::syscall::SyscallNum`（syscall 标签）。

---

## 1. 通用约定

### 1.1 传输层

所有服务间通信使用 seL4 `Call` / `Reply` / `Send` / `Recv` 机制：
- **Call**: 客户端发送请求并阻塞等待响应。
- **Reply**: 服务端在处理完成后回复客户端。
- 消息寄存器（MR）最多 `seL4_MsgMaxLength`（120）个 `seL4_Word`。
- 额外能力槽最多 `seL4_MsgMaxExtraCaps`（2）个。

### 1.2 消息格式

| MR0..N | 含义 |
|--------|------|
| MR0 | 通常为第一个参数或返回状态 |
| MR1..N | 随 label 变化的参数/数据 |

### 1.3 错误约定

- 服务端在正常处理时回复 `MessageInfo(label=0, ...)`。
- 标签值 0 表示成功响应。
- 非零标签值表示错误（由 `check_msg_err` 处理为 `seL4_Error`）。
- 具体错误码通过 MR0 返回，约定为：
  - 负值（`i64` 解释）：特定错误码（如 `FS_ERR_NOT_IMPLEMENTED = -38`）
  - 正值：标准 POSIX 风格错误码

---

## 2. RootServer Syscall 协议

**端点**: RootServer syscall endpoint（进程创建时分配，badge = 100 + pid）。

**服务端**: `services/rootserver/src/main.rs` dispatch（约行 1439+）。

**客户端**: `libs/libnova/src/syscall.rs`。

### 2.1 通用请求格式

```
label = SyscallNum 值 (1-50)
caps_unwrapped = 0 (大部分 syscall)
extra_caps = 0 或 1 (service_register 带能力)
length = 消息字数
```

### 2.2 响应格式

```
label = 0 (成功) 或 seL4_Error (失败)
length = 响应字数
MR0.. = 返回值
```

### 2.3 Syscall 一览

| SyscallNum | 名称 | 请求 MR | 响应 MR | 描述 |
|-----------|------|---------|---------|------|
| Print (1) | `sys_print` | MR0=len, MR1..=bytes | — | 打印字符串（无返回） |
| Exit (2) | `sys_exit` | MR0=exit_code | — | 终止进程 |
| Brk (3) | `sys_brk` | MR0=new_brk | MR0=actual_brk | 调整堆边界 |
| Yield (4) | `sys_yield` | — | — | 让出 CPU |
| GetTime (6) | `sys_get_time` | — | MR0=tick | 获取系统 tick |
| WaitPid (7) | `sys_waitpid` | MR0=pid, MR1=options | MR0=ret_pid, MR1=status | 等待子进程 |
| Spawn (8) | `sys_spawn` | MR0~5 协议头, MR6..=路径/参数 | MR0=pid | 创建进程 |
| GetPid (9) | `sys_get_pid` | — | MR0=pid | 获取当前 PID |
| Sleep (10) | `sys_sleep` | MR0=ticks | MR0=0/1 | 睡眠指定 tick |
| ShmAlloc (11) | `sys_shm_alloc` | MR0=size | MR0=key | 分配共享内存 |
| ShmMap (12) | `sys_shm_map` | MR0=key, MR1=vaddr | MR0=0/-1 | 映射共享内存 |
| Send (13) | `sys_send` | MR0=target_pid, MR1-3=msg | MR0=status | 发送 IPC 消息 |
| Fork (14) | `sys_fork` | — | MR0=child_pid | 复制进程 |
| Kill (15) | `sys_kill` | MR0=pid, MR1=sig | MR0=0/-1 | 发送信号 |
| Open (20) | `sys_open` | MR0=len, MR1=flags, MR2..=path | MR0=fd | 打开文件 |
| Read (21) | `sys_read` | MR0=fd, MR1=len, 响应 MR1..=data | MR0=bytes_read | 读取文件 |
| Write (22) | `sys_write` | MR0=fd, MR1=len, MR2..=data | MR0=bytes_written | 写入文件 |
| Close (23) | `sys_close` | MR0=fd | MR0=0/-1 | 关闭文件 |
| Chmod (24) | `sys_chmod` | MR0=len, MR1=mode, MR2..=path | MR0=0/-1 | 修改权限 |
| Chown (25) | `sys_chown` | MR0=len, MR1=uid, MR2=gid, MR3..=path | MR0=0/-1 | 修改所有者 |
| Symlink (26) | `sys_symlink` | MR0=t_len, MR1=l_len, MR2..=payload | MR0=0/-1 | 创建符号链接 |
| Readlink (27) | `sys_readlink` | MR0=len, MR1=buf_len, MR2..=path | MR0=bytes_read, MR1..=data | 读取链接目标 |
| GetUid (28) | `sys_getuid` | — | MR0=uid | 获取 UID |
| SetUid (29) | `sys_setuid` | MR0=uid | MR0=0/-1 | 设置 UID |
| ServiceRegister (30) | `sys_service_register` | MR0=len, MR1..=name, cap0=endpoint | MR0=0/-1 | 注册服务 |
| ServiceLookup (31) | `sys_service_lookup` | MR0=len, MR1..=name | extra_cap=endpoint | 查找服务 |
| GetGid (32) | `sys_getgid` | — | MR0=gid | 获取 GID |
| SetGid (33) | `sys_setgid` | MR0=gid | MR0=0/-1 | 设置 GID |
| Mkdir (34) | `sys_mkdir` | MR0=len, MR1..=path | MR0=0/-1 | 创建目录 |
| Rmdir (35) | `sys_rmdir` | MR0=len, MR1..=path | MR0=0/-1 | 删除目录 |
| Unlink (36) | `sys_unlink` | MR0=len, MR1..=path | MR0=0/-1 | 删除文件 |
| Rename (37) | `sys_rename` | MR0=o_len, MR1=n_len, MR2..=old+new | MR0=0/-1 | 重命名 |
| MmapShared (38) | `sys_mmap_shared` | MR0=size | MR0=vaddr | 映射共享内存 |
| MunmapShared (39) | `sys_munmap_shared` | MR0=addr, MR1=size | MR0=0/-1 | 取消映射 |
| Link (40) | `sys_link` | MR0=t_len, MR1=l_len, MR2..=tgt+lnk | MR0=0/-1 | 创建硬链接 |
| BlockRead (41) | `sys_block_read` | MR0=block_id | MR0=status, MR1..=data | 读块设备 |
| BlockWrite (42) | `sys_block_write` | MR0=block_id, MR1..=data | MR0=status | 写块设备 |
| BlockInfo (43) | `sys_block_info` | — | MR0=sectors, MR1=rotational | 块设备信息 |
| GetUnixTime (44) | `sys_get_unix_time` | — | MR0=timestamp | 获取 Unix 时间 |
| ServiceSetReady (45) | `sys_service_set_ready` | MR0=len, MR1..=name | MR0=0/-1 | 服务就绪标志 |
| FsViewEpoch (46) | `sys_fs_view_epoch` | — | MR0=epoch | 获取 FS 视图纪元 |
| Shutdown (50) | `sys_shutdown` | — | — | 关闭系统 |

---

## 3. fs_server IPC 协议

**端点**: 服务注册名为 `fs` / `fs.v1`（由 `sys_service_register` 注册）。

**服务端**: `services/fs_server/src/main.rs`（约行 720+ dispatch）。

**客户端**: `libs/libnova/src/fs_ipc.rs`（`FsLabel` 枚举）。

### 3.1 不变量

- fs_server 直接持有块设备能力（ATA I/O 端口 CMD=slot 1, DATA=slot 2，见 `CAPABILITY_MODEL.md §10.3`）；本地运行 NovaFS 实例，不再向 RootServer 转发 I/O。
- `RemoteBlockDevice` 保留为 ATA 能力不可用时的回退路径（`cspace_cap == 0` 根 CNode fallback）。
- fd 表最大 32 项，与 RootServer 侧一一对应（`remote_fd` 字段同步）。
- 路径最大长度：`FS_MAX_PATH_LEN = 255`。
- 读写最大长度：`FS_MAX_RW_LEN = 900`（MR 限制）。

### 3.2 协议详情

| FsLabel | 请求 MR | 响应 MR | 说明 |
|---------|---------|---------|------|
| Ping (0xF500) | — | MR0=status(FS_STATUS_READY), MR1=proto(FS_PROTO_V1), MR2=open+close, MR3=read+write | 健康检查 |
| Refresh (28) | — | MR0=0/-1 | 重新挂载 FS |
| Open (20) | MR0=len, MR1=mode, MR2..=path | MR0=fd | 打开文件/目录 |
| Read (21) | MR0=fd, MR1=len | MR0=bytes, MR1..=data | 读取文件 |
| Write (22) | MR0=fd, MR1=len, MR2..=data | MR0=bytes_written | 写入文件 |
| Close (23) | MR0=fd | MR0=0/-1 | 关闭文件 |
| Unlink (24) | MR0=len, MR1..=path | MR0=0/-1 | 删除文件 |
| Mkdir (29) | MR0=len, MR1..=path | MR0=0/-1 | 创建目录 |
| Truncate (30) | MR0=len, MR1=size, MR2..=path | MR0=0/-1 | 截断文件 |
| Chmod (31) | MR0=len, MR1=mode, MR2..=path | MR0=0/-1 | 修改权限 |
| Chown (32) | MR0=len, MR1=uid, MR2=gid, MR3..=path | MR0=0/-1 | 修改所有者 |
| Sync (33) | — | MR0=0/-1 | 同步缓存 |
| List (36) | MR0=len, MR1..=path | MR0=0/-1, 已注册回调输出 | 列出目录 |
| Stat (38) | MR0=len, MR1..=path | MR0=type_kind（`local_stat_kind` 返回值） | 获取文件类型 |
| Encrypt (34) | MR0=len, MR1..=path | MR0=0/-1 | 加密文件 |
| Decrypt (35) | MR0=len, MR1..=path | MR0=0/-1 | 解密文件 |
| Rename (25) | MR0=o_len, MR1=n_len, MR2..=old+new | MR0=0/-1 | 重命名 |
| Link (26) | MR0=t_len, MR1=l_len, MR2..=tgt+lnk | MR0=0/-1 | 创建硬链接 |
| Symlink (27) | MR0=t_len, MR1=l_len, MR2..=tgt+lnk | MR0=0/-1 | 创建符号链接 |
| Writetest (37) | MR0=len, MR1=size_kb, MR2..=path | MR0=0/-1 | 写性能测试 |

### 3.3 错误码

| 常量 | 值 | 含义 |
|------|-----|------|
| `FS_ERR_NOT_IMPLEMENTED` | -38 | 该操作在 fs_server 上尚未实现 |
| `FS_ERR_IO` | -5 | I/O 错误 |
| `FS_ERR_INVAL` | -22 | 无效参数 |

---

## 4. serial_server 协议

**端点**: 服务注册名为 `serial.v1`。

**服务端**: `services/serial_server/src/main.rs`（约 48 行）。

**客户端**: 无当前客户端（仅注册并标记就绪，等待 Phase 4 实现串口转发）。

### 4.1 当前行为

- 启动时注册为 `serial.v1`。
- 标记为 `Ready`。
- 进入空闲循环（`sys_yield`）。
- **不接受** 任何 IPC 请求（无 dispatch match）。

### 4.2 未来协议（计划）

```
FsLabel-like 枚举待定义：
- SerialRead  — 从串口读取
- SerialWrite — 写入串口
```

---

## 5. user_app 通信契约

**Binary**: `/bin/hello`，多模式启动。

**启动模式**:
- PID 0 模式：运行完整测试套件（直接调用 libnova syscall stubs，不与 fs_server 直接 IPC 通信）。
- 子模式（`run_fs_*` helper）：通过解析 `EarlyArgs` 从进程参数获取 `fs_server` endpoint，直接调用 fs_server IPC。

### 5.1 Helper 模式通信路径

```
user_app (子) ──seL4_Call──▶ fs_server endpoint
```

- 使用 `libnova::fs_ipc::*_direct` 函数族（如 `open_direct`，`read_direct`）。
- 不经过 RootServer syscall dispatch。
- endpoint 从进程环境参数获取（`NOVA_FS_SERVICE_EP` / `NOVA_FS_SERVICE_SLOT`）。

---

## 6. 不变量总则

| 不变量 | 说明 | 违反后果 |
|--------|------|----------|
| 路径长度 | 所有文件路径 ≤ `FS_MAX_PATH_LEN`（255 字节） | 系统拒绝操作 |
| 读写长度 | 所有读写请求 ≤ `FS_MAX_RW_LEN`（900 字节） | 系统拒绝操作 |
| fd 范围 | fd 值必须 < `MAX_FDS`（16） | 越界访问 |
| 能力所有权 | 服务端不得修改客户端的能力槽 | CSpace 损坏 |
| 消息长度 | 消息长度 ≤ `seL4_MsgMaxLength`（120 字） | 越界读取 |
| 服务注册 | 服务名 ≤ 255 字节，只能注册一次 | 重复注册返回错误 |
| 进程数 | 活跃进程 ≤ `MAX_PROCESSES`（32） | spawn 返回错误 |
| 共享内存键 | 共享内存 key 必须唯一 | 映射冲突 |

---

## 7. 修订记录

| 日期 | 版本 | 变更 |
|------|------|------|
| 2026-07-07 | 1.0 | 初始版本，基于当前代码实现 |
| 2026-07-09 | 1.1 | §3.1 更新：fs_server 直接持有块设备，移除 `FS_SYNC_FORWARD_ENABLED=false` 引用 |

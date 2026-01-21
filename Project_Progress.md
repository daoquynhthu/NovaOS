# NovaOS 项目进度书 (Project Progress)

> 本文档用于记录项目里程碑、已完成任务以及下一步计划。每次重大变更后必须更新。

## 📅 当前状态
- **日期**: 2026-01-20
- **阶段**: 0.7.5 - 系统鲁棒性与高级特性 (System Robustness & Advanced Features)
- **版本**: `v0.0.9-alpha`
- **状态**: 稳定，通过全量自动化测试验证 (Stable, Passed Full Automated Tests)

## ✅ 已完成任务 (Completed)

### 2026-01-21: 系统调用与权限控制 (System Calls & Permission Control)
- [x] **系统调用标准化**:
    - 对齐了 libnova 与 Kernel 的 Syscall ID (Open=20, Read=21, Write=22, Close=23, Rename=37)。
    - 统一了 IPC 消息打包/解包规范 (MessageInfo, MR0-MRn)。
    - 修复了 `sys_write` 数据解包错误和返回值丢失问题。
- [x] **权限控制体系**:
    - 实现了基于 UID/GID 的权限检查机制 (`process::can_control`)。
    - 在 `sys_kill`, `sys_open`, `sys_write`, `sys_rename` 中集成了权限验证。
- [x] **Shell 功能完善**:
    - 修复了 `mv` 命令依赖的 `sys_rename` 实现，支持文件重命名。
    - 修复了 `sys_sleep` 的语法错误。
- [x] **Bug 修复**:
    - 修复了 `NovaFS` 中 `lookup` 函数读取稀疏块 (Hole) 导致读取 SuperBlock 的严重 Bug。
    - 修复了 `console.rs` 中 `sys_print` 作用域引用错误。
    - 移除了 RootServer 中重复的 Syscall Handler。
    - **NovaFS 目录一致性修复**: 修复了 `remove` 和 `rename` 操作中未更新父目录 `size` 和 `mtime` 的缺陷，解决了 `mv` 命令在特定场景下静默失败的问题。
    - **测试脚本增强**: 修复了 `test.ps1` 在重命名测试阶段因残留文件导致静默失败的问题，增加了测试前的环境清理步骤。
    - **进程管理增强**:
        - **环境变量支持**: `sys_spawn` 系统调用新增环境变量传递功能 (Env Vars)，支持从父进程向子进程传递配置信息。
        - **安全增强**: 为 `sys_spawn` 添加了参数长度校验 (Path < 4096, Args/Envs Count < 256)，防止恶意输入导致内核 Panic。
        - **用户态集成**: 更新 `user_app` 和 `libnova` 适配新的 `sys_spawn` 接口。

### 2026-01-20: 系统鲁棒性与高级文件特性 (System Robustness & Advanced FS Features)
- [x] **文件系统鲁棒性增强 (Critical)**:
    - **死循环防护**: 在 `ls` 和目录遍历逻辑中引入 `MAX_LOOP` 限制，彻底解决了文件系统损坏导致内核死锁/超时的问题。
    - **内存清零**: 修复 `alloc_block`，强制对新分配的磁盘块进行零初始化，防止旧数据泄露和元数据污染。
    - **强制重格式化**: 更新 Magic Number 至 v8 (`0x4E4F5648`)，清除历史残留的错误 Inode 状态，恢复系统纯净。
    - **错误处理**: 为 `encrypt`/`decrypt` 等命令添加了 VFS 挂载状态检查，防止静默失败。
- [x] **高级文件系统特性**:
    - **透明加密 (Transparent Encryption)**: 实现了基于 ChaCha20 的文件级加密。每个 Inode 拥有独立 Nonce，支持 `encrypt`/`decrypt` 命令。
    - **目录重命名 (Directory Rename)**: 实现了 `rename` 系统调用，支持目录移动，并增加了自引用检查（防止移动到子目录中）。
    - **文件截断与稀疏文件 (Truncate & Sparse)**: 实现了 `sys_truncate`，支持文件伸缩。支持**稀疏文件**，截断到大尺寸时不实际分配磁盘块。
- [x] **Shell 工具链增强**:
    - 新增 `encrypt`, `decrypt` 命令用于测试加密特性。
    - 新增 `truncate` 命令测试文件伸缩。
    - 新增 `mv` 命令支持重命名。
    - 修复 `ls` 超时问题，优化了错误回显。
- [x] **自动化测试验证**:
    - 修复了 `test.ps1` Stage 13 (Encryption) 的超时问题（根源为 VFS 未初始化）。
    - 通过了包含加密、截断、重命名、大文件读写在内的全量测试用例。

### 2026-01-19: 关键 Bug 修复与全流程验证 (Critical Fixes & Verification)
- [x] **内存破坏修复 (Critical)**:
    - 修复了 `NovaFS` 中 `DiskInode` 结构的 Padding 错误（从 `[u8; 71]` 修正为 `[u8; 68]`），严格对齐 128 字节，消除了导致 VM Fault 的根源。
    - 确保了块 I/O 操作的 16 字节内存对齐。
- [x] **系统调用完善**:
    - 修复了 `sys_write` 等系统调用的返回值丢失问题（通过在 IPC 循环中手动保留 MR0 寄存器）。
    - 解决了 `NovaFS` 的 Trait 对象转换问题 (`Arc<dyn FileSystem>`)。
- [x] **自动化测试体系**:
    - 完善 `test.ps1` 脚本，增加了 60秒超时保护、日志监控和错误捕获。
    - 实现了 QEMU 自动化测试流程，成功验证了从用户态到文件系统的完整链路。
- [x] **全链路验证通过**:
    - **用户态验证**: User App 成功调用 `sys_open`, `sys_write`, `sys_read`，数据回显正确 ("Hello NovaFS!")。
    - **驱动验证**: ATA PIO 驱动读写稳定，`test.ps1` 报告 `[PASS] Disk Read/Write Verified!`。
    - **内存验证**: 堆内存扩展（Heap Expansion）和读写测试通过。

### 2026-01-18: 文件系统系统调用 (File System Syscalls)
- [x] **Syscall 实现**:
    - 在 RootServer (`main.rs`) 中实现了完整的文件操作 IPC 接口。
    - `sys_open` (Label 20): 支持路径解析与 FD 分配。
    - `sys_read` (Label 21): 支持从磁盘/文件系统读取数据。
    - `sys_write` (Label 22): 支持向磁盘/文件系统写入数据。
    - `sys_close` (Label 23): 资源释放。
- [x] **IPC 安全增强**:
    - 实现了 IPC Buffer 的边界检查，限制路径长度 < 256 字节，单次读写数据 < 900 字节。
- [x] **进程状态增强**:
    - `Process` 结构体集成了 `FileDescriptor` 表，支持多文件并发打开。

### 2026-01-18: 驱动增强与自动挂载 (Driver Enhancements & Auto-Mount)
- [x] **ATA 驱动增强**:
    - 实现了 `identify` 方法，支持通过 ATA IDENTIFY (0xEC) 命令检测硬盘型号和容量。
    - 支持 LBA28/LBA48 模式扇区计数检测。
    - `BlockDevice` 实现增加了块 ID 越界检查。
- [x] **自动挂载与格式化**:
    - RootServer 启动时自动初始化 ATA 驱动并尝试挂载 NovaFS。
    - 如果挂载失败（Magic 错误）或 `/bin` 目录缺失，自动触发格式化。
- [x] **Shell 与 VFS 改进**:
    - VFS 新增 `write_file` 辅助方法，支持文件创建/覆盖。
    - Shell 新增 `write` 命令和重定向 (`>`) 支持真实文件写入。

### 2026-01-18: Capability 管理与系统构建增强
- [x] **seL4 Capability 管理优化**:
    - 解决了页帧映射过程中的 `seL4_InvalidCapability` 错误。
    - 在 `VSpace` 中引入了 `PagingCap` 结构，精确追踪 PDPT、PD、PT 等分页结构的 Capability。
    - 实现了 `ensure_pt_exists` 机制，支持在映射页面时自动创建缺失的分页结构 (Level 1-3)。
    - 修复了 `libnova::cap::cap_rights_new` 的参数顺序及调用逻辑。
- [x] **代码质量与构建修复**:
    - 修复了 `vspace.rs` 和 `elf_loader.rs` 中的未使用代码警告。
    - 解决了 `libnova` 编译时的 Trait 作用域问题 (`ToString`)。

### 2026-01-17: 磁盘驱动与文件系统 (Disk Driver & File System)
- [x] **ATA PIO 驱动器**: 实现了 PIO 模式 ATA 驱动，支持 LBA28。
- [x] **Nova Simple File System (NSFS)**: 实现了 SuperBlock, Bitmap, RootDir, Format, CheckMagic。
- [x] **Shell 集成**: 新增 `mkfs`, `mount` 命令。

### 2026-01-17: 系统关机功能 (System Shutdown)
- [x] **ACPI 电源管理**: 实现了 S5 关机逻辑。
- [x] **双重关机策略**: QEMU Port 0x604 + ACPI PM1a/PM1b。

## ⚠️ 待解决问题 (Pending Issues)
- [ ] **Shell 功能增强**: 目前仅支持基础命令，需增加 `cat`, `rm` 等文件操作命令。
- [ ] **文件系统功能扩展**: 支持子目录、文件删除等高级功能。

## 📊 路线图更新 (Roadmap Update)
#### Phase 2: 持久化与扩展 (Completed)
- [x] **块设备驱动**: ATA/IDE 驱动完成。
- [x] **持久化文件系统**: NovaFS 基础读写完成。
- [x] **系统调用**: `open`, `read`, `write`, `close` 完成并验证。
- [x] **Shell 工具**: 增强 Shell 以支持完整的文件系统操作 (cp, mv, rm, cat)。

### 2026-01-19: NovaFS 核心增强 (Core Enhancements)
- [x] **大文件支持 (Large File Support)**:
    - 实现了 **二级间接索引 (Double Indirect Block)**，将单文件最大限制从 70KB 提升至约 36MB。
    - Shell 新增 `writetest` 命令，用于验证大文件写入与读取。
- [x] **目录树支持 (Directory Tree)**:
    - VFS 和 Shell 实现了 **路径规范化 (Canonicalization)**，正确处理 `..` 和 `.` 路径组件，支持 `cd ..`。
    - Shell 新增 `mkdir` 命令，支持创建子目录。
    - 修复了 `list` 和 `remove` 操作中直接访问 `direct` 数组的 Bug，现在通过 `get_block_id` 正确处理跨块的目录项。
    - `remove` 操作增加了非空目录检查（全量扫描），防止误删非空目录。

#### Phase 3: 核心功能完善 (Current - Core System Maturity)
> *由于 NovaFS 功能尚简陋（如不支持子目录、大文件），且进程管理缺失关键特性（如 fork/exec），本阶段优先完善核心功能，推迟架构重构。*

- [ ] **文件系统增强 (File System 2.0)**:
    - [x] **目录树支持**: 实现子目录 (`mkdir`), 支持路径解析 (`..` support, `/home/user/doc.txt`).
    - [x] **大文件支持**: 引入二级间接索引 (Double Indirect Block), 突破 70KB 限制 (Shell `writetest` added).
    - [x] **文件删除完善**: 优化 `rm` / `unlink`, 已实现 Direct/Indirect/Double-Indirect 数据块的全量回收 (Bitmap Clearing).
    - [x] **Buffer Cache**: 基础的 LRU Block Cache 已集成，减少磁盘 I/O.
    - [x] **安全与高级特性**: 透明加密 (ChaCha20), 目录重命名 (Rename), 稀疏文件支持.

- [ ] **进程管理增强 (Process Management)**:
    - [x] **Process Hierarchy**: 维护父子进程关系树 (已实现 ppid/children).
    - [x] **System Calls**:
        - [ ] `sys_fork`: 进程克隆 (Copy-on-Write 暂不强求，先实现深拷贝).
        - [ ] `sys_exec`: 加载新程序覆盖当前进程.
        - [x] `sys_wait`: 父进程等待子进程退出 (sys_waitpid).
        - [x] `sys_spawn`: 环境变量支持与参数传递优化.
    - [ ] **ELF Loader 改进**: 支持动态链接器 (ld.so) 预留接口.

- [ ] **内存管理增强 (Memory Management)**:
    - [ ] **Shared Memory**: 实现 `sys_mmap` (Shared), 为未来微内核 IPC 做准备.
    - [ ] **Heap Management**: 完善 `sys_brk` 的内存回收机制 (Shrink).

#### Phase 4: 微内核化演进 (Future - Microkernel Evolution)
- [ ] **架构重构**:
    - [x] 创建 `services/serial_server` 目录结构。


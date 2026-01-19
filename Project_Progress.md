# NovaOS 项目进度书 (Project Progress)

> 本文档用于记录项目里程碑、已完成任务以及下一步计划。每次重大变更后必须更新。

## 📅 当前状态
- **日期**: 2026-01-19
- **阶段**: 0.7.2 - 稳定性修复与全流程验证 (Stability Fixes & Full Verification)
- **版本**: `v0.0.8-alpha`
- **状态**: 稳定，通过自动化测试验证 (Stable, Verified via Automated Tests)

## ✅ 已完成任务 (Completed)

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
#### Phase 2: 持久化与扩展 (Current)
- [x] **块设备驱动**: ATA/IDE 驱动完成。
- [x] **持久化文件系统**: NovaFS 基础读写完成。
- [x] **系统调用**: `open`, `read`, `write`, `close` 完成并验证。
- [ ] **用户库封装**: 在 `libnova` 中提供类似 `std::fs::File` 的封装 (Next).
- [ ] **Shell 工具**: 增强 Shell 以支持完整的文件系统操作 (Next).

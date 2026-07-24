# NovaOS — Code Index & Architecture Reality

> **Purpose**: Quick code navigation (front) + layered architecture description for AI agent context (back).  
> **Truth source**: Code only. If docs disagree with code, code wins.  
> **Generated**: 2026-07-09 (Phase 4 complete, clippy zeroed, ISSUE-94~112 fixed)

---

## I. Quick Code Index

### 1. Kernel Layer (seL4 — C, submodule)

| What | Location | Line |
|---|---|---|
| seL4 source | `kernel/seL4/` | — |
| Formally verified microkernel | tag `v14.0.0-23-g04fba8577` | — |
| Build config (NovaOS overrides) | `CMakeLists.txt` | 42-56 |
| Toolchain file (cross-compile) | `gcc.cmake` | — |

### 2. FFI Bindings (`libs/seL4-sys/`)

| What | File | Line |
|---|---|---|
| Build script (bindgen wrapper) | `libs/seL4-sys/build.rs` | 1-77 |
| Wrapper header | `libs/seL4-sys/src/wrapper.h` | — |
| Generated bindings output | `libs/seL4-sys/src/bindings.rs` (gitignored) | — |
| Required env: `SEL4_OUT_DIR` | `build.rs` | 9 |
| Required env: `SEL4_KERNEL_DIR` | `build.rs` | 12 |

### 3. Core Library (`libs/libnova/src/`)

| Module | File | Key contents |
|---|---|---|
| `ipc` — raw seL4 IPC | `ipc.rs` | `MessageInfo`, `call()`, `send()`, `recv()`, `reply()`, `reply_recv()`, `set_mr()`, `get_mr()` |
| `ipc::pack` — bounded message packing | `ipc/pack.rs` | `BoundError`, `MessageWriter`, `MessageReader`; replaces duplicate packing loops in `syscall.rs` and `fs_ipc.rs` |
| `allocator` — memory management | `allocator.rs` | `SlotAllocator`, `UntypedAllocator`, `FrameAllocator`, `ObjectAllocator` trait; moved from RootServer's `memory.rs` |
| `syscall` — syscall stubs | `syscall.rs` | `sys_open` (260), `sys_read` (279), `sys_write` (310), `sys_close` (251), `sys_spawn` (180), `sys_yield` (62), `sys_exit` (67), `Error` enum (6) |
| `fs_ipc` — FS protocol | `fs_ipc.rs` | `FS_LABEL_OPEN=20` (4), `FS_LABEL_*` constants (4-23), `open_direct()` (50), `read_direct()` (95), `write_direct()` (77), `close_direct()` (69), all FS helpers (50-400) |
| `cap` — CNode ops | `cap.rs` | `CNode` (27), `cap_rights_new()` (16), `copy()`, `mint()`, `move_()`, `delete()`, `revoke()` |
| `console` — print macros | `console.rs` | `print!` (80), `println!` (84), `DebugConsole` (14), `UserConsole` (51) |
| `log` — leveled logging | `log.rs` | domain-gated `log_debug!`, `log_trace!` |
| `tcb` — TCB config | `tcb.rs` | TCB setup wrappers |
| `arch::x86_64::port_io` | `arch/x86_64/port_io.rs` | Port I/O functions migrated from RootServer `arch/x86_64/port_io.rs` (P4.2) |
| `env` — arg iterator | `env.rs` | Early arg parsing |
| `validate` — IPC message validation | `validate.rs` | `validate_message_length`, `validate_mr_index`, `validate_cap_index`, `validate_payload_fits`, `validate_one/two_mrs`, `validate_fs_request_min`, `fs_min_words`; 34 host tests (P4.6) |
| Syscall label map | `syscall.rs` | `SyscallNum` enum: `Print=1`, `Exit=2`, `Brk=3`, `Yield=4`, `Open=20`, `Read=21`, `Write=22`, `Close=23`, `Spawn=8`, ... (see `libnova::syscall::SyscallNum`) |

### 4. Services

#### 4a. RootServer (`services/rootserver/src/`)

| What | File | Line |
|---|---|---|
| Entry point (`rust_main`) | `main.rs` | 464 |
| Main event loop (recv→dispatch→reply) | `main.rs` | 1274-1360 |
| Syscall dispatch `match label` | `main.rs` | 1366-3319 |
| Syscall handlers module | `handlers/` | — |
| Handler input validation | `libnova/src/validate.rs` | — |
| Core handlers (`yield`, `get_pid`, `sleep`, `wait`, `kill`, `exit`, `spawn`, `fork`) | `handlers/core.rs` | — |
| Memory handlers (`brk`, `shm_alloc`, `shm_map`, `mmap_shared`, `munmap_shared`) | `handlers/core.rs` | — |
| FS handlers (`open`/`read`/`write`/`close`/`mkdir`/`rmdir`/`unlink`/`rename`/`link`/`symlink`/`readlink`/`chmod`/`chown`/`block_*`) | `handlers/fs.rs` | — |
| Metadata handlers (`getuid`/`setuid`/`getgid`/`setgid`) | `handlers/metadata.rs` | — |
| Service handlers (`register`/`lookup`/`set_ready`/`epoch`/`get_time`/`get_unix_time`/`shutdown`) | `handlers/service.rs` | — |
| OOM admission control | `main.rs` | 67-94 |
| `FS_SYNC_FORWARD_ENABLED` (false) | `main.rs` | 65 |
| `FS_READ_PREFER_SERVER` (true) | `main.rs` | 61 |
| `try_forward_fs_call` | `main.rs` | 131 |
| `try_forward_fs_read_data` | `main.rs` | 223 |
| Shell — `COMMANDS` list | `shell.rs` | 16-21 |
| Shell — `execute_command()` | `shell.rs` | 691 |
| Shell — helper spawners | `shell.rs` | 665-687 |
| Process — `Process` struct | `process.rs` | 256 |
| Process — `FileDescriptor` struct | `process.rs` | 240 |
| Process — `MAX_PROCESSES=32` | `process.rs` | 233 |
| Process — `spawn()` | `process.rs` | 654 |
| VFS — `FileSystem` trait | `vfs.rs` | 49 |
| VFS — `Inode` trait | `vfs.rs` | 209 |
| VFS — global `VFS` static | `vfs.rs` | 7 |
| Service registry — `SERVICE_REGISTRY` | `services.rs` | 22 |
| Service registry — `register()` | `services.rs` | 34 |
| Service registry — `mark_ready()` | `services.rs` | 47 |
| Service registry — `lookup_ready()` | `services.rs` | 73 |
| Memory — `SlotAllocator` | `libnova::allocator` (via `memory.rs` re-export) | `libs/libnova/src/allocator.rs:42` |
| Memory — `UntypedAllocator` | `libnova::allocator` (via `memory.rs` re-export) | `libs/libnova/src/allocator.rs:175` |
| Memory — `FrameAllocator` | `libnova::allocator` (via `memory.rs` re-export) | `libs/libnova/src/allocator.rs:439` |
| Memory — `MAX_CSPACE_SLOTS=4096` | `libnova::allocator` | `libs/libnova/src/allocator.rs:13` |
| Shared Memory — `SharedMemoryManager` | `shared_memory.rs` | — |
| ELF loader | `elf_loader.rs` | — |
| Drivers — ATA PIO | `drivers/ata.rs` | — |
| Drivers — keyboard | `drivers/keyboard.rs` | — |
| Drivers — serial | `drivers/serial.rs` | — |
| Drivers — timer (PIT/HPET) | `drivers/timer.rs` | — |
| RTC wall-clock stub | `rtc.rs` | — |
| **Arch** — x86_64 port I/O | `arch/x86_64/port_io.rs` | — |
| Arch — APIC | `arch/x86_64/apic.rs` | — |
| Arch — IOAPIC | `arch/x86_64/ioapic.rs` | — |
| Arch — ACPI | `arch/x86_64/acpi.rs` | — |
| Arch — PCI config | `arch/x86_64/pci.rs` | — |
| Tests | `tests.rs` | — |

#### NovaFS Core (`libs/novafs-core/src/`)

| What | File | Line |
|---|---|---|
| `BlockDevice` trait | `block_device.rs` | 1-4 |
| `MockBlockDevice` (host tests) | `block_device.rs` | 8-75 |
| Block cache | `block_cache.rs` | — |
| Block allocation strategy | `strategy.rs` | — |
| ChaCha20 crypto | `crypto.rs` | — |
| NovaFS constants | `novafs.rs` | 11-15 |
| NovaFS `SuperBlock` | `novafs.rs` | 18 |
| NovaFS `DiskInode` | `novafs.rs` | 32 |
| NovaFS `DirEntry` | `novafs.rs` | 51 |
| NovaFS `NovaFS<D>` struct | `novafs.rs` | 59 |
| NovaFS `mount()` / `new()` | `novafs.rs` | 67 |
| NovaFS `format()` | `novafs.rs` | 90 |
| NovaFS block I/O (indirect resolution) | `novafs.rs` | 399 |
| NovaFS `Inode::read_at()` | `novafs.rs` | 589 |
| NovaFS `Inode::write_at()` | `novafs.rs` | 641 |
| NovaFS `Inode::control()` (truncate, chmod, chown) | `novafs.rs` | 709 |
| NovaFS directory ops | `novafs.rs` | 794-1337 |
| VFS traits | `vfs.rs` | — |
| Host-native tests | `tests/novafs_host.rs` | — |

#### 4b. fs_server (`services/fs_server/src/`)

| What | File | Line |
|---|---|---|
| Entry (`_start`) | `main.rs` | 639 |
| Main service loop | `main.rs` | 719-1323 |
| `FdEntry` struct | `main.rs` | 98-102 |
| `DISK_FS` / `FS_STATE` / `LOCAL_FS_EPOCH` statics | `main.rs` | 84-86 |
| NovaFS dependency | `Cargo.toml` | `novafs-core` crate |
| Handler: `local_open` → `open_inode` | `main.rs` | 273-294 |
| FS protocol dispatch | `main.rs` | 724-1321 |

#### 4c. serial_server (`services/serial_server/src/`)

| What | File | Line |
|---|---|---|
| Entry (`_start`) | `main.rs` | 16 |
| Register `serial.v1` | `main.rs` | 23 |
| Mark ready | `main.rs` | 24 |
| Idle loop (`sys_yield`) | `main.rs` | 37-39 |

#### 4d. user_app (`services/user_app/src/`)

| What | File | Line |
|---|---|---|
| Entry (`_start`) | `main.rs` | 1301 |
| `EarlyArgs` struct | `main.rs` | 43-98 |
| FS helper: `run_fs_touch` | `main.rs` | 739 |
| FS helper: `run_fs_cat` | `main.rs` | 767 |
| FS helper: `run_fs_ls` | `main.rs` | 856 |
| FS helper: `run_fs_cd` | `main.rs` | 876 |
| FS helper: `run_fs_cp` | `main.rs` | 1059 |
| FS helper: `run_fs_mv` | `main.rs` | 1121 |
| FS helper: `run_fs_rm` | `main.rs` | 1011 |
| FS helper: `run_fs_mkdir` | `main.rs` | 1038 |
| FS helper: `run_fs_truncate` | `main.rs` | 1146 |
| FS helper: `run_fs_chmod` | `main.rs` | 1167 |
| FS helper: `run_fs_chown` | `main.rs` | 1188 |
| FS helper: `run_fs_sync` | `main.rs` | 1209 |
| FS helper: `run_fs_link` | `main.rs` | 1230 |
| FS helper: `run_fs_symlink` | `main.rs` | 1251 |
| FS helper: `run_fs_encrypt` | `main.rs` | 957 |
| FS helper: `run_fs_decrypt` | `main.rs` | 984 |
| FS helper: `run_fs_write_text` (echo) | `main.rs` | 900 |
| FS helper: `run_fs_writetest` | `main.rs` | 934 |
| Smoke: `run_fs_proxy_smoke` | `main.rs` | 631 |
| Smoke: `run_fs_syscall_smoke` | `main.rs` | 684 |

### 5. Build & Config

| What | File | Line |
|---|---|---|
| Workspace Cargo.toml | `Cargo.toml` | 1-40 |
| Workspace members (7 crates) | `Cargo.toml` | 2-10 |
| Workspace dependencies | `Cargo.toml` | 12-15 |
| Workspace lints | `Cargo.toml` | 25-40 |
| Cargo target config | `.cargo/config.toml` | 1-5 |
| Rust toolchain (pinned nightly) | `rust-toolchain.toml` | 1-4 |
| Rustfmt config | `rustfmt.toml` | 1-10 |
| Root CMakeLists.txt | `CMakeLists.txt` | 1-145 |
| Kernel config defaults | `CMakeLists.txt` | 42-56 |
| Trace level system | `CMakeLists.txt` | 58-80 |
| Rust service build targets | `CMakeLists.txt` | 88-136 (`nova_rust_services`) |
| Build script (Win) | `scripts/build.ps1` | 1-32 |
| Build script (Linux) | `scripts/build.sh` | 1-12 |
| Test script (Win) | `scripts/test.ps1` | 1-1086 |
| Test script (Linux) | `scripts/test.sh` | 1-26 |
| QEMU launcher (Win) | `scripts/run_qemu.ps1` | 1-46 |
| QEMU launcher (Linux) | `scripts/run_qemu.sh` | 1-12 |
| Environment setup (Win) | `scripts/init_env.ps1` | 1-35 |
| Environment setup (Linux) | `scripts/init_env.sh` | 1-43 |
| Common CMake config (Linux) | `scripts/cmake-common.sh` | 1-53 |
| ELF/Multiboot checker | `scripts/check_mb.py` | 1-114 |
| .gitignore | `.gitignore` | 1-65 |
| .gitattributes | `.gitattributes` | 1-32 |
| CI workflow | `.github/workflows/ci.yml` | 1-83 |
| .gitmodules (3 submodules) | `.gitmodules` | 1-9 |
| Submodule pins | seL4 `04fba8577`, tools `fbfc63978`, util_libs `07a7e15b8` | — |

### 6. Documentation

| File | Content |
|---|---|
| `docs/PROGRESS.md` | Progress log (single source of truth for project status) |
| `docs/PLAN.md` | Roadmap with 7 phases |
| `docs/TASK.md` | Current execution plan |
| `docs/ISSUE.md` | Known issues archive |
| `docs/INDEX.md` | Code index and architecture reality (this file) |
| `docs/NovaOS_Proposal.md` | Design proposal / vision |
| `docs/NovaOS_Syscall_Design.md` | Syscall design notes |
| `docs/NovaOS_Verification_Spec.md` | Verification spec |
| `docs/NovaOS_Memory_Error_Spec.md` | Memory error spec |
| `docs/CAPABILITY_MODEL.md` | Capability model — CSpace layout per service |
| `docs/SERVICE_CONTRACTS.md` | Service interface contracts — fs_server/serial_server/user_app IPC protocols |
| `skills/NovaOS_Project/SKILL.md` | opencode skill for NovaOS development |

---

## II. Architecture Reality

- boot 流程不再格式化磁盘/安装二进制（P4.5）：`create_deprecated_local_fs()` 创建最小桩
- fs_server 是唯一数据面权威，DISK_FS/VFS 保留为弃用兼容桩
- ATA PIO 设备端口能力通过 `issue_ioport_cap` 安装到 fs_server CNode（P4.2）
- `FS_SYNC_FORWARD_ENABLED` 死锁已解除（P4.3）

### Layer 0: Physical / Host

```
Host (Windows 10 + WSL2 Ubuntu 24.04 or native Linux)
  └─ QEMU (x86_64, pc99 platform, KVM or TCG)
      └─ seL4 kernel (ELF, 64-bit, converted to 32-bit ELF for multiboot)
```

- **Kernel built on Linux** (WSL2 or native). Windows native build is broken:
  - MinGW GCC produces PE objects, not ELF
  - Clang on Windows has `-Wa,--64` compatibility issue with seL4 ASM files
  - `CMakeLists.txt` LLD flag now conditionally disabled on Windows
- **Rust user-space built on Windows** (native `x86_64-unknown-none`)
- **Test runner**: `test.ps1` drives QEMU via TCP serial, ~50-stage state machine
- **Disk**: 10MB raw image (`disk.img`), auto-generated each test run

### Layer 1: Kernel (seL4)

- **Version**: `kernel/seL4` submodule at `04fba85774` (v14.0.0 + 23 commits)
- **Config**: Debug build, printing enabled, verification OFF
- **Capabilities provided**: Untyped memory, TCBs, CNodes, VSpaces (page tables), endpoints, IRQ handlers, frames (4K pages)
- **seL4 features used**: `seL4_Call`/`seL4_Send`/`seL4_Reply`/`seL4_Recv` for IPC, `seL4_UntypedRetype` for object creation, debug syscalls (`seL4_DebugPutChar`), IRQ control, scheduling contexts
- **Trace level system**: 5 domains × 4 levels, compile-time via CMake `-DNOVA_BOOT_TRACE_*` flags

### Layer 2: FFI Bindings (seL4-sys)

- `libs/seL4-sys/build.rs` runs `bindgen` against seL4 headers → generates Rust FFI
- Needs `SEL4_OUT_DIR` (kernel build output) and `SEL4_KERNEL_DIR` (kernel source)
- Forces `LP64` data model (`-D__LP64__`) for correct `seL4_Word` size
- Custom blocklist + manual `#[repr(C)]` for `seL4_Word`, `seL4_MessageInfo`, `seL4_CapRights`
- Only generated once per kernel build; output is `OUT_DIR/bindings.rs`

### Layer 3: Core Library (libnova)

`libnova` is a `no_std` Rust library providing all user-space abstractions. Has `std` feature for host-native unit tests (34 tests across validate, allocator, syscall, fs_ipc, cap modules):

```
libnova/
├── ipc.rs        — Raw seL4 IPC primitives (call/send/recv/reply/reply_recv)
├── ipc/pack.rs   — Bounded message packing (MessageWriter/MessageReader, TASK-5)
├── syscall.rs    — Syscall stubs + SyscallNum enum (29 variants, Phase 2)
├── fs_ipc.rs     — FS protocol + FsLabel enum (20 variants) + *_direct() helpers
├── cap.rs        — CNode capability wrappers (copy/mint/move/delete/revoke)
├── console.rs    — print!/println! macros (DebugConsole via seL4_DebugPutChar)
├── log.rs        — Domain-gated logging (log_debug!, log_trace!) + DOM_PAGING (P3.4)
├── allocator.rs  — SlotAllocator/UntypedAllocator/FrameAllocator (TASK-7)
├── validate.rs   — IPC message validation (34 host tests, P4.6)
├── tcb.rs        — TCB configuration
├── env.rs        — Argument iterator
└── arch/x86_64/
    └── port_io.rs — I/O port functions (P4.2, migrated from RootServer)

`std` feature: enables host-native `cargo test` (provides `__sel4_ipc_buffer` stub).
```

### Layer 4: Services

#### 4a. RootServer (3328 lines)

The initial user-mode process. RootServer is the **syscall dispatch center** + **NovaFS data plane** + **Shell** + **Process manager** + **Memory manager** + **Service registry**.

**Process model** (P4.1): Each process now has an independent CNode (`cspace_cap` field), 256 slots (size_bits=8, 4KB). Falls back to root CNode when untyped memory is exhausted. Syscall endpoint installed at slot 0. ATA I/O port caps installed at slots 1-2 for fs_server (root CNode fallback uses dynamically allocated slots).

**Syscall dispatch** (`main.rs:~1366-2556`):
- ~~Single 1953-line `match label` block~~ — split into `services/rootserver/src/handlers/` (TASK-4)
- `handlers/core.rs`: process lifecycle + memory handlers (Phase 2)
- `handlers/fs.rs`: FS handlers (open, read, write, close, chmod, chown, symlink, readlink, mkdir, rmdir, unlink, rename, link, block_*) (Phase 2)
- `handlers/metadata.rs`: uid/gid handlers (Phase 2)
- `handlers/service.rs`: service registry + time + shutdown handlers (Phase 2)
- Input validation: `libnova::validate` with 34 host tests (P4.6)
- Each handler calls `validate_message_length` / `validate_mr_index` / `validate_cap_index` at entry
- Dispatch uses `SyscallNum::from_u64(label)` enum
- P4.6: inline Send handler validated, fs_server dispatch validates message length
- Non-FS Shell commands now use direct fs_server IPC fallback before spawn_fs_helper (P4.4)

**Architecture — NovaFS delegation (P4.5)**:
RootServer boot no longer formats disk or installs system binaries. A `create_deprecated_local_fs()` stub creates a minimal local NovaFS for boot-time compatibility. fs_server is the sole data authority — all file operations go through fs_server IPC (Shell commands via P4.4, exec binary loading via P4.4.6). DISK_FS and novafs_core::VFS are deprecated legacy stubs.

**Legacy — FS forwarding deadlock** (`main.rs:65`):
```rust
const FS_SYNC_FORWARD_ENABLED: bool = false;
```
Deadlock condition eliminated (P4.3). fs_server now has local ATA or RemoteBlockDevice fallback, no longer calls back to RootServer for block I/O.

**OOM protection** (`main.rs:67-94`):
- `deny_if_memory_pressure()` checks free slots (>64 reserve) and free RAM (>256KB)
- Run-time observable: `oom_stats`, `fragmentation_bytes`

#### 4b. fs_server (1328 lines)

File system service. **Current state**: has local ATA block device (P4.2), owns `novafs_core::ata::AtaBlockDevice` at init, deadlock resolved (P4.3). Falls back to `RemoteBlockDevice` (syscall-based) when ATA port cap unavailable (root CNode fallback). NOT yet the sole data plane authority.

**Architecture reality**:
- Depends on `libs/novafs-core/` as a normal crate dependency (no `include!()`)
- Has its own `FdEntry` table (32 entries) mirrored from RootServer
- `ENSURE_LOCAL_FS_FRESH`: lazy epoch-based refresh when RootServer's `FS_VIEW_EPOCH` changes
- **Not yet sole persistence authority** — RootServer's local NovaFS still active
- ATA I/O port caps installed at CNode slots 1-2 (independent CNode) or dynamic slots (root CNode fallback)
- P4.6: IPC entry validated with `validate_fs_request_min` at dispatch entry

**Protocol** (all via seL4 IPC Call, labels defined by `libnova::fs_ipc::FsLabel`):
| Label | Operation | Handler line |
|-------|-----------|-------------|
| 0xF500 | `FsLabel::Ping` — health check | 724 |
| 28 | `FsLabel::Refresh` — re-mount FS | 735 |
| 20 | `FsLabel::Open` | 746 |
| 23 | `FsLabel::Close` | 803 |
| 24 | `FsLabel::Unlink` | 829 |
| 29 | `FsLabel::Mkdir` | 845 |
| 30 | `FsLabel::Truncate` | 866 |
| 31 | `FsLabel::Chmod` | 890 |
| 32 | `FsLabel::Chown` | 914 |
| 33 | `FsLabel::Sync` | 939 |
| 36 | `FsLabel::List` | 949 |
| 38 | `FsLabel::Stat` | 970 |
| 34 | `FsLabel::Encrypt` | 986 |
| 35 | `FsLabel::Decrypt` | 1009 |
| 25 | `FsLabel::Rename` | 1032 |
| 26 | `FsLabel::Link` | 1077 |
| 27 | `FsLabel::Symlink` | 1122 |
| 22 | `FsLabel::Write` | 1167 |
| 37 | `FsLabel::Writetest` | 1237 |
| 21 | `FsLabel::Read` | 1265 |

#### 4c. serial_server (45 lines)

Trivial service. Registers as `serial.v1`, marks ready, idles. No actual serial forwarding implemented yet.

#### 4d. user_app (1730 lines)

User-mode multi-mode binary, launched as `/bin/hello`:
- **PID 0 mode**: Runs the full test suite (when spawned by RootServer at the right time)
- **Child/helper mode**: Parses `EarlyArgs` at ELF entry, dispatches to `run_fs_*` functions
- All helpers communicate with `fs_server` directly via `FS_LABEL_*` IPC calls (not via RootServer syscall)

### Layer 5: File System (NovaFS)

NovaFS implementation now lives in `libs/novafs-core/` and is consumed by both RootServer and fs_server.

| Property | Value |
|---|---|
| On-disk format | Custom, `NOVJ` magic (0x4E4F564A) |
| Block size | 512 bytes |
| Inode size | 128 bytes (4 per block) |
| Max inodes | 65,536 |
| Direct pointers | 12 × 4B = 48B of direct block pointers |
| Indirect | Single + double indirect blocks |
| Block allocation | Bitmap (separate inode + data bitmaps) |
| Directory entry | 32 bytes (4B inode + 28B name) |
| Root inode | Inode #1 |
| Block cache | Write-through, LRU eviction |
| Transparent encryption | ChaCha20 (custom impl), key from `SuperBlock.volume_key` |
| `BLOCK_SIZE=512` | 512 |

**Implemented operations**: 
- `open`/`read`/`write`/`close` (via Inode read_at/write_at)
- `mkdir`, `rmdir`, `unlink`, `rename`, `link` (hard), `symlink`
- `truncate` (extend + shrink), sparse files
- `chmod`, `chown` (UID/GID permission model, root=0 always allowed)
- `sync` (flush block cache)
- Encryption/decryption (inode flag bit)

### Layer 6: Service Discovery

- **Name-based registry**: `BTreeMap<String, ServiceEntry>` behind `Mutex`
- **States**: `Bootstrapping` → `Ready`
- **Version suffix**: `name.vN` format supported (e.g., `fs.v1`, `serial.v1`)
- **Epoch synchronization**: `FS_VIEW_EPOCH` — RootServer bumps epoch when local FS changes; fs_server checks epoch before operations and lazy-refreshes if stale

### Layer 7: Process Model

- **Max processes**: 32 (`MAX_PROCESSES`)
- **Max FDs per process**: 16 (`MAX_FDS`)
- **PID allocation**: simple linear allocation (`ProcessManager::allocate_pid`)
- **ELF loading**: static, non-PIE only (`-no-pie`, `relocation-model=static` forced globally)
- **IPC Buffer**: mapped at fixed `0x3000_0000` for all processes
- **Heap**: starts at `0x4000_0000` (managed via `sys_brk`)
- **MMAP top**: `0x7000_0000` (downward growing)
- **Process states**: `Created, Loaded, Configured, Running, Sleeping, Suspended, Terminated, BlockedOnRecv, BlockedOnWait, BlockedOnInput`
- **Fork**: `sys_fork` (label 14) — copies parent VSpace/CSpace
- **Wait**: `sys_waitpid` (label 7)
- **Zombie reaping**: `ProcessManager::exit_process` → notifies parent

### Layer 8: Memory Management

| Allocator | Granularity | Backend |
|---|---|---|
| `SlotAllocator` | 1 CSpace slot | Bitmap (4096 slots) |
| `UntypedAllocator` | Variable (seL4 untyped) | Linear scan with fragmentation tracking |
| `FrameAllocator` | 4K frame | Recycle pool + allocate from untyped |
| `SharedMemoryManager` | 4K pages | Reference-counted, auto-detach on exit |

- OOM admission: `deny_if_memory_pressure()` — 64 slot reserve + 256KB RAM minimum
- Fragmentation observable via `fragmentation_bytes()`, `oom_stats`

### Key Architectural Constraints

1. **`FS_SYNC_FORWARD_ENABLED=false`** (legacy flag): RootServer cannot synchronously forward FS calls to fs_server. **Deadlock condition resolved (P4.3)** — fs_server now has local ATA access via `AtaBlockDevice` or falls back to `RemoteBlockDevice` via syscall. Shell FS commands being migrated to direct IPC with fs_server (P4.4), after which RootServer's local NovaFS mount will be removed.

2. ~~`include!()` code sharing~~ **RESOLVED** (Phase 2.1): `fs_server` depends on `libs/novafs-core/` as a normal crate.

3. **No network stack**: All IPC is within a single host. No network drivers, sockets, or inter-host communication.

4. **Single-threaded RootServer**: All syscalls processed sequentially on one thread. No concurrency model.

5. **Static ELF only**: No PIE, no ASLR. Linker script, base addresses all hardcoded.

6. **QEMU TCG only**: QEMU TCG does not emulate PCID/INVPCID; kernel must be built with `-DKernelSupportPCID=OFF`. Haswell CPU model with pdpe1gb. Not tested on real hardware, KVM, or WHPX.

7. ~~**Magic syscall numbers**~~ **RESOLVED** (Phase 2.4): `SyscallNum` and `FsLabel` enums in libnova.

8. **Build split across platforms**: Kernel built in WSL/Linux. Rust services built on Windows. Shared target directory requires careful cargo lock management.

### Current Migration State (NovaFS-First)

```
[RootServer as FS authority] ──P4.4──▶ [fs_server as FS authority]
         │                                      │
         │  Owns NovaFS + block device           │  Owns ATA block device (P4.2)
         │  Shell FS ops: IPC fallback added     │  RemoteBlockDevice via syscall
         │   (12/16 commands, P4.4 Phase 1)      │  Deadlock resolved (P4.3)
         │  exec binary load: still VFS          │  NOT yet sole data authority
         │  P4.5 privilege reduction (pending)   │  ⚠ Dual NovaFS instances active
         └──────────────────────────────────────┘
                 FS_SYNC_FORWARD_ENABLED=false (legacy)
                 (deadlock eliminated — fs_server no longer
                  calls back for block I/O)

Shell FS command migration status (P4.4 Phase 1): direct fs_server IPC → spawn_fs_helper → LOCAL_VFS.
12 of 16 commands migrated. exec/runhello still via VFS (P4.4 Phase 2 pending).

Phase 4 remaining: exec IPC loading (P4.4.6), remove local NovaFS (P4.4.8),
RootServer privilege reduction (P4.5), debug syscall shutdown (P4.7).

### Repository Structure (Post-Cleanup)

```
E:\System/
├── Cargo.toml           — Workspace root (6 members)
├── CMakeLists.txt       — seL4 kernel CMake build + trace config
├── gcc.cmake            — seL4 cross-compilation toolchain
├── rust-toolchain.toml  — Nightly, x86_64-unknown-none
├── rustfmt.toml         — rustfmt config
│
├── .cargo/config.toml   — target + no-pie flags
├── .gitignore
├── .gitmodules
├── .env.example
├── Cargo.lock
│
├── kernel/seL4/         — submodule (ELF kernel)
├── libs/
│   ├── libnova/         — Core user-space library
│   ├── novafs-core/     — NovaFS on-disk format, block cache, VFS traits
│   ├── seL4-sys/        — seL4 FFI bindings
│   └── util_libs/       — submodule (seL4 utility libs)
├── services/
│   ├── rootserver/      — Init process: syscall, shell, NovaFS, mem, services
│   ├── fs_server/       — FS service (persistent proxy)
│   ├── serial_server/   — Serial service (stub)
│   └── user_app/        — Helper binary + test suite
├── tools/seL4_tools/    — submodule (elfloader, cmake helpers)
├── scripts/             — Build/run/test scripts
├── docs/                — Design docs + progress
└── skills/              — opencode skill definitions
```

### Known Frontiers (what's NOT done)

| Area | Status |
|---|---|
| Network stack | Not started |
| Real hardware boot | Never tested |
| AHCI/NVMe driver | Not started |
| VirtIO (net/block) | Library exists (`libs/util_libs/libvirtio`) but unused |
| PIE/ASLR support | Not started |
| Multi-threaded RootServer | Not started |
| fs_server as sole data plane authority | ✅ Phase 4 (direct ATA + local NovaFS) |
| Shell command fs_server IPC | ✅ Phase 4 (16/16 commands, direct IPC over fs_server); exec fallback retained |
| clippy debt | ✅ Zero errors (D2 completed) |
| Crash recovery / durability | P3.2/P3.3 host tests exist; not automated in CI |
| CI/CD pipeline | Basic workflow exists (fmt/check on Linux + Windows); QEMU not in CI |
| Host-native unit tests | ✅ 34 libnova tests + novafs-core tests |
| Rust edition 2024 migration | Not done (file-level warnings) |
| RISC-V port | Not started (config exists in seL4-sys) |
| PCID/INVPCID kernel features | Disabled (`-DKernelSupportPCID=OFF`) for QEMU TCG compat |

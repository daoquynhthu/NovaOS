# NovaOS — Code Index & Architecture Reality

> **Purpose**: Quick code navigation (front) + layered architecture description for AI agent context (back).  
> **Truth source**: Code only. If docs disagree with code, code wins.  
> **Generated**: 2026-07-06

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
| `syscall` — syscall stubs | `syscall.rs` | `sys_open` (329), `sys_read` (363), `sys_write` (387), `sys_close` (320), `sys_spawn` (206), `sys_yield` (60), `sys_exit` (65), `Error` enum (6) |
| `fs_ipc` — FS protocol | `fs_ipc.rs` | `FS_LABEL_OPEN=20` (4), `FS_LABEL_*` constants (4-23), `open_direct()` (64), `read_direct()` (105), `write_direct()` (89), `close_direct()` (81), all FS helpers (64-385) |
| `cap` — CNode ops | `cap.rs` | `CNode` (27), `cap_rights_new()` (16), `copy()`, `mint()`, `move_()`, `delete()`, `revoke()` |
| `console` — print macros | `console.rs` | `print!` (80), `println!` (84), `DebugConsole` (14), `UserConsole` (51) |
| `log` — leveled logging | `log.rs` | domain-gated `log_debug!`, `log_trace!` |
| `tcb` — TCB config | `tcb.rs` | TCB setup wrappers |
| `env` — arg iterator | `env.rs` | Early arg parsing |
| Syscall label map | `syscall.rs` | yield=4, exit=2, print=1, open=20, read=21, write=22, close=23, spawn=8, brk=3, ... (see file) |

### 4. Services

#### 4a. RootServer (`services/rootserver/src/`)

| What | File | Line |
|---|---|---|
| Entry point (`rust_main`) | `main.rs` | 464 |
| Main event loop (recv→dispatch→reply) | `main.rs` | 1274-1360 |
| Syscall dispatch `match label` | `main.rs` | 1366-3319 |
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
| Memory — `SlotAllocator` | `memory.rs` | 26 |
| Memory — `UntypedAllocator` | `memory.rs` | 150 |
| Memory — `FrameAllocator` | `memory.rs` | 446 |
| Memory — `MAX_CSPACE_SLOTS=4096` | `memory.rs` | 9 |
| Shared Memory — `SharedMemoryManager` | `shared_memory.rs` | — |
| ELF loader | `elf_loader.rs` | — |
| **NovaFS** — constants | `fs/novafs.rs` | 11-15 |
| NovaFS — `SuperBlock` | `fs/novafs.rs` | 18 |
| NovaFS — `DiskInode` | `fs/novafs.rs` | 32 |
| NovaFS — `DirEntry` | `fs/novafs.rs` | 51 |
| NovaFS — `NovaFS<D>` struct | `fs/novafs.rs` | 59 |
| NovaFS — `mount()` / `new()` | `fs/novafs.rs` | 67 |
| NovaFS — `format()` | `fs/novafs.rs` | 90 |
| NovaFS — block I/O (indirect resolution) | `fs/novafs.rs` | 399 |
| NovaFS — `Inode::read_at()` | `fs/novafs.rs` | 589 |
| NovaFS — `Inode::write_at()` | `fs/novafs.rs` | 641 |
| NovaFS — `Inode::control()` (truncate, chmod, chown) | `fs/novafs.rs` | 709 |
| NovaFS — directory ops (`lookup`, `create`, `list`, `link`, `rename`, `remove`) | `fs/novafs.rs` | 794-1337 |
| Block cache | `fs/block_cache.rs` | — |
| Block allocation strategy | `fs/strategy.rs` | — |
| **Drivers** — `BlockDevice` trait | `drivers/block.rs` | 1-4 |
| Drivers — ATA PIO | `drivers/ata.rs` | — |
| Drivers — keyboard | `drivers/keyboard.rs` | — |
| Drivers — serial | `drivers/serial.rs` | — |
| Drivers — timer (PIT/HPET) | `drivers/timer.rs` | — |
| Drivers — RTC | `drivers/rtc.rs` | — |
| **Arch** — x86_64 port I/O | `arch/x86_64/port_io.rs` | — |
| Arch — APIC | `arch/x86_64/apic.rs` | — |
| Arch — IOAPIC | `arch/x86_64/ioapic.rs` | — |
| Arch — ACPI | `arch/x86_64/acpi.rs` | — |
| Arch — PCI config | `arch/x86_64/pci.rs` | — |
| **Crypto** — ChaCha20 | `crypto.rs` | 3-104 |
| Tests | `tests.rs` | — |

#### 4b. fs_server (`services/fs_server/src/`)

| What | File | Line |
|---|---|---|
| Entry (`_start`) | `main.rs` | 639 |
| Main service loop | `main.rs` | 719-1323 |
| `FdEntry` struct | `main.rs` | 98-102 |
| `DISK_FS` / `FS_STATE` / `LOCAL_FS_EPOCH` statics | `main.rs` | 84-86 |
| Shared code via `include!()` | `main.rs` | 10-60 |
| — from rootserver: `crypto.rs`, `vfs.rs`, `block.rs`, `block_cache.rs`, `novafs.rs`, `strategy.rs` | | |
| Handler: `local_open` → `open_inode` | `main.rs` | 273-294 |
| FS protocol dispatch | `main.rs` | 724-1321 |

#### 4c. serial_server (`services/serial_server/src/`)

| What | File | Line |
|---|---|---|
| Entry (`_start`) | `main.rs` | 13 |
| Register `serial.v1` | `main.rs` | 23 |
| Mark ready | `main.rs` | 24 |
| Idle loop (`sys_yield`) | `main.rs` | 37-39 |

#### 4d. user_app (`services/user_app/src/`)

| What | File | Line |
|---|---|---|
| Entry (`_start`) | `main.rs` | 1288 |
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
| Workspace Cargo.toml | `Cargo.toml` | 1-36 |
| Workspace members (6 crates) | `Cargo.toml` | 2-9 |
| Workspace lints | `Cargo.toml` | 21-36 |
| Cargo target config | `.cargo/config.toml` | 1-5 |
| Rust toolchain (nightly) | `rust-toolchain.toml` | 1-4 |
| Rustfmt config | `rustfmt.toml` | 1-10 |
| Root CMakeLists.txt | `CMakeLists.txt` | 1-133 |
| Kernel config defaults | `CMakeLists.txt` | 42-56 |
| Trace level system | `CMakeLists.txt` | 58-80 |
| Build script (Win) | `scripts/build.ps1` | 1-37 |
| Build script (Linux) | `scripts/build.sh` | 1-53 |
| Test script (Win) | `scripts/test.ps1` | 1-1095 |
| Test script (Linux) | `scripts/test.sh` | 1-67 |
| QEMU launcher (Win) | `scripts/run_qemu.ps1` | 1-46 |
| QEMU launcher (Linux) | `scripts/run_qemu.sh` | 1-48 |
| Environment setup (Win) | `scripts/init_env.ps1` | 1-35 |
| Environment setup (Linux) | `scripts/init_env.sh` | 1-43 |
| ELF/Multiboot checker | `scripts/check_mb.py` | 1-114 |
| .gitignore | `.gitignore` | 1-65 |
| .gitmodules (3 submodules) | `.gitmodules` | 1-9 |
| Submodule pins | seL4 `04fba8577`, tools `fbfc63978`, util_libs `07a7e15b8` | — |

### 6. Documentation

| File | Content |
|---|---|
| `docs/Project_Progress.md` | Progress log (single source of truth for project status) |
| `docs/HANDOVER.md` | Architecture handover doc (NovaFS-centric) |
| `docs/NovaOS_Proposal.md` | Design proposal / vision |
| `docs/NovaOS_Syscall_Design.md` | Syscall design notes |
| `docs/NovaOS_Verification_Spec.md` | Verification spec |
| `docs/NovaOS_Memory_Error_Spec.md` | Memory error spec |
| `skills/NovaOS_Project/SKILL.md` | opencode skill for NovaOS development |

---

## II. Architecture Reality

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

`libnova` is a `no_std` Rust library providing all user-space abstractions:

```
libnova/
├── ipc.rs        — Raw seL4 IPC primitives (call/send/recv/reply/reply_recv)
├── syscall.rs    — Per-syscall client stubs (sys_open, sys_read, etc.)
├── fs_ipc.rs     — FS protocol direct-call helpers (open_direct, etc.)
├── cap.rs        — CNode capability wrappers (copy/mint/move/delete/revoke)
├── console.rs    — print!/println! macros (debug vs user console)
├── log.rs        — Domain-gated logging (log_debug!, log_trace!)
├── tcb.rs        — TCB configuration
└── env.rs        — Argument iterator
```

**Key architectural note**: Syscall numbers are magic numbers scattered in code:
- `MessageInfo::new(1, ..)` = sys_print
- `MessageInfo::new(20, ..)` = sys_open
- No shared `#[repr(u64)]` enum exists — client stubs and server dispatch both hardcode the same numbers

### Layer 4: Services

#### 4a. RootServer (3328 lines)

The initial user-mode process. RootServer is the **syscall dispatch center** + **NovaFS data plane** + **Shell** + **Process manager** + **Memory manager** + **Service registry**.

**Syscall dispatch** (`main.rs:1366-3319`):
- Single 1953-line `match label { 1..=50 => { ... } }` block
- Labels 1-13: core (print, exit, brk, yield, wait, spawn, get_pid, sleep, shm)
- Labels 20-23: FS (open, read, write, close)
- Labels 24-29: metadata (chmod, chown, symlink, readlink, get/set uid/gid)
- Labels 30-33: services (register, lookup, set_ready)
- Labels 34-46: more FS, mmap, block I/O, time, epoch, shutdown
- Label 5: VM fault handler

**Architecture constraint — FS forwarding deadlock** (`main.rs:65`):
```rust
const FS_SYNC_FORWARD_ENABLED: bool = false;
```
RootServer cannot synchronously `Call` fs_server and have fs_server `Call` back (deadlock). All fs_server communication uses **async helper pattern**: shell spawns `/bin/hello fs_X <args>` which directly calls fs_server via IPC.

**OOM protection** (`main.rs:67-94`):
- `deny_if_memory_pressure()` checks free slots (>64 reserve) and free RAM (>256KB)
- Run-time observable: `oom_stats`, `fragmentation_bytes`

#### 4b. fs_server (1328 lines)

File system service. **Current state**: syscall-backed persistent proxy, NOT the real data plane owner.

**Architecture reality**:
- Shares NovaFS code via `include!("../../rootserver/src/fs/novafs.rs")` — compile-time copy, not a library dependency
- Same for `vfs.rs`, `block_cache.rs`, `strategy.rs`, `crypto.rs`, `block.rs`
- Has its own `FdEntry` table (32 entries) mirrored from RootServer
- `ENSURE_LOCAL_FS_FRESH` pattern: before handling FS requests, checks if RootServer's `FS_VIEW_EPOCH` has changed; if so, re-mounts NovaFS from block device (lazy epoch-based refresh)
- **Not yet the persistence authority** — RootServer's local NovaFS is still the real data plane

**Protocol** (all via seL4 IPC Call):
| Label | Operation | Handler line |
|-------|-----------|-------------|
| 0xF500 | `FS_LABEL_PING` — health check | 724 |
| 28 | `FS_LABEL_REFRESH` — re-mount FS | 735 |
| 20 | `FS_LABEL_OPEN` | 746 |
| 23 | `FS_LABEL_CLOSE` | 803 |
| 24 | `FS_LABEL_UNLINK` | 829 |
| 29 | `FS_LABEL_MKDIR` | 845 |
| 30 | `FS_LABEL_TRUNCATE` | 866 |
| 31 | `FS_LABEL_CHMOD` | 890 |
| 32 | `FS_LABEL_CHOWN` | 914 |
| 33 | `FS_LABEL_SYNC` | 939 |
| 36 | `FS_LABEL_LIST` | 949 |
| 38 | `FS_LABEL_STAT` | 970 |
| 34 | `FS_LABEL_ENCRYPT` | 986 |
| 35 | `FS_LABEL_DECRYPT` | 1009 |
| 25 | `FS_LABEL_RENAME` | 1032 |
| 26 | `FS_LABEL_LINK` | 1077 |
| 27 | `FS_LABEL_SYMLINK` | 1122 |
| 22 | `FS_LABEL_WRITE` | 1167 |
| 37 | `FS_LABEL_WRITETEST` | 1237 |
| 21 | `FS_LABEL_READ` | 1265 |

#### 4c. serial_server (45 lines)

Trivial service. Registers as `serial.v1`, marks ready, idles. No actual serial forwarding implemented yet.

#### 4d. user_app (1730 lines)

User-mode multi-mode binary, launched as `/bin/hello`:
- **PID 0 mode**: Runs the full test suite (when spawned by RootServer at the right time)
- **Child/helper mode**: Parses `EarlyArgs` at ELF entry, dispatches to `run_fs_*` functions
- All helpers communicate with `fs_server` directly via `FS_LABEL_*` IPC calls (not via RootServer syscall)

### Layer 5: File System (NovaFS)

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

1. **`FS_SYNC_FORWARD_ENABLED=false`**: RootServer cannot synchronously forward FS calls to fs_server because fs_server calls back into RootServer's syscall endpoint (same-thread deadlock). Architecturally unsolved.

2. **`include!()` code sharing**: `fs_server` includes rootserver source files at compile time (`include!("../../rootserver/src/...")`). This creates tight coupling — changes to rootserver can silently break fs_server. The `dead_code` lint had to be relaxed for fs_server because of unused rootserver code.

3. **No network stack**: All IPC is within a single host. No network drivers, sockets, or inter-host communication.

4. **Single-threaded RootServer**: All syscalls processed sequentially on one thread. No concurrency model.

5. **Static ELF only**: No PIE, no ASLR. Linker script, base addresses all hardcoded.

6. **QEMU-only**: Never booted on real hardware. ATA PIO driver assumes emulated disk, no AHCI/NVMe.

7. **Magic syscall numbers**: No shared enum for syscall labels — labels are numeric constants duplicated in both client stubs (`syscall.rs`) and server dispatch (`main.rs`).

8. **Build split across platforms**: Kernel must be built on Linux (WSL/native). Rust services on Windows. The `build.sh` workflow bridges this.

### Current Migration State (NovaFS-First)

```
[RootServer as FS authority] ──migrating──▶ [fs_server as FS authority]
         │                                           │
         │  Owns NovaFS + block device               │  Persistent proxy only
         │  Shell commands partially delegated        │  Real NovaFS via include!()
         │   via /bin/hello helpers                   │  Epoch-based lazy refresh
         │                                           │  Not yet direct block device owner
         └───────────────────────────────────────────┘
                    FS_SYNC_FORWARD_ENABLED=false
                    (architectural deadlock)
```

Service migration completed (shell commands via fs_server helper): `cat`, `touch`, `cp`, `mv`, `rm`, `ln` (hard+sym), `mkdir`, `truncate`, `chmod`, `chown`, `sync`, `echo > file`, `encrypt`, `decrypt`, `cd`.

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
| fs_server as real data plane authority | In progress (blocked by deadlock) |
| Shell command full service migration | In progress (basic commands done) |
| Crash recovery / durability testing | Not automated |
| CI/CD pipeline | Not started |
| Rust edition 2024 migration | Not done (file-level warnings) |
| RISC-V port | Not started (config exists in seL4-sys) |
| std environment | Not applicable (no_std everywhere) |

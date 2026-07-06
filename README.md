# NovaOS

NovaOS is a microkernel-based operating system built on top of the seL4 formally verified microkernel. The project explores capability-based security, a minimal RootServer, and a NovaFS user-space file system service.

> **Status**: early alpha / bring-up phase. APIs, on-disk formats, and the service boundary layout are all subject to change.

## Overview

- **Kernel**: seL4 (x86_64 pc99)
- **User space**: `no_std` Rust services
  - `rootserver` — init process, syscall dispatch, shell, memory management
  - `fs_server` — file system service (NovaFS)
  - `serial_server` — serial port service (stub)
  - `user_app` — helper binary and integration test runner
- **Core library**: `libnova` — seL4 IPC, capability wrappers, syscall stubs
- **File system**: NovaFS — custom 512-byte block FS with transparent encryption

## Building

### Requirements

- Rust nightly toolchain (pinned in `rust-toolchain.toml`)
- CMake >= 3.18, Ninja
- QEMU (x86_64)
- PowerShell 7+ (Windows) or bash (Linux/WSL)
- seL4 Python build dependencies: `pip install sel4-deps`

### Quick start

```powershell
# Windows (Rust services built natively; kernel built in WSL/Linux)
scripts/init_env.ps1
scripts/build.ps1
$env:NOVA_TEST_TIMEOUT_SECONDS = 120
scripts/test.ps1
```

```bash
# Linux / WSL
scripts/init_env.sh
scripts/build.sh
NOVA_TEST_TIMEOUT_SECONDS=120 ./scripts/test.sh
```

See `docs/PLAN.md`, `docs/INDEX.md`, and `AGENT.md` for the project roadmap, code index, and development workflow.

## License

NovaOS is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

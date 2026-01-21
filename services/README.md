# NovaOS Services

This directory contains the various microservices that make up the NovaOS userspace.

## Directory Structure

*   **rootserver/**: The initial process started by the seL4 kernel. It acts as the "Init" process, responsible for bootstrapping other services, managing resources (Untyped Memory), and handling process lifecycle. Ideally, it should contain minimal logic.
*   **serial_server/**: (Planned) Manages the Serial Port (UART). Provides logging and console input services to other processes via IPC.
*   **fs_server/**: (Planned) Manages the Block Device (ATA) and File System (NovaFS). Handles file I/O requests from other processes.
*   **user_app/**: A sample user application demonstrating system calls.

## Architecture Evolution (Monolith -> Microkernel)

Currently, `rootserver` implements most functionality (Drivers, FS, Shell). The goal is to migrate these into the separate server processes listed above.

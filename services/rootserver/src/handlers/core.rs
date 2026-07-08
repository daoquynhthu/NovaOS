//! Core syscall handlers (print, exit, brk, yield, wait, spawn, get_pid, sleep,
//! shm).

use crate::handlers::SyscallContext;
use crate::process::{get_process_manager, ProcessState};
use libnova::ipc::MessageInfo;
use libnova::validate::ValidateError;

/// Handle `sys_yield` — reply immediately with an empty message.
pub fn handle_yield() -> (MessageInfo, [u64; 4]) {
    (MessageInfo::new(0, 0, 0, 0), [0u64; 4])
}

/// Handle `sys_get_pid` — return the caller's PID in MR0.
pub fn handle_get_pid(pid: usize) -> (MessageInfo, [u64; 4]) {
    let mut reply_mrs = [0u64; 4];
    reply_mrs[0] = pid as u64;
    (MessageInfo::new(0, 0, 0, 1), reply_mrs)
}

/// Handle `sys_sleep` — mark the process as sleeping and save the caller.
/// Returns `Ok(false)` when the caller is blocked (no immediate reply),
/// or `Ok(true)` with a reply if the sleep duration is zero.
pub fn handle_sleep(
    ctx: &mut SyscallContext<'_>,
    system_tick: u64,
) -> Result<(MessageInfo, [u64; 4], bool), &'static str> {
    if let Err(_e) = validate_one_mr(ctx) {
        // Malformed sleep request; reply with success (0 ticks) rather than
        // leaving the caller blocked forever.
        let mut reply_mrs = [0u64; 4];
        reply_mrs[0] = 0;
        return Ok((MessageInfo::new(0, 0, 0, 1), reply_mrs, true));
    }

    let pid = ctx.pid;
    let ticks = ctx.mrs[0];
    let wake_at_tick = system_tick + ticks;
    let slot_allocator = &mut *ctx.slot_allocator;
    let mut pm = get_process_manager();

    if ticks == 0 {
        let mut reply_mrs = [0u64; 4];
        reply_mrs[0] = 0;
        return Ok((MessageInfo::new(0, 0, 0, 1), reply_mrs, true));
    }

    let root_cnode =
        sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as sel4_sys::seL4_CPtr;
    if let Some(p) = pm.get_process_mut(pid) {
        p.state = ProcessState::Sleeping;
        p.wake_at_tick = wake_at_tick;
        if let Err(_e) = p.save_caller(root_cnode, slot_allocator) {
            return Err("Failed to save caller for sleep");
        }
        Ok((MessageInfo::new(0, 0, 0, 0), [0u64; 4], false))
    } else {
        Err("Process not found for sleep")
    }
}

/// Handle `sys_waitpid(pid, options)`.
///
/// Returns `(reply_info, reply_mrs, need_reply)`. `need_reply == false` means
/// the caller is blocked waiting for a child.
pub fn handle_wait(ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    if let Err(e) = validate_two_mrs(ctx) {
        return error_reply(e);
    }

    let target_pid = ctx.mrs[0] as isize;
    let options = ctx.mrs[1] as usize;
    let pid = ctx.pid;
    let slot_allocator = &mut *ctx.slot_allocator;

    let mut pm = get_process_manager();
    match pm.wait_for_child(pid, target_pid) {
        Ok(Some((child_pid, status))) => {
            let mut reply_mrs = [0u64; 4];
            reply_mrs[0] = child_pid as u64;
            reply_mrs[1] = status as u64;
            (MessageInfo::new(0, 0, 0, 2), reply_mrs, true)
        }
        Ok(None) => {
            if (options & 1) != 0 {
                // WNOHANG
                let mut reply_mrs = [0u64; 4];
                reply_mrs[0] = 0;
                reply_mrs[1] = 0;
                (MessageInfo::new(0, 0, 0, 2), reply_mrs, true)
            } else {
                if let Some(p) = pm.get_process_mut(pid) {
                    p.state = ProcessState::BlockedOnWait;
                    p.waiting_for_child = if target_pid > 0 {
                        Some(target_pid as usize)
                    } else {
                        None
                    };

                    let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode
                        as sel4_sys::seL4_CPtr;
                    if let Err(_e) = p.save_caller(root_cnode, slot_allocator) {
                        let mut reply_mrs = [0u64; 4];
                        reply_mrs[0] = (-1i64) as u64;
                        (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
                    } else {
                        (MessageInfo::new(0, 0, 0, 0), [0u64; 4], false)
                    }
                } else {
                    let mut reply_mrs = [0u64; 4];
                    reply_mrs[0] = (-1i64) as u64;
                    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
                }
            }
        }
        Err(_) => {
            let mut reply_mrs = [0u64; 4];
            reply_mrs[0] = (-1i64) as u64;
            (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
        }
    }
}

fn validate_message_only(ctx: &SyscallContext<'_>) -> Result<(), ValidateError> {
    libnova::validate::validate_message_length(ctx.info)
}

fn validate_one_mr(ctx: &SyscallContext<'_>) -> Result<(), ValidateError> {
    libnova::validate::validate_message_length(ctx.info)?;
    libnova::validate::validate_mr_index(ctx.info, 0)?;
    Ok(())
}

fn validate_two_mrs(ctx: &SyscallContext<'_>) -> Result<(), ValidateError> {
    validate_one_mr(ctx)?;
    libnova::validate::validate_mr_index(ctx.info, 1)?;
    Ok(())
}

/// Handle `sys_kill(pid, sig)`.
pub fn handle_kill(ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    if let Err(e) = validate_two_mrs(ctx) {
        return error_reply(e);
    }

    let target_pid = ctx.mrs[0] as usize;
    let sig = ctx.mrs[1] as usize;
    let pid = ctx.pid;
    let slot_allocator = &mut *ctx.slot_allocator;
    let frame_allocator = &mut *ctx.frame_allocator;

    let mut reply_mrs = [0u64; 4];

    if sig == 9 || sig == 15 {
        let cnode =
            sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as sel4_sys::seL4_CPtr;
        let mut pm = get_process_manager();

        let allowed = if let Some(caller) = pm.get_process(pid) {
            if let Some(target) = pm.get_process(target_pid) {
                caller.can_control(target)
            } else {
                true // Target doesn't exist; exit_process will fail gracefully.
            }
        } else {
            false
        };

        if allowed {
            unsafe {
                let _ = (*core::ptr::addr_of_mut!(crate::SHARED_MEMORY_MANAGER))
                    .detach_process(target_pid, slot_allocator);
            }
            if let Err(_e) = pm.exit_process(target_pid, -1, cnode, slot_allocator, frame_allocator)
            {
                reply_mrs[0] = (-1i64) as u64;
            } else {
                reply_mrs[0] = 0;
            }
        } else {
            reply_mrs[0] = (-1i64) as u64;
        }
    } else {
        reply_mrs[0] = (-1i64) as u64;
    }

    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

/// Handle `sys_exit(code)`.
///
/// This handler has side effects (process teardown, deferred service spawn)
/// and never replies to the exiting process.
pub fn handle_exit(ctx: &mut SyscallContext<'_>) {
    if let Err(_e) = validate_one_mr(ctx) {
        // Exit is terminal; if the message is malformed we still tear down the
        // process but log it.
        println!("[KERNEL] sys_exit: malformed message, defaulting code to 0");
    }

    let code = ctx.mrs[0] as isize;
    let pid = ctx.pid;

    println!("[INFO] Process {} exited with code: {}", pid, code);

    unsafe {
        let _ = (*core::ptr::addr_of_mut!(crate::SHARED_MEMORY_MANAGER))
            .detach_process(pid, ctx.slot_allocator);
    }

    if pid == 0 && code == 0 {
        println!("[TEST] PASSED");
    }

    let cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as sel4_sys::seL4_CPtr;
    if let Err(_e) = get_process_manager().exit_process(
        pid,
        code,
        cnode,
        ctx.slot_allocator,
        ctx.frame_allocator,
    ) {
        println!("[KERNEL] Failed to exit process {}", pid);
        get_process_manager().remove_process(pid);
    }

    let helper_prompt_released = ctx.shell.on_process_exit(pid, code);
    if helper_prompt_released {
        if let Err(_e) = crate::refresh_local_fs_view(ctx.ata.clone()) {
            println!("[KERNEL] Failed to refresh local FS view after helper exit");
        }
    }

    if pid == 0 && !*ctx.deferred_services_spawned {
        println!("[KERNEL] Main test process exited. Launching deferred service processes...");
        crate::services::register("serial.v1", ctx.test_service_slot);
        println!(
            "[KERNEL] Service 'serial.v1' registered (placeholder endpoint {}).",
            ctx.test_service_slot
        );

        let fs_service_slot = match ctx.slot_allocator.alloc() {
            Ok(slot) => slot,
            Err(_e) => {
                println!("[KERNEL] Failed to allocate fs service slot");
                0
            }
        };

        if fs_service_slot != 0 {
            let root_cnode =
                sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode as sel4_sys::seL4_CPtr;
            let cnode_depth = sel4_sys::seL4_WordBits as u8;
            let mint_err = unsafe {
                sel4_sys::seL4_CNode_Mint(
                    root_cnode,
                    fs_service_slot,
                    cnode_depth,
                    root_cnode,
                    ctx.fs_service_ep_cap,
                    cnode_depth,
                    libnova::cap::cap_rights_new(false, true, true, true),
                    203,
                )
            };
            if mint_err != 0.into() {
                println!(
                    "[KERNEL] Failed to mint dedicated fs service cap: {:?}",
                    mint_err
                );
            }
        }

        let fs_service_slot_arg = alloc::format!("{}", ctx.fs_service_ep_cap);
        let fs_args = [fs_service_slot_arg.as_str()];
        crate::spawn_boot_process(
            ctx.boot_info,
            ctx.allocator,
            ctx.slot_allocator,
            ctx.frame_allocator,
            ctx.syscall_ep_cap,
            "fs_server",
            "fs_server",
            103,
            &fs_args,
        );
        if fs_service_slot != 0 {
            crate::services::register("fs.v1", fs_service_slot);
            println!(
                "[KERNEL] Service 'fs.v1' rebound to dedicated endpoint slot {}.",
                fs_service_slot
            );
        }
        *ctx.deferred_services_spawned = true;
    }
}

/// Handle `sys_spawn(path, args, envs)`.
pub fn handle_spawn(ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    if let Err(e) = validate_message_only(ctx) {
        return error_reply(e);
    }
    if let Err(e) = validate_two_mrs(ctx) {
        return error_reply(e);
    }

    let pid = ctx.pid;
    let msg_len = ctx.info.length() as usize;
    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };

    println!(
        "[KERNEL] sys_spawn debug: MR0={:x}, MR1={:x}, MR2={:x}, MR3={:x}, len={}",
        ctx.mrs[0], ctx.mrs[1], ctx.mrs[2], ctx.mrs[3], msg_len
    );

    let get_word = |idx: usize| -> usize {
        if idx < 4 {
            ctx.mrs[idx] as usize
        } else {
            ipc_buf.msg[idx] as usize
        }
    };

    let w0 = get_word(0);
    let (path_len, args_count, mut envs_count, mut current_mr) = if w0 == 0xCAFEBABE {
        println!("[KERNEL] sys_spawn: New Protocol Detected");
        (get_word(1), get_word(2), get_word(5), 6)
    } else {
        (w0, get_word(1), get_word(4), 5)
    };

    if envs_count > 256 {
        println!(
            "[KERNEL] sys_spawn: Suspicious envs_count {:x}, resetting to 0",
            envs_count
        );
        envs_count = 0;
    }

    let mut reply_mrs = [0u64; 4];
    if msg_len < 3 {
        println!(
            "[KERNEL] sys_spawn: Invalid message length {} (expected >= 3).",
            msg_len
        );
        reply_mrs[0] = usize::MAX as u64;
        return (MessageInfo::new(0, 0, 0, 1), reply_mrs, true);
    }
    if path_len > 4096 {
        println!(
            "[KERNEL] sys_spawn: Path too long ({}). Aborting.",
            path_len
        );
        reply_mrs[0] = usize::MAX as u64;
        return (MessageInfo::new(0, 0, 0, 1), reply_mrs, true);
    }
    if args_count > 256 {
        println!(
            "[KERNEL] sys_spawn: Too many args ({}). Aborting.",
            args_count
        );
        reply_mrs[0] = usize::MAX as u64;
        return (MessageInfo::new(0, 0, 0, 1), reply_mrs, true);
    }
    if envs_count > 256 {
        println!(
            "[KERNEL] sys_spawn: Too many envs ({}). Aborting.",
            envs_count
        );
        reply_mrs[0] = usize::MAX as u64;
        return (MessageInfo::new(0, 0, 0, 1), reply_mrs, true);
    }

    let read_bytes = |len: usize, start_mr: &mut usize| -> Option<alloc::vec::Vec<u8>> {
        if len > 4096 {
            return None;
        }
        let words = len.div_ceil(8);
        if *start_mr + words > msg_len {
            return None;
        }
        let mut bytes = alloc::vec![0u8; len];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let word_idx = *start_mr + (i / 8);
            let byte_idx = i % 8;
            let word = if word_idx < 4 {
                ctx.mrs[word_idx]
            } else {
                ipc_buf.msg[word_idx]
            };
            *byte = ((word >> (byte_idx * 8)) & 0xFF) as u8;
        }
        *start_mr += words;
        Some(bytes)
    };

    let path_bytes = match read_bytes(path_len, &mut current_mr) {
        Some(b) => b,
        None => {
            println!("[KERNEL] sys_spawn: Path too long during read.");
            reply_mrs[0] = usize::MAX as u64;
            return (MessageInfo::new(0, 0, 0, 1), reply_mrs, true);
        }
    };
    let path = alloc::string::String::from(core::str::from_utf8(&path_bytes).unwrap_or(""));

    let mut args_strings = alloc::vec::Vec::new();
    for _ in 0..args_count {
        let len_word = if current_mr < 4 {
            ctx.mrs[current_mr]
        } else {
            ipc_buf.msg[current_mr]
        };
        let arg_len = len_word as usize;
        current_mr += 1;

        match read_bytes(arg_len, &mut current_mr) {
            Some(arg_bytes) => {
                args_strings.push(alloc::string::String::from_utf8(arg_bytes).unwrap_or_default());
            }
            None => {
                println!("[KERNEL] sys_spawn: Arg too long.");
                reply_mrs[0] = usize::MAX as u64;
                return (MessageInfo::new(0, 0, 0, 1), reply_mrs, true);
            }
        }
    }
    let args_refs: alloc::vec::Vec<&str> = args_strings.iter().map(|s| s.as_str()).collect();

    let mut envs_strings = alloc::vec::Vec::new();
    for _ in 0..envs_count {
        let len_word = if current_mr < 4 {
            ctx.mrs[current_mr]
        } else {
            ipc_buf.msg[current_mr]
        };
        let env_len = len_word as usize;
        current_mr += 1;

        match read_bytes(env_len, &mut current_mr) {
            Some(env_bytes) => {
                envs_strings.push(alloc::string::String::from_utf8(env_bytes).unwrap_or_default());
            }
            None => {
                println!("[KERNEL] sys_spawn: Env too long.");
                reply_mrs[0] = usize::MAX as u64;
                return (MessageInfo::new(0, 0, 0, 1), reply_mrs, true);
            }
        }
    }
    let envs_refs: alloc::vec::Vec<&str> = envs_strings.iter().map(|s| s.as_str()).collect();

    println!(
        "[KERNEL] sys_spawn: Request to spawn '{}' from PID {} with args {:?} envs {:?}",
        path, pid, args_refs, envs_refs
    );

    let mut success_pid = -1isize;

    let (caller_uid, caller_gid) = get_process_manager()
        .get_process(pid)
        .map(|p| (p.uid, p.gid))
        .unwrap_or((0, 0));

    if crate::deny_if_memory_pressure(
        ctx.slot_allocator,
        ctx.allocator,
        ctx.boot_info,
        48,
        "sys_spawn",
    ) {
        reply_mrs[0] = (-1i64) as u64;
        return (MessageInfo::new(0, 0, 0, 1), reply_mrs, true);
    }

    let file_data = if let Some(fs) = crate::fs::DISK_FS.lock().as_ref() {
        if let Ok(inode) = novafs_core::resolve_path(fs, "/", &path) {
            if !novafs_core::check_permission(&inode, caller_uid, caller_gid, 5) {
                println!("[KERNEL] sys_spawn: Permission denied for '{}'", path);
                None
            } else {
                let size = inode.metadata().map(|m| m.size).unwrap_or(0);
                if size > 1024 * 1024 {
                    println!("[KERNEL] sys_spawn: File too large ({} bytes)", size);
                    None
                } else {
                    let mut buf = alloc::vec![0u8; size];
                    if inode.read_at(0, &mut buf).is_ok() {
                        Some(buf)
                    } else {
                        println!("[KERNEL] sys_spawn: Failed to read file");
                        None
                    }
                }
            }
        } else {
            println!("[KERNEL] sys_spawn: File not found: {}", path);
            None
        }
    } else {
        None
    };

    if let Some(data) = file_data {
        if let Ok(badged_ep_slot) = ctx.slot_allocator.alloc() {
            let new_pid = get_process_manager().allocate_pid().unwrap_or(999);

            if new_pid != 999 {
                let badge = new_pid + 100;
                let root_cnode = sel4_sys::seL4_RootCNodeCapSlots::seL4_CapInitThreadCNode
                    as sel4_sys::seL4_CPtr;
                let cnode_depth = sel4_sys::seL4_WordBits;

                let err = unsafe {
                    sel4_sys::seL4_CNode_Mint(
                        root_cnode,
                        badged_ep_slot,
                        cnode_depth as u8,
                        root_cnode,
                        ctx.syscall_ep_cap,
                        cnode_depth as u8,
                        libnova::cap::cap_rights_new(false, true, true, true),
                        badge as u64,
                    )
                };

                if err == 0.into() {
                    match crate::process::Process::spawn(
                        ctx.allocator,
                        ctx.slot_allocator,
                        ctx.frame_allocator,
                        ctx.boot_info,
                        &path,
                        &data,
                        &args_refs,
                        &envs_refs,
                        100,
                        badged_ep_slot,
                        pid,
                        caller_uid,
                        caller_gid,
                    ) {
                        Ok(p) => {
                            if get_process_manager().add_process_at(new_pid, p).is_ok() {
                                success_pid = new_pid as isize;
                                println!("[KERNEL] Spawned process {} (PID {})", path, new_pid);
                            } else {
                                println!("[KERNEL] Failed to add process to manager");
                            }
                        }
                        Err(_e) => {
                            println!("[KERNEL] Process::spawn failed");
                        }
                    }
                } else {
                    println!("[KERNEL] Failed to mint endpoint for new process");
                }
            } else {
                println!("[KERNEL] No PID available");
            }
        } else {
            println!("[KERNEL] No slots available");
        }
    }

    reply_mrs[0] = success_pid as u64;
    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

/// Handle `sys_fork()`.
pub fn handle_fork(ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    if let Err(e) = validate_message_only(ctx) {
        return error_reply(e);
    }
    let pid = ctx.pid;
    let fork_res = {
        let pm = get_process_manager();
        match pm.get_process(pid) {
            Some(parent) => crate::process::Process::fork_from(
                parent,
                ctx.allocator,
                ctx.slot_allocator,
                ctx.frame_allocator,
                ctx.boot_info,
                pid,
            ),
            None => Err(libnova::syscall::Error::InvalidArgument),
        }
    };

    let mut reply_mrs = [0u64; 4];
    match fork_res {
        Ok(child) => {
            let mut pm = get_process_manager();
            match pm.add_process(child) {
                Ok(child_pid) => {
                    reply_mrs[0] = child_pid as u64;
                }
                Err(_e) => {
                    println!("[KERNEL] sys_fork: Failed to add child process");
                    reply_mrs[0] = (-1i64) as u64;
                }
            }
        }
        Err(_e) => {
            reply_mrs[0] = (-1i64) as u64;
        }
    }

    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

/// Handle `sys_brk(new_addr)`.
pub fn handle_brk(ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    if let Err(e) = validate_one_mr(ctx) {
        return error_reply(e);
    }

    let mut reply_mrs = [0u64; 4];
    let new_addr = ctx.mrs[0] as usize;

    if new_addr >= 0x8000_0000 {
        println!("[KERNEL] sys_brk invalid address: 0x{:x}", new_addr);
        return (MessageInfo::new(0, 0, 0, 1), reply_mrs, true);
    }

    let pid = ctx.pid;
    if let Some(p) = get_process_manager().get_process_mut(pid) {
        match p.brk(
            ctx.allocator,
            ctx.slot_allocator,
            ctx.frame_allocator,
            ctx.boot_info,
            new_addr,
        ) {
            Ok(new_brk) => {
                reply_mrs[0] = new_brk as u64;
            }
            Err(e) => {
                println!("[KERNEL] sys_brk failed for pid {}: {:?}", pid, e);
                reply_mrs[0] = 0;
            }
        }
    } else {
        println!(
            "[KERNEL] Process {} not found for sys_brk; returning 0",
            pid
        );
        reply_mrs[0] = 0;
    }

    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

/// Handle `sys_shm_alloc(size)`.
pub fn handle_shm_alloc(ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    if let Err(e) = validate_one_mr(ctx) {
        return error_reply(e);
    }

    let mut reply_mrs = [0u64; 4];
    let size = ctx.mrs[0] as usize;
    let page_count = size
        .checked_add(4095)
        .map(|v| v / 4096)
        .unwrap_or(usize::MAX);

    if crate::deny_if_memory_pressure(
        ctx.slot_allocator,
        ctx.allocator,
        ctx.boot_info,
        page_count.max(1),
        "sys_shm_alloc",
    ) {
        reply_mrs[0] = 0;
    } else {
        unsafe {
            match (*core::ptr::addr_of_mut!(crate::SHARED_MEMORY_MANAGER)).create_shared_region(
                ctx.allocator,
                ctx.slot_allocator,
                ctx.boot_info,
                size,
            ) {
                Ok(key) => {
                    reply_mrs[0] = (key + 1) as u64;
                }
                Err(e) => {
                    println!("[KERNEL] sys_shm_alloc failed: {:?}", e);
                    reply_mrs[0] = 0;
                }
            }
        }
    }

    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

/// Handle `sys_shm_map(key, vaddr)`.
pub fn handle_shm_map(ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    if let Err(e) = validate_two_mrs(ctx) {
        return error_reply(e);
    }

    let mut reply_mrs = [0u64; 4];
    let key = ctx.mrs[0] as usize;
    let vaddr = ctx.mrs[1] as usize;
    let pid = ctx.pid;

    if let Some(p) = get_process_manager().get_process_mut(pid) {
        unsafe {
            if key == 0 {
                reply_mrs[0] = 1; // Error
            } else {
                match (*core::ptr::addr_of_mut!(crate::SHARED_MEMORY_MANAGER)).map_shared_region(
                    key - 1,
                    pid,
                    p,
                    ctx.allocator,
                    ctx.slot_allocator,
                    ctx.boot_info,
                    vaddr,
                ) {
                    Ok(_) => {
                        reply_mrs[0] = 0; // Success
                    }
                    Err(e) => {
                        reply_mrs[0] = e as u64; // Error code
                    }
                }
            }
        }
    } else {
        reply_mrs[0] = 1; // Error
    }

    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

/// Handle `sys_mmap_shared(size)`.
pub fn handle_mmap_shared(ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    if let Err(e) = validate_one_mr(ctx) {
        return error_reply(e);
    }

    let mut reply_mrs = [0u64; 4];
    let requested_size = ctx.mrs[0] as usize;
    let page_size = 4096usize;
    let aligned_size = match requested_size.checked_add(page_size - 1) {
        Some(v) => v & !(page_size - 1),
        None => 0,
    };
    const MMAP_FLOOR: usize = 0x4000_0000;

    if requested_size == 0 || aligned_size == 0 {
        return (MessageInfo::new(0, 0, 0, 1), reply_mrs, true);
    }

    let pid = ctx.pid;
    if let Some(p) = get_process_manager().get_process_mut(pid) {
        if p.mmap_top < aligned_size || (p.mmap_top - aligned_size) < MMAP_FLOOR {
            return (MessageInfo::new(0, 0, 0, 1), reply_mrs, true);
        }

        let page_count = aligned_size / page_size;
        if crate::deny_if_memory_pressure(
            ctx.slot_allocator,
            ctx.allocator,
            ctx.boot_info,
            page_count.saturating_mul(2).saturating_add(4),
            "sys_mmap_shared",
        ) {
            return (MessageInfo::new(0, 0, 0, 1), reply_mrs, true);
        }

        let vaddr = p.mmap_top - aligned_size;
        unsafe {
            match (*core::ptr::addr_of_mut!(crate::SHARED_MEMORY_MANAGER)).create_shared_region(
                ctx.allocator,
                ctx.slot_allocator,
                ctx.boot_info,
                aligned_size,
            ) {
                Ok(key) => {
                    match (*core::ptr::addr_of_mut!(crate::SHARED_MEMORY_MANAGER))
                        .map_shared_region(
                            key,
                            pid,
                            p,
                            ctx.allocator,
                            ctx.slot_allocator,
                            ctx.boot_info,
                            vaddr,
                        ) {
                        Ok(_) => {
                            p.mmap_top = vaddr;
                            reply_mrs[0] = vaddr as u64;
                        }
                        Err(_) => {
                            let _ = (*core::ptr::addr_of_mut!(crate::SHARED_MEMORY_MANAGER))
                                .destroy_unmapped_region(key, ctx.slot_allocator);
                            reply_mrs[0] = 0;
                        }
                    }
                }
                Err(_) => {
                    reply_mrs[0] = 0;
                }
            }
        }
    }

    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

/// Handle `sys_munmap_shared(vaddr, size)`.
pub fn handle_munmap_shared(ctx: &mut SyscallContext<'_>) -> (MessageInfo, [u64; 4], bool) {
    if let Err(e) = validate_two_mrs(ctx) {
        return error_reply(e);
    }

    let mut reply_mrs = [0u64; 4];
    let vaddr = ctx.mrs[0] as usize;
    let size = ctx.mrs[1] as usize;
    let pid = ctx.pid;

    if let Some(p) = get_process_manager().get_process_mut(pid) {
        unsafe {
            match (*core::ptr::addr_of_mut!(crate::SHARED_MEMORY_MANAGER)).unmap_shared_region(
                pid,
                p,
                ctx.slot_allocator,
                vaddr,
                size,
            ) {
                Ok(_) => {
                    reply_mrs[0] = 0;
                }
                Err(e) => {
                    reply_mrs[0] = e as u64;
                }
            }
        }
    } else {
        reply_mrs[0] = 1;
    }

    (MessageInfo::new(0, 0, 0, 1), reply_mrs, true)
}

fn error_reply(err: ValidateError) -> (MessageInfo, [u64; 4], bool) {
    let mut reply_mrs = [0u64; 4];
    reply_mrs[0] = (-1i64) as u64;
    let info = MessageInfo::new(0, 0, 0, 1);
    // In a debug build we could encode the error kind, but for now just
    // return -1 to the caller.
    let _ = err;
    (info, reply_mrs, true)
}

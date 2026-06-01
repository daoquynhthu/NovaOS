#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;

mod allocator;
use libnova::fs_ipc::{
    chmod_direct as fs_chmod_direct, chown_direct as fs_chown_direct, close_direct as fs_close_direct,
    decrypt_direct as fs_decrypt_direct, encrypt_direct as fs_encrypt_direct, link_direct as fs_link_direct,
    list_direct as fs_list_direct, mkdir_direct as fs_mkdir_direct, open_direct as fs_open_direct, read_direct as fs_read_direct,
    rename_direct as fs_rename_direct, sync_direct as fs_sync_direct, symlink_direct as fs_symlink_direct,
    truncate_direct as fs_truncate_direct, unlink_direct as fs_unlink_direct, write_direct as fs_write_direct,
    writetest_direct as fs_writetest_direct, stat_direct as fs_stat_direct,
    FS_MAX_RW_LEN,
};
use libnova::syscall::*;
use libnova::{print, println};
use sel4_sys::{seL4_CPtr, seL4_IPCBuffer};

use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// Define the IPC Buffer symbol required by libsel4/sel4-sys
// The RootServer maps the IPC buffer at 0x3000_0000 for this process.
#[no_mangle]
pub static mut __sel4_ipc_buffer: *mut seL4_IPCBuffer = 0x3000_0000 as *mut seL4_IPCBuffer;

const SHM_CHILD_VADDR: usize = 0x6FFD_0000;
const SHM_PARENT_VADDR: usize = 0x6FFE_0000;
const SHM_PARENT_MAGIC: u64 = 0xA1B2_C3D4_E5F6_0718;
const SHM_CHILD_MAGIC: u64 = 0x1837_26F5_E4D3_C2B1;
const FS_PROXY_SMOKE_PATH: &str = "/fs_proxy_smoke.txt";
const FS_SYSCALL_SMOKE_PATH: &str = "/fs_syscall_smoke.txt";
const FS_CMD_PATH_MAX: usize = 255;
const FS_CMD_CONTENT_MAX: usize = FS_MAX_RW_LEN;

struct EarlyArgs {
    loop_mode: bool,
    fs_proxy_smoke: bool,
    fs_syscall_smoke: bool,
    shm_child_key: Option<usize>,
    fs_cat_len: usize,
    fs_cat_path: [u8; FS_CMD_PATH_MAX],
    fs_ls_len: usize,
    fs_ls_path: [u8; FS_CMD_PATH_MAX],
    fs_cd_len: usize,
    fs_cd_path: [u8; FS_CMD_PATH_MAX],
    fs_writetest_len: usize,
    fs_writetest_path: [u8; FS_CMD_PATH_MAX],
    fs_writetest_kb: usize,
    fs_cp_src_len: usize,
    fs_cp_src_path: [u8; FS_CMD_PATH_MAX],
    fs_cp_dest_len: usize,
    fs_cp_dest_path: [u8; FS_CMD_PATH_MAX],
    fs_mv_src_len: usize,
    fs_mv_src_path: [u8; FS_CMD_PATH_MAX],
    fs_mv_dest_len: usize,
    fs_mv_dest_path: [u8; FS_CMD_PATH_MAX],
    fs_link_target_len: usize,
    fs_link_target_path: [u8; FS_CMD_PATH_MAX],
    fs_link_path_len: usize,
    fs_link_path: [u8; FS_CMD_PATH_MAX],
    fs_symlink_target_len: usize,
    fs_symlink_target_path: [u8; FS_CMD_PATH_MAX],
    fs_symlink_path_len: usize,
    fs_symlink_path: [u8; FS_CMD_PATH_MAX],
    fs_rm_len: usize,
    fs_rm_path: [u8; FS_CMD_PATH_MAX],
    fs_mkdir_len: usize,
    fs_mkdir_path: [u8; FS_CMD_PATH_MAX],
    fs_touch_len: usize,
    fs_touch_path: [u8; FS_CMD_PATH_MAX],
    fs_truncate_len: usize,
    fs_truncate_path: [u8; FS_CMD_PATH_MAX],
    fs_truncate_size: u64,
    fs_chmod_len: usize,
    fs_chmod_path: [u8; FS_CMD_PATH_MAX],
    fs_chmod_mode: u16,
    fs_chown_len: usize,
    fs_chown_path: [u8; FS_CMD_PATH_MAX],
    fs_chown_uid: u32,
    fs_chown_gid: u32,
    fs_sync: bool,
    fs_write_path_len: usize,
    fs_write_path: [u8; FS_CMD_PATH_MAX],
    fs_write_content_len: usize,
    fs_write_content: [u8; FS_CMD_CONTENT_MAX],
    fs_encrypt_len: usize,
    fs_encrypt_path: [u8; FS_CMD_PATH_MAX],
    fs_decrypt_len: usize,
    fs_decrypt_path: [u8; FS_CMD_PATH_MAX],
}

impl EarlyArgs {
    const fn new() -> Self {
        Self {
            loop_mode: false,
            fs_proxy_smoke: false,
            fs_syscall_smoke: false,
            shm_child_key: None,
            fs_cat_len: 0,
            fs_cat_path: [0; FS_CMD_PATH_MAX],
            fs_ls_len: 0,
            fs_ls_path: [0; FS_CMD_PATH_MAX],
            fs_cd_len: 0,
            fs_cd_path: [0; FS_CMD_PATH_MAX],
            fs_writetest_len: 0,
            fs_writetest_path: [0; FS_CMD_PATH_MAX],
            fs_writetest_kb: 0,
            fs_cp_src_len: 0,
            fs_cp_src_path: [0; FS_CMD_PATH_MAX],
            fs_cp_dest_len: 0,
            fs_cp_dest_path: [0; FS_CMD_PATH_MAX],
            fs_mv_src_len: 0,
            fs_mv_src_path: [0; FS_CMD_PATH_MAX],
            fs_mv_dest_len: 0,
            fs_mv_dest_path: [0; FS_CMD_PATH_MAX],
            fs_link_target_len: 0,
            fs_link_target_path: [0; FS_CMD_PATH_MAX],
            fs_link_path_len: 0,
            fs_link_path: [0; FS_CMD_PATH_MAX],
            fs_symlink_target_len: 0,
            fs_symlink_target_path: [0; FS_CMD_PATH_MAX],
            fs_symlink_path_len: 0,
            fs_symlink_path: [0; FS_CMD_PATH_MAX],
            fs_rm_len: 0,
            fs_rm_path: [0; FS_CMD_PATH_MAX],
            fs_mkdir_len: 0,
            fs_mkdir_path: [0; FS_CMD_PATH_MAX],
            fs_touch_len: 0,
            fs_touch_path: [0; FS_CMD_PATH_MAX],
            fs_truncate_len: 0,
            fs_truncate_path: [0; FS_CMD_PATH_MAX],
            fs_truncate_size: 0,
            fs_chmod_len: 0,
            fs_chmod_path: [0; FS_CMD_PATH_MAX],
            fs_chmod_mode: 0,
            fs_chown_len: 0,
            fs_chown_path: [0; FS_CMD_PATH_MAX],
            fs_chown_uid: 0,
            fs_chown_gid: 0,
            fs_sync: false,
            fs_write_path_len: 0,
            fs_write_path: [0; FS_CMD_PATH_MAX],
            fs_write_content_len: 0,
            fs_write_content: [0; FS_CMD_CONTENT_MAX],
            fs_encrypt_len: 0,
            fs_encrypt_path: [0; FS_CMD_PATH_MAX],
            fs_decrypt_len: 0,
            fs_decrypt_path: [0; FS_CMD_PATH_MAX],
        }
    }

    fn fs_cat_path(&self) -> Option<&str> {
        if self.fs_cat_len == 0 {
            None
        } else {
            core::str::from_utf8(&self.fs_cat_path[..self.fs_cat_len]).ok()
        }
    }

    fn fs_ls_path(&self) -> Option<&str> {
        if self.fs_ls_len == 0 {
            None
        } else {
            core::str::from_utf8(&self.fs_ls_path[..self.fs_ls_len]).ok()
        }
    }

    fn fs_cd_path(&self) -> Option<&str> {
        if self.fs_cd_len == 0 {
            None
        } else {
            core::str::from_utf8(&self.fs_cd_path[..self.fs_cd_len]).ok()
        }
    }

    fn fs_writetest_args(&self) -> Option<(&str, usize)> {
        if self.fs_writetest_len == 0 {
            None
        } else {
            let path = core::str::from_utf8(&self.fs_writetest_path[..self.fs_writetest_len]).ok()?;
            Some((path, self.fs_writetest_kb))
        }
    }

    fn fs_touch_path(&self) -> Option<&str> {
        if self.fs_touch_len == 0 {
            None
        } else {
            core::str::from_utf8(&self.fs_touch_path[..self.fs_touch_len]).ok()
        }
    }

    fn fs_rm_path(&self) -> Option<&str> {
        if self.fs_rm_len == 0 {
            None
        } else {
            core::str::from_utf8(&self.fs_rm_path[..self.fs_rm_len]).ok()
        }
    }

    fn fs_mkdir_path(&self) -> Option<&str> {
        if self.fs_mkdir_len == 0 {
            None
        } else {
            core::str::from_utf8(&self.fs_mkdir_path[..self.fs_mkdir_len]).ok()
        }
    }

    fn fs_mv_paths(&self) -> Option<(&str, &str)> {
        if self.fs_mv_src_len == 0 || self.fs_mv_dest_len == 0 {
            None
        } else {
            let src = core::str::from_utf8(&self.fs_mv_src_path[..self.fs_mv_src_len]).ok()?;
            let dest = core::str::from_utf8(&self.fs_mv_dest_path[..self.fs_mv_dest_len]).ok()?;
            Some((src, dest))
        }
    }

    fn fs_link_paths(&self) -> Option<(&str, &str)> {
        if self.fs_link_target_len == 0 || self.fs_link_path_len == 0 {
            None
        } else {
            let target = core::str::from_utf8(&self.fs_link_target_path[..self.fs_link_target_len]).ok()?;
            let link = core::str::from_utf8(&self.fs_link_path[..self.fs_link_path_len]).ok()?;
            Some((target, link))
        }
    }

    fn fs_symlink_paths(&self) -> Option<(&str, &str)> {
        if self.fs_symlink_target_len == 0 || self.fs_symlink_path_len == 0 {
            None
        } else {
            let target = core::str::from_utf8(&self.fs_symlink_target_path[..self.fs_symlink_target_len]).ok()?;
            let link = core::str::from_utf8(&self.fs_symlink_path[..self.fs_symlink_path_len]).ok()?;
            Some((target, link))
        }
    }

    fn fs_cp_paths(&self) -> Option<(&str, &str)> {
        if self.fs_cp_src_len == 0 || self.fs_cp_dest_len == 0 {
            None
        } else {
            let src = core::str::from_utf8(&self.fs_cp_src_path[..self.fs_cp_src_len]).ok()?;
            let dest = core::str::from_utf8(&self.fs_cp_dest_path[..self.fs_cp_dest_len]).ok()?;
            Some((src, dest))
        }
    }

    fn fs_write_args(&self) -> Option<(&str, &str)> {
        if self.fs_write_path_len == 0 || self.fs_write_content_len == 0 {
            None
        } else {
            let path = core::str::from_utf8(&self.fs_write_path[..self.fs_write_path_len]).ok()?;
            let content =
                core::str::from_utf8(&self.fs_write_content[..self.fs_write_content_len]).ok()?;
            Some((path, content))
        }
    }

    fn fs_encrypt_path(&self) -> Option<&str> {
        if self.fs_encrypt_len == 0 {
            None
        } else {
            core::str::from_utf8(&self.fs_encrypt_path[..self.fs_encrypt_len]).ok()
        }
    }

    fn fs_decrypt_path(&self) -> Option<&str> {
        if self.fs_decrypt_len == 0 {
            None
        } else {
            core::str::from_utf8(&self.fs_decrypt_path[..self.fs_decrypt_len]).ok()
        }
    }

    fn fs_truncate_args(&self) -> Option<(&str, u64)> {
        if self.fs_truncate_len == 0 {
            None
        } else {
            let path = core::str::from_utf8(&self.fs_truncate_path[..self.fs_truncate_len]).ok()?;
            Some((path, self.fs_truncate_size))
        }
    }

    fn fs_chmod_args(&self) -> Option<(&str, u16)> {
        if self.fs_chmod_len == 0 {
            None
        } else {
            let path = core::str::from_utf8(&self.fs_chmod_path[..self.fs_chmod_len]).ok()?;
            Some((path, self.fs_chmod_mode))
        }
    }

    fn fs_chown_args(&self) -> Option<(&str, u32, u32)> {
        if self.fs_chown_len == 0 {
            None
        } else {
            let path = core::str::from_utf8(&self.fs_chown_path[..self.fs_chown_len]).ok()?;
            Some((path, self.fs_chown_uid, self.fs_chown_gid))
        }
    }
}

fn copy_str_to_buf(src: &str, dst: &mut [u8]) -> usize {
    let bytes = src.as_bytes();
    let len = core::cmp::min(bytes.len(), dst.len());
    dst[..len].copy_from_slice(&bytes[..len]);
    len
}

unsafe fn arg_ptr_to_str(ptr: *const u8) -> Option<&'static str> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let s_slice = core::slice::from_raw_parts(ptr, len);
    let s = core::str::from_utf8(s_slice).ok()?;
    Some(core::mem::transmute(s))
}

fn parse_early_args(argc: usize, argv: *const *const u8) -> EarlyArgs {
    let mut parsed = EarlyArgs::new();
    if argv.is_null() {
        return parsed;
    }

    let mut expect_shm_key = false;
    let mut expect_fs_cat_path = false;
    let mut expect_fs_ls_path = false;
    let mut expect_fs_cd_path = false;
    let mut expect_fs_writetest_path = false;
    let mut expect_fs_writetest_kb = false;
    let mut expect_fs_cp_src_path = false;
    let mut expect_fs_cp_dest_path = false;
    let mut expect_fs_link_target_path = false;
    let mut expect_fs_link_path = false;
    let mut expect_fs_mv_src_path = false;
    let mut expect_fs_mv_dest_path = false;
    let mut expect_fs_mkdir_path = false;
    let mut expect_fs_rm_path = false;
    let mut expect_fs_symlink_target = false;
    let mut expect_fs_symlink_path = false;
    let mut expect_fs_touch_path = false;
    let mut expect_fs_truncate_path = false;
    let mut expect_fs_truncate_size = false;
    let mut expect_fs_chmod_mode = false;
    let mut expect_fs_chmod_path = false;
    let mut expect_fs_chown_uid_gid = false;
    let mut expect_fs_chown_path = false;
    let mut expect_fs_write_path = false;
    let mut expect_fs_write_content = false;
    let mut expect_fs_encrypt_path = false;
    let mut expect_fs_decrypt_path = false;

    unsafe {
        for idx in 0..argc {
            let Some(arg) = arg_ptr_to_str(*argv.add(idx)) else {
                continue;
            };

            if expect_shm_key {
                if let Ok(k) = arg.parse::<usize>() {
                    parsed.shm_child_key = Some(k);
                }
                expect_shm_key = false;
                continue;
            }
            if expect_fs_cat_path {
                parsed.fs_cat_len = copy_str_to_buf(arg, &mut parsed.fs_cat_path);
                expect_fs_cat_path = false;
                continue;
            }
            if expect_fs_ls_path {
                parsed.fs_ls_len = copy_str_to_buf(arg, &mut parsed.fs_ls_path);
                expect_fs_ls_path = false;
                continue;
            }
            if expect_fs_cd_path {
                parsed.fs_cd_len = copy_str_to_buf(arg, &mut parsed.fs_cd_path);
                expect_fs_cd_path = false;
                continue;
            }
            if expect_fs_writetest_path {
                parsed.fs_writetest_len = copy_str_to_buf(arg, &mut parsed.fs_writetest_path);
                expect_fs_writetest_path = false;
                expect_fs_writetest_kb = true;
                continue;
            }
            if expect_fs_writetest_kb {
                if let Ok(kb) = arg.parse::<usize>() {
                    parsed.fs_writetest_kb = kb;
                }
                expect_fs_writetest_kb = false;
                continue;
            }
            if expect_fs_cp_src_path {
                parsed.fs_cp_src_len = copy_str_to_buf(arg, &mut parsed.fs_cp_src_path);
                expect_fs_cp_src_path = false;
                expect_fs_cp_dest_path = true;
                continue;
            }
            if expect_fs_cp_dest_path {
                parsed.fs_cp_dest_len = copy_str_to_buf(arg, &mut parsed.fs_cp_dest_path);
                expect_fs_cp_dest_path = false;
                continue;
            }
            if expect_fs_mv_src_path {
                parsed.fs_mv_src_len = copy_str_to_buf(arg, &mut parsed.fs_mv_src_path);
                expect_fs_mv_src_path = false;
                expect_fs_mv_dest_path = true;
                continue;
            }
            if expect_fs_mv_dest_path {
                parsed.fs_mv_dest_len = copy_str_to_buf(arg, &mut parsed.fs_mv_dest_path);
                expect_fs_mv_dest_path = false;
                continue;
            }
            if expect_fs_mkdir_path {
                parsed.fs_mkdir_len = copy_str_to_buf(arg, &mut parsed.fs_mkdir_path);
                expect_fs_mkdir_path = false;
                continue;
            }
            if expect_fs_link_target_path {
                parsed.fs_link_target_len = copy_str_to_buf(arg, &mut parsed.fs_link_target_path);
                expect_fs_link_target_path = false;
                expect_fs_link_path = true;
                continue;
            }
            if expect_fs_link_path {
                parsed.fs_link_path_len = copy_str_to_buf(arg, &mut parsed.fs_link_path);
                expect_fs_link_path = false;
                continue;
            }
            if expect_fs_rm_path {
                parsed.fs_rm_len = copy_str_to_buf(arg, &mut parsed.fs_rm_path);
                expect_fs_rm_path = false;
                continue;
            }
            if expect_fs_symlink_target {
                parsed.fs_symlink_target_len = copy_str_to_buf(arg, &mut parsed.fs_symlink_target_path);
                expect_fs_symlink_target = false;
                expect_fs_symlink_path = true;
                continue;
            }
            if expect_fs_symlink_path {
                parsed.fs_symlink_path_len = copy_str_to_buf(arg, &mut parsed.fs_symlink_path);
                expect_fs_symlink_path = false;
                continue;
            }
            if expect_fs_touch_path {
                parsed.fs_touch_len = copy_str_to_buf(arg, &mut parsed.fs_touch_path);
                expect_fs_touch_path = false;
                continue;
            }
            if expect_fs_truncate_path {
                parsed.fs_truncate_len = copy_str_to_buf(arg, &mut parsed.fs_truncate_path);
                expect_fs_truncate_path = false;
                expect_fs_truncate_size = true;
                continue;
            }
            if expect_fs_truncate_size {
                if let Ok(size) = arg.parse::<u64>() {
                    parsed.fs_truncate_size = size;
                }
                expect_fs_truncate_size = false;
                continue;
            }
            if expect_fs_chmod_mode {
                if let Ok(mode) = u16::from_str_radix(arg, 8) {
                    parsed.fs_chmod_mode = mode;
                }
                expect_fs_chmod_mode = false;
                expect_fs_chmod_path = true;
                continue;
            }
            if expect_fs_chmod_path {
                parsed.fs_chmod_len = copy_str_to_buf(arg, &mut parsed.fs_chmod_path);
                expect_fs_chmod_path = false;
                continue;
            }
            if expect_fs_chown_uid_gid {
                let mut split = arg.split(':');
                if let (Some(uid_s), Some(gid_s), None) = (split.next(), split.next(), split.next()) {
                    if let (Ok(uid), Ok(gid)) = (uid_s.parse::<u32>(), gid_s.parse::<u32>()) {
                        parsed.fs_chown_uid = uid;
                        parsed.fs_chown_gid = gid;
                    }
                }
                expect_fs_chown_uid_gid = false;
                expect_fs_chown_path = true;
                continue;
            }
            if expect_fs_chown_path {
                parsed.fs_chown_len = copy_str_to_buf(arg, &mut parsed.fs_chown_path);
                expect_fs_chown_path = false;
                continue;
            }
            if expect_fs_write_path {
                parsed.fs_write_path_len = copy_str_to_buf(arg, &mut parsed.fs_write_path);
                expect_fs_write_path = false;
                expect_fs_write_content = true;
                continue;
            }
            if expect_fs_write_content {
                parsed.fs_write_content_len = copy_str_to_buf(arg, &mut parsed.fs_write_content);
                expect_fs_write_content = false;
                continue;
            }
            if expect_fs_encrypt_path {
                parsed.fs_encrypt_len = copy_str_to_buf(arg, &mut parsed.fs_encrypt_path);
                expect_fs_encrypt_path = false;
                continue;
            }
            if expect_fs_decrypt_path {
                parsed.fs_decrypt_len = copy_str_to_buf(arg, &mut parsed.fs_decrypt_path);
                expect_fs_decrypt_path = false;
                continue;
            }

            if arg == "loop" {
                parsed.loop_mode = true;
            }
            if arg == "shm_child" {
                expect_shm_key = true;
            }
            if arg == "fs_proxy_smoke" {
                parsed.fs_proxy_smoke = true;
            }
            if arg == "fs_syscall_smoke" {
                parsed.fs_syscall_smoke = true;
            }
            if arg == "fs_cat" {
                expect_fs_cat_path = true;
            }
            if arg == "fs_ls" {
                expect_fs_ls_path = true;
            }
            if arg == "fs_cd" {
                expect_fs_cd_path = true;
            }
            if arg == "fs_writetest" {
                expect_fs_writetest_path = true;
            }
            if arg == "fs_cp" {
                expect_fs_cp_src_path = true;
            }
            if arg == "fs_link" {
                expect_fs_link_target_path = true;
            }
            if arg == "fs_mv" {
                expect_fs_mv_src_path = true;
            }
            if arg == "fs_mkdir" {
                expect_fs_mkdir_path = true;
            }
            if arg == "fs_rm" {
                expect_fs_rm_path = true;
            }
            if arg == "fs_symlink" {
                expect_fs_symlink_target = true;
            }
            if arg == "fs_touch" {
                expect_fs_touch_path = true;
            }
            if arg == "fs_truncate" {
                expect_fs_truncate_path = true;
            }
            if arg == "fs_chmod" {
                expect_fs_chmod_mode = true;
            }
            if arg == "fs_chown" {
                expect_fs_chown_uid_gid = true;
            }
            if arg == "fs_sync" {
                parsed.fs_sync = true;
            }
            if arg == "fs_write" {
                expect_fs_write_path = true;
            }
            if arg == "fs_encrypt" {
                expect_fs_encrypt_path = true;
            }
            if arg == "fs_decrypt" {
                expect_fs_decrypt_path = true;
            }
        }
    }

    parsed
}

fn parse_env_usize(envp: *const *const u8, key: &str) -> Option<usize> {
    if envp.is_null() {
        return None;
    }

    unsafe {
        let mut curr = envp;
        while !(*curr).is_null() {
            let s_ptr = *curr;
            let mut len = 0;
            while *s_ptr.add(len) != 0 {
                len += 1;
            }
            let s_slice = core::slice::from_raw_parts(s_ptr, len);
            if let Ok(s) = core::str::from_utf8(s_slice) {
                if let Some(value) = s.strip_prefix(key).and_then(|rest| rest.strip_prefix('=')) {
                    if let Ok(parsed) = value.parse::<usize>() {
                        return Some(parsed);
                    }
                }
            }
            curr = curr.add(1);
        }
    }

    None
}

fn run_fs_proxy_smoke(envp: *const *const u8) -> isize {
    println!("[FS_PROXY] Starting smoke test...");
    let Some(fs_ep) = parse_env_usize(envp, "NOVA_FS_SERVICE_EP").map(|slot| slot as seL4_CPtr) else {
        println!("[FS_PROXY] missing NOVA_FS_SERVICE_EP");
        return 209;
    };

    let fd = fs_open_direct(fs_ep, FS_PROXY_SMOKE_PATH, 1);
    if fd < 0 {
        println!("[FS_PROXY] open(write) failed: {}", fd);
        return 210;
    }

    let payload = b"fs_proxy_path_ok";
    let written = fs_write_direct(fs_ep, fd as usize, payload);
    if written != payload.len() as isize {
        println!("[FS_PROXY] write failed: {}", written);
        let _ = fs_close_direct(fs_ep, fd as usize);
        return 211;
    }

    let close_write = fs_close_direct(fs_ep, fd as usize);
    if close_write != 0 {
        println!("[FS_PROXY] close(write) failed: {}", close_write);
        return 212;
    }

    let fd_read = fs_open_direct(fs_ep, FS_PROXY_SMOKE_PATH, 0);
    if fd_read < 0 {
        println!("[FS_PROXY] open(read) failed: {}", fd_read);
        return 213;
    }

    let mut read_buf = [0u8; 32];
    let read_len = fs_read_direct(fs_ep, fd_read as usize, &mut read_buf);
    let close_read = fs_close_direct(fs_ep, fd_read as usize);
    if close_read != 0 {
        println!("[FS_PROXY] close(read) failed: {}", close_read);
        return 214;
    }
    if read_len != payload.len() as isize {
        println!("[FS_PROXY] read length mismatch: {}", read_len);
        return 215;
    }
    if &read_buf[..payload.len()] != payload {
        println!("[FS_PROXY] read content mismatch");
        return 216;
    }

    println!("[FS_PROXY] PASS");
    0
}

fn run_fs_syscall_smoke(ep_cap: seL4_CPtr) -> isize {
    println!("[FS_SYSCALL] Starting syscall smoke test...");

    let fd = sys_open(ep_cap, FS_SYSCALL_SMOKE_PATH, 1);
    if fd < 0 {
        println!("[FS_SYSCALL] open(write) failed: {}", fd);
        return 217;
    }

    let payload = b"fs_syscall_path_ok";
    let written = sys_write(ep_cap, fd as usize, payload);
    if written != payload.len() as isize {
        println!("[FS_SYSCALL] write failed: {}", written);
        let _ = sys_close(ep_cap, fd as usize);
        return 218;
    }

    let close_write = sys_close(ep_cap, fd as usize);
    if close_write != 0 {
        println!("[FS_SYSCALL] close(write) failed: {}", close_write);
        return 219;
    }

    let fd_read = sys_open(ep_cap, FS_SYSCALL_SMOKE_PATH, 0);
    if fd_read < 0 {
        println!("[FS_SYSCALL] open(read) failed: {}", fd_read);
        return 220;
    }

    let mut read_buf = [0u8; 32];
    let read_len = sys_read(ep_cap, fd_read as usize, &mut read_buf);
    let close_read = sys_close(ep_cap, fd_read as usize);
    if close_read != 0 {
        println!("[FS_SYSCALL] close(read) failed: {}", close_read);
        return 221;
    }
    if read_len != payload.len() as isize {
        println!("[FS_SYSCALL] read length mismatch: {}", read_len);
        return 222;
    }
    if &read_buf[..payload.len()] != payload {
        println!("[FS_SYSCALL] read content mismatch");
        return 223;
    }

    println!("[FS_SYSCALL] PASS");
    0
}

fn resolve_fs_ep(envp: *const *const u8) -> core::result::Result<seL4_CPtr, isize> {
    parse_env_usize(envp, "NOVA_FS_SERVICE_EP")
        .map(|slot| slot as seL4_CPtr)
        .ok_or(217)
}

fn run_fs_touch(envp: *const *const u8, path: &str) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("touch: fs service unavailable");
            return code;
        }
    };

    println!("[FS_CMD] touch begin {}", path);
    let fd = fs_open_direct(fs_ep, path, 1);
    if fd < 0 {
        println!("touch: {}: open failed ({})", path, fd);
        return 218;
    }
    println!("[FS_CMD] touch opened fd={}", fd);

    let close_res = fs_close_direct(fs_ep, fd as usize);
    if close_res != 0 {
        println!("touch: {}: close failed ({})", path, close_res);
        return 219;
    }

    println!("[FS_CMD] touch ok {}", path);

    0
}

fn run_fs_cat(envp: *const *const u8, path: &str) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("cat: fs service unavailable");
            return code;
        }
    };

    println!("[FS_CMD] cat begin {}", path);
    let fd = fs_open_direct(fs_ep, path, 0);
    if fd < 0 {
        println!("cat: {}: open failed ({})", path, fd);
        return 220;
    }

    let mut buf = [0u8; FS_MAX_RW_LEN];
    let mut collected = Vec::new();
    let mut saw_output = false;
    let mut ended_with_newline = false;
    loop {
        let n = fs_read_direct(fs_ep, fd as usize, &mut buf);
        if n < 0 {
            println!("cat: {}: read failed ({})", path, n);
            let _ = fs_close_direct(fs_ep, fd as usize);
            return 221;
        }
        println!("[FS_CMD] cat read {} bytes path={}", n, path);
        if n == 0 {
            break;
        }

        let chunk = &buf[..n as usize];
        if !chunk.is_empty() {
            let first = chunk[0];
            let last = chunk[chunk.len() - 1];
            println!(
                "[FS_CMD] cat chunk len={} first={:02x} last={:02x}",
                chunk.len(),
                first,
                last
            );
            if chunk.len() <= 16 {
                print!("[FS_CMD] cat hex");
                for byte in chunk {
                    print!(" {:02x}", byte);
                }
                println!();
            }
        }
        match core::str::from_utf8(chunk) {
            Ok(s) => {
                print!("{}", s);
                if collected.len() <= 4096 {
                    collected.extend_from_slice(s.as_bytes());
                }
                saw_output = true;
                ended_with_newline = s.ends_with('\n');
            }
            Err(_) => {
                println!("(Binary file, {} bytes chunk)", n);
                let _ = fs_close_direct(fs_ep, fd as usize);
                return 222;
            }
        }
    }

    let close_res = fs_close_direct(fs_ep, fd as usize);
    if close_res != 0 {
        println!("cat: {}: close failed ({})", path, close_res);
        return 223;
    }

    if saw_output && !ended_with_newline {
        println!();
    }

    println!("[FS_CMD] cat bytes={} path={}", collected.len(), path);
    if saw_output && !collected.is_empty() {
        if let Ok(summary) = core::str::from_utf8(&collected) {
            println!("[FS_CMD] cat data {}", summary);
        }
    }

    println!("[FS_CMD] cat ok {}", path);

    0
}

fn run_fs_ls(envp: *const *const u8, path: &str) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("ls: fs service unavailable");
            return code;
        }
    };

    println!("[FS_CMD] ls begin {}", path);
    let res = fs_list_direct(fs_ep, path);
    if res != 0 {
        println!("ls: {}", res);
        return 244;
    }

    println!("[FS_CMD] ls ok {}", path);
    0
}

fn run_fs_cd(envp: *const *const u8, path: &str) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("cd: fs service unavailable");
            return code;
        }
    };

    println!("[FS_CMD] cd begin {}", path);
    let stat_kind = fs_stat_direct(fs_ep, path);
    if stat_kind != 1 {
        if stat_kind < 0 {
            println!("cd: {}: {}", path, stat_kind);
        } else {
            println!("cd: {}: Not a directory", path);
        }
        return 245;
    }

    println!("[FS_CMD] cd ok {}", path);
    0
}

fn run_fs_write_text(envp: *const *const u8, path: &str, content: &str) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("echo: fs service unavailable");
            return code;
        }
    };

    println!("[FS_CMD] write begin {}", path);
    let fd = fs_open_direct(fs_ep, path, 1);
    if fd < 0 {
        println!("echo: {}: open failed ({})", path, fd);
        return 235;
    }

    let written = fs_write_direct(fs_ep, fd as usize, content.as_bytes());
    if written != content.len() as isize {
        let _ = fs_close_direct(fs_ep, fd as usize);
        println!("echo: {}: write failed ({})", path, written);
        return 236;
    }

    let close_res = fs_close_direct(fs_ep, fd as usize);
    if close_res != 0 {
        println!("echo: {}: close failed ({})", path, close_res);
        return 237;
    }

    println!("Written to {}", path);
    println!("[FS_CMD] write ok {}", path);
    0
}

fn run_fs_writetest(envp: *const *const u8, path: &str, size_kb: usize) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("writetest: fs service unavailable");
            return code;
        }
    };

    println!("Writing {} KB to {}", size_kb, path);
    println!("[FS_CMD] writetest direct begin {} size={}KB", path, size_kb);
    let res = fs_writetest_direct(fs_ep, path, size_kb);
    println!("[FS_CMD] writetest direct result {} => {}", path, res);
    if res != 0 {
        println!("writetest: {}: write failed ({})", path, res);
        return 246;
    }

    println!("Write success");
    println!("[FS_CMD] writetest ok {} size={}KB", path, size_kb);
    0
}

fn run_fs_encrypt(envp: *const *const u8, path: &str) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("encrypt: fs service unavailable");
            return code;
        }
    };

    println!("[FS_CMD] encrypt begin {}", path);
    match fs_encrypt_direct(fs_ep, path) {
        0 => {
            println!("File '{}' encrypted.", path);
            println!("[FS_CMD] encrypt ok {}", path);
            0
        }
        1 => {
            println!("File '{}' is already encrypted.", path);
            0
        }
        code => {
            println!("Failed to encrypt: {}", code);
            238
        }
    }
}

fn run_fs_decrypt(envp: *const *const u8, path: &str) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("decrypt: fs service unavailable");
            return code;
        }
    };

    println!("[FS_CMD] decrypt begin {}", path);
    match fs_decrypt_direct(fs_ep, path) {
        0 => {
            println!("File '{}' decrypted.", path);
            println!("[FS_CMD] decrypt ok {}", path);
            0
        }
        1 => {
            println!("File '{}' is not encrypted.", path);
            0
        }
        code => {
            println!("Failed to decrypt: {}", code);
            239
        }
    }
}

fn run_fs_rm(envp: *const *const u8, path: &str) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("rm: fs service unavailable");
            return code;
        }
    };

    println!("[FS_CMD] rm begin {}", path);
    let res = fs_unlink_direct(fs_ep, path);
    if res != 0 {
        if res == -39 {
            println!("rm: cannot remove '{}': Directory not empty", path);
        } else if res == -2 {
            println!("rm: cannot remove '{}': File not found", path);
        } else {
            println!("rm: cannot remove '{}': {}", path, res);
        }
        return 224;
    }

    println!("Removed '{}'", path);
    println!("[FS_CMD] rm ok {}", path);
    0
}

fn run_fs_mkdir(envp: *const *const u8, path: &str) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("mkdir: fs service unavailable");
            return code;
        }
    };

    println!("[FS_CMD] mkdir begin {}", path);
    let res = fs_mkdir_direct(fs_ep, path);
    if res != 0 {
        println!("mkdir: {}", res);
        return 238;
    }

    println!("Created directory {}", path);
    println!("[FS_CMD] mkdir ok {}", path);
    0
}

fn run_fs_cp(envp: *const *const u8, src: &str, dest: &str) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("cp: fs service unavailable");
            return code;
        }
    };
    if src == dest {
        println!("cp: '{}' and '{}' are the same file", src, dest);
        return 225;
    }

    println!("[FS_CMD] cp begin {} -> {}", src, dest);
    let src_fd = fs_open_direct(fs_ep, src, 0);
    if src_fd < 0 {
        println!("cp: read error: {}", src_fd);
        return 226;
    }

    let _ = fs_unlink_direct(fs_ep, dest);
    let dest_fd = fs_open_direct(fs_ep, dest, 1);
    if dest_fd < 0 {
        let _ = fs_close_direct(fs_ep, src_fd as usize);
        println!("cp: write error: {}", dest_fd);
        return 227;
    }

    let mut buf = [0u8; FS_MAX_RW_LEN];
    loop {
        let read_res = fs_read_direct(fs_ep, src_fd as usize, &mut buf);
        if read_res < 0 {
            let _ = fs_close_direct(fs_ep, src_fd as usize);
            let _ = fs_close_direct(fs_ep, dest_fd as usize);
            println!("cp: read error: {}", read_res);
            return 228;
        }
        if read_res == 0 {
            break;
        }
        let chunk = &buf[..read_res as usize];
        let written = fs_write_direct(fs_ep, dest_fd as usize, chunk);
        if written != read_res {
            let _ = fs_close_direct(fs_ep, src_fd as usize);
            let _ = fs_close_direct(fs_ep, dest_fd as usize);
            println!("cp: write error: {}", written);
            return 229;
        }
    }

    let close_src = fs_close_direct(fs_ep, src_fd as usize);
    let close_dest = fs_close_direct(fs_ep, dest_fd as usize);
    if close_src != 0 || close_dest != 0 {
        println!("cp: close error: src={} dest={}", close_src, close_dest);
        return 230;
    }

    println!("Copied '{}' to '{}'", src, dest);
    println!("[FS_CMD] cp ok {} -> {}", src, dest);
    0
}

fn run_fs_mv(envp: *const *const u8, src: &str, dest: &str) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("mv: fs service unavailable");
            return code;
        }
    };
    if src == dest {
        println!("mv: '{}' and '{}' are the same file", src, dest);
        return 231;
    }

    println!("[FS_CMD] mv begin {} -> {}", src, dest);
    let res = fs_rename_direct(fs_ep, src, dest);
    if res != 0 {
        println!("mv: {}", res);
        return 232;
    }

    println!("Renamed '{}' to '{}'", src, dest);
    println!("[FS_CMD] mv ok {} -> {}", src, dest);
    0
}

fn run_fs_truncate(envp: *const *const u8, path: &str, size: u64) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("truncate: fs service unavailable");
            return code;
        }
    };

    println!("[FS_CMD] truncate begin {} size={}", path, size);
    let res = fs_truncate_direct(fs_ep, path, size);
    if res != 0 {
        println!("truncate: {}", res);
        return 239;
    }

    println!("Truncated '{}' to {} bytes.", path, size);
    println!("[FS_CMD] truncate ok {} size={}", path, size);
    0
}

fn run_fs_chmod(envp: *const *const u8, path: &str, mode: u16) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("chmod: fs service unavailable");
            return code;
        }
    };

    println!("[FS_CMD] chmod begin {} mode={:o}", path, mode);
    let res = fs_chmod_direct(fs_ep, path, mode);
    if res != 0 {
        println!("chmod: {}", res);
        return 240;
    }

    println!("Changed mode of '{}' to {:o}", path, mode);
    println!("[FS_CMD] chmod ok {} mode={:o}", path, mode);
    0
}

fn run_fs_chown(envp: *const *const u8, path: &str, uid: u32, gid: u32) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("chown: fs service unavailable");
            return code;
        }
    };

    println!("[FS_CMD] chown begin {} {}:{}", path, uid, gid);
    let res = fs_chown_direct(fs_ep, path, uid, gid);
    if res != 0 {
        println!("chown: {}", res);
        return 241;
    }

    println!("Changed ownership of '{}' to {}:{}", path, uid, gid);
    println!("[FS_CMD] chown ok {} {}:{}", path, uid, gid);
    0
}

fn run_fs_sync(envp: *const *const u8) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("sync: fs service unavailable");
            return code;
        }
    };

    println!("[FS_CMD] sync begin");
    let res = fs_sync_direct(fs_ep);
    if res != 0 {
        println!("sync failed: {}", res);
        return 242;
    }

    println!("FileSystem synced.");
    println!("[FS_CMD] sync ok");
    0
}

fn run_fs_link(envp: *const *const u8, target_path: &str, link_path: &str) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("ln: fs service unavailable");
            return code;
        }
    };

    println!("[FS_CMD] link begin {} => {}", link_path, target_path);
    let res = fs_link_direct(fs_ep, target_path, link_path);
    if res != 0 {
        println!("ln: failed to link: {}", res);
        return 233;
    }

    println!("Created hard link '{}' => '{}'", link_path, target_path);
    println!("[FS_CMD] link ok {} => {}", link_path, target_path);
    0
}

fn run_fs_symlink(envp: *const *const u8, target: &str, link_path: &str) -> isize {
    let fs_ep = match resolve_fs_ep(envp) {
        Ok(ep) => ep,
        Err(code) => {
            println!("ln: fs service unavailable");
            return code;
        }
    };

    println!("[FS_CMD] symlink begin {} -> {}", link_path, target);
    let res = fs_symlink_direct(fs_ep, target, link_path);
    if res != 0 {
        println!("ln: create failed: {}", res);
        return 234;
    }

    println!("Created symbolic link '{}' -> '{}'", link_path, target);
    println!("[FS_CMD] symlink ok {} -> {}", link_path, target);
    0
}

fn usize_to_decimal_str<'a>(mut value: usize, buf: &'a mut [u8; 20]) -> &'a str {
    let mut i = buf.len();
    if value == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while value > 0 && i > 0 {
            i -= 1;
            buf[i] = b'0' + (value % 10) as u8;
            value /= 10;
        }
    }
    unsafe { core::str::from_utf8_unchecked(&buf[i..]) }
}

#[no_mangle]
pub extern "C" fn _start(argc: usize, argv: *const *const u8, ep_cap_usize: usize, envp: *const *const u8) -> ! {
    let ep_cap = ep_cap_usize as seL4_CPtr;
    // Initialize libnova console
    libnova::console::init_console(ep_cap_usize);
    let early_args = parse_early_args(argc, argv);

    println!("DEBUG: User App Updated");
    println!("Process Entry: argc={}", argc);

    unsafe {
        // Demonstrate Arg iterator usage
        let args_iter = libnova::env::Args::new(argc, argv);
        for (i, arg) in args_iter.enumerate() {
            println!("Arg {}: {}", i, arg);
        }

        // Print Environment Variables
        println!("Environment Variables:");
        if !envp.is_null() {
            let mut curr = envp;
            while !(*curr).is_null() {
                let s_ptr = *curr;
                // simple strlen
                let mut len = 0;
                while *s_ptr.add(len) != 0 {
                    len += 1;
                }
                let s_slice = core::slice::from_raw_parts(s_ptr, len);
                if let Ok(s) = core::str::from_utf8(s_slice) {
                    println!("  {}", s);
                }
                curr = curr.add(1);
            }
        } else {
            println!("  <none>");
        }
    }
    
    // Determine who we are
    let pid = sys_get_pid(ep_cap);
    println!("DEBUG: Got PID {}", pid);
    
    // Only PID 0 should execute the full integration suite.
    // This avoids duplicated destructive setup when extra user_app instances are launched.
    let is_main_suite = pid == 0;

    if is_main_suite {
        println!("Process {}: Started (Main Suite).", pid);
        println!("Hello from Rust User App via Syscall!");
        
        // Test File System Syscalls
        println!("Testing File System Syscalls...");
        let filename = "/test_fs.txt";
        // 1 = WriteOnly (Implies Create in our simplified logic for now)
        let fd = sys_open(ep_cap, filename, 1); 
        
        if fd >= 0 {
            println!("File opened successfully. FD: {}", fd);
            let content = b"Hello NovaFS!";
            let written = sys_file_write(ep_cap, fd as usize, content);
            println!("Written {} bytes.", written);
            
            sys_close(ep_cap, fd as usize);
            println!("File closed.");
            
            // Re-open for reading
            let fd_read = sys_open(ep_cap, filename, 0); // 0 = ReadOnly
            if fd_read >= 0 {
                 println!("File re-opened for reading. FD: {}", fd_read);
                 let mut read_buf = [0u8; 32];
                 let read_bytes = sys_read(ep_cap, fd_read as usize, &mut read_buf);
                 if read_bytes > 0 {
                     let read_str = core::str::from_utf8(&read_buf[..read_bytes as usize]).unwrap_or("<invalid utf8>");
                     println!("Read content: {}", read_str);
                     if read_str == "Hello NovaFS!" {
                         println!("FS Test Passed!");
                     } else {
                         println!("FS Test Failed: Content mismatch.");
                     }
                 } else {
                     println!("FS Test Failed: Read returned {}", read_bytes);
                 }
                 sys_close(ep_cap, fd_read as usize);
            } else {
                println!("FS Test Failed: Could not re-open file.");
            }
            
            // Test Rename
            println!("Testing sys_rename...");
            if sys_rename(ep_cap, filename, "/test_renamed.txt") == 0 {
                println!("Rename successful.");
                let fd_renamed = sys_open(ep_cap, "/test_renamed.txt", 0);
                if fd_renamed >= 0 {
                    println!("Renamed file opened successfully.");
                    sys_close(ep_cap, fd_renamed as usize);
                    println!("Rename Test Passed!");
                } else {
                    println!("Rename Test Failed: Could not open renamed file.");
                }
            } else {
                println!("Rename Test Failed: sys_rename returned error.");
            }
        } else {
             println!("FS Test Failed: Could not open file (FD={}).", fd);
        }
        
        // Test Dynamic Memory
        let current_brk = sys_brk(ep_cap, 0);
        let new_brk_req = current_brk + 4096;
        let new_brk = sys_brk(ep_cap, new_brk_req);
        
        if new_brk == new_brk_req {
            println!("Heap expansion successful!");
            let ptr = current_brk as *mut u8;
            unsafe { *ptr = b'A'; }
            if unsafe { *ptr } == b'A' {
                 println!("Heap memory write verified!");
            } else {
                 println!("Heap memory write failed!");
            }
        } else {
            println!("Heap expansion failed!");
        }

        let shrink_brk = sys_brk(ep_cap, current_brk);
        if shrink_brk == current_brk {
            println!("Heap shrink successful!");
        } else {
            println!(
                "Heap shrink failed! expected=0x{:x}, got=0x{:x}",
                current_brk, shrink_brk
            );
        }

        // Test shared mmap baseline (multi-page: 8K).
        println!("Testing sys_mmap_shared...");
        let shared_size = 8192usize;
        let shared_addr = sys_mmap_shared(ep_cap, shared_size);
        if shared_addr != 0 {
            unsafe {
                let p0 = shared_addr as *mut u64;
                let p1 = (shared_addr + 4096) as *mut u64;
                *p0 = 0x1122_3344_5566_7788;
                *p1 = 0x8877_6655_4433_2211;
                if *p0 == 0x1122_3344_5566_7788 && *p1 == 0x8877_6655_4433_2211 {
                    println!("Shared mmap test passed at 0x{:x}.", shared_addr);
                } else {
                    println!("Shared mmap test failed: read-back mismatch.");
                }
            }

            let unmap_ret = sys_munmap_shared(ep_cap, shared_addr, shared_size);
            if unmap_ret == 0 {
                println!("Shared munmap test passed.");
            } else {
                println!("Shared munmap test failed: {}.", unmap_ret);
            }

            let unmap_twice_ret = sys_munmap_shared(ep_cap, shared_addr, shared_size);
            if unmap_twice_ret != 0 {
                println!("Shared munmap double-call protection passed.");
            } else {
                println!("Shared munmap double-call protection failed.");
            }
        } else {
            println!("Shared mmap test failed: syscall returned 0.");
        }

        // Cross-process shared memory regression:
        // parent writes magic, child maps same key and writes back.
        // Child intentionally exits without munmap to verify exit-time detach path.
        println!("Testing cross-process shared memory...");
        let shm_key = sys_shm_alloc(ep_cap, 4096);
        if shm_key == 0 {
            println!("Cross-process SHM test failed: alloc returned 0.");
        } else {
            let parent_map_ret = sys_shm_map(ep_cap, shm_key, SHM_PARENT_VADDR);
            if parent_map_ret != 0 {
                println!("Cross-process SHM test failed: parent map failed.");
            } else {
                unsafe {
                    let p = SHM_PARENT_VADDR as *mut u64;
                    *p = SHM_PARENT_MAGIC;
                }

                let mut key_buf = [0u8; 20];
                let key_arg = usize_to_decimal_str(shm_key, &mut key_buf);
                let shm_child_pid = sys_spawn(ep_cap, "/bin/hello", &["shm_child", key_arg], &[]);
                if shm_child_pid < 0 {
                    println!("Cross-process SHM test failed: child spawn failed.");
                } else {
                    let mut child_status: usize = 0;
                    let mut child_reaped = false;
                    for _ in 0..2000 {
                        let (wpid, status) = sys_wait(ep_cap, shm_child_pid, 1);
                        if wpid == shm_child_pid {
                            child_status = status;
                            child_reaped = true;
                            break;
                        }
                        if wpid < 0 {
                            println!("Cross-process SHM test failed: wait returned {}.", wpid);
                            break;
                        }
                        sys_yield(ep_cap);
                    }

                    if !child_reaped {
                        println!("Cross-process SHM test timeout, trying to kill child...");
                        let _ = sys_kill(ep_cap, shm_child_pid as usize, 9);
                        for _ in 0..256 {
                            let (wpid, status) = sys_wait(ep_cap, shm_child_pid, 1);
                            if wpid == shm_child_pid {
                                child_status = status;
                                child_reaped = true;
                                break;
                            }
                            if wpid < 0 {
                                break;
                            }
                            sys_yield(ep_cap);
                        }
                    }

                    unsafe {
                        let p = SHM_PARENT_VADDR as *mut u64;
                        if child_reaped
                            && child_status == 124
                            && *p == SHM_CHILD_MAGIC
                        {
                            println!("Cross-process SHM test passed.");
                        } else {
                            println!(
                                "Cross-process SHM test failed: reaped={}, status={}, value=0x{:x}.",
                                child_reaped,
                                child_status,
                                *p
                            );
                        }
                    }
                }
            }
        }

        if shm_key != 0 {
            let parent_unmap_ret = sys_munmap_shared(ep_cap, SHM_PARENT_VADDR, 4096);
            if parent_unmap_ret == 0 {
                println!("Cross-process SHM cleanup passed.");
            } else {
                println!(
                    "Cross-process SHM cleanup failed: {}.",
                    parent_unmap_ret
                );
            }
        }

        // Test Global Allocator
        println!("Initializing Global Allocator...");
        let heap_size = 64 * 1024; // 64KB
        let heap_start = sys_brk(ep_cap, 0);
        let heap_end = sys_brk(ep_cap, heap_start + heap_size);
        
        println!("Heap Range: 0x{:x} - 0x{:x}", heap_start, heap_end);

        if heap_end == heap_start + heap_size {
             println!("Heap block allocated. Initializing Allocator...");
             allocator::init_heap(heap_start, heap_size);
             
             // Test Vec
             println!("Testing Vec...");
             {
                 let mut v = Vec::new();
                 v.push(10);
                 v.push(20);
                 v.push(30);
                 println!("Vec: {:?}", v);
             }
             println!("Vec test passed!");
        } else {
             println!("Failed to allocate heap for allocator!");
        }

        // Test Process Management
        println!("Testing Process Management...");
    println!("[USER APP] About to call sys_spawn...");
    // Use standard sys_spawn
    let child_pid = sys_spawn(ep_cap, "/bin/hello", &["arg1", "arg2"], &["TEST_ENV=NovaOS"]);
        
        if child_pid >= 0 {
            println!("Spawned child PID: {}", child_pid);
            let (wpid, status) = sys_wait(ep_cap, child_pid, 0);
            println!("Waited for child {}, status: {}", wpid, status);
            
            if wpid == child_pid && status == 123 {
                println!("Process Management Test Passed!");
            } else {
                println!("Process Management Test Failed! (Expected status 123, got {})", status);
            }
        } else {
            println!("Failed to spawn child!");
        }

        // Test sys_kill
        println!("Testing sys_kill...");
        let child_pid_kill = sys_spawn(ep_cap, "/bin/hello", &["loop"], &[]);
        if child_pid_kill >= 0 {
             println!("Spawned child to kill PID: {}", child_pid_kill);
             sys_yield(ep_cap);
             
             println!("Killing child {}...", child_pid_kill);
             if sys_kill(ep_cap, child_pid_kill as usize, 9) == 0 {
                 println!("Kill signal sent.");
                 let (wpid, status) = sys_wait(ep_cap, child_pid_kill, 0);
                 println!("Waited for killed child {}, status: {}", wpid, status);
                 
                 // status -1 cast to usize is u64::MAX
                 if wpid == child_pid_kill && (status as isize) == -1 {
                     println!("Kill Test Passed!");
                 } else {
                     println!("Kill Test Failed! Status: {} (Expected -1)", status as isize);
                 }
             } else {
                 println!("Kill Test Failed: sys_kill returned error.");
             }
        }

    } else {
        println!("Process {} (Child) Started!", pid);
        println!(
            "[FS_CMD] parsed touch={} rm={} mkdir={} cp={} mv={} truncate={} chmod={} chown={} link={} symlink={} cat={} ls={} writetest={} write={} encrypt={} decrypt={} sync={} smoke={} syscall_smoke={} loop={} shm={}",
            early_args.fs_touch_path().is_some(),
            early_args.fs_rm_path().is_some(),
            early_args.fs_mkdir_path().is_some(),
            early_args.fs_cp_paths().is_some(),
            early_args.fs_mv_paths().is_some(),
            early_args.fs_truncate_args().is_some(),
            early_args.fs_chmod_args().is_some(),
            early_args.fs_chown_args().is_some(),
            early_args.fs_link_paths().is_some(),
            early_args.fs_symlink_paths().is_some(),
            early_args.fs_cat_path().is_some(),
            early_args.fs_ls_path().is_some(),
            early_args.fs_writetest_args().is_some(),
            early_args.fs_write_args().is_some(),
            early_args.fs_encrypt_path().is_some(),
            early_args.fs_decrypt_path().is_some(),
            early_args.fs_sync,
            early_args.fs_proxy_smoke,
            early_args.fs_syscall_smoke,
            early_args.loop_mode,
            early_args.shm_child_key.is_some()
        );

        if let Some(key) = early_args.shm_child_key {
            println!("Child entering shared-memory verification mode...");
            if sys_shm_map(ep_cap, key, SHM_CHILD_VADDR) != 0 {
                println!("Child SHM map failed.");
                sys_exit(ep_cap, 201);
            }
            unsafe {
                let p = SHM_CHILD_VADDR as *mut u64;
                if *p != SHM_PARENT_MAGIC {
                    println!("Child SHM read mismatch.");
                    sys_exit(ep_cap, 202);
                }
                *p = SHM_CHILD_MAGIC;
            }
            // Intentionally do not call munmap here to verify exit-time detach/reclaim path.
            println!("Child SHM verification passed.");
            sys_exit(ep_cap, 124);
        } else if let Some(path) = early_args.fs_touch_path() {
            let code = run_fs_touch(envp, path);
            sys_exit(ep_cap, code as usize);
        } else if let Some(path) = early_args.fs_ls_path() {
            let code = run_fs_ls(envp, path);
            sys_exit(ep_cap, code as usize);
        } else if let Some(path) = early_args.fs_cd_path() {
            let code = run_fs_cd(envp, path);
            sys_exit(ep_cap, code as usize);
        } else if let Some((path, kb)) = early_args.fs_writetest_args() {
            let code = run_fs_writetest(envp, path, kb);
            sys_exit(ep_cap, code as usize);
        } else if let Some(path) = early_args.fs_rm_path() {
            let code = run_fs_rm(envp, path);
            sys_exit(ep_cap, code as usize);
        } else if let Some(path) = early_args.fs_mkdir_path() {
            let code = run_fs_mkdir(envp, path);
            sys_exit(ep_cap, code as usize);
        } else if let Some((src, dest)) = early_args.fs_cp_paths() {
            let code = run_fs_cp(envp, src, dest);
            sys_exit(ep_cap, code as usize);
        } else if let Some((src, dest)) = early_args.fs_mv_paths() {
            let code = run_fs_mv(envp, src, dest);
            sys_exit(ep_cap, code as usize);
        } else if let Some((path, size)) = early_args.fs_truncate_args() {
            let code = run_fs_truncate(envp, path, size);
            sys_exit(ep_cap, code as usize);
        } else if let Some((path, mode)) = early_args.fs_chmod_args() {
            let code = run_fs_chmod(envp, path, mode);
            sys_exit(ep_cap, code as usize);
        } else if let Some((path, uid, gid)) = early_args.fs_chown_args() {
            let code = run_fs_chown(envp, path, uid, gid);
            sys_exit(ep_cap, code as usize);
        } else if let Some((target, link_path)) = early_args.fs_link_paths() {
            let code = run_fs_link(envp, target, link_path);
            sys_exit(ep_cap, code as usize);
        } else if let Some((target, link_path)) = early_args.fs_symlink_paths() {
            let code = run_fs_symlink(envp, target, link_path);
            sys_exit(ep_cap, code as usize);
        } else if let Some(path) = early_args.fs_cat_path() {
            let code = run_fs_cat(envp, path);
            sys_exit(ep_cap, code as usize);
        } else if let Some((path, content)) = early_args.fs_write_args() {
            let code = run_fs_write_text(envp, path, content);
            sys_exit(ep_cap, code as usize);
        } else if let Some(path) = early_args.fs_encrypt_path() {
            let code = run_fs_encrypt(envp, path);
            sys_exit(ep_cap, code as usize);
        } else if let Some(path) = early_args.fs_decrypt_path() {
            let code = run_fs_decrypt(envp, path);
            sys_exit(ep_cap, code as usize);
        } else if early_args.fs_sync {
            let code = run_fs_sync(envp);
            sys_exit(ep_cap, code as usize);
        } else if early_args.fs_proxy_smoke {
            let code = run_fs_proxy_smoke(envp);
            sys_exit(ep_cap, code as usize);
        } else if early_args.fs_syscall_smoke {
            let code = run_fs_syscall_smoke(ep_cap);
            sys_exit(ep_cap, code as usize);
        } else if early_args.loop_mode {
             println!("Child entering infinite loop...");
             loop {
                 sys_yield(ep_cap);
             }
        } else {
            println!("Child exiting with code 123...");
            sys_exit(ep_cap, 123);
        }
    }
    
    sys_exit(ep_cap, 0);
}

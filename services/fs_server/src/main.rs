#![no_std]
#![no_main]

extern crate alloc;
#[macro_use]
extern crate libnova;

mod allocator;
#[path = "../../rootserver/src/crypto.rs"]
mod crypto;
#[path = "../../rootserver/src/vfs.rs"]
mod vfs;

mod drivers {
    pub mod block {
        include!("../../rootserver/src/drivers/block.rs");
    }

    pub mod rtc {
        use core::sync::atomic::{AtomicUsize, Ordering};
        use libnova::syscall::sys_get_unix_time;
        use sel4_sys::seL4_CPtr;

        static SYSCALL_EP: AtomicUsize = AtomicUsize::new(0);

        pub fn set_syscall_ep(ep: seL4_CPtr) {
            SYSCALL_EP.store(ep as usize, Ordering::Relaxed);
        }

        pub struct RtcDriver;

        impl RtcDriver {
            pub fn new() -> Self {
                Self
            }

            pub fn get_unix_timestamp(&self) -> u64 {
                let ep = SYSCALL_EP.load(Ordering::Relaxed) as seL4_CPtr;
                if ep == 0 {
                    0
                } else {
                    sys_get_unix_time(ep)
                }
            }
        }
    }
}

mod fs {
    pub mod block_cache {
        include!("../../rootserver/src/fs/block_cache.rs");
    }
    pub mod novafs {
        include!("../../rootserver/src/fs/novafs.rs");
    }
    pub mod strategy {
        include!("../../rootserver/src/fs/strategy.rs");
    }
}

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use drivers::block::BlockDevice;
use libnova::fs_ipc::{
    fs_err_not_implemented_word, FS_LABEL_CHMOD, FS_LABEL_CHOWN, FS_LABEL_CLOSE, FS_LABEL_LINK,
    FS_LABEL_MKDIR, FS_LABEL_OPEN, FS_LABEL_PING, FS_LABEL_READ, FS_LABEL_REFRESH, FS_LABEL_RENAME,
    FS_LABEL_SYNC, FS_LABEL_SYMLINK, FS_LABEL_TRUNCATE, FS_LABEL_UNLINK, FS_LABEL_WRITE, FS_PROTO_V1,
    FS_STATUS_READY,
};
use libnova::ipc;
use libnova::syscall::{
    sys_block_info, sys_block_read, sys_block_write, sys_brk, sys_fs_view_epoch, sys_service_set_ready,
};
use sel4_sys::{seL4_CPtr, seL4_IPCBuffer, seL4_Word};
use spin::Mutex;
use vfs::{FileSystem, FileType, Inode};

static OPEN_COUNT: AtomicU64 = AtomicU64::new(0);
static READ_COUNT: AtomicU64 = AtomicU64::new(0);
static WRITE_COUNT: AtomicU64 = AtomicU64::new(0);
static CLOSE_COUNT: AtomicU64 = AtomicU64::new(0);
static FS_STATE: Mutex<Option<FsState>> = Mutex::new(None);
static DISK_FS: Mutex<Option<Arc<dyn FileSystem>>> = Mutex::new(None);
static LOCAL_FS_EPOCH: AtomicU64 = AtomicU64::new(0);

const FS_ERR_BADF: i64 = -9;
const FS_ERR_NOENT: i64 = -2;
const FS_ERR_INVAL: i64 = -22;
const FS_ERR_MFILE: i64 = -24;
const FS_ERR_IO: i64 = -5;
const FS_ERR_NOTEMPTY: i64 = -39;
const MAX_TRACKED_FDS: usize = 32;
const MAX_PATH_LEN: usize = 255;
const MAX_RW_LEN: usize = 900;

struct FdEntry {
    inode: Arc<dyn Inode>,
    offset: usize,
    mode: u64,
}

struct FsState {
    fds: [Option<FdEntry>; MAX_TRACKED_FDS],
}

impl FsState {
    fn new() -> Self {
        Self {
            fds: core::array::from_fn(|_| None),
        }
    }
}

struct RemoteBlockDevice {
    syscall_ep_cap: seL4_CPtr,
    sector_count: u64,
    rotational: bool,
}

impl RemoteBlockDevice {
    fn new(syscall_ep_cap: seL4_CPtr) -> Result<Self, &'static str> {
        println!("[FS_SERVER] requesting block info via syscall ep {}", syscall_ep_cap);
        let Some((sector_count, rotational)) = sys_block_info(syscall_ep_cap) else {
            return Err("disk-info-unavailable");
        };
        println!(
            "[FS_SERVER] block info ok sectors={} rotational={}",
            sector_count,
            rotational
        );

        Ok(Self {
            syscall_ep_cap,
            sector_count,
            rotational,
        })
    }
}

impl BlockDevice for RemoteBlockDevice {
    fn read_block(&self, block_id: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        if buf.len() != 512 {
            return Err("invalid-block-buffer");
        }
        if self.sector_count > 0 && block_id as u64 >= self.sector_count {
            return Err("block-out-of-range");
        }

        let mut block = [0u8; 512];
        if block_id < 4 {
            println!("[FS_SERVER] read_block {}", block_id);
        }
        let res = sys_block_read(self.syscall_ep_cap, block_id, &mut block);
        if res != 512 {
            return Err("block-read-failed");
        }
        buf.copy_from_slice(&block);
        Ok(())
    }

    fn write_block(&self, block_id: u32, buf: &[u8]) -> Result<(), &'static str> {
        if buf.len() != 512 {
            return Err("invalid-block-buffer");
        }
        if self.sector_count > 0 && block_id as u64 >= self.sector_count {
            return Err("block-out-of-range");
        }

        let mut block = [0u8; 512];
        block.copy_from_slice(buf);
        let res = sys_block_write(self.syscall_ep_cap, block_id, &block);
        if res < 0 {
            return Err("block-write-failed");
        }
        Ok(())
    }

    fn is_rotational(&self) -> bool {
        self.rotational
    }
}

#[inline]
fn pack_u32_pair(high: u64, low: u64) -> u64 {
    ((high & 0xFFFF_FFFF) << 32) | (low & 0xFFFF_FFFF)
}

fn copy_bytes_from_msg(start_word: usize, requested_len: usize, msg_words: usize, out: &mut [u8]) -> usize {
    let available_words = msg_words.saturating_sub(start_word);
    let available_bytes = available_words.saturating_mul(core::mem::size_of::<seL4_Word>());
    let len = core::cmp::min(requested_len, core::cmp::min(available_bytes, out.len()));
    let ipc_buf = unsafe { &*sel4_sys::seL4_GetIPCBuffer() };
    for (i, dst) in out.iter_mut().enumerate().take(len) {
        let word_idx = start_word + (i / 8);
        let byte_idx = i % 8;
        let word = ipc_buf.msg[word_idx];
        *dst = ((word >> (byte_idx * 8)) & 0xFF) as u8;
    }
    len
}

fn write_bytes_to_msg(start_word: usize, data: &[u8]) {
    let ipc_buf = unsafe { &mut *sel4_sys::seL4_GetIPCBuffer() };
    let words = data.len().div_ceil(8);
    for w in 0..words {
        ipc_buf.msg[start_word + w] = 0;
    }
    for (i, b) in data.iter().enumerate() {
        let word_idx = start_word + (i / 8);
        let shift = ((i % 8) * 8) as seL4_Word;
        ipc_buf.msg[word_idx] |= (*b as seL4_Word) << shift;
    }
}

fn current_fs() -> Option<Arc<dyn FileSystem>> {
    DISK_FS.lock().as_ref().cloned()
}

fn mount_local_fs(syscall_ep_cap: seL4_CPtr) -> Result<(), &'static str> {
    drivers::rtc::set_syscall_ep(syscall_ep_cap);
    let device = Arc::new(RemoteBlockDevice::new(syscall_ep_cap)?);
    let fs = fs::novafs::NovaFS::new(device, 0)?;
    let fs_arc = Arc::new(fs.clone());
    let fs_trait: Arc<dyn FileSystem> = fs_arc;
    *DISK_FS.lock() = Some(fs_trait);
    LOCAL_FS_EPOCH.store(sys_fs_view_epoch(syscall_ep_cap), Ordering::Relaxed);
    Ok(())
}

fn refresh_local_fs(syscall_ep_cap: seL4_CPtr) -> Result<(), &'static str> {
    {
        let mut state = FS_STATE.lock();
        *state = Some(FsState::new());
    }
    mount_local_fs(syscall_ep_cap)
}

fn ensure_local_fs_fresh(syscall_ep_cap: seL4_CPtr) -> Result<(), &'static str> {
    let remote_epoch = sys_fs_view_epoch(syscall_ep_cap);
    let local_epoch = LOCAL_FS_EPOCH.load(Ordering::Relaxed);
    if remote_epoch != 0 && remote_epoch != local_epoch {
        println!(
            "[FS_SERVER] refreshing stale view local_epoch={} remote_epoch={}",
            local_epoch, remote_epoch
        );
        refresh_local_fs(syscall_ep_cap)?;
    }
    Ok(())
}

fn resolve_parent<'a>(fs: &Arc<dyn FileSystem>, path: &'a str) -> Result<(Arc<dyn Inode>, &'a str), i64> {
    if path.is_empty() || path == "/" {
        return Err(FS_ERR_INVAL);
    }

    if let Some(idx) = path.rfind('/') {
        let (parent_path, name_with_slash) = path.split_at(idx);
        let name = &name_with_slash[1..];
        if name.is_empty() {
            return Err(FS_ERR_INVAL);
        }
        let parent_path = if parent_path.is_empty() { "/" } else { parent_path };
        fs.resolve_path("/", parent_path)
            .map(|parent| (parent, name))
            .map_err(|_| FS_ERR_INVAL)
    } else {
        Ok((fs.root_inode(), path))
    }
}

fn open_inode(fs: &Arc<dyn FileSystem>, path: &str, mode: u64) -> Result<FdEntry, i64> {
    let inode = match fs.resolve_path("/", path) {
        Ok(inode) => inode,
        Err(_) => {
            if mode == 0 {
                return Err(FS_ERR_INVAL);
            }
            let (parent, name) = resolve_parent(fs, path)?;
            parent
                .create(name, FileType::File)
                .map_err(|_| FS_ERR_IO)?
        }
    };

    let offset = if mode == 3 {
        inode.metadata().map(|meta| meta.size).unwrap_or(0)
    } else {
        0
    };

    Ok(FdEntry { inode, offset, mode })
}

fn local_unlink(fs: &Arc<dyn FileSystem>, path: &str) -> i64 {
    let Ok((parent, name)) = resolve_parent(fs, path) else {
        return FS_ERR_INVAL;
    };
    match parent.remove(name) {
        Ok(()) => 0,
        Err("Directory not empty") => FS_ERR_NOTEMPTY,
        Err("File not found") => FS_ERR_NOENT,
        Err(e) => {
            println!("[FS_SERVER] unlink error path={} err={}", path, e);
            FS_ERR_IO
        }
    }
}

fn local_rename(fs: &Arc<dyn FileSystem>, old_path: &str, new_path: &str) -> i64 {
    let Ok((old_parent, old_name)) = resolve_parent(fs, old_path) else {
        return FS_ERR_INVAL;
    };
    let Ok((new_parent, new_name)) = resolve_parent(fs, new_path) else {
        return FS_ERR_INVAL;
    };
    match old_parent.rename(old_name, &new_parent, new_name) {
        Ok(()) => 0,
        Err(_) => FS_ERR_IO,
    }
}

fn local_link(fs: &Arc<dyn FileSystem>, target_path: &str, link_path: &str) -> i64 {
    let Ok(target_inode) = fs.resolve_path("/", target_path) else {
        return FS_ERR_INVAL;
    };
    let Ok((parent, name)) = resolve_parent(fs, link_path) else {
        return FS_ERR_INVAL;
    };
    match parent.link(name, target_inode.as_ref()) {
        Ok(()) => 0,
        Err(_) => FS_ERR_IO,
    }
}

fn local_symlink(fs: &Arc<dyn FileSystem>, target: &str, link_path: &str) -> i64 {
    let Ok((parent, name)) = resolve_parent(fs, link_path) else {
        return FS_ERR_INVAL;
    };
    match parent.create(name, FileType::Symlink) {
        Ok(inode) => match inode.write_at(0, target.as_bytes()) {
            Ok(_) => 0,
            Err(_) => FS_ERR_IO,
        },
        Err(_) => FS_ERR_IO,
    }
}

fn local_mkdir(fs: &Arc<dyn FileSystem>, path: &str) -> i64 {
    let Ok((parent, name)) = resolve_parent(fs, path) else {
        return FS_ERR_INVAL;
    };
    match parent.create(name, FileType::Directory) {
        Ok(_) => match fs.sync() {
            Ok(()) => 0,
            Err(_) => FS_ERR_IO,
        },
        Err(_) => FS_ERR_IO,
    }
}

fn local_truncate(fs: &Arc<dyn FileSystem>, path: &str, size: u64) -> i64 {
    let inode = match fs.resolve_path("/", path) {
        Ok(inode) => inode,
        Err(_) => match fs.create_file(path) {
            Ok(inode) => inode,
            Err(_) => return FS_ERR_IO,
        },
    };
    match inode.control(3, size) {
        Ok(_) => 0,
        Err(_) => FS_ERR_IO,
    }
}

fn local_chmod(fs: &Arc<dyn FileSystem>, path: &str, mode: u16) -> i64 {
    let Ok(inode) = fs.resolve_path("/", path) else {
        return FS_ERR_NOENT;
    };
    match inode.control(4, mode as u64) {
        Ok(_) => 0,
        Err(_) => FS_ERR_IO,
    }
}

fn local_chown(fs: &Arc<dyn FileSystem>, path: &str, uid: u32, gid: u32) -> i64 {
    let Ok(inode) = fs.resolve_path("/", path) else {
        return FS_ERR_NOENT;
    };
    if inode.control(5, uid as u64).is_err() {
        return FS_ERR_IO;
    }
    if inode.control(6, gid as u64).is_err() {
        return FS_ERR_IO;
    }
    0
}

fn local_sync(fs: &Arc<dyn FileSystem>) -> i64 {
    match fs.sync() {
        Ok(()) => 0,
        Err(_) => FS_ERR_IO,
    }
}

#[no_mangle]
pub static mut __sel4_ipc_buffer: *mut seL4_IPCBuffer = 0x3000_0000 as *mut seL4_IPCBuffer;

#[no_mangle]
pub extern "C" fn _start(
    argc: usize,
    argv: *const *const u8,
    ep_cap_usize: usize,
    _envp: *const *const u8,
) -> ! {
    let syscall_ep_cap = ep_cap_usize as seL4_CPtr;
    libnova::console::init_console(ep_cap_usize);
    println!("[FS_SERVER] _start syscall_ep={}", syscall_ep_cap);

    let heap_size = 256 * 1024;
    let heap_start = sys_brk(syscall_ep_cap, 0);
    let heap_end = sys_brk(syscall_ep_cap, heap_start + heap_size);
    if heap_end == heap_start + heap_size {
        allocator::init_heap(heap_start, heap_size);
        println!("[FS_SERVER] heap initialized start=0x{:x} size={}", heap_start, heap_size);
    } else {
        println!(
            "[FS_SERVER] heap init failed start=0x{:x} requested={} got=0x{:x}",
            heap_start,
            heap_size,
            heap_end
        );
    }

    let mut service_ep_cap = syscall_ep_cap;
    unsafe {
        if argc > 0 && !argv.is_null() {
            let arg0 = *argv;
            if !arg0.is_null() {
                let mut slot: usize = 0;
                let mut seen_digit = false;
                let mut valid = true;
                let mut i = 0usize;
                loop {
                    let b = *arg0.add(i);
                    if b == 0 {
                        break;
                    }
                    if b.is_ascii_digit() {
                        seen_digit = true;
                        slot = slot
                            .saturating_mul(10)
                            .saturating_add((b - b'0') as usize);
                    } else {
                        valid = false;
                        break;
                    }
                    i += 1;
                    if i > 20 {
                        valid = false;
                        break;
                    }
                }
                if valid && seen_digit && slot != 0 {
                    service_ep_cap = slot as seL4_CPtr;
                }
            }
        }
    }
    println!("[FS_SERVER] listening service_ep={}", service_ep_cap);

    {
        let mut state = FS_STATE.lock();
        *state = Some(FsState::new());
    }

    match mount_local_fs(syscall_ep_cap) {
        Ok(()) => {
            println!("[FS_SERVER] NovaFS mounted on remote block device.");
            let ready_res = sys_service_set_ready(syscall_ep_cap, "fs.v1");
            if ready_res == 0 {
                println!("[FS_SERVER] service marked ready.");
            } else {
                println!("[FS_SERVER] failed to mark service ready ({})", ready_res);
            }
        }
        Err(e) => println!("[FS_SERVER] mount failed: {}", e),
    }

    loop {
        let (_badge, info) = ipc::recv(service_ep_cap);
        let label = info.label();

        match label {
            FS_LABEL_PING => {
                ipc::set_mr(0, if current_fs().is_some() { FS_STATUS_READY } else { 0 });
                ipc::set_mr(1, FS_PROTO_V1);
                let open = OPEN_COUNT.load(Ordering::Relaxed);
                let close = CLOSE_COUNT.load(Ordering::Relaxed);
                let read = READ_COUNT.load(Ordering::Relaxed);
                let write = WRITE_COUNT.load(Ordering::Relaxed);
                ipc::set_mr(2, pack_u32_pair(open, close));
                ipc::set_mr(3, pack_u32_pair(read, write));
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 4));
            }
            FS_LABEL_REFRESH => {
                let res = match refresh_local_fs(syscall_ep_cap) {
                    Ok(()) => 0,
                    Err(e) => {
                        println!("[FS_SERVER] refresh failed: {}", e);
                        FS_ERR_IO
                    }
                };
                ipc::set_mr(0, res as u64);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_OPEN => {
                let path_len = ipc::get_mr(0) as usize;
                let mode = ipc::get_mr(1);
                let mut path_buf = [0u8; MAX_PATH_LEN];
                let actual_len = copy_bytes_from_msg(2, path_len, info.length() as usize, &mut path_buf);
                let path_str = match core::str::from_utf8(&path_buf[..actual_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };
                if ensure_local_fs_fresh(syscall_ep_cap).is_err() {
                    ipc::set_mr(0, FS_ERR_IO as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }
                println!("[FS_SERVER] open path={} mode={}", path_str, mode);

                let Some(fs) = current_fs() else {
                    ipc::set_mr(0, FS_ERR_IO as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                };

                let entry = match open_inode(&fs, path_str, mode) {
                    Ok(entry) => entry,
                    Err(err) => {
                        ipc::set_mr(0, err as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                let mut state_guard = FS_STATE.lock();
                let state = match state_guard.as_mut() {
                    Some(s) => s,
                    None => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                let Some((idx, slot)) = state.fds.iter_mut().enumerate().find(|(_, entry)| entry.is_none()) else {
                    ipc::set_mr(0, FS_ERR_MFILE as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                };

                *slot = Some(entry);
                let fd = (idx + 3) as u64;
                OPEN_COUNT.fetch_add(1, Ordering::Relaxed);
                ipc::set_mr(0, fd);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_CLOSE => {
                let fd = ipc::get_mr(0);
                let Some(idx) = fd.checked_sub(3).and_then(|v| usize::try_from(v).ok()) else {
                    ipc::set_mr(0, FS_ERR_BADF as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                };

                let mut state_guard = FS_STATE.lock();
                let state = match state_guard.as_mut() {
                    Some(s) => s,
                    None => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                if idx < state.fds.len() && state.fds[idx].take().is_some() {
                    CLOSE_COUNT.fetch_add(1, Ordering::Relaxed);
                    ipc::set_mr(0, 0);
                } else {
                    ipc::set_mr(0, FS_ERR_BADF as u64);
                }
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_UNLINK => {
                let path_len = ipc::get_mr(0) as usize;
                let mut path_buf = [0u8; MAX_PATH_LEN];
                let actual_len = copy_bytes_from_msg(1, path_len, info.length() as usize, &mut path_buf);
                let path_str = match core::str::from_utf8(&path_buf[..actual_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };
                if ensure_local_fs_fresh(syscall_ep_cap).is_err() {
                    ipc::set_mr(0, FS_ERR_IO as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }
                let res = current_fs().map(|fs| local_unlink(&fs, path_str)).unwrap_or(FS_ERR_IO);
                ipc::set_mr(0, res as u64);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_MKDIR => {
                let path_len = ipc::get_mr(0) as usize;
                let mut path_buf = [0u8; MAX_PATH_LEN];
                let actual_len = copy_bytes_from_msg(1, path_len, info.length() as usize, &mut path_buf);
                let path_str = match core::str::from_utf8(&path_buf[..actual_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };
                if ensure_local_fs_fresh(syscall_ep_cap).is_err() {
                    ipc::set_mr(0, FS_ERR_IO as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }
                let res = current_fs().map(|fs| local_mkdir(&fs, path_str)).unwrap_or(FS_ERR_IO);
                ipc::set_mr(0, res as u64);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_TRUNCATE => {
                let path_len = ipc::get_mr(0) as usize;
                let size = ipc::get_mr(1);
                let mut path_buf = [0u8; MAX_PATH_LEN];
                let actual_len = copy_bytes_from_msg(2, path_len, info.length() as usize, &mut path_buf);
                let path_str = match core::str::from_utf8(&path_buf[..actual_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };
                if ensure_local_fs_fresh(syscall_ep_cap).is_err() {
                    ipc::set_mr(0, FS_ERR_IO as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }
                let res = current_fs()
                    .map(|fs| local_truncate(&fs, path_str, size))
                    .unwrap_or(FS_ERR_IO);
                ipc::set_mr(0, res as u64);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_CHMOD => {
                let path_len = ipc::get_mr(0) as usize;
                let mode = ipc::get_mr(1) as u16;
                let mut path_buf = [0u8; MAX_PATH_LEN];
                let actual_len = copy_bytes_from_msg(2, path_len, info.length() as usize, &mut path_buf);
                let path_str = match core::str::from_utf8(&path_buf[..actual_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };
                if ensure_local_fs_fresh(syscall_ep_cap).is_err() {
                    ipc::set_mr(0, FS_ERR_IO as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }
                let res = current_fs()
                    .map(|fs| local_chmod(&fs, path_str, mode))
                    .unwrap_or(FS_ERR_IO);
                ipc::set_mr(0, res as u64);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_CHOWN => {
                let path_len = ipc::get_mr(0) as usize;
                let uid = ipc::get_mr(1) as u32;
                let gid = ipc::get_mr(2) as u32;
                let mut path_buf = [0u8; MAX_PATH_LEN];
                let actual_len = copy_bytes_from_msg(3, path_len, info.length() as usize, &mut path_buf);
                let path_str = match core::str::from_utf8(&path_buf[..actual_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };
                if ensure_local_fs_fresh(syscall_ep_cap).is_err() {
                    ipc::set_mr(0, FS_ERR_IO as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }
                let res = current_fs()
                    .map(|fs| local_chown(&fs, path_str, uid, gid))
                    .unwrap_or(FS_ERR_IO);
                ipc::set_mr(0, res as u64);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_SYNC => {
                if ensure_local_fs_fresh(syscall_ep_cap).is_err() {
                    ipc::set_mr(0, FS_ERR_IO as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }
                let res = current_fs().map(|fs| local_sync(&fs)).unwrap_or(FS_ERR_IO);
                ipc::set_mr(0, res as u64);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_RENAME => {
                let old_len = ipc::get_mr(0) as usize;
                let new_len = ipc::get_mr(1) as usize;
                if old_len == 0 || old_len > MAX_PATH_LEN || new_len == 0 || new_len > MAX_PATH_LEN {
                    ipc::set_mr(0, FS_ERR_INVAL as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let mut path_buf = [0u8; MAX_PATH_LEN * 2];
                let actual_len = copy_bytes_from_msg(2, old_len + new_len, info.length() as usize, &mut path_buf);
                if actual_len < old_len + new_len {
                    ipc::set_mr(0, FS_ERR_INVAL as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let old_path = match core::str::from_utf8(&path_buf[..old_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };
                let new_path = match core::str::from_utf8(&path_buf[old_len..old_len + new_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                if ensure_local_fs_fresh(syscall_ep_cap).is_err() {
                    ipc::set_mr(0, FS_ERR_IO as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }
                let res = current_fs()
                    .map(|fs| local_rename(&fs, old_path, new_path))
                    .unwrap_or(FS_ERR_IO);
                ipc::set_mr(0, res as u64);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_LINK => {
                let target_len = ipc::get_mr(0) as usize;
                let link_len = ipc::get_mr(1) as usize;
                if target_len == 0 || target_len > MAX_PATH_LEN || link_len == 0 || link_len > MAX_PATH_LEN {
                    ipc::set_mr(0, FS_ERR_INVAL as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let mut path_buf = [0u8; MAX_PATH_LEN * 2];
                let actual_len = copy_bytes_from_msg(2, target_len + link_len, info.length() as usize, &mut path_buf);
                if actual_len < target_len + link_len {
                    ipc::set_mr(0, FS_ERR_INVAL as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let target_path = match core::str::from_utf8(&path_buf[..target_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };
                let link_path = match core::str::from_utf8(&path_buf[target_len..target_len + link_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                if ensure_local_fs_fresh(syscall_ep_cap).is_err() {
                    ipc::set_mr(0, FS_ERR_IO as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }
                let res = current_fs()
                    .map(|fs| local_link(&fs, target_path, link_path))
                    .unwrap_or(FS_ERR_IO);
                ipc::set_mr(0, res as u64);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_SYMLINK => {
                let target_len = ipc::get_mr(0) as usize;
                let link_len = ipc::get_mr(1) as usize;
                if target_len == 0 || target_len > MAX_PATH_LEN || link_len == 0 || link_len > MAX_PATH_LEN {
                    ipc::set_mr(0, FS_ERR_INVAL as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let mut path_buf = [0u8; MAX_PATH_LEN * 2];
                let actual_len = copy_bytes_from_msg(2, target_len + link_len, info.length() as usize, &mut path_buf);
                if actual_len < target_len + link_len {
                    ipc::set_mr(0, FS_ERR_INVAL as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let target = match core::str::from_utf8(&path_buf[..target_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };
                let link_path = match core::str::from_utf8(&path_buf[target_len..target_len + link_len]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                if ensure_local_fs_fresh(syscall_ep_cap).is_err() {
                    ipc::set_mr(0, FS_ERR_IO as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }
                let res = current_fs()
                    .map(|fs| local_symlink(&fs, target, link_path))
                    .unwrap_or(FS_ERR_IO);
                ipc::set_mr(0, res as u64);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_WRITE => {
                let fd = ipc::get_mr(0);
                let len = ipc::get_mr(1) as usize;
                let Some(idx) = fd.checked_sub(3).and_then(|v| usize::try_from(v).ok()) else {
                    ipc::set_mr(0, FS_ERR_BADF as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                };

                let mut state_guard = FS_STATE.lock();
                let state = match state_guard.as_mut() {
                    Some(s) => s,
                    None => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                let Some(entry) = state.fds.get_mut(idx).and_then(Option::as_mut) else {
                    ipc::set_mr(0, FS_ERR_BADF as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                };

                if entry.mode == 0 {
                    ipc::set_mr(0, FS_ERR_BADF as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let mut data = [0u8; MAX_RW_LEN];
                let data_len = copy_bytes_from_msg(2, len, info.length() as usize, &mut data);
                if entry.mode == 3 {
                    if let Ok(meta) = entry.inode.metadata() {
                        entry.offset = meta.size;
                    }
                }

                let written = match entry.inode.write_at(entry.offset, &data[..data_len]) {
                    Ok(n) => {
                        entry.offset += n;
                        WRITE_COUNT.fetch_add(1, Ordering::Relaxed);
                        n as i64
                    }
                    Err(_) => FS_ERR_IO,
                };

                ipc::set_mr(0, written as u64);
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
            FS_LABEL_READ => {
                let fd = ipc::get_mr(0);
                let len = ipc::get_mr(1) as usize;
                let Some(idx) = fd.checked_sub(3).and_then(|v| usize::try_from(v).ok()) else {
                    ipc::set_mr(0, FS_ERR_BADF as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                };

                let mut state_guard = FS_STATE.lock();
                let state = match state_guard.as_mut() {
                    Some(s) => s,
                    None => {
                        ipc::set_mr(0, FS_ERR_INVAL as u64);
                        ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                        continue;
                    }
                };

                let Some(entry) = state.fds.get_mut(idx).and_then(Option::as_mut) else {
                    ipc::set_mr(0, FS_ERR_BADF as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                };

                if entry.mode == 1 {
                    ipc::set_mr(0, FS_ERR_BADF as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let capped_len = core::cmp::min(len, MAX_RW_LEN);
                let mut out = [0u8; MAX_RW_LEN];
                let read_res = match entry.inode.read_at(entry.offset, &mut out[..capped_len]) {
                    Ok(n) => {
                        entry.offset += n;
                        READ_COUNT.fetch_add(1, Ordering::Relaxed);
                        n as i64
                    }
                    Err(_) => FS_ERR_IO,
                };
                if read_res < 0 {
                    ipc::set_mr(0, read_res as u64);
                    ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
                    continue;
                }

                let read_len = read_res as usize;
                ipc::set_mr(0, read_len as u64);
                write_bytes_to_msg(1, &out[..read_len]);
                let words = 1 + read_len.div_ceil(8) as u64;
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, words));
            }
            _ => {
                ipc::set_mr(0, fs_err_not_implemented_word());
                ipc::reply(ipc::MessageInfo::new(0, 0, 0, 1));
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

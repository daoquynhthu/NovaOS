#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
#[macro_use]
extern crate libnova;

pub mod ata;
pub mod block_cache;
pub mod block_device;
pub mod crypto;
pub mod novafs;
pub mod strategy;
pub mod vfs;

pub use block_device::BlockDevice;
#[cfg(any(test, feature = "std"))]
pub use block_device::MockBlockDevice;
pub use crypto::ChaCha20;
pub use novafs::{DirEntry, DiskInode, NovaFS, SuperBlock};
pub use strategy::{create_strategy, IOStrategy};
pub use vfs::{check_permission, resolve_path, FileStat, FileSystem, FileType, Inode, VFS};

use spin::Mutex;

/// Global wall-clock timestamp used by NovaFS for atime/ctime/mtime.
/// The environment (RootServer, tests, etc.) is responsible for keeping it
/// reasonably up to date via [`set_wall_clock`].
pub static WALL_CLOCK: Mutex<u64> = Mutex::new(0);

pub fn wall_clock() -> u64 {
    *WALL_CLOCK.lock()
}

pub fn set_wall_clock(ts: u64) {
    *WALL_CLOCK.lock() = ts;
}

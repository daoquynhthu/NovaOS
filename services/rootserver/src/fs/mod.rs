pub mod novafs;
pub mod block_cache;
pub mod strategy;

use spin::Mutex;
use crate::vfs::FileSystem;
use alloc::sync::Arc;

// Global FS instance
pub static DISK_FS: Mutex<Option<Arc<dyn FileSystem>>> = Mutex::new(None);

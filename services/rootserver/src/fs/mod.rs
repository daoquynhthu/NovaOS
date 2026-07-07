use alloc::sync::Arc;
use novafs_core::FileSystem;
use spin::Mutex;

// Global FS instance
pub static DISK_FS: Mutex<Option<Arc<dyn FileSystem>>> = Mutex::new(None);

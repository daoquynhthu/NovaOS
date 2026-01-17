pub mod simplefs;

use spin::Mutex;
use crate::drivers::ata::AtaDriver;
use crate::fs::simplefs::SimpleFS;

pub static DISK_FS: Mutex<Option<SimpleFS<AtaDriver>>> = Mutex::new(None);

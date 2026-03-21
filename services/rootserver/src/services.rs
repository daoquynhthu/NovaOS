use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use libnova::fs_ipc::{FS_LABEL_PING, FS_PROTO_V1, FS_STATUS_READY};
use core::sync::atomic::{AtomicU64, Ordering};
use sel4_sys::{seL4_CPtr, seL4_Word};
use spin::Mutex;

static SERVICE_REGISTRY: Mutex<Option<BTreeMap<String, seL4_CPtr>>> = Mutex::new(None);
static FS_FWD_OPEN: AtomicU64 = AtomicU64::new(0);
static FS_FWD_CLOSE: AtomicU64 = AtomicU64::new(0);
static FS_FWD_READ: AtomicU64 = AtomicU64::new(0);
static FS_FWD_WRITE: AtomicU64 = AtomicU64::new(0);

pub fn init() {
    let mut registry = SERVICE_REGISTRY.lock();
    *registry = Some(BTreeMap::new());
}

pub fn register(name: &str, endpoint: seL4_CPtr) {
    let mut lock = SERVICE_REGISTRY.lock();
    if let Some(registry) = lock.as_mut() {
        registry.insert(String::from(name), endpoint);
    }
}

#[allow(dead_code)]
pub fn lookup(name: &str) -> Option<seL4_CPtr> {
    let lock = SERVICE_REGISTRY.lock();
    if let Some(registry) = lock.as_ref() {
        registry.get(name).cloned()
    } else {
        None
    }
}

fn parse_versioned_name(name: &str) -> Option<(&str, u32)> {
    let (base, version_part) = name.rsplit_once(".v")?;
    if base.is_empty() {
        return None;
    }
    let version = version_part.parse::<u32>().ok()?;
    Some((base, version))
}

pub fn lookup_latest(base_name: &str) -> Option<(String, seL4_CPtr, u32)> {
    let lock = SERVICE_REGISTRY.lock();
    let registry = lock.as_ref()?;

    let mut best_name: Option<String> = None;
    let mut best_ep: seL4_CPtr = 0;
    let mut best_version = 0u32;
    let mut found = false;

    for (name, endpoint) in registry.iter() {
        if let Some((base, version)) = parse_versioned_name(name) {
            if base == base_name && (!found || version > best_version) {
                best_name = Some(name.clone());
                best_ep = *endpoint;
                best_version = version;
                found = true;
            }
        }
    }

    if found {
        Some((best_name.expect("name exists"), best_ep, best_version))
    } else {
        None
    }
}

pub fn list() -> Vec<(String, seL4_CPtr)> {
    let lock = SERVICE_REGISTRY.lock();
    if let Some(registry) = lock.as_ref() {
        registry
            .iter()
            .map(|(name, ep)| (name.clone(), *ep))
            .collect()
    } else {
        Vec::new()
    }
}

pub fn note_fs_forward(label: seL4_Word) {
    match label {
        libnova::fs_ipc::FS_LABEL_OPEN => {
            FS_FWD_OPEN.fetch_add(1, Ordering::Relaxed);
        }
        libnova::fs_ipc::FS_LABEL_CLOSE => {
            FS_FWD_CLOSE.fetch_add(1, Ordering::Relaxed);
        }
        libnova::fs_ipc::FS_LABEL_READ => {
            FS_FWD_READ.fetch_add(1, Ordering::Relaxed);
        }
        libnova::fs_ipc::FS_LABEL_WRITE => {
            FS_FWD_WRITE.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

pub fn ping(name: &str) -> Result<(seL4_Word, seL4_Word, seL4_Word, seL4_Word), &'static str> {
    let _endpoint = if let Some(ep) = lookup(name) {
        ep
    } else if let Some((_resolved, ep, _version)) = lookup_latest(name) {
        ep
    } else {
        return Err("service-not-found");
    };

    let _ = FS_LABEL_PING;
    let open_count = FS_FWD_OPEN.load(Ordering::Relaxed) as seL4_Word;
    let close_count = FS_FWD_CLOSE.load(Ordering::Relaxed) as seL4_Word;
    let read_count = FS_FWD_READ.load(Ordering::Relaxed) as seL4_Word;
    let write_count = FS_FWD_WRITE.load(Ordering::Relaxed) as seL4_Word;
    Ok((
        FS_STATUS_READY,
        FS_PROTO_V1,
        (open_count << 32) | (close_count & 0xFFFF_FFFF),
        (read_count << 32) | (write_count & 0xFFFF_FFFF),
    ))
}

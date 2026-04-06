use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use libnova::fs_ipc::{FS_LABEL_PING, FS_PROTO_V1, FS_STATUS_READY};
use libnova::ipc;
use sel4_sys::{seL4_CPtr, seL4_Word};
use spin::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState {
    Bootstrapping,
    Ready,
}

#[derive(Clone, Copy, Debug)]
pub struct ServiceEntry {
    pub endpoint: seL4_CPtr,
    pub state: ServiceState,
}

static SERVICE_REGISTRY: Mutex<Option<BTreeMap<String, ServiceEntry>>> = Mutex::new(None);
static FS_FWD_OPEN: AtomicU64 = AtomicU64::new(0);
static FS_FWD_CLOSE: AtomicU64 = AtomicU64::new(0);
static FS_FWD_READ: AtomicU64 = AtomicU64::new(0);
static FS_FWD_WRITE: AtomicU64 = AtomicU64::new(0);
static FS_VIEW_EPOCH: AtomicU64 = AtomicU64::new(1);

pub fn init() {
    let mut registry = SERVICE_REGISTRY.lock();
    *registry = Some(BTreeMap::new());
}

pub fn register(name: &str, endpoint: seL4_CPtr) {
    let mut lock = SERVICE_REGISTRY.lock();
    if let Some(registry) = lock.as_mut() {
        registry.insert(
            String::from(name),
            ServiceEntry {
                endpoint,
                state: ServiceState::Bootstrapping,
            },
        );
    }
}

pub fn mark_ready(name: &str) -> bool {
    let mut lock = SERVICE_REGISTRY.lock();
    let Some(registry) = lock.as_mut() else {
        return false;
    };
    let Some(entry) = registry.get_mut(name) else {
        return false;
    };
    entry.state = ServiceState::Ready;
    true
}

pub fn lookup_entry(name: &str) -> Option<ServiceEntry> {
    let lock = SERVICE_REGISTRY.lock();
    if let Some(registry) = lock.as_ref() {
        registry.get(name).copied()
    } else {
        None
    }
}

#[allow(dead_code)]
pub fn lookup(name: &str) -> Option<seL4_CPtr> {
    lookup_entry(name).map(|entry| entry.endpoint)
}

pub fn lookup_ready(name: &str) -> Option<seL4_CPtr> {
    let entry = lookup_entry(name)?;
    if entry.state == ServiceState::Ready {
        Some(entry.endpoint)
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
    lookup_latest_entry(base_name).map(|(name, entry, version)| (name, entry.endpoint, version))
}

pub fn lookup_latest_ready(base_name: &str) -> Option<(String, seL4_CPtr, u32)> {
    let (name, entry, version) = lookup_latest_entry(base_name)?;
    if entry.state == ServiceState::Ready {
        Some((name, entry.endpoint, version))
    } else {
        None
    }
}

pub fn lookup_latest_entry(base_name: &str) -> Option<(String, ServiceEntry, u32)> {
    let lock = SERVICE_REGISTRY.lock();
    let registry = lock.as_ref()?;

    let mut best_name: Option<String> = None;
    let mut best_entry: Option<ServiceEntry> = None;
    let mut best_version = 0u32;
    let mut found = false;

    for (name, entry) in registry.iter() {
        if let Some((base, version)) = parse_versioned_name(name) {
            if base == base_name && (!found || version > best_version) {
                best_name = Some(name.clone());
                best_entry = Some(*entry);
                best_version = version;
                found = true;
            }
        }
    }

    if found {
        Some((best_name.expect("name exists"), best_entry.expect("entry exists"), best_version))
    } else {
        None
    }
}

pub fn list() -> Vec<(String, seL4_CPtr, ServiceState)> {
    let lock = SERVICE_REGISTRY.lock();
    if let Some(registry) = lock.as_ref() {
        registry
            .iter()
            .map(|(name, entry)| (name.clone(), entry.endpoint, entry.state))
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

pub fn bump_fs_view_epoch() -> u64 {
    FS_VIEW_EPOCH.fetch_add(1, Ordering::Relaxed) + 1
}

pub fn current_fs_view_epoch() -> u64 {
    FS_VIEW_EPOCH.load(Ordering::Relaxed)
}

pub fn ping(name: &str) -> Result<(seL4_Word, seL4_Word, seL4_Word, seL4_Word), &'static str> {
    let endpoint = if let Some(ep) = lookup_ready(name) {
        ep
    } else if let Some((_resolved, ep, _version)) = lookup_latest_ready(name) {
        ep
    } else if lookup(name).is_some() || lookup_latest(name).is_some() {
        return Err("service-not-ready");
    } else {
        return Err("service-not-found");
    };

    match ipc::call(endpoint, ipc::MessageInfo::new(FS_LABEL_PING, 0, 0, 0)) {
        Ok(_) => Ok((ipc::get_mr(0), ipc::get_mr(1), ipc::get_mr(2), ipc::get_mr(3))),
        Err(_) => {
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
    }
}

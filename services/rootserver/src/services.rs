use alloc::collections::BTreeMap;
use alloc::string::String;
use sel4_sys::seL4_CPtr;
use spin::Mutex;

static SERVICE_REGISTRY: Mutex<Option<BTreeMap<String, seL4_CPtr>>> = Mutex::new(None);

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

use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

// 1MB Heap for RootServer
// Align to 4096 bytes (page size) to ensure compatibility and efficiency
#[repr(align(4096))]
#[allow(dead_code)]
struct HeapMem([u8; 1024 * 1024]);

static mut HEAP_MEM: HeapMem = HeapMem([0; 1024 * 1024]);
static mut INITIALIZED: bool = false;

pub fn init_heap() {
    unsafe {
        if INITIALIZED {
            return;
        }
        let heap_start = core::ptr::addr_of_mut!(HEAP_MEM) as *mut u8;
        ALLOCATOR.lock().init(heap_start, 1024 * 1024);
        INITIALIZED = true;
    }
}

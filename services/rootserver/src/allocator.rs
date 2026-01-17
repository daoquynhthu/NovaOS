use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

// 1MB Heap for RootServer
static mut HEAP_MEM: [u8; 1024 * 1024] = [0; 1024 * 1024];

pub fn init_heap() {
    unsafe {
        let heap_start = core::ptr::addr_of_mut!(HEAP_MEM) as *mut u8;
        ALLOCATOR.lock().init(heap_start, 1024 * 1024);
    }
}

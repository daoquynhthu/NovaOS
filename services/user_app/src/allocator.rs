use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

pub fn init_heap(start: usize, size: usize) {
    unsafe {
        ALLOCATOR.lock().init(start as *mut u8, size);
    }
}

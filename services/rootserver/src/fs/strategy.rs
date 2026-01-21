use alloc::vec::Vec;

pub trait IOStrategy: Send + Sync {
    /// Reorder a list of block IDs for optimal access.
    /// Returns a new vector with sorted/scheduled block IDs.
    fn schedule(&self, requests: &[u32]) -> Vec<u32>;
    
    fn name(&self) -> &'static str;
}

/// Elevator Strategy (SCAN algorithm)
/// Sorts requests by Block ID (LBA) in ascending order.
/// Ideal for Rotational Drives (HDD) to minimize seek time.
pub struct ElevatorStrategy;

impl IOStrategy for ElevatorStrategy {
    fn schedule(&self, requests: &[u32]) -> Vec<u32> {
        let mut sorted = requests.to_vec();
        sorted.sort_unstable();
        sorted
    }

    fn name(&self) -> &'static str {
        "Elevator (SCAN)"
    }
}

/// No-op Strategy (FIFO)
/// Keeps requests in original order.
/// Ideal for Non-Rotational Drives (SSD) where random access is fast
/// and reordering overhead is unnecessary.
pub struct NoopStrategy;

impl IOStrategy for NoopStrategy {
    fn schedule(&self, requests: &[u32]) -> Vec<u32> {
        requests.to_vec()
    }

    fn name(&self) -> &'static str {
        "No-op (FIFO)"
    }
}

pub fn create_strategy(is_rotational: bool) -> alloc::boxed::Box<dyn IOStrategy> {
    if is_rotational {
        alloc::boxed::Box::new(ElevatorStrategy)
    } else {
        alloc::boxed::Box::new(NoopStrategy)
    }
}

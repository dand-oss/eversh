//! Process-wide Rust allocator request counters for diagnostic builds only.
//! Counts include failed requests and reallocations, not net live bytes or
//! native allocations bypassing Rust's global allocator. Counters are separate
//! atomic observations, not a transactional cross-thread allocation ledger.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub struct CountingAllocator;
static CALLS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
static OVERFLOW: AtomicBool = AtomicBool::new(false);

fn add(counter: &AtomicU64, amount: u64) {
    if counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(amount)
        })
        .is_err()
    {
        OVERFLOW.store(true, Ordering::Relaxed);
    }
}

fn request(bytes: usize) {
    add(&CALLS, 1);
    add(&BYTES, bytes as u64);
}

pub fn snapshot() -> (u64, u64, bool) {
    (
        CALLS.load(Ordering::Relaxed),
        BYTES.load(Ordering::Relaxed),
        OVERFLOW.load(Ordering::Relaxed),
    )
}

// SAFETY: every operation forwards the original pointer/layout unchanged to
// System. Bookkeeping uses only atomics and cannot recursively allocate.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        request(layout.size());
        // SAFETY: caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        request(layout.size());
        // SAFETY: forwarding the caller's layout unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        request(size);
        // SAFETY: caller owns a System allocation and satisfies realloc's contract.
        unsafe { System.realloc(pointer, layout, size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: forwarding exactly the allocation pointer/layout from caller.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_count_and_system_zeroing_is_preserved() {
        let allocator = CountingAllocator;
        let before = snapshot();
        let layout = Layout::from_size_align(32, 8).expect("layout");
        // SAFETY: valid layout, checked pointer and matching deallocation.
        unsafe {
            let pointer = allocator.alloc_zeroed(layout);
            assert!(!pointer.is_null());
            assert!(std::slice::from_raw_parts(pointer, 32)
                .iter()
                .all(|byte| *byte == 0));
            allocator.dealloc(pointer, layout);
        }
        let after = snapshot();
        assert!(after.0 > before.0);
        assert!(after.1 >= before.1 + 32);
        assert!(!after.2);
    }
}

//! Separate allocator probe; never use its elapsed time for throughput claims.
mod write_matrix_support;

use praxis::{PraxisEngine, WriteBatch};
use serde_json::json;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct CountingAllocator;

thread_local! {
    static ENABLED: Cell<bool> = const { Cell::new(false) };
    static CALLS: Cell<u64> = const { Cell::new(0) };
    static BYTES: Cell<u64> = const { Cell::new(0) };
}

fn record(size: usize) {
    if ENABLED.try_with(Cell::get).unwrap_or(false) {
        let _ = CALLS.try_with(|calls| calls.set(calls.get() + 1));
        let _ = BYTES.try_with(|bytes| bytes.set(bytes.get() + size as u64));
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn measure(engine: &PraxisEngine, batches: Vec<WriteBatch>, _probe: bool) -> serde_json::Value {
    CALLS.set(0);
    BYTES.set(0);
    ENABLED.set(true);
    for batch in batches {
        engine.write_batch(batch).unwrap();
    }
    ENABLED.set(false);
    json!({
        "measurement": "thread_local_allocation_probe",
        "allocation_calls": CALLS.get(),
        "allocated_bytes": BYTES.get(),
    })
}

fn main() {
    write_matrix_support::run(measure);
}

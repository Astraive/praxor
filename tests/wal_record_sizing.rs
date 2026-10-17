use bytes::Bytes;
use praxis::wal::WalRecord;
use praxis::{ColumnFamily, WriteBatch};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct CountingAllocator;
thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn record_allocation() {
    if TRACK.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation();
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn mixed_record() -> WalRecord {
    let cf = ColumnFamily("tenant/α".to_string());
    let mut batch = WriteBatch::new();
    batch.put_default(Bytes::new(), Bytes::new());
    batch.put(cf.clone(), "key", Bytes::from(vec![42; 4096]));
    batch.put_with_expiry(cf.clone(), "ttl", "expiring", 123_456);
    batch.merge(cf.clone(), "key", "delta");
    batch.delete(cf, "gone");
    WalRecord {
        sequence: 123,
        batch,
    }
}

#[test]
fn encoded_length_matches_every_operation_without_allocating() {
    let record = mixed_record();
    let expected = record.encode().len();
    ALLOCATIONS.with(|count| count.set(0));
    TRACK.with(|track| track.set(true));
    let actual = std::hint::black_box(record.encoded_len());
    TRACK.with(|track| track.set(false));
    let allocations = ALLOCATIONS.with(Cell::get);
    assert_eq!(actual, expected);
    assert_eq!(
        allocations, 0,
        "measuring a WAL record must not encode or allocate it"
    );
}

#[test]
fn empty_batch_length_still_includes_record_and_batch_headers() {
    let record = WalRecord {
        sequence: 0,
        batch: WriteBatch::new(),
    };
    assert_eq!(record.encoded_len(), record.encode().len());
}

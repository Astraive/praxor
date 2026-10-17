//! Measure live encoder workspace, excluding the already-owned batch. No
//! production hook or allocator behavior is changed outside this test binary.
use praxis::transactions::WriteBatch;
use praxis::wal::WalRecord;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct EncoderAllocator;
thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}
fn allocation_delta(delta: isize) {
    let _ = TRACK.try_with(|track| {
        if track.get() {
            LIVE.with(|live| {
                let next = live.get() + delta;
                live.set(next);
                PEAK.with(|peak| peak.set(peak.get().max(next)));
            });
        }
    });
}
unsafe impl GlobalAlloc for EncoderAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            allocation_delta(layout.size() as isize);
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            allocation_delta(layout.size() as isize);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        allocation_delta(-(layout.size() as isize));
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let replacement = unsafe { System.realloc(pointer, layout, size) };
        if !replacement.is_null() {
            allocation_delta(size as isize - layout.size() as isize);
        }
        replacement
    }
}
#[global_allocator]
static ALLOCATOR: EncoderAllocator = EncoderAllocator;

#[test]
fn ordinary_encoding_needs_one_frame_buffer_not_an_additional_payload_copy() {
    let mut batch = WriteBatch::new();
    batch.put_default("put", vec![1; 1024 * 1024]);
    batch.put_with_expiry("other", "expiry", vec![2; 257], u64::MAX);
    batch.merge("other", "merge", vec![3; 129]);
    batch.delete("other", "delete");
    let record = WalRecord {
        sequence: u64::MAX,
        batch,
    };
    let expected = record.try_encoded_len().unwrap();
    LIVE.with(|live| live.set(0));
    PEAK.with(|peak| peak.set(0));
    TRACK.with(|track| track.set(true));
    let encoded = record.try_encode().unwrap();
    TRACK.with(|track| track.set(false));
    let peak = PEAK.with(Cell::get);
    assert_eq!(encoded.len(), expected);
    assert!(
        peak as usize <= expected + 512,
        "encoder live workspace {peak} exceeds one frame {expected}"
    );
    assert_eq!(WalRecord::decode(&encoded, "one-frame").unwrap(), record);
}

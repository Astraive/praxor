use praxis::index::SpecializedEngineContract;
use praxis::store::{StorageEngine, StorageManifest};
use std::alloc::{GlobalAlloc, Layout, System};
use std::borrow::Cow;
use std::cell::Cell;

struct ScopedAllocationCounter;

thread_local! {
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static OUTSTANDING_BYTES: Cell<isize> = const { Cell::new(0) };
}

fn record_allocation_change(bytes: isize) {
    let _ = TRACK_ALLOCATIONS.try_with(|tracking| {
        if tracking.get() {
            OUTSTANDING_BYTES.with(|outstanding| outstanding.set(outstanding.get() + bytes));
        }
    });
}

unsafe impl GlobalAlloc for ScopedAllocationCounter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation_change(layout.size() as isize);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation_change(layout.size() as isize);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record_allocation_change(-(layout.size() as isize));
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let replacement = unsafe { System.realloc(pointer, layout, new_size) };
        if !replacement.is_null() {
            record_allocation_change(new_size as isize - layout.size() as isize);
        }
        replacement
    }
}

#[global_allocator]
static ALLOCATOR: ScopedAllocationCounter = ScopedAllocationCounter;

fn dynamic_manifest() -> StorageManifest {
    let dir = tempfile::tempdir().unwrap();
    let engine = StorageEngine::open(dir.path(), 1024).unwrap();
    let mut manifest = engine.manifest().clone();
    manifest.durable_files[0].checksum = format!("custom-checksum-{}", 42);
    manifest.durable_files[0].format_version = 7;
    manifest
}

#[test]
fn descriptor_owns_dynamic_checksum_after_source_and_original_are_dropped() {
    let descriptor = dynamic_manifest().durable_files[0].to_kernel_descriptor();
    assert!(matches!(descriptor.format.checksum, Cow::Owned(_)));
    assert_eq!(descriptor.format.checksum, "custom-checksum-42");
    assert!(descriptor.format.validate().is_ok());
    let cloned = descriptor.clone();
    drop(descriptor);
    assert_eq!(cloned.format.checksum, "custom-checksum-42");
    assert_eq!(cloned.format.format_version, 7);
}

#[test]
fn static_engine_checksum_names_remain_borrowed() {
    for contract in SpecializedEngineContract::shipping_defaults() {
        assert!(matches!(contract.format.checksum, Cow::Borrowed("crc32c")));
    }
}

#[test]
fn dropping_repeated_dynamic_descriptors_releases_every_allocation() {
    let manifest = dynamic_manifest();
    let record = &manifest.durable_files[0];
    // Initialize the thread-local counters before tracking. The input remains
    // alive throughout, so only descriptor allocations and frees are measured.
    OUTSTANDING_BYTES.with(|outstanding| outstanding.set(0));
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    for _ in 0..2_048 {
        let descriptor = record.to_kernel_descriptor();
        std::hint::black_box(&descriptor);
        drop(descriptor);
    }
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    let outstanding = OUTSTANDING_BYTES.with(Cell::get);
    assert_eq!(
        outstanding, 0,
        "dropped descriptors retained heap allocations"
    );
}

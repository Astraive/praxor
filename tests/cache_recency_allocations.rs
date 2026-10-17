use bytes::Bytes;
use praxis::cache::BlockCache;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static LIVE_BYTES: Cell<isize> = const { Cell::new(0) };
}

struct CountingAllocator;

fn record_allocation(delta: isize, allocation: bool) {
    if TRACK_ALLOCATIONS.try_with(Cell::get).unwrap_or(false) {
        if allocation {
            ALLOCATIONS.with(|count| count.set(count.get() + 1));
        }
        LIVE_BYTES.with(|live| live.set(live.get() + delta));
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size() as isize, true);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size() as isize, true);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record_allocation(-(layout.size() as isize), false);
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let pointer = unsafe { System.realloc(pointer, layout, size) };
        if !pointer.is_null() {
            record_allocation(size as isize - layout.size() as isize, true);
        }
        pointer
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn allocations_during(operation: impl FnOnce()) -> usize {
    ALLOCATIONS.with(|count| count.set(0));
    LIVE_BYTES.with(|live| live.set(0));
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    operation();
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    ALLOCATIONS.with(Cell::get)
}

#[test]
fn retain_releases_lookup_allocation_even_when_deleted_buckets_reduce_reported_capacity() {
    use std::hash::{Hash, Hasher};

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CollidingKey(usize);

    impl Hash for CollidingKey {
        fn hash<H: Hasher>(&self, state: &mut H) {
            0_usize.hash(state);
        }
    }

    let mut retained = 0;
    let mut after_drop = 0;
    allocations_during(|| {
        let mut cache = BlockCache::new(896);
        for key in 0..896 {
            cache.insert(CollidingKey(key), Bytes::from_static(b"v"));
        }
        cache.retain(|key| key.0 == 0);
        retained = LIVE_BYTES.with(Cell::get);
        drop(cache);
        after_drop = LIVE_BYTES.with(Cell::get);
    });
    assert_eq!(
        after_drop, 0,
        "allocator probe did not balance cache ownership"
    );
    assert!(
        retained < 8_192,
        "one resident retained {retained} bytes of cache allocations"
    );
}

#[test]
fn warmed_hits_do_not_allocate_owned_keys_or_recency_buffers() {
    let key: Box<[u8]> = Box::from(&b"an owned cache key"[..]);
    let mut cache = BlockCache::new(1);
    cache.insert(key.clone(), Bytes::from_static(b"v"));

    let allocations = allocations_during(|| {
        for _ in 0..4_096 {
            std::hint::black_box(cache.get(&key));
        }
    });

    assert_eq!(allocations, 0, "warmed hits allocated cache metadata");
    assert_eq!(cache.get(&key), Some(Bytes::from_static(b"v")));
}

#[test]
fn occupied_insert_does_not_clone_the_callers_owned_key() {
    let keys: Vec<Box<[u8]>> = (0..4_096)
        .map(|_| Box::from(&b"an owned cache key"[..]))
        .collect();
    let mut cache = BlockCache::new(1);
    cache.insert(keys[0].clone(), Bytes::from_static(b"v"));

    // The caller has already constructed each owned input before counting.
    let allocations = allocations_during(|| {
        for key in keys {
            cache.insert(key, Bytes::from_static(b"x"));
        }
    });

    assert_eq!(allocations, 0, "occupied insert cloned its owned input");
    let lookup: Box<[u8]> = Box::from(&b"an owned cache key"[..]);
    assert_eq!(cache.get(&lookup), Some(Bytes::from_static(b"x")));
}

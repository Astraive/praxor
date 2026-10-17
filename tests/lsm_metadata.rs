use praxis::{IndexPlugin, LsmIndex, RecordId};
use serde_json::json;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::Path;
use tempfile::tempdir;

#[derive(Clone, Copy, Debug, Default)]
struct Allocations {
    calls: usize,
    bytes: usize,
}

thread_local! {
    // Only count the current test's measured region, even with parallel tests.
    static ALLOCATIONS: Cell<Option<Allocations>> = const { Cell::new(None) };
}

struct CountingAllocator;

fn count_allocation(bytes: usize) {
    let _ = ALLOCATIONS.try_with(|counts| {
        if let Some(mut current) = counts.get() {
            current.calls += 1;
            current.bytes += bytes;
            counts.set(Some(current));
        }
    });
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_allocation(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_allocation(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count_allocation(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn allocations_during(f: impl FnOnce()) -> Allocations {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ALLOCATIONS.set(None);
        }
    }
    ALLOCATIONS.set(Some(Allocations::default()));
    let _reset = Reset;
    f();
    ALLOCATIONS.get().unwrap()
}

fn key(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn write_legacy_fixture(dir: &Path, count: u64, live: bool) {
    let entries: Vec<_> = (0..count)
        .map(|i| {
            json!([
                key(i),
                [{ "sequence": 1, "rid": live.then_some(i + 1) }]
            ])
        })
        .collect();
    std::fs::write(
        dir.join("kv.lsm"),
        serde_json::to_vec(&json!({ "next_sequence": 1, "entries": entries })).unwrap(),
    )
    .unwrap();
}

#[test]
fn distinct_insertion_allocations_grow_below_quadratic() {
    let measure = |size: u64| {
        let dir = tempdir().unwrap();
        let mut index = LsmIndex::open("kv", dir.path()).unwrap();
        let keys: Vec<_> = (0..size).map(key).collect();
        let allocations = allocations_during(|| {
            for (i, key) in keys.iter().enumerate() {
                index.put(key, RecordId(i as u64 + 1)).unwrap();
            }
        });
        assert_eq!(index.stats().live_keys, size);
        allocations
    };
    let small = measure(512);
    let large = measure(1024);
    eprintln!("distinct insertion allocations: 512={small:?}, 1024={large:?}");
    assert!(
        large.calls < small.calls * 3 && large.bytes < small.bytes * 3,
        "doubling keys must not quadruple metadata allocations: {small:?} -> {large:?}"
    );
}

#[test]
fn overwriting_a_live_key_does_not_reallocate_other_keys() {
    let dir = tempdir().unwrap();
    write_legacy_fixture(dir.path(), 1024, true);
    let mut index = LsmIndex::open("kv", dir.path()).unwrap();
    let key = key(0);
    let operations = 256;
    let allocations = allocations_during(|| {
        for i in 0..operations {
            index.put(&key, RecordId(i as u64 + 1)).unwrap();
        }
    });
    eprintln!("hot overwrite allocations: {allocations:?}");
    assert!(
        allocations.calls < operations * 8 && allocations.bytes < operations * 512,
        "overwrites must only allocate for their own version history: {allocations:?}"
    );
    assert_eq!(index.stats().live_keys, 1024);
    assert_eq!(index.stats().versions, 1024 + operations as u64);
}

fn assert_live_metadata(index: &LsmIndex, expected: &BTreeMap<Vec<u8>, RecordId>, versions: u64) {
    assert_eq!(index.stats().live_keys, expected.len() as u64);
    assert_eq!(index.stats().versions, versions);
    assert_eq!(
        index.fence_bounds(),
        (
            expected.first_key_value().map(|(key, _)| key.clone()),
            expected.last_key_value().map(|(key, _)| key.clone()),
        )
    );
    for (key, rid) in expected {
        assert_eq!(index.get(key), Some(*rid));
        assert!(
            index.may_contain_key(key),
            "Bloom rejected live key {key:?}"
        );
    }
    assert_eq!(
        index.scan(None, None),
        expected
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect::<Vec<_>>()
    );
}

#[test]
fn live_metadata_tracks_boundary_changes_tombstones_and_reinsertion() {
    let dir = tempdir().unwrap();
    let mut index = LsmIndex::open("kv", dir.path()).unwrap();
    let mut live = BTreeMap::new();
    let mut versions = 0;
    assert_live_metadata(&index, &live, versions);
    for i in [2, 0, 4, 1, 3] {
        index.put(&key(i), RecordId(i + 1)).unwrap();
        live.insert(key(i), RecordId(i + 1));
        versions += 1;
        assert_live_metadata(&index, &live, versions);
    }
    for i in [0, 4, 2, 2, 99, 1, 3] {
        index.delete(&key(i)).unwrap();
        live.remove(&key(i));
        versions += 1;
        assert_live_metadata(&index, &live, versions);
    }
    assert!(!index.may_contain_key(&key(0)));
    index.put(&key(2), RecordId(42)).unwrap();
    live.insert(key(2), RecordId(42));
    assert_live_metadata(&index, &live, versions + 1);
}

#[test]
fn append_order_and_historical_reads_survive_metadata_changes_and_reopen() {
    let dir = tempdir().unwrap();
    let mut index = LsmIndex::open("kv", dir.path()).unwrap();
    index.put_with_sequence(b"k", RecordId(1), 100).unwrap();
    index.put_with_sequence(b"k", RecordId(2), 10).unwrap();
    index.delete_with_sequence(b"k", 50).unwrap();
    index.put_with_sequence(b"k", RecordId(3), 50).unwrap();
    index.delete_with_sequence(b"other", 200).unwrap();
    let assert_history = |index: &LsmIndex| {
        assert_eq!(index.get_at(b"k", 9), None);
        assert_eq!(index.get_at(b"k", 10), Some(RecordId(2)));
        assert_eq!(index.get_at(b"k", 49), Some(RecordId(2)));
        assert_eq!(index.get_at(b"k", 50), Some(RecordId(3)));
        assert_eq!(index.get_at(b"k", 100), Some(RecordId(3)));
        assert_eq!(index.get(b"k"), Some(RecordId(3)));
        assert_eq!(index.stats().live_keys, 1);
        assert_eq!(index.stats().versions, 5);
        assert!(index.may_contain_key(b"k"));
    };
    assert_history(&index);
    index.flush().unwrap();
    drop(index);
    let mut index = LsmIndex::open("kv", dir.path()).unwrap();
    assert_history(&index);
    index.put(b"k", RecordId(4)).unwrap();
    assert_eq!(index.get_at(b"k", 200), Some(RecordId(3)));
    assert_eq!(index.get_at(b"k", 201), Some(RecordId(4)));
}

#[test]
fn tombstoned_key_keeps_historical_reads_when_current_metadata_is_empty() {
    let dir = tempdir().unwrap();
    let mut index = LsmIndex::open("kv", dir.path()).unwrap();
    index.put_with_sequence(b"k", RecordId(1), 10).unwrap();
    index.delete_with_sequence(b"k", 20).unwrap();
    for _ in 0..4 {
        assert!(!index.may_contain_key(b"k"));
        assert_eq!(index.get_at(b"k", 10), Some(RecordId(1)));
        assert_eq!(index.get_at(b"k", 20), None);
        index.flush().unwrap();
        index = LsmIndex::open("kv", dir.path()).unwrap();
    }
}

#[test]
fn bloom_growth_shrink_and_churn_never_reject_live_keys() {
    let dir = tempdir().unwrap();
    let mut index = LsmIndex::open("kv", dir.path()).unwrap();
    let mut live = BTreeMap::new();
    let mut versions = 0;
    for i in 0..2048 {
        index.put(&key(i), RecordId(i + 1)).unwrap();
        live.insert(key(i), RecordId(i + 1));
        versions += 1;
        if i % 127 == 0 {
            assert_live_metadata(&index, &live, versions);
        }
    }
    // Shrink by deleting boundary and interior keys; remaining keys share bits
    // with removed keys, so clearing Bloom bits would introduce false negatives.
    for i in 0..2016 {
        index.delete(&key(i)).unwrap();
        live.remove(&key(i));
        versions += 1;
    }
    assert_live_metadata(&index, &live, versions);
    // Keep the live cardinality small while adding many stale Bloom insertions.
    for i in 10_000..12_000 {
        index.put(&key(i), RecordId(i)).unwrap();
        index.delete(&key(i)).unwrap();
        versions += 2;
    }
    assert_live_metadata(&index, &live, versions);
    assert_eq!(index.get_at(&key(0), 1), Some(RecordId(1)));
    assert_eq!(index.get(&key(0)), None);
    let false_positives = (20_000..30_000)
        .filter(|i| index.may_contain_key(&key(*i)))
        .count();
    assert!(
        false_positives < 300,
        "stale Bloom bits accumulated: {false_positives}/10000"
    );
    index.flush().unwrap();
    drop(index);
    let index = LsmIndex::open("kv", dir.path()).unwrap();
    assert_live_metadata(&index, &live, versions);
    assert_eq!(index.get_at(&key(0), 1), Some(RecordId(1)));
}

#[test]
fn legacy_metadata_is_rebuilt_then_binary_snapshot_roundtrips() {
    let dir = tempdir().unwrap();
    std::fs::write(
        dir.path().join("kv.lsm"),
        serde_json::to_vec(&json!({
            "next_sequence": 90,
            "entries": [
                [b"a".to_vec(), [{"sequence": 10, "rid": 1}, {"sequence": 20, "rid": null}]],
                [b"b".to_vec(), [{"sequence": 30, "rid": 2}]],
                [b"c".to_vec(), [{"sequence": 40, "rid": 3}]]
            ],
            "bloom_keys": [b"wrong".to_vec()],
            "fence_min": b"wrong".to_vec(),
            "fence_max": b"wrong".to_vec()
        }))
        .unwrap(),
    )
    .unwrap();
    let mut index = LsmIndex::open("kv", dir.path()).unwrap();
    let mut live = BTreeMap::from([(b"b".to_vec(), RecordId(2)), (b"c".to_vec(), RecordId(3))]);
    assert_live_metadata(&index, &live, 4);
    assert_eq!(index.get_at(b"a", 10), Some(RecordId(1)));
    index.put(b"d", RecordId(4)).unwrap();
    live.insert(b"d".to_vec(), RecordId(4));
    assert_eq!(index.get_at(b"d", 90), None);
    assert_eq!(index.get_at(b"d", 91), Some(RecordId(4)));
    index.flush().unwrap();
    let bytes = std::fs::read(dir.path().join("kv.lsm")).unwrap();
    assert_eq!(&bytes[..4], &0x4c53_4d32_u32.to_le_bytes());
    assert_eq!(bytes[4], 1, "snapshot version remains compatible");
    drop(index);
    let mut index = LsmIndex::open("kv", dir.path()).unwrap();
    assert_live_metadata(&index, &live, 5);
    index.delete(b"b").unwrap();
    live.remove(b"b".as_slice());
    assert_live_metadata(&index, &live, 6);
    index.compact().unwrap();
    assert_live_metadata(&index, &live, 2);
    index.flush().unwrap();
    let index = LsmIndex::open("kv", dir.path()).unwrap();
    assert_live_metadata(&index, &live, 2);
}

use praxis::catalog::{CatalogSnapshot, CatalogStore};
use praxis::errors::PraxisError;
use praxis::io::crc32_ieee;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct Observer;
thread_local! {
    static ON: Cell<bool> = const { Cell::new(false) };
    static MAX: Cell<usize> = const { Cell::new(0) };
}
fn record(size: usize) {
    if ON.try_with(Cell::get).unwrap_or(false) {
        let _ = MAX.try_with(|maximum| maximum.set(maximum.get().max(size)));
    }
}
unsafe impl GlobalAlloc for Observer {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: Observer = Observer;

fn envelope(payload: &[u8]) -> Vec<u8> {
    let mut bytes = 0x5443_4154_u32.to_le_bytes().to_vec();
    bytes.push(1);
    bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&crc32_ieee(payload).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
fn count_case(name: &str) {
    let dir = tempfile::tempdir().unwrap();
    let store = CatalogStore::open(dir.path()).unwrap();
    store.save(&CatalogSnapshot::default()).unwrap();
    // Safe historical repro: at most a few MiB per table, never u32::MAX.
    std::fs::write(
        store.layout().catalog_root().join(name),
        envelope(&65_536_u32.to_le_bytes()),
    )
    .unwrap();
    MAX.set(0);
    ON.set(true);
    let result = store.load();
    ON.set(false);
    assert!(result.is_err());
    let maximum = MAX.get();
    eprintln!("17-byte {name}: largest requested load allocation={maximum} bytes");
    assert!(maximum < 65_536, "17-byte {name} allocated {maximum} bytes");
}
macro_rules! counts {
    ($($test:ident => $name:literal),* $(,)?) => { $(#[test] fn $test() { count_case($name); })* };
}
counts! {
    collections_count => "collections.cat", entities_count => "entities.cat",
    fixed_attrs_count => "fixed_attrs.cat", dynamic_attrs_count => "dynamic_attrs.cat",
    indexes_count => "indexes.cat", vector_models_count => "vector_models.cat",
    fulltext_count => "fulltext.cat", graph_count => "graph.cat",
    shards_count => "shards.cat", users_count => "users.cat",
}

fn corrupt_case(name: &str, payload: &[u8], extra: bool) {
    let dir = tempfile::tempdir().unwrap();
    let store = CatalogStore::open(dir.path()).unwrap();
    store.save(&CatalogSnapshot::default()).unwrap();
    let mut bytes = envelope(payload);
    if extra {
        bytes.push(0xff);
    }
    std::fs::write(store.layout().catalog_root().join(name), bytes).unwrap();
    let result = store.load();
    assert!(
        matches!(result, Err(PraxisError::Corrupt { .. })),
        "malformed {name} accepted: {result:?}"
    );
}
#[test]
fn fixed_id_narrowing() {
    let mut payload = 1_u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&2_u32.to_le_bytes());
    payload.extend_from_slice(&0x10001_u32.to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes());
    payload.extend_from_slice(&[7, 0]);
    corrupt_case("fixed_attrs.cat", &payload, false);
}
#[test]
fn dynamic_id_narrowing() {
    let mut payload = 1_u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&2_u32.to_le_bytes());
    payload.extend_from_slice(&0x10001_u32.to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes());
    payload.extend_from_slice(&[0, 0]);
    corrupt_case("dynamic_attrs.cat", &payload, false);
}
#[test]
fn trailing_payload() {
    corrupt_case("users.cat", &[0, 0, 0, 0, 0xff], false);
}
#[test]
fn trailing_envelope() {
    corrupt_case("users.cat", &[0, 0, 0, 0], true);
}
#[test]
fn fresh_control() {
    let dir = tempfile::tempdir().unwrap();
    let store = CatalogStore::open(dir.path()).unwrap();
    store.save(&CatalogSnapshot::default()).unwrap();
    assert_eq!(store.load().unwrap(), CatalogSnapshot::default());
}

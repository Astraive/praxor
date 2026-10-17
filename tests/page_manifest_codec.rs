use praxis::io::crc32c;
use praxis::manifest::{ManifestTrackedFile, PageLayoutManifest, PageManifestStore};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct Observer;
thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static MAX: Cell<usize> = const { Cell::new(0) };
}
fn observe(size: usize) {
    let _ = TRACK.try_with(|track| {
        if track.get() {
            MAX.with(|max| max.set(max.get().max(size)));
        }
    });
}
unsafe impl GlobalAlloc for Observer {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let out = unsafe { System.alloc(layout) };
        if !out.is_null() {
            observe(layout.size());
        }
        out
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let out = unsafe { System.alloc_zeroed(layout) };
        if !out.is_null() {
            observe(layout.size());
        }
        out
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let out = unsafe { System.realloc(ptr, layout, size) };
        if !out.is_null() {
            observe(size);
        }
        out
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Observer = Observer;

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(0x5450_4d46u32.to_le_bytes());
    out.push(1);
    out.extend((payload.len() as u32).to_le_bytes());
    out.extend(crc32c(payload).to_le_bytes());
    out.extend(payload);
    out
}
fn string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend((bytes.len() as u32).to_le_bytes());
    out.extend(bytes);
}
fn row(version: u32, flag: u8) -> Vec<u8> {
    let mut payload = 1u32.to_le_bytes().to_vec();
    string(&mut payload, b"opaque/path");
    string(&mut payload, b"future-kind");
    payload.extend(version.to_le_bytes());
    string(&mut payload, b"opaque-checksum");
    payload.push(flag);
    payload
}
fn load(bytes: &[u8]) -> praxis::Result<PageLayoutManifest> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("MANIFEST.page");
    std::fs::write(&path, bytes).unwrap();
    PageManifestStore::open(path).load()
}

#[test]
fn tiny_count_does_not_allocate_from_claimed_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("MANIFEST.page");
    let bytes = frame(&65536u32.to_le_bytes());
    assert_eq!(bytes.len(), 17);
    std::fs::write(&path, bytes).unwrap();
    MAX.with(|max| max.set(0));
    TRACK.with(|track| track.set(true));
    let result = PageManifestStore::open(path).load();
    TRACK.with(|track| track.set(false));
    assert!(result.is_err());
    let max = MAX.with(Cell::get);
    eprintln!("tiny 17-byte manifest max allocation={max}");
    assert!(max <= 4096, "tiny manifest reserved {max} bytes");
}

#[test]
fn format_version_must_not_alias_to_u16() {
    assert!(load(&frame(&row(65537, 1))).is_err());
}
#[test]
fn recoverable_flag_is_closed() {
    for flag in [2, 255] {
        assert!(load(&frame(&row(1, flag))).is_err());
    }
}
#[test]
fn payload_trailing_is_refused() {
    let mut payload = row(1, 1);
    payload.push(0);
    assert!(load(&frame(&payload)).is_err());
}
#[test]
fn frame_trailing_is_refused() {
    let mut bytes = frame(&row(1, 1));
    bytes.push(0);
    assert!(load(&bytes).is_err());
}
#[test]
fn valid_v1_writer_bytes_order_duplicates_and_full_u16_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("MANIFEST.page");
    let store = PageManifestStore::open(&path);
    let item = ManifestTrackedFile {
        path: "opaque/path".into(),
        format: "future-kind".into(),
        format_version: u16::MAX,
        checksum: "opaque-checksum".into(),
        recoverable: true,
    };
    let manifest = PageLayoutManifest {
        files: vec![item.clone(), item],
    };
    store.save(&manifest).unwrap();
    let mut payload = row(u16::MAX as u32, 1);
    payload[..4].copy_from_slice(&2u32.to_le_bytes());
    payload.extend(&row(u16::MAX as u32, 1)[4..]);
    assert_eq!(std::fs::read(path).unwrap(), frame(&payload));
    assert_eq!(store.load().unwrap(), manifest);
}
#[test]
fn missing_and_empty_inventory_remain_empty_but_empty_file_is_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        PageManifestStore::open(dir.path().join("absent"))
            .load()
            .unwrap(),
        PageLayoutManifest::default()
    );
    assert_eq!(
        load(&frame(&0u32.to_le_bytes())).unwrap(),
        PageLayoutManifest::default()
    );
    assert!(load(&[]).is_err());
}
#[test]
fn checksum_and_truncation_remain_refused() {
    let bytes = frame(&row(1, 0));
    for cut in 0..bytes.len() {
        assert!(load(&bytes[..cut]).is_err());
    }
    let mut bad = bytes;
    bad[13] ^= 1;
    assert!(load(&bad).is_err());
}

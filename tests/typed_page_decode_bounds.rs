use praxis::datatype::PraxisValue;
use praxis::errors::PraxisError;
use praxis::identity::{Aid, Cid, Did, Eid, FieldId};
use praxis::io::crc32_ieee;
use praxis::record::PageRecordStore;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::path::{Path, PathBuf};

struct ObservedAllocator;

thread_local! {
    static OBSERVING: Cell<bool> = const { Cell::new(false) };
    static LARGEST: Cell<usize> = const { Cell::new(0) };
}

fn observe(size: usize) {
    if OBSERVING.try_with(Cell::get).unwrap_or(false) {
        let _ = LARGEST.try_with(|largest| largest.set(largest.get().max(size)));
    }
}

unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        observe(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        observe(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        observe(size);
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

fn observed<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    LARGEST.set(0);
    OBSERVING.set(true);
    let result = operation();
    OBSERVING.set(false);
    (result, LARGEST.get())
}

fn envelope(payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x5456_4944_u32.to_le_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&crc32_ieee(payload).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn inline_cell(kind: u8, id: u32, value: &[u8], pointer: &[u8]) -> Vec<u8> {
    let mut bytes = vec![kind];
    bytes.extend_from_slice(&id.to_le_bytes());
    bytes.extend_from_slice(&[0x70, 1]); // Bytea, Inline.
    bytes.extend_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(value);
    bytes.extend_from_slice(pointer);
    bytes
}

fn body(cells: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = u32::try_from(cells.len()).unwrap().to_le_bytes().to_vec();
    for cell in cells {
        payload.extend_from_slice(cell);
    }
    envelope(&payload)
}

fn file_tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn visit(root: &Path, path: &Path, files: &mut Vec<(PathBuf, Vec<u8>)>) {
        let mut entries: Vec<_> = std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                files.push((path.strip_prefix(root).unwrap().to_path_buf(), Vec::new()));
                visit(root, &path, files);
            } else if path == root.join(".praxor.writer.lock") {
                // The supported permanent lease is unreadable while held on
                // Windows. Keep its exact entry in the snapshot, without trying
                // to read through the active OS byte-range lock.
                assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
                files.push((path.strip_prefix(root).unwrap().to_path_buf(), Vec::new()));
            } else {
                files.push((
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(path).unwrap(),
                ));
            }
        }
    }
    let mut files = Vec::new();
    visit(root, root, &mut files);
    files
}

fn assert_corrupt_read(bytes: &[u8], field: FieldId) {
    let temporary = tempfile::tempdir().unwrap();
    let mut store = PageRecordStore::open(temporary.path(), Cid(1), Eid(2)).unwrap();
    let rid = store.put(&[(FieldId::Fixed(Aid(7)), bytes)]).unwrap();
    let before = file_tree(temporary.path());
    let result = store.get_typed_field_bytes(rid, field);
    assert!(
        matches!(result, Err(PraxisError::Corrupt { .. })),
        "malformed typed input accepted: {result:?}"
    );
    assert_eq!(
        file_tree(temporary.path()),
        before,
        "read changed disk state"
    );
    assert_eq!(
        store.get(rid).unwrap(),
        bytes,
        "malformed read poisoned the shared owner"
    );
}

#[test]
fn tiny_declared_cell_count_is_checked_before_reserving() {
    let temporary = tempfile::tempdir().unwrap();
    let mut store = PageRecordStore::open(temporary.path(), Cid(1), Eid(2)).unwrap();
    // 65,536 is deliberately bounded: the historical bug requests a few MiB,
    // never u32::MAX or a potentially process-ending allocation.
    let bytes = envelope(&65_536_u32.to_le_bytes());
    let rid = store
        .put(&[(FieldId::Fixed(Aid(7)), bytes.as_slice())])
        .unwrap();
    let (result, largest) = observed(|| store.get_typed_field_bytes(rid, FieldId::Fixed(Aid(1))));
    assert!(matches!(result, Err(PraxisError::Corrupt { .. })));
    assert!(
        largest < 65_536,
        "17-byte malformed body requested {largest} bytes"
    );
}

#[test]
fn fixed_field_id_does_not_alias_after_narrowing() {
    assert_corrupt_read(
        &body(&[inline_cell(1, 0x1_0001, b"wrong", &[0])]),
        FieldId::Fixed(Aid(1)),
    );
}

#[test]
fn dynamic_field_id_does_not_alias_after_narrowing() {
    assert_corrupt_read(
        &body(&[inline_cell(2, 0x1_0001, b"wrong", &[0])]),
        FieldId::Dynamic(Did(1)),
    );
}

#[test]
fn trailing_bytes_outside_envelope_are_refused() {
    let mut bytes = body(&[inline_cell(1, 1, b"valid", &[0])]);
    bytes.push(0x42);
    assert_corrupt_read(&bytes, FieldId::Fixed(Aid(1)));
}

#[test]
fn trailing_bytes_inside_payload_are_refused() {
    let mut payload = 1_u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&inline_cell(1, 1, b"valid", &[0]));
    payload.push(0x42);
    assert_corrupt_read(&envelope(&payload), FieldId::Fixed(Aid(1)));
}

#[test]
fn mismatched_pointer_in_later_cell_is_not_ignored() {
    let mut overflow_pointer = vec![1];
    overflow_pointer.extend_from_slice(&1_u64.to_le_bytes());
    overflow_pointer.extend_from_slice(&5_u32.to_le_bytes());
    overflow_pointer.extend_from_slice(&0_u32.to_le_bytes());
    overflow_pointer.extend_from_slice(&0_u32.to_le_bytes());
    let bytes = body(&[
        inline_cell(1, 1, b"valid", &[0]),
        inline_cell(1, 2, b"invalid", &overflow_pointer),
    ]);
    assert_corrupt_read(&bytes, FieldId::Fixed(Aid(1)));
}

#[test]
fn tiny_blob_declared_length_is_checked_before_reserving() {
    let temporary = tempfile::tempdir().unwrap();
    let mut store = PageRecordStore::open(temporary.path(), Cid(1), Eid(2)).unwrap();
    let path = store.layout().overflow_blob_path(Cid(1), Eid(2)).path;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut blob = 0x5442_4c4f_u32.to_le_bytes().to_vec();
    blob.push(1);
    blob.extend_from_slice(&65_536_u32.to_le_bytes());
    blob.extend_from_slice(&0_u32.to_le_bytes());
    std::fs::write(&path, &blob).unwrap();
    let mut cell = vec![1];
    cell.extend_from_slice(&1_u32.to_le_bytes());
    cell.extend_from_slice(&[0x31, 2]); // Json, External.
    cell.extend_from_slice(&0_u32.to_le_bytes()); // empty inline bytes.
    cell.push(1);
    cell.extend_from_slice(&1_u64.to_le_bytes());
    cell.extend_from_slice(&5_u32.to_le_bytes());
    cell.extend_from_slice(&65_536_u32.to_le_bytes());
    cell.extend_from_slice(&0_u32.to_le_bytes());
    let bytes = body(&[cell]);
    let rid = store
        .put(&[(FieldId::Fixed(Aid(7)), bytes.as_slice())])
        .unwrap();
    let before = file_tree(temporary.path());
    let (result, largest) = observed(|| store.get_typed_field_bytes(rid, FieldId::Fixed(Aid(1))));
    assert!(matches!(result, Err(PraxisError::Corrupt { .. })));
    assert!(
        largest < 65_536,
        "13-byte malformed blob requested {largest} bytes"
    );
    assert_eq!(file_tree(temporary.path()), before);
    assert_eq!(store.get(rid).unwrap(), bytes);
}

#[test]
fn valid_v1_raw_and_writer_records_remain_readable() {
    let temporary = tempfile::tempdir().unwrap();
    let mut store = PageRecordStore::open(temporary.path(), Cid(1), Eid(2)).unwrap();
    let bytes = body(&[inline_cell(1, 1, b"valid", &[0])]);
    let raw = store
        .put(&[(FieldId::Fixed(Aid(7)), bytes.as_slice())])
        .unwrap();
    assert_eq!(
        store
            .get_typed_field_bytes(raw, FieldId::Fixed(Aid(1)))
            .unwrap(),
        b"valid"
    );
    let typed = store
        .put_typed(&[(
            FieldId::Dynamic(Did(2)),
            PraxisValue::Json(b"external".to_vec()),
        )])
        .unwrap();
    assert_eq!(
        store
            .get_typed_field_bytes(typed, FieldId::Dynamic(Did(2)))
            .unwrap(),
        b"external"
    );
}

#[test]
fn malformed_tags_lengths_and_pointer_roles_are_refused_without_mutation() {
    let mut cases = Vec::new();
    for (offset, tag) in [(0, 3), (5, 0xff), (6, 0xff), (12, 0xff)] {
        let mut cell = inline_cell(1, 1, b"x", &[0]);
        cell[offset] = tag;
        cases.push(body(&[cell]));
    }
    let mut truncated_inline = inline_cell(1, 1, b"x", &[0]);
    truncated_inline[7..11].copy_from_slice(&u32::MAX.to_le_bytes());
    cases.push(body(&[truncated_inline])); // read_len_slice rejects before allocation.
    for (class, pointer_tag, file_id, offset) in [
        (2, 0, 1_u64, 5),
        (2, 1, 2, 5),
        (2, 1, 1, 0),
        (3, 2, 2, 5),
        (3, 2, 1, u64::MAX),
        (4, 0, 1, 5),
    ] {
        let mut cell = inline_cell(1, 1, &[], &[]);
        cell[6] = class;
        cell.push(pointer_tag);
        match pointer_tag {
            1 => {
                cell.extend_from_slice(&file_id.to_le_bytes());
                cell.extend_from_slice(&u32::try_from(offset).unwrap().to_le_bytes());
                cell.extend_from_slice(&0_u32.to_le_bytes());
                cell.extend_from_slice(&0_u32.to_le_bytes());
            }
            2 => {
                cell.push(1);
                cell.extend_from_slice(&file_id.to_le_bytes());
                cell.extend_from_slice(&offset.to_le_bytes());
                cell.extend_from_slice(&0_u32.to_le_bytes());
            }
            _ => {}
        }
        cases.push(body(&[cell]));
    }
    for bytes in cases {
        assert_corrupt_read(&bytes, FieldId::Fixed(Aid(1)));
    }
}

#[test]
fn known_type_tags_and_zero_duplicate_field_policy_are_preserved() {
    let temporary = tempfile::tempdir().unwrap();
    let mut store = PageRecordStore::open(temporary.path(), Cid(1), Eid(2)).unwrap();
    let tags = [
        0x01, 0x02, 0x03, 0x04, 0x10, 0x11, 0x12, 0x20, 0x30, 0x31, 0x32, 0x40, 0x50, 0x51, 0x53,
        0x60, 0x61, 0x70, 0x80, 0x81, 0x82, 0x83, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0xa0, 0xa1,
        0xa2, 0xa3, 0xb0, 0xc0, 0xc1, 0xd0, 0xd1, 0xe0, 0xe1, 0xe2,
    ];
    for tag in tags {
        let mut first = inline_cell(1, 0, b"first", &[0]);
        first[5] = tag;
        let bytes = body(&[first, inline_cell(1, 0, b"second", &[0])]);
        let rid = store
            .put(&[(FieldId::Fixed(Aid(7)), bytes.as_slice())])
            .unwrap();
        assert_eq!(
            store
                .get_typed_field_bytes(rid, FieldId::Fixed(Aid(0)))
                .unwrap(),
            b"first"
        );
    }
}

#[test]
fn supported_writer_types_roundtrip_all_storage_families() {
    let temporary = tempfile::tempdir().unwrap();
    let mut store = PageRecordStore::open(temporary.path(), Cid(1), Eid(2)).unwrap();
    let values = vec![
        PraxisValue::Int2(-7),
        PraxisValue::Int4(-77),
        PraxisValue::Int8(-777),
        PraxisValue::UInt8(77),
        PraxisValue::Float4(1.5),
        PraxisValue::Float8(-2.5),
        PraxisValue::Bool(true),
        PraxisValue::Text("small".to_string()),
        PraxisValue::Text("large".repeat(100)),
        PraxisValue::Json(b"{}".to_vec()),
        PraxisValue::Jsonb(b"[]".to_vec()),
        PraxisValue::Uuid([7; 16]),
        PraxisValue::Date(5),
        PraxisValue::TimeMicros(123),
        PraxisValue::TimestampMicros(456),
        PraxisValue::Money {
            amount: 75,
            currency: *b"USD",
            scale: 2,
        },
        PraxisValue::Enum(7),
        PraxisValue::Bytea(vec![7; 500]),
        PraxisValue::List {
            element_type: praxis::datatype::TypeCode::Int2,
            encoded_elements: vec![7; 600],
        },
        PraxisValue::Vec32 {
            dims: 2,
            data: vec![1.5, 2.5],
        },
        PraxisValue::EdgeRef {
            source: praxis::identity::Rid(1),
            target: praxis::identity::Rid(2),
            edge_type: 1,
            weight_bits: 2,
            created_at: 3,
        },
        PraxisValue::TsVector(b"word:1".to_vec()),
        PraxisValue::RidRef {
            collection: Cid(1),
            rid: praxis::identity::Rid(2),
        },
    ];
    let expected: Vec<_> = values
        .iter()
        .map(|value| {
            let encoded = praxis::datatype::DataTypeRegistry::encode(value).unwrap();
            if encoded.storage_class == praxis::datatype::StorageClass::Inline {
                encoded.inline_bytes
            } else {
                value.payload_bytes().unwrap()
            }
        })
        .collect();
    let fields: Vec<_> = values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            (
                FieldId::Fixed(Aid(u16::try_from(index + 1).unwrap())),
                value,
            )
        })
        .collect();
    let rid = store.put_typed(&fields).unwrap();
    for (index, bytes) in expected.iter().enumerate() {
        assert_eq!(
            &store.get_typed_field_bytes(rid, fields[index].0).unwrap(),
            bytes
        );
    }
    drop(store);
    let store = PageRecordStore::open(temporary.path(), Cid(1), Eid(2)).unwrap();
    for (index, bytes) in expected.iter().enumerate() {
        assert_eq!(
            &store.get_typed_field_bytes(rid, fields[index].0).unwrap(),
            bytes
        );
    }
}

#[test]
fn blob_read_allocates_for_the_validated_record_instead_of_the_whole_file() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("overflow.blob");
    let store = praxis::segments::BlobStore::open_overflow(&path).unwrap();
    let location = store.append(b"small").unwrap();
    // A sparse suffix is real file length, but irrelevant to this record. This
    // stays modest even when linked to the old whole-file reader for RED proof.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(8 * 1024 * 1024)
        .unwrap();
    let (result, largest) = observed(|| store.read(&location));
    assert_eq!(result.unwrap(), b"small");
    assert!(largest < 65_536, "five-byte read requested {largest} bytes");
}

#[test]
fn missing_typed_blob_is_a_read_error_without_initialization_or_poison() {
    let temporary = tempfile::tempdir().unwrap();
    let mut store = PageRecordStore::open(temporary.path(), Cid(1), Eid(2)).unwrap();
    let rid = store
        .put_typed(&[(FieldId::Fixed(Aid(1)), PraxisValue::Json(b"{}".to_vec()))])
        .unwrap();
    let blob = store.layout().overflow_blob_path(Cid(1), Eid(2)).path;
    std::fs::remove_file(&blob).unwrap();
    let before = file_tree(temporary.path());
    assert!(matches!(
        store.get_typed_field_bytes(rid, FieldId::Fixed(Aid(1))),
        Err(PraxisError::Corrupt { .. })
    ));
    assert_eq!(file_tree(temporary.path()), before);
    assert!(!blob.exists());
    assert!(store.get(rid).is_ok());
}

#[test]
fn full_u16_field_ids_remain_valid_for_both_kinds() {
    let temporary = tempfile::tempdir().unwrap();
    let mut store = PageRecordStore::open(temporary.path(), Cid(1), Eid(2)).unwrap();
    let bytes = body(&[
        inline_cell(1, u16::MAX.into(), b"fixed", &[0]),
        inline_cell(2, u16::MAX.into(), b"dynamic", &[0]),
    ]);
    let rid = store
        .put(&[(FieldId::Fixed(Aid(7)), bytes.as_slice())])
        .unwrap();
    assert_eq!(
        store
            .get_typed_field_bytes(rid, FieldId::Fixed(Aid(u16::MAX)))
            .unwrap(),
        b"fixed"
    );
    assert_eq!(
        store
            .get_typed_field_bytes(rid, FieldId::Dynamic(Did(u16::MAX)))
            .unwrap(),
        b"dynamic"
    );
}

#[test]
fn blob_read_refuses_directory_leaf_without_changing_it() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("overflow.blob");
    let store = praxis::segments::BlobStore::open_overflow(&path).unwrap();
    let location = store.append(b"small").unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let before = file_tree(temporary.path());
    assert!(matches!(
        store.read(&location),
        Err(PraxisError::Corrupt { .. })
    ));
    assert_eq!(file_tree(temporary.path()), before);
}

#[cfg(unix)]
#[test]
fn blob_read_refuses_symlink_leaf_without_reading_its_target() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("overflow.blob");
    let store = praxis::segments::BlobStore::open_overflow(&path).unwrap();
    let location = store.append(b"small").unwrap();
    let actual = temporary.path().join("actual.blob");
    std::fs::rename(&path, &actual).unwrap();
    std::os::unix::fs::symlink(&actual, &path).unwrap();
    let before = std::fs::read(&actual).unwrap();
    assert!(matches!(
        store.read(&location),
        Err(PraxisError::Corrupt { .. })
    ));
    assert!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&actual).unwrap(), before);
}

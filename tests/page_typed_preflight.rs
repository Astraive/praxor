use praxis::datatype::PraxisValue;
use praxis::errors::PraxisError;
use praxis::identity::{Aid, Cid, Eid, Fid, FieldId, Pid, Rid, Sid, SlotAddress};
use praxis::layout::PraxisLayout;
use praxis::page::RecordPage;
use praxis::record::{PageRecordStore, RidDirectory};
use std::path::Path;

fn bytes_if_present(path: &Path) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("cannot inspect blob fixture: {error}"),
    }
}

#[test]
fn invalid_later_typed_field_does_not_append_an_earlier_external_value() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap();
    let old = store.put(&[(FieldId::Fixed(Aid(1)), b"old")]).unwrap();
    let clone = store.clone();
    let blob_path = store.layout().overflow_blob_path(Cid(1), Eid(2)).path;
    let before = bytes_if_present(&blob_path);

    let result = store.put_typed(&[
        (FieldId::Fixed(Aid(2)), PraxisValue::Json(vec![1])),
        (
            FieldId::Fixed(Aid(3)),
            PraxisValue::Vec32 {
                dims: 2,
                data: vec![1.0],
            },
        ),
    ]);
    let unchanged = bytes_if_present(&blob_path) == before;
    let healthy = store.get(old).is_ok() && clone.get(old).is_ok();
    assert!(
        matches!(result, Err(PraxisError::InvalidConfig(_))) && unchanged && healthy,
        "pure invalid typed input: blob unchanged={unchanged}, all views healthy={healthy}"
    );
}

#[test]
fn oversized_external_field_metadata_fails_before_any_blob_append() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap();
    let old = store.put(&[(FieldId::Fixed(Aid(1)), b"old")]).unwrap();
    let blob_path = store.layout().overflow_blob_path(Cid(1), Eid(2)).path;
    let before = bytes_if_present(&blob_path);
    let fields: Vec<_> = (1..=300)
        .map(|id| (FieldId::Fixed(Aid(id)), PraxisValue::Json(vec![1])))
        .collect();

    let result = store.put_typed(&fields);
    let unchanged = bytes_if_present(&blob_path) == before;
    let healthy = store.get(old).is_ok();
    assert!(
        matches!(result, Err(PraxisError::WriteStalled { .. })) && unchanged && healthy,
        "oversized typed metadata: blob unchanged={unchanged}, owner healthy={healthy}"
    );
}

#[test]
fn typed_page_placement_exhaustion_is_checked_before_blob_append() {
    let dir = tempfile::tempdir().unwrap();
    let layout = PraxisLayout::new(dir.path());
    layout.create_all().unwrap();
    let page_path = layout.page_path(Cid(1), Eid(2), Fid(1), Pid(u32::MAX)).path;
    std::fs::create_dir_all(page_path.parent().unwrap()).unwrap();
    let mut page = RecordPage::new(1);
    page.insert(Sid(1), &vec![b'K'; 8_176]).unwrap();
    std::fs::write(&page_path, page.to_bytes()).unwrap();
    let mut directory = RidDirectory::default();
    directory.insert(
        Rid(1),
        SlotAddress {
            cid: Cid(1),
            eid: Eid(2),
            fid: Fid(1),
            pid: Pid(u32::MAX),
            sid: Sid(1),
        },
    );
    directory
        .save_binary(
            &layout.critical_map_path(Cid(1), "rid_to_slot").path,
            2,
            2,
            Pid(u32::MAX),
        )
        .unwrap();
    let mut store = PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap();
    let blob_path = layout.overflow_blob_path(Cid(1), Eid(2)).path;
    let before = bytes_if_present(&blob_path);

    let result = store.put_typed(&[(FieldId::Fixed(Aid(2)), PraxisValue::Json(vec![1]))]);
    assert!(matches!(result, Err(PraxisError::WriteStalled { .. })));
    assert_eq!(bytes_if_present(&blob_path), before);
    assert_eq!(store.get(Rid(1)).unwrap().len(), 8_176);
}

#[test]
fn larger_legacy_page_does_not_bypass_final_typed_record_size_preflight() {
    let dir = tempfile::tempdir().unwrap();
    let layout = PraxisLayout::new(dir.path());
    layout.create_all().unwrap();
    let page_path = layout.page_path(Cid(1), Eid(2), Fid(1), Pid(1)).path;
    std::fs::create_dir_all(page_path.parent().unwrap()).unwrap();
    let mut page = RecordPage::new(1);
    page.header.page_size = 16_384;
    page.insert(Sid(1), b"old").unwrap();
    std::fs::write(&page_path, page.to_bytes()).unwrap();
    let mut directory = RidDirectory::default();
    directory.insert(
        Rid(1),
        SlotAddress {
            cid: Cid(1),
            eid: Eid(2),
            fid: Fid(1),
            pid: Pid(1),
            sid: Sid(1),
        },
    );
    directory
        .save_binary(
            &layout.critical_map_path(Cid(1), "rid_to_slot").path,
            2,
            2,
            Pid(1),
        )
        .unwrap();
    let mut store = PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap();
    let blob_path = layout.overflow_blob_path(Cid(1), Eid(2)).path;
    let before_blob = bytes_if_present(&blob_path);
    let before_page = std::fs::read(&page_path).unwrap();
    let fields: Vec<_> = (1..=300)
        .map(|id| (FieldId::Fixed(Aid(id)), PraxisValue::Json(vec![1])))
        .collect();

    assert!(matches!(
        store.put_typed(&fields),
        Err(PraxisError::WriteStalled { .. })
    ));
    assert_eq!(bytes_if_present(&blob_path), before_blob);
    assert_eq!(std::fs::read(&page_path).unwrap(), before_page);
    assert_eq!(store.get(Rid(1)).unwrap(), b"old");
}

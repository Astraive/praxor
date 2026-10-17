use praxis::datatype::{PraxisValue, SegmentFamily};
use praxis::identity::{Aid, Cid, Eid, Fid, FieldId, Pid, Rid, Sid, SlotAddress};
use praxis::page::RecordPage;
use praxis::record::{PageRecordStore, RecordSlot, RidDirectory};

#[test]
fn record_page_inserts_reads_deletes_and_defragments_slots() {
    let mut page = RecordPage::new(10);
    page.insert(Sid(1), b"alpha").unwrap();
    page.insert(Sid(2), b"bravo").unwrap();

    assert_eq!(page.get(Sid(1)).unwrap(), Some(b"alpha".as_slice()));
    assert_eq!(page.get(Sid(2)).unwrap(), Some(b"bravo".as_slice()));
    assert_eq!(page.header.slot_count, 2);

    page.delete(Sid(1)).unwrap();
    assert_eq!(page.get(Sid(1)).unwrap(), None);
    page.defragment();

    assert_eq!(page.slots().len(), 1);
    assert_eq!(page.get(Sid(2)).unwrap(), Some(b"bravo".as_slice()));
}

#[test]
fn record_page_roundtrips_with_checksum_and_rejects_corruption() {
    let mut page = RecordPage::new(99);
    page.insert(Sid(7), b"payload").unwrap();

    let encoded = page.to_bytes();
    let decoded = RecordPage::from_bytes(&encoded, "page").unwrap();
    assert_eq!(decoded.header.page_lsn, 99);
    assert_eq!(decoded.get(Sid(7)).unwrap(), Some(b"payload".as_slice()));

    let mut corrupt = encoded;
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xff;
    assert!(RecordPage::from_bytes(&corrupt, "page").is_err());
}

#[test]
fn record_slot_tracks_field_offsets_and_rid_directory_resolves_vids() {
    let slot = RecordSlot::from_fields(
        Sid(0x001a),
        &[
            (FieldId::Fixed(Aid(1)), b"Neeraj".as_slice()),
            (FieldId::Fixed(Aid(3)), &92_i32.to_le_bytes()),
        ],
    );
    assert_eq!(
        slot.field_bytes(FieldId::Fixed(Aid(1))).unwrap(),
        Some(b"Neeraj".as_slice())
    );

    let mut directory = RidDirectory::default();
    directory.insert(
        Rid(42),
        SlotAddress {
            cid: Cid(1),
            eid: Eid(2),
            fid: Fid(0x000f),
            pid: Pid(3),
            sid: Sid(0x001a),
        },
    );

    let vid = directory.vid_for(Rid(42), FieldId::Fixed(Aid(3))).unwrap();
    assert_eq!(vid.to_global_hex(), "0002-000f-0003-001a-0003");

    let mut page = RecordPage::new(1);
    slot.install_into_page(&mut page).unwrap();
    assert_eq!(page.get(Sid(0x001a)).unwrap(), Some(slot.body.as_slice()));
}

#[test]
fn page_record_store_persists_rid_to_page_slot_mapping() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap();

    let rid = store
        .put(&[(FieldId::Fixed(Aid(1)), b"Neeraj".as_slice())])
        .unwrap();

    assert_eq!(rid, Rid(1));
    assert_eq!(store.get(rid).unwrap(), b"Neeraj");
    assert!(
        store
            .layout()
            .page_path(Cid(1), Eid(2), Fid(1), Pid(1))
            .path
            .exists()
    );
    assert!(
        store
            .layout()
            .slot_directory_path(Cid(1), Eid(2), Fid(1), Pid(1))
            .path
            .exists()
    );
    let slot_root = store
        .layout()
        .slot_directory_root(Cid(1), Eid(2), Fid(1), Pid(1));
    assert!(slot_root.join("page.header").exists());
    assert!(slot_root.join("fixed.map").exists());
    assert!(slot_root.join("dynamic.map").exists());
    assert!(slot_root.join("null.bitmap").exists());
    assert!(
        store
            .layout()
            .critical_map_path(Cid(1), "rid_to_page")
            .path
            .exists()
    );
    assert!(
        store
            .layout()
            .critical_map_path(Cid(1), "rid_to_entity")
            .path
            .exists()
    );
    assert!(
        store
            .layout()
            .critical_map_path(Cid(1), "commit_state")
            .path
            .exists()
    );
    assert!(
        store
            .layout()
            .critical_map_path(Cid(1), "sequence")
            .path
            .exists()
    );

    drop(store);
    let reopened = PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap();
    assert_eq!(reopened.get(rid).unwrap(), b"Neeraj");
    assert_eq!(
        reopened
            .directory()
            .unwrap()
            .vid_for(rid, FieldId::Fixed(Aid(1)))
            .unwrap()
            .to_global_hex(),
        "0002-0001-0001-0001-0001"
    );
}

#[test]
fn page_record_store_deletes_slot_without_reusing_rid() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap();
    let rid = store
        .put(&[(FieldId::Fixed(Aid(1)), b"gone".as_slice())])
        .unwrap();

    store.delete(rid).unwrap();

    assert!(store.get(rid).is_err());
    let page = RecordPage::from_bytes(
        &std::fs::read(
            store
                .layout()
                .page_path(Cid(1), Eid(2), Fid(1), Pid(1))
                .path,
        )
        .unwrap(),
        "page",
    )
    .unwrap();
    assert!(page.slots()[0].tombstone);
}

#[test]
fn page_record_store_places_typed_values_by_storage_class() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = PageRecordStore::open(dir.path(), Cid(1), Eid(2)).unwrap();
    let large_text = "x".repeat(300);
    let rid = store
        .put_typed(&[
            (FieldId::Fixed(Aid(1)), PraxisValue::Int4(92)),
            (
                FieldId::Fixed(Aid(2)),
                PraxisValue::Text(large_text.clone()),
            ),
            (
                FieldId::Fixed(Aid(3)),
                PraxisValue::Vec32 {
                    dims: 2,
                    data: vec![1.0, 2.0],
                },
            ),
        ])
        .unwrap();

    assert_eq!(
        store
            .get_typed_field_bytes(rid, FieldId::Fixed(Aid(1)))
            .unwrap(),
        92_i32.to_le_bytes()
    );
    assert_eq!(
        store
            .get_typed_field_bytes(rid, FieldId::Fixed(Aid(2)))
            .unwrap(),
        large_text.as_bytes()
    );
    assert_eq!(
        store
            .get_typed_field_bytes(rid, FieldId::Fixed(Aid(3)))
            .unwrap()
            .len(),
        10
    );
    assert!(
        store
            .layout()
            .overflow_blob_path(Cid(1), Eid(2))
            .path
            .exists()
    );
    assert!(
        store
            .layout()
            .segment_blob_path(Cid(1), Eid(2), SegmentFamily::Vector)
            .path
            .exists()
    );
}

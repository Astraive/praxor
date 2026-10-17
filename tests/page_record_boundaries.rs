use praxis::errors::PraxisError;
use praxis::identity::{Aid, Cid, Eid, Fid, FieldId, Pid, Rid, Sid, SlotAddress};
use praxis::io::{BinaryWriter, crc32c};
use praxis::layout::PraxisLayout;
use praxis::page::RecordPage;
use praxis::record::{PageRecordStore, RidDirectory};
use std::path::Path;

const CID: Cid = Cid(1);
const EID: Eid = Eid(2);

fn address(eid: Eid, fid: Fid, pid: Pid, sid: Sid) -> SlotAddress {
    SlotAddress {
        cid: CID,
        eid,
        fid,
        pid,
        sid,
    }
}

fn write_page(root: &Path, location: SlotAddress, page: &RecordPage) -> std::path::PathBuf {
    let layout = PraxisLayout::new(root);
    layout.create_all().unwrap();
    let path = layout
        .page_path(location.cid, location.eid, location.fid, location.pid)
        .path;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, page.to_bytes()).unwrap();
    path
}

fn save_directory(
    root: &Path,
    entries: &[(Rid, SlotAddress)],
    next_rid: u64,
    next_sid: u16,
    current_pid: Pid,
) -> std::path::PathBuf {
    PraxisLayout::new(root).create_all().unwrap();
    let mut directory = RidDirectory::default();
    for (rid, location) in entries {
        directory.insert(*rid, *location);
    }
    let path = PraxisLayout::new(root)
        .critical_map_path(CID, "rid_to_slot")
        .path;
    directory
        .save_binary(&path, next_rid, next_sid, current_pid)
        .unwrap();
    path
}

#[test]
fn cloned_entity_view_observes_new_directory_entries() {
    let dir = tempfile::tempdir().unwrap();
    let mut writer = PageRecordStore::open(dir.path(), CID, EID).unwrap();
    let reader = writer.clone();
    let rid = writer
        .put(&[(FieldId::Fixed(Aid(1)), b"after clone")])
        .unwrap();

    assert_eq!(reader.get(rid).unwrap(), b"after clone");
}

#[test]
fn cloned_entity_writers_do_not_acknowledge_the_same_rid() {
    let dir = tempfile::tempdir().unwrap();
    let mut original = PageRecordStore::open(dir.path(), CID, EID).unwrap();
    let mut cloned = original.clone();
    let first = original
        .put(&[(FieldId::Fixed(Aid(1)), b"original")])
        .unwrap();
    let second = cloned.put(&[(FieldId::Fixed(Aid(1)), b"cloned")]).unwrap();

    assert_ne!(first, second, "cloned writers acknowledged one RID twice");
    assert_eq!(original.get(first).unwrap(), b"original");
    assert_eq!(cloned.get(second).unwrap(), b"cloned");
}

#[test]
fn independent_same_entity_open_is_excluded_while_owner_is_live() {
    let dir = tempfile::tempdir().unwrap();
    let _owner = PageRecordStore::open(dir.path(), CID, EID).unwrap();
    let second = PageRecordStore::open(dir.path(), CID, EID);

    assert!(second.is_err(), "independent second writer was admitted");
}

#[test]
fn independent_other_entity_open_is_excluded_while_root_is_owned() {
    let dir = tempfile::tempdir().unwrap();
    let _owner = PageRecordStore::open(dir.path(), CID, EID).unwrap();
    let second = PageRecordStore::open(dir.path(), CID, Eid(3));

    assert!(
        second.is_err(),
        "another entity independently acquired a collection snapshot"
    );
}

#[test]
fn rid_exhaustion_fails_before_publication_and_keeps_old_records_readable() {
    let dir = tempfile::tempdir().unwrap();
    let location = address(EID, Fid(1), Pid(1), Sid(1));
    let mut page = RecordPage::new(1);
    page.insert(Sid(1), b"old").unwrap();
    let page_path = write_page(dir.path(), location, &page);
    let map_path = save_directory(dir.path(), &[(Rid(1), location)], u64::MAX, 2, Pid(1));
    let mut store = PageRecordStore::open(dir.path(), CID, EID).unwrap();
    let page_before = std::fs::read(&page_path).unwrap();
    let directory_before = std::fs::read(&map_path).unwrap();

    let result = store.put(&[(FieldId::Fixed(Aid(1)), b"must not allocate")]);
    let unchanged = std::fs::read(&page_path).unwrap() == page_before
        && std::fs::read(&map_path).unwrap() == directory_before;
    assert!(
        matches!(result, Err(PraxisError::WriteStalled { .. })) && unchanged,
        "exhausted allocation result={result:?}, files unchanged={unchanged}"
    );
    assert_eq!(store.get(Rid(1)).unwrap(), b"old");
}

#[test]
fn sid_exhaustion_rolls_to_a_new_page_without_aliasing_an_existing_slot() {
    let dir = tempfile::tempdir().unwrap();
    let location = address(EID, Fid(1), Pid(1), Sid(u16::MAX));
    let mut page = RecordPage::new(1);
    page.insert(Sid(u16::MAX), b"old").unwrap();
    write_page(dir.path(), location, &page);
    save_directory(dir.path(), &[(Rid(1), location)], 2, u16::MAX, Pid(1));
    let mut store = PageRecordStore::open(dir.path(), CID, EID).unwrap();

    let rid = store.put(&[(FieldId::Fixed(Aid(1)), b"new")]).unwrap();
    assert_eq!(
        store.get(rid).unwrap(),
        b"new",
        "new RID points at the old occupied maximum SID"
    );
    assert_eq!(store.get(Rid(1)).unwrap(), b"old");
}

#[test]
fn pid_exhaustion_cannot_replace_the_last_existing_page() {
    let dir = tempfile::tempdir().unwrap();
    let location = address(EID, Fid(1), Pid(u32::MAX), Sid(1));
    let mut page = RecordPage::new(1);
    page.insert(Sid(1), &vec![b'A'; 7_000]).unwrap();
    let page_path = write_page(dir.path(), location, &page);
    let map_path = save_directory(dir.path(), &[(Rid(1), location)], 2, 2, Pid(u32::MAX));
    let mut store = PageRecordStore::open(dir.path(), CID, EID).unwrap();
    let page_before = std::fs::read(&page_path).unwrap();
    let directory_before = std::fs::read(&map_path).unwrap();

    let result = store.put(&[(FieldId::Fixed(Aid(1)), &vec![b'B'; 7_000])]);
    let unchanged = std::fs::read(&page_path).unwrap() == page_before
        && std::fs::read(&map_path).unwrap() == directory_before;
    assert!(
        matches!(result, Err(PraxisError::WriteStalled { .. })) && unchanged,
        "exhausted page result={result:?}, old page/directory unchanged={unchanged}"
    );
}

#[test]
fn legacy_other_entity_cursor_cannot_reuse_a_tombstoned_slot() {
    let dir = tempfile::tempdir().unwrap();
    let first = address(EID, Fid(1), Pid(1), Sid(1));
    let deleted = address(EID, Fid(1), Pid(1), Sid(2));
    let other = address(Eid(3), Fid(1), Pid(1), Sid(1));
    let mut page = RecordPage::new(1);
    page.insert(Sid(1), b"kept").unwrap();
    page.insert(Sid(2), b"deleted").unwrap();
    page.delete(Sid(2)).unwrap();
    write_page(dir.path(), first, &page);
    let mut other_page = RecordPage::new(3);
    other_page.insert(Sid(1), b"other entity").unwrap();
    write_page(dir.path(), other, &other_page);
    // The scalar cursor was persisted by Eid3, which has used only Sid1.
    save_directory(
        dir.path(),
        &[(Rid(1), first), (Rid(2), deleted), (Rid(3), other)],
        4,
        2,
        Pid(1),
    );
    let mut store = PageRecordStore::open(dir.path(), CID, EID).unwrap();
    assert!(matches!(store.get(Rid(2)), Err(PraxisError::KeyNotFound)));

    let new_rid = store
        .put(&[(FieldId::Fixed(Aid(1)), b"replacement")])
        .unwrap();
    assert!(
        matches!(store.get(Rid(2)), Err(PraxisError::KeyNotFound)),
        "reusing another entity's scalar SID resurrected the deleted RID"
    );
    assert_eq!(store.get(new_rid).unwrap(), b"replacement");
}

#[test]
fn point_lookup_uses_the_frame_from_its_resolved_address() {
    let dir = tempfile::tempdir().unwrap();
    let requested = address(EID, Fid(2), Pid(1), Sid(1));
    let unrelated = address(EID, Fid(1), Pid(1), Sid(1));
    let mut correct_page = RecordPage::new(1);
    correct_page.insert(Sid(1), b"frame two").unwrap();
    write_page(dir.path(), requested, &correct_page);
    let mut other_page = RecordPage::new(2);
    other_page.insert(Sid(1), b"unrelated frame one").unwrap();
    write_page(dir.path(), unrelated, &other_page);
    save_directory(dir.path(), &[(Rid(1), requested)], 2, 2, Pid(1));
    let store = PageRecordStore::open(dir.path(), CID, EID).unwrap();

    assert_eq!(store.get(Rid(1)).unwrap(), b"frame two");
}

#[test]
fn directory_address_from_another_collection_cannot_alias_local_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let local = address(EID, Fid(1), Pid(1), Sid(1));
    let mut page = RecordPage::new(1);
    page.insert(Sid(1), b"local unrelated bytes").unwrap();
    write_page(dir.path(), local, &page);
    let foreign = SlotAddress {
        cid: Cid(9),
        ..local
    };
    save_directory(dir.path(), &[(Rid(1), foreign)], 2, 2, Pid(1));
    let result = PageRecordStore::open(dir.path(), CID, EID).and_then(|store| store.get(Rid(1)));

    assert!(
        matches!(result, Err(PraxisError::Corrupt { .. })),
        "foreign Cid metadata was routed to the local collection: {result:?}"
    );
}

fn raw_directory(path: &Path, next_sid: u32, entries: &[(Rid, SlotAddress, u32)]) {
    let mut payload = BinaryWriter::new();
    payload.write_u64(3);
    payload.write_u32(next_sid);
    payload.write_u32(1);
    payload.write_u32(entries.len() as u32);
    for (rid, location, raw_sid) in entries {
        payload.write_u64(rid.0);
        payload.write_u32(location.cid.0);
        payload.write_u32(location.eid.0);
        payload.write_u32(location.fid.0);
        payload.write_u32(location.pid.0);
        payload.write_u32(*raw_sid);
    }
    let payload = payload.into_inner();
    let mut file = BinaryWriter::new();
    file.write_u32(0x5452_4944);
    file.write_u8(1);
    file.write_u32(payload.len() as u32);
    file.write_u32(crc32c(&payload));
    file.write_bytes(&payload);
    std::fs::write(path, file.into_inner()).unwrap();
}

#[test]
fn directory_decoder_rejects_sid_counter_narrowing_overflow() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("directory.kv");
    raw_directory(&path, 65_536, &[]);

    assert!(
        RidDirectory::load_binary(&path).is_err(),
        "u32 next-SID 65536 was silently narrowed to reserved Sid0"
    );
}

#[test]
fn directory_decoder_rejects_slot_address_narrowing_overflow() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("directory.kv");
    raw_directory(
        &path,
        2,
        &[(Rid(1), address(EID, Fid(1), Pid(1), Sid(1)), 65_537)],
    );

    assert!(
        RidDirectory::load_binary(&path).is_err(),
        "u32 slot ID 65537 was silently aliased to occupied Sid1"
    );
}

#[test]
fn directory_decoder_rejects_duplicate_rid_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("directory.kv");
    raw_directory(
        &path,
        2,
        &[
            (Rid(1), address(EID, Fid(1), Pid(1), Sid(1)), 1),
            (Rid(1), address(Eid(3), Fid(1), Pid(1), Sid(1)), 1),
        ],
    );

    assert!(
        RidDirectory::load_binary(&path).is_err(),
        "second entity silently replaced a duplicate RID's first identity"
    );
}

#[test]
fn page_decoder_rejects_physical_slot_identity_narrowing_overflow() {
    let mut page = RecordPage::new(1);
    page.insert(Sid(1), b"occupied").unwrap();
    let mut file = page.to_bytes();
    // v1: 13-byte envelope, then 21-byte page metadata before the first u32 SID.
    file[34..38].copy_from_slice(&65_537_u32.to_le_bytes());
    let checksum = crc32c(&file[13..]);
    file[9..13].copy_from_slice(&checksum.to_le_bytes());

    assert!(
        RecordPage::from_bytes(&file, "overflowed-slot.page").is_err(),
        "physical u32 slot ID 65537 was silently narrowed to Sid1"
    );
}

#[test]
fn oversized_put_leaves_old_data_readable_and_does_not_consume_a_rid() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = PageRecordStore::open(dir.path(), CID, EID).unwrap();
    let first = store.put(&[(FieldId::Fixed(Aid(1)), b"first")]).unwrap();
    assert!(matches!(
        store.put(&[(FieldId::Fixed(Aid(1)), &vec![b'X'; 9_000])]),
        Err(PraxisError::WriteStalled { .. })
    ));

    assert_eq!(store.get(first).unwrap(), b"first");
    let second = store.put(&[(FieldId::Fixed(Aid(1)), b"second")]).unwrap();
    assert_eq!(second, Rid(2));
    assert_eq!(store.get(second).unwrap(), b"second");
}

#[test]
fn uncertain_sidecar_failure_stops_reads_and_further_publication_on_every_clone() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = PageRecordStore::open(dir.path(), CID, EID).unwrap();
    let first = store
        .put(&[(FieldId::Fixed(Aid(1)), b"acknowledged")])
        .unwrap();
    let reader = store.clone();
    let obstructed_sidecar = store.layout().critical_map_path(CID, "rid_to_entity").path;
    std::fs::remove_file(&obstructed_sidecar).unwrap();
    std::fs::create_dir(&obstructed_sidecar).unwrap();

    // This fails after page and RID-directory publication, not during preflight.
    assert!(
        store
            .put(&[(FieldId::Fixed(Aid(1)), b"uncertain")])
            .is_err()
    );
    let page_path = store.layout().page_path(CID, EID, Fid(1), Pid(1)).path;
    let map_path = store.layout().critical_map_path(CID, "rid_to_slot").path;
    let page_before_retry = std::fs::read(&page_path).unwrap();
    let map_before_retry = std::fs::read(&map_path).unwrap();
    let owner_read = store.get(first);
    let clone_read = reader.get(first);
    let retry = store.put(&[(FieldId::Fixed(Aid(1)), b"must not publish again")]);
    let unchanged = std::fs::read(&page_path).unwrap() == page_before_retry
        && std::fs::read(&map_path).unwrap() == map_before_retry;

    assert!(
        owner_read.is_err() && clone_read.is_err() && retry.is_err() && unchanged,
        "after uncertain write: owner serves reads={}, clone serves reads={}, \
         retry changed page/directory={}",
        owner_read.is_ok(),
        clone_read.is_ok(),
        !unchanged
    );
}

#[test]
fn collection_open_rejects_two_rids_aliasing_one_physical_slot() {
    fn tree(root: &Path) -> std::collections::BTreeMap<std::path::PathBuf, Option<Vec<u8>>> {
        fn visit(
            base: &Path,
            at: &Path,
            files: &mut std::collections::BTreeMap<std::path::PathBuf, Option<Vec<u8>>>,
        ) {
            for item in std::fs::read_dir(at).unwrap() {
                let path = item.unwrap().path();
                files.insert(
                    path.strip_prefix(base).unwrap().to_path_buf(),
                    if path.is_dir() {
                        None
                    } else {
                        Some(std::fs::read(&path).unwrap())
                    },
                );
                if path.is_dir() {
                    visit(base, &path, files);
                }
            }
        }
        let mut files = std::collections::BTreeMap::new();
        visit(root, root, &mut files);
        files
    }
    let dir = tempfile::tempdir().unwrap();
    drop(praxis::record::PageDatabase::open(dir.path()).unwrap());
    let location = address(EID, Fid(1), Pid(1), Sid(1));
    let mut page = RecordPage::new(1);
    page.insert(Sid(1), b"one physical record").unwrap();
    write_page(dir.path(), location, &page);
    let directory_path = save_directory(
        dir.path(),
        &[(Rid(1), location), (Rid(2), location)],
        3,
        2,
        Pid(1),
    );
    // save_binary emits a checksum-valid directory; this is a semantic alias, not torn input.
    RidDirectory::load_binary(&directory_path).unwrap();
    let before = tree(dir.path());
    let result = praxis::record::PageDatabase::open(dir.path());
    assert!(
        matches!(result, Err(PraxisError::Corrupt { .. })),
        "physical alias was admitted: {result:?}"
    );
    assert_eq!(tree(dir.path()), before);
}

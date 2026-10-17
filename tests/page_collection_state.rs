use praxis::api::service::{
    DeletePageRecordRequest, GetPageRecordRequest, PagePrimitiveStorageService,
    PrimitiveFieldBytes, PrimitiveFieldId, PutPageRecordRequest, RequestContext,
};
use praxis::errors::{PraxisError, Result};
use praxis::identity::{Cid, Eid, Fid, Pid, Rid, Sid};
use praxis::layout::PraxisLayout;
use praxis::page::RecordPage;
use praxis::record::RidDirectory;
use std::collections::BTreeSet;
use std::path::Path;

const COLLECTION: Cid = Cid(41);
const ENTITY_A: Eid = Eid(7);
const ENTITY_B: Eid = Eid(9);

fn put(service: &PagePrimitiveStorageService, cid: Cid, eid: Eid, body: &[u8]) -> Rid {
    service
        .put_page_record(PutPageRecordRequest {
            context: RequestContext::new("collection-put"),
            cid,
            eid,
            fields: vec![PrimitiveFieldBytes {
                field: PrimitiveFieldId::Fixed(1),
                bytes: body.to_vec(),
            }],
        })
        .unwrap()
        .rid
}

fn get(
    service: &PagePrimitiveStorageService,
    cid: Cid,
    eid: Eid,
    rid: Rid,
) -> Result<Option<Vec<u8>>> {
    service
        .get_page_record(GetPageRecordRequest {
            context: RequestContext::new("collection-get"),
            cid,
            eid,
            rid,
        })
        .map(|response| response.body)
}

fn delete(service: &PagePrimitiveStorageService, cid: Cid, eid: Eid, rid: Rid) -> Result<bool> {
    service
        .delete_page_record(DeletePageRecordRequest {
            context: RequestContext::new("collection-delete"),
            cid,
            eid,
            rid,
        })
        .map(|response| response.deleted)
}

#[test]
fn equal_rids_in_different_collections_keep_distinct_payloads() {
    let dir = tempfile::tempdir().unwrap();
    let service = PagePrimitiveStorageService::open(dir.path()).unwrap();
    let first = put(&service, Cid(1), ENTITY_A, b"first collection");
    let second = put(&service, Cid(2), ENTITY_A, b"second collection");

    // Page Rid is collection scoped; it is not the separate store::RecordId protocol.
    assert_eq!(first, Rid(1));
    assert_eq!(second, Rid(1));
    assert_eq!(
        get(&service, Cid(1), ENTITY_A, first).unwrap(),
        Some(b"first collection".to_vec())
    );
    assert_eq!(
        get(&service, Cid(2), ENTITY_A, second).unwrap(),
        Some(b"second collection".to_vec())
    );
}

#[test]
fn interleaved_entity_puts_allocate_distinct_collection_rids() {
    let dir = tempfile::tempdir().unwrap();
    let service = PagePrimitiveStorageService::open(dir.path()).unwrap();
    let acknowledged = [
        put(&service, COLLECTION, ENTITY_A, b"a-one"),
        put(&service, COLLECTION, ENTITY_B, b"b-one"),
        put(&service, COLLECTION, ENTITY_A, b"a-two"),
        put(&service, COLLECTION, ENTITY_B, b"b-two"),
    ];
    let distinct: BTreeSet<_> = acknowledged.into_iter().collect();

    assert_eq!(
        distinct.len(),
        acknowledged.len(),
        "different entity views acknowledged duplicate collection RIDs: {acknowledged:?}"
    );
}

#[test]
fn stale_entity_put_preserves_foreign_directory_and_allocation_high_water() {
    let dir = tempfile::tempdir().unwrap();
    let service = PagePrimitiveStorageService::open(dir.path()).unwrap();
    let a_one = put(&service, COLLECTION, ENTITY_A, b"a-one");
    let b_one = put(&service, COLLECTION, ENTITY_B, b"b-one");
    let b_two = put(&service, COLLECTION, ENTITY_B, b"b-two");
    let a_two = put(&service, COLLECTION, ENTITY_A, b"a-two");
    let map_path = PraxisLayout::new(dir.path())
        .critical_map_path(COLLECTION, "rid_to_slot")
        .path;
    let (directory, next_rid, _, _) = RidDirectory::load_binary(&map_path).unwrap();
    let b_two_address = directory.resolve(b_two);
    let maximum_acknowledged = [a_one, b_one, b_two, a_two]
        .into_iter()
        .map(|rid| rid.0)
        .max()
        .unwrap();

    assert!(
        matches!(&b_two_address, Ok(address) if address.eid == ENTITY_B)
            && next_rid > maximum_acknowledged,
        "last entity flush lost acknowledged state: b_two={b_two:?}, address={b_two_address:?}, \
         next_rid={next_rid}, maximum_acknowledged={maximum_acknowledged}"
    );
}

#[test]
fn reopen_preserves_other_entity_after_delete_and_reinsert() {
    let dir = tempfile::tempdir().unwrap();
    let service = PagePrimitiveStorageService::open(dir.path()).unwrap();
    let a_one = put(&service, COLLECTION, ENTITY_A, b"a-one");
    let b_deleted = put(&service, COLLECTION, ENTITY_B, b"b-deleted");
    assert!(delete(&service, COLLECTION, ENTITY_B, b_deleted).unwrap());
    let b_survivor = put(&service, COLLECTION, ENTITY_B, b"b-survivor");
    let a_two = put(&service, COLLECTION, ENTITY_A, b"a-two");
    assert!(delete(&service, COLLECTION, ENTITY_A, a_one).unwrap());
    // The missing record has no RID collision with either entity-A receipt.
    assert_ne!(b_survivor, a_one);
    assert_ne!(b_survivor, a_two);
    drop(service);

    for _ in 0..2 {
        let reopened = PagePrimitiveStorageService::open(dir.path()).unwrap();
        assert_eq!(
            get(&reopened, COLLECTION, ENTITY_B, b_survivor).unwrap(),
            Some(b"b-survivor".to_vec()),
            "acknowledged foreign entity record disappeared on reopen"
        );
        assert_eq!(get(&reopened, COLLECTION, ENTITY_A, a_one).unwrap(), None);
    }
}

#[test]
fn wrong_entity_lookup_returns_absent_without_loading_a_foreign_page_number() {
    let dir = tempfile::tempdir().unwrap();
    let service = PagePrimitiveStorageService::open(dir.path()).unwrap();
    let a_one = put(&service, COLLECTION, ENTITY_A, b"a-one");
    let result = get(&service, COLLECTION, ENTITY_B, a_one);

    assert!(
        matches!(result, Ok(None)),
        "wrong entity must resolve as absent before page IO: {result:?}"
    );
}

// Force both entities to own page 2 / slot 1, with different collection RIDs.
// This proves wrong-entity routing independently of equal RID allocation.
fn colliding_page_addresses(root: &Path) -> (PagePrimitiveStorageService, Rid, Vec<u8>) {
    let service = PagePrimitiveStorageService::open(root).unwrap();
    let a_one = put(&service, COLLECTION, ENTITY_A, &vec![b'A'; 7_000]);
    put(&service, COLLECTION, ENTITY_B, b"b-small");
    put(&service, COLLECTION, ENTITY_B, &vec![b'B'; 7_000]);
    let foreign = put(&service, COLLECTION, ENTITY_B, &vec![b'C'; 7_000]);
    let a_body = vec![b'D'; 7_000];
    let a_two = put(&service, COLLECTION, ENTITY_A, &a_body);
    put(&service, COLLECTION, ENTITY_B, b"b-last");
    assert_ne!(foreign, a_one);
    assert_ne!(foreign, a_two);
    drop(service);
    (
        PagePrimitiveStorageService::open(root).unwrap(),
        foreign,
        a_body,
    )
}

#[test]
fn wrong_entity_lookup_cannot_return_an_unrelated_local_record() {
    let dir = tempfile::tempdir().unwrap();
    let (service, foreign, _) = colliding_page_addresses(dir.path());
    let actual = get(&service, COLLECTION, ENTITY_A, foreign).unwrap();

    assert!(
        actual.is_none(),
        "foreign RID {foreign:?} returned {} bytes from an unrelated entity-A slot",
        actual.as_ref().map_or(0, Vec::len)
    );
}

#[test]
fn wrong_entity_delete_cannot_tombstone_an_unrelated_local_record() {
    let dir = tempfile::tempdir().unwrap();
    let (service, foreign, a_body) = colliding_page_addresses(dir.path());
    let page_path = PraxisLayout::new(dir.path())
        .page_path(COLLECTION, ENTITY_A, Fid(1), Pid(2))
        .path;
    let before = RecordPage::from_bytes(&std::fs::read(&page_path).unwrap(), &page_path).unwrap();
    assert_eq!(before.get(Sid(1)).unwrap(), Some(a_body.as_slice()));

    let result = delete(&service, COLLECTION, ENTITY_A, foreign);
    let after = RecordPage::from_bytes(&std::fs::read(&page_path).unwrap(), &page_path).unwrap();
    let surviving = after.get(Sid(1)).unwrap();
    assert!(
        matches!(result, Err(PraxisError::KeyNotFound)) && surviving == Some(a_body.as_slice()),
        "foreign delete result={result:?}, unrelated local slot still live={}",
        surviving.is_some()
    );
}

#[test]
fn concurrent_service_and_sdk_clones_preserve_collection_receipts_and_reopen_state() {
    use praxis::manifest::PageManifestStore;
    use praxis::record::PageDatabase;
    use praxis::sdk::LocalPagepraxisClient;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Barrier};

    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let service = PagePrimitiveStorageService::new(database.clone());
    let barrier = Arc::new(Barrier::new(8));
    let mut workers = Vec::new();
    for worker in 0..8 {
        let service = service.clone();
        let client = LocalPagepraxisClient::new(service.clone());
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            let cid = Cid(41 + (worker / 2) % 2);
            let eid = if worker % 2 == 0 { ENTITY_A } else { ENTITY_B };
            let other = if eid == ENTITY_A { ENTITY_B } else { ENTITY_A };
            let mut receipts = Vec::new();
            barrier.wait();
            for round in 0..6 {
                let body = format!("worker-{worker}-round-{round}").into_bytes();
                let rid = if (worker + round) % 2 == 0 {
                    put(&service, cid, eid, &body)
                } else {
                    client
                        .put_page_record(
                            RequestContext::new("concurrent-sdk-put"),
                            cid,
                            eid,
                            vec![PrimitiveFieldBytes {
                                field: PrimitiveFieldId::Fixed(1),
                                bytes: body.clone(),
                            }],
                        )
                        .unwrap()
                        .rid
                };
                assert_eq!(get(&service, cid, eid, rid).unwrap(), Some(body.clone()));
                assert_eq!(
                    client
                        .get_page_record(RequestContext::new("concurrent-sdk-get"), cid, other, rid)
                        .unwrap()
                        .body,
                    None
                );
                let deleted = round % 3 == 0;
                if deleted {
                    assert!(
                        client
                            .delete_page_record(
                                RequestContext::new("concurrent-sdk-delete"),
                                cid,
                                eid,
                                rid
                            )
                            .unwrap()
                            .deleted
                    );
                    assert_eq!(get(&service, cid, eid, rid).unwrap(), None);
                }
                receipts.push((cid, eid, rid, body, deleted));
            }
            receipts
        }));
    }
    let mut receipts = Vec::new();
    let mut allocated: BTreeMap<Cid, BTreeSet<Rid>> = BTreeMap::new();
    for worker in workers {
        for receipt in worker.join().unwrap() {
            assert!(
                allocated.entry(receipt.0).or_default().insert(receipt.2),
                "duplicate acknowledged collection RID"
            );
            receipts.push(receipt);
        }
    }
    for rids in allocated.values() {
        assert_eq!(rids.len(), 24);
        assert_eq!(
            rids.iter().copied().collect::<Vec<_>>(),
            (1..=24).map(Rid).collect::<Vec<_>>()
        );
    }
    drop(service);
    drop(database);
    for reopen in 0..2 {
        let database = PageDatabase::open(dir.path()).unwrap();
        let service = PagePrimitiveStorageService::new(database.clone());
        for (cid, eid, rid, body, deleted) in &receipts {
            assert_eq!(
                get(&service, *cid, *eid, *rid).unwrap(),
                (!deleted).then(|| body.clone())
            );
        }
        for cid in [Cid(41), Cid(42)] {
            for eid in [ENTITY_A, ENTITY_B] {
                let body = format!("reopen-{reopen}-{cid:?}-{eid:?}").into_bytes();
                let rid = put(&service, cid, eid, &body);
                assert!(allocated.get_mut(&cid).unwrap().insert(rid));
                receipts.push((cid, eid, rid, body, false));
            }
            let layout = PraxisLayout::new(dir.path());
            let (directory, next, _, _) =
                RidDirectory::load_binary(&layout.critical_map_path(cid, "rid_to_slot").path)
                    .unwrap();
            assert_eq!(next, u64::try_from(allocated[&cid].len()).unwrap() + 1);
            for (_, eid, rid, _, _) in receipts.iter().filter(|receipt| receipt.0 == cid) {
                assert_eq!(directory.resolve(*rid).unwrap().eid, *eid);
            }
        }
        let manifest =
            PageManifestStore::open(PraxisLayout::new(dir.path()).page_manifest_path().path)
                .load()
                .unwrap();
        for file in manifest.files {
            assert_eq!(
                file.checksum,
                format!(
                    "{:08x}",
                    praxis::io::crc32_ieee(&std::fs::read(file.path).unwrap())
                )
            );
        }
    }
}

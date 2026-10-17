use praxis::PraxisError;
use praxis::catalog::*;
use praxis::config::{Compression, WalSyncPolicy};
use praxis::identity::{Aid, Cid, Did, Eid, Fid, FieldId, Rid};
use praxis::manifest::PageManifestStore;
use praxis::record::{PageDatabase, RidDirectory};
use praxis::wal::{PageWal, PageWalMutation};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Barrier};

fn snapshot(epoch: &str) -> CatalogSnapshot {
    CatalogSnapshot {
        collections: vec![CollectionCatalogEntry {
            cid: Cid(1),
            name: epoch.into(),
            retention_policy: Some(epoch.into()),
        }],
        entities: vec![EntityCatalogEntry {
            cid: Cid(1),
            eid: Eid(2),
            name: epoch.into(),
            storage_model: EntityStorageModel::Hybrid,
            primary_key: Some(epoch.into()),
            compression: Compression::None,
        }],
        fixed_attributes: vec![FixedAttributeCatalogEntry {
            eid: Eid(2),
            aid: Aid(1),
            name: epoch.into(),
            type_code: 1,
            nullable: false,
        }],
        dynamic_attributes: vec![DynamicAttributeCatalogEntry {
            eid: Eid(2),
            did: Did(1),
            name: epoch.into(),
            inferred_type_code: None,
        }],
        indexes: vec![IndexCatalogEntry {
            eid: Eid(2),
            index_id: 1,
            name: epoch.into(),
            kind: epoch.into(),
            pointer_target: epoch.into(),
        }],
        vector_models: vec![VectorModelCatalogEntry {
            model_id: 1,
            name: epoch.into(),
            dimensions: 3,
            metric: epoch.into(),
        }],
        fulltext: vec![FullTextCatalogEntry {
            eid: Eid(2),
            analyzer: epoch.into(),
            language: epoch.into(),
        }],
        graph: vec![GraphCatalogEntry {
            eid: Eid(2),
            edge_label: epoch.into(),
            directed: false,
        }],
        shards: vec![ShardCatalogEntry {
            shard_id: 1,
            cid: Cid(1),
            range_start: epoch.into(),
            range_end: epoch.into(),
        }],
        users: vec![UserCatalogEntry {
            user_id: 1,
            name: epoch.into(),
            role: epoch.into(),
        }],
    }
}

#[derive(Clone, Debug)]
struct Receipt {
    cid: Cid,
    eid: Eid,
    rid: Rid,
    body: Vec<u8>,
    deleted: bool,
}

#[test]
fn concurrent_catalog_load_save_page_and_wal_views_keep_receipts_and_complete_epochs() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let catalog = CatalogStore::new(database.clone());
    let first = snapshot("first");
    let second = snapshot("second");
    catalog.save(&first).unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let mut workers = Vec::new();
    for worker in 0..8 {
        let catalog = catalog.clone();
        let first = first.clone();
        let second = second.clone();
        let page_identity = (3..7)
            .contains(&worker)
            .then(|| (Cid(1 + (worker - 3) / 2), Eid(2 + (worker - 3) % 2)));
        let page = page_identity.map(|(cid, eid)| database.entity(cid, eid).unwrap());
        let wal = (worker == 2 || page.is_some())
            .then(|| database.page_wal(WalSyncPolicy::EveryBatch).unwrap());
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            let mut receipts = Vec::new();
            barrier.wait();
            match worker {
                0 => {
                    for round in 0..6 {
                        catalog
                            .save(if round % 2 == 0 { &first } else { &second })
                            .unwrap();
                    }
                }
                1 | 7 => {
                    for _ in 0..12 {
                        let loaded = catalog.load().unwrap();
                        assert!(
                            loaded == first || loaded == second,
                            "mixed ten-file catalog epoch"
                        );
                    }
                }
                2 => {
                    let mut wal = wal.unwrap();
                    for _ in 0..12 {
                        wal.sync().unwrap();
                    }
                }
                _ => {
                    let (cid, eid) = page_identity.unwrap();
                    let mut page = page.unwrap();
                    let mut wal = wal.unwrap();
                    for round in 0..6 {
                        let body = format!("worker-{worker}-round-{round}").into_bytes();
                        let rid = page
                            .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), &body)])
                            .unwrap();
                        assert_eq!(page.get(rid).unwrap(), body);
                        let deleted = round % 3 == 0;
                        if deleted {
                            page.delete_durable(&mut wal, rid).unwrap();
                            assert!(matches!(page.get(rid), Err(PraxisError::KeyNotFound)));
                        }
                        receipts.push(Receipt {
                            cid,
                            eid,
                            rid,
                            body,
                            deleted,
                        });
                    }
                }
            }
            receipts
        }));
    }
    let mut receipts: Vec<_> = workers
        .into_iter()
        .flat_map(|worker| worker.join().unwrap())
        .collect();
    let mut allocated: BTreeMap<Cid, BTreeSet<Rid>> = BTreeMap::new();
    for receipt in &receipts {
        assert!(
            allocated
                .entry(receipt.cid)
                .or_default()
                .insert(receipt.rid)
        );
    }
    for rids in allocated.values() {
        assert_eq!(
            rids.iter().copied().collect::<Vec<_>>(),
            (1..=12).map(Rid).collect::<Vec<_>>()
        );
    }
    let wal_path = database
        .entity(Cid(1), Eid(2))
        .unwrap()
        .layout()
        .logs_root()
        .join("page.wal");
    let records = PageWal::replay(&wal_path).unwrap();
    assert_eq!(records.len(), 32);
    let mut puts = BTreeMap::new();
    let mut deletes = BTreeSet::new();
    for (index, record) in records.into_iter().enumerate() {
        assert_eq!(record.sequence, u64::try_from(index).unwrap() + 1);
        match record.mutation {
            PageWalMutation::Put {
                cid,
                eid,
                rid,
                fields,
            } => {
                assert!(puts.insert((cid, eid, rid), fields).is_none());
            }
            PageWalMutation::Delete { cid, eid, rid } => {
                assert!(deletes.insert((cid, eid, rid)));
            }
        }
    }
    for receipt in &receipts {
        assert_eq!(
            puts[&(receipt.cid, receipt.eid, receipt.rid)],
            vec![(FieldId::Fixed(Aid(1)), receipt.body.clone())]
        );
        assert_eq!(
            deletes.contains(&(receipt.cid, receipt.eid, receipt.rid)),
            receipt.deleted
        );
    }
    assert_eq!(catalog.load().unwrap(), second);
    drop(catalog);
    drop(database);
    let mut expected = second;
    for reopen in 0..2 {
        let database = PageDatabase::open(dir.path()).unwrap();
        let catalog = CatalogStore::new(database.clone());
        assert_eq!(catalog.load().unwrap(), expected);
        for receipt in &receipts {
            let page = database.entity(receipt.cid, receipt.eid).unwrap();
            let result = page.get(receipt.rid);
            if receipt.deleted {
                assert!(matches!(result, Err(PraxisError::KeyNotFound)));
            } else {
                assert_eq!(result.unwrap(), receipt.body);
            }
            let other = if receipt.eid == Eid(2) {
                Eid(3)
            } else {
                Eid(2)
            };
            assert!(matches!(
                database
                    .entity(receipt.cid, other)
                    .unwrap()
                    .get(receipt.rid),
                Err(PraxisError::KeyNotFound)
            ));
        }
        for cid in [Cid(1), Cid(2)] {
            for eid in [Eid(2), Eid(3)] {
                let mut page = database.entity(cid, eid).unwrap();
                let body = format!("reopen-{reopen}-{cid:?}-{eid:?}").into_bytes();
                let rid = page.put(&[(FieldId::Fixed(Aid(1)), &body)]).unwrap();
                assert!(allocated.get_mut(&cid).unwrap().insert(rid));
                receipts.push(Receipt {
                    cid,
                    eid,
                    rid,
                    body,
                    deleted: false,
                });
            }
            let directory = database.entity(cid, Eid(2)).unwrap().directory().unwrap();
            let path = catalog.layout().critical_map_path(cid, "rid_to_slot").path;
            let (_, next, _, _) = RidDirectory::load_binary(&path).unwrap();
            assert_eq!(next, u64::try_from(allocated[&cid].len()).unwrap() + 1);
            for receipt in receipts.iter().filter(|receipt| receipt.cid == cid) {
                let address = directory.resolve(receipt.rid).unwrap();
                assert_eq!(
                    (address.cid, address.eid, address.fid),
                    (cid, receipt.eid, Fid(1))
                );
            }
        }
        expected = snapshot(if reopen == 0 {
            "reopen-first"
        } else {
            "reopen-second"
        });
        catalog.save(&expected).unwrap();
        assert_eq!(catalog.load().unwrap(), expected);
        let manifest = PageManifestStore::open(catalog.layout().page_manifest_path().path)
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

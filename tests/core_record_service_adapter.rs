use praxis::api::service::{
    BatchRecordInput, CorePrimitiveStorageService, CoreRecordServiceCapability,
    DeleteRecordRequest, DeleteRecordResponse, FlushRequest, FlushResponse, GetRecordRequest,
    GetRecordResponse, PutRecordBatchRequest, PutRecordBatchResponse, PutRecordRequest,
    PutRecordResponse, RequestContext, UnsupportedCoreRecordServiceCapability,
};
use praxis::sdk::{LocalCorepraxisClient, LocalPagepraxisClient, LocalpraxisClient};
use praxis::store::{IndexInsert, StorageEngine};
use praxis::{
    CoreDatabase, MappingDescriptor, PraxisConfig, PraxisError, RecordAuthorityOptions, RecordId,
    WalSyncPolicy,
};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn database(policy: WalSyncPolicy) -> (tempfile::TempDir, PraxisConfig, CoreDatabase) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = policy;
    config.memtable_flush_threshold_bytes = usize::MAX;
    let db = CoreDatabase::create_fresh(
        config.clone(),
        RecordAuthorityOptions {
            indexes: vec![MappingDescriptor {
                name: "kv".into(),
                namespace: "adapter".into(),
            }],
        },
    )
    .unwrap();
    (dir, config, db)
}

#[derive(Debug, PartialEq)]
enum TreeEntry {
    Directory,
    File(Vec<u8>),
    // Windows denies reads of the already exclusively locked artifact.
    // Preserve its entry/length; compare every other file's exact bytes.
    WriterLock(u64),
}

fn tree(root: &Path) -> BTreeMap<PathBuf, TreeEntry> {
    fn visit(root: &Path, path: &Path, files: &mut BTreeMap<PathBuf, TreeEntry>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                files.insert(
                    path.strip_prefix(root).unwrap().into(),
                    TreeEntry::Directory,
                );
                visit(root, &path, files);
            } else if entry.file_name() == ".praxor.writer.lock" {
                files.insert(
                    path.strip_prefix(root).unwrap().into(),
                    TreeEntry::WriterLock(entry.metadata().unwrap().len()),
                );
            } else {
                files.insert(
                    path.strip_prefix(root).unwrap().into(),
                    TreeEntry::File(std::fs::read(path).unwrap()),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

#[test]
fn existing_dto_wire_fixtures_and_legacy_constructors_remain_compatible() {
    fn fixture<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(
        value: T,
        json: &str,
    ) {
        assert_eq!(serde_json::to_string(&value).unwrap(), json);
        assert_eq!(serde_json::from_str::<T>(json).unwrap(), value);
    }
    let context = RequestContext::new("r");
    fixture(
        PutRecordRequest {
            context: context.clone(),
            value: vec![0, 255],
            indexes: vec![IndexInsert::new("kv", vec![107])],
        },
        r#"{"context":{"request_id":"r","tenant_id":null,"trace_id":null},"value":[0,255],"indexes":[{"index_type":"kv","key":[107]}]}"#,
    );
    fixture(
        PutRecordResponse {
            record_id: RecordId(7),
        },
        r#"{"record_id":7}"#,
    );
    fixture(
        PutRecordBatchRequest {
            context: context.clone(),
            records: vec![BatchRecordInput {
                value: vec![1],
                indexes: vec![],
            }],
        },
        r#"{"context":{"request_id":"r","tenant_id":null,"trace_id":null},"records":[{"value":[1],"indexes":[]}]}"#,
    );
    fixture(
        PutRecordBatchResponse {
            record_ids: vec![RecordId(7), RecordId(8)],
        },
        r#"{"record_ids":[7,8]}"#,
    );
    fixture(
        GetRecordRequest {
            context: context.clone(),
            record_id: RecordId(7),
        },
        r#"{"context":{"request_id":"r","tenant_id":null,"trace_id":null},"record_id":7}"#,
    );
    fixture(GetRecordResponse { value: None }, r#"{"value":null}"#);
    fixture(
        GetRecordResponse {
            value: Some(vec![0, 255]),
        },
        r#"{"value":[0,255]}"#,
    );
    fixture(
        DeleteRecordRequest {
            context: context.clone(),
            record_id: RecordId(7),
        },
        r#"{"context":{"request_id":"r","tenant_id":null,"trace_id":null},"record_id":7}"#,
    );
    fixture(
        DeleteRecordResponse { deleted: true },
        r#"{"deleted":true}"#,
    );
    fixture(
        FlushRequest { context },
        r#"{"context":{"request_id":"r","tenant_id":null,"trace_id":null}}"#,
    );
    fixture(FlushResponse { ok: true }, r#"{"ok":true}"#);

    // These unchanged constructors still select the legacy concrete backends.
    let _: fn(StorageEngine) -> LocalpraxisClient = LocalpraxisClient::new;
    let _: fn(praxis::api::service::PagePrimitiveStorageService) -> LocalPagepraxisClient =
        LocalPagepraxisClient::new;
    let _: fn(StorageEngine) -> praxis::api::service::PrimitiveStorageService =
        praxis::api::service::PrimitiveStorageService::new;
    fn legacy_kernel<T: praxis::kernel::StorageKernel>() {}
    legacy_kernel::<StorageEngine>();
}

#[test]
fn construction_and_static_capability_checks_do_not_touch_the_existing_owner() {
    let (dir, _config, db) = database(WalSyncPolicy::EveryBatch);
    let before = tree(dir.path());
    let service = CorePrimitiveStorageService::new(db.records());
    let client = LocalCorepraxisClient::new(service.clone());
    let _records = client.records();
    for capability in [
        CoreRecordServiceCapability::LogicalCrud,
        CoreRecordServiceCapability::FixedMappingIndex,
        CoreRecordServiceCapability::DurableFlush,
    ] {
        assert_eq!(service.require_capability(capability), Ok(()));
        assert_eq!(client.require_capability(capability), Ok(()));
    }
    for capability in [
        CoreRecordServiceCapability::LegacyPhysicalAdmin,
        CoreRecordServiceCapability::DynamicPluginAttachment,
        CoreRecordServiceCapability::DynamicCatalogDdl,
        CoreRecordServiceCapability::HistoricalPayload,
    ] {
        let expected = Err(UnsupportedCoreRecordServiceCapability { capability });
        assert_eq!(service.require_capability(capability), expected);
        assert_eq!(client.require_capability(capability), expected);
    }
    assert_eq!(tree(dir.path()), before);
    assert_eq!(db.records().compatibility_sequence().unwrap(), 0);
}

#[test]
fn client_crud_preserves_absence_idempotent_delete_and_real_errors() {
    let (_dir, config, db) = database(WalSyncPolicy::EveryBatch);
    let service = CorePrimitiveStorageService::new(db.records());
    let client = LocalCorepraxisClient::new(service.clone());
    for record_id in [RecordId::NULL, RecordId(999)] {
        assert_eq!(
            client
                .get_record(RequestContext::new("missing"), record_id)
                .unwrap()
                .value,
            None
        );
        let before = db.kv().snapshot().sequence;
        assert!(matches!(
            client.delete_record(RequestContext::new("unknown"), record_id),
            Err(PraxisError::KeyNotFound)
        ));
        assert_eq!(db.kv().snapshot().sequence, before);
    }
    let rid = client
        .put_record(
            RequestContext::new("put"),
            vec![0, 255, 1],
            vec![IndexInsert::new("kv", b"k".to_vec())],
        )
        .unwrap()
        .record_id;
    assert_eq!(
        service
            .get_record(GetRecordRequest {
                context: RequestContext::new("service-get"),
                record_id: rid
            })
            .unwrap()
            .value,
        Some(vec![0, 255, 1])
    );
    assert!(
        client
            .delete_record(RequestContext::new("delete"), rid)
            .unwrap()
            .deleted
    );
    assert!(
        client
            .delete_record(RequestContext::new("repeat"), rid)
            .unwrap()
            .deleted
    );
    assert_eq!(
        client
            .get_record(RequestContext::new("dead"), rid)
            .unwrap()
            .value,
        None
    );
    assert_eq!(service.records().lookup_rid("kv", b"k").unwrap(), Some(rid));
    assert_eq!(service.records().fetch_by_index("kv", b"k").unwrap(), None);
    assert_eq!(
        service.records().delete_by_index("kv", b"k").unwrap(),
        Some(rid)
    );
    assert!(matches!(
        client.records().lookup_rid("unknown", b"k"),
        Err(PraxisError::InvalidConfig(_))
    ));
    assert!(client.flush(RequestContext::new("flush")).unwrap().ok);
    drop(client);
    drop(service);
    drop(db);
    let reopened = CoreDatabase::open(config).unwrap();
    assert!(matches!(
        reopened.records().fetch(rid),
        Err(PraxisError::KeyNotFound)
    ));
    assert_eq!(reopened.records().lookup_rid("kv", b"k").unwrap(), None);
    assert_eq!(reopened.records().put(b"next", &[]).unwrap(), RecordId(2));
}

#[test]
fn one_batch_has_one_core_commit_and_invalid_later_input_changes_nothing() {
    let (_dir, config, db) = database(WalSyncPolicy::GroupCommit);
    let client = LocalCorepraxisClient::new(CorePrimitiveStorageService::new(db.records()));
    let core_before = db.kv().snapshot().sequence;
    assert!(
        client
            .put_record_batch(RequestContext::new("empty"), vec![])
            .unwrap()
            .record_ids
            .is_empty()
    );
    assert_eq!(db.kv().snapshot().sequence, core_before);
    let input = |value, index: &str| BatchRecordInput {
        value: vec![value],
        indexes: vec![IndexInsert::new(index, b"k".to_vec())],
    };
    assert!(matches!(
        client.put_record_batch(
            RequestContext::new("invalid"),
            vec![input(1, "kv"), input(2, "absent")]
        ),
        Err(PraxisError::InvalidConfig(_))
    ));
    assert_eq!(db.kv().snapshot().sequence, core_before);
    assert_eq!(db.records().compatibility_sequence().unwrap(), 0);
    assert_eq!(db.records().live_count().unwrap(), 0);
    assert_eq!(db.records().lookup_rid("kv", b"k").unwrap(), None);
    let ids = client
        .put_record_batch(
            RequestContext::new("valid"),
            vec![input(1, "kv"), input(2, "kv")],
        )
        .unwrap()
        .record_ids;
    assert_eq!(ids, [RecordId(1), RecordId(2)]);
    assert_eq!(db.kv().snapshot().sequence, core_before + 1);
    assert_eq!(client.records().compatibility_sequence().unwrap(), 4);
    assert_eq!(
        client.records().lookup_rid_at("kv", b"k", 2).unwrap(),
        Some(ids[0])
    );
    assert_eq!(
        client.records().lookup_rid("kv", b"k").unwrap(),
        Some(ids[1])
    );
    client.flush(RequestContext::new("flush")).unwrap();
    drop(client);
    drop(db);
    let reopened = CoreDatabase::open(config).unwrap();
    assert_eq!(reopened.records().fetch(ids[0]).unwrap(), [1]);
    assert_eq!(reopened.records().fetch(ids[1]).unwrap(), [2]);
    assert_eq!(
        reopened.records().lookup_rid("kv", b"k").unwrap(),
        Some(ids[1])
    );
}

#[test]
fn returned_record_view_preserves_mapping_operations_and_cleanup_semantics() {
    let (_dir, _config, db) = database(WalSyncPolicy::EveryBatch);
    let client = LocalCorepraxisClient::new(CorePrimitiveStorageService::new(db.records()));
    let first = client
        .put_record(RequestContext::new("first"), b"a".to_vec(), vec![])
        .unwrap()
        .record_id;
    let records = client.records();
    records.put_index("kv", b"k", first).unwrap();
    let at_first = records.compatibility_sequence().unwrap();
    let second = db.records().put(b"b", &[]).unwrap();
    records.put_index("kv", b"k", second).unwrap();
    assert_eq!(
        records.lookup_rid_at("kv", b"k", at_first).unwrap(),
        Some(first)
    );
    assert_eq!(
        records.fetch_by_index("kv", b"k").unwrap(),
        Some(b"b".to_vec())
    );
    records.delete_index("kv", b"k").unwrap();
    assert_eq!(records.lookup_rid("kv", b"k").unwrap(), None);
    records.put_index("kv", b"k", first).unwrap();
    records
        .delete_record_with_index_cleanup(first, &[IndexInsert::new("kv", b"k".to_vec())])
        .unwrap();
    assert_eq!(records.lookup_rid("kv", b"k").unwrap(), None);
    assert_eq!(
        client
            .get_record(RequestContext::new("cleaned"), first)
            .unwrap()
            .value,
        None
    );
    assert_eq!(
        client
            .get_record(RequestContext::new("still-live"), second)
            .unwrap()
            .value,
        Some(b"b".to_vec())
    );
}

#[test]
fn service_client_and_returned_view_retain_the_single_writer_lease_until_final_drop() {
    let (_dir, config, db) = database(WalSyncPolicy::Never);
    let service = CorePrimitiveStorageService::new(db.records());
    let client = LocalCorepraxisClient::new(service.clone());
    let client_clone = client.clone();
    let records = client.records();
    drop(db);
    assert!(matches!(
        CoreDatabase::open(config.clone()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    let rid = client
        .put_record(RequestContext::new("retained"), b"live".to_vec(), vec![])
        .unwrap()
        .record_id;
    drop(service);
    client.flush(RequestContext::new("durable-never")).unwrap();
    drop(client);
    assert_eq!(
        client_clone
            .get_record(RequestContext::new("clone-retained"), rid)
            .unwrap()
            .value,
        Some(b"live".to_vec())
    );
    drop(client_clone);
    assert!(matches!(
        CoreDatabase::open(config.clone()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    assert_eq!(records.fetch(rid).unwrap(), b"live");
    drop(records);
    let reopened = CoreDatabase::open(config).unwrap();
    assert_eq!(reopened.records().fetch(rid).unwrap(), b"live");
}

#[test]
fn concurrent_service_clones_direct_records_and_kv_share_one_ordered_owner() {
    for policy in [
        WalSyncPolicy::EveryBatch,
        WalSyncPolicy::GroupCommit,
        WalSyncPolicy::Never,
    ] {
        let (_dir, config, db) = database(policy);
        let before = db.kv().snapshot().sequence;
        let service = CorePrimitiveStorageService::new(db.records());
        let client = LocalCorepraxisClient::new(service.clone());
        let mut joins = Vec::new();
        for worker in 0..4 {
            let service = service.clone();
            let records = client.records();
            let kv = db.kv();
            joins.push(std::thread::spawn(move || {
                let mut ids = Vec::new();
                for index in 0..4 {
                    let value = format!("{worker}-{index}").into_bytes();
                    let rid = if index % 2 == 0 {
                        service
                            .put_record(PutRecordRequest {
                                context: RequestContext::new("concurrent"),
                                value: value.clone(),
                                indexes: vec![IndexInsert::new("kv", value.clone())],
                            })
                            .unwrap()
                            .record_id
                    } else {
                        records
                            .put(&value, &[IndexInsert::new("kv", value.clone())])
                            .unwrap()
                    };
                    kv.put(value.clone(), value.clone()).unwrap();
                    ids.push((rid, value));
                }
                ids
            }));
        }
        let expected: Vec<_> = joins
            .into_iter()
            .flat_map(|join| join.join().unwrap())
            .collect();
        assert_eq!(
            expected
                .iter()
                .map(|(rid, _)| *rid)
                .collect::<BTreeSet<_>>()
                .len(),
            16
        );
        assert_eq!(db.kv().snapshot().sequence, before + 32);
        for (rid, value) in &expected {
            assert_eq!(
                client
                    .get_record(RequestContext::new("visible"), *rid)
                    .unwrap()
                    .value
                    .as_ref(),
                Some(value)
            );
            assert_eq!(
                client
                    .records()
                    .fetch_by_index("kv", value)
                    .unwrap()
                    .as_ref(),
                Some(value)
            );
            assert_eq!(
                db.kv().get(value).unwrap().unwrap().as_ref(),
                value.as_slice()
            );
        }
        client.flush(RequestContext::new("flush")).unwrap();
        drop(client);
        drop(service);
        drop(db);
        let reopened = CoreDatabase::open(config).unwrap();
        for (rid, value) in expected {
            assert_eq!(reopened.records().fetch(rid).unwrap(), value);
            assert_eq!(
                reopened.kv().get(&value).unwrap().unwrap().as_ref(),
                value.as_slice()
            );
        }
    }
}

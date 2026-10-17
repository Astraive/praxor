use super::*;
use crate::api::service::RequestContext;
use crate::core_records::codec::{Key, Role};
use crate::sdk::LocalCorepraxisClient;
use crate::types::{ColumnFamily, StoredValue};
use crate::{CoreDatabase, PraxisConfig, RecordAuthorityOptions};

#[test]
fn get_preserves_actual_blob_read_io_and_payload_checksum_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.large_value_threshold = 1;
    let db = CoreDatabase::create_fresh(config.clone(), RecordAuthorityOptions { indexes: vec![] })
        .unwrap();
    let rid = db.records().put(b"external payload", &[]).unwrap();
    db.records().flush().unwrap();
    drop(db);
    // Flush retains an in-memory inline version. Reopen resolves the actual
    // persisted external pointer, so these reads exercise real filesystem IO.
    let db = CoreDatabase::open(config).unwrap();
    let service = CorePrimitiveStorageService::new(db.records());
    let client = LocalCorepraxisClient::new(service.clone());
    let engine = db.kv();
    let key = (
        ColumnFamily(Role::Payload.cf().into()),
        bytes::Bytes::from(Key::Payload(rid.0).encode().unwrap()),
    );
    let pointer = match &engine.inner.segment_index.read()[&key]
        .last()
        .unwrap()
        .value
    {
        StoredValue::BlobPointer(pointer) => pointer.clone(),
        value => panic!("expected a real flushed payload pointer, got {value:?}"),
    };
    let original = std::fs::read(&pointer.path).unwrap();
    // The file can contain other protected extents too: removing it proves
    // record-read IO passthrough without claiming a specific read stage.
    std::fs::remove_file(&pointer.path).unwrap();
    for error in [
        service
            .get_record(GetRecordRequest {
                context: RequestContext::new("service-io"),
                record_id: rid,
            })
            .unwrap_err(),
        client
            .get_record(RequestContext::new("client-io"), rid)
            .unwrap_err(),
    ] {
        assert!(
            matches!(error, PraxisError::Io(ref error) if error.kind() == std::io::ErrorKind::NotFound)
        );
    }
    let mut damaged = original.clone();
    damaged[(pointer.offset + 12) as usize] ^= 1;
    std::fs::write(&pointer.path, damaged).unwrap();
    for error in [
        service
            .get_record(GetRecordRequest {
                context: RequestContext::new("service-corrupt"),
                record_id: rid,
            })
            .unwrap_err(),
        client
            .get_record(RequestContext::new("client-corrupt"), rid)
            .unwrap_err(),
    ] {
        assert!(
            matches!(error, PraxisError::Corrupt { path, reason } if path == std::path::Path::new(&pointer.path) && reason == "value log checksum mismatch")
        );
    }
    std::fs::write(&pointer.path, original).unwrap();
    assert_eq!(
        client
            .get_record(RequestContext::new("restored"), rid)
            .unwrap()
            .value,
        Some(b"external payload".to_vec())
    );
}

#[test]
fn never_client_flush_executes_one_ordered_durable_barrier_without_consuming_sequence() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = crate::WalSyncPolicy::Never;
    config.wal_segment_size = config.page_size;
    config.memtable_flush_threshold_bytes = usize::MAX;
    let payload_size = config.page_size * 2;
    let db = CoreDatabase::create_fresh(config.clone(), RecordAuthorityOptions { indexes: vec![] })
        .unwrap();
    let engine = db.kv();
    let client = LocalCorepraxisClient::new(CorePrimitiveStorageService::new(db.records()));
    let rid = client
        .put_record(RequestContext::new("never"), vec![7; payload_size], vec![])
        .unwrap()
        .record_id;
    engine.put("ordinary-never", "shared-owner").unwrap();
    assert!(engine.inner.manifest.lock().active_wal_id > 1);
    let before = engine
        .inner
        .metrics
        .commit_sync_attempts
        .load(Ordering::Relaxed);
    let sequence = engine.snapshot().sequence;
    assert!(client.flush(RequestContext::new("barrier")).unwrap().ok);
    assert_eq!(
        engine
            .inner
            .metrics
            .commit_sync_attempts
            .load(Ordering::Relaxed),
        before + 1
    );
    assert_eq!(engine.snapshot().sequence, sequence);
    drop(client);
    drop(engine);
    drop(db);
    let reopened = CoreDatabase::open(config).unwrap();
    assert_eq!(reopened.records().fetch(rid).unwrap().len(), payload_size);
    assert_eq!(
        reopened
            .kv()
            .get("ordinary-never")
            .unwrap()
            .unwrap()
            .as_ref(),
        b"shared-owner"
    );
}

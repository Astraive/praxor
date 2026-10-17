use praxis::store::{
    ManifestEdit, RecordStore, StorageEngine, StorageManifest, StorageManifestStore,
};
use tempfile::tempdir;

#[test]
fn compaction_manifest_tracks_started_installed_and_cleanup() {
    let dir = tempdir().unwrap();
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    let stale = engine.put(b"stale", &[]).unwrap();
    engine.put(b"live", &[]).unwrap();
    engine.delete_record(stale).unwrap();

    let stats = engine.compact_primary().unwrap();
    assert_eq!(stats.records_retained, 1);
    assert_eq!(stats.records_dropped, 1);

    let manifest_bytes = std::fs::read(dir.path().join("MANIFEST.store")).unwrap();
    let manifest: StorageManifest = serde_json::from_slice(&manifest_bytes).unwrap();

    assert!(manifest.edits.iter().any(|edit| matches!(
        edit,
        ManifestEdit::CompactionStarted { job_id, old_segments }
            if job_id == "primary-3" && old_segments == &vec![0]
    )));
    assert!(manifest.edits.iter().any(|edit| matches!(
        edit,
        ManifestEdit::CompactionInstalled {
            job_id,
            old_segments,
            new_segment,
            records_retained,
            ..
        } if job_id == "primary-3"
            && old_segments == &vec![0]
            && *new_segment == 1
            && *records_retained == 1
    )));
    assert!(manifest.edits.iter().any(|edit| matches!(
        edit,
        ManifestEdit::CompactionCleanupComplete {
            job_id,
            cleaned_segments,
        } if job_id == "primary-3" && cleaned_segments == &vec![0]
    )));
}

#[test]
fn engine_open_completes_pending_compaction_cleanup_from_manifest() {
    let dir = tempdir().unwrap();
    let primary_root = dir.path().join("primary");
    let mut store = RecordStore::open(&primary_root).unwrap();

    let deleted = store.put(b"delete-me").unwrap();
    store.put(b"keep-me").unwrap();
    store.delete(deleted).unwrap();
    store.flush().unwrap();

    let old_segments = store.live_segment_ids().unwrap();
    assert_eq!(old_segments, vec![0]);

    let prepared = store.compact_prepare().unwrap();
    assert_eq!(prepared.new_segment_id, 1);
    assert!(primary_root.join("records").join("00000000.trec").exists());

    let manifest_store = StorageManifestStore::new(dir.path().join("MANIFEST.store"));
    let mut manifest = StorageManifest::default();
    manifest.append_edit(ManifestEdit::CompactionStarted {
        job_id: "primary-0".to_string(),
        old_segments: old_segments.clone(),
    });
    manifest.append_edit(ManifestEdit::CompactionInstalled {
        job_id: "primary-0".to_string(),
        old_segments: old_segments.clone(),
        new_segment: prepared.new_segment_id,
        records_retained: prepared.stats.records_retained,
        bytes_written: prepared.stats.bytes_written,
    });
    manifest_store.save(&manifest).unwrap();

    drop(store);
    let _engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();

    assert!(!primary_root.join("records").join("00000000.trec").exists());
    assert!(primary_root.join("records").join("00000001.trec").exists());

    let manifest = manifest_store.load_or_create().unwrap();
    assert!(manifest.edits.iter().any(|edit| matches!(
        edit,
        ManifestEdit::CompactionCleanupComplete {
            job_id,
            cleaned_segments,
        } if job_id == "primary-0" && cleaned_segments == &vec![0]
    )));
}

#[test]
fn engine_open_marks_started_without_install_as_aborted() {
    let dir = tempdir().unwrap();
    let primary_root = dir.path().join("primary");
    let mut store = RecordStore::open(&primary_root).unwrap();
    store.put(b"keep-me").unwrap();
    store.flush().unwrap();

    let manifest_store = StorageManifestStore::new(dir.path().join("MANIFEST.store"));
    let mut manifest = StorageManifest::default();
    manifest.append_edit(ManifestEdit::CompactionStarted {
        job_id: "primary-0".to_string(),
        old_segments: vec![0],
    });
    manifest_store.save(&manifest).unwrap();

    drop(store);
    let _engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();

    assert!(primary_root.join("records").join("00000000.trec").exists());

    let manifest = manifest_store.load_or_create().unwrap();
    assert!(manifest.edits.iter().any(|edit| matches!(
        edit,
        ManifestEdit::CompactionAborted {
            job_id,
            old_segments,
            reason,
        } if job_id == "primary-0"
            && old_segments == &vec![0]
            && reason == "startup_reconcile_missing_install"
    )));
}

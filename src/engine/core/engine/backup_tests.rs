use super::*;
use crate::engine::core::backup::{Phase, hooks};
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn capture_excludes_later_clone_writes_and_holds_files_against_gc() {
    let dir = tempfile::tempdir().unwrap();
    let live = dir.path().join("live");
    let target = dir.path().join("backup");
    let mut config = PraxisConfig::new(&live);
    config.wal_segment_size = config.page_size;
    let late_size = config.page_size * 2;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    engine.put("before", "captured").unwrap();
    engine.flush().unwrap();
    let cut = engine.snapshot();
    let writer = engine.clone();
    let collector = engine.clone();
    let (done_tx, done_rx) = mpsc::channel();
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let _hook = hooks::install(move |point| {
        if point == Phase::Captured {
            let writer = writer.clone();
            std::thread::spawn(move || {
                writer.put("after", vec![b'L'; late_size]).unwrap();
                writer.put("after-rotation", vec![b'R'; late_size]).unwrap();
            })
            .join()
            .unwrap();
            let collector = collector.clone();
            let done_tx = done_tx.clone();
            let started_tx = started_tx.clone();
            let finished_tx = finished_tx.clone();
            std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                collector.garbage_collect().unwrap();
                done_tx.send(()).unwrap();
                finished_tx.send(()).unwrap();
            });
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(
                done_rx.recv_timeout(Duration::from_millis(150)).is_err(),
                "GC escaped the backup's physical retention boundary"
            );
        }
        Ok(())
    });
    engine.backup_to(&target).unwrap();
    finished_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    config.data_dir = target;
    let archived = PraxisEngine::open(config).unwrap();
    assert_eq!(archived.snapshot(), cut);
    assert_eq!(
        archived.get("before").unwrap(),
        Some(Bytes::from_static(b"captured"))
    );
    assert_eq!(archived.get("after").unwrap(), None);
    assert_eq!(
        engine.get("after").unwrap(),
        Some(Bytes::from(vec![b'L'; late_size]))
    );
}

#[test]
fn recognized_abandoned_staging_is_discarded_without_adopting_its_content() {
    for marker in [
        b"".as_slice(),
        b"praxor core",
        b"praxor core copy incomplete v1\n",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("backup");
        let source = PraxisEngine::open(PraxisConfig::new(dir.path().join("live"))).unwrap();
        source.put("new", "new").unwrap();
        {
            let old = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
            old.put("old", "old").unwrap();
            old.flush().unwrap();
        }
        let abandoned = target.join("tmp/backup-stage-interrupted");
        fs::create_dir_all(abandoned.join("checkpoints")).unwrap();
        fs::write(abandoned.join("COPY_PUBLICATION_MARKER"), marker).unwrap();
        fs::write(
            abandoned.join("checkpoints/00000000000000000001.tmp"),
            b"{\"format_version\"",
        )
        .unwrap();
        source.backup_to(&target).unwrap();
        assert!(!abandoned.exists());
        let copy = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
        assert_eq!(copy.get("new").unwrap(), Some(Bytes::from_static(b"new")));
    }
}

#[test]
fn an_unknown_abandoned_marker_refuses_before_removing_the_old_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("backup");
    let source = PraxisEngine::open(PraxisConfig::new(dir.path().join("live"))).unwrap();
    {
        let old = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
        old.put("old", "old").unwrap();
        old.flush().unwrap();
    }
    let manifest = fs::read(target.join("MANIFEST")).unwrap();
    let abandoned = target.join("tmp/backup-stage-interrupted");
    fs::create_dir_all(&abandoned).unwrap();
    fs::write(abandoned.join("COPY_PUBLICATION_MARKER"), b"foreign copy").unwrap();
    assert!(source.backup_to(&target).is_err());
    assert_eq!(fs::read(target.join("MANIFEST")).unwrap(), manifest);
    assert!(!target.join(super::super::backup::INCOMPLETE).exists());
}

#[test]
fn relative_legacy_labels_relocate_by_role_without_following_the_working_directory() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("backup");
    let hidden = dir.path().join("hidden");
    let target = dir.path().join("restored");
    let mut config = PraxisConfig::new(dir.path().join("live"));
    config.large_value_threshold = 8;
    let source = PraxisEngine::open(config).unwrap();
    let value = vec![b'L'; 8192];
    source.put("value", value.clone()).unwrap();
    source.flush().unwrap();
    source.backup_to(&bundle).unwrap();
    let root = bundle.canonicalize().unwrap();
    let store = ManifestStore::new(root.join("MANIFEST"));
    let mut manifest = store.load_or_create(&PraxisConfig::new(&root)).unwrap();
    for metadata in &mut manifest.segments {
        let path = PathBuf::from(&metadata.path);
        let mut raw = crate::segments::codec::decode_segment(
            &fs::read(&path).unwrap(),
            &path,
            &CpuAccelerator,
        )
        .unwrap();
        for entry in raw.blocks.iter_mut().flatten() {
            if let StoredValue::BlobPointer(pointer) = &mut entry.entry.version.value {
                pointer.path = Path::new(&pointer.path)
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
            }
        }
        let bytes = raw.encode(&CpuAccelerator).unwrap();
        fs::write(&path, &bytes).unwrap();
        metadata.file_digest = blake3::hash(&bytes).to_hex().to_string();
        metadata.path = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
    }
    let checkpoint = manifest.latest_checkpoint.as_mut().unwrap();
    checkpoint.path = Path::new(&checkpoint.path)
        .strip_prefix(&root)
        .unwrap()
        .to_string_lossy()
        .into_owned();
    store.save(&manifest).unwrap();
    fs::rename(&bundle, &hidden).unwrap();
    PraxisEngine::restore_from_backup(&hidden, &target).unwrap();
    let mut restored_config = PraxisConfig::new(&target);
    restored_config.large_value_threshold = 8;
    let restored = PraxisEngine::open(restored_config).unwrap();
    assert_eq!(restored.get("value").unwrap().unwrap().as_ref(), value);
}

#[test]
fn failed_staging_preserves_the_previous_destination_and_source_health() {
    let dir = tempfile::tempdir().unwrap();
    let live = dir.path().join("live");
    let target = dir.path().join("backup");
    let engine = PraxisEngine::open(PraxisConfig::new(&live)).unwrap();
    engine.put("source", "source").unwrap();
    {
        let old = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
        old.put("previous", "previous").unwrap();
        old.flush().unwrap();
    }
    let _hook = hooks::install(|point| {
        if point == Phase::Staged {
            return Err(std::io::Error::other("staging interruption").into());
        }
        Ok(())
    });
    assert!(engine.backup_to(&target).is_err());
    assert_eq!(
        engine.get("source").unwrap(),
        Some(Bytes::from_static(b"source"))
    );
    let old = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
    assert_eq!(
        old.get("previous").unwrap(),
        Some(Bytes::from_static(b"previous"))
    );
}

#[test]
fn interrupted_publication_refuses_open_and_an_explicit_retry_completes() {
    let dir = tempfile::tempdir().unwrap();
    let live = dir.path().join("live");
    let target = dir.path().join("backup");
    let engine = PraxisEngine::open(PraxisConfig::new(&live)).unwrap();
    engine.put("source", "source").unwrap();
    {
        let _hook = hooks::install(|point| {
            if point == Phase::Invalidated {
                return Err(std::io::Error::other("publication interruption").into());
            }
            Ok(())
        });
        assert!(engine.backup_to(&target).is_err());
    }
    assert!(target.join(super::super::backup::INCOMPLETE).is_file());
    assert!(PraxisEngine::open(PraxisConfig::new(&target)).is_err());
    assert_eq!(
        engine.get("source").unwrap(),
        Some(Bytes::from_static(b"source"))
    );
    engine.backup_to(&target).unwrap();
    assert!(!target.join(super::super::backup::INCOMPLETE).exists());
    let copy = PraxisEngine::open(PraxisConfig::new(target)).unwrap();
    assert_eq!(
        copy.get("source").unwrap(),
        Some(Bytes::from_static(b"source"))
    );
}

#[test]
fn failed_fresh_staging_can_be_retried_without_an_orphan_authority() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("backup");
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path().join("live"))).unwrap();
    engine.put("value", "retained").unwrap();
    {
        let _hook = hooks::install(|phase| {
            if phase == Phase::Staged {
                return Err(std::io::Error::other("before publication").into());
            }
            Ok(())
        });
        assert!(engine.backup_to(&target).is_err());
    }
    engine.backup_to(&target).unwrap();
    let copy = PraxisEngine::open(PraxisConfig::new(target)).unwrap();
    assert_eq!(
        copy.get("value").unwrap(),
        Some(Bytes::from_static(b"retained"))
    );
}

#[test]
fn retry_after_removing_dependencies_or_publishing_manifest_preserves_neutral_primary_lock() {
    for point in [Phase::Cleared, Phase::Published] {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("backup");
        let engine = PraxisEngine::open(PraxisConfig::new(dir.path().join("live"))).unwrap();
        engine.put("value", "new").unwrap();
        engine.flush().unwrap();
        {
            let old = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
            old.put("old", "old").unwrap();
            old.flush().unwrap();
        }
        std::fs::create_dir(target.join("primary")).unwrap();
        let lock = target.join("primary").join(LOCK_FILE_NAME);
        std::fs::write(&lock, b"permanent primary identity").unwrap();
        {
            let _hook = hooks::install(move |phase| {
                if phase == point {
                    return Err(std::io::Error::other("replacement interruption").into());
                }
                Ok(())
            });
            assert!(engine.backup_to(&target).is_err());
        }
        assert_eq!(std::fs::read(&lock).unwrap(), b"permanent primary identity");
        assert!(PraxisEngine::open(PraxisConfig::new(&target)).is_err());
        engine.backup_to(&target).unwrap();
        assert_eq!(std::fs::read(&lock).unwrap(), b"permanent primary identity");
        let copy = PraxisEngine::open(PraxisConfig::new(target)).unwrap();
        assert_eq!(copy.get("value").unwrap(), Some(Bytes::from_static(b"new")));
        assert_eq!(copy.get("old").unwrap(), None);
    }
}

#[test]
fn a_failed_sentinel_preparation_never_invalidates_the_previous_authority() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("backup");
    let engine = PraxisEngine::open(PraxisConfig::new(dir.path().join("live"))).unwrap();
    engine.put("new", "new").unwrap();
    {
        let old = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
        old.put("old", "old").unwrap();
        old.flush().unwrap();
    }
    let old_manifest = fs::read(target.join("MANIFEST")).unwrap();
    let target_for_hook = target.clone();
    let _hook = hooks::install(move |point| {
        if point == Phase::Staged {
            let stage = fs::read_dir(target_for_hook.join("tmp"))
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            fs::create_dir(stage.join("COPY_PUBLICATION_MARKER")).unwrap();
        }
        Ok(())
    });
    assert!(engine.backup_to(&target).is_err());
    assert!(!target.join(super::super::backup::INCOMPLETE).exists());
    assert_eq!(fs::read(target.join("MANIFEST")).unwrap(), old_manifest);
    let old = PraxisEngine::open(PraxisConfig::new(target)).unwrap();
    assert_eq!(old.get("old").unwrap(), Some(Bytes::from_static(b"old")));
}

#[cfg(windows)]
#[test]
fn retry_marker_sync_refusal_preserves_previous_authority_and_source_health() {
    use std::os::windows::fs::OpenOptionsExt;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("backup");
    let source = PraxisEngine::open(PraxisConfig::new(dir.path().join("live"))).unwrap();
    source.put("new", "new").unwrap();
    {
        let old = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
        old.put("old", "old").unwrap();
        old.flush().unwrap();
    }
    let before = fs::read(target.join("MANIFEST")).unwrap();
    let marker = target.join(super::super::backup::INCOMPLETE);
    fs::write(&marker, b"praxor core copy incomplete v1\n").unwrap();
    // Permit reading/deleting but deny reopening for write+sync. This isolates
    // the missing pre-delete marker IO; it does not obstruct later cleanup.
    let blocker = fs::OpenOptions::new()
        .read(true)
        .share_mode(0x1 | 0x4)
        .open(&marker)
        .unwrap();
    let result = source.backup_to(&target);
    let after = fs::read(target.join("MANIFEST")).unwrap();
    drop(blocker);
    assert!(result.is_err());
    assert_eq!(
        after, before,
        "retry deleted old authority before synchronizing its marker"
    );
    source.put("source-later", "healthy").unwrap();
    source.backup_to(&target).unwrap();
    let copy = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
    assert_eq!(copy.get("new").unwrap(), Some(Bytes::from_static(b"new")));
}

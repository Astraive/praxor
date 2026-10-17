use bytes::Bytes;
use praxis::wal::{Wal, WalRecord};
use praxis::{PraxisConfig, PraxisEngine, PraxisError, WalSyncPolicy, WriteBatch};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use tempfile::tempdir;

fn record(sequence: u64, value: &'static str) -> WalRecord {
    let mut batch = WriteBatch::new();
    batch.put_default(
        Bytes::from_static(b"key"),
        Bytes::from_static(value.as_bytes()),
    );
    WalRecord { sequence, batch }
}

fn append_bytes(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn append_after_recovering_a_torn_record_survives_another_reopen() {
    let first = record(1, "before crash");
    let torn = record(2, "partly written").encode();
    let after = record(2, "after recovery");

    // Exercise an incomplete header, a complete header without its payload,
    // and a record missing only its last byte.
    for cut in [3, 12, torn.len() - 1] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("active.wal");
        let mut wal = Wal::open(&path, 1, WalSyncPolicy::EveryBatch).unwrap();
        wal.append(&first).unwrap();
        drop(wal);
        let valid_len = fs::metadata(&path).unwrap().len();
        append_bytes(&path, &torn[..cut]);

        assert_eq!(Wal::replay(&path).unwrap(), vec![first.clone()]);
        let mut recovered = Wal::open(&path, 1, WalSyncPolicy::EveryBatch).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), valid_len);
        // Rotation must use the repaired length, not the discarded suffix.
        assert!(!recovered.should_rotate(
            after.encoded_len(),
            (valid_len as usize) + after.encoded_len()
        ));
        recovered.append(&after).unwrap();
        drop(recovered);

        assert_eq!(
            Wal::replay(&path).unwrap(),
            vec![first.clone(), after.clone()]
        );
        let reopened = Wal::open(&path, 1, WalSyncPolicy::EveryBatch).unwrap();
        drop(reopened);
        assert_eq!(
            Wal::replay(&path).unwrap(),
            vec![first.clone(), after.clone()]
        );
    }
}

#[test]
fn legacy_headerless_wal_can_repair_a_torn_tail_and_keep_appending() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("legacy.wal");
    let first = record(1, "legacy");
    let after = record(2, "new");
    fs::write(&path, first.encode()).unwrap();
    let torn = record(2, "incomplete").encode();
    append_bytes(&path, &torn[..torn.len() - 1]);

    let mut wal = Wal::open(&path, 1, WalSyncPolicy::EveryBatch).unwrap();
    wal.append(&after).unwrap();
    drop(wal);

    assert_eq!(Wal::replay(&path).unwrap(), vec![first, after]);
}

#[test]
fn complete_checksum_corruption_is_reported_without_truncating_the_wal() {
    for has_later_record in [false, true] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("corrupt.wal");
        let mut wal = Wal::open(&path, 1, WalSyncPolicy::EveryBatch).unwrap();
        wal.append(&record(1, "valid prefix")).unwrap();
        drop(wal);
        let mut corrupt = record(2, "corrupt payload").encode();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xff;
        append_bytes(&path, &corrupt);
        if has_later_record {
            append_bytes(&path, &record(3, "valid suffix").encode());
        }
        let original = fs::read(&path).unwrap();

        assert!(matches!(
            Wal::replay(&path),
            Err(PraxisError::Corrupt { .. })
        ));
        assert!(matches!(
            Wal::open(&path, 1, WalSyncPolicy::EveryBatch),
            Err(PraxisError::Corrupt { .. })
        ));
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}

#[test]
fn invalid_complete_record_header_is_not_mistaken_for_a_torn_payload() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bad-magic.wal");
    let mut wal = Wal::open(&path, 1, WalSyncPolicy::EveryBatch).unwrap();
    wal.append(&record(1, "valid prefix")).unwrap();
    drop(wal);
    // A complete header with bad magic and a length extending past EOF is
    // corruption, rather than evidence of an interrupted valid append.
    append_bytes(&path, &[0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0]);
    let original = fs::read(&path).unwrap();

    assert!(matches!(
        Wal::replay(&path),
        Err(PraxisError::Corrupt { .. })
    ));
    assert!(Wal::open(&path, 1, WalSyncPolicy::EveryBatch).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
}

fn wal_file_header(segment_id: u64) -> Vec<u8> {
    let mut header = vec![0x46, 0x41, 0x57, 0x54, 1, 0, 0, 0];
    header.extend_from_slice(&segment_id.to_le_bytes());
    header
}

#[test]
fn matching_partial_wal_file_header_is_completed_before_appending() {
    let header = wal_file_header(7);
    for cut in 0..header.len() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("active.wal");
        fs::write(&path, &header[..cut]).unwrap();
        assert!(Wal::replay(&path).unwrap().is_empty());

        let expected = record(1, "after header recovery");
        let mut wal = Wal::open(&path, 7, WalSyncPolicy::EveryBatch).unwrap();
        assert_eq!(fs::read(&path).unwrap(), header);
        wal.append(&expected).unwrap();
        drop(wal);
        drop(Wal::open(&path, 7, WalSyncPolicy::EveryBatch).unwrap());
        assert_eq!(Wal::replay(&path).unwrap(), vec![expected]);
    }
}

#[test]
fn orphan_partial_next_wal_does_not_block_engine_recovery_or_rotation() {
    let header = wal_file_header(2);
    for cut in 0..header.len() {
        let dir = tempdir().unwrap();
        let mut config = PraxisConfig::new(dir.path());
        config.page_size = 4096;
        config.wal_segment_size = 4096;
        let engine = PraxisEngine::open(config.clone()).unwrap();
        engine
            .put(
                Bytes::from_static(b"safe"),
                Bytes::from_static(b"acknowledged"),
            )
            .unwrap();
        drop(engine);

        // Rotation creates the next WAL before publishing its id in the
        // manifest. A crash at any header byte must preserve prior writes.
        let orphan = dir.path().join("wal").join("00000000000000000002.wal");
        fs::write(&orphan, &header[..cut]).unwrap();
        let recovered = PraxisEngine::open(config.clone()).unwrap();
        assert_eq!(
            recovered.get("safe").unwrap().unwrap().as_ref(),
            b"acknowledged"
        );
        // This write forces reuse of the orphan next segment.
        recovered
            .put(Bytes::from_static(b"after"), Bytes::from(vec![7; 4096]))
            .unwrap();
        drop(recovered);

        let reopened = PraxisEngine::open(config).unwrap();
        assert_eq!(
            reopened.get("safe").unwrap().unwrap().as_ref(),
            b"acknowledged"
        );
        assert_eq!(
            reopened.get("after").unwrap().unwrap().as_ref(),
            vec![7; 4096]
        );
    }
}

#[test]
fn invalid_wal_file_header_prefix_or_version_is_not_repaired() {
    let mut bad_version = wal_file_header(1);
    bad_version[4] = 2;
    for original in [vec![0xff], bad_version[..6].to_vec(), bad_version] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("invalid.wal");
        fs::write(&path, &original).unwrap();

        assert!(matches!(
            Wal::replay(&path),
            Err(PraxisError::Corrupt { .. })
        ));
        assert!(matches!(
            Wal::open(&path, 1, WalSyncPolicy::EveryBatch),
            Err(PraxisError::Corrupt { .. })
        ));
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}

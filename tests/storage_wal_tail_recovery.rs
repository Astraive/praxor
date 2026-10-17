use praxis::PraxisError;
use praxis::store::{
    RecordId, StorageWal, StorageWalEntry, StorageWalOperation, StorageWalOptions,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn entry(sequence: u64, key_len: usize) -> StorageWalEntry {
    StorageWalEntry {
        sequence,
        index_type: "kv".into(),
        key: vec![sequence as u8; key_len],
        rid: Some(RecordId(sequence)),
        operation: StorageWalOperation::Put,
    }
}

fn segment(root: &Path, id: u64) -> PathBuf {
    root.join(format!("storage.{id:020}.swal"))
}

fn append_bytes(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

// Legacy JSON records use the same framing as binary records. Construct a
// real compatible frame so recovery is checked across both payload formats.
fn legacy_record(entry: &StorageWalEntry) -> Vec<u8> {
    let payload = serde_json::to_vec(entry).unwrap();
    let mut frame = Vec::new();
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    frame.extend_from_slice(&payload);
    frame
}

#[test]
fn torn_storage_wal_tail_is_removed_before_appending_a_batch() {
    let torn = legacy_record(&entry(2, 80));
    for cut in [3, 8, torn.len() - 1] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("storage.wal");
        let active = segment(dir.path(), 1);
        let first = entry(1, 5);
        let second = entry(2, 5);
        let third = entry(3, 5);
        let fourth = entry(4, 5);
        let mut wal = StorageWal::open(&path).unwrap();
        wal.append(&first).unwrap();
        drop(wal);
        let valid_len = fs::metadata(&active).unwrap().len();
        append_bytes(&active, &torn[..cut]);
        assert_eq!(StorageWal::replay(&path).unwrap(), vec![first.clone()]);

        let mut wal = StorageWal::open(&path).unwrap();
        assert_eq!(fs::metadata(&active).unwrap().len(), valid_len);
        wal.append_batch(&[second.clone(), third.clone()]).unwrap();
        drop(wal);
        let mut wal = StorageWal::open(&path).unwrap();
        wal.append(&fourth).unwrap();
        drop(wal);

        assert_eq!(
            StorageWal::replay(&path).unwrap(),
            vec![first, second, third, fourth]
        );
    }
}

#[test]
fn interrupted_storage_wal_file_header_can_be_completed_before_appending() {
    // Little-endian storage magic followed by version 1.
    let header = [0x4c, 0x57, 0x53, 0x54, 1];
    for cut in 0..header.len() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("storage.wal");
        let active = segment(dir.path(), 1);
        fs::write(&active, &header[..cut]).unwrap();
        assert!(StorageWal::replay(&path).unwrap().is_empty());

        let expected = entry(1, 5);
        let mut wal = StorageWal::open(&path).unwrap();
        wal.append(&expected).unwrap();
        drop(wal);

        assert_eq!(StorageWal::replay(&path).unwrap(), vec![expected]);
    }
}

#[test]
fn complete_storage_wal_checksum_corruption_is_rejected_without_repair() {
    for has_later_record in [false, true] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("storage.wal");
        let active = segment(dir.path(), 1);
        let mut wal = StorageWal::open(&path).unwrap();
        wal.append(&entry(1, 5)).unwrap();
        drop(wal);
        let mut corrupt = legacy_record(&entry(2, 5));
        corrupt[4] ^= 0xff; // Damage the stored checksum, leaving framing intact.
        append_bytes(&active, &corrupt);
        if has_later_record {
            append_bytes(&active, &legacy_record(&entry(3, 5)));
        }
        let original = fs::read(&active).unwrap();

        assert!(matches!(
            StorageWal::replay(&path),
            Err(PraxisError::Corrupt { .. })
        ));
        assert!(matches!(
            StorageWal::open(&path),
            Err(PraxisError::Corrupt { .. })
        ));
        assert_eq!(fs::read(&active).unwrap(), original);
    }
}

#[test]
fn corrupt_older_storage_wal_segment_blocks_open_before_mutating_the_active_tail() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("storage.wal");
    let mut wal = StorageWal::open_with_options(
        &path,
        StorageWalOptions {
            max_segment_bytes: 1024,
        },
    )
    .unwrap();
    wal.append(&entry(1, 1100)).unwrap();
    wal.append(&entry(2, 5)).unwrap();
    drop(wal);
    let older = segment(dir.path(), 1);
    let active = segment(dir.path(), 2);
    let mut corrupt = fs::read(&older).unwrap();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xff;
    fs::write(&older, &corrupt).unwrap();
    append_bytes(&active, &[0xaa, 0xbb, 0xcc]);
    let active_original = fs::read(&active).unwrap();

    assert!(matches!(
        StorageWal::replay(&path),
        Err(PraxisError::Corrupt { .. })
    ));
    assert!(matches!(
        StorageWal::open(&path),
        Err(PraxisError::Corrupt { .. })
    ));
    assert_eq!(fs::read(&older).unwrap(), corrupt);
    assert_eq!(fs::read(&active).unwrap(), active_original);
}

#[test]
fn storage_wal_rotation_uses_repaired_size_and_keeps_batches_together() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("storage.wal");
    let options = StorageWalOptions {
        max_segment_bytes: 1024,
    };
    let first = entry(1, 128);
    let second = entry(2, 128);
    let third = entry(3, 128);
    let fourth = entry(4, 1100);
    let fifth = entry(5, 5);
    let mut wal = StorageWal::open_with_options(&path, options).unwrap();
    wal.append(&first).unwrap();
    drop(wal);
    let torn = legacy_record(&entry(2, 1900));
    append_bytes(&segment(dir.path(), 1), &torn[..850]);

    let mut wal = StorageWal::open_with_options(&path, options).unwrap();
    wal.append_batch(&[second.clone(), third.clone()]).unwrap();
    assert!(
        !segment(dir.path(), 2).exists(),
        "a discarded tail must not cause early rotation"
    );
    wal.append_batch(&[fourth.clone(), fifth.clone()]).unwrap();
    assert!(segment(dir.path(), 2).exists());
    assert!(
        !segment(dir.path(), 3).exists(),
        "a batch rotates as one unit"
    );
    drop(wal);
    drop(StorageWal::open_with_options(&path, options).unwrap());

    assert_eq!(
        StorageWal::replay(&path).unwrap(),
        vec![first, second, third, fourth, fifth]
    );
}

#[test]
fn invalid_short_storage_wal_header_is_reported_without_overwriting_it() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("storage.wal");
    let active = segment(dir.path(), 1);
    let original = [0xff, 0xff, 0xff];
    fs::write(&active, original).unwrap();

    assert!(matches!(
        StorageWal::replay(&path),
        Err(PraxisError::Corrupt { .. })
    ));
    assert!(matches!(
        StorageWal::open(&path),
        Err(PraxisError::Corrupt { .. })
    ));
    assert_eq!(fs::read(&active).unwrap(), original);
}

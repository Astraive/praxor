use praxis::io::{BinaryReader, BinaryWriter, crc32c};
use praxis::wal::{Wal, WalRecord};
use praxis::{PraxisConfig, PraxisEngine, PraxisError, WalSyncPolicy, WriteBatch};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

const V1_MAGIC: u32 = 0x5457_414c;
const V2_MAGIC: u32 = 0x5457_4132;

thread_local! {
    static PEAK: Cell<Option<usize>> = const { Cell::new(None) };
}
struct PeakAllocator;
fn allocation(size: usize) {
    let _ = PEAK.try_with(|peak| {
        if let Some(previous) = peak.get() {
            peak.set(Some(previous.max(size)));
        }
    });
}
unsafe impl GlobalAlloc for PeakAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocation(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocation(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocation(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: PeakAllocator = PeakAllocator;

fn record(sequence: u64) -> WalRecord {
    let mut batch = WriteBatch::new();
    batch.put_default("key", "acknowledged");
    WalRecord { sequence, batch }
}

// Explicit wire fixtures: legacy coverage must not follow the current encoder.
fn payload(sequence: u64) -> Vec<u8> {
    let mut out = BinaryWriter::new();
    out.write_u64(sequence);
    out.write_u32(1);
    out.write_u8(1);
    out.write_len_bytes(b"default");
    out.write_len_bytes(b"key");
    out.write_len_bytes(b"acknowledged");
    out.into_inner()
}

fn frame(payload: &[u8], v2: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&if v2 { V2_MAGIC } else { V1_MAGIC }.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&crc32c(payload).to_le_bytes());
    if v2 {
        out.extend_from_slice(&crc32c(&out).to_le_bytes());
    }
    out.extend_from_slice(payload);
    out
}

fn file_header() -> Vec<u8> {
    let mut out = 0x5457_4146_u32.to_le_bytes().to_vec();
    out.extend_from_slice(&1_u32.to_le_bytes());
    out.extend_from_slice(&1_u64.to_le_bytes());
    out
}

fn assert_corrupt_without_modifying(path: &Path) {
    let before = fs::read(path).unwrap();
    assert!(matches!(
        Wal::replay(path),
        Err(PraxisError::Corrupt { .. })
    ));
    assert!(matches!(
        Wal::open(path, 1, WalSyncPolicy::EveryBatch),
        Err(PraxisError::Corrupt { .. })
    ));
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn acknowledged_final_record_length_bitflip_must_not_discard_the_write() {
    let dir = tempdir().unwrap();
    let mut config = PraxisConfig::new(dir.path());
    config.wal_sync_policy = WalSyncPolicy::EveryBatch;
    let engine = PraxisEngine::open(config.clone()).unwrap();
    engine.put("first", "sound").unwrap();
    assert_eq!(engine.put("last", "acknowledged").unwrap(), 2);
    drop(engine);
    let path = dir.path().join("wal/00000000000000000001.wal");
    let mut bytes = fs::read(&path).unwrap();
    let first_len = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
    let first_magic = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let second = 16 + if first_magic == V2_MAGIC { 16 } else { 12 } + first_len;
    assert_eq!(bytes[second + 4] & 0x80, 0);
    bytes[second + 4] ^= 0x80;
    fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        PraxisEngine::open(config),
        Err(PraxisError::Corrupt { .. })
    ));
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn intact_legacy_body_proves_a_corrupted_length_in_final_or_middle_record() {
    for has_suffix in [false, true] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy.wal");
        let mut bytes = file_header();
        bytes.extend(frame(&payload(1), false));
        let mut corrupt = frame(&payload(2), false);
        corrupt[4] ^= 0x80;
        bytes.extend(corrupt);
        if has_suffix {
            bytes.extend(frame(&payload(3), false));
        }
        fs::write(&path, bytes).unwrap();
        assert_corrupt_without_modifying(&path);
    }
}

#[test]
fn strict_decoder_rejects_outer_and_inner_trailing_bytes_and_wrong_counts() {
    for v2 in [false, true] {
        let mut outer = frame(&payload(1), v2);
        outer.push(0xaa);
        assert!(WalRecord::decode(&outer, "outer-trailing").is_err());
        let mut inner = payload(1);
        inner.push(0xaa);
        assert!(WalRecord::decode(&frame(&inner, v2), "inner-trailing").is_err());
        let mut wrong_count = payload(1);
        wrong_count[8..12].copy_from_slice(&0_u32.to_le_bytes());
        assert!(WalRecord::decode(&frame(&wrong_count, v2), "wrong-count").is_err());
    }
}

#[test]
fn strict_decoder_rejects_invalid_utf8_and_unknown_operation_tags() {
    for v2 in [false, true] {
        let mut invalid_cf = payload(1);
        invalid_cf[17] = 0xff;
        assert!(WalRecord::decode(&frame(&invalid_cf, v2), "invalid-utf8").is_err());
        let mut invalid_tag = payload(1);
        invalid_tag[12] = 99;
        assert!(WalRecord::decode(&frame(&invalid_tag, v2), "unknown-tag").is_err());
    }
}

#[test]
fn short_input_does_not_allocate_from_untrusted_inner_lengths() {
    let mut body = payload(1);
    body[13..17].copy_from_slice(&4096_u32.to_le_bytes());
    let bytes = frame(&body, false);
    PEAK.set(Some(0));
    let result = WalRecord::decode(&bytes, "short-field");
    let peak = PEAK.replace(None).unwrap();
    assert!(result.is_err());
    assert!(peak < 1024, "46-byte input requested {peak} bytes");
}

#[test]
fn binary_reader_checks_remaining_input_before_allocating_a_field() {
    let declared = 4096_u32.to_le_bytes();
    let mut reader = BinaryReader::new(&declared, "short-reader");
    PEAK.set(Some(0));
    let result = reader.read_len_bytes();
    let peak = PEAK.replace(None).unwrap();
    assert!(result.is_err());
    assert!(peak < 1024, "four-byte input requested {peak} bytes");
}

#[test]
fn new_encoder_uses_checked_v2_layout_and_matches_fallible_sizing() {
    let expected = record(7);
    let encoded = expected.try_encode().unwrap();
    assert_eq!(encoded, frame(&payload(7), true));
    assert_eq!(expected.try_encoded_len().unwrap(), encoded.len());
    assert_eq!(expected.encoded_len(), encoded.len());
    assert_eq!(expected.encode(), encoded);
}

#[test]
fn v2_payload_limit_is_checked_before_missing_bytes_are_called_torn() {
    for len in [0, 11, 64 * 1024 * 1024 + 1, u32::MAX] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad-length.wal");
        let mut header = V2_MAGIC.to_le_bytes().to_vec();
        header.extend_from_slice(&len.to_le_bytes());
        header.extend_from_slice(&0_u32.to_le_bytes());
        header.extend_from_slice(&crc32c(&header).to_le_bytes());
        let mut bytes = file_header();
        bytes.extend(header);
        fs::write(&path, bytes).unwrap();
        assert_corrupt_without_modifying(&path);
    }
}

#[test]
fn impossible_operation_count_is_rejected_without_allocating_a_batch() {
    for v2 in [false, true] {
        let mut bytes = payload(1);
        bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        let encoded = frame(&bytes, v2);
        PEAK.set(Some(0));
        let result = WalRecord::decode(&encoded, "impossible-count");
        let peak = PEAK.replace(None).unwrap();
        assert!(result.is_err());
        assert!(peak < 1024);
    }
}

#[test]
fn truncate_then_append_keeps_headerless_current_records_readable() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("truncate.wal");
    let mut wal = Wal::open(&path, 1, WalSyncPolicy::EveryBatch).unwrap();
    wal.append(&record(1)).unwrap();
    wal.truncate().unwrap();
    wal.append(&record(2)).unwrap();
    drop(wal);
    assert_eq!(Wal::replay(&path).unwrap(), vec![record(2)]);
    let mut wal = Wal::open(&path, 1, WalSyncPolicy::EveryBatch).unwrap();
    wal.append(&record(3)).unwrap();
    drop(wal);
    assert_eq!(Wal::replay(&path).unwrap(), vec![record(2), record(3)]);
}

#[test]
fn incomplete_legacy_large_claim_remains_repairable_without_large_allocations() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("large-legacy-claim.wal");
    let mut bytes = V1_MAGIC.to_le_bytes().to_vec();
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&[1, 0, 0]);
    fs::write(&path, bytes).unwrap();
    assert!(Wal::replay(&path).unwrap().is_empty());
    let mut wal = Wal::open(&path, 1, WalSyncPolicy::EveryBatch).unwrap();
    wal.append(&record(1)).unwrap();
    drop(wal);
    assert_eq!(Wal::replay(&path).unwrap(), vec![record(1)]);
}

#[test]
fn first_headerless_record_can_be_torn_at_any_byte_before_reopen_append() {
    for v2 in [false, true] {
        let full = frame(&payload(1), v2);
        for cut in 0..full.len() {
            let dir = tempdir().unwrap();
            let path = dir.path().join("first-torn.wal");
            fs::write(&path, &full[..cut]).unwrap();
            assert!(Wal::replay(&path).unwrap().is_empty());
            let mut wal = Wal::open(&path, 1, WalSyncPolicy::EveryBatch).unwrap();
            wal.append(&record(1)).unwrap();
            drop(wal);
            assert_eq!(Wal::replay(&path).unwrap(), vec![record(1)]);
        }
    }
}

#[test]
fn explicit_v1_and_v2_records_roundtrip_empty_and_nonempty_batches() {
    for v2 in [false, true] {
        assert_eq!(
            WalRecord::decode(&frame(&payload(7), v2), "fixture").unwrap(),
            record(7)
        );
        let mut empty = 9_u64.to_le_bytes().to_vec();
        empty.extend_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            WalRecord::decode(&frame(&empty, v2), "empty").unwrap(),
            WalRecord {
                sequence: 9,
                batch: WriteBatch::new()
            }
        );
    }
}

#[test]
fn all_v1_and_v2_torn_cuts_repair_before_append_and_second_reopen() {
    for v2 in [false, true] {
        let torn = frame(&payload(2), v2);
        for headerless in [false, true] {
            for cut in 0..torn.len() {
                let dir = tempdir().unwrap();
                let path = dir.path().join("tail.wal");
                let mut bytes = if headerless {
                    Vec::new()
                } else {
                    file_header()
                };
                bytes.extend(frame(&payload(1), false));
                let prefix_len = bytes.len();
                bytes.extend_from_slice(&torn[..cut]);
                fs::write(&path, bytes).unwrap();
                assert_eq!(
                    Wal::replay(&path).unwrap(),
                    vec![record(1)],
                    "v2={v2}, headerless={headerless}, cut={cut}"
                );
                let mut wal = Wal::open(&path, 1, WalSyncPolicy::EveryBatch).unwrap();
                assert_eq!(fs::metadata(&path).unwrap().len() as usize, prefix_len);
                wal.append(&record(2)).unwrap();
                drop(wal);
                let wal = Wal::open(&path, 1, WalSyncPolicy::EveryBatch).unwrap();
                drop(wal);
                assert_eq!(Wal::replay(&path).unwrap(), vec![record(1), record(2)]);
            }
        }
    }
}

#[test]
fn mixed_versions_and_headerless_v2_keep_order_when_appending() {
    for headerless in [false, true] {
        for first_v2 in [false, true] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("mixed.wal");
            let mut bytes = if headerless {
                Vec::new()
            } else {
                file_header()
            };
            bytes.extend(frame(&payload(1), first_v2));
            bytes.extend(frame(&payload(2), !first_v2));
            fs::write(&path, bytes).unwrap();
            let mut wal = Wal::open(&path, 1, WalSyncPolicy::EveryBatch).unwrap();
            wal.append(&record(3)).unwrap();
            drop(wal);
            assert_eq!(
                Wal::replay(&path).unwrap(),
                vec![record(1), record(2), record(3)]
            );
        }
    }
}

#[test]
fn every_v2_header_byte_is_checked_before_torn_tail_classification() {
    for index in 0..16 {
        for has_suffix in [false, true] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("header.wal");
            let mut bytes = file_header();
            bytes.extend(frame(&payload(1), false));
            let mut corrupt = frame(&payload(2), true);
            corrupt[index] ^= 0x80;
            bytes.extend(corrupt);
            if has_suffix {
                bytes.extend(frame(&payload(3), true));
            }
            fs::write(&path, bytes).unwrap();
            assert_corrupt_without_modifying(&path);
        }
    }
}

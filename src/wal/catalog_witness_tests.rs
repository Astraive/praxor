use super::catalog_witness::{
    WalCut, recheck_v4_wals, scan_v4_wals, set_recheck_final_open_hook,
    set_scan_before_first_open_hook, set_second_pass_hook,
};
use super::record::{CoreWalRecord, WalRecord};
use crate::errors::PraxisError;
use crate::io::crc32c;
use crate::transactions::WriteBatch;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::fs::{self, File};
use std::io::{Read, Write};

#[derive(Clone, Copy, Default)]
struct AllocationStats {
    live: usize,
    peak: usize,
    max_request: usize,
}

thread_local! {
    static ALLOCATION_STATS: Cell<Option<AllocationStats>> = const { Cell::new(None) };
}

fn track_allocation(old: usize, new: usize) {
    let _ = ALLOCATION_STATS.try_with(|cell| {
        if let Some(mut stats) = cell.get() {
            stats.live = stats.live.saturating_sub(old).saturating_add(new);
            stats.peak = stats.peak.max(stats.live);
            stats.max_request = stats.max_request.max(new);
            cell.set(Some(stats));
        }
    });
}

struct WitnessTestAllocator;
unsafe impl GlobalAlloc for WitnessTestAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            track_allocation(0, layout.size());
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            track_allocation(0, layout.size());
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        track_allocation(layout.size(), 0);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, size) };
        if !new_ptr.is_null() {
            track_allocation(layout.size(), size);
        }
        new_ptr
    }
}

#[global_allocator]
static WITNESS_TEST_ALLOCATOR: WitnessTestAllocator = WitnessTestAllocator;

fn measure<T>(body: impl FnOnce() -> T) -> (T, AllocationStats) {
    ALLOCATION_STATS.with(|cell| cell.set(Some(AllocationStats::default())));
    let result = body();
    let stats = ALLOCATION_STATS.with(|cell| cell.replace(None).unwrap());
    (result, stats)
}

const BOOTSTRAP: &[u8; 563] = include_bytes!("../../tests/fixtures/catalog_tag6_bootstrap_s1.bin");
const CREATE: &[u8; 424] = include_bytes!("../../tests/fixtures/catalog_tag7_create_s2.bin");

fn header(id: u64) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&0x5457_4146u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    bytes[8..].copy_from_slice(&id.to_le_bytes());
    bytes
}

fn cut(flushed_wal_id: u64, active_wal_id: u64, next_wal_id: u64) -> WalCut {
    WalCut {
        flushed_sequence: 0,
        last_sequence: 1,
        flushed_wal_id,
        active_wal_id,
        next_wal_id,
    }
}

fn path(root: &std::path::Path, id: u64) -> std::path::PathBuf {
    root.join("wal").join(format!("{id:020}.wal"))
}

fn write(root: &std::path::Path, id: u64, body: &[u8]) -> Vec<u8> {
    let bytes = [header(id).as_slice(), body].concat();
    fs::write(path(root, id), &bytes).unwrap();
    bytes
}

fn empty(sequence: u64) -> Vec<u8> {
    WalRecord {
        sequence,
        batch: WriteBatch::new(),
    }
    .encode()
}

fn v2_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = 0x5457_4132u32.to_le_bytes().to_vec();
    frame.extend((payload.len() as u32).to_le_bytes());
    frame.extend(crc32c(payload).to_le_bytes());
    frame.extend(crc32c(&frame[..12]).to_le_bytes());
    frame.extend(payload);
    frame
}

#[test]
fn literal_bootstrap_yields_read_only_full_and_prefix_witness() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let path = root.path().join("wal/00000000000000000001.wal");
    let bytes = [header(1).as_slice(), BOOTSTRAP].concat();
    fs::write(&path, &bytes).unwrap();
    let mut visited = Vec::new();
    let witness = scan_v4_wals(root.path(), cut(0, 1, 2), |id, start, end, record| {
        visited.push((
            id,
            start,
            end,
            record.sequence(),
            matches!(record, CoreWalRecord::Catalog { .. }),
        ));
        Ok(())
    })
    .unwrap();
    assert_eq!(visited, vec![(1, 16, 579, 1, true)]);
    assert_eq!(witness.len(), 1);
    assert_eq!(witness[0].id, 1);
    assert_eq!(witness[0].full_len, 579);
    assert_eq!(witness[0].prefix_len, 579);
    assert_eq!(witness[0].full_digest, blake3::hash(&bytes));
    assert_eq!(witness[0].prefix_digest, blake3::hash(&bytes));
    assert!(witness[0].torn_start.is_none());
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn forged_huge_wal_cut_refuses_without_enumerating_claimed_range() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let path = root.path().join("wal/00000000000000000001.wal");
    fs::write(&path, [header(1).as_slice(), BOOTSTRAP].concat()).unwrap();
    // Counter ordering is valid: a range loop would attempt almost 2^64 IDs.
    let result = scan_v4_wals(root.path(), cut(0, u64::MAX - 1, u64::MAX), |_, _, _, _| {
        Ok(())
    });
    assert!(result.is_err());
}

#[test]
fn empty_user_frame_at_eof_is_valid() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let frame = WalRecord {
        sequence: 1,
        batch: WriteBatch::new(),
    }
    .encode();
    assert_eq!(frame.len(), 28);
    fs::write(
        root.path().join("wal/00000000000000000001.wal"),
        [header(1).as_slice(), frame.as_slice()].concat(),
    )
    .unwrap();
    let observed = scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).unwrap();
    assert_eq!(observed[0].record_count, 1);
}

#[test]
fn empty_user_frame_before_catalog_frame_is_valid() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let frame = WalRecord {
        sequence: 0,
        batch: WriteBatch::new(),
    }
    .encode();
    let bytes = [header(1).as_slice(), frame.as_slice(), BOOTSTRAP.as_slice()].concat();
    fs::write(root.path().join("wal/00000000000000000001.wal"), bytes).unwrap();
    let mut spans = Vec::new();
    let observed = scan_v4_wals(root.path(), cut(0, 1, 2), |_, start, end, _| {
        spans.push((start, end));
        Ok(())
    })
    .unwrap();
    assert_eq!(spans, vec![(16, 44), (44, 607)]);
    assert_eq!(observed[0].record_count, 2);
}

#[test]
fn two_literal_controls_include_complete_frame_above_last_sequence() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let first = write(root.path(), 1, BOOTSTRAP);
    let second = write(root.path(), 2, CREATE);
    let mut control_tags = Vec::new();
    let proofs = scan_v4_wals(root.path(), cut(0, 2, 3), |id, start, end, record| {
        if let CoreWalRecord::Catalog { control, .. } = record {
            control_tags.push((id, start, end, control.tag()));
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(control_tags, vec![(1, 16, 579, 6), (2, 16, 440, 7)]);
    assert_eq!(
        (proofs[0].catalog_bootstraps, proofs[0].catalog_creates),
        (1, 0)
    );
    assert_eq!(
        (proofs[1].catalog_bootstraps, proofs[1].catalog_creates),
        (0, 1)
    );
    assert_eq!(proofs[1].last_sequence, Some(2));
    assert_eq!(proofs[0].full_digest, blake3::hash(&first));
    assert_eq!(proofs[1].full_digest, blake3::hash(&second));
    recheck_v4_wals(root.path(), cut(0, 2, 3), &proofs).unwrap();
}

#[test]
fn sparse_retired_files_are_visited_but_required_gap_is_rejected_before_visit() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    write(root.path(), 1, BOOTSTRAP);
    write(root.path(), 3, &[]);
    let positive = WalCut {
        flushed_sequence: 2,
        last_sequence: 2,
        flushed_wal_id: 2,
        active_wal_id: 3,
        next_wal_id: 4,
    };
    let mut count = 0;
    let proofs = scan_v4_wals(root.path(), positive, |_, _, _, _| {
        count += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(count, 1);
    assert_eq!(proofs.len(), 2);
    assert_eq!(proofs[1].full_len, 16);
    let negative = WalCut {
        flushed_wal_id: 1,
        ..positive
    };
    let mut count = 0;
    assert!(
        scan_v4_wals(root.path(), negative, |_, _, _, _| {
            count += 1;
            Ok(())
        })
        .is_err()
    );
    assert_eq!(count, 0);
}

#[test]
fn active_torn_tail_retains_full_and_accepted_prefix_bytes() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let tail = &empty(2)[..9];
    let body = [BOOTSTRAP.as_slice(), tail].concat();
    let bytes = write(root.path(), 1, &body);
    let proofs = scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).unwrap();
    assert_eq!(proofs[0].torn_start, Some(579));
    assert_eq!(proofs[0].prefix_len, 579);
    assert_eq!(proofs[0].full_len, 588);
    assert_eq!(proofs[0].prefix_digest, blake3::hash(&bytes[..579]));
    assert_eq!(proofs[0].full_digest, blake3::hash(&bytes));
    recheck_v4_wals(root.path(), cut(0, 1, 2), &proofs).unwrap();
    let mut changed = bytes.clone();
    *changed.last_mut().unwrap() ^= 1;
    fs::write(path(root.path(), 1), changed).unwrap();
    assert!(recheck_v4_wals(root.path(), cut(0, 1, 2), &proofs).is_err());
    fs::write(path(root.path(), 1), &bytes).unwrap();
    fs::write(path(root.path(), 2), [header(2).as_slice(), tail].concat()).unwrap();
    assert!(scan_v4_wals(root.path(), cut(0, 2, 3), |_, _, _, _| Ok(())).is_err());
}

#[test]
fn v4_rejects_legacy_shape_bad_header_and_complete_bad_crc() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let good = empty(1);
    let mut v1 = 0x5457_414cu32.to_le_bytes().to_vec();
    v1.extend_from_slice(&good[4..12]);
    v1.extend_from_slice(&good[16..]);
    for body in [v1, {
        let mut bad = good.clone();
        bad[16] ^= 1;
        bad
    }] {
        write(root.path(), 1, &body);
        assert!(scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).is_err());
    }
    fs::write(path(root.path(), 1), &good).unwrap(); // headerless
    assert!(scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).is_err());
    fs::write(path(root.path(), 1), &header(1)[..8]).unwrap(); // partial header
    assert!(scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).is_err());
    fs::write(path(root.path(), 1), header(2)).unwrap(); // wrong embedded id
    assert!(scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).is_err());
    fs::remove_file(path(root.path(), 1)).unwrap();
    fs::write(root.path().join("wal/1.wal"), header(1)).unwrap();
    assert!(scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).is_err());
}

fn boundary_catalog_frame(total_len: usize) -> Vec<u8> {
    // Retain the authenticated PCB1 control, add one ordinary Put.
    let mut payload = 1u64.to_le_bytes().to_vec();
    payload.extend(2u32.to_le_bytes());
    payload.push(6);
    payload.extend(120u32.to_le_bytes());
    payload.extend(&BOOTSTRAP[33..153]);
    payload.push(1);
    payload.extend(1u32.to_le_bytes());
    payload.push(b'x');
    payload.extend(1u32.to_le_bytes());
    payload.push(b'k');
    let value_len = total_len - 168;
    payload.extend((value_len as u32).to_le_bytes());
    payload.resize(payload.len() + value_len, b'v');
    let mut frame = 0x5457_4132u32.to_le_bytes().to_vec();
    frame.extend((payload.len() as u32).to_le_bytes());
    frame.extend(crc32c(&payload).to_le_bytes());
    frame.extend(crc32c(&frame[..12]).to_le_bytes());
    frame.extend(payload);
    assert_eq!(frame.len(), total_len);
    frame
}

#[test]
fn exact_catalog_cap_accepts_and_overcap_reports_checksum_before_limit() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let exact = boundary_catalog_frame(1_048_576);
    write(root.path(), 1, &exact);
    let proofs = scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).unwrap();
    assert_eq!(proofs[0].catalog_bootstraps, 1);
    let mut frame = boundary_catalog_frame(1_048_577);
    assert_eq!(frame.len(), 1_048_577);
    write(root.path(), 1, &frame);
    let error = scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).unwrap_err();
    assert!(error.to_string().contains("1 MiB limit"), "{error}");
    frame[100] ^= 1;
    write(root.path(), 1, &frame);
    let error = scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).unwrap_err();
    assert!(error.to_string().contains("checksum"), "{error}");
}

#[test]
fn authenticated_global_overlimit_refuses_even_on_active_short_body() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let mut frame = 0x5457_4132u32.to_le_bytes().to_vec();
    frame.extend((64 * 1024 * 1024 + 1u32).to_le_bytes());
    frame.extend(0u32.to_le_bytes());
    frame.extend(crc32c(&frame[..12]).to_le_bytes());
    write(root.path(), 1, &frame);
    let error = scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).unwrap_err();
    assert!(
        error.to_string().contains("invalid v2 WAL payload length"),
        "{error}"
    );
}

fn large_user_header(payload_len: usize) -> ([u8; 16], Vec<u8>, usize) {
    let mut prefix = 1u64.to_le_bytes().to_vec();
    prefix.extend(1u32.to_le_bytes());
    prefix.push(1); // Put
    prefix.extend(7u32.to_le_bytes());
    prefix.extend(b"default");
    prefix.extend(1u32.to_le_bytes());
    prefix.push(b'k');
    let value_len = payload_len - prefix.len() - 4;
    prefix.extend((value_len as u32).to_le_bytes());
    let mut crc = crc32fast::Hasher::new();
    crc.update(&prefix);
    let block = [b'v'; 64 * 1024];
    let mut left = value_len;
    while left != 0 {
        let count = left.min(block.len());
        crc.update(&block[..count]);
        left -= count;
    }
    let mut header = [0; 16];
    header[..4].copy_from_slice(&0x5457_4132u32.to_le_bytes());
    header[4..8].copy_from_slice(&(payload_len as u32).to_le_bytes());
    header[8..12].copy_from_slice(&crc.finalize().to_le_bytes());
    let header_crc = crc32c(&header[..12]);
    header[12..16].copy_from_slice(&header_crc.to_le_bytes());
    (header, prefix, value_len)
}

#[test]
fn physically_complete_over_global_limit_refuses_before_large_reserve() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let payload_len = 64 * 1024 * 1024 + 1;
    let (record_header, prefix, mut left) = large_user_header(payload_len);
    let wal = path(root.path(), 1);
    let mut file = File::create(&wal).unwrap();
    file.write_all(&header(1)).unwrap();
    file.write_all(&record_header).unwrap();
    file.write_all(&prefix).unwrap();
    let block = [b'v'; 64 * 1024];
    while left != 0 {
        let count = left.min(block.len());
        file.write_all(&block[..count]).unwrap();
        left -= count;
    }
    drop(file);
    assert_eq!(fs::metadata(&wal).unwrap().len(), 32 + payload_len as u64);
    let mut callbacks = 0;
    let (error, stats) = measure(|| {
        scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err()
    });
    assert!(
        error.to_string().contains("invalid v2 WAL payload length"),
        "{error}"
    );
    assert_eq!(callbacks, 0);
    assert!(
        stats.max_request < 1024 * 1024,
        "largest {}",
        stats.max_request
    );
    assert!(stats.peak < 4 * 1024 * 1024, "peak {}", stats.peak);
}

#[test]
fn near_limit_claim_with_short_body_is_active_torn_only_without_large_reserve() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let (record_header, prefix, _) = large_user_header(64 * 1024 * 1024);
    let body = [BOOTSTRAP.as_slice(), record_header.as_slice(), &prefix[..5]].concat();
    let bytes = write(root.path(), 1, &body);
    let mut callbacks = 0;
    let (proofs, stats) = measure(|| {
        scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| {
            callbacks += 1;
            Ok(())
        })
        .unwrap()
    });
    assert_eq!(callbacks, 1);
    assert_eq!(proofs[0].torn_start, Some(579));
    assert_eq!(proofs[0].prefix_len, 579);
    assert_eq!(proofs[0].full_len, bytes.len() as u64);
    assert_eq!(proofs[0].prefix_digest, blake3::hash(&bytes[..579]));
    assert_eq!(proofs[0].full_digest, blake3::hash(&bytes));
    assert!(
        stats.max_request < 1024 * 1024,
        "largest {}",
        stats.max_request
    );
    assert!(stats.peak < 4 * 1024 * 1024, "peak {}", stats.peak);
    assert_eq!(fs::read(path(root.path(), 1)).unwrap(), bytes);
    write(root.path(), 2, &[]);
    assert!(scan_v4_wals(root.path(), cut(0, 2, 3), |_, _, _, _| Ok(())).is_err());
    assert_eq!(fs::read(path(root.path(), 1)).unwrap(), bytes);
}

#[test]
fn between_pass_rewrite_refuses_but_postscan_rewrite_needs_recheck() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let original = write(root.path(), 1, &empty(1));
    let target = path(root.path(), 1);
    let mut replacement = original.clone();
    replacement[16 + 16] ^= 1; // payload sequence first byte
    let payload_crc = crc32c(&replacement[32..]);
    replacement[24..28].copy_from_slice(&payload_crc.to_le_bytes());
    let header_crc = crc32c(&replacement[16..28]);
    replacement[28..32].copy_from_slice(&header_crc.to_le_bytes());
    let rewritten = replacement.clone();
    let alias = root.path().join("ephemeral-hardlink");
    set_second_pass_hook(move || {
        fs::hard_link(&target, &alias).unwrap();
        fs::write(&alias, rewritten).unwrap();
        fs::remove_file(&alias).unwrap();
    });
    let mut visited = 0;
    assert!(
        scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| {
            visited += 1;
            Ok(())
        })
        .is_err()
    );
    assert_eq!(visited, 1); // callbacks are provisional
    assert_eq!(fs::read(path(root.path(), 1)).unwrap(), replacement);
    fs::write(path(root.path(), 1), &original).unwrap();
    let proofs = scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).unwrap();
    fs::write(path(root.path(), 1), replacement).unwrap();
    assert!(recheck_v4_wals(root.path(), cut(0, 1, 2), &proofs).is_err());
}

#[test]
fn recheck_binds_cut_and_physical_identity() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let original = write(root.path(), 1, &empty(1));
    let proofs = scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).unwrap();
    let changed_cut = WalCut {
        last_sequence: 2,
        ..cut(0, 1, 2)
    };
    assert!(recheck_v4_wals(root.path(), changed_cut, &proofs).is_err());
    let old = root.path().join("old.wal");
    fs::rename(path(root.path(), 1), &old).unwrap();
    fs::write(path(root.path(), 1), original).unwrap();
    assert!(recheck_v4_wals(root.path(), cut(0, 1, 2), &proofs).is_err());
}

#[test]
fn external_hardlink_alias_is_physical_corruption() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    write(root.path(), 1, &empty(1));
    fs::hard_link(path(root.path(), 1), root.path().join("external-alias")).unwrap();
    let error = scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).unwrap_err();
    assert!(matches!(error, PraxisError::Corrupt { .. }), "{error}");
}

#[test]
fn multi_megabyte_wal_hashes_all_bytes_without_returning_records() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let path = path(root.path(), 1);
    let mut file = File::create(&path).unwrap();
    file.write_all(&header(1)).unwrap();
    for sequence in 1..=768_u64 {
        let mut batch = WriteBatch::new();
        batch.put_default(sequence.to_le_bytes().to_vec(), vec![b'v'; 32 * 1024]);
        file.write_all(&WalRecord { sequence, batch }.encode())
            .unwrap();
    }
    drop(file);
    let mut count = 0;
    let (proofs, stats) = measure(|| {
        scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| {
            count += 1;
            Ok(())
        })
        .unwrap()
    });
    assert_eq!(count, 768);
    assert!(
        stats.max_request < 1024 * 1024,
        "max request {}",
        stats.max_request
    );
    assert!(stats.peak < 4 * 1024 * 1024, "peak {}", stats.peak);
    assert!(proofs[0].full_len > 24 * 1024 * 1024);
    let mut independent = blake3::Hasher::new();
    let mut file = File::open(&path).unwrap();
    let mut chunk = [0; 64 * 1024];
    loop {
        let read = file.read(&mut chunk).unwrap();
        if read == 0 {
            break;
        }
        independent.update(&chunk[..read]);
    }
    assert_eq!(proofs[0].full_digest, independent.finalize());
    assert_eq!(proofs[0].prefix_digest, proofs[0].full_digest);
}

#[test]
fn newly_appearing_retired_wal_invalidates_inventory_candidate() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    write(root.path(), 1, &empty(1));
    write(root.path(), 3, &empty(3));
    let cut = WalCut {
        flushed_sequence: 2,
        last_sequence: 3,
        flushed_wal_id: 2,
        active_wal_id: 3,
        next_wal_id: 4,
    };
    let new_path = path(root.path(), 2);
    set_second_pass_hook(move || fs::write(new_path, header(2)).unwrap());
    assert!(scan_v4_wals(root.path(), cut, |_, _, _, _| Ok(())).is_err());
}

#[test]
fn active_append_at_recheck_final_open_is_refused() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    write(root.path(), 1, &empty(1));
    let proofs = scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).unwrap();
    let target = path(root.path(), 1);
    set_recheck_final_open_hook(move || {
        let mut file = fs::OpenOptions::new().append(true).open(target).unwrap();
        file.write_all(b"x").unwrap();
    });
    assert!(recheck_v4_wals(root.path(), cut(0, 1, 2), &proofs).is_err());
}

#[test]
fn canonical_path_replacement_after_inventory_is_refused() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let bytes = write(root.path(), 1, &empty(1));
    let target = path(root.path(), 1);
    let old = root.path().join("former-file");
    set_scan_before_first_open_hook(move || {
        fs::rename(&target, &old).unwrap();
        fs::write(&target, bytes).unwrap();
    });
    assert!(scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).is_err());
}

#[test]
fn malformed_control_lookalikes_do_not_dispatch() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let mut count = 0;
    let mut zero_count = 1u64.to_le_bytes().to_vec();
    zero_count.extend(0u32.to_le_bytes());
    zero_count.push(6);
    zero_count.extend(0u32.to_le_bytes());
    write(root.path(), 1, &v2_frame(&zero_count));
    assert!(
        scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| {
            count += 1;
            Ok(())
        })
        .is_err()
    );
    let mut nonfirst = 1u64.to_le_bytes().to_vec();
    nonfirst.extend(2u32.to_le_bytes());
    nonfirst.push(1); // ordinary Put first
    nonfirst.extend(7u32.to_le_bytes());
    nonfirst.extend(b"default");
    nonfirst.extend(1u32.to_le_bytes());
    nonfirst.push(b'k');
    nonfirst.extend(1u32.to_le_bytes());
    nonfirst.push(b'v');
    nonfirst.push(6); // catalog control illegally second
    nonfirst.extend(120u32.to_le_bytes());
    nonfirst.extend(&BOOTSTRAP[33..153]);
    write(root.path(), 1, &v2_frame(&nonfirst));
    assert!(
        scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| {
            count += 1;
            Ok(())
        })
        .is_err()
    );
    assert_eq!(count, 0);
}

#[test]
fn near_global_limit_user_frame_stays_within_per_frame_workspace() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let mut payload_prefix = 1u64.to_le_bytes().to_vec();
    payload_prefix.extend(1u32.to_le_bytes());
    payload_prefix.push(1);
    payload_prefix.extend(7u32.to_le_bytes());
    payload_prefix.extend(b"default");
    payload_prefix.extend(1u32.to_le_bytes());
    payload_prefix.push(b'k');
    let value_len = 64 * 1024 * 1024 - (payload_prefix.len() + 4);
    payload_prefix.extend((value_len as u32).to_le_bytes());
    let mut crc = crc32fast::Hasher::new();
    crc.update(&payload_prefix);
    let chunk = [b'v'; 64 * 1024];
    let mut remaining = value_len;
    while remaining != 0 {
        let count = remaining.min(chunk.len());
        crc.update(&chunk[..count]);
        remaining -= count;
    }
    let mut frame_header = 0x5457_4132u32.to_le_bytes().to_vec();
    frame_header.extend((64u32 * 1024 * 1024).to_le_bytes());
    frame_header.extend(crc.finalize().to_le_bytes());
    frame_header.extend(crc32c(&frame_header[..12]).to_le_bytes());
    let mut file = File::create(path(root.path(), 1)).unwrap();
    file.write_all(&header(1)).unwrap();
    file.write_all(&frame_header).unwrap();
    file.write_all(&payload_prefix).unwrap();
    remaining = value_len;
    while remaining != 0 {
        let count = remaining.min(chunk.len());
        file.write_all(&chunk[..count]).unwrap();
        remaining -= count;
    }
    drop(file);
    let (proofs, stats) =
        measure(|| scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, _| Ok(())).unwrap());
    assert_eq!(proofs[0].record_count, 1);
    assert_eq!(proofs[0].full_len, 16 + 16 + 64 * 1024 * 1024);
    assert!(
        stats.max_request <= 64 * 1024 * 1024 + 16,
        "max request {}",
        stats.max_request
    );
    assert!(stats.peak < 144 * 1024 * 1024, "peak {}", stats.peak);
}

#[test]
fn dense_delete_frame_has_bounded_owned_batch_workspace() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    let operations = 800_000u32;
    let mut payload = 1u64.to_le_bytes().to_vec();
    payload.extend(operations.to_le_bytes());
    for _ in 0..operations {
        payload.push(2); // Delete with empty family and key: nine bytes.
        payload.extend(0u32.to_le_bytes());
        payload.extend(0u32.to_le_bytes());
    }
    let frame = v2_frame(&payload);
    assert!(frame.len() > 6 * 1024 * 1024);
    write(root.path(), 1, &frame);
    drop(frame);
    drop(payload);
    let mut observed_ops = 0;
    let (proofs, stats) = measure(|| {
        scan_v4_wals(root.path(), cut(0, 1, 2), |_, _, _, record| {
            observed_ops = record.batch().len();
            Ok(())
        })
        .unwrap()
    });
    assert_eq!(proofs[0].record_count, 1);
    assert_eq!(observed_ops, operations as usize);
    let batch_bytes = std::mem::size_of::<crate::transactions::BatchOp>() * operations as usize;
    assert!(
        stats.max_request <= batch_bytes.max(8 * 1024 * 1024),
        "largest {}",
        stats.max_request
    );
    assert!(
        stats.peak < batch_bytes + 32 * 1024 * 1024,
        "peak {}",
        stats.peak
    );
}

#[test]
fn relative_root_scans_and_rechecks_without_changing_cwd() {
    let cwd = std::env::current_dir().unwrap();
    let root = tempfile::tempdir_in(&cwd).unwrap();
    fs::create_dir(root.path().join("wal")).unwrap();
    write(root.path(), 1, &empty(1));
    let relative = root.path().strip_prefix(&cwd).unwrap();
    assert!(!relative.is_absolute());
    let proofs = scan_v4_wals(relative, cut(0, 1, 2), |_, _, _, _| Ok(())).unwrap();
    recheck_v4_wals(relative, cut(0, 1, 2), &proofs).unwrap();
    assert_eq!(std::env::current_dir().unwrap(), cwd);
}

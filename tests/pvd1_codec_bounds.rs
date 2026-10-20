//! Test-first PVD1 fixtures. The production module is included directly so
//! this integration test can observe allocations without adding a public API.
#[allow(dead_code)]
#[path = "../src/manifest/pvd1.rs"]
mod pvd1;

use pvd1::{Pvd1Entry, Pvd1Error, Pvd1Kind, decode_pvd1};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

const HEADER_LEN: usize = 24;
const ENTRY_LEN: usize = 45;
const MAX_ENTRIES: u64 = 131_072;
const MAX_BYTES: u64 = 8 * 1024 * 1024;

struct AllocationObserver;
thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static CALLS: Cell<usize> = const { Cell::new(0) };
}

fn allocation() {
    if TRACK.try_with(Cell::get).unwrap_or(false) {
        let _ = CALLS.try_with(|calls| calls.set(calls.get() + 1));
    }
}

unsafe impl GlobalAlloc for AllocationObserver {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocation();
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: AllocationObserver = AllocationObserver;

#[derive(Clone, Copy)]
struct WireEntry {
    node_id: [u8; 32],
    pack_id: u64,
    record_index: u32,
    kind: u8,
}

fn entry(id: u8, pack_id: u64, record_index: u32, kind: u8) -> WireEntry {
    WireEntry {
        node_id: [id; 32],
        pack_id,
        record_index,
        kind,
    }
}

// Independent reference implementation of CRC32C/Castagnoli. In particular,
// the existing crate::io::crc32c is IEEE CRC32 and cannot serve PVD1.
fn castagnoli(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

fn fixture(entries: &[WireEntry]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_LEN + ENTRY_LEN * entries.len() + 4);
    bytes.extend_from_slice(b"PVD1");
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&((ENTRY_LEN * entries.len()) as u64).to_le_bytes());
    for entry in entries {
        bytes.extend_from_slice(&entry.node_id);
        bytes.extend_from_slice(&entry.pack_id.to_le_bytes());
        bytes.extend_from_slice(&entry.record_index.to_le_bytes());
        bytes.push(entry.kind);
    }
    let crc = castagnoli(&bytes);
    bytes.extend_from_slice(&crc.to_le_bytes());
    bytes
}

fn repair_crc(bytes: &mut [u8]) {
    let payload_end = bytes.len() - 4;
    let crc = castagnoli(&bytes[..payload_end]);
    bytes[payload_end..].copy_from_slice(&crc.to_le_bytes());
}

fn advertised(count: u64, payload_len: u64) -> [u8; HEADER_LEN] {
    let mut bytes = [0_u8; HEADER_LEN];
    bytes[..4].copy_from_slice(b"PVD1");
    bytes[4..6].copy_from_slice(&1_u16.to_le_bytes());
    bytes[8..16].copy_from_slice(&count.to_le_bytes());
    bytes[16..24].copy_from_slice(&payload_len.to_le_bytes());
    bytes
}

fn assert_no_allocation_before_bound(bytes: &[u8], expected: Pvd1Error) {
    CALLS.set(0);
    TRACK.set(true);
    let decoded = decode_pvd1(bytes);
    TRACK.set(false);
    assert_eq!(CALLS.get(), 0, "untrusted header caused allocation");
    assert_eq!(decoded.unwrap_err(), expected);
}

#[test]
fn castagnoli_fixture_uses_the_correct_polynomial() {
    assert_eq!(castagnoli(b"123456789"), 0xe306_9283);
    assert_ne!(castagnoli(b"123456789"), praxis::io::crc32c(b"123456789"));
}

#[test]
fn sorted_directory_decodes_as_untrusted_and_preserves_exact_bytes() {
    let entries = [
        entry(0x11, 7, 1, 1),
        entry(0x22, 7, 2, 2),
        entry(0x33, 9, 1, 3),
    ];
    let encoded = fixture(&entries);
    assert_eq!(encoded, fixture(&entries), "fixture bytes must be stable");
    let decoded = decode_pvd1(&encoded).unwrap();
    assert_eq!(decoded.bytes(), encoded.as_slice());
    assert_eq!(
        decoded.entries(),
        &[
            Pvd1Entry {
                node_id: [0x11; 32],
                pack_id: 7,
                record_index: 1,
                kind: Pvd1Kind::Birth,
            },
            Pvd1Entry {
                node_id: [0x22; 32],
                pack_id: 7,
                record_index: 2,
                kind: Pvd1Kind::Edge,
            },
            Pvd1Entry {
                node_id: [0x33; 32],
                pack_id: 9,
                record_index: 1,
                kind: Pvd1Kind::InstallDelta,
            },
        ]
    );
}

#[test]
fn empty_directory_is_only_a_syntactic_genesis_candidate() {
    let encoded = fixture(&[]);
    let decoded = decode_pvd1(&encoded).unwrap();
    assert!(decoded.entries().is_empty());
    assert_eq!(decoded.bytes(), encoded.as_slice());
}

#[test]
fn magic_version_and_unknown_flags_are_refused() {
    let mut bytes = fixture(&[entry(0x11, 7, 1, 1)]);
    bytes[0] = b'X';
    repair_crc(&mut bytes);
    assert_eq!(decode_pvd1(&bytes).unwrap_err(), Pvd1Error::BadMagic);

    bytes[0] = b'P';
    bytes[4..6].copy_from_slice(&2_u16.to_le_bytes());
    repair_crc(&mut bytes);
    assert_eq!(
        decode_pvd1(&bytes).unwrap_err(),
        Pvd1Error::UnsupportedVersion
    );

    bytes[4..6].copy_from_slice(&1_u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&1_u16.to_le_bytes());
    repair_crc(&mut bytes);
    assert_eq!(
        decode_pvd1(&bytes).unwrap_err(),
        Pvd1Error::UnsupportedFlags
    );
}

#[test]
fn truncated_header_entry_and_trailer_and_trailing_byte_are_refused() {
    let bytes = fixture(&[entry(0x11, 7, 1, 1)]);
    assert_eq!(decode_pvd1(&bytes[..3]).unwrap_err(), Pvd1Error::Truncated);
    assert_eq!(
        decode_pvd1(&bytes[..HEADER_LEN]).unwrap_err(),
        Pvd1Error::Truncated
    );
    assert_eq!(
        decode_pvd1(&bytes[..bytes.len() - 1]).unwrap_err(),
        Pvd1Error::Truncated
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(decode_pvd1(&trailing).unwrap_err(), Pvd1Error::Trailing);
}

#[test]
fn count_arithmetic_caps_and_length_mismatch_precede_allocation() {
    assert_no_allocation_before_bound(&advertised(u64::MAX, 0), Pvd1Error::CountOverflow);
    assert_no_allocation_before_bound(&advertised(MAX_ENTRIES + 1, 0), Pvd1Error::CountLimit);
    assert_no_allocation_before_bound(&advertised(1, MAX_BYTES + 1), Pvd1Error::LengthLimit);
    assert_no_allocation_before_bound(
        &advertised(1, ENTRY_LEN as u64 - 1),
        Pvd1Error::LengthMismatch,
    );
}

#[test]
fn zero_duplicate_and_descending_node_ids_are_refused_with_valid_crc() {
    for (entries, expected) in [
        (vec![entry(0, 7, 1, 1)], Pvd1Error::ZeroNodeId),
        (
            vec![entry(1, 7, 1, 1), entry(1, 7, 2, 2)],
            Pvd1Error::DuplicateNodeId,
        ),
        (
            vec![entry(2, 7, 1, 1), entry(1, 7, 2, 2)],
            Pvd1Error::UnsortedNodeId,
        ),
    ] {
        let bytes = fixture(&entries);
        assert_eq!(decode_pvd1(&bytes).unwrap_err(), expected);
    }
}

#[test]
fn invalid_pack_record_index_and_kind_are_refused_with_valid_crc() {
    for (entry, expected) in [
        (entry(1, 0, 1, 1), Pvd1Error::ZeroPackId),
        (entry(1, 7, 0, 1), Pvd1Error::InvalidRecordIndex),
        (
            entry(1, 7, MAX_ENTRIES as u32 + 1, 1),
            Pvd1Error::InvalidRecordIndex,
        ),
        (entry(1, 7, 1, 0), Pvd1Error::UnknownKind),
        (entry(1, 7, 1, 4), Pvd1Error::UnknownKind),
    ] {
        let bytes = fixture(&[entry]);
        assert_eq!(decode_pvd1(&bytes).unwrap_err(), expected);
    }
}

#[test]
fn corrupted_payload_or_crc_is_refused_before_semantic_entry_checks() {
    let mut bytes = fixture(&[entry(0x11, 7, 1, 1)]);
    bytes[HEADER_LEN + ENTRY_LEN - 1] = 99; // Also makes kind invalid.
    assert_eq!(
        decode_pvd1(&bytes).unwrap_err(),
        Pvd1Error::ChecksumMismatch
    );

    let mut bytes = fixture(&[entry(0x11, 7, 1, 1)]);
    let trailer = bytes.len() - 1;
    bytes[trailer] ^= 1;
    assert_eq!(
        decode_pvd1(&bytes).unwrap_err(),
        Pvd1Error::ChecksumMismatch
    );
}

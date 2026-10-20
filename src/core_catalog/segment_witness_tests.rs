use super::codec::{
    CatalogKey, CatalogValue, CollectionId, Field, Head, NamespaceId, ScalarType, Schema,
};
use super::external_value::{
    UnwitnessedRecordValue, ValuePayloadProbe, resolve_catalog_external_caps,
    resolve_catalog_head_external, resolve_record_external_caps,
};
use super::physical::inspect_v4_owner;
use super::physical_tests::flushed_create_fixture;
use super::segment_witness::{
    AuthenticatedLz4Pass, AuthenticatedZstdPass, BlockFrame, CompressedWorkFacts, Lz4PassProbe,
    ObservedSegmentRow, ObservedSegmentValue, PRODUCTION_COMPRESSED_PROOF_PROFILE,
    PROTECTED_STAGE_LIMITS, PhysicalRowClass, ProofProfile, ProtectedRole, ProtectedStage,
    ProtectedStageLimits, ScratchLedger, ScratchSlot, SegmentFileWitness, SegmentSource,
    WorkLedger, ZstdPassProbe, collect_protected_segment_candidate,
    collect_protected_segment_candidate_for_test, decode_bounded_block, inventory_count_for_test,
    next_observed_file, physical_id, scan_lz4_pass1, scan_lz4_pass2, scan_lz4_pass3,
    scan_zstd_pass1, scan_zstd_pass2, scan_zstd_pass3, visit_v4_segments,
    visit_v4_segments_with_profile_and_hook_for_test,
    visit_v4_segments_with_profile_and_tag_hook_for_test,
};
use crate::accel::cpu::scalar::CpuAccelerator;
use crate::config::{Compression, PraxisConfig};
use crate::disk::DiskLayout;
use crate::errors::PraxisError;
use crate::io::{BinaryReader, BinaryWriter, crc32c, decode_block};
use crate::manifest::{Manifest, ManifestStore, SegmentMetadata};
use crate::segments::block::SegmentEntry;
use crate::segments::codec::{decode_entries, decode_segment, encode_entries};
use crate::segments::{BloomFilter, SegmentWriteOptions, SegmentWriter};
use crate::types::{ColumnFamily, StoredValue, ValuePointer, VersionedValue};
use crate::values::ValueLog;
use crate::wal::catalog_witness::{
    PhysicalWitnessBudget, WalCut, scan_v4_wals_with_budget, vector_charge,
};
use crate::wal::record::MAX_WAL_PAYLOAD_BYTES;
use crate::writer_lease::{LOCK_FILE_NAME, WriterLease};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zstd::zstd_safe::zstd_sys as zstd_ffi;

const CATALOG_CF: &str = "__praxor_record_catalog_v1";

// Private test-first contract for full-file and per-extent value witnesses.
// The public installed owner remains fenced while #81 is incomplete.
mod value_file_witness_red;

// Private same-(CF,key,S) copy ledger tests; no public owner is granted.
mod physical_copy_ledger_red;

// Adversarial selected-row replay coverage for the narrow LZ4 Catalog Head.
mod lz4_head_replay_adversarial;

fn row(key: u8, value: StoredValue) -> SegmentEntry {
    SegmentEntry {
        cf: ColumnFamily(CATALOG_CF.into()),
        key: vec![key].into(),
        version: VersionedValue { sequence: 2, value },
    }
}

fn row_in(cf: &str, key: &[u8], sequence: u64, value: StoredValue) -> SegmentEntry {
    SegmentEntry {
        cf: ColumnFamily(cf.into()),
        key: key.to_vec().into(),
        version: VersionedValue { sequence, value },
    }
}

fn two_segments(
    compression: Compression,
    reverse_manifest_order: bool,
) -> (
    tempfile::TempDir,
    PraxisConfig,
    WriterLease,
    [SegmentMetadata; 2],
) {
    let (dir, config, lease) = flushed_create_fixture();
    let layout = DiskLayout::at(lease.root());
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let value_path = layout.value_log_path(1);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let common = row(0, StoredValue::Put(vec![0xca, 0xfe]));
    let first = SegmentWriter::write(
        SegmentWriteOptions {
            path: &layout.segment_path(0, 1),
            id: 1,
            level: 0,
            compression,
            accelerator: &CpuAccelerator,
            value_log: &mut value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: 1,
            partitioned_bloom: None,
            direct_io: false,
        },
        vec![common.clone(), row(1, StoredValue::Delete)],
    )
    .unwrap();
    let second = SegmentWriter::write(
        SegmentWriteOptions {
            path: &layout.segment_path(1, 2),
            id: 2,
            level: 1,
            compression,
            accelerator: &CpuAccelerator,
            value_log: &mut value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: 1,
            partitioned_bloom: None,
            direct_io: false,
        },
        vec![common, row(2, StoredValue::Merge(vec![0x22]))],
    )
    .unwrap();
    drop(value_log);
    fs::remove_file(value_path).unwrap();
    manifest.segments = if reverse_manifest_order {
        vec![second.clone(), first.clone()]
    } else {
        vec![first.clone(), second.clone()]
    };
    manifest.next_segment_id = 3;
    ManifestStore::new(manifest_path).save(&manifest).unwrap();
    (dir, config, lease, [first, second])
}

fn two_literal_segments(
    reverse_manifest_order: bool,
) -> (
    tempfile::TempDir,
    PraxisConfig,
    WriterLease,
    [SegmentMetadata; 2],
) {
    two_segments(Compression::None, reverse_manifest_order)
}

fn mixed_literal_lz4_segments(
    literal_first: bool,
) -> (tempfile::TempDir, PraxisConfig, WriterLease, Manifest) {
    let initial = if literal_first {
        Compression::Lz4
    } else {
        Compression::None
    };
    let (dir, config, lease, _) = two_segments(initial, false);
    let first = if literal_first {
        Compression::None
    } else {
        Compression::Lz4
    };
    let manifest = rewrite_first_segment(
        lease.root(),
        vec![
            row(0, StoredValue::Put(vec![0xca, 0xfe])),
            row(1, StoredValue::Delete),
        ],
        first,
        config.large_value_threshold,
        1,
    );
    (dir, config, lease, manifest)
}

#[derive(Debug, Eq, PartialEq)]
struct TreeEntry {
    is_dir: bool,
    bytes: Option<Vec<u8>>,
    file_id: Option<Vec<u8>>,
    alias_target: Option<PathBuf>,
}

#[cfg(windows)]
fn file_id(path: &Path) -> Vec<u8> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };

    let file = File::open(path).unwrap();
    let mut info = FILE_ID_INFO::default();
    assert_ne!(
        unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&raw mut info).cast(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        },
        0
    );
    let mut id = info.VolumeSerialNumber.to_le_bytes().to_vec();
    id.extend_from_slice(&info.FileId.Identifier);
    id
}

#[cfg(unix)]
fn file_id(path: &Path) -> Vec<u8> {
    use std::os::unix::fs::MetadataExt;

    let meta = File::open(path).unwrap().metadata().unwrap();
    let mut id = meta.dev().to_le_bytes().to_vec();
    id.extend_from_slice(&meta.ino().to_le_bytes());
    id
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, TreeEntry> {
    fn walk(root: &Path, at: &Path, out: &mut BTreeMap<PathBuf, TreeEntry>) {
        for entry in fs::read_dir(at).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let meta = fs::symlink_metadata(&path).unwrap();
            #[cfg(windows)]
            let alias = {
                use std::os::windows::fs::MetadataExt;
                meta.file_attributes() & 0x400 != 0
            };
            #[cfg(not(windows))]
            let alias = meta.file_type().is_symlink();
            if alias {
                out.insert(
                    relative,
                    TreeEntry {
                        is_dir: false,
                        bytes: None,
                        file_id: None,
                        alias_target: Some(fs::read_link(&path).unwrap()),
                    },
                );
            } else if meta.is_dir() {
                out.insert(
                    relative,
                    TreeEntry {
                        is_dir: true,
                        bytes: None,
                        file_id: None,
                        alias_target: None,
                    },
                );
                walk(root, &path, out);
            } else {
                assert!(meta.is_file());
                let lock = relative == Path::new(LOCK_FILE_NAME);
                if lock {
                    assert_eq!(meta.len(), 0);
                }
                out.insert(
                    relative,
                    TreeEntry {
                        is_dir: false,
                        // The held writer lock cannot be reopened on Windows.
                        bytes: Some(if lock {
                            Vec::new()
                        } else {
                            fs::read(&path).unwrap()
                        }),
                        file_id: if lock { None } else { Some(file_id(&path)) },
                        alias_target: None,
                    },
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn two_block_offsets(path: &Path) -> [u64; 2] {
    let bytes = fs::read(path).unwrap();
    let parsed = decode_segment(&bytes, path, &CpuAccelerator).unwrap();
    assert_eq!(parsed.blocks.len(), 2);
    assert!(parsed.blocks.iter().all(|block| block.len() == 1));
    let first_len = u32::from_le_bytes(bytes[21..25].try_into().unwrap()) as u64;
    [21, 21 + 12 + first_len]
}

fn writer_block_frame(bytes: &[u8], offset: u64) -> (&[u8], u64, u32) {
    let start = usize::try_from(offset).unwrap();
    let encoded_len = u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap()) as usize;
    let decoded_len = u32::from_le_bytes(bytes[start + 4..start + 8].try_into().unwrap());
    let checksum = u32::from_le_bytes(bytes[start + 8..start + 12].try_into().unwrap());
    let end = start.checked_add(12 + encoded_len).unwrap();
    assert!(end <= bytes.len());
    (&bytes[start + 12..end], u64::from(decoded_len), checksum)
}

fn parsed_zstd_header(frame: &[u8]) -> zstd_ffi::ZSTD_FrameHeader {
    let mut header = std::mem::MaybeUninit::<zstd_ffi::ZSTD_FrameHeader>::uninit();
    // The pinned Zstd ABI initializes every header field only on a zero return.
    let status = unsafe {
        zstd_ffi::ZSTD_getFrameHeader(header.as_mut_ptr(), frame.as_ptr().cast(), frame.len())
    };
    assert_eq!(unsafe { zstd_ffi::ZSTD_isError(status) }, 0);
    assert_eq!(status, 0, "incomplete test frame header");
    unsafe { header.assume_init() }
}

fn zstd_frame_with_header(original: &[u8], replacement_header: &[u8]) -> Vec<u8> {
    let old_header_len = parsed_zstd_header(original).headerSize as usize;
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd];
    frame.extend_from_slice(replacement_header);
    frame.extend_from_slice(&original[old_header_len..]);
    let first_size =
        unsafe { zstd_ffi::ZSTD_findFrameCompressedSize(frame.as_ptr().cast(), frame.len()) };
    assert_eq!(unsafe { zstd_ffi::ZSTD_isError(first_size) }, 0);
    assert_eq!(first_size, frame.len());
    frame
}

fn direct_lz4_pass1(
    meta: &SegmentMetadata,
    work: &mut WorkLedger,
    probe: impl FnMut(Lz4PassProbe),
) -> crate::errors::Result<AuthenticatedLz4Pass> {
    let path = Path::new(&meta.path);
    let file = File::open(path).unwrap();
    let identity = physical_id(&file, path).unwrap();
    drop(file);
    scan_lz4_pass1(path, identity, meta, work, probe)
}

fn direct_zstd_pass1(
    meta: &SegmentMetadata,
    work: &mut WorkLedger,
    probe: impl FnMut(ZstdPassProbe),
) -> crate::errors::Result<AuthenticatedZstdPass> {
    let path = Path::new(&meta.path);
    let file = File::open(path).unwrap();
    let identity = physical_id(&file, path).unwrap();
    drop(file);
    scan_zstd_pass1(path, identity, meta, work, probe)
}

fn replace_lz4_footer(bytes: &[u8], footer: &[u8]) -> Vec<u8> {
    let trailer_start = bytes.len() - 12;
    let old_len =
        u32::from_le_bytes(bytes[trailer_start..trailer_start + 4].try_into().unwrap()) as usize;
    let footer_start = trailer_start - old_len;
    let mut rewritten = bytes[..footer_start].to_vec();
    rewritten.extend_from_slice(footer);
    rewritten.extend_from_slice(&(footer.len() as u32).to_le_bytes());
    rewritten.extend_from_slice(&crc32c(footer).to_le_bytes());
    rewritten.extend_from_slice(&bytes[trailer_start + 8..]);
    rewritten
}

fn same_length_lz4_value_variant(bytes: &[u8], path: &Path) -> Vec<u8> {
    let (original, decoded_len, _) = writer_block_frame(bytes, 21);
    let decoded = decode_block(Compression::Lz4, original).unwrap();
    assert_eq!(decoded.len() as u64, decoded_len);
    let original_entries = decode_entries(&decoded, path).unwrap();
    assert_eq!(original_entries.len(), 1);
    for replacement in 0_u8..=u8::MAX {
        let candidate = [replacement, replacement ^ 0x5a];
        if matches!(&original_entries[0].entry.version.value, StoredValue::Put(value) if value.as_slice() == candidate)
        {
            continue;
        }
        let mut entries = decode_entries(&decoded, path).unwrap();
        entries[0].entry.version.value = StoredValue::Put(candidate.to_vec());
        let candidate_decoded = encode_entries(&entries).unwrap();
        assert_eq!(candidate_decoded.len(), decoded.len());
        let encoded = lz4_flex::compress_prepend_size(&candidate_decoded);
        if encoded.len() != original.len() {
            continue;
        }
        let mut changed = bytes.to_vec();
        changed[29..33].copy_from_slice(&crc32c(&encoded).to_le_bytes());
        changed[33..33 + encoded.len()].copy_from_slice(&encoded);
        assert_ne!(changed, bytes);
        assert_eq!(changed.len(), bytes.len());
        assert_eq!(
            &changed[33 + encoded.len()..],
            &bytes[33 + original.len()..]
        );
        let decoded_changed = decode_segment(&changed, path, &CpuAccelerator).unwrap();
        assert_eq!(decoded_changed.blocks.len(), 2);
        assert_eq!(
            decoded_changed.blocks[0][0].entry.version.value,
            StoredValue::Put(candidate.to_vec())
        );
        return changed;
    }
    panic!("no same-length, independently decodable LZ4 value variant");
}

fn same_length_zstd_value_variant(bytes: &[u8], path: &Path) -> Vec<u8> {
    let (original, decoded_len, _) = writer_block_frame(bytes, 21);
    let decoded = decode_block(Compression::Zstd, original).unwrap();
    assert_eq!(decoded.len() as u64, decoded_len);
    let original_entries = decode_entries(&decoded, path).unwrap();
    assert_eq!(original_entries.len(), 1);
    for replacement in 0_u8..=u8::MAX {
        let candidate = [replacement, replacement ^ 0x5a];
        if matches!(&original_entries[0].entry.version.value, StoredValue::Put(value) if value.as_slice() == candidate)
        {
            continue;
        }
        let mut entries = decode_entries(&decoded, path).unwrap();
        entries[0].entry.version.value = StoredValue::Put(candidate.to_vec());
        let candidate_decoded = encode_entries(&entries).unwrap();
        assert_eq!(candidate_decoded.len(), decoded.len());
        let encoded = zstd::bulk::compress(&candidate_decoded, 3).unwrap();
        if encoded.len() != original.len() {
            continue;
        }
        let mut changed = bytes.to_vec();
        changed[29..33].copy_from_slice(&crc32c(&encoded).to_le_bytes());
        changed[33..33 + encoded.len()].copy_from_slice(&encoded);
        assert_eq!(changed.len(), bytes.len());
        assert_ne!(changed, bytes);
        assert_eq!(
            &changed[33 + encoded.len()..],
            &bytes[33 + original.len()..]
        );
        let parsed = decode_segment(&changed, path, &CpuAccelerator).unwrap();
        assert_eq!(parsed.blocks.len(), 2);
        assert_eq!(
            parsed.blocks[0][0].entry.version.value,
            StoredValue::Put(candidate.to_vec())
        );
        return changed;
    }
    panic!("no same-length, independently decodable Zstd value variant");
}

fn expected_row(
    source: SegmentSource,
    offset: u64,
    key: u8,
    value: ObservedSegmentValue,
) -> ObservedSegmentRow {
    ObservedSegmentRow {
        source,
        block_offset: offset,
        row_ordinal: 0,
        classification: PhysicalRowClass::BoundProtected(ProtectedRole::Catalog),
        cf: CATALOG_CF.into(),
        key: vec![key],
        sequence: 2,
        value,
    }
}

fn visit_with_wal_budget(
    root: &Path,
    manifest: &Manifest,
    visit: impl FnMut(ObservedSegmentRow) -> crate::errors::Result<()>,
) -> crate::errors::Result<Vec<SegmentFileWitness>> {
    let cut = WalCut {
        flushed_sequence: manifest.flushed_sequence,
        last_sequence: manifest.last_sequence,
        flushed_wal_id: manifest.flushed_wal_id,
        active_wal_id: manifest.active_wal_id,
        next_wal_id: manifest.next_wal_id,
    };
    let (wal_witnesses, mut budget) =
        scan_v4_wals_with_budget(root, cut, |_, _, _, _| Ok(())).unwrap();
    assert_eq!(wal_witnesses.len(), 1);
    visit_v4_segments(root, manifest, &mut budget, visit)
}

fn with_wal_budget<T>(
    root: &Path,
    manifest: &Manifest,
    run: impl FnOnce(&mut PhysicalWitnessBudget) -> T,
) -> T {
    let cut = WalCut {
        flushed_sequence: manifest.flushed_sequence,
        last_sequence: manifest.last_sequence,
        flushed_wal_id: manifest.flushed_wal_id,
        active_wal_id: manifest.active_wal_id,
        next_wal_id: manifest.next_wal_id,
    };
    let (wal_witnesses, mut budget) =
        scan_v4_wals_with_budget(root, cut, |_, _, _, _| Ok(())).unwrap();
    assert_eq!(wal_witnesses.len(), 1);
    run(&mut budget)
}

fn rewrite_first_segment(
    root: &Path,
    rows: Vec<SegmentEntry>,
    compression: Compression,
    large_value_threshold: usize,
    block_size: usize,
) -> Manifest {
    let layout = DiskLayout::at(root);
    let path = layout.segment_path(0, 1);
    let value_path = layout.value_log_path(1);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let first = SegmentWriter::write(
        SegmentWriteOptions {
            path: &path,
            id: 1,
            level: 0,
            compression,
            accelerator: &CpuAccelerator,
            value_log: &mut value_log,
            large_value_threshold,
            block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        rows,
    )
    .unwrap();
    drop(value_log);
    fs::remove_file(value_path).unwrap();
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let first_meta = manifest
        .segments
        .iter_mut()
        .find(|meta| meta.id == 1)
        .unwrap();
    *first_meta = first;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap()
}

fn replace_segment_bytes(root: &Path, level: u32, id: u64, bytes: &[u8]) -> Manifest {
    let layout = DiskLayout::at(root);
    let path = layout.segment_path(level, id);
    fs::write(path, bytes).unwrap();
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    manifest
        .segments
        .iter_mut()
        .find(|meta| meta.id == id)
        .unwrap()
        .file_digest = blake3::hash(bytes).to_hex().to_string();
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap()
}

fn replace_first_segment_bytes(root: &Path, bytes: &[u8]) -> Manifest {
    replace_segment_bytes(root, 0, 1, bytes)
}

fn save_strict_manifest(root: &Path, manifest: &Manifest) -> Manifest {
    let path = DiskLayout::at(root).manifest_path();
    ManifestStore::new(path.clone()).save(manifest).unwrap();
    let saved = Manifest::decode(&fs::read(&path).unwrap(), &path).unwrap();
    assert_eq!(saved.format_version, 4);
    saved
}

fn assert_segment_corrupt_without_mutation(
    root: &Path,
    manifest: &Manifest,
    segment_path: &Path,
    expected_reason: &str,
) {
    let before = snapshot(root);
    with_wal_budget(root, manifest, |budget| {
        let wal_balance = budget.remaining_bytes();
        let mut callbacks = 0;
        let error = visit_v4_segments(root, manifest, budget, |_| {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(
            matches!(&error, PraxisError::Corrupt { path, reason }
                if path.as_path() == segment_path && reason.as_str() == expected_reason),
            "{error}"
        );
        assert_eq!(callbacks, 0);
        assert_eq!(budget.remaining_bytes(), wal_balance);
    });
    assert_eq!(snapshot(root), before);
}

#[test]
fn relative_manifest_segment_path_refuses_before_callbacks_without_mutation() {
    let (_dir, _config, lease, metadata) = two_literal_segments(false);
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let canonical_id2 = layout.segment_path(1, 2);
    let relative_id2 = PathBuf::from("segments")
        .join("1")
        .join(format!("{:020}.tseg", 2_u64));
    assert!(relative_id2.is_relative());
    assert_eq!(root.join(&relative_id2), canonical_id2);
    assert_ne!(relative_id2.to_str().unwrap(), metadata[1].path);

    let mut changed_id2 = metadata[1].clone();
    changed_id2.path = relative_id2.to_str().unwrap().to_owned();
    manifest.segments[1] = changed_id2.clone();
    let saved = save_strict_manifest(root, &manifest);
    assert_eq!(saved.segments[0], metadata[0]);
    assert_eq!(saved.segments[1], changed_id2);
    assert_segment_corrupt_without_mutation(
        root,
        &saved,
        &canonical_id2,
        "noncanonical v4 segment MANIFEST path",
    );
}

#[test]
fn external_segment_hardlink_refuses_before_callbacks_without_mutation() {
    let (_dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let id1_path = layout.segment_path(0, 1);
    let alias = root.join("external-segment-alias");
    fs::hard_link(&id1_path, &alias).unwrap();
    assert!(id1_path.is_file());
    assert!(alias.is_file());
    assert_eq!(file_id(&id1_path), file_id(&alias));

    let manifest_path = layout.manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_segment_corrupt_without_mutation(
        root,
        &manifest,
        &id1_path,
        "v4 segment has an external hardlink alias",
    );
}

#[cfg(unix)]
#[test]
fn segment_leaf_symlink_refuses_without_following_parked_file() {
    use std::os::unix::fs::symlink;

    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let path = layout.segment_path(0, 1);
    let parked = root.join("parked-segment");
    fs::rename(&path, &parked).unwrap();
    symlink(&parked, &path).unwrap();
    assert!(
        fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let manifest_path = layout.manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let before = snapshot(dir.path());
    let mut callbacks = 0;
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let error = visit_v4_segments(root, &manifest, budget, |_| {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(
            matches!(&error, PraxisError::Corrupt { path: failed_path, reason }
                if failed_path.as_path() == path.as_path() && reason == "v4 segment path crosses a symbolic link"),
            "{error}"
        );
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert_eq!(callbacks, 0);
    assert_eq!(snapshot(dir.path()), before);
}

#[cfg(windows)]
#[test]
fn segment_level_junction_refuses_without_following_parked_directory() {
    use std::os::windows::fs::MetadataExt;

    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let level_path = layout.segment_root().join("0");
    let parked = root.join("parked-level");
    fs::rename(&level_path, &parked).unwrap();
    let output = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&level_path)
        .arg(&parked)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "junction creation failed: {output:?}"
    );
    assert_ne!(
        fs::symlink_metadata(&level_path).unwrap().file_attributes() & 0x400,
        0
    );
    let manifest_path = layout.manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let before = snapshot(dir.path());
    let mut callbacks = 0;
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let error = visit_v4_segments(root, &manifest, budget, |_| {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(
            matches!(&error, PraxisError::Corrupt { path: failed_path, reason }
                if failed_path.as_path() == level_path.as_path()
                    && (reason == "v4 segment path crosses a reparse point"
                        || reason == "v4 segment path crosses a symbolic link")),
            "{error}"
        );
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert_eq!(callbacks, 0);
    assert_eq!(snapshot(dir.path()), before);
    fs::remove_dir(&level_path).unwrap();
}

#[derive(Clone, Copy)]
struct FooterFieldPositions {
    first_key: usize,
    last_key: usize,
    offset: usize,
    len: usize,
    original_offset: u64,
    original_len: u64,
}

fn three_block_footer_positions(
    bytes: &[u8],
    path: &Path,
) -> (usize, usize, [FooterFieldPositions; 3]) {
    let trailer = bytes.len().checked_sub(12).unwrap();
    let footer_len = u32::from_le_bytes(bytes[trailer..trailer + 4].try_into().unwrap()) as usize;
    let footer_start = trailer.checked_sub(footer_len).unwrap();
    assert!(footer_start >= 21);
    assert_eq!(footer_len, 82);
    let mut footer = BinaryReader::new(&bytes[footer_start..trailer], path);
    assert_eq!(footer.read_u32().unwrap(), 3);
    let fields: [FooterFieldPositions; 3] = std::array::from_fn(|index| {
        let first_key = footer_start + footer.position() + 4;
        assert_eq!(footer.read_len_slice().unwrap(), &[index as u8][..]);
        let last_key = footer_start + footer.position() + 4;
        assert_eq!(footer.read_len_slice().unwrap(), &[index as u8][..]);
        let offset = footer_start + footer.position();
        let original_offset = footer.read_u64().unwrap();
        let len = footer_start + footer.position();
        let original_len = footer.read_u64().unwrap();
        FooterFieldPositions {
            first_key,
            last_key,
            offset,
            len,
            original_offset,
            original_len,
        }
    });
    assert_eq!(footer.remaining(), 0);
    assert_eq!(fields[1].first_key - footer_start, 34);
    assert_eq!(fields[1].last_key - footer_start, 39);
    assert_eq!(fields[1].offset - footer_start, 40);
    assert_eq!(fields[1].len - footer_start, 48);
    assert_eq!(fields[2].len - footer_start, 74);
    (footer_start, trailer, fields)
}

#[test]
fn two_literal_segments_emit_owned_physical_copies_but_owner_refuses() {
    for reverse in [true, false] {
        let (dir, config, lease, metadata) = two_literal_segments(reverse);
        let root = lease.root();
        let manifest_path = root.join("MANIFEST");
        let manifest =
            Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
        assert_eq!(manifest.segments.len(), 2);
        assert_eq!(manifest.segments[0].id, if reverse { 2 } else { 1 });
        let first_path = Path::new(&metadata[0].path);
        let second_path = Path::new(&metadata[1].path);
        assert_eq!(metadata[0].entries, 2);
        assert_eq!(metadata[1].entries, 2);
        assert!(fs::metadata(first_path).unwrap().len() <= 1_048_576);
        assert!(fs::metadata(second_path).unwrap().len() <= 1_048_576);
        let first_offsets = two_block_offsets(first_path);
        let second_offsets = two_block_offsets(second_path);
        let before = snapshot(dir.path());

        // This existing owner gate must keep rejecting the generalized root.
        match inspect_v4_owner(&lease, &config, &CpuAccelerator) {
            Err(PraxisError::UnsupportedCatalogFeature { feature }) => {
                assert_eq!(feature, "v4 installed cut beyond narrow D0 bootstrap");
            }
            _ => panic!("two physical segments must not acquire a v4 catalog owner"),
        }
        assert_eq!(snapshot(dir.path()), before);

        let cut = WalCut {
            flushed_sequence: manifest.flushed_sequence,
            last_sequence: manifest.last_sequence,
            flushed_wal_id: manifest.flushed_wal_id,
            active_wal_id: manifest.active_wal_id,
            next_wal_id: manifest.next_wal_id,
        };
        let (wal_witnesses, mut budget) =
            scan_v4_wals_with_budget(root, cut, |_, _, _, _| Ok(())).unwrap();
        assert_eq!(wal_witnesses.len(), 1);
        let mut observed = Vec::new();
        let candidate = visit_v4_segments(root, &manifest, &mut budget, |row| {
            observed.push(row);
            Ok(())
        });
        assert_eq!(snapshot(dir.path()), before);
        let witnesses = candidate.unwrap();

        let first_source = SegmentSource {
            level: 0,
            id: 1,
            manifest_ordinal: usize::from(reverse),
        };
        let second_source = SegmentSource {
            level: 1,
            id: 2,
            manifest_ordinal: usize::from(!reverse),
        };
        assert_eq!(witnesses.len(), 2);
        for (witness, source, meta) in [
            (&witnesses[0], first_source, &metadata[0]),
            (&witnesses[1], second_source, &metadata[1]),
        ] {
            assert_eq!(witness.source, source);
            assert_eq!(witness.path.as_path(), Path::new(&meta.path));
            assert_eq!(witness.len, fs::metadata(&meta.path).unwrap().len());
            assert_eq!(witness.digest, blake3::hash(&fs::read(&meta.path).unwrap()));
            assert_eq!(witness.observed_rows, 2);
        }
        assert_eq!(
            observed,
            vec![
                expected_row(
                    first_source,
                    first_offsets[0],
                    0,
                    ObservedSegmentValue::Put(vec![0xca, 0xfe])
                ),
                expected_row(
                    first_source,
                    first_offsets[1],
                    1,
                    ObservedSegmentValue::Delete
                ),
                expected_row(
                    second_source,
                    second_offsets[0],
                    0,
                    ObservedSegmentValue::Put(vec![0xca, 0xfe])
                ),
                expected_row(
                    second_source,
                    second_offsets[1],
                    2,
                    ObservedSegmentValue::Merge(vec![0x22])
                ),
            ]
        );
        // Both same-(CF,key,S) copies remain physical observations; no winner is chosen.
        assert_eq!(observed.iter().filter(|row| row.key == [0]).count(), 2);
        assert_eq!(snapshot(dir.path()), before);
    }
}

#[test]
fn unlisted_canonical_segment_refuses_before_visiting_any_row() {
    let (dir, config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let extra_path = layout.segment_path(0, 7);
    let value_path = layout.value_log_path(1);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let extra = SegmentWriter::write(
        SegmentWriteOptions {
            path: &extra_path,
            id: 7,
            level: 0,
            compression: Compression::None,
            accelerator: &CpuAccelerator,
            value_log: &mut value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: 1,
            partitioned_bloom: None,
            direct_io: false,
        },
        vec![row(7, StoredValue::Put(vec![0x77]))],
    )
    .unwrap();
    drop(value_log);
    fs::remove_file(value_path).unwrap();
    assert_eq!(extra.id, 7);
    assert_eq!(Path::new(&extra.path), extra_path.as_path());
    assert!(fs::metadata(&extra_path).unwrap().len() <= 1_048_576);

    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    manifest.next_segment_id = 8;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.next_segment_id, 8);
    assert_eq!(manifest.segments.len(), 2);
    assert!(manifest.segments.iter().all(|segment| segment.id != 7));
    let cut = WalCut {
        flushed_sequence: manifest.flushed_sequence,
        last_sequence: manifest.last_sequence,
        flushed_wal_id: manifest.flushed_wal_id,
        active_wal_id: manifest.active_wal_id,
        next_wal_id: manifest.next_wal_id,
    };
    let (wal_witnesses, mut budget) =
        scan_v4_wals_with_budget(root, cut, |_, _, _, _| Ok(())).unwrap();
    assert_eq!(wal_witnesses.len(), 1);
    let before = snapshot(dir.path());
    let mut callbacks = 0;
    let error = visit_v4_segments(root, &manifest, &mut budget, |_| {
        callbacks += 1;
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(&error, PraxisError::Corrupt { .. }), "{error}");
    assert_eq!(callbacks, 0);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn inventory_accepts_4096_and_refuses_4097_listed_or_observed_files() {
    let started = std::time::Instant::now();
    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let manifest_path = layout.manifest_path();
    let mut listed = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let template = listed.segments[0].clone();
    for id in 3_u64..=4096 {
        let path = layout.segment_path(0, id);
        File::create(&path).unwrap();
        let mut meta = template.clone();
        meta.id = id;
        meta.level = 0;
        meta.path = path.to_str().unwrap().to_owned();
        listed.segments.push(meta);
    }
    listed.next_segment_id = 4097;
    assert_eq!(listed.segments.len(), 4096);
    let baseline = snapshot(dir.path());
    with_wal_budget(root, &listed, |budget| {
        let balance = budget.remaining_bytes();
        assert_eq!(
            inventory_count_for_test(root, &listed, budget).unwrap(),
            4096
        );
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert_eq!(snapshot(dir.path()), baseline);

    let extra_path = layout.segment_path(0, 4097);
    let mut overlisted = listed.clone();
    let mut extra_meta = template;
    extra_meta.id = 4097;
    extra_meta.level = 0;
    extra_meta.path = extra_path.to_str().unwrap().to_owned();
    overlisted.segments.push(extra_meta);
    assert_eq!(overlisted.segments.len(), 4097);
    with_wal_budget(root, &overlisted, |budget| {
        let balance = budget.remaining_bytes();
        let mut callbacks = 0;
        let error = visit_v4_segments(root, &overlisted, budget, |_| {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(
            matches!(&error, PraxisError::Corrupt { path, reason }
                if path.as_path() == root && reason == "v4 segment listed-file limit exceeded"),
            "{error}"
        );
        assert_eq!(callbacks, 0);
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert_eq!(snapshot(dir.path()), baseline);

    let level_path = layout.segment_root().join("0");
    assert_eq!(next_observed_file(&level_path, 4095).unwrap(), 4096);
    let error = next_observed_file(&level_path, 4096).unwrap_err();
    assert!(
        matches!(&error, PraxisError::Corrupt { path, reason }
            if path.as_path() == level_path.as_path() && reason == "v4 segment observed-file limit exceeded"),
        "{error}"
    );

    File::create(&extra_path).unwrap();
    let mut with_extra = baseline;
    with_extra.insert(
        extra_path.strip_prefix(root).unwrap().to_path_buf(),
        TreeEntry {
            is_dir: false,
            bytes: Some(Vec::new()),
            file_id: Some(file_id(&extra_path)),
            alias_target: None,
        },
    );
    with_wal_budget(root, &listed, |budget| {
        let balance = budget.remaining_bytes();
        let mut callbacks = 0;
        let error = visit_v4_segments(root, &listed, budget, |_| {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(
            matches!(&error, PraxisError::Corrupt { reason, .. }
                if reason == "unlisted v4 segment file"
                    || reason == "v4 segment observed-file limit exceeded"),
            "{error}"
        );
        assert_eq!(callbacks, 0);
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert_eq!(snapshot(dir.path()), with_extra);
    eprintln!(
        "4,096/4,097 segment inventory fixture: {:?}",
        started.elapsed()
    );
}

#[test]
fn charged_wal_budget_exhaustion_refuses_before_segment_callbacks() {
    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let cut = WalCut {
        flushed_sequence: manifest.flushed_sequence,
        last_sequence: manifest.last_sequence,
        flushed_wal_id: manifest.flushed_wal_id,
        active_wal_id: manifest.active_wal_id,
        next_wal_id: manifest.next_wal_id,
    };
    let (wal_witnesses, mut budget) =
        scan_v4_wals_with_budget(root, cut, |_, _, _, _| Ok(())).unwrap();
    assert_eq!(wal_witnesses.len(), 1);
    assert!(budget.remaining_bytes() < 64 * 1024 * 1024);
    let remaining = budget.remaining_bytes();
    budget.charge(root, remaining).unwrap();
    assert_eq!(budget.remaining_bytes(), 0);

    let before = snapshot(dir.path());
    let mut callbacks = 0;
    let error = visit_v4_segments(root, &manifest, &mut budget, |_| {
        callbacks += 1;
        Ok(())
    })
    .unwrap_err();
    assert!(
        matches!(&error, PraxisError::Corrupt { reason, .. } if reason.contains("budget")),
        "{error}"
    );
    assert_eq!(callbacks, 0);
    assert_eq!(budget.remaining_bytes(), 0);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn equal_key_rows_remain_distinct_owned_physical_observations() {
    let (dir, config, lease, _) = two_literal_segments(true);
    let root = lease.root();
    let manifest = rewrite_first_segment(
        root,
        vec![
            row(0, StoredValue::Put(vec![0x11])),
            row(0, StoredValue::Delete),
            row(1, StoredValue::Merge(vec![0x33])),
        ],
        Compression::None,
        config.large_value_threshold,
        1,
    );
    let before = snapshot(dir.path());
    let mut observed = Vec::new();
    let witnesses = visit_with_wal_budget(root, &manifest, |row| {
        observed.push(row);
        Ok(())
    })
    .unwrap();
    assert_eq!(witnesses.len(), 2);
    assert_eq!(witnesses[0].observed_rows, 3);
    assert_eq!(witnesses[0].source.manifest_ordinal, 1);
    assert_eq!(observed.len(), 5);
    assert_eq!(observed[0].source, observed[1].source);
    assert_eq!(observed[0].key, observed[1].key);
    assert_eq!(observed[0].sequence, observed[1].sequence);
    assert_eq!(observed[0].value, ObservedSegmentValue::Put(vec![0x11]));
    assert_eq!(observed[1].value, ObservedSegmentValue::Delete);
    assert_eq!(
        observed.iter().filter(|row| row.key == [0]).count(),
        3,
        "same-key copies across and within files must all be observed"
    );
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn repaired_block_row_count_refuses_before_callbacks() {
    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let path = DiskLayout::at(root).segment_path(0, 1);
    let mut bytes = fs::read(&path).unwrap();
    let encoded_len = u32::from_le_bytes(bytes[21..25].try_into().unwrap()) as usize;
    bytes[33..37].copy_from_slice(&u32::MAX.to_le_bytes());
    let checksum = crc32c(&bytes[33..33 + encoded_len]);
    bytes[29..33].copy_from_slice(&checksum.to_le_bytes());
    assert_eq!(crc32c(&bytes[33..33 + encoded_len]), checksum);
    let manifest = replace_first_segment_bytes(root, &bytes);
    let before = snapshot(dir.path());
    let mut callbacks = 0;
    let error = visit_with_wal_budget(root, &manifest, |_| {
        callbacks += 1;
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(&error, PraxisError::Corrupt { .. }), "{error}");
    assert_eq!(callbacks, 0);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn redigested_bad_block_crc_refuses_before_callbacks() {
    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let path = DiskLayout::at(root).segment_path(0, 1);
    let mut bytes = fs::read(&path).unwrap();
    bytes[29] ^= 1; // The first block checksum follows the 21-byte header and two lengths.
    let manifest = replace_first_segment_bytes(root, &bytes);
    let before = snapshot(dir.path());
    let mut callbacks = 0;
    let error = visit_with_wal_budget(root, &manifest, |_| {
        callbacks += 1;
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(&error, PraxisError::Corrupt { .. }), "{error}");
    assert_eq!(callbacks, 0);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn checksum_repaired_interior_row_disorder_refuses_before_callbacks() {
    let (dir, config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    rewrite_first_segment(
        root,
        vec![
            row(0, StoredValue::Delete),
            row(1, StoredValue::Delete),
            row(2, StoredValue::Delete),
            row(3, StoredValue::Delete),
        ],
        Compression::None,
        config.large_value_threshold,
        usize::MAX,
    );
    let path = DiskLayout::at(root).segment_path(0, 1);
    let mut raw = decode_segment(&fs::read(&path).unwrap(), &path, &CpuAccelerator).unwrap();
    assert_eq!(raw.blocks.len(), 1);
    raw.blocks[0].swap(1, 2);
    let bytes = raw.encode(&CpuAccelerator).unwrap();
    assert_eq!(
        decode_segment(&bytes, &path, &CpuAccelerator)
            .unwrap()
            .blocks[0]
            .len(),
        4
    );
    let manifest = replace_first_segment_bytes(root, &bytes);
    let before = snapshot(dir.path());
    let mut callbacks = 0;
    let error = visit_with_wal_budget(root, &manifest, |_| {
        callbacks += 1;
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(&error, PraxisError::Corrupt { .. }), "{error}");
    assert_eq!(callbacks, 0);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn redigested_wrong_segment_header_id_refuses_before_callbacks() {
    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let path = DiskLayout::at(root).segment_path(0, 1);
    let mut bytes = fs::read(&path).unwrap();
    bytes[13..21].copy_from_slice(&7_u64.to_le_bytes());
    let manifest = replace_first_segment_bytes(root, &bytes);
    let before = snapshot(dir.path());
    let mut callbacks = 0;
    let error = visit_with_wal_budget(root, &manifest, |_| {
        callbacks += 1;
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(&error, PraxisError::Corrupt { .. }), "{error}");
    assert_eq!(callbacks, 0);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn forged_manifest_row_count_does_not_drive_allocation() {
    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    manifest
        .segments
        .iter_mut()
        .find(|meta| meta.id == 1)
        .unwrap()
        .entries = u64::MAX;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.segments[0].entries, u64::MAX);
    let before = snapshot(dir.path());
    let mut callbacks = 0;
    let error = visit_with_wal_budget(root, &manifest, |_| {
        callbacks += 1;
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(&error, PraxisError::Corrupt { .. }), "{error}");
    assert_eq!(callbacks, 0);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn wrong_manifest_min_and_max_refuse_before_callbacks() {
    for wrong_min in [true, false] {
        let (_dir, _config, lease, metadata) = two_literal_segments(false);
        let root = lease.root();
        let path = DiskLayout::at(root).segment_path(0, 1);
        let original_bytes = fs::read(&path).unwrap();
        let manifest_path = DiskLayout::at(root).manifest_path();
        let mut manifest =
            Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
        let mut expected_meta = metadata[0].clone();
        if wrong_min {
            expected_meta.min_key = vec![1];
        } else {
            expected_meta.max_key = vec![0];
        }
        manifest.segments[0] = expected_meta.clone();
        let saved = save_strict_manifest(root, &manifest);
        assert_eq!(saved.segments[0], expected_meta);
        assert_eq!(saved.segments[1], metadata[1]);
        assert_eq!(saved.segments[0].entries, 2);
        assert_eq!(saved.segments[0].bloom_filter, metadata[0].bloom_filter);
        assert_eq!(saved.segments[0].file_digest, metadata[0].file_digest);
        assert_eq!(fs::read(&path).unwrap(), original_bytes);
        assert_segment_corrupt_without_mutation(
            root,
            &saved,
            &path,
            "v4 segment observed count or key range mismatch",
        );
    }
}

#[test]
fn wrong_manifest_bloom_bit_and_legal_shape_refuse_before_callbacks() {
    for single_bit in [true, false] {
        let (_dir, _config, lease, metadata) = two_literal_segments(false);
        let root = lease.root();
        let path = DiskLayout::at(root).segment_path(0, 1);
        let original_bytes = fs::read(&path).unwrap();
        let manifest_path = DiskLayout::at(root).manifest_path();
        let mut manifest =
            Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
        let original_wire = serde_json::to_value(&metadata[0].bloom_filter).unwrap();
        let changed_bloom = if single_bit {
            let mut wire = original_wire.clone();
            let word = wire["bits"][0].as_u64().unwrap();
            wire["bits"][0] = serde_json::Value::from(word ^ 1_u64);
            let changed_wire = wire.clone();
            assert_eq!(changed_wire["bit_count"], original_wire["bit_count"]);
            assert_eq!(changed_wire["hash_count"], original_wire["hash_count"]);
            assert_eq!(
                changed_wire["bits"].as_array().unwrap().len(),
                original_wire["bits"].as_array().unwrap().len()
            );
            assert_eq!(
                (word ^ changed_wire["bits"][0].as_u64().unwrap()).count_ones(),
                1
            );
            serde_json::from_value::<BloomFilter>(wire).unwrap()
        } else {
            let changed = BloomFilter::with_expected_items(1);
            let changed_wire = serde_json::to_value(&changed).unwrap();
            assert_eq!(original_wire["bit_count"].as_u64(), Some(32));
            assert_eq!(changed_wire["bit_count"].as_u64(), Some(16));
            assert_eq!(changed_wire["hash_count"], original_wire["hash_count"]);
            changed
        };
        assert_ne!(changed_bloom, metadata[0].bloom_filter);
        let mut expected_meta = metadata[0].clone();
        expected_meta.bloom_filter = changed_bloom;
        manifest.segments[0] = expected_meta.clone();
        let saved = save_strict_manifest(root, &manifest);
        assert_eq!(saved.segments[0], expected_meta);
        assert_eq!(saved.segments[1], metadata[1]);
        assert_eq!(saved.segments[0].entries, 2);
        assert_eq!(saved.segments[0].min_key, metadata[0].min_key);
        assert_eq!(saved.segments[0].max_key, metadata[0].max_key);
        assert_eq!(saved.segments[0].file_digest, metadata[0].file_digest);
        assert_eq!(fs::read(&path).unwrap(), original_bytes);
        assert_segment_corrupt_without_mutation(
            root,
            &saved,
            &path,
            "v4 segment Bloom or semantic pass mismatch",
        );
    }
}

#[derive(Clone, Copy, Debug)]
enum FooterMutation {
    MiddleFirstKey,
    MiddleLastKey,
    MiddleOffsetGap,
    MiddleOffsetOverlap,
    LastBlockPastFooter,
}

#[test]
fn repaired_middle_footer_keys_and_block_boundaries_refuse_before_callbacks() {
    for mutation in [
        FooterMutation::MiddleFirstKey,
        FooterMutation::MiddleLastKey,
        FooterMutation::MiddleOffsetGap,
        FooterMutation::MiddleOffsetOverlap,
        FooterMutation::LastBlockPastFooter,
    ] {
        let (_dir, config, lease, _) = two_literal_segments(false);
        let root = lease.root();
        let writer_manifest = rewrite_first_segment(
            root,
            vec![
                row(0, StoredValue::Delete),
                row(1, StoredValue::Delete),
                row(2, StoredValue::Delete),
            ],
            Compression::None,
            config.large_value_threshold,
            1,
        );
        let path = DiskLayout::at(root).segment_path(0, 1);
        let mut bytes = fs::read(&path).unwrap();
        let decoded = decode_segment(&bytes, &path, &CpuAccelerator).unwrap();
        assert_eq!(decoded.blocks.len(), 3);
        assert!(decoded.blocks.iter().all(|block| block.len() == 1));
        let original_bytes = bytes.clone();
        let (footer_start, trailer, fields) = three_block_footer_positions(&bytes, &path);
        assert_eq!(
            crc32c(&bytes[footer_start..trailer]),
            u32::from_le_bytes(bytes[trailer + 4..trailer + 8].try_into().unwrap())
        );
        let reason = match mutation {
            FooterMutation::MiddleFirstKey => {
                bytes[fields[1].first_key] = 9;
                "v4 segment block key range or framing mismatch"
            }
            FooterMutation::MiddleLastKey => {
                bytes[fields[1].last_key] = 9;
                "v4 segment block key range or framing mismatch"
            }
            FooterMutation::MiddleOffsetGap => {
                bytes[fields[1].offset..fields[1].offset + 8].copy_from_slice(
                    &fields[1]
                        .original_offset
                        .checked_add(1)
                        .unwrap()
                        .to_le_bytes(),
                );
                "v4 segment block is not contiguous"
            }
            FooterMutation::MiddleOffsetOverlap => {
                bytes[fields[1].offset..fields[1].offset + 8].copy_from_slice(
                    &fields[1]
                        .original_offset
                        .checked_sub(1)
                        .unwrap()
                        .to_le_bytes(),
                );
                "v4 segment block is not contiguous"
            }
            FooterMutation::LastBlockPastFooter => {
                assert_eq!(
                    fields[2].original_offset + fields[2].original_len,
                    footer_start as u64
                );
                bytes[fields[2].len..fields[2].len + 8]
                    .copy_from_slice(&fields[2].original_len.checked_add(1).unwrap().to_le_bytes());
                "v4 segment block is not contiguous"
            }
        };
        assert_eq!(&bytes[..footer_start], &original_bytes[..footer_start]);
        assert_ne!(
            &bytes[footer_start..trailer],
            &original_bytes[footer_start..trailer]
        );
        let footer_checksum = crc32c(&bytes[footer_start..trailer]);
        bytes[trailer + 4..trailer + 8].copy_from_slice(&footer_checksum.to_le_bytes());
        assert_eq!(
            crc32c(&bytes[footer_start..trailer]),
            u32::from_le_bytes(bytes[trailer + 4..trailer + 8].try_into().unwrap())
        );
        let saved = replace_first_segment_bytes(root, &bytes);
        let mut expected_meta = writer_manifest.segments[0].clone();
        expected_meta.file_digest = blake3::hash(&bytes).to_hex().to_string();
        assert_eq!(saved.segments[0], expected_meta);
        assert_eq!(saved.segments[1], writer_manifest.segments[1]);
        assert_eq!(saved.segments[0].entries, 3);
        assert_eq!(saved.segments[0].min_key, vec![0]);
        assert_eq!(saved.segments[0].max_key, vec![2]);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_segment_corrupt_without_mutation(root, &saved, &path, reason);
    }
}

#[test]
fn later_file_corruption_invalidates_earlier_provisional_callbacks() {
    let (dir, _config, lease, _) = two_literal_segments(true);
    let root = lease.root();
    let path = DiskLayout::at(root).segment_path(1, 2);
    let mut bytes = fs::read(&path).unwrap();
    bytes[29] ^= 1;
    fs::write(&path, &bytes).unwrap();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    manifest
        .segments
        .iter_mut()
        .find(|meta| meta.id == 2)
        .unwrap()
        .file_digest = blake3::hash(&bytes).to_hex().to_string();
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let before = snapshot(dir.path());
    let mut provisional = Vec::new();
    let error = visit_with_wal_budget(root, &manifest, |row| {
        provisional.push(row);
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(&error, PraxisError::Corrupt { .. }), "{error}");
    assert_eq!(provisional.len(), 2);
    assert!(provisional.iter().all(|row| row.source.id == 1));
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn same_length_overwrite_during_callbacks_fails_final_byte_recheck() {
    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let path = DiskLayout::at(root).segment_path(0, 1);
    let mut changed = fs::read(&path).unwrap();
    changed[13] ^= 1;
    let mut expected = snapshot(dir.path());
    expected
        .get_mut(path.strip_prefix(root).unwrap())
        .unwrap()
        .bytes = Some(changed.clone());
    let mut callbacks = 0;
    let error = visit_with_wal_budget(root, &manifest, |_| {
        callbacks += 1;
        if callbacks == 4 {
            fs::write(&path, &changed).unwrap();
        }
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(&error, PraxisError::Corrupt { .. }), "{error}");
    assert_eq!(callbacks, 4);
    assert_eq!(snapshot(dir.path()), expected);
}

#[test]
fn retagged_literal_is_not_a_valid_lz4_segment() {
    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let path = DiskLayout::at(root).segment_path(0, 1);
    let mut bytes = fs::read(&path).unwrap();
    bytes[8] = 1; // Repairing only the outer digest cannot create valid LZ4 block frames.
    let manifest = replace_first_segment_bytes(root, &bytes);
    let before = snapshot(dir.path());
    let mut callbacks = 0;
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let error = visit_v4_segments(root, &manifest, budget, |_| {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(&error, PraxisError::Corrupt { .. }), "{error}");
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert_eq!(callbacks, 0);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn writer_valid_zstd_segments_remain_fenced_from_public_owner() {
    let (dir, config, lease, metadata) = two_segments(Compression::Zstd, true);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.format_version, 4);
    assert_eq!(manifest.segments.len(), 2);
    assert_eq!(manifest.segments[0].id, 2);
    assert_eq!(manifest.segments[1].id, 1);
    for meta in &metadata {
        let bytes = fs::read(&meta.path).unwrap();
        assert_eq!(meta.entries, 2);
        assert_eq!(bytes[8], 2);
        assert_eq!(
            decode_segment(&bytes, Path::new(&meta.path), &CpuAccelerator)
                .unwrap()
                .blocks
                .len(),
            2
        );
    }
    let before = snapshot(dir.path());
    assert!(matches!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(dir.path()), before);
}

fn assert_compressed_segment_provenance(compression: Compression, reverse: bool) {
    let (dir, config, lease, metadata) = two_segments(compression, reverse);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.segments[0].id, if reverse { 2 } else { 1 });
    assert_eq!(manifest.segments[1].id, if reverse { 1 } else { 2 });
    let first_offsets = two_block_offsets(Path::new(&metadata[0].path));
    let second_offsets = two_block_offsets(Path::new(&metadata[1].path));
    let first_source = SegmentSource {
        level: 0,
        id: 1,
        manifest_ordinal: usize::from(reverse),
    };
    let second_source = SegmentSource {
        level: 1,
        id: 2,
        manifest_ordinal: usize::from(!reverse),
    };
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let wal_balance = budget.remaining_bytes();
        let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        assert_eq!(
            wal_balance - budget.remaining_bytes(),
            candidate.retained_witness_bytes()
        );
        assert_eq!(candidate.witnesses.len(), 2);
        assert_eq!(candidate.rows.len(), 4);
        assert_ne!(
            candidate.witnesses[0].identity,
            candidate.witnesses[1].identity
        );
        assert_eq!(
            candidate.rows.iter().filter(|row| row.key == [0]).count(),
            2
        );
        assert_eq!(
            candidate
                .witnesses
                .iter()
                .map(|w| w.source)
                .collect::<Vec<_>>(),
            vec![first_source, second_source]
        );
        for (witness, meta) in candidate.witnesses.iter().zip(&metadata) {
            assert_eq!(witness.path.as_path(), Path::new(&meta.path));
            let opened = File::open(&meta.path).unwrap();
            assert_eq!(
                witness.identity,
                physical_id(&opened, Path::new(&meta.path)).unwrap()
            );
            assert_eq!(witness.observed_rows, 2);
            assert_eq!(witness.len, fs::metadata(&meta.path).unwrap().len());
            assert_eq!(witness.digest, blake3::hash(&fs::read(&meta.path).unwrap()));
        }
        assert_eq!(
            candidate.rows,
            vec![
                expected_row(
                    first_source,
                    first_offsets[0],
                    0,
                    ObservedSegmentValue::Put(vec![0xca, 0xfe])
                ),
                expected_row(
                    first_source,
                    first_offsets[1],
                    1,
                    ObservedSegmentValue::Delete
                ),
                expected_row(
                    second_source,
                    second_offsets[0],
                    0,
                    ObservedSegmentValue::Put(vec![0xca, 0xfe])
                ),
                expected_row(
                    second_source,
                    second_offsets[1],
                    2,
                    ObservedSegmentValue::Merge(vec![0x22])
                ),
            ]
        );
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), wal_balance);
    });
    assert!(matches!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn writer_valid_lz4_segments_preserve_physical_provenance_when_admitted() {
    assert_compressed_segment_provenance(Compression::Lz4, false);
    assert_compressed_segment_provenance(Compression::Lz4, true);
}

#[test]
fn mixed_literal_and_lz4_segments_keep_both_physical_sources() {
    for literal_first in [true, false] {
        let (dir, config, lease, manifest) = mixed_literal_lz4_segments(literal_first);
        let root = lease.root();
        assert_eq!(manifest.segments.len(), 2);
        assert_eq!(manifest.segments[0].id, 1);
        assert_eq!(manifest.segments[1].id, 2);
        let first_path = Path::new(&manifest.segments[0].path);
        let second_path = Path::new(&manifest.segments[1].path);
        let first_bytes = fs::read(first_path).unwrap();
        let second_bytes = fs::read(second_path).unwrap();
        assert_eq!(first_bytes[8], if literal_first { 0 } else { 1 });
        assert_eq!(second_bytes[8], if literal_first { 1 } else { 0 });
        for (path, bytes) in [(first_path, &first_bytes), (second_path, &second_bytes)] {
            assert_eq!(
                decode_segment(bytes, path, &CpuAccelerator)
                    .unwrap()
                    .blocks
                    .len(),
                2
            );
        }
        let first_offsets = two_block_offsets(first_path);
        let second_offsets = two_block_offsets(second_path);
        let first_source = SegmentSource {
            level: 0,
            id: 1,
            manifest_ordinal: 0,
        };
        let second_source = SegmentSource {
            level: 1,
            id: 2,
            manifest_ordinal: 1,
        };
        let before = snapshot(dir.path());
        with_wal_budget(root, &manifest, |budget| {
            let balance = budget.remaining_bytes();
            let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
            assert_eq!(candidate.witnesses.len(), 2);
            assert_eq!(candidate.rows.len(), 4);
            assert_eq!(
                candidate
                    .witnesses
                    .iter()
                    .map(|w| w.source)
                    .collect::<Vec<_>>(),
                vec![first_source, second_source]
            );
            assert_eq!(
                candidate.rows,
                vec![
                    expected_row(
                        first_source,
                        first_offsets[0],
                        0,
                        ObservedSegmentValue::Put(vec![0xca, 0xfe]),
                    ),
                    expected_row(
                        first_source,
                        first_offsets[1],
                        1,
                        ObservedSegmentValue::Delete
                    ),
                    expected_row(
                        second_source,
                        second_offsets[0],
                        0,
                        ObservedSegmentValue::Put(vec![0xca, 0xfe]),
                    ),
                    expected_row(
                        second_source,
                        second_offsets[1],
                        2,
                        ObservedSegmentValue::Merge(vec![0x22]),
                    ),
                ]
            );
            for (witness, meta) in candidate.witnesses.iter().zip(&manifest.segments) {
                let path = Path::new(&meta.path);
                let opened = File::open(path).unwrap();
                assert_eq!(witness.identity, physical_id(&opened, path).unwrap());
                assert_eq!(witness.len, fs::metadata(path).unwrap().len());
                assert_eq!(witness.digest, blake3::hash(&fs::read(path).unwrap()));
            }
            assert_eq!(
                balance - budget.remaining_bytes(),
                candidate.retained_witness_bytes()
            );
            candidate.discard(root, budget).unwrap();
            assert_eq!(budget.remaining_bytes(), balance);
        });
        assert!(matches!(
            inspect_v4_owner(&lease, &config, &CpuAccelerator),
            Err(PraxisError::UnsupportedCatalogFeature {
                feature: "v4 installed cut beyond narrow D0 bootstrap"
            })
        ));
        assert_eq!(snapshot(dir.path()), before);
    }
}

#[test]
fn visitor_accepts_writer_valid_lz4_inline_put_over_one_mebibyte() {
    let (dir, config, lease, _) = two_segments(Compression::Lz4, false);
    let root = lease.root();
    let mut value = vec![0_u8; 1_100_000];
    blake3::Hasher::new().finalize_xof().fill(&mut value);
    let manifest = rewrite_first_segment(
        root,
        vec![row(0, StoredValue::Put(value.clone()))],
        Compression::Lz4,
        value.len() + 1,
        4096,
    );
    let path = Path::new(&manifest.segments[0].path);
    let bytes = fs::read(path).unwrap();
    assert_eq!(bytes[8], 1);
    assert!(bytes.len() > 1_048_576);
    assert!(writer_block_frame(&bytes, 21).1 > 1_048_576);
    let decoded = decode_segment(&bytes, path, &CpuAccelerator).unwrap();
    assert_eq!(decoded.blocks.len(), 1);
    assert_eq!(decoded.blocks[0].len(), 1);
    assert_eq!(
        decoded.blocks[0][0].entry.version.value,
        StoredValue::Put(value.clone())
    );
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        assert_eq!(candidate.witnesses.len(), 2);
        assert_eq!(candidate.rows.len(), 3);
        assert_eq!(candidate.witnesses[0].len, bytes.len() as u64);
        assert_eq!(candidate.witnesses[0].digest, blake3::hash(&bytes));
        assert_eq!(candidate.witnesses[0].observed_rows, 1);
        assert_eq!(
            candidate.rows[0],
            expected_row(
                SegmentSource {
                    level: 0,
                    id: 1,
                    manifest_ordinal: 0,
                },
                21,
                0,
                ObservedSegmentValue::Put(value.clone()),
            )
        );
        assert_eq!(
            balance - budget.remaining_bytes(),
            candidate.retained_witness_bytes()
        );
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert!(matches!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn lz4_discovery_retag_before_pass1_is_rejected_by_reopened_parser() {
    let (dir, _config, lease, metadata) = two_segments(Compression::Lz4, false);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    assert_eq!(original[8], 1);
    assert_eq!(fs::read(&metadata[1].path).unwrap()[8], 1);
    let identity = file_id(path);
    let mut expected = snapshot(dir.path());
    let mut retagged = original.clone();
    retagged[8] = 0;
    expected
        .get_mut(path.strip_prefix(root).unwrap())
        .unwrap()
        .bytes = Some(retagged.clone());
    let mut writer = OpenOptions::new().write(true).open(path).unwrap();
    let mut hooks = 0;
    let mut callbacks = 0;
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let error = visit_v4_segments_with_profile_and_hook_for_test(
            root,
            &manifest,
            budget,
            PRODUCTION_COMPRESSED_PROOF_PROFILE,
            |discovered| {
                assert_eq!(discovered, path);
                hooks += 1;
                assert_eq!(hooks, 1);
                writer.seek(SeekFrom::Start(8)).unwrap();
                writer.write_all(&[0]).unwrap();
                writer.sync_data().unwrap();
                Ok(())
            },
            |_| {
                callbacks += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(
            matches!(
                &error,
                PraxisError::Corrupt { path: error_path, reason }
                    if error_path.as_path() == path && reason == "compressed v4 pass expected LZ4 tag"
            ),
            "{error}"
        );
        assert_eq!(budget.remaining_bytes(), balance);
    });
    drop(writer);
    assert_eq!(hooks, 1);
    assert_eq!(callbacks, 0);
    assert_eq!(file_id(path), identity);
    assert_eq!(fs::read(path).unwrap(), retagged);
    assert_eq!(snapshot(dir.path()), expected);
}

#[test]
fn zstd_discovery_retag_before_pass1_is_rejected_by_reopened_parser() {
    let (dir, _config, lease, metadata) = two_segments(Compression::Zstd, false);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    assert_eq!(original[8], 2);
    let identity = file_id(path);
    let mut retagged = original.clone();
    retagged[8] = 0;
    let mut expected = snapshot(dir.path());
    expected
        .get_mut(path.strip_prefix(root).unwrap())
        .unwrap()
        .bytes = Some(retagged.clone());
    let mut writer = OpenOptions::new().write(true).open(path).unwrap();
    let mut hooks = 0;
    let mut callbacks = 0;
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let error = visit_v4_segments_with_profile_and_tag_hook_for_test(
            root,
            &manifest,
            budget,
            PRODUCTION_COMPRESSED_PROOF_PROFILE,
            |discovered, tag| {
                assert_eq!(discovered, path);
                assert_eq!(tag, 2);
                hooks += 1;
                assert_eq!(hooks, 1);
                writer.seek(SeekFrom::Start(8)).unwrap();
                writer.write_all(&[0]).unwrap();
                writer.sync_data().unwrap();
                Ok(())
            },
            |_| {
                callbacks += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(
            matches!(&error, PraxisError::Corrupt { path: failed_path, reason }
                if failed_path.as_path() == path && reason == "compressed v4 pass expected Zstd tag"),
            "{error}"
        );
        assert_eq!(budget.remaining_bytes(), balance);
    });
    drop(writer);
    assert_eq!(hooks, 1);
    assert_eq!(callbacks, 0);
    assert_eq!(file_id(path), identity);
    assert_eq!(fs::read(path).unwrap(), retagged);
    assert_eq!(snapshot(dir.path()), expected);
}

#[test]
fn zstd_discovery_path_substitution_refuses_before_pass1() {
    let (dir, _config, lease, metadata) = two_segments(Compression::Zstd, false);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    assert_eq!(original[8], 2);
    let identity = file_id(path);
    // Keep the temporary file outside segments/ so inventory never sees it.
    let replacement = root.join("discovery-replacement");
    assert!(!replacement.exists());
    let mut expected = snapshot(dir.path());
    let mut replacement_identity = None;
    let mut hooks = 0;
    let mut callbacks = 0;
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let error = visit_v4_segments_with_profile_and_tag_hook_for_test(
            root,
            &manifest,
            budget,
            PRODUCTION_COMPRESSED_PROOF_PROFILE,
            |discovered, tag| {
                assert_eq!(discovered, path);
                assert_eq!(tag, 2);
                hooks += 1;
                assert_eq!(hooks, 1);
                fs::write(&replacement, &original).unwrap();
                // file_id closes its handle before either rename operation.
                let new_identity = file_id(&replacement);
                assert_ne!(new_identity, identity);
                fs::remove_file(path).unwrap();
                fs::rename(&replacement, path).unwrap();
                assert_eq!(file_id(path), new_identity);
                expected
                    .get_mut(path.strip_prefix(root).unwrap())
                    .unwrap()
                    .file_id = Some(new_identity.clone());
                replacement_identity = Some(new_identity);
                Ok(())
            },
            |_| {
                callbacks += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(
            matches!(&error, PraxisError::Corrupt { path: failed_path, reason }
                if failed_path.as_path() == path && reason == "compressed v4 identity changed before pass"),
            "{error}"
        );
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert_eq!(hooks, 1);
    assert_eq!(callbacks, 0);
    assert_eq!(fs::read(path).unwrap(), original);
    assert_eq!(file_id(path), replacement_identity.unwrap());
    assert!(!replacement.exists());
    assert_eq!(snapshot(dir.path()), expected);
}

#[test]
fn lz4_visitor_enforces_aggregate_physical_cap_at_second_file() {
    let (dir, _config, lease, metadata) = two_segments(Compression::Lz4, false);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let paths = [Path::new(&metadata[0].path), Path::new(&metadata[1].path)];
    let bytes = [fs::read(paths[0]).unwrap(), fs::read(paths[1]).unwrap()];
    let lengths = [bytes[0].len() as u64, bytes[1].len() as u64];
    for (path, bytes) in paths.into_iter().zip(&bytes) {
        assert_eq!(bytes[8], 1);
        let decoded = decode_segment(bytes, path, &CpuAccelerator).unwrap();
        assert_eq!(decoded.blocks.len(), 2);
        assert!(decoded.blocks.iter().all(|block| block.len() == 1));
    }
    assert_ne!(file_id(paths[0]), file_id(paths[1]));
    let total = lengths[0].checked_add(lengths[1]).unwrap();
    assert!(total > lengths[0].max(lengths[1]));
    assert!(
        lengths[0].max(lengths[1]) <= PRODUCTION_COMPRESSED_PROOF_PROFILE.max_physical_file_bytes
    );
    let first_source = SegmentSource {
        level: 0,
        id: 1,
        manifest_ordinal: 0,
    };
    let second_source = SegmentSource {
        level: 1,
        id: 2,
        manifest_ordinal: 1,
    };
    let offsets = [two_block_offsets(paths[0]), two_block_offsets(paths[1])];
    let expected_rows = vec![
        expected_row(
            first_source,
            offsets[0][0],
            0,
            ObservedSegmentValue::Put(vec![0xca, 0xfe]),
        ),
        expected_row(first_source, offsets[0][1], 1, ObservedSegmentValue::Delete),
        expected_row(
            second_source,
            offsets[1][0],
            0,
            ObservedSegmentValue::Put(vec![0xca, 0xfe]),
        ),
        expected_row(
            second_source,
            offsets[1][1],
            2,
            ObservedSegmentValue::Merge(vec![0x22]),
        ),
    ];
    let before = snapshot(dir.path());
    let profile = ProofProfile {
        max_physical_file_bytes: lengths[0].max(lengths[1]),
        max_physical_visit_bytes: total - 1,
        ..PRODUCTION_COMPRESSED_PROOF_PROFILE
    };
    let mut rejected_rows = Vec::new();
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let error = visit_v4_segments_with_profile_and_hook_for_test(
            root,
            &manifest,
            budget,
            profile,
            |_| Ok(()),
            |row| {
                rejected_rows.push(row);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PraxisError::UnsupportedCatalogFeature {
                feature: "compressed v4 visit physical bytes exceed proof profile"
            }
        ));
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert_eq!(rejected_rows, expected_rows[..2]);
    assert!(rejected_rows.iter().all(|row| row.source.id == 1));
    assert_eq!(snapshot(dir.path()), before);

    let mut admitted_rows = Vec::new();
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let (witnesses, retained) = visit_v4_segments_with_profile_and_hook_for_test(
            root,
            &manifest,
            budget,
            ProofProfile {
                max_physical_visit_bytes: total,
                ..profile
            },
            |_| Ok(()),
            |row| {
                admitted_rows.push(row);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(witnesses.len(), 2);
        for (witness, meta) in witnesses.iter().zip(&manifest.segments) {
            let path = Path::new(&meta.path);
            let contents = fs::read(path).unwrap();
            assert_eq!(witness.source.id, meta.id);
            assert_eq!(
                witness.identity,
                physical_id(&File::open(path).unwrap(), path).unwrap()
            );
            assert_eq!(witness.len, contents.len() as u64);
            assert_eq!(witness.digest, blake3::hash(&contents));
            assert_eq!(witness.observed_rows, 2);
        }
        assert_eq!(balance - budget.remaining_bytes(), retained);
        drop(witnesses);
        budget.release(root, retained).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert_eq!(admitted_rows, expected_rows);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn literal_files_are_excluded_from_lz4_visitor_physical_cap() {
    for literal_first in [true, false] {
        let (dir, _config, lease, manifest) = mixed_literal_lz4_segments(literal_first);
        let root = lease.root();
        let paths = [
            Path::new(&manifest.segments[0].path),
            Path::new(&manifest.segments[1].path),
        ];
        let bytes = [fs::read(paths[0]).unwrap(), fs::read(paths[1]).unwrap()];
        assert_eq!(bytes[0][8], if literal_first { 0 } else { 1 });
        assert_eq!(bytes[1][8], if literal_first { 1 } else { 0 });
        for (path, contents) in paths.into_iter().zip(&bytes) {
            let decoded = decode_segment(contents, path, &CpuAccelerator).unwrap();
            assert_eq!(decoded.blocks.len(), 2);
            assert!(decoded.blocks.iter().all(|block| block.len() == 1));
        }
        let compressed_index = usize::from(literal_first);
        let compressed_len = bytes[compressed_index].len() as u64;
        assert!(compressed_len > 0);
        assert!(compressed_len <= PRODUCTION_COMPRESSED_PROOF_PROFILE.max_physical_file_bytes);
        let first_source = SegmentSource {
            level: 0,
            id: 1,
            manifest_ordinal: 0,
        };
        let second_source = SegmentSource {
            level: 1,
            id: 2,
            manifest_ordinal: 1,
        };
        let offsets = [two_block_offsets(paths[0]), two_block_offsets(paths[1])];
        let expected_rows = vec![
            expected_row(
                first_source,
                offsets[0][0],
                0,
                ObservedSegmentValue::Put(vec![0xca, 0xfe]),
            ),
            expected_row(first_source, offsets[0][1], 1, ObservedSegmentValue::Delete),
            expected_row(
                second_source,
                offsets[1][0],
                0,
                ObservedSegmentValue::Put(vec![0xca, 0xfe]),
            ),
            expected_row(
                second_source,
                offsets[1][1],
                2,
                ObservedSegmentValue::Merge(vec![0x22]),
            ),
        ];
        let before = snapshot(dir.path());
        let mut admitted_rows = Vec::new();
        with_wal_budget(root, &manifest, |budget| {
            let balance = budget.remaining_bytes();
            let (witnesses, retained) = visit_v4_segments_with_profile_and_hook_for_test(
                root,
                &manifest,
                budget,
                ProofProfile {
                    max_physical_visit_bytes: compressed_len,
                    ..PRODUCTION_COMPRESSED_PROOF_PROFILE
                },
                |_| Ok(()),
                |row| {
                    admitted_rows.push(row);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(witnesses.len(), 2);
            for (witness, meta) in witnesses.iter().zip(&manifest.segments) {
                let path = Path::new(&meta.path);
                let contents = fs::read(path).unwrap();
                assert_eq!(witness.source.id, meta.id);
                assert_eq!(
                    witness.identity,
                    physical_id(&File::open(path).unwrap(), path).unwrap()
                );
                assert_eq!(witness.len, contents.len() as u64);
                assert_eq!(witness.digest, blake3::hash(&contents));
                assert_eq!(witness.observed_rows, 2);
            }
            assert_eq!(balance - budget.remaining_bytes(), retained);
            drop(witnesses);
            budget.release(root, retained).unwrap();
            assert_eq!(budget.remaining_bytes(), balance);
        });
        assert_eq!(admitted_rows, expected_rows);
        let mut rejected_rows = Vec::new();
        with_wal_budget(root, &manifest, |budget| {
            let balance = budget.remaining_bytes();
            let error = visit_v4_segments_with_profile_and_hook_for_test(
                root,
                &manifest,
                budget,
                ProofProfile {
                    max_physical_visit_bytes: compressed_len - 1,
                    ..PRODUCTION_COMPRESSED_PROOF_PROFILE
                },
                |_| Ok(()),
                |row| {
                    rejected_rows.push(row);
                    Ok(())
                },
            )
            .unwrap_err();
            assert!(matches!(
                error,
                PraxisError::UnsupportedCatalogFeature {
                    feature: "compressed v4 visit physical bytes exceed proof profile"
                }
            ));
            assert_eq!(budget.remaining_bytes(), balance);
        });
        assert_eq!(
            rejected_rows,
            if literal_first {
                expected_rows[..2].to_vec()
            } else {
                Vec::new()
            }
        );
        assert!(rejected_rows.iter().all(|row| row.source.id == 1));
        assert_eq!(snapshot(dir.path()), before);
    }
}

#[test]
fn writer_valid_zstd_segments_preserve_reversed_manifest_ordinals_when_admitted() {
    assert_compressed_segment_provenance(Compression::Zstd, true);
}

#[test]
fn zstd_visitor_accepts_writer_valid_inline_put_over_one_mebibyte() {
    let (dir, config, lease, _) = two_segments(Compression::Zstd, false);
    let root = lease.root();
    let mut value = vec![0_u8; 1_100_000];
    blake3::Hasher::new().finalize_xof().fill(&mut value);
    let manifest = rewrite_first_segment(
        root,
        vec![row(0, StoredValue::Put(value.clone()))],
        Compression::Zstd,
        value.len() + 1,
        4096,
    );
    assert_eq!(manifest.format_version, 4);
    let first = manifest.segments.iter().find(|meta| meta.id == 1).unwrap();
    let path = Path::new(&first.path);
    let bytes = fs::read(path).unwrap();
    assert_eq!(bytes[8], 2);
    assert!(bytes.len() > 1_048_576);
    let (encoded, decoded_len, _) = writer_block_frame(&bytes, 21);
    assert!(encoded.len() > 1_048_576);
    assert!(decoded_len > 1_048_576 && decoded_len <= 8 * 1024 * 1024);
    let parsed = decode_segment(&bytes, path, &CpuAccelerator).unwrap();
    assert_eq!(parsed.blocks.len(), 1);
    assert_eq!(parsed.blocks[0].len(), 1);
    assert_eq!(
        parsed.blocks[0][0].entry.version.value,
        StoredValue::Put(value.clone())
    );
    assert_eq!(first.file_digest, blake3::hash(&bytes).to_hex().to_string());
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        assert_eq!(candidate.witnesses.len(), 2);
        assert_eq!(candidate.rows.len(), 3);
        assert_eq!(candidate.witnesses[0].source.id, 1);
        assert_eq!(candidate.witnesses[0].len, bytes.len() as u64);
        assert_eq!(candidate.witnesses[0].digest, blake3::hash(&bytes));
        assert_eq!(candidate.witnesses[0].observed_rows, 1);
        assert_eq!(
            candidate.rows[0],
            expected_row(
                SegmentSource {
                    level: 0,
                    id: 1,
                    manifest_ordinal: 0,
                },
                21,
                0,
                ObservedSegmentValue::Put(value.clone()),
            )
        );
        assert_eq!(
            balance - budget.remaining_bytes(),
            candidate.retained_witness_bytes()
        );
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert!(matches!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn mixed_literal_lz4_zstd_share_one_compressed_visit_ledger() {
    let (dir, config, lease, _) = two_segments(Compression::Lz4, false);
    let root = lease.root();
    let mut manifest = rewrite_first_segment(
        root,
        vec![
            row(0, StoredValue::Put(vec![0xca, 0xfe])),
            row(1, StoredValue::Delete),
        ],
        Compression::None,
        config.large_value_threshold,
        1,
    );
    let layout = DiskLayout::at(root);
    let value_path = layout.value_log_path(1);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let third = SegmentWriter::write(
        SegmentWriteOptions {
            path: &layout.segment_path(1, 3),
            id: 3,
            level: 1,
            compression: Compression::Zstd,
            accelerator: &CpuAccelerator,
            value_log: &mut value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: 1,
            partitioned_bloom: None,
            direct_io: false,
        },
        vec![
            row(0, StoredValue::Put(vec![0x33])),
            row(3, StoredValue::Delete),
        ],
    )
    .unwrap();
    drop(value_log);
    fs::remove_file(value_path).unwrap();
    manifest.segments.push(third);
    manifest.next_segment_id = 4;
    let manifest = save_strict_manifest(root, &manifest);
    assert_eq!(
        manifest.segments.iter().map(|m| m.id).collect::<Vec<_>>(),
        [1, 2, 3]
    );

    let paths = [
        Path::new(&manifest.segments[0].path),
        Path::new(&manifest.segments[1].path),
        Path::new(&manifest.segments[2].path),
    ];
    let bytes = [
        fs::read(paths[0]).unwrap(),
        fs::read(paths[1]).unwrap(),
        fs::read(paths[2]).unwrap(),
    ];
    assert_eq!([bytes[0][8], bytes[1][8], bytes[2][8]], [0, 1, 2]);
    for (path, contents) in paths.into_iter().zip(&bytes) {
        let parsed = decode_segment(contents, path, &CpuAccelerator).unwrap();
        assert_eq!(parsed.blocks.len(), 2);
        assert!(parsed.blocks.iter().all(|block| block.len() == 1));
    }
    let offsets = [
        two_block_offsets(paths[0]),
        two_block_offsets(paths[1]),
        two_block_offsets(paths[2]),
    ];
    let lengths = [bytes[1].len() as u64, bytes[2].len() as u64];
    let physical = lengths[0] + lengths[1];
    let decoded_files = [1_usize, 2_usize].map(|index| {
        offsets[index]
            .into_iter()
            .map(|offset| writer_block_frame(&bytes[index], offset).1)
            .sum::<u64>()
    });
    let decoded = decoded_files[0] + decoded_files[1];
    assert!(physical > 0 && decoded > 0);
    let profile = ProofProfile {
        max_physical_file_bytes: lengths[0].max(lengths[1]),
        max_physical_visit_bytes: physical,
        max_decoded_file_bytes: decoded_files[0].max(decoded_files[1]),
        max_decoded_visit_bytes: decoded,
        ..PRODUCTION_COMPRESSED_PROOF_PROFILE
    };
    let sources = [
        SegmentSource {
            level: 0,
            id: 1,
            manifest_ordinal: 0,
        },
        SegmentSource {
            level: 1,
            id: 2,
            manifest_ordinal: 1,
        },
        SegmentSource {
            level: 1,
            id: 3,
            manifest_ordinal: 2,
        },
    ];
    let expected_rows = vec![
        expected_row(
            sources[0],
            offsets[0][0],
            0,
            ObservedSegmentValue::Put(vec![0xca, 0xfe]),
        ),
        expected_row(sources[0], offsets[0][1], 1, ObservedSegmentValue::Delete),
        expected_row(
            sources[1],
            offsets[1][0],
            0,
            ObservedSegmentValue::Put(vec![0xca, 0xfe]),
        ),
        expected_row(
            sources[1],
            offsets[1][1],
            2,
            ObservedSegmentValue::Merge(vec![0x22]),
        ),
        expected_row(
            sources[2],
            offsets[2][0],
            0,
            ObservedSegmentValue::Put(vec![0x33]),
        ),
        expected_row(sources[2], offsets[2][1], 3, ObservedSegmentValue::Delete),
    ];
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let mut rows = Vec::new();
        let error = visit_v4_segments_with_profile_and_hook_for_test(
            root,
            &manifest,
            budget,
            ProofProfile {
                max_physical_visit_bytes: physical - 1,
                ..profile
            },
            |_| Ok(()),
            |row| {
                rows.push(row);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PraxisError::UnsupportedCatalogFeature {
                feature: "compressed v4 visit physical bytes exceed proof profile"
            }
        ));
        assert_eq!(rows, expected_rows[..4]);
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);

        rows.clear();
        let error = visit_v4_segments_with_profile_and_hook_for_test(
            root,
            &manifest,
            budget,
            ProofProfile {
                max_decoded_visit_bytes: decoded - 1,
                ..profile
            },
            |_| Ok(()),
            |row| {
                rows.push(row);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PraxisError::UnsupportedCatalogFeature {
                feature: "compressed v4 visit decoded bytes exceed proof profile"
            }
        ));
        assert_eq!(rows, expected_rows[..4]);
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);

        rows.clear();
        let (witnesses, retained) = visit_v4_segments_with_profile_and_hook_for_test(
            root,
            &manifest,
            budget,
            profile,
            |_| Ok(()),
            |row| {
                rows.push(row);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(rows, expected_rows);
        assert_eq!(witnesses.len(), 3);
        assert_eq!(
            witnesses.iter().map(|w| w.source).collect::<Vec<_>>(),
            sources
        );
        for (witness, meta) in witnesses.iter().zip(&manifest.segments) {
            let path = Path::new(&meta.path);
            let opened = File::open(path).unwrap();
            let contents = fs::read(path).unwrap();
            assert_eq!(witness.identity, physical_id(&opened, path).unwrap());
            assert_eq!(witness.len, contents.len() as u64);
            assert_eq!(witness.digest, blake3::hash(&contents));
            assert_eq!(witness.observed_rows, 2);
        }
        assert_eq!(balance - budget.remaining_bytes(), retained);
        drop(witnesses);
        budget.release(root, retained).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert!(matches!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn repaired_lz4_inner_size_mismatch_is_corrupt_before_callbacks() {
    let (dir, _config, lease, _) = two_segments(Compression::Lz4, false);
    let root = lease.root();
    let path = DiskLayout::at(root).segment_path(0, 1);
    let mut bytes = fs::read(&path).unwrap();
    assert_eq!(bytes[8], 1);
    let encoded_len = u32::from_le_bytes(bytes[21..25].try_into().unwrap()) as usize;
    let decoded_len = u32::from_le_bytes(bytes[25..29].try_into().unwrap());
    assert!(encoded_len >= 4);
    assert!(33 + encoded_len <= bytes.len());
    assert_eq!(
        u32::from_le_bytes(bytes[33..37].try_into().unwrap()),
        decoded_len
    );
    bytes[33..37].copy_from_slice(&(decoded_len + 1).to_le_bytes());
    let checksum = crc32c(&bytes[33..33 + encoded_len]);
    bytes[29..33].copy_from_slice(&checksum.to_le_bytes());
    assert!(matches!(
        decode_segment(&bytes, &path, &CpuAccelerator),
        Err(PraxisError::Corrupt { reason, .. })
            if reason == "LZ4 inner and segment lengths disagree"
    ));
    let manifest = replace_first_segment_bytes(root, &bytes);
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&bytes).to_hex().to_string()
    );
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let wal_balance = budget.remaining_bytes();
        let mut callbacks = 0;
        let error = visit_v4_segments(root, &manifest, budget, |_| {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(
            matches!(&error, PraxisError::Corrupt { path: error_path, .. }
            if error_path == &path),
            "{error}"
        );
        assert_eq!(callbacks, 0);
        assert_eq!(budget.remaining_bytes(), wal_balance);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn oversized_lz4_outer_decoded_claim_is_refused_before_allocation() {
    let (dir, _config, lease, _) = two_segments(Compression::Lz4, false);
    let root = lease.root();
    let path = DiskLayout::at(root).segment_path(0, 1);
    let mut bytes = fs::read(&path).unwrap();
    assert!(bytes.len() < 4096);
    assert_eq!(bytes[8], 1);
    bytes[25..29].copy_from_slice(&(8_u32 * 1024 * 1024 + 1).to_le_bytes());
    let manifest = replace_first_segment_bytes(root, &bytes);
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&bytes).to_hex().to_string()
    );
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let wal_balance = budget.remaining_bytes();
        let mut callbacks = 0;
        let error = visit_v4_segments(root, &manifest, budget, |_| {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(
            matches!(&error, PraxisError::UnsupportedCatalogFeature { feature }
            if feature.contains("decoded block")),
            "{error}"
        );
        assert_eq!(callbacks, 0);
        assert_eq!(budget.remaining_bytes(), wal_balance);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn bounded_lz4_helper_decodes_writer_blocks_and_charges_direct_fixture_work_once() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Lz4, false);
    let path = Path::new(&metadata[0].path);
    let bytes = fs::read(path).unwrap();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    work.admit_compressed_file(bytes.len() as u64, path)
        .unwrap();
    let mut scratch = ScratchLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let mut decoded = Vec::new();
    let mut facts = CompressedWorkFacts::default();
    let pass = work.first_pass();
    for (ordinal, offset) in two_block_offsets(path).into_iter().enumerate() {
        let (encoded, decoded_len, checksum) = writer_block_frame(&bytes, offset);
        facts = decode_bounded_block(
            BlockFrame {
                codec: Compression::Lz4,
                encoded,
                checksum,
                decoded_len,
            },
            &work,
            facts,
            pass,
            &mut decoded,
            &mut scratch,
            path,
        )
        .unwrap();
        let rows = decode_entries(&decoded, path).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].entry.cf.0, CATALOG_CF);
        assert_eq!(rows[0].entry.key.as_ref(), &[ordinal as u8]);
        assert_eq!(rows[0].entry.version.sequence, 2);
        facts = work.check_next_row(facts, pass, path).unwrap();
    }
    assert_eq!(facts.blocks, 2);
    assert_eq!(facts.rows, 2);
    // This ledger unit test commits known writer fixture facts directly. Only
    // the later same-handle scanner may claim a MANIFEST-authenticated pass.
    work.accept_authenticated_file(pass, facts, path).unwrap();
    assert_eq!(work.accepted(), facts);
    assert_eq!(work.compressed_physical_bytes(), bytes.len() as u64);
    assert_eq!(scratch.live_bytes(), decoded.capacity());
    let replay = work.replay_pass(facts).unwrap();
    let mut replay_facts = CompressedWorkFacts::default();
    for offset in two_block_offsets(path) {
        let (encoded, decoded_len, checksum) = writer_block_frame(&bytes, offset);
        replay_facts = decode_bounded_block(
            BlockFrame {
                codec: Compression::Lz4,
                encoded,
                checksum,
                decoded_len,
            },
            &work,
            replay_facts,
            replay,
            &mut decoded,
            &mut scratch,
            path,
        )
        .unwrap();
        replay_facts = work.check_next_row(replay_facts, replay, path).unwrap();
    }
    replay.require_exact_replay(replay_facts, path).unwrap();
    assert_eq!(work.accepted(), facts);
}

#[test]
fn bounded_lz4_helper_refuses_repaired_inner_size_and_outer_profile_before_output() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Lz4, false);
    let path = Path::new(&metadata[0].path);
    let bytes = fs::read(path).unwrap();
    let (encoded, outer, _checksum) = writer_block_frame(&bytes, 21);
    let mut repaired = encoded.to_vec();
    repaired[..4].copy_from_slice(&(u32::try_from(outer).unwrap() + 1).to_le_bytes());
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    work.admit_compressed_file(bytes.len() as u64, path)
        .unwrap();
    let mut scratch = ScratchLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let mut decoded = Vec::new();
    let pass = work.first_pass();
    let error = decode_bounded_block(
        BlockFrame {
            codec: Compression::Lz4,
            encoded: &repaired,
            checksum: crc32c(&repaired),
            decoded_len: outer,
        },
        &work,
        CompressedWorkFacts::default(),
        pass,
        &mut decoded,
        &mut scratch,
        path,
    )
    .unwrap_err();
    assert!(matches!(error, PraxisError::Corrupt { .. }));
    assert_eq!(decoded.capacity(), 0);
    assert_eq!(scratch.live_bytes(), 0);
    let error = decode_bounded_block(
        BlockFrame {
            codec: Compression::Lz4,
            encoded,
            checksum: crc32c(encoded),
            decoded_len: 8 * 1024 * 1024 + 1,
        },
        &work,
        CompressedWorkFacts::default(),
        pass,
        &mut decoded,
        &mut scratch,
        path,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        PraxisError::UnsupportedCatalogFeature { feature } if feature.contains("decoded block")
    ));
    assert_eq!(decoded.capacity(), 0);
    assert_eq!(scratch.live_bytes(), 0);
    assert_eq!(work.accepted(), CompressedWorkFacts::default());
}

#[test]
fn private_lz4_pass1_authenticates_writer_blocks_without_exposing_rows() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Lz4, false);
    let path = Path::new(&metadata[0].path);
    let bytes = fs::read(path).unwrap();
    let expected_decoded: u64 = two_block_offsets(path)
        .into_iter()
        .map(|offset| writer_block_frame(&bytes, offset).1)
        .sum();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let mut probes = Vec::new();
    let pass = direct_lz4_pass1(&metadata[0], &mut work, |event| probes.push(event)).unwrap();
    assert_eq!(pass.len, bytes.len() as u64);
    assert_eq!(pass.digest, blake3::hash(&bytes));
    assert_eq!(pass.work.decoded_bytes, expected_decoded);
    assert_eq!(pass.work.blocks, 2);
    assert_eq!(pass.work.rows, 2);
    assert_eq!(work.accepted(), CompressedWorkFacts::default());
    assert_eq!(work.compressed_physical_bytes(), pass.len);
    assert_eq!(
        probes,
        vec![
            Lz4PassProbe::AfterFooterPreread,
            Lz4PassProbe::AfterContiguousRead {
                digest: pass.digest
            }
        ]
    );
}

#[test]
fn private_lz4_pass2_rebuilds_writer_blooms_without_charging_two_files_twice() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Lz4, false);
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let mut expected_physical = 0;
    for (ordinal, meta) in metadata.iter().enumerate() {
        let path = Path::new(&meta.path);
        let bytes = fs::read(path).unwrap();
        let file = File::open(path).unwrap();
        let original_identity = physical_id(&file, path).unwrap();
        drop(file);

        let first = scan_lz4_pass1(path, original_identity, meta, &mut work, |_| {}).unwrap();
        assert_eq!(first.work.blocks, 2);
        assert_eq!(first.work.rows, 2);
        assert_eq!(first.digest, blake3::hash(&bytes));
        let first_context = work.first_pass();
        work.accept_authenticated_file(first_context, first.work, path)
            .unwrap();
        expected_physical += first.len;
        let accepted_before_replay = work.accepted();
        let physical_before_replay = work.compressed_physical_bytes();
        assert_eq!(physical_before_replay, expected_physical);
        assert_eq!(
            accepted_before_replay.rows,
            if ordinal == 0 { 2 } else { 4 }
        );
        if ordinal == 1 {
            assert!(accepted_before_replay.rows > first.work.rows);
        }

        let mut probes = Vec::new();
        let replay = scan_lz4_pass2(path, original_identity, meta, &work, first, |event| {
            probes.push(event)
        })
        .unwrap();
        assert_eq!(replay, first);
        assert_eq!(work.accepted(), accepted_before_replay);
        assert_eq!(work.compressed_physical_bytes(), physical_before_replay);
        assert_eq!(
            probes,
            vec![
                Lz4PassProbe::AfterFooterPreread,
                Lz4PassProbe::AfterContiguousRead {
                    digest: first.digest
                }
            ]
        );
    }
    assert_eq!(work.accepted().rows, 4);
}

#[test]
fn private_lz4_pass3_emits_owned_rows_without_recharging_two_files() {
    let (dir, _config, lease, metadata) = two_segments(Compression::Lz4, true);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(
        manifest
            .segments
            .iter()
            .map(|meta| meta.id)
            .collect::<Vec<_>>(),
        [2, 1]
    );
    let before = snapshot(dir.path());
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let mut rows = Vec::new();
    let mut expected_rows = Vec::new();
    let mut expected_physical = 0;
    let mut expected_decoded = 0;

    for (index, meta) in metadata.iter().enumerate() {
        let path = Path::new(&meta.path);
        let bytes = fs::read(path).unwrap();
        let offsets = two_block_offsets(path);
        let expected_file_decoded: u64 = offsets
            .into_iter()
            .map(|offset| writer_block_frame(&bytes, offset).1)
            .sum();
        let opened = File::open(path).unwrap();
        let identity = physical_id(&opened, path).unwrap();
        drop(opened);
        let source = SegmentSource {
            level: meta.level,
            id: meta.id,
            manifest_ordinal: 1 - index,
        };
        assert_eq!(manifest.segments[source.manifest_ordinal].id, meta.id);
        assert_eq!(manifest.segments[source.manifest_ordinal].path, meta.path);
        assert_eq!(meta.file_digest, blake3::hash(&bytes).to_hex().to_string());

        let first = scan_lz4_pass1(path, identity, meta, &mut work, |_| {}).unwrap();
        assert_eq!(first.len, bytes.len() as u64);
        assert_eq!(first.digest, blake3::hash(&bytes));
        assert_eq!(
            first.work,
            CompressedWorkFacts {
                decoded_bytes: expected_file_decoded,
                blocks: 2,
                rows: 2,
            }
        );
        let first_context = work.first_pass();
        work.accept_authenticated_file(first_context, first.work, path)
            .unwrap();
        expected_physical += bytes.len() as u64;
        expected_decoded += expected_file_decoded;
        let replay = scan_lz4_pass2(path, identity, meta, &work, first, |_| {}).unwrap();
        assert_eq!(replay, first);
        let accepted_before_pass3 = work.accepted();
        let physical_before_pass3 = work.compressed_physical_bytes();
        if index == 1 {
            assert_eq!(accepted_before_pass3.rows, 4);
            assert!(accepted_before_pass3.rows > first.work.rows);
        }

        let third = scan_lz4_pass3(path, identity, meta, source, &work, first, |row| {
            rows.push(row);
            Ok(())
        })
        .unwrap();
        assert_eq!(third, first);
        assert_eq!(work.accepted(), accepted_before_pass3);
        assert_eq!(work.compressed_physical_bytes(), physical_before_pass3);
        let reopened = File::open(path).unwrap();
        assert_eq!(physical_id(&reopened, path).unwrap(), identity);
        assert_eq!(fs::read(path).unwrap(), bytes);

        expected_rows.push(expected_row(
            source,
            offsets[0],
            0,
            ObservedSegmentValue::Put(vec![0xca, 0xfe]),
        ));
        expected_rows.push(expected_row(
            source,
            offsets[1],
            if index == 0 { 1 } else { 2 },
            if index == 0 {
                ObservedSegmentValue::Delete
            } else {
                ObservedSegmentValue::Merge(vec![0x22])
            },
        ));
    }

    assert_eq!(rows, expected_rows);
    let (ObservedSegmentValue::Put(first), ObservedSegmentValue::Put(second)) =
        (&rows[0].value, &rows[2].value)
    else {
        panic!("both files must contribute owned Put values")
    };
    assert_ne!(first.as_ptr(), second.as_ptr());
    assert_eq!(work.compressed_physical_bytes(), expected_physical);
    assert_eq!(
        work.accepted(),
        CompressedWorkFacts {
            decoded_bytes: expected_decoded,
            blocks: 4,
            rows: 4,
        }
    );
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_lz4_pass3_emits_writer_valid_inline_put_over_one_mebibyte() {
    let (dir, _config, lease, metadata) = two_segments(Compression::Lz4, false);
    let root = lease.root();
    let path = Path::new(&metadata[0].path);
    let mut value = vec![0_u8; 1_100_000];
    blake3::Hasher::new().finalize_xof().fill(&mut value);
    let value_path = DiskLayout::at(root).value_log_path(1);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let meta = SegmentWriter::write(
        SegmentWriteOptions {
            path,
            id: 1,
            level: 0,
            compression: Compression::Lz4,
            accelerator: &CpuAccelerator,
            value_log: &mut value_log,
            large_value_threshold: value.len() + 1,
            block_size: 4096,
            partitioned_bloom: None,
            direct_io: false,
        },
        vec![row(0, StoredValue::Put(value.clone()))],
    )
    .unwrap();
    drop(value_log);
    let before = snapshot(dir.path());
    let bytes = fs::read(path).unwrap();
    assert!(bytes.len() > 1_048_576);
    assert!(writer_block_frame(&bytes, 21).1 > 1_048_576);
    let opened = File::open(path).unwrap();
    let identity = physical_id(&opened, path).unwrap();
    drop(opened);
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let first = scan_lz4_pass1(path, identity, &meta, &mut work, |_| {}).unwrap();
    assert_eq!(first.len, bytes.len() as u64);
    assert_eq!(first.digest, blake3::hash(&bytes));
    assert_eq!(first.work.rows, 1);
    assert_eq!(first.work.blocks, 1);
    let first_context = work.first_pass();
    work.accept_authenticated_file(first_context, first.work, path)
        .unwrap();
    let second = scan_lz4_pass2(path, identity, &meta, &work, first, |_| {}).unwrap();
    assert_eq!(second, first);
    let accepted = work.accepted();
    let physical = work.compressed_physical_bytes();
    let source = SegmentSource {
        level: 0,
        id: 1,
        manifest_ordinal: 0,
    };
    let mut rows = Vec::new();
    let third = scan_lz4_pass3(path, identity, &meta, source, &work, first, |row| {
        rows.push(row);
        Ok(())
    })
    .unwrap();
    assert_eq!(third, first);
    assert_eq!(
        rows,
        [expected_row(
            source,
            21,
            0,
            ObservedSegmentValue::Put(value)
        )]
    );
    assert_eq!(work.accepted(), accepted);
    assert_eq!(work.compressed_physical_bytes(), physical);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_lz4_pass3_preflights_entire_two_row_block_against_file_and_visit_caps() {
    let (dir, config, lease, _) = two_segments(Compression::Lz4, false);
    let root = lease.root();
    let manifest = rewrite_first_segment(
        root,
        vec![
            row(0, StoredValue::Put(vec![0xca, 0xfe])),
            row(1, StoredValue::Delete),
        ],
        Compression::Lz4,
        config.large_value_threshold,
        4096,
    );
    let target = &manifest.segments[0];
    assert_eq!(target.id, 1);
    assert_eq!(target.entries, 2);
    let path = Path::new(&target.path);
    let bytes = fs::read(path).unwrap();
    assert_eq!(bytes[8], 1);
    let decoded = decode_segment(&bytes, path, &CpuAccelerator).unwrap();
    assert_eq!(decoded.blocks.len(), 1);
    assert_eq!(decoded.blocks[0].len(), 2);
    let identity = physical_id(&File::open(path).unwrap(), path).unwrap();
    let source = SegmentSource {
        level: target.level,
        id: target.id,
        manifest_ordinal: 0,
    };
    let before = snapshot(dir.path());

    let mut file_limited = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let first = scan_lz4_pass1(path, identity, target, &mut file_limited, |_| {}).unwrap();
    assert_eq!(first.work.rows, 2);
    assert_eq!(first.work.blocks, 1);
    let first_context = file_limited.first_pass();
    file_limited
        .accept_authenticated_file(first_context, first.work, path)
        .unwrap();
    assert_eq!(
        scan_lz4_pass2(path, identity, target, &file_limited, first, |_| {}).unwrap(),
        first
    );
    let accepted = file_limited.accepted();
    let physical = file_limited.compressed_physical_bytes();
    assert_eq!(accepted.rows, 2);
    assert_eq!(physical, bytes.len() as u64);
    file_limited.lower_row_caps_for_test(1, PRODUCTION_COMPRESSED_PROOF_PROFILE.max_rows_visit);
    let mut callbacks = 0;
    let error = scan_lz4_pass3(path, identity, target, source, &file_limited, first, |_| {
        callbacks += 1;
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(
        error,
        PraxisError::UnsupportedCatalogFeature {
            feature: "compressed v4 file row count exceeds proof profile"
        }
    ));
    assert_eq!(callbacks, 0);
    assert_eq!(file_limited.accepted(), accepted);
    assert_eq!(file_limited.compressed_physical_bytes(), physical);
    assert_eq!(
        physical_id(&File::open(path).unwrap(), path).unwrap(),
        identity
    );
    assert_eq!(snapshot(dir.path()), before);

    // A second authenticated file gives pass 3 a nonzero visit baseline.
    let prior = &manifest.segments[1];
    assert_eq!(prior.id, 2);
    let prior_path = Path::new(&prior.path);
    let prior_identity = physical_id(&File::open(prior_path).unwrap(), prior_path).unwrap();
    let mut visit_limited = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let prior_first = scan_lz4_pass1(
        prior_path,
        prior_identity,
        prior,
        &mut visit_limited,
        |_| {},
    )
    .unwrap();
    assert_eq!(prior_first.work.rows, 2);
    let prior_context = visit_limited.first_pass();
    visit_limited
        .accept_authenticated_file(prior_context, prior_first.work, prior_path)
        .unwrap();
    assert_eq!(
        scan_lz4_pass2(
            prior_path,
            prior_identity,
            prior,
            &visit_limited,
            prior_first,
            |_| {},
        )
        .unwrap(),
        prior_first
    );
    assert_eq!(visit_limited.accepted().rows, 2);
    let target_first = scan_lz4_pass1(path, identity, target, &mut visit_limited, |_| {}).unwrap();
    let target_context = visit_limited.first_pass();
    visit_limited
        .accept_authenticated_file(target_context, target_first.work, path)
        .unwrap();
    assert_eq!(
        scan_lz4_pass2(path, identity, target, &visit_limited, target_first, |_| {}).unwrap(),
        target_first
    );
    let accepted = visit_limited.accepted();
    let physical = visit_limited.compressed_physical_bytes();
    assert_eq!(accepted.rows, 4);
    assert_eq!(
        physical,
        bytes.len() as u64 + fs::metadata(prior_path).unwrap().len()
    );
    visit_limited.lower_row_caps_for_test(PRODUCTION_COMPRESSED_PROOF_PROFILE.max_rows_file, 3);
    let mut callbacks = 0;
    let error = scan_lz4_pass3(
        path,
        identity,
        target,
        source,
        &visit_limited,
        target_first,
        |_| {
            callbacks += 1;
            Ok(())
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        PraxisError::UnsupportedCatalogFeature {
            feature: "compressed v4 visit row count exceeds proof profile"
        }
    ));
    assert_eq!(callbacks, 0);
    assert_eq!(visit_limited.accepted(), accepted);
    assert_eq!(visit_limited.compressed_physical_bytes(), physical);
    assert_eq!(
        physical_id(&File::open(path).unwrap(), path).unwrap(),
        identity
    );
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_lz4_pass3_rejects_byte_identical_replacement_before_callbacks() {
    let (_dir, _config, lease, metadata) = two_segments(Compression::Lz4, false);
    let root = lease.root();
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let original_manifest = fs::read(&manifest_path).unwrap();
    let opened = File::open(path).unwrap();
    let original_identity = physical_id(&opened, path).unwrap();
    drop(opened);
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let first = scan_lz4_pass1(path, original_identity, &metadata[0], &mut work, |_| {}).unwrap();
    assert_eq!(first.digest, blake3::hash(&original));
    let first_context = work.first_pass();
    work.accept_authenticated_file(first_context, first.work, path)
        .unwrap();
    assert_eq!(
        scan_lz4_pass2(path, original_identity, &metadata[0], &work, first, |_| {}).unwrap(),
        first
    );

    // Create B while A still exists so the replacement has a distinct file ID.
    let replacement = path.with_extension("pass3-replacement");
    fs::write(&replacement, &original).unwrap();
    let replacement_file = File::open(&replacement).unwrap();
    assert_ne!(
        physical_id(&replacement_file, &replacement).unwrap(),
        original_identity
    );
    drop(replacement_file);
    fs::remove_file(path).unwrap();
    fs::rename(&replacement, path).unwrap();
    assert_eq!(fs::read(path).unwrap(), original);
    assert_eq!(fs::read(&manifest_path).unwrap(), original_manifest);
    let manifest = Manifest::decode(&original_manifest, &manifest_path).unwrap();
    assert_eq!(manifest.format_version, 4);
    assert_eq!(manifest.segments[0].path, metadata[0].path);
    assert_eq!(manifest.segments[0].file_digest, metadata[0].file_digest);
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&original).to_hex().to_string()
    );
    let current = File::open(path).unwrap();
    assert_ne!(physical_id(&current, path).unwrap(), original_identity);
    drop(current);

    let accepted = work.accepted();
    let physical = work.compressed_physical_bytes();
    let mut callbacks = 0;
    let source = SegmentSource {
        level: 0,
        id: 1,
        manifest_ordinal: 0,
    };
    let error = scan_lz4_pass3(
        path,
        original_identity,
        &metadata[0],
        source,
        &work,
        first,
        |_| {
            callbacks += 1;
            Ok(())
        },
    )
    .unwrap_err();
    assert!(
        matches!(&error, PraxisError::Corrupt { path: error_path, reason }
        if error_path.as_path() == path && reason.contains("identity") && reason.contains("changed")),
        "{error}"
    );
    assert_eq!(callbacks, 0);
    assert_eq!(work.accepted(), accepted);
    assert_eq!(work.compressed_physical_bytes(), physical);
    assert_eq!(fs::read(path).unwrap(), original);
    assert_eq!(fs::read(manifest_path).unwrap(), original_manifest);
}

#[test]
fn private_lz4_pass3_rejects_parser_integrated_digest_after_first_callback_aba() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Lz4, false);
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    let changed = same_length_lz4_value_variant(&original, path);
    assert_eq!(changed.len(), original.len());
    assert_ne!(changed, original);
    let decoded_b = decode_segment(&changed, path, &CpuAccelerator).unwrap();
    assert_eq!(decoded_b.blocks.len(), 2);
    let expected_b_value = match &decoded_b.blocks[0][0].entry.version.value {
        StoredValue::Put(value) => value.clone(),
        other => panic!("variant must hold an inline Put, got {other:?}"),
    };
    assert_ne!(expected_b_value, [0xca, 0xfe]);
    assert_eq!(
        metadata[0].file_digest,
        blake3::hash(&original).to_hex().to_string()
    );
    let opened = File::open(path).unwrap();
    let identity = physical_id(&opened, path).unwrap();
    drop(opened);
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let first = scan_lz4_pass1(path, identity, &metadata[0], &mut work, |_| {}).unwrap();
    assert_eq!(first.digest, blake3::hash(&original));
    let first_context = work.first_pass();
    work.accept_authenticated_file(first_context, first.work, path)
        .unwrap();
    assert_eq!(
        scan_lz4_pass2(path, identity, &metadata[0], &work, first, |_| {}).unwrap(),
        first
    );
    let accepted = work.accepted();
    let physical = work.compressed_physical_bytes();
    let mut writer = OpenOptions::new().write(true).open(path).unwrap();
    writer.seek(SeekFrom::Start(0)).unwrap();
    writer.write_all(&changed).unwrap();
    writer.sync_all().unwrap();
    assert_eq!(fs::read(path).unwrap(), changed);
    let changed_handle = File::open(path).unwrap();
    assert_eq!(physical_id(&changed_handle, path).unwrap(), identity);
    drop(changed_handle);

    let source = SegmentSource {
        level: 0,
        id: 1,
        manifest_ordinal: 0,
    };
    let mut saw_b = false;
    let error = scan_lz4_pass3(path, identity, &metadata[0], source, &work, first, |row| {
        if !saw_b {
            assert_eq!(row.source, source);
            assert_eq!(row.block_offset, 21);
            assert_eq!(row.row_ordinal, 0);
            assert_eq!(row.key, [0]);
            assert_eq!(
                row.value,
                ObservedSegmentValue::Put(expected_b_value.clone())
            );
            saw_b = true;
            writer.seek(SeekFrom::Start(0)).unwrap();
            writer.write_all(&original).unwrap();
            writer.sync_all().unwrap();
            assert_eq!(fs::read(path).unwrap(), original);
        }
        Ok(())
    })
    .unwrap_err();
    assert!(
        saw_b,
        "pass 3 did not callback with the independently decoded B row: {error}"
    );
    assert!(
        matches!(&error, PraxisError::Corrupt { path: error_path, reason }
        if error_path.as_path() == path && reason.contains("integrated") && reason.contains("digest")),
        "{error}"
    );
    assert_eq!(work.accepted(), accepted);
    assert_eq!(work.compressed_physical_bytes(), physical);
    drop(writer);
    assert_eq!(fs::read(path).unwrap(), original);
    let restored = File::open(path).unwrap();
    assert_eq!(physical_id(&restored, path).unwrap(), identity);
}

#[test]
fn private_lz4_pass2_rejects_legal_manifest_bloom_bit_change() {
    let (dir, _config, lease, metadata) = two_segments(Compression::Lz4, false);
    let root = lease.root();
    let path = Path::new(&metadata[0].path);
    let original_bytes = fs::read(path).unwrap();
    let mut wire = serde_json::to_value(&metadata[0].bloom_filter).unwrap();
    let original_bit_count = wire["bit_count"].clone();
    let original_hash_count = wire["hash_count"].clone();
    let original_word_count = wire["bits"].as_array().unwrap().len();
    let word = wire["bits"][0].as_u64().unwrap();
    wire["bits"][0] = serde_json::Value::from(word ^ 1);
    assert_eq!(wire["bit_count"], original_bit_count);
    assert_eq!(wire["hash_count"], original_hash_count);
    assert_eq!(wire["bits"].as_array().unwrap().len(), original_word_count);
    assert_eq!((word ^ wire["bits"][0].as_u64().unwrap()).count_ones(), 1);
    let changed_bloom: BloomFilter = serde_json::from_value(wire).unwrap();
    assert_ne!(changed_bloom, metadata[0].bloom_filter);

    let manifest_path = DiskLayout::at(root).manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    manifest.segments[0].bloom_filter = changed_bloom.clone();
    let saved = save_strict_manifest(root, &manifest);
    let altered = &saved.segments[0];
    assert_eq!(altered.bloom_filter, changed_bloom);
    assert_eq!(altered.file_digest, metadata[0].file_digest);
    assert_eq!(fs::read(path).unwrap(), original_bytes);

    let file = File::open(path).unwrap();
    let original_identity = physical_id(&file, path).unwrap();
    drop(file);
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let first = scan_lz4_pass1(path, original_identity, altered, &mut work, |_| {}).unwrap();
    assert_eq!(first.digest, blake3::hash(&original_bytes));
    let first_context = work.first_pass();
    work.accept_authenticated_file(first_context, first.work, path)
        .unwrap();
    let accepted_before_replay = work.accepted();
    let physical_before_replay = work.compressed_physical_bytes();
    let tree_before_replay = snapshot(dir.path());
    let error = scan_lz4_pass2(path, original_identity, altered, &work, first, |_| {}).unwrap_err();
    assert!(matches!(
        error,
        PraxisError::Corrupt { reason, .. }
            if reason == "compressed v4 observed Bloom disagrees with MANIFEST"
    ));
    assert_eq!(work.accepted(), accepted_before_replay);
    assert_eq!(work.compressed_physical_bytes(), physical_before_replay);
    assert_eq!(snapshot(dir.path()), tree_before_replay);
}

#[test]
fn private_lz4_passes_accept_writer_valid_block_and_file_over_one_mebibyte() {
    let (_dir, _config, lease, metadata) = two_segments(Compression::Lz4, false);
    let root = lease.root();
    let path = Path::new(&metadata[0].path);
    let mut value = vec![0_u8; 1_100_000];
    blake3::Hasher::new().finalize_xof().fill(&mut value);
    let value_path = DiskLayout::at(root).value_log_path(1);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let meta = SegmentWriter::write(
        SegmentWriteOptions {
            path,
            id: 1,
            level: 0,
            compression: Compression::Lz4,
            accelerator: &CpuAccelerator,
            value_log: &mut value_log,
            large_value_threshold: value.len() + 1,
            block_size: 4096,
            partitioned_bloom: None,
            direct_io: false,
        },
        vec![row(0, StoredValue::Put(value))],
    )
    .unwrap();
    drop(value_log);
    let bytes = fs::read(path).unwrap();
    assert!(bytes.len() > 1_048_576);
    assert!(writer_block_frame(&bytes, 21).1 > 1_048_576);
    let file = File::open(path).unwrap();
    let identity = physical_id(&file, path).unwrap();
    drop(file);
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let pass = scan_lz4_pass1(path, identity, &meta, &mut work, |_| {}).unwrap();
    assert_eq!(pass.work.rows, 1);
    assert_eq!(pass.work.blocks, 1);
    assert_eq!(pass.digest, blake3::hash(&bytes));
    assert_eq!(work.accepted(), CompressedWorkFacts::default());

    let first_context = work.first_pass();
    work.accept_authenticated_file(first_context, pass.work, path)
        .unwrap();
    let accepted = work.accepted();
    let physical = work.compressed_physical_bytes();
    let replay = scan_lz4_pass2(path, identity, &meta, &work, pass, |_| {}).unwrap();
    assert_eq!(replay, pass);
    assert_eq!(work.accepted(), accepted);
    assert_eq!(work.compressed_physical_bytes(), physical);
}

#[test]
fn private_lz4_pass2_precharges_bloom_words_before_allocation_and_releases_them() {
    let path = Path::new("compressed-bloom-test.tseg");
    let maximum_bits_allowance = 16 * 1024 * 1024 + 128;
    let mut short = ScratchLedger::new(ProofProfile {
        max_parser_owned_peak_bytes: maximum_bits_allowance - 1,
        ..PRODUCTION_COMPRESSED_PROOF_PROFILE
    });
    assert!(matches!(
        short.reserve_observed_bloom(0, path),
        Err(PraxisError::UnsupportedCatalogFeature { .. })
    ));
    assert_eq!(short.live_bytes(), 0);

    let mut exact = ScratchLedger::new(ProofProfile {
        max_parser_owned_peak_bytes: maximum_bits_allowance,
        ..PRODUCTION_COMPRESSED_PROOF_PROFILE
    });
    let bloom = exact.reserve_observed_bloom(0, path).unwrap();
    assert!(exact.live_bytes() > 0);
    assert!(exact.live_bytes() <= maximum_bits_allowance);
    exact.release_observed_bloom(bloom, path).unwrap();
    assert_eq!(exact.live_bytes(), 0);

    let mut impossible = ScratchLedger::new(ProofProfile {
        max_rows_file: u64::MAX,
        ..PRODUCTION_COMPRESSED_PROOF_PROFILE
    });
    assert!(matches!(
        impossible.reserve_observed_bloom(0, path),
        Err(PraxisError::UnsupportedCatalogFeature { .. })
    ));
    assert_eq!(impossible.live_bytes(), 0);
}

#[test]
fn private_lz4_pass1_distinguishes_impossible_footer_from_possible_overcap_count() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Lz4, false);
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    let trailer_start = original.len() - 12;
    let footer_len = u32::from_le_bytes(
        original[trailer_start..trailer_start + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let footer_start = trailer_start - footer_len;
    let mut impossible = original[footer_start..trailer_start].to_vec();
    impossible[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(path, replace_lz4_footer(&original, &impossible)).unwrap();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    assert!(matches!(
        direct_lz4_pass1(&metadata[0], &mut work, |_| {}),
        Err(PraxisError::Corrupt { reason, .. }) if reason == "compressed v4 block count exceeds footer"
    ));

    let count = 65_537_u32;
    let mut possible = vec![0_u8; 4 + count as usize * 24];
    possible[..4].copy_from_slice(&count.to_le_bytes());
    let enlarged = replace_lz4_footer(&original, &possible);
    fs::write(path, &enlarged).unwrap();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    assert!(matches!(
        direct_lz4_pass1(&metadata[0], &mut work, |_| {}),
        Err(PraxisError::UnsupportedCatalogFeature { feature })
            if feature == "compressed v4 block count exceeds proof profile"
    ));
    assert!(enlarged.len() < 8 * 1024 * 1024);
}

#[test]
fn private_lz4_pass1_refuses_outer_claim_before_decode_and_repaired_inner_size() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Lz4, false);
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    let mut outer = original.clone();
    outer[25..29].copy_from_slice(&(8_u32 * 1024 * 1024 + 1).to_le_bytes());
    fs::write(path, &outer).unwrap();
    let mut meta = metadata[0].clone();
    meta.file_digest = blake3::hash(&outer).to_hex().to_string();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    assert!(matches!(
        direct_lz4_pass1(&meta, &mut work, |_| {}),
        Err(PraxisError::UnsupportedCatalogFeature { feature })
            if feature.contains("decoded block")
    ));
    assert_eq!(work.accepted(), CompressedWorkFacts::default());

    let mut inner = original;
    let encoded_len = u32::from_le_bytes(inner[21..25].try_into().unwrap()) as usize;
    let decoded_len = u32::from_le_bytes(inner[25..29].try_into().unwrap());
    inner[33..37].copy_from_slice(&(decoded_len + 1).to_le_bytes());
    let checksum = crc32c(&inner[33..33 + encoded_len]);
    inner[29..33].copy_from_slice(&checksum.to_le_bytes());
    fs::write(path, &inner).unwrap();
    meta.file_digest = blake3::hash(&inner).to_hex().to_string();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    assert!(matches!(
        direct_lz4_pass1(&meta, &mut work, |_| {}),
        Err(PraxisError::Corrupt { reason, .. })
            if reason == "compressed v4 LZ4 inner and outer lengths disagree"
    ));
    assert_eq!(work.accepted(), CompressedWorkFacts::default());
}

#[test]
fn private_lz4_pass1_rejects_repaired_offset_and_decoded_row_count() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Lz4, false);
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    let trailer_start = original.len() - 12;
    let footer_len = u32::from_le_bytes(
        original[trailer_start..trailer_start + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let footer_start = trailer_start - footer_len;
    let mut footer = original[footer_start..trailer_start].to_vec();
    let mut index = BinaryReader::new(&footer, path);
    assert_eq!(index.read_u32().unwrap(), 2);
    index.read_len_slice().unwrap();
    index.read_len_slice().unwrap();
    let offset_position = index.position();
    drop(index);
    footer[offset_position..offset_position + 8].copy_from_slice(&22_u64.to_le_bytes());
    let changed = replace_lz4_footer(&original, &footer);
    fs::write(path, &changed).unwrap();
    let mut meta = metadata[0].clone();
    meta.file_digest = blake3::hash(&changed).to_hex().to_string();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    assert!(matches!(
        direct_lz4_pass1(&meta, &mut work, |_| {}),
        Err(PraxisError::Corrupt { reason, .. }) if reason == "compressed v4 block is not contiguous"
    ));

    let (encoded, _, _) = writer_block_frame(&original, 21);
    let mut decoded = decode_block(Compression::Lz4, encoded).unwrap();
    decoded[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    let recompressed = lz4_flex::compress_prepend_size(&decoded);
    let mut single = BinaryWriter::new();
    single.write_bytes(&original[..21]);
    single.write_u32(recompressed.len() as u32);
    single.write_u32(decoded.len() as u32);
    single.write_u32(crc32c(&recompressed));
    single.write_bytes(&recompressed);
    let mut one_footer = BinaryWriter::new();
    one_footer.write_u32(1);
    one_footer.write_len_bytes(&[0]);
    one_footer.write_len_bytes(&[0]);
    one_footer.write_u64(21);
    one_footer.write_u64(12 + recompressed.len() as u64);
    let one_footer = one_footer.into_inner();
    single.write_bytes(&one_footer);
    single.write_u32(one_footer.len() as u32);
    single.write_u32(crc32c(&one_footer));
    single.write_u32(crate::segments::format::SEGMENT_FOOTER_MAGIC);
    let single = single.into_inner();
    fs::write(path, &single).unwrap();
    meta.entries = 1;
    meta.max_key = vec![0];
    meta.file_digest = blake3::hash(&single).to_hex().to_string();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    assert!(matches!(
        direct_lz4_pass1(&meta, &mut work, |_| {}),
        Err(PraxisError::Corrupt { reason, .. }) if reason == "compressed v4 row count exceeds block"
    ));
}

#[test]
fn private_lz4_pass1_rejects_same_handle_aba_by_integrated_digest() {
    let (dir, _config, _lease, metadata) = two_segments(Compression::Lz4, false);
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    let changed = same_length_lz4_value_variant(&original, path);
    assert_eq!(original.len(), changed.len());
    assert_ne!(blake3::hash(&original), blake3::hash(&changed));
    assert_eq!(
        metadata[0].file_digest,
        blake3::hash(&original).to_hex().to_string()
    );
    let before = snapshot(dir.path());
    let identity = file_id(path);
    let mut writer = OpenOptions::new().write(true).open(path).unwrap();
    let first_len = writer_block_frame(&original, 21).0.len() + 12;
    let mut observed_digest = None;
    let mut preread_count = 0;
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let error = direct_lz4_pass1(&metadata[0], &mut work, |event| match event {
        Lz4PassProbe::AfterFooterPreread => {
            preread_count += 1;
            assert_eq!(fs::read(path).unwrap(), original);
            writer.seek(SeekFrom::Start(21)).unwrap();
            writer.write_all(&changed[21..21 + first_len]).unwrap();
            writer.sync_data().unwrap();
            assert_eq!(fs::read(path).unwrap(), changed);
            assert_eq!(file_id(path), identity);
        }
        Lz4PassProbe::AfterContiguousRead { digest } => {
            assert_eq!(digest, blake3::hash(&changed));
            observed_digest = Some(digest);
            writer.seek(SeekFrom::Start(21)).unwrap();
            writer.write_all(&original[21..21 + first_len]).unwrap();
            writer.sync_data().unwrap();
            assert_eq!(fs::read(path).unwrap(), original);
            assert_eq!(file_id(path), identity);
        }
    })
    .unwrap_err();
    assert!(matches!(
        error,
        PraxisError::Corrupt { reason, .. }
            if reason == "compressed v4 integrated pass digest mismatch"
    ));
    assert_eq!(preread_count, 1);
    assert_eq!(observed_digest, Some(blake3::hash(&changed)));
    assert_eq!(work.accepted(), CompressedWorkFacts::default());
    assert_eq!(fs::read(path).unwrap(), original);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_lz4_pass2_rejects_same_handle_aba_before_bloom_comparison() {
    let (dir, _config, _lease, metadata) = two_segments(Compression::Lz4, false);
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    let changed = same_length_lz4_value_variant(&original, path);
    assert_eq!(original.len(), changed.len());
    let file = File::open(path).unwrap();
    let identity = physical_id(&file, path).unwrap();
    drop(file);
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let first = scan_lz4_pass1(path, identity, &metadata[0], &mut work, |_| {}).unwrap();
    let first_context = work.first_pass();
    work.accept_authenticated_file(first_context, first.work, path)
        .unwrap();
    let accepted = work.accepted();
    let physical = work.compressed_physical_bytes();
    let before = snapshot(dir.path());
    let mut writer = OpenOptions::new().write(true).open(path).unwrap();
    let first_len = writer_block_frame(&original, 21).0.len() + 12;
    let mut observed_digest = None;
    let error = scan_lz4_pass2(
        path,
        identity,
        &metadata[0],
        &work,
        first,
        |event| match event {
            Lz4PassProbe::AfterFooterPreread => {
                writer.seek(SeekFrom::Start(21)).unwrap();
                writer.write_all(&changed[21..21 + first_len]).unwrap();
                writer.sync_data().unwrap();
                assert_eq!(fs::read(path).unwrap(), changed);
            }
            Lz4PassProbe::AfterContiguousRead { digest } => {
                observed_digest = Some(digest);
                writer.seek(SeekFrom::Start(21)).unwrap();
                writer.write_all(&original[21..21 + first_len]).unwrap();
                writer.sync_data().unwrap();
                assert_eq!(fs::read(path).unwrap(), original);
            }
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        PraxisError::Corrupt { reason, .. }
            if reason == "compressed v4 integrated pass digest mismatch"
    ));
    assert_eq!(observed_digest, Some(blake3::hash(&changed)));
    assert_eq!(work.accepted(), accepted);
    assert_eq!(work.compressed_physical_bytes(), physical);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_lz4_pass1_compares_the_preread_trailer_to_hashed_bytes() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Lz4, false);
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    let mut writer = OpenOptions::new().write(true).open(path).unwrap();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let error = direct_lz4_pass1(&metadata[0], &mut work, |event| {
        if event == Lz4PassProbe::AfterFooterPreread {
            writer.seek(SeekFrom::End(-8)).unwrap();
            writer
                .write_all(&[original[original.len() - 8] ^ 1])
                .unwrap();
            writer.sync_data().unwrap();
        }
    })
    .unwrap_err();
    assert!(matches!(
        error,
        PraxisError::Corrupt { reason, .. }
            if reason == "compressed v4 trailer changed during pass"
    ));
    assert_eq!(work.accepted(), CompressedWorkFacts::default());
}

#[test]
fn private_zstd_passes_authenticate_reversed_two_file_replay_without_double_charge() {
    let (dir, _config, lease, metadata) = two_segments(Compression::Zstd, true);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(
        manifest
            .segments
            .iter()
            .map(|meta| meta.id)
            .collect::<Vec<_>>(),
        [2, 1]
    );
    let before = snapshot(dir.path());
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let mut physical_total = 0;
    let mut decoded_total = 0;
    for (ordinal, meta) in manifest.segments.iter().enumerate() {
        assert_eq!(meta.id, metadata[1 - ordinal].id);
        let path = Path::new(&meta.path);
        let bytes = fs::read(path).unwrap();
        let expected_decoded: u64 = two_block_offsets(path)
            .into_iter()
            .map(|offset| writer_block_frame(&bytes, offset).1)
            .sum();
        let opened = File::open(path).unwrap();
        let identity = physical_id(&opened, path).unwrap();
        drop(opened);
        let mut first_probes = Vec::new();
        let first = scan_zstd_pass1(path, identity, meta, &mut work, |event| {
            first_probes.push(event)
        })
        .unwrap();
        assert_eq!(first.len, bytes.len() as u64);
        assert_eq!(first.digest, blake3::hash(&bytes));
        assert_eq!(meta.file_digest, first.digest.to_hex().to_string());
        assert_eq!(
            first.work,
            CompressedWorkFacts {
                decoded_bytes: expected_decoded,
                blocks: 2,
                rows: 2,
            }
        );
        assert_eq!(work.accepted().rows, ordinal as u64 * 2);
        assert_eq!(work.compressed_physical_bytes(), physical_total + first.len);
        assert_eq!(
            first_probes,
            vec![
                ZstdPassProbe::AfterFooterPreread,
                ZstdPassProbe::AfterContiguousRead {
                    digest: first.digest
                },
            ]
        );
        work.accept_authenticated_file(work.first_pass(), first.work, path)
            .unwrap();
        physical_total += first.len;
        decoded_total += expected_decoded;
        let accepted = work.accepted();
        let physical = work.compressed_physical_bytes();
        assert_eq!(accepted.rows, (ordinal as u64 + 1) * 2);
        assert_eq!(accepted.decoded_bytes, decoded_total);
        assert_eq!(physical, physical_total);
        if ordinal == 1 {
            assert!(accepted.rows > first.work.rows);
        }
        let mut replay_probes = Vec::new();
        let replay = scan_zstd_pass2(path, identity, meta, &work, first, |event| {
            replay_probes.push(event)
        })
        .unwrap();
        assert_eq!(replay, first);
        assert_eq!(replay_probes, first_probes);
        assert_eq!(work.accepted(), accepted);
        assert_eq!(work.compressed_physical_bytes(), physical);
        assert_eq!(
            physical_id(&File::open(path).unwrap(), path).unwrap(),
            identity
        );
    }
    assert_eq!(work.accepted().rows, 4);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_zstd_pass3_emits_four_owned_physical_rows_without_recharging() {
    let (dir, _config, lease, metadata) = two_segments(Compression::Zstd, true);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.format_version, 4);
    assert_eq!(
        manifest
            .segments
            .iter()
            .map(|meta| meta.id)
            .collect::<Vec<_>>(),
        [2, 1]
    );
    let before = snapshot(dir.path());
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let mut rows = Vec::new();
    let mut expected_rows = Vec::new();
    let mut physical_total = 0;
    let mut decoded_total = 0;

    for (index, meta) in metadata.iter().enumerate() {
        let path = Path::new(&meta.path);
        let bytes = fs::read(path).unwrap();
        assert_eq!(bytes[8], 2);
        assert_eq!(meta.file_digest, blake3::hash(&bytes).to_hex().to_string());
        let parsed = decode_segment(&bytes, path, &CpuAccelerator).unwrap();
        assert_eq!(parsed.blocks.len(), 2);
        assert!(parsed.blocks.iter().all(|block| block.len() == 1));
        let offsets = two_block_offsets(path);
        let decoded_file: u64 = offsets
            .into_iter()
            .map(|offset| writer_block_frame(&bytes, offset).1)
            .sum();
        let identity = physical_id(&File::open(path).unwrap(), path).unwrap();
        let source = SegmentSource {
            level: meta.level,
            id: meta.id,
            manifest_ordinal: 1 - index,
        };
        assert_eq!(manifest.segments[source.manifest_ordinal].path, meta.path);

        let first = scan_zstd_pass1(path, identity, meta, &mut work, |_| {}).unwrap();
        assert_eq!(first.len, bytes.len() as u64);
        assert_eq!(first.digest, blake3::hash(&bytes));
        assert_eq!(
            first.work,
            CompressedWorkFacts {
                decoded_bytes: decoded_file,
                blocks: 2,
                rows: 2
            }
        );
        work.accept_authenticated_file(work.first_pass(), first.work, path)
            .unwrap();
        physical_total += first.len;
        decoded_total += decoded_file;
        assert_eq!(
            scan_zstd_pass2(path, identity, meta, &work, first, |_| {}).unwrap(),
            first
        );
        let accepted = work.accepted();
        let physical = work.compressed_physical_bytes();
        assert_eq!(physical, physical_total);
        if index == 1 {
            assert!(accepted.rows > first.work.rows);
        }

        let third = scan_zstd_pass3(path, identity, meta, source, &work, first, |row| {
            rows.push(row);
            Ok(())
        })
        .unwrap();
        assert_eq!(third, first);
        assert_eq!(work.accepted(), accepted);
        assert_eq!(work.compressed_physical_bytes(), physical);
        assert_eq!(fs::read(path).unwrap(), bytes);
        assert_eq!(
            physical_id(&File::open(path).unwrap(), path).unwrap(),
            identity
        );

        expected_rows.push(expected_row(
            source,
            offsets[0],
            0,
            ObservedSegmentValue::Put(vec![0xca, 0xfe]),
        ));
        expected_rows.push(expected_row(
            source,
            offsets[1],
            if index == 0 { 1 } else { 2 },
            if index == 0 {
                ObservedSegmentValue::Delete
            } else {
                ObservedSegmentValue::Merge(vec![0x22])
            },
        ));
    }

    assert_eq!(rows, expected_rows);
    let (ObservedSegmentValue::Put(first), ObservedSegmentValue::Put(second)) =
        (&rows[0].value, &rows[2].value)
    else {
        panic!("two physical copies must retain independently owned Put payloads")
    };
    assert_ne!(first.as_ptr(), second.as_ptr());
    assert_eq!(work.compressed_physical_bytes(), physical_total);
    assert_eq!(
        work.accepted(),
        CompressedWorkFacts {
            decoded_bytes: decoded_total,
            blocks: 4,
            rows: 4
        }
    );
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_zstd_pass3_keeps_writer_valid_inline_put_above_one_mebibyte() {
    let (dir, _config, lease, _) = two_segments(Compression::Zstd, false);
    let root = lease.root();
    let mut value = vec![0_u8; 1_100_000];
    blake3::Hasher::new().finalize_xof().fill(&mut value);
    let manifest = rewrite_first_segment(
        root,
        vec![row(0, StoredValue::Put(value.clone()))],
        Compression::Zstd,
        value.len() + 1,
        4096,
    );
    assert_eq!(manifest.format_version, 4);
    let meta = manifest.segments.iter().find(|meta| meta.id == 1).unwrap();
    let path = Path::new(&meta.path);
    let bytes = fs::read(path).unwrap();
    assert_eq!(bytes[8], 2);
    assert!(bytes.len() > 1_048_576);
    let (frame, decoded_len, _) = writer_block_frame(&bytes, 21);
    assert!(decoded_len > 1_048_576 && decoded_len <= 8 * 1024 * 1024);
    let decoded = decode_block(Compression::Zstd, frame).unwrap();
    assert_eq!(decoded.len() as u64, decoded_len);
    let parsed = decode_segment(&bytes, path, &CpuAccelerator).unwrap();
    assert_eq!(parsed.blocks.len(), 1);
    assert_eq!(parsed.blocks[0].len(), 1);
    assert_eq!(
        parsed.blocks[0][0].entry.version.value,
        StoredValue::Put(value.clone())
    );
    assert_eq!(meta.file_digest, blake3::hash(&bytes).to_hex().to_string());
    let before = snapshot(dir.path());
    let identity = physical_id(&File::open(path).unwrap(), path).unwrap();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let first = scan_zstd_pass1(path, identity, meta, &mut work, |_| {}).unwrap();
    assert_eq!(first.digest, blake3::hash(&bytes));
    assert_eq!(first.work.rows, 1);
    assert_eq!(first.work.blocks, 1);
    work.accept_authenticated_file(work.first_pass(), first.work, path)
        .unwrap();
    assert_eq!(
        scan_zstd_pass2(path, identity, meta, &work, first, |_| {}).unwrap(),
        first
    );
    let accepted = work.accepted();
    let physical = work.compressed_physical_bytes();
    let source = SegmentSource {
        level: meta.level,
        id: meta.id,
        manifest_ordinal: 0,
    };
    let mut stage = ProtectedStage::new(PROTECTED_STAGE_LIMITS);
    let mut observed = Vec::new();
    let third = scan_zstd_pass3(path, identity, meta, source, &work, first, |row| {
        observed.push(row.clone());
        stage.push(row)
    })
    .unwrap();
    assert_eq!(third, first);
    assert_eq!(stage.len(), 1);
    assert_eq!(
        observed,
        [expected_row(
            source,
            21,
            0,
            ObservedSegmentValue::Put(value)
        )]
    );
    assert!(stage.used_bytes() <= PROTECTED_STAGE_LIMITS.max_bytes);
    assert_eq!(work.accepted(), accepted);
    assert_eq!(work.compressed_physical_bytes(), physical);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_zstd_pass3_rejects_byte_identical_path_replacement_before_callback() {
    let (dir, _config, lease, metadata) = two_segments(Compression::Zstd, false);
    let root = lease.root();
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest_bytes = fs::read(&manifest_path).unwrap();
    let manifest = Manifest::decode(&manifest_bytes, &manifest_path).unwrap();
    assert_eq!(manifest.format_version, 4);
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&original).to_hex().to_string()
    );
    let before = snapshot(dir.path());
    let identity = physical_id(&File::open(path).unwrap(), path).unwrap();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let first = scan_zstd_pass1(path, identity, &metadata[0], &mut work, |_| {}).unwrap();
    work.accept_authenticated_file(work.first_pass(), first.work, path)
        .unwrap();
    assert_eq!(
        scan_zstd_pass2(path, identity, &metadata[0], &work, first, |_| {}).unwrap(),
        first
    );
    let accepted = work.accepted();
    let physical = work.compressed_physical_bytes();

    // Keep the original inode/file ID alive while the identical copy takes its path.
    let replacement = path.with_extension("pass3-replacement");
    let parked_original = path.with_extension("pass3-original");
    fs::write(&replacement, &original).unwrap();
    assert_ne!(
        physical_id(&File::open(&replacement).unwrap(), &replacement).unwrap(),
        identity
    );
    fs::rename(path, &parked_original).unwrap();
    fs::rename(&replacement, path).unwrap();
    assert_eq!(fs::read(path).unwrap(), original);
    assert_ne!(
        physical_id(&File::open(path).unwrap(), path).unwrap(),
        identity
    );
    assert_eq!(fs::read(&manifest_path).unwrap(), manifest_bytes);
    let source = SegmentSource {
        level: metadata[0].level,
        id: metadata[0].id,
        manifest_ordinal: 0,
    };
    let mut callbacks = 0;
    let error = scan_zstd_pass3(path, identity, &metadata[0], source, &work, first, |_| {
        callbacks += 1;
        Ok(())
    })
    .unwrap_err();
    fs::remove_file(path).unwrap();
    fs::rename(&parked_original, path).unwrap();
    assert!(
        matches!(&error, PraxisError::Corrupt { path: error_path, reason }
        if error_path.as_path() == path && reason.contains("identity") && reason.contains("changed")),
        "{error}"
    );
    assert_eq!(callbacks, 0);
    assert_eq!(work.accepted(), accepted);
    assert_eq!(work.compressed_physical_bytes(), physical);
    assert_eq!(
        physical_id(&File::open(path).unwrap(), path).unwrap(),
        identity
    );
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_zstd_pass3_rejects_wrong_source_id_and_level_before_callback() {
    let (dir, _config, _lease, metadata) = two_segments(Compression::Zstd, false);
    let path = Path::new(&metadata[0].path);
    let bytes = fs::read(path).unwrap();
    assert_eq!(bytes[8], 2);
    let before = snapshot(dir.path());
    let identity = physical_id(&File::open(path).unwrap(), path).unwrap();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let first = scan_zstd_pass1(path, identity, &metadata[0], &mut work, |_| {}).unwrap();
    work.accept_authenticated_file(work.first_pass(), first.work, path)
        .unwrap();
    assert_eq!(
        scan_zstd_pass2(path, identity, &metadata[0], &work, first, |_| {}).unwrap(),
        first
    );
    let accepted = work.accepted();
    let physical = work.compressed_physical_bytes();
    let wrong_sources = [
        SegmentSource {
            level: metadata[0].level,
            id: metadata[0].id + 1,
            manifest_ordinal: 0,
        },
        SegmentSource {
            level: metadata[0].level + 1,
            id: metadata[0].id,
            manifest_ordinal: 0,
        },
    ];
    for source in wrong_sources {
        let mut callbacks = 0;
        let error = scan_zstd_pass3(path, identity, &metadata[0], source, &work, first, |_| {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(
            matches!(&error, PraxisError::Corrupt { path: error_path, reason }
            if error_path.as_path() == path && reason.contains("source") && reason.contains("MANIFEST")),
            "{error}"
        );
        assert_eq!(callbacks, 0);
        assert_eq!(work.accepted(), accepted);
        assert_eq!(work.compressed_physical_bytes(), physical);
    }
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_zstd_pass3_refuses_whole_block_row_cap_before_callbacks() {
    let (dir, config, lease, _) = two_segments(Compression::Zstd, false);
    let root = lease.root();
    let manifest = rewrite_first_segment(
        root,
        vec![
            row(0, StoredValue::Put(vec![1])),
            row(1, StoredValue::Delete),
        ],
        Compression::Zstd,
        config.large_value_threshold,
        4096,
    );
    assert_eq!(manifest.format_version, 4);
    let meta = manifest.segments.iter().find(|meta| meta.id == 1).unwrap();
    let path = Path::new(&meta.path);
    let bytes = fs::read(path).unwrap();
    assert_eq!(bytes[8], 2);
    let parsed = decode_segment(&bytes, path, &CpuAccelerator).unwrap();
    assert_eq!(parsed.blocks.len(), 1);
    assert_eq!(parsed.blocks[0].len(), 2);
    assert_eq!(parsed.blocks[0][0].entry.key.as_ref(), &[0]);
    assert_eq!(parsed.blocks[0][1].entry.key.as_ref(), &[1]);
    assert_eq!(meta.file_digest, blake3::hash(&bytes).to_hex().to_string());
    let before = snapshot(dir.path());
    let identity = physical_id(&File::open(path).unwrap(), path).unwrap();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let first = scan_zstd_pass1(path, identity, meta, &mut work, |_| {}).unwrap();
    assert_eq!(first.work.rows, 2);
    assert_eq!(first.work.blocks, 1);
    work.accept_authenticated_file(work.first_pass(), first.work, path)
        .unwrap();
    assert_eq!(
        scan_zstd_pass2(path, identity, meta, &work, first, |_| {}).unwrap(),
        first
    );
    let accepted = work.accepted();
    let physical = work.compressed_physical_bytes();
    work.set_max_rows_file_for_test(1);
    let source = SegmentSource {
        level: meta.level,
        id: meta.id,
        manifest_ordinal: 0,
    };
    let mut callbacks = 0;
    let error = scan_zstd_pass3(path, identity, meta, source, &work, first, |_| {
        callbacks += 1;
        Ok(())
    })
    .unwrap_err();
    assert!(
        matches!(&error, PraxisError::UnsupportedCatalogFeature { feature }
        if *feature == "compressed v4 file row count exceeds proof profile"),
        "{error}"
    );
    assert_eq!(callbacks, 0);
    assert_eq!(work.accepted(), accepted);
    assert_eq!(work.compressed_physical_bytes(), physical);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_zstd_pass3_rejects_integrated_digest_after_first_callback_aba() {
    let (dir, _config, _lease, metadata) = two_segments(Compression::Zstd, false);
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    let changed = same_length_zstd_value_variant(&original, path);
    assert_eq!(changed.len(), original.len());
    assert_ne!(changed, original);
    let decoded_b = decode_segment(&changed, path, &CpuAccelerator).unwrap();
    assert_eq!(decoded_b.blocks.len(), 2);
    let expected_b_value = match &decoded_b.blocks[0][0].entry.version.value {
        StoredValue::Put(value) => value.clone(),
        other => panic!("variant must be a Put, got {other:?}"),
    };
    assert_ne!(expected_b_value, [0xca, 0xfe]);
    assert_eq!(
        metadata[0].file_digest,
        blake3::hash(&original).to_hex().to_string()
    );
    let before = snapshot(dir.path());
    let identity = physical_id(&File::open(path).unwrap(), path).unwrap();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let first = scan_zstd_pass1(path, identity, &metadata[0], &mut work, |_| {}).unwrap();
    work.accept_authenticated_file(work.first_pass(), first.work, path)
        .unwrap();
    assert_eq!(
        scan_zstd_pass2(path, identity, &metadata[0], &work, first, |_| {}).unwrap(),
        first
    );
    let accepted = work.accepted();
    let physical = work.compressed_physical_bytes();
    let first_frame_len = writer_block_frame(&original, 21).0.len() + 12;
    let mut writer = OpenOptions::new().write(true).open(path).unwrap();
    writer.seek(SeekFrom::Start(21)).unwrap();
    writer
        .write_all(&changed[21..21 + first_frame_len])
        .unwrap();
    writer.sync_data().unwrap();
    assert_eq!(fs::read(path).unwrap(), changed);
    assert_eq!(
        physical_id(&File::open(path).unwrap(), path).unwrap(),
        identity
    );

    let source = SegmentSource {
        level: metadata[0].level,
        id: metadata[0].id,
        manifest_ordinal: 0,
    };
    let mut saw_b = false;
    let error = scan_zstd_pass3(path, identity, &metadata[0], source, &work, first, |row| {
        if !saw_b {
            assert_eq!(row.source, source);
            assert_eq!(row.block_offset, 21);
            assert_eq!(row.row_ordinal, 0);
            assert_eq!(row.key, [0]);
            assert_eq!(
                row.value,
                ObservedSegmentValue::Put(expected_b_value.clone())
            );
            saw_b = true;
            writer.seek(SeekFrom::Start(21)).unwrap();
            writer
                .write_all(&original[21..21 + first_frame_len])
                .unwrap();
            writer.sync_data().unwrap();
            assert_eq!(fs::read(path).unwrap(), original);
        }
        Ok(())
    })
    .unwrap_err();
    if !saw_b {
        writer.seek(SeekFrom::Start(21)).unwrap();
        writer
            .write_all(&original[21..21 + first_frame_len])
            .unwrap();
        writer.sync_data().unwrap();
    }
    drop(writer);
    assert!(
        saw_b,
        "pass 3 did not expose independently decoded B row: {error}"
    );
    assert!(
        matches!(&error, PraxisError::Corrupt { path: error_path, reason }
        if error_path.as_path() == path && reason.contains("integrated") && reason.contains("digest")),
        "{error}"
    );
    assert_eq!(work.accepted(), accepted);
    assert_eq!(work.compressed_physical_bytes(), physical);
    assert_eq!(fs::read(path).unwrap(), original);
    assert_eq!(
        physical_id(&File::open(path).unwrap(), path).unwrap(),
        identity
    );
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_zstd_pass3_callback_error_releases_pending_row_and_retries() {
    let (dir, _config, _lease, metadata) = two_segments(Compression::Zstd, false);
    let path = Path::new(&metadata[0].path);
    let bytes = fs::read(path).unwrap();
    assert_eq!(
        decode_segment(&bytes, path, &CpuAccelerator)
            .unwrap()
            .blocks
            .len(),
        2
    );
    let before = snapshot(dir.path());
    let identity = physical_id(&File::open(path).unwrap(), path).unwrap();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let first = scan_zstd_pass1(path, identity, &metadata[0], &mut work, |_| {}).unwrap();
    work.accept_authenticated_file(work.first_pass(), first.work, path)
        .unwrap();
    assert_eq!(
        scan_zstd_pass2(path, identity, &metadata[0], &work, first, |_| {}).unwrap(),
        first
    );
    let accepted = work.accepted();
    let physical = work.compressed_physical_bytes();
    let source = SegmentSource {
        level: metadata[0].level,
        id: metadata[0].id,
        manifest_ordinal: 0,
    };
    let mut callbacks = 0;
    let error = scan_zstd_pass3(path, identity, &metadata[0], source, &work, first, |_| {
        callbacks += 1;
        Err(PraxisError::Corrupt {
            path: path.to_path_buf(),
            reason: "injected private Zstd owned callback error".into(),
        })
    })
    .unwrap_err();
    assert_eq!(
        callbacks, 1,
        "callback failure should follow one owned row: {error}"
    );
    assert!(
        matches!(&error, PraxisError::Corrupt { path: error_path, reason }
        if error_path.as_path() == path && reason == "injected private Zstd owned callback error"),
        "{error}"
    );
    assert_eq!(work.accepted(), accepted);
    assert_eq!(work.compressed_physical_bytes(), physical);

    let mut rows = Vec::new();
    assert_eq!(
        scan_zstd_pass3(path, identity, &metadata[0], source, &work, first, |row| {
            rows.push(row);
            Ok(())
        })
        .unwrap(),
        first
    );
    assert_eq!(
        rows,
        [
            expected_row(source, 21, 0, ObservedSegmentValue::Put(vec![0xca, 0xfe])),
            expected_row(
                source,
                two_block_offsets(path)[1],
                1,
                ObservedSegmentValue::Delete
            ),
        ]
    );
    assert_eq!(work.accepted(), accepted);
    assert_eq!(work.compressed_physical_bytes(), physical);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_zstd_pass3_callback_unwind_drops_stage_and_retries() {
    let (dir, _config, _lease, metadata) = two_segments(Compression::Zstd, false);
    let path = Path::new(&metadata[0].path);
    let before = snapshot(dir.path());
    let identity = physical_id(&File::open(path).unwrap(), path).unwrap();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let first = scan_zstd_pass1(path, identity, &metadata[0], &mut work, |_| {}).unwrap();
    work.accept_authenticated_file(work.first_pass(), first.work, path)
        .unwrap();
    assert_eq!(
        scan_zstd_pass2(path, identity, &metadata[0], &work, first, |_| {}).unwrap(),
        first
    );
    let accepted = work.accepted();
    let physical = work.compressed_physical_bytes();
    let source = SegmentSource {
        level: metadata[0].level,
        id: metadata[0].id,
        manifest_ordinal: 0,
    };
    let mut callbacks = 0;
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut provisional = ProtectedStage::new(PROTECTED_STAGE_LIMITS);
        scan_zstd_pass3(path, identity, &metadata[0], source, &work, first, |row| {
            provisional.push(row)?;
            callbacks += 1;
            panic!("injected private Zstd owned callback unwind")
        })
    }));
    assert!(
        unwind.is_err(),
        "owned callback must be reached before unwind"
    );
    assert_eq!(callbacks, 1);
    assert_eq!(work.accepted(), accepted);
    assert_eq!(work.compressed_physical_bytes(), physical);

    let mut retry = ProtectedStage::new(PROTECTED_STAGE_LIMITS);
    assert_eq!(
        scan_zstd_pass3(path, identity, &metadata[0], source, &work, first, |row| {
            retry.push(row)
        })
        .unwrap(),
        first
    );
    assert_eq!(retry.len(), 2);
    assert_eq!(work.accepted(), accepted);
    assert_eq!(work.compressed_physical_bytes(), physical);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_zstd_pass3_preserves_wire_values_roles_and_within_block_ordinals() {
    let (dir, _config, lease, _) = two_segments(Compression::Zstd, false);
    let root = lease.root();
    let explicit = ValuePointer {
        path: "unresolved-pointer".into(),
        offset: 17,
        len: 19,
        checksum: 23,
    };
    let large_expiry_value = vec![0x5a; 64];
    let manifest = rewrite_first_segment(
        root,
        vec![
            row_in("default", b"d", 3, StoredValue::Put(vec![9])),
            row_in("__praxor_record_unbound_v1", b"u", 4, StoredValue::Delete),
            row_in(
                "__praxor_record_state_v1",
                b"s",
                5,
                StoredValue::Merge(vec![2]),
            ),
            row_in("__praxor_record_meta_v1", b"m", 6, StoredValue::Delete),
            row_in(
                "__praxor_record_payload_v1",
                b"p",
                7,
                StoredValue::Put(vec![1]),
            ),
            row_in(
                "__praxor_record_index_v1",
                b"i",
                8,
                StoredValue::PutWithExpiry {
                    value: vec![4, 5],
                    expires_at_ms: 71,
                },
            ),
            row_in(
                CATALOG_CF,
                b"x",
                u64::MAX,
                StoredValue::PutWithExpiry {
                    value: large_expiry_value.clone(),
                    expires_at_ms: 73,
                },
            ),
            row_in(
                CATALOG_CF,
                b"e",
                9,
                StoredValue::BlobPointer(explicit.clone()),
            ),
        ],
        Compression::Zstd,
        8,
        1_000_000,
    );
    assert_eq!(manifest.format_version, 4);
    let meta = manifest.segments.iter().find(|meta| meta.id == 1).unwrap();
    let path = Path::new(&meta.path);
    let bytes = fs::read(path).unwrap();
    assert_eq!(bytes[8], 2);
    assert_eq!(meta.file_digest, blake3::hash(&bytes).to_hex().to_string());
    let parsed = decode_segment(&bytes, path, &CpuAccelerator).unwrap();
    assert_eq!(parsed.blocks.len(), 1);
    assert_eq!(parsed.blocks[0].len(), 8);
    let decoded = decode_block(Compression::Zstd, writer_block_frame(&bytes, 21).0).unwrap();
    assert_eq!(decode_entries(&decoded, path).unwrap().len(), 8);
    let converted = ValuePointer {
        path: DiskLayout::at(root)
            .value_log_path(1)
            .to_string_lossy()
            .into_owned(),
        offset: 0,
        len: large_expiry_value.len() as u64,
        checksum: crc32c(&large_expiry_value),
    };
    assert_eq!(
        parsed.blocks[0][0].entry.version.value,
        StoredValue::BlobPointer(explicit.clone())
    );
    assert_eq!(parsed.blocks[0][0].blob_expiry, None);
    assert_eq!(
        parsed.blocks[0][1].entry.version.value,
        StoredValue::BlobPointer(converted.clone())
    );
    assert_eq!(parsed.blocks[0][1].blob_expiry, Some(73));
    let before = snapshot(dir.path());
    let identity = physical_id(&File::open(path).unwrap(), path).unwrap();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let first = scan_zstd_pass1(path, identity, meta, &mut work, |_| {}).unwrap();
    assert_eq!(first.work.rows, 8);
    assert_eq!(first.work.blocks, 1);
    work.accept_authenticated_file(work.first_pass(), first.work, path)
        .unwrap();
    assert_eq!(
        scan_zstd_pass2(path, identity, meta, &work, first, |_| {}).unwrap(),
        first
    );
    let accepted = work.accepted();
    let physical = work.compressed_physical_bytes();
    let source = SegmentSource {
        level: meta.level,
        id: meta.id,
        manifest_ordinal: 0,
    };
    let mut rows = Vec::new();
    assert_eq!(
        scan_zstd_pass3(path, identity, meta, source, &work, first, |row| {
            rows.push(row);
            Ok(())
        })
        .unwrap(),
        first
    );
    let expected = [
        (
            PhysicalRowClass::BoundProtected(ProtectedRole::Catalog),
            CATALOG_CF,
            &b"e"[..],
            9,
            ObservedSegmentValue::Pointer {
                pointer: explicit,
                expires_at_ms: None,
            },
        ),
        (
            PhysicalRowClass::BoundProtected(ProtectedRole::Catalog),
            CATALOG_CF,
            &b"x"[..],
            u64::MAX,
            ObservedSegmentValue::Pointer {
                pointer: converted,
                expires_at_ms: Some(73),
            },
        ),
        (
            PhysicalRowClass::BoundProtected(ProtectedRole::Index),
            "__praxor_record_index_v1",
            &b"i"[..],
            8,
            ObservedSegmentValue::PutWithExpiry {
                value: vec![4, 5],
                expires_at_ms: 71,
            },
        ),
        (
            PhysicalRowClass::BoundProtected(ProtectedRole::Meta),
            "__praxor_record_meta_v1",
            &b"m"[..],
            6,
            ObservedSegmentValue::Delete,
        ),
        (
            PhysicalRowClass::BoundProtected(ProtectedRole::Payload),
            "__praxor_record_payload_v1",
            &b"p"[..],
            7,
            ObservedSegmentValue::Put(vec![1]),
        ),
        (
            PhysicalRowClass::BoundProtected(ProtectedRole::State),
            "__praxor_record_state_v1",
            &b"s"[..],
            5,
            ObservedSegmentValue::Merge(vec![2]),
        ),
        (
            PhysicalRowClass::ReservedUnbound,
            "__praxor_record_unbound_v1",
            &b"u"[..],
            4,
            ObservedSegmentValue::Delete,
        ),
        (
            PhysicalRowClass::Other,
            "default",
            &b"d"[..],
            3,
            ObservedSegmentValue::Put(vec![9]),
        ),
    ];
    assert_eq!(rows.len(), expected.len());
    for (ordinal, (classification, cf, key, sequence, value)) in expected.into_iter().enumerate() {
        assert_eq!(
            rows[ordinal],
            ObservedSegmentRow {
                source,
                block_offset: 21,
                row_ordinal: ordinal as u32,
                classification,
                cf: cf.into(),
                key: key.to_vec(),
                sequence,
                value,
            }
        );
    }
    assert_eq!(work.accepted(), accepted);
    assert_eq!(work.compressed_physical_bytes(), physical);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_zstd_pass2_rejects_legal_bloom_change_from_observed_rows() {
    let (dir, _config, lease, metadata) = two_segments(Compression::Zstd, true);
    let root = lease.root();
    let path = Path::new(&metadata[0].path);
    let original_bytes = fs::read(path).unwrap();
    let mut wire = serde_json::to_value(&metadata[0].bloom_filter).unwrap();
    let bit_count = wire["bit_count"].clone();
    let hash_count = wire["hash_count"].clone();
    let word_count = wire["bits"].as_array().unwrap().len();
    let word = wire["bits"][0].as_u64().unwrap();
    wire["bits"][0] = serde_json::Value::from(word ^ 1);
    assert_eq!(wire["bit_count"], bit_count);
    assert_eq!(wire["hash_count"], hash_count);
    assert_eq!(wire["bits"].as_array().unwrap().len(), word_count);
    let changed_bloom: BloomFilter = serde_json::from_value(wire).unwrap();
    assert_ne!(changed_bloom, metadata[0].bloom_filter);
    let manifest_path = DiskLayout::at(root).manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let index = manifest
        .segments
        .iter()
        .position(|meta| meta.id == metadata[0].id)
        .unwrap();
    manifest.segments[index].bloom_filter = changed_bloom.clone();
    let saved = save_strict_manifest(root, &manifest);
    let altered = &saved.segments[index];
    assert_eq!(altered.bloom_filter, changed_bloom);
    assert_eq!(altered.file_digest, metadata[0].file_digest);
    assert_eq!(fs::read(path).unwrap(), original_bytes);
    let identity = physical_id(&File::open(path).unwrap(), path).unwrap();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let first = scan_zstd_pass1(path, identity, altered, &mut work, |_| {}).unwrap();
    assert_eq!(first.digest, blake3::hash(&original_bytes));
    work.accept_authenticated_file(work.first_pass(), first.work, path)
        .unwrap();
    let accepted = work.accepted();
    let physical = work.compressed_physical_bytes();
    let before = snapshot(dir.path());
    let error = scan_zstd_pass2(path, identity, altered, &work, first, |_| {}).unwrap_err();
    assert!(matches!(error, PraxisError::Corrupt { reason, .. }
        if reason == "compressed v4 observed Bloom disagrees with MANIFEST"));
    assert_eq!(work.accepted(), accepted);
    assert_eq!(work.compressed_physical_bytes(), physical);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_zstd_pass1_rejects_repaired_magic_offset_and_overcap_claim() {
    let (_dir, _config, lease, metadata) = two_segments(Compression::Zstd, false);
    let root = lease.root();
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    assert_eq!(original[8], 2);
    let (encoded, _, _) = writer_block_frame(&original, 21);
    assert_eq!(encoded.get(..4), Some(&[0x28, 0xb5, 0x2f, 0xfd][..]));

    let mut bad_magic = original.clone();
    bad_magic[33] ^= 1;
    let encoded_len = encoded.len();
    let checksum = crc32c(&bad_magic[33..33 + encoded_len]);
    bad_magic[29..33].copy_from_slice(&checksum.to_le_bytes());
    let manifest = replace_first_segment_bytes(root, &bad_magic);
    let altered = manifest.segments.iter().find(|meta| meta.id == 1).unwrap();
    assert_eq!(
        altered.file_digest,
        blake3::hash(&bad_magic).to_hex().to_string()
    );
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let error = direct_zstd_pass1(altered, &mut work, |_| {}).unwrap_err();
    assert!(matches!(error, PraxisError::Corrupt { reason, .. }
        if reason == "compressed v4 Zstd standard frame magic missing"));
    assert_eq!(work.accepted(), CompressedWorkFacts::default());

    let trailer_start = original.len() - 12;
    let footer_len = u32::from_le_bytes(
        original[trailer_start..trailer_start + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let footer_start = trailer_start - footer_len;
    let mut footer = original[footer_start..trailer_start].to_vec();
    let mut index = BinaryReader::new(&footer, path);
    assert_eq!(index.read_u32().unwrap(), 2);
    index.read_len_slice().unwrap();
    index.read_len_slice().unwrap();
    let offset_position = index.position();
    drop(index);
    footer[offset_position..offset_position + 8].copy_from_slice(&22_u64.to_le_bytes());
    let bad_offset = replace_lz4_footer(&original, &footer);
    let manifest = replace_first_segment_bytes(root, &bad_offset);
    let altered = manifest.segments.iter().find(|meta| meta.id == 1).unwrap();
    assert_eq!(
        altered.file_digest,
        blake3::hash(&bad_offset).to_hex().to_string()
    );
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let error = direct_zstd_pass1(altered, &mut work, |_| {}).unwrap_err();
    assert!(matches!(error, PraxisError::Corrupt { reason, .. }
        if reason == "compressed v4 block is not contiguous"));
    assert_eq!(work.accepted(), CompressedWorkFacts::default());

    let mut overcap = original;
    overcap[25..29].copy_from_slice(&(8_u32 * 1024 * 1024 + 1).to_le_bytes());
    let manifest = replace_first_segment_bytes(root, &overcap);
    let altered = manifest.segments.iter().find(|meta| meta.id == 1).unwrap();
    assert_eq!(
        altered.file_digest,
        blake3::hash(&overcap).to_hex().to_string()
    );
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let mut refusal_probe = Vec::new();
    let error =
        direct_zstd_pass1(altered, &mut work, |event| refusal_probe.push(event)).unwrap_err();
    assert!(
        matches!(error, PraxisError::UnsupportedCatalogFeature { feature }
        if feature == "compressed v4 decoded block exceeds proof profile")
    );
    assert_eq!(
        refusal_probe,
        vec![
            ZstdPassProbe::AfterFooterPreread,
            ZstdPassProbe::RefusedDecodedClaimBeforeReserve {
                encoded_capacity: 0,
                decoded_capacity: 0,
                native_zstd_bytes: 0,
            },
        ]
    );
    assert_eq!(work.accepted(), CompressedWorkFacts::default());
}

#[test]
fn private_zstd_pass1_refuses_second_overcap_claim_with_prior_block_charge() {
    let (dir, _config, lease, metadata) = two_segments(Compression::Zstd, false);
    let root = lease.root();
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    let [first_offset, second_offset] = two_block_offsets(path);
    assert_eq!(first_offset, 21);
    let (first_encoded, first_decoded_len, _) = writer_block_frame(&original, first_offset);
    let (second_encoded, second_decoded_len, _) = writer_block_frame(&original, second_offset);
    assert!(!first_encoded.is_empty());
    assert!(first_decoded_len > 0);
    assert!(first_decoded_len <= PRODUCTION_COMPRESSED_PROOF_PROFILE.max_decoded_block_bytes);
    assert!(second_decoded_len <= PRODUCTION_COMPRESSED_PROOF_PROFILE.max_decoded_block_bytes);
    assert_eq!(
        second_offset,
        first_offset + 12 + first_encoded.len() as u64
    );

    let second_start = usize::try_from(second_offset).unwrap();
    let mut overcap = original.clone();
    let refused_len =
        u32::try_from(PRODUCTION_COMPRESSED_PROOF_PROFILE.max_decoded_block_bytes + 1).unwrap();
    overcap[second_start + 4..second_start + 8].copy_from_slice(&refused_len.to_le_bytes());
    assert_eq!(&overcap[..second_start], &original[..second_start]);
    assert_eq!(overcap.len(), original.len());
    assert_eq!(
        writer_block_frame(&overcap, second_offset).0,
        second_encoded
    );

    let manifest = replace_first_segment_bytes(root, &overcap);
    let altered = manifest.segments.iter().find(|meta| meta.id == 1).unwrap();
    assert_eq!(
        altered.file_digest,
        blake3::hash(&overcap).to_hex().to_string()
    );
    assert_eq!(fs::read(path).unwrap(), overcap);
    let before = snapshot(dir.path());
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let mut probes = Vec::new();
    let error = direct_zstd_pass1(altered, &mut work, |event| probes.push(event)).unwrap_err();
    assert!(
        matches!(error, PraxisError::UnsupportedCatalogFeature { feature }
        if feature == "compressed v4 decoded block exceeds proof profile")
    );
    assert_eq!(probes.len(), 2);
    assert_eq!(probes[0], ZstdPassProbe::AfterFooterPreread);
    let ZstdPassProbe::RefusedDecodedClaimBeforeReserve {
        encoded_capacity,
        decoded_capacity,
        native_zstd_bytes,
    } = probes[1]
    else {
        panic!("second-block refusal did not report retained scratch");
    };
    assert!(encoded_capacity > 0);
    assert!(decoded_capacity > 0);
    assert!(encoded_capacity >= first_encoded.len());
    assert!(decoded_capacity >= usize::try_from(first_decoded_len).unwrap());
    assert!(native_zstd_bytes > 0);
    assert!(
        native_zstd_bytes <= PRODUCTION_COMPRESSED_PROOF_PROFILE.max_zstd_native_workspace_bytes
    );
    assert!(
        encoded_capacity + decoded_capacity + native_zstd_bytes
            <= PRODUCTION_COMPRESSED_PROOF_PROFILE.max_parser_owned_peak_bytes
    );
    assert_eq!(work.accepted(), CompressedWorkFacts::default());
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_zstd_pass1_rejects_reencoded_excess_row_count_after_repaired_framing() {
    let (_dir, _config, lease, metadata) = two_segments(Compression::Zstd, false);
    let root = lease.root();
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    let parsed = decode_segment(&original, path, &CpuAccelerator).unwrap();
    assert_eq!(parsed.blocks.len(), 2);
    assert!(parsed.blocks.iter().all(|block| block.len() == 1));
    let trailer_start = original.len() - 12;
    let footer_len = u32::from_le_bytes(
        original[trailer_start..trailer_start + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let footer_start = trailer_start - footer_len;
    let mut index = BinaryReader::new(&original[footer_start..trailer_start], path);
    assert_eq!(index.read_u32().unwrap(), 2);
    let first_key = index.read_len_slice().unwrap().to_vec();
    let first_last_key = index.read_len_slice().unwrap().to_vec();
    let first_offset = index.read_u64().unwrap();
    let first_len = index.read_u64().unwrap();
    let second_key = index.read_len_slice().unwrap().to_vec();
    let second_last_key = index.read_len_slice().unwrap().to_vec();
    let second_offset = index.read_u64().unwrap();
    let second_len = index.read_u64().unwrap();
    assert_eq!(index.remaining(), 0);
    assert_eq!(first_offset, 21);
    assert_eq!(second_offset, first_offset + first_len);
    assert_eq!(second_offset + second_len, footer_start as u64);

    let (encoded, decoded_len, _) = writer_block_frame(&original, first_offset);
    assert!(decoded_len <= PRODUCTION_COMPRESSED_PROOF_PROFILE.max_decoded_block_bytes);
    let mut decoded = decode_block(Compression::Zstd, encoded).unwrap();
    assert_eq!(decoded.len() as u64, decoded_len);
    assert_eq!(u32::from_le_bytes(decoded[..4].try_into().unwrap()), 1);
    decoded[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    let recompressed = zstd::bulk::compress(&decoded, 3).unwrap();
    assert_eq!(
        parsed_zstd_header(&recompressed).frameContentSize,
        decoded_len
    );
    assert!(
        recompressed.len() as u64 <= PRODUCTION_COMPRESSED_PROOF_PROFILE.max_encoded_block_bytes
    );
    assert_eq!(
        decode_block(Compression::Zstd, &recompressed).unwrap(),
        decoded
    );

    let mut rebuilt = BinaryWriter::new();
    rebuilt.write_bytes(&original[..21]);
    rebuilt.write_u32(recompressed.len() as u32);
    rebuilt.write_u32(decoded.len() as u32);
    rebuilt.write_u32(crc32c(&recompressed));
    rebuilt.write_bytes(&recompressed);
    let repaired_second_offset = rebuilt.len() as u64;
    let second_start = second_offset as usize;
    let second_end = (second_offset + second_len) as usize;
    rebuilt.write_bytes(&original[second_start..second_end]);
    let mut repaired_footer = BinaryWriter::new();
    repaired_footer.write_u32(2);
    repaired_footer.write_len_bytes(&first_key);
    repaired_footer.write_len_bytes(&first_last_key);
    repaired_footer.write_u64(first_offset);
    repaired_footer.write_u64(12 + recompressed.len() as u64);
    repaired_footer.write_len_bytes(&second_key);
    repaired_footer.write_len_bytes(&second_last_key);
    repaired_footer.write_u64(repaired_second_offset);
    repaired_footer.write_u64(second_len);
    let repaired_footer = repaired_footer.into_inner();
    rebuilt.write_bytes(&repaired_footer);
    rebuilt.write_u32(repaired_footer.len() as u32);
    rebuilt.write_u32(crc32c(&repaired_footer));
    rebuilt.write_u32(crate::segments::format::SEGMENT_FOOTER_MAGIC);
    let changed = rebuilt.into_inner();
    assert!(changed.len() as u64 <= PRODUCTION_COMPRESSED_PROOF_PROFILE.max_physical_file_bytes);
    assert_eq!(changed[8], 2);
    let (repaired_encoded, repaired_decoded_len, repaired_crc) = writer_block_frame(&changed, 21);
    assert_eq!(repaired_encoded, recompressed);
    assert_eq!(repaired_decoded_len, decoded_len);
    assert_eq!(repaired_crc, crc32c(&recompressed));
    let manifest = replace_first_segment_bytes(root, &changed);
    let altered = manifest.segments.iter().find(|meta| meta.id == 1).unwrap();
    assert_eq!(
        altered.file_digest,
        blake3::hash(&changed).to_hex().to_string()
    );
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let error = direct_zstd_pass1(altered, &mut work, |_| {}).unwrap_err();
    assert!(matches!(error, PraxisError::Corrupt { reason, .. }
        if reason == "compressed v4 row count exceeds block"));
    assert_eq!(work.accepted(), CompressedWorkFacts::default());
}

#[test]
fn private_zstd_pass1_rejects_same_handle_aba_by_integrated_digest() {
    let (dir, _config, _lease, metadata) = two_segments(Compression::Zstd, false);
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    let changed = same_length_zstd_value_variant(&original, path);
    assert_eq!(original.len(), changed.len());
    assert_ne!(blake3::hash(&original), blake3::hash(&changed));
    assert_eq!(
        metadata[0].file_digest,
        blake3::hash(&original).to_hex().to_string()
    );
    let before = snapshot(dir.path());
    let identity = physical_id(&File::open(path).unwrap(), path).unwrap();
    let file_identity = file_id(path);
    let mut writer = OpenOptions::new().write(true).open(path).unwrap();
    let first_len = writer_block_frame(&original, 21).0.len() + 12;
    let mut observed_digest = None;
    let mut preread_count = 0;
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let error = scan_zstd_pass1(
        path,
        identity,
        &metadata[0],
        &mut work,
        |event| match event {
            ZstdPassProbe::AfterFooterPreread => {
                preread_count += 1;
                assert_eq!(fs::read(path).unwrap(), original);
                writer.seek(SeekFrom::Start(21)).unwrap();
                writer.write_all(&changed[21..21 + first_len]).unwrap();
                writer.sync_data().unwrap();
                assert_eq!(fs::read(path).unwrap(), changed);
                assert_eq!(file_id(path), file_identity);
            }
            ZstdPassProbe::AfterContiguousRead { digest } => {
                observed_digest = Some(digest);
                writer.seek(SeekFrom::Start(21)).unwrap();
                writer.write_all(&original[21..21 + first_len]).unwrap();
                writer.sync_data().unwrap();
                assert_eq!(fs::read(path).unwrap(), original);
            }
            ZstdPassProbe::RefusedDecodedClaimBeforeReserve { .. } => {
                panic!("writer-valid ABA replay did not exceed a decoded limit")
            }
        },
    )
    .unwrap_err();
    assert!(matches!(error, PraxisError::Corrupt { reason, .. }
        if reason == "compressed v4 integrated pass digest mismatch"));
    assert_eq!(preread_count, 1);
    assert_eq!(observed_digest, Some(blake3::hash(&changed)));
    assert_eq!(work.accepted(), CompressedWorkFacts::default());
    assert_eq!(fs::read(path).unwrap(), original);
    assert_eq!(
        physical_id(&File::open(path).unwrap(), path).unwrap(),
        identity
    );
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_zstd_pass2_rejects_same_handle_aba_before_bloom_comparison() {
    let (dir, _config, _lease, metadata) = two_segments(Compression::Zstd, false);
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    let changed = same_length_zstd_value_variant(&original, path);
    assert_eq!(original.len(), changed.len());
    let identity = physical_id(&File::open(path).unwrap(), path).unwrap();
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let first = scan_zstd_pass1(path, identity, &metadata[0], &mut work, |_| {}).unwrap();
    work.accept_authenticated_file(work.first_pass(), first.work, path)
        .unwrap();
    let accepted = work.accepted();
    let physical = work.compressed_physical_bytes();
    let before = snapshot(dir.path());
    let mut writer = OpenOptions::new().write(true).open(path).unwrap();
    let first_len = writer_block_frame(&original, 21).0.len() + 12;
    let mut observed_digest = None;
    let error = scan_zstd_pass2(
        path,
        identity,
        &metadata[0],
        &work,
        first,
        |event| match event {
            ZstdPassProbe::AfterFooterPreread => {
                writer.seek(SeekFrom::Start(21)).unwrap();
                writer.write_all(&changed[21..21 + first_len]).unwrap();
                writer.sync_data().unwrap();
                assert_eq!(fs::read(path).unwrap(), changed);
            }
            ZstdPassProbe::AfterContiguousRead { digest } => {
                observed_digest = Some(digest);
                writer.seek(SeekFrom::Start(21)).unwrap();
                writer.write_all(&original[21..21 + first_len]).unwrap();
                writer.sync_data().unwrap();
                assert_eq!(fs::read(path).unwrap(), original);
            }
            ZstdPassProbe::RefusedDecodedClaimBeforeReserve { .. } => {
                panic!("writer-valid ABA replay did not exceed a decoded limit")
            }
        },
    )
    .unwrap_err();
    assert!(matches!(error, PraxisError::Corrupt { reason, .. }
        if reason == "compressed v4 integrated pass digest mismatch"));
    assert_eq!(observed_digest, Some(blake3::hash(&changed)));
    assert_eq!(work.accepted(), accepted);
    assert_eq!(work.compressed_physical_bytes(), physical);
    assert_eq!(
        physical_id(&File::open(path).unwrap(), path).unwrap(),
        identity
    );
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn bounded_zstd_helper_decodes_writer_frames_across_two_blocks() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Zstd, false);
    let path = Path::new(&metadata[0].path);
    let bytes = fs::read(path).unwrap();
    assert_eq!(bytes[8], 2);
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    work.admit_compressed_file(bytes.len() as u64, path)
        .unwrap();
    let pass = work.first_pass();
    let mut scratch = ScratchLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let mut decoded = Vec::new();
    let mut facts = CompressedWorkFacts::default();
    let mut native_charge = None;
    for (ordinal, offset) in two_block_offsets(path).into_iter().enumerate() {
        let (encoded, decoded_len, checksum) = writer_block_frame(&bytes, offset);
        assert_eq!(encoded.get(..4), Some(&[0x28, 0xb5, 0x2f, 0xfd][..]));
        assert_eq!(
            zstd::zstd_safe::get_frame_content_size(encoded).unwrap(),
            Some(decoded_len)
        );
        facts = decode_bounded_block(
            BlockFrame {
                codec: Compression::Zstd,
                encoded,
                checksum,
                decoded_len,
            },
            &work,
            facts,
            pass,
            &mut decoded,
            &mut scratch,
            path,
        )
        .unwrap();
        let rows = decode_entries(&decoded, path).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].entry.cf.0, CATALOG_CF);
        assert_eq!(rows[0].entry.key.as_ref(), &[ordinal as u8]);
        facts = work.check_next_row(facts, pass, path).unwrap();
        let current_charge = scratch.native_zstd_bytes();
        assert!(current_charge > 0);
        assert!(
            current_charge <= PRODUCTION_COMPRESSED_PROOF_PROFILE.max_zstd_native_workspace_bytes
        );
        assert_eq!(*native_charge.get_or_insert(current_charge), current_charge);
    }
    assert_eq!(facts.blocks, 2);
    assert_eq!(facts.rows, 2);
    assert_eq!(work.accepted(), CompressedWorkFacts::default());
    assert_eq!(
        scratch.live_bytes(),
        decoded.capacity() + scratch.native_zstd_bytes()
    );
}

#[test]
fn bounded_zstd_helper_rejects_repaired_inner_frames_and_wrong_outer_length() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Zstd, false);
    let path = Path::new(&metadata[0].path);
    let bytes = fs::read(path).unwrap();
    let (encoded, decoded_len, checksum) = writer_block_frame(&bytes, 21);
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    work.admit_compressed_file(bytes.len() as u64, path)
        .unwrap();
    let pass = work.first_pass();
    let mut scratch = ScratchLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let mut decoded = Vec::new();

    // The frame is writer-valid, but its declared content size disagrees
    // with the segment block header's outer length.
    let error = decode_bounded_block(
        BlockFrame {
            codec: Compression::Zstd,
            encoded,
            checksum,
            decoded_len: decoded_len + 1,
        },
        &work,
        CompressedWorkFacts::default(),
        pass,
        &mut decoded,
        &mut scratch,
        path,
    )
    .unwrap_err();
    assert!(matches!(error, PraxisError::Corrupt { .. }), "{error}");
    assert_eq!(decoded.capacity(), 0);

    // Repair the outer CRC after changing the encoded bytes, so rejection
    // must come from the single-standard-frame policy, not the block CRC.
    let mut concatenated = encoded.to_vec();
    concatenated.extend_from_slice(encoded);
    let error = decode_bounded_block(
        BlockFrame {
            codec: Compression::Zstd,
            encoded: &concatenated,
            checksum: crc32c(&concatenated),
            decoded_len,
        },
        &work,
        CompressedWorkFacts::default(),
        pass,
        &mut decoded,
        &mut scratch,
        path,
    )
    .unwrap_err();
    assert!(matches!(error, PraxisError::Corrupt { .. }), "{error}");
    assert_eq!(decoded.capacity(), 0);
    assert_eq!(scratch.live_bytes(), 0);
    assert_eq!(work.accepted(), CompressedWorkFacts::default());
}

#[test]
fn bounded_zstd_helper_rejects_over_profile_claim_before_output_allocation() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Zstd, false);
    let path = Path::new(&metadata[0].path);
    let bytes = fs::read(path).unwrap();
    let (encoded, _decoded_len, checksum) = writer_block_frame(&bytes, 21);
    let mut work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    work.admit_compressed_file(bytes.len() as u64, path)
        .unwrap();
    let mut scratch = ScratchLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let mut decoded = Vec::new();
    let error = decode_bounded_block(
        BlockFrame {
            codec: Compression::Zstd,
            encoded,
            checksum,
            decoded_len: PRODUCTION_COMPRESSED_PROOF_PROFILE.max_decoded_block_bytes + 1,
        },
        &work,
        CompressedWorkFacts::default(),
        work.first_pass(),
        &mut decoded,
        &mut scratch,
        path,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        PraxisError::UnsupportedCatalogFeature { feature } if feature.contains("decoded block")
    ));
    assert_eq!(decoded.capacity(), 0);
    assert_eq!(scratch.live_bytes(), 0);
    assert_eq!(work.accepted(), CompressedWorkFacts::default());
}

#[test]
fn bounded_zstd_native_workspace_is_aligned_and_refused_before_output_reserve() {
    let estimate = unsafe { zstd_ffi::ZSTD_estimateDCtxSize() };
    assert!(estimate > 1);
    let rounded = estimate.checked_add(7).unwrap() & !7;
    eprintln!("pinned Zstd static DCtx estimate={estimate} aligned_layout={rounded}");
    assert!(rounded <= PRODUCTION_COMPRESSED_PROOF_PROFILE.max_zstd_native_workspace_bytes);
    let mut words = vec![0_u64; rounded.div_ceil(8) + 2];
    let aligned = words.as_mut_ptr().cast();
    assert_eq!((aligned as usize) % 8, 0);
    assert!(unsafe { zstd_ffi::ZSTD_initStaticDCtx(aligned, estimate - 1) }.is_null());
    let unaligned = unsafe { words.as_mut_ptr().cast::<u8>().add(1) }.cast();
    assert!(unsafe { zstd_ffi::ZSTD_initStaticDCtx(unaligned, estimate) }.is_null());

    let (_dir, _config, _lease, metadata) = two_segments(Compression::Zstd, false);
    let path = Path::new(&metadata[0].path);
    let bytes = fs::read(path).unwrap();
    let (encoded, decoded_len, checksum) = writer_block_frame(&bytes, 21);
    for profile in [
        ProofProfile {
            max_zstd_native_workspace_bytes: rounded - 1,
            ..PRODUCTION_COMPRESSED_PROOF_PROFILE
        },
        ProofProfile {
            max_parser_owned_peak_bytes: rounded - 1,
            ..PRODUCTION_COMPRESSED_PROOF_PROFILE
        },
    ] {
        let work = WorkLedger::new(profile);
        let mut scratch = ScratchLedger::new(profile);
        let mut decoded = Vec::new();
        let error = decode_bounded_block(
            BlockFrame {
                codec: Compression::Zstd,
                encoded,
                checksum,
                decoded_len,
            },
            &work,
            CompressedWorkFacts::default(),
            work.first_pass(),
            &mut decoded,
            &mut scratch,
            path,
        )
        .unwrap_err();
        assert!(
            matches!(&error, PraxisError::UnsupportedCatalogFeature { .. }),
            "{error}"
        );
        assert_eq!(decoded.len(), 0);
        assert_eq!(decoded.capacity(), 0);
        assert_eq!(scratch.native_zstd_bytes(), 0);
        assert_eq!(scratch.live_bytes(), 0);
    }
}

#[test]
fn bounded_zstd_rejects_valid_but_out_of_profile_frame_headers_without_allocating() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Zstd, false);
    let path = Path::new(&metadata[0].path);
    let bytes = fs::read(path).unwrap();
    let (encoded, decoded_len, _) = writer_block_frame(&bytes, 21);
    assert_eq!(parsed_zstd_header(encoded).checksumFlag, 0);
    let known = u32::try_from(decoded_len).unwrap().to_le_bytes();
    let over = (8_u32 * 1024 * 1024 + 1).to_le_bytes();
    let cases: [(&str, Vec<u8>, u64, &str); 4] = [
        (
            "unknown content",
            vec![0x00, 0x00],
            decoded_len,
            "content size",
        ),
        (
            "oversized window",
            [vec![0x80, 0x70], known.to_vec()].concat(),
            decoded_len,
            "window",
        ),
        (
            "oversized content",
            [vec![0x80, 0x68], over.to_vec()].concat(),
            decoded_len,
            "content size",
        ),
        (
            "advertised dictionary",
            [vec![0x81, 0x00, 7], known.to_vec()].concat(),
            decoded_len,
            "dictionary",
        ),
    ];
    for (name, header, outer_len, reason_fragment) in cases {
        let frame = zstd_frame_with_header(encoded, &header);
        let parsed = parsed_zstd_header(&frame);
        match name {
            "unknown content" => assert_eq!(parsed.frameContentSize, u64::MAX),
            "oversized window" => assert!(parsed.windowSize > 8 * 1024 * 1024),
            "oversized content" => assert_eq!(parsed.frameContentSize, 8 * 1024 * 1024 + 1),
            "advertised dictionary" => assert_eq!(parsed.dictID, 7),
            _ => unreachable!(),
        }
        let work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
        let mut scratch = ScratchLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
        let mut decoded = Vec::new();
        let error = decode_bounded_block(
            BlockFrame {
                codec: Compression::Zstd,
                encoded: &frame,
                checksum: crc32c(&frame),
                decoded_len: outer_len,
            },
            &work,
            CompressedWorkFacts::default(),
            work.first_pass(),
            &mut decoded,
            &mut scratch,
            path,
        )
        .unwrap_err();
        assert!(
            matches!(&error, PraxisError::UnsupportedCatalogFeature { feature } if feature.contains(reason_fragment)),
            "{name}: {error}"
        );
        assert_eq!(decoded.capacity(), 0, "{name}");
        assert_eq!(scratch.native_zstd_bytes(), 0, "{name}");
        assert_eq!(scratch.live_bytes(), 0, "{name}");
    }
}

#[test]
fn bounded_zstd_rejects_malformed_single_frames_before_output_reserve() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Zstd, false);
    let path = Path::new(&metadata[0].path);
    let bytes = fs::read(path).unwrap();
    let (encoded, decoded_len, _) = writer_block_frame(&bytes, 21);
    let mut bad_magic = encoded.to_vec();
    bad_magic[0] ^= 1;
    let skip = [0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
    let mut prepended_skip = skip.to_vec();
    prepended_skip.extend_from_slice(encoded);
    let mut appended_skip = encoded.to_vec();
    appended_skip.extend_from_slice(&skip);
    let mut suffix = encoded.to_vec();
    suffix.push(0x77);
    let truncated = encoded[..encoded.len() - 1].to_vec();
    let mut reserved_bit = encoded.to_vec();
    reserved_bit[4] |= 0x08;
    for (name, frame) in [
        ("bad magic", bad_magic),
        ("prepended skippable", prepended_skip),
        ("appended skippable", appended_skip),
        ("suffix", suffix),
        ("truncated", truncated),
        ("reserved bit", reserved_bit),
    ] {
        let work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
        let mut scratch = ScratchLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
        let mut decoded = Vec::new();
        let error = decode_bounded_block(
            BlockFrame {
                codec: Compression::Zstd,
                encoded: &frame,
                checksum: crc32c(&frame),
                decoded_len,
            },
            &work,
            CompressedWorkFacts::default(),
            work.first_pass(),
            &mut decoded,
            &mut scratch,
            path,
        )
        .unwrap_err();
        assert!(
            matches!(&error, PraxisError::Corrupt { .. }),
            "{name}: {error}"
        );
        assert_eq!(decoded.capacity(), 0, "{name}");
        assert_eq!(scratch.native_zstd_bytes(), 0, "{name}");
        assert_eq!(scratch.live_bytes(), 0, "{name}");
    }
}

#[test]
fn bounded_zstd_second_call_early_error_clears_output_and_refunds_context() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Zstd, false);
    let path = Path::new(&metadata[0].path);
    let bytes = fs::read(path).unwrap();
    let (encoded, decoded_len, checksum) = writer_block_frame(&bytes, 21);
    let work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let pass = work.first_pass();
    let mut scratch = ScratchLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let mut decoded = Vec::new();
    let first = decode_bounded_block(
        BlockFrame {
            codec: Compression::Zstd,
            encoded,
            checksum,
            decoded_len,
        },
        &work,
        CompressedWorkFacts::default(),
        pass,
        &mut decoded,
        &mut scratch,
        path,
    )
    .unwrap();
    assert!(!decoded.is_empty());
    assert!(scratch.native_zstd_bytes() > 0);
    let error = decode_bounded_block(
        BlockFrame {
            codec: Compression::Zstd,
            encoded,
            checksum,
            decoded_len: decoded_len + 1,
        },
        &work,
        first,
        pass,
        &mut decoded,
        &mut scratch,
        path,
    )
    .unwrap_err();
    assert!(matches!(&error, PraxisError::Corrupt { .. }), "{error}");
    assert_eq!(decoded.len(), 0);
    assert_eq!(scratch.native_zstd_bytes(), 0);
    assert_eq!(scratch.live_bytes(), decoded.capacity());
    assert_eq!(work.accepted(), CompressedWorkFacts::default());
}

#[test]
fn bounded_zstd_checksum_error_after_reserve_clears_and_releases_context() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Zstd, false);
    let path = Path::new(&metadata[0].path);
    let bytes = fs::read(path).unwrap();
    let (encoded, decoded_len, checksum) = writer_block_frame(&bytes, 21);
    let work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let pass = work.first_pass();
    let mut scratch = ScratchLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let mut decoded = Vec::new();
    let first = decode_bounded_block(
        BlockFrame {
            codec: Compression::Zstd,
            encoded,
            checksum,
            decoded_len,
        },
        &work,
        CompressedWorkFacts::default(),
        pass,
        &mut decoded,
        &mut scratch,
        path,
    )
    .unwrap();
    let payload = vec![0x5a_u8; 257];
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), 0).unwrap();
    encoder.include_checksum(true).unwrap();
    encoder
        .set_pledged_src_size(Some(payload.len() as u64))
        .unwrap();
    encoder.write_all(&payload).unwrap();
    let mut damaged = encoder.finish().unwrap();
    assert_eq!(
        parsed_zstd_header(&damaged).frameContentSize,
        payload.len() as u64
    );
    assert_eq!(parsed_zstd_header(&damaged).checksumFlag, 1);
    let first_size =
        unsafe { zstd_ffi::ZSTD_findFrameCompressedSize(damaged.as_ptr().cast(), damaged.len()) };
    assert_eq!(first_size, damaged.len());
    *damaged.last_mut().unwrap() ^= 1;
    // Header and frame boundaries still parse; only the inner checksum is invalid.
    assert_eq!(
        parsed_zstd_header(&damaged).frameContentSize,
        payload.len() as u64
    );
    let first_size =
        unsafe { zstd_ffi::ZSTD_findFrameCompressedSize(damaged.as_ptr().cast(), damaged.len()) };
    assert_eq!(first_size, damaged.len());
    let error = decode_bounded_block(
        BlockFrame {
            codec: Compression::Zstd,
            encoded: &damaged,
            checksum: crc32c(&damaged),
            decoded_len: payload.len() as u64,
        },
        &work,
        first,
        pass,
        &mut decoded,
        &mut scratch,
        path,
    )
    .unwrap_err();
    assert!(matches!(&error, PraxisError::Corrupt { .. }), "{error}");
    assert_eq!(decoded.len(), 0);
    assert!(decoded.capacity() >= payload.len());
    assert_eq!(scratch.native_zstd_bytes(), 0);
    assert_eq!(scratch.live_bytes(), decoded.capacity());
    assert_eq!(work.accepted(), CompressedWorkFacts::default());

    // The retained Decoded Vec is still enrolled and safe for a new context.
    let retry = decode_bounded_block(
        BlockFrame {
            codec: Compression::Zstd,
            encoded,
            checksum,
            decoded_len,
        },
        &work,
        CompressedWorkFacts::default(),
        pass,
        &mut decoded,
        &mut scratch,
        path,
    )
    .unwrap();
    assert_eq!(retry.blocks, 1);
    assert!(scratch.native_zstd_bytes() > 0);
}

#[test]
fn bounded_zstd_exact_eight_mib_output_reuses_and_releases_native_charge() {
    let payload = vec![0_u8; 8 * 1024 * 1024];
    let encoded = zstd::bulk::compress(&payload, 0).unwrap();
    assert!(encoded.len() <= 9 * 1024 * 1024);
    assert_eq!(
        parsed_zstd_header(&encoded).frameContentSize,
        payload.len() as u64
    );
    let path = Path::new("bounded-zstd-direct-frame");
    let work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let mut scratch = ScratchLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let mut decoded = Vec::new();
    let first = decode_bounded_block(
        BlockFrame {
            codec: Compression::Zstd,
            encoded: &encoded,
            checksum: crc32c(&encoded),
            decoded_len: payload.len() as u64,
        },
        &work,
        CompressedWorkFacts::default(),
        work.first_pass(),
        &mut decoded,
        &mut scratch,
        path,
    )
    .unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(first.decoded_bytes, 8 * 1024 * 1024);
    let charge = scratch.native_zstd_bytes();
    assert!(charge > 0);
    assert_eq!(scratch.live_bytes(), decoded.capacity() + charge);
    let small_payload = [0x72_u8; 19];
    let small = zstd::bulk::compress(&small_payload, 0).unwrap();
    let second = decode_bounded_block(
        BlockFrame {
            codec: Compression::Zstd,
            encoded: &small,
            checksum: crc32c(&small),
            decoded_len: small_payload.len() as u64,
        },
        &work,
        first,
        work.first_pass(),
        &mut decoded,
        &mut scratch,
        path,
    )
    .unwrap();
    assert_eq!(decoded.as_slice(), &small_payload);
    assert_eq!(
        second.decoded_bytes,
        payload.len() as u64 + small_payload.len() as u64
    );
    assert_eq!(scratch.native_zstd_bytes(), charge);
    scratch.release_zstd_context().unwrap();
    assert_eq!(scratch.native_zstd_bytes(), 0);
    assert_eq!(scratch.live_bytes(), decoded.capacity());
    assert_eq!(work.accepted(), CompressedWorkFacts::default());
}

#[test]
fn compressed_work_ledger_checks_file_and_visit_caps_at_exact_claims() {
    let (_dir, _config, _lease, metadata) = two_segments(Compression::Lz4, false);
    let first_path = Path::new(&metadata[0].path);
    let second_path = Path::new(&metadata[1].path);
    let first = fs::read(first_path).unwrap();
    let second = fs::read(second_path).unwrap();
    let first_offsets = two_block_offsets(first_path);
    let first_claims = first_offsets.map(|offset| writer_block_frame(&first, offset).1);
    let exact_file_total = first_claims[0] + first_claims[1];
    let profile = ProofProfile {
        max_decoded_file_bytes: exact_file_total,
        ..PRODUCTION_COMPRESSED_PROOF_PROFILE
    };
    let work = WorkLedger::new(profile);
    let pass = work.first_pass();
    let first_block = work
        .check_next_block(
            CompressedWorkFacts::default(),
            first_claims[0],
            pass,
            first_path,
        )
        .unwrap();
    let both_blocks = work
        .check_next_block(first_block, first_claims[1], pass, first_path)
        .unwrap();
    assert_eq!(both_blocks.decoded_bytes, exact_file_total);
    let narrowed = WorkLedger::new(ProofProfile {
        max_decoded_file_bytes: exact_file_total - 1,
        ..profile
    });
    let narrowed_pass = narrowed.first_pass();
    let error = narrowed
        .check_next_block(first_block, first_claims[1], narrowed_pass, first_path)
        .unwrap_err();
    assert!(matches!(
        error,
        PraxisError::UnsupportedCatalogFeature { .. }
    ));

    let physical_sum = first.len() as u64 + second.len() as u64;
    let mut physical = WorkLedger::new(ProofProfile {
        max_physical_visit_bytes: physical_sum,
        ..PRODUCTION_COMPRESSED_PROOF_PROFILE
    });
    physical
        .admit_compressed_file(first.len() as u64, first_path)
        .unwrap();
    physical
        .admit_compressed_file(second.len() as u64, second_path)
        .unwrap();
    assert_eq!(physical.compressed_physical_bytes(), physical_sum);
    assert!(matches!(
        physical.admit_compressed_file(1, first_path),
        Err(PraxisError::UnsupportedCatalogFeature { .. })
    ));

    let second_claim = writer_block_frame(&second, two_block_offsets(second_path)[0]).1;
    let mut visit = WorkLedger::new(ProofProfile {
        max_decoded_visit_bytes: exact_file_total + second_claim,
        max_blocks_visit: 3,
        max_rows_visit: 3,
        ..PRODUCTION_COMPRESSED_PROOF_PROFILE
    });
    let prior_pass = visit.first_pass();
    visit
        .accept_authenticated_file(
            prior_pass,
            CompressedWorkFacts {
                decoded_bytes: exact_file_total,
                blocks: 2,
                rows: 2,
            },
            first_path,
        )
        .unwrap();
    let next_pass = visit.first_pass();
    let second_facts = visit
        .check_next_block(
            CompressedWorkFacts::default(),
            second_claim,
            next_pass,
            second_path,
        )
        .unwrap();
    assert_eq!(second_facts.decoded_bytes, second_claim);
    assert!(matches!(
        visit.check_next_block(second_facts, 1, next_pass, second_path),
        Err(PraxisError::UnsupportedCatalogFeature { .. })
    ));
    let second_facts = visit
        .check_next_row(second_facts, next_pass, second_path)
        .unwrap();
    assert!(matches!(
        visit.check_next_row(second_facts, next_pass, second_path),
        Err(PraxisError::UnsupportedCatalogFeature { .. })
    ));
    let visit_over = WorkLedger::new(ProofProfile {
        max_decoded_visit_bytes: exact_file_total + second_claim - 1,
        ..PRODUCTION_COMPRESSED_PROOF_PROFILE
    });
    // A prior authenticated file is the only source of the visit charge.
    let mut visit_over = visit_over;
    let prior_pass = visit_over.first_pass();
    visit_over
        .accept_authenticated_file(
            prior_pass,
            CompressedWorkFacts {
                decoded_bytes: exact_file_total,
                blocks: 2,
                rows: 2,
            },
            first_path,
        )
        .unwrap();
    let next_pass = visit_over.first_pass();
    assert!(matches!(
        visit_over.check_next_block(
            CompressedWorkFacts::default(),
            second_claim,
            next_pass,
            second_path
        ),
        Err(PraxisError::UnsupportedCatalogFeature { .. })
    ));
}

#[test]
fn compressed_counters_refuse_checked_overflow_and_zero_length_claim() {
    let path = Path::new("compressed-work-test.tseg");
    let work = WorkLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
    let pass = work.first_pass();
    assert!(matches!(
        work.check_next_block(CompressedWorkFacts::default(), 0, pass, path),
        Err(PraxisError::Corrupt { .. })
    ));
    assert!(matches!(
        work.check_next_block(
            CompressedWorkFacts {
                decoded_bytes: u64::MAX,
                ..Default::default()
            },
            1,
            pass,
            path,
        ),
        Err(PraxisError::UnsupportedCatalogFeature { .. })
    ));
    assert!(matches!(
        work.check_next_row(
            CompressedWorkFacts {
                rows: u64::MAX,
                ..Default::default()
            },
            pass,
            path,
        ),
        Err(PraxisError::UnsupportedCatalogFeature { .. })
    ));
}

#[test]
fn compressed_replay_uses_prior_files_and_refuses_changed_work_early() {
    let path = Path::new("compressed-replay-test.tseg");
    let profile = ProofProfile {
        max_decoded_visit_bytes: 7,
        max_blocks_visit: 7,
        max_rows_visit: 7,
        ..PRODUCTION_COMPRESSED_PROOF_PROFILE
    };
    let mut work = WorkLedger::new(profile);
    let prior_file = CompressedWorkFacts {
        decoded_bytes: 5,
        blocks: 5,
        rows: 5,
    };
    let prior_pass = work.first_pass();
    work.accept_authenticated_file(prior_pass, prior_file, path)
        .unwrap();
    let this_file = CompressedWorkFacts {
        decoded_bytes: 2,
        blocks: 2,
        rows: 2,
    };
    let first_pass = work.first_pass();
    work.accept_authenticated_file(first_pass, this_file, path)
        .unwrap();
    assert_eq!(
        work.accepted(),
        CompressedWorkFacts {
            decoded_bytes: 7,
            blocks: 7,
            rows: 7,
        }
    );
    let replay = work.replay_pass(this_file).unwrap();
    let one = work
        .check_next_block(CompressedWorkFacts::default(), 1, replay, path)
        .unwrap();
    let two = work.check_next_block(one, 1, replay, path).unwrap();
    let one_row = work.check_next_row(two, replay, path).unwrap();
    let exact = work.check_next_row(one_row, replay, path).unwrap();
    replay.require_exact_replay(exact, path).unwrap();
    assert!(matches!(
        replay.require_exact_replay(one_row, path),
        Err(PraxisError::Corrupt { .. })
    ));

    // A later pass cannot consume even one more unit than the authenticated
    // file or the visit boundary before its next decode or row callback.
    let decoded_error = work
        .check_next_block(
            CompressedWorkFacts {
                decoded_bytes: 2,
                ..Default::default()
            },
            1,
            replay,
            path,
        )
        .unwrap_err();
    assert!(matches!(
        decoded_error,
        PraxisError::UnsupportedCatalogFeature { feature }
            if feature.contains("replay decoded")
    ));
    let block_error = work
        .check_next_block(
            CompressedWorkFacts {
                blocks: 2,
                ..Default::default()
            },
            1,
            replay,
            path,
        )
        .unwrap_err();
    assert!(matches!(
        block_error,
        PraxisError::UnsupportedCatalogFeature { feature }
            if feature.contains("replay block")
    ));
    let row_error = work
        .check_next_row(
            CompressedWorkFacts {
                rows: 2,
                ..Default::default()
            },
            replay,
            path,
        )
        .unwrap_err();
    assert!(matches!(
        row_error,
        PraxisError::UnsupportedCatalogFeature { feature }
            if feature.contains("replay") && feature.contains("row")
    ));
    assert!(matches!(
        work.replay_pass(CompressedWorkFacts {
            decoded_bytes: 8,
            ..Default::default()
        }),
        Err(PraxisError::UnsupportedCatalogFeature { .. })
    ));
    assert_eq!(work.accepted().decoded_bytes, 7);
}

#[test]
fn scratch_ledger_precharges_growth_and_bloom_word_overhead() {
    let path = Path::new("compressed-scratch-test.tseg");
    let mut short = ScratchLedger::new(ProofProfile {
        max_decoded_block_bytes: 16,
        max_parser_owned_peak_bytes: 95,
        ..PRODUCTION_COMPRESSED_PROOF_PROFILE
    });
    let mut decoded = Vec::new();
    assert!(matches!(
        short.reserve_vec(ScratchSlot::Decoded, &mut decoded, 1, path),
        Err(PraxisError::UnsupportedCatalogFeature { .. })
    ));
    assert_eq!(decoded.capacity(), 0);
    assert_eq!(short.live_bytes(), 0);

    let mut exact = ScratchLedger::new(ProofProfile {
        max_decoded_block_bytes: 16,
        max_parser_owned_peak_bytes: 96,
        ..PRODUCTION_COMPRESSED_PROOF_PROFILE
    });
    exact
        .reserve_vec(ScratchSlot::Decoded, &mut decoded, 1, path)
        .unwrap();
    assert!(decoded.capacity() > 0);
    assert_eq!(exact.live_bytes(), decoded.capacity());
    if decoded.capacity() < 16 {
        let old_capacity = decoded.capacity();
        assert!(matches!(
            exact.reserve_vec(ScratchSlot::Decoded, &mut decoded, 16, path),
            Err(PraxisError::UnsupportedCatalogFeature { .. })
        ));
        assert_eq!(decoded.capacity(), old_capacity);
    }

    let mut bloom = ScratchLedger::new(ProofProfile {
        max_decoded_block_bytes: 8 * 1024 * 1024,
        max_parser_owned_peak_bytes: 16 * 1024 * 1024 + 127,
        ..PRODUCTION_COMPRESSED_PROOF_PROFILE
    });
    let mut bits = Vec::new();
    assert!(matches!(
        bloom.reserve_vec(ScratchSlot::BloomBits, &mut bits, 1, path),
        Err(PraxisError::UnsupportedCatalogFeature { .. })
    ));
    assert_eq!(bits.capacity(), 0);
}

#[test]
fn scratch_ledger_counts_live_bloom_words_during_bloom_key_growth() {
    let path = Path::new("compressed-bloom-overlap-test.tseg");
    let mut short = ScratchLedger::new(ProofProfile {
        max_rows_file: 0,
        max_encoded_block_bytes: 16,
        max_decoded_block_bytes: 16,
        max_footer_bytes: 16,
        max_parser_owned_peak_bytes: 144,
        ..PRODUCTION_COMPRESSED_PROOF_PROFILE
    });
    let bloom = short.reserve_observed_bloom(0, path).unwrap();
    let mut encoded = Vec::new();
    let mut decoded = Vec::new();
    let mut footer = Vec::new();
    short
        .reserve_vec(ScratchSlot::Encoded, &mut encoded, 16, path)
        .unwrap();
    short
        .reserve_vec(ScratchSlot::Decoded, &mut decoded, 16, path)
        .unwrap();
    short
        .reserve_vec(ScratchSlot::Footer, &mut footer, 16, path)
        .unwrap();
    let live_before = short.live_bytes();
    let mut key = Vec::new();
    assert!(matches!(
        short.reserve_vec(ScratchSlot::BloomScratch, &mut key, 3, path),
        Err(PraxisError::UnsupportedCatalogFeature { .. })
    ));
    assert_eq!(key.capacity(), 0);
    assert_eq!(short.live_bytes(), live_before);
    short.release_observed_bloom(bloom, path).unwrap();

    let mut permitted = ScratchLedger::new(ProofProfile {
        max_rows_file: 0,
        max_encoded_block_bytes: 16,
        max_decoded_block_bytes: 16,
        max_footer_bytes: 16,
        max_parser_owned_peak_bytes: 152,
        ..PRODUCTION_COMPRESSED_PROOF_PROFILE
    });
    let mut bloom = permitted.reserve_observed_bloom(0, path).unwrap();
    let mut encoded = Vec::new();
    let mut decoded = Vec::new();
    let mut footer = Vec::new();
    permitted
        .reserve_vec(ScratchSlot::Encoded, &mut encoded, 16, path)
        .unwrap();
    permitted
        .reserve_vec(ScratchSlot::Decoded, &mut decoded, 16, path)
        .unwrap();
    permitted
        .reserve_vec(ScratchSlot::Footer, &mut footer, 16, path)
        .unwrap();
    let mut key = Vec::new();
    permitted
        .reserve_vec(ScratchSlot::BloomScratch, &mut key, 3, path)
        .unwrap();
    let capacity = key.capacity();
    bloom.try_insert_parts("c", b"k", &mut key, 16).unwrap();
    assert_eq!(key.capacity(), capacity);
    assert!(bloom.may_contain(b"c\0k"));
    assert_eq!(
        permitted.live_bytes(),
        bloom.observed_bits_capacity_bytes().unwrap()
            + encoded.capacity()
            + decoded.capacity()
            + footer.capacity()
            + capacity
    );
}

#[test]
fn writer_valid_segment_over_literal_cap_is_unsupported() {
    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let manifest = rewrite_first_segment(
        root,
        vec![row(0, StoredValue::Put(vec![0x5a; 1_048_576]))],
        Compression::None,
        usize::MAX,
        1,
    );
    assert!(
        fs::metadata(DiskLayout::at(root).segment_path(0, 1))
            .unwrap()
            .len()
            > 1_048_576
    );
    let before = snapshot(dir.path());
    let mut callbacks = 0;
    let error = visit_with_wal_budget(root, &manifest, |_| {
        callbacks += 1;
        Ok(())
    })
    .unwrap_err();
    assert!(
        matches!(&error, PraxisError::UnsupportedCatalogFeature { .. }),
        "{error}"
    );
    assert_eq!(callbacks, 0);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn protected_stage_preserves_physical_copies_while_owner_refuses() {
    for reverse in [true, false] {
        let (dir, config, lease, metadata) = two_literal_segments(reverse);
        let root = lease.root();
        let manifest_path = DiskLayout::at(root).manifest_path();
        let manifest =
            Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
        let first_offsets = two_block_offsets(Path::new(&metadata[0].path));
        let second_offsets = two_block_offsets(Path::new(&metadata[1].path));
        let first_source = SegmentSource {
            level: 0,
            id: 1,
            manifest_ordinal: usize::from(reverse),
        };
        let second_source = SegmentSource {
            level: 1,
            id: 2,
            manifest_ordinal: usize::from(!reverse),
        };
        let before = snapshot(dir.path());
        assert!(matches!(
            inspect_v4_owner(&lease, &config, &CpuAccelerator),
            Err(PraxisError::UnsupportedCatalogFeature {
                feature: "v4 installed cut beyond narrow D0 bootstrap"
            })
        ));
        with_wal_budget(root, &manifest, |budget| {
            let before_budget = budget.remaining_bytes();
            let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
            assert_eq!(
                before_budget - budget.remaining_bytes(),
                candidate.retained_witness_bytes()
            );
            assert_eq!(candidate.witnesses.len(), 2);
            assert_eq!(candidate.rows.len(), 4);
            assert_eq!(
                candidate
                    .witnesses
                    .iter()
                    .map(|witness| witness.source)
                    .collect::<Vec<_>>(),
                vec![first_source, second_source]
            );
            assert_eq!(
                candidate.witnesses[0].path.as_path(),
                Path::new(&metadata[0].path)
            );
            assert_eq!(
                candidate.witnesses[1].path.as_path(),
                Path::new(&metadata[1].path)
            );
            for (witness, meta) in candidate.witnesses.iter().zip(&metadata) {
                assert_eq!(witness.observed_rows, 2);
                assert_eq!(witness.len, fs::metadata(&meta.path).unwrap().len());
                assert_eq!(witness.digest, blake3::hash(&fs::read(&meta.path).unwrap()));
            }
            assert_eq!(
                candidate.rows,
                vec![
                    expected_row(
                        first_source,
                        first_offsets[0],
                        0,
                        ObservedSegmentValue::Put(vec![0xca, 0xfe])
                    ),
                    expected_row(
                        first_source,
                        first_offsets[1],
                        1,
                        ObservedSegmentValue::Delete
                    ),
                    expected_row(
                        second_source,
                        second_offsets[0],
                        0,
                        ObservedSegmentValue::Put(vec![0xca, 0xfe])
                    ),
                    expected_row(
                        second_source,
                        second_offsets[1],
                        2,
                        ObservedSegmentValue::Merge(vec![0x22])
                    ),
                ]
            );
            candidate.discard(root, budget).unwrap();
            assert_eq!(budget.remaining_bytes(), before_budget);
        });
        assert!(matches!(
            inspect_v4_owner(&lease, &config, &CpuAccelerator),
            Err(PraxisError::UnsupportedCatalogFeature {
                feature: "v4 installed cut beyond narrow D0 bootstrap"
            })
        ));
        assert_eq!(snapshot(dir.path()), before);
    }
}

#[test]
fn protected_stage_row_cap_is_all_or_nothing() {
    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let before = snapshot(dir.path());
    let mut staged = 0;
    with_wal_budget(root, &manifest, |budget| {
        let retained_wal_balance = budget.remaining_bytes();
        let error = collect_protected_segment_candidate_for_test(
            root,
            &manifest,
            budget,
            ProtectedStageLimits {
                max_rows: 3,
                max_bytes: PROTECTED_STAGE_LIMITS.max_bytes,
            },
            |count| {
                staged = count;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PraxisError::UnsupportedCatalogFeature { .. }
        ));
        assert_eq!(budget.remaining_bytes(), retained_wal_balance);
    });
    assert_eq!(staged, 3);
    with_wal_budget(root, &manifest, |budget| {
        let before_budget = budget.remaining_bytes();
        let candidate = collect_protected_segment_candidate_for_test(
            root,
            &manifest,
            budget,
            ProtectedStageLimits {
                max_rows: 4,
                max_bytes: PROTECTED_STAGE_LIMITS.max_bytes,
            },
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(candidate.rows.len(), 4);
        assert_eq!(candidate.witnesses.len(), 2);
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), before_budget);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn protected_stage_bytes_charge_actual_row_capacity() {
    let make_row = || {
        let mut value = Vec::with_capacity(8 * 1024);
        value.push(0x42);
        ObservedSegmentRow {
            source: SegmentSource {
                level: 0,
                id: 1,
                manifest_ordinal: 0,
            },
            block_offset: 21,
            row_ordinal: 0,
            classification: PhysicalRowClass::BoundProtected(ProtectedRole::Catalog),
            cf: CATALOG_CF.into(),
            key: vec![0],
            sequence: 2,
            value: ObservedSegmentValue::Put(value),
        }
    };
    let rejected_row = make_row();
    let rejected_capacity = match &rejected_row.value {
        ObservedSegmentValue::Put(value) => value.capacity(),
        _ => unreachable!(),
    };
    assert!(rejected_capacity > 4 * 1024);
    let mut low = ProtectedStage::new(ProtectedStageLimits {
        max_rows: 1,
        max_bytes: 4 * 1024,
    });
    assert!(matches!(
        low.push(rejected_row),
        Err(PraxisError::UnsupportedCatalogFeature { .. })
    ));
    assert_eq!(low.len(), 0);
    assert_eq!(low.capacity(), 0);
    assert_eq!(low.used_bytes(), 0);

    let make_plain_row = || ObservedSegmentRow {
        source: SegmentSource {
            level: 0,
            id: 1,
            manifest_ordinal: 0,
        },
        block_offset: 21,
        row_ordinal: 0,
        classification: PhysicalRowClass::BoundProtected(ProtectedRole::Catalog),
        cf: CATALOG_CF.into(),
        key: vec![0],
        sequence: 2,
        value: ObservedSegmentValue::Delete,
    };
    let mut oversized_cf = make_plain_row();
    let mut cf = String::with_capacity(8 * 1024);
    cf.push_str(CATALOG_CF);
    oversized_cf.cf = cf;
    let mut oversized_key = make_plain_row();
    let mut key = Vec::with_capacity(8 * 1024);
    key.push(0);
    oversized_key.key = key;
    let mut oversized_pointer_path = make_plain_row();
    let mut pointer_path = String::with_capacity(8 * 1024);
    pointer_path.push('p');
    oversized_pointer_path.value = ObservedSegmentValue::Pointer {
        pointer: ValuePointer {
            path: pointer_path,
            offset: 17,
            len: 19,
            checksum: 23,
        },
        expires_at_ms: Some(29),
    };
    for row in [oversized_cf, oversized_key, oversized_pointer_path] {
        let mut stage = ProtectedStage::new(ProtectedStageLimits {
            max_rows: 1,
            max_bytes: 4 * 1024,
        });
        assert!(matches!(
            stage.push(row),
            Err(PraxisError::UnsupportedCatalogFeature { .. })
        ));
        assert_eq!(
            (stage.len(), stage.capacity(), stage.used_bytes()),
            (0, 0, 0)
        );
    }

    let mut admitted = ProtectedStage::new(PROTECTED_STAGE_LIMITS);
    let admitted_row = make_row();
    let admitted_capacity = match &admitted_row.value {
        ObservedSegmentValue::Put(value) => value.capacity(),
        _ => unreachable!(),
    };
    admitted.push(admitted_row).unwrap();
    assert_eq!(admitted.len(), 1);
    assert!(admitted.used_bytes() >= admitted_capacity);
}

#[test]
fn protected_stage_refuses_vector_growth_before_capacity_changes() {
    let make_row = || ObservedSegmentRow {
        source: SegmentSource {
            level: 0,
            id: 1,
            manifest_ordinal: 0,
        },
        block_offset: 21,
        row_ordinal: 0,
        classification: PhysicalRowClass::BoundProtected(ProtectedRole::Catalog),
        cf: CATALOG_CF.into(),
        key: vec![0],
        sequence: 2,
        value: ObservedSegmentValue::Delete,
    };
    let mut stage = ProtectedStage::new(PROTECTED_STAGE_LIMITS);
    stage.push(make_row()).unwrap();
    let actual_capacity = stage.capacity();
    assert!((1..=64).contains(&actual_capacity));
    while stage.len() < actual_capacity {
        stage.push(make_row()).unwrap();
    }
    let before_len = stage.len();
    let before_bytes = stage.used_bytes();
    let next_row = make_row();
    let next_row_heap = next_row
        .cf
        .capacity()
        .checked_add(next_row.key.capacity())
        .unwrap();
    let minimum_new_vector = vector_charge::<ObservedSegmentRow>(
        Path::new("protected-stage-vector-growth-test"),
        actual_capacity + 1,
    )
    .unwrap();
    let one_below_growth = before_bytes
        .checked_add(next_row_heap)
        .and_then(|bytes| bytes.checked_add(minimum_new_vector))
        .unwrap()
        - 1;
    assert!(one_below_growth < PROTECTED_STAGE_LIMITS.max_bytes);
    stage.set_max_bytes_for_test(one_below_growth);
    assert!(matches!(
        stage.push(next_row),
        Err(PraxisError::UnsupportedCatalogFeature { .. })
    ));
    assert_eq!(stage.len(), before_len);
    assert_eq!(stage.capacity(), actual_capacity);
    assert_eq!(stage.used_bytes(), before_bytes);
    stage.set_max_bytes_for_test(PROTECTED_STAGE_LIMITS.max_bytes);
    stage.push(make_row()).unwrap();
    assert_eq!(stage.len(), before_len + 1);
}

#[test]
fn protected_stage_keeps_five_bound_roles_and_reserved_but_drops_other() {
    let (dir, config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let pointer = ValuePointer {
        path: "unresolved-pointer".into(),
        offset: 17,
        len: 19,
        checksum: 23,
    };
    let manifest = rewrite_first_segment(
        root,
        vec![
            row_in("__praxor_record_meta_v1", b"m", 2, StoredValue::Delete),
            row_in(
                "__praxor_record_payload_v1",
                b"p",
                2,
                StoredValue::Put(vec![1]),
            ),
            row_in(
                "__praxor_record_state_v1",
                b"s",
                2,
                StoredValue::Merge(vec![2]),
            ),
            row_in("__praxor_record_index_v1", b"i", 2, StoredValue::Delete),
            row_in(
                CATALOG_CF,
                b"unknown-key",
                u64::MAX,
                StoredValue::BlobPointer(pointer.clone()),
            ),
            row_in("__praxor_record_unbound_v1", b"u", 2, StoredValue::Delete),
            row_in("default", b"catalog-looking-key", 2, StoredValue::Delete),
        ],
        Compression::None,
        config.large_value_threshold,
        1,
    );
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let before_budget = budget.remaining_bytes();
        let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        assert_eq!(candidate.rows.len(), 8); // Six first-file protected/reserved plus two catalog copies.
        for (cf, role) in [
            ("__praxor_record_meta_v1", ProtectedRole::Meta),
            ("__praxor_record_payload_v1", ProtectedRole::Payload),
            ("__praxor_record_state_v1", ProtectedRole::State),
            ("__praxor_record_index_v1", ProtectedRole::Index),
            (CATALOG_CF, ProtectedRole::Catalog),
        ] {
            assert!(candidate.rows.iter().any(|row| {
                row.cf == cf && row.classification == PhysicalRowClass::BoundProtected(role)
            }));
        }
        assert_eq!(
            candidate
                .rows
                .iter()
                .filter(|row| row.cf == "default")
                .count(),
            0
        );
        assert_eq!(
            candidate
                .rows
                .iter()
                .filter(|row| row.classification == PhysicalRowClass::ReservedUnbound)
                .count(),
            1
        );
        let raw_pointer = candidate
            .rows
            .iter()
            .find(|row| row.cf == CATALOG_CF && row.key.as_slice() == b"unknown-key")
            .unwrap();
        assert_eq!(raw_pointer.sequence, u64::MAX);
        assert_eq!(
            raw_pointer.value,
            ObservedSegmentValue::Pointer {
                pointer: pointer.clone(),
                expires_at_ms: None,
            }
        );
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), before_budget);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn protected_stage_callback_error_discards_the_candidate() {
    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let before = snapshot(dir.path());
    let mut staged = 0;
    with_wal_budget(root, &manifest, |budget| {
        let retained_wal_balance = budget.remaining_bytes();
        let error = collect_protected_segment_candidate_for_test(
            root,
            &manifest,
            budget,
            PROTECTED_STAGE_LIMITS,
            |count| {
                staged = count;
                Err(PraxisError::Corrupt {
                    path: root.to_path_buf(),
                    reason: "injected protected-stage callback error".into(),
                })
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PraxisError::Corrupt { path, reason }
                if path.as_path() == root && reason == "injected protected-stage callback error"
        ));
        assert_eq!(budget.remaining_bytes(), retained_wal_balance);
    });
    assert_eq!(staged, 1);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn lz4_protected_stage_callback_error_refunds_and_retries_on_same_budget() {
    let (dir, _config, lease, metadata) = two_segments(Compression::Lz4, false);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.segments.len(), 2);
    assert_eq!(fs::read(&metadata[0].path).unwrap()[8], 1);
    assert_eq!(fs::read(&metadata[1].path).unwrap()[8], 1);
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let mut staged = 0;
        let error = collect_protected_segment_candidate_for_test(
            root,
            &manifest,
            budget,
            PROTECTED_STAGE_LIMITS,
            |count| {
                staged = count;
                Err(PraxisError::Corrupt {
                    path: root.to_path_buf(),
                    reason: "injected LZ4 protected-stage callback error".into(),
                })
            },
        )
        .unwrap_err();
        assert_eq!(staged, 1, "a protected LZ4 row must stage before injection");
        assert!(matches!(
            error,
            PraxisError::Corrupt { path, reason }
                if path.as_path() == root && reason == "injected LZ4 protected-stage callback error"
        ));
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);

        let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        assert_eq!(candidate.rows.len(), 4);
        assert_eq!(candidate.witnesses.len(), 2);
        assert_eq!(
            balance - budget.remaining_bytes(),
            candidate.retained_witness_bytes()
        );
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn zstd_protected_stage_error_and_unwind_refund_same_budget() {
    let (dir, config, lease, metadata) = two_segments(Compression::Zstd, false);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.segments.len(), 2);
    assert!(
        metadata
            .iter()
            .all(|meta| fs::read(&meta.path).unwrap()[8] == 2)
    );
    let before = snapshot(dir.path());

    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let mut staged = 0;
        let error = collect_protected_segment_candidate_for_test(
            root,
            &manifest,
            budget,
            PROTECTED_STAGE_LIMITS,
            |count| {
                staged = count;
                Err(PraxisError::Corrupt {
                    path: root.to_path_buf(),
                    reason: "injected Zstd protected-stage callback error".into(),
                })
            },
        )
        .unwrap_err();
        assert_eq!(staged, 1);
        assert!(matches!(
            error,
            PraxisError::Corrupt { path, reason }
                if path.as_path() == root && reason == "injected Zstd protected-stage callback error"
        ));
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);

        let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        assert_eq!(candidate.rows.len(), 4);
        assert_eq!(candidate.witnesses.len(), 2);
        assert_eq!(
            balance - budget.remaining_bytes(),
            candidate.retained_witness_bytes()
        );
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);

        let mut reached = 0;
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = collect_protected_segment_candidate_for_test(
                root,
                &manifest,
                budget,
                PROTECTED_STAGE_LIMITS,
                |count| {
                    reached = count;
                    assert_eq!(count, 1);
                    panic!("injected Zstd after-stage panic");
                },
            );
        }));
        assert!(caught.is_err());
        assert_eq!(reached, 1);
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);

        let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        assert_eq!(candidate.rows.len(), 4);
        assert_eq!(candidate.witnesses.len(), 2);
        assert_eq!(
            balance - budget.remaining_bytes(),
            candidate.retained_witness_bytes()
        );
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert!(matches!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn lz4_protected_stage_row_cap_discards_one_provisional_row() {
    let (dir, _config, lease, metadata) = two_segments(Compression::Lz4, false);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(fs::read(&metadata[0].path).unwrap()[8], 1);
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let mut staged = Vec::new();
        let error = collect_protected_segment_candidate_for_test(
            root,
            &manifest,
            budget,
            ProtectedStageLimits {
                max_rows: 1,
                max_bytes: PROTECTED_STAGE_LIMITS.max_bytes,
            },
            |count| {
                staged.push(count);
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(staged, vec![1], "one LZ4 row must stage before the cap");
        assert!(matches!(
            error,
            PraxisError::UnsupportedCatalogFeature { feature }
                if feature == "protected segment staging exceeds the private row or byte proof profile"
        ));
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);

        let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        assert_eq!(candidate.rows.len(), 4);
        assert_eq!(candidate.witnesses.len(), 2);
        assert_eq!(
            balance - budget.remaining_bytes(),
            candidate.retained_witness_bytes()
        );
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn protected_stage_panic_after_first_push_refunds_witness_attempt_and_retries() {
    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let mut reached = 0;
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = collect_protected_segment_candidate_for_test(
                root,
                &manifest,
                budget,
                PROTECTED_STAGE_LIMITS,
                |count| {
                    reached = count;
                    assert_eq!(count, 1);
                    panic!("injected after-stage panic");
                },
            );
        }));
        assert!(caught.is_err());
        assert_eq!(reached, 1);
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);

        let candidate = collect_protected_segment_candidate_for_test(
            root,
            &manifest,
            budget,
            PROTECTED_STAGE_LIMITS,
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(candidate.rows.len(), 4);
        assert_eq!(candidate.witnesses.len(), 2);
        assert_eq!(
            balance - budget.remaining_bytes(),
            candidate.retained_witness_bytes()
        );
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn direct_visitor_panic_after_first_witness_refunds_and_retries() {
    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let mut seen = 0;
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = visit_v4_segments(root, &manifest, budget, |row| {
                seen += 1;
                if row.source.id == 2 {
                    panic!("injected second-file visitor panic");
                }
                Ok(())
            });
        }));
        assert!(caught.is_err());
        assert_eq!(seen, 3);
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);

        let candidate = collect_protected_segment_candidate_for_test(
            root,
            &manifest,
            budget,
            PROTECTED_STAGE_LIMITS,
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(candidate.rows.len(), 4);
        assert_eq!(candidate.witnesses.len(), 2);
        assert_eq!(
            balance - budget.remaining_bytes(),
            candidate.retained_witness_bytes()
        );
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn later_file_corruption_discards_the_protected_candidate() {
    let (dir, _config, lease, _) = two_literal_segments(true);
    let root = lease.root();
    let path = DiskLayout::at(root).segment_path(1, 2);
    let mut bytes = fs::read(&path).unwrap();
    bytes[29] ^= 1;
    let manifest = replace_segment_bytes(root, 1, 2, &bytes);
    let before = snapshot(dir.path());
    let mut staged = 0;
    with_wal_budget(root, &manifest, |budget| {
        let retained_wal_balance = budget.remaining_bytes();
        let error = collect_protected_segment_candidate_for_test(
            root,
            &manifest,
            budget,
            PROTECTED_STAGE_LIMITS,
            |count| {
                staged = count;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(matches!(error, PraxisError::Corrupt { .. }));
        assert_eq!(budget.remaining_bytes(), retained_wal_balance);
    });
    assert_eq!(staged, 2);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn zstd_later_file_corruption_discards_provisional_candidate() {
    let (dir, _config, lease, metadata) = two_segments(Compression::Zstd, false);
    let root = lease.root();
    let first_path = Path::new(&metadata[0].path);
    let first_bytes = fs::read(first_path).unwrap();
    let second_bytes = fs::read(&metadata[1].path).unwrap();
    assert_eq!(first_bytes[8], 2);
    assert_eq!(second_bytes[8], 2);
    assert_eq!(
        decode_segment(&first_bytes, first_path, &CpuAccelerator)
            .unwrap()
            .blocks
            .len(),
        2
    );
    let mut corrupt_second = second_bytes;
    corrupt_second[29] ^= 1; // Change only the first outer block CRC.
    let manifest = replace_segment_bytes(root, 1, 2, &corrupt_second);
    assert_eq!(fs::read(&metadata[1].path).unwrap()[8], 2);
    assert_eq!(
        manifest
            .segments
            .iter()
            .find(|meta| meta.id == 2)
            .unwrap()
            .file_digest,
        blake3::hash(&corrupt_second).to_hex().to_string()
    );
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let mut staged = 0;
        let error = collect_protected_segment_candidate_for_test(
            root,
            &manifest,
            budget,
            PROTECTED_STAGE_LIMITS,
            |count| {
                staged = count;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(staged, 2, "ID1 protected rows must stage before ID2 fails");
        assert!(matches!(
            error,
            PraxisError::Corrupt { path, reason }
                if path.as_path() == Path::new(&metadata[1].path)
                    && reason == "compressed v4 block checksum mismatch"
        ));
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn final_recheck_failure_discards_the_protected_candidate() {
    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let path = DiskLayout::at(root).segment_path(0, 1);
    let mut changed = fs::read(&path).unwrap();
    changed[13] ^= 1;
    let mut expected = snapshot(dir.path());
    expected
        .get_mut(path.strip_prefix(root).unwrap())
        .unwrap()
        .bytes = Some(changed.clone());
    let mut staged = 0;
    with_wal_budget(root, &manifest, |budget| {
        let retained_wal_balance = budget.remaining_bytes();
        let error = collect_protected_segment_candidate_for_test(
            root,
            &manifest,
            budget,
            PROTECTED_STAGE_LIMITS,
            |count| {
                staged = count;
                if count == 4 {
                    fs::write(&path, &changed).unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(matches!(error, PraxisError::Corrupt { .. }));
        assert_eq!(budget.remaining_bytes(), retained_wal_balance);
    });
    assert_eq!(staged, 4);
    assert_eq!(snapshot(dir.path()), expected);
}

#[test]
fn zstd_final_recheck_detects_changed_earlier_file_after_stage() {
    let (dir, _config, lease, metadata) = two_segments(Compression::Zstd, false);
    let root = lease.root();
    let manifest_path = DiskLayout::at(root).manifest_path();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert!(
        metadata
            .iter()
            .all(|meta| fs::read(&meta.path).unwrap()[8] == 2)
    );
    let path = Path::new(&metadata[0].path);
    let original = fs::read(path).unwrap();
    let original_id = file_id(path);
    let mut changed = original.clone();
    changed[13] ^= 1;
    let before = snapshot(dir.path());
    let mut expected = snapshot(dir.path());
    expected
        .get_mut(path.strip_prefix(root).unwrap())
        .unwrap()
        .bytes = Some(changed.clone());
    let mut mutator = OpenOptions::new().write(true).open(path).unwrap();
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let mut staged = 0;
        let error = collect_protected_segment_candidate_for_test(
            root,
            &manifest,
            budget,
            PROTECTED_STAGE_LIMITS,
            |count| {
                staged = count;
                if count == 4 {
                    mutator.seek(SeekFrom::Start(13)).unwrap();
                    mutator.write_all(&[changed[13]]).unwrap();
                    mutator.flush().unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(staged, 4, "ID2 must stage before ID1 changes");
        assert!(matches!(
            error,
            PraxisError::Corrupt { path: failed_path, reason }
                if failed_path.as_path() == path && reason == "v4 segment bytes or identity changed"
        ));
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert_eq!(file_id(path), original_id);
    assert_eq!(snapshot(dir.path()), expected);
    mutator.seek(SeekFrom::Start(13)).unwrap();
    mutator.write_all(&[original[13]]).unwrap();
    mutator.flush().unwrap();
    assert_eq!(file_id(path), original_id);
    assert_eq!(fs::read(path).unwrap(), original);
    assert_eq!(snapshot(dir.path()), before);
}

fn writer_external_head_fixture() -> (
    tempfile::TempDir,
    PraxisConfig,
    WriterLease,
    Manifest,
    Vec<u8>,
) {
    let (dir, mut config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let layout = DiskLayout::at(root);
    config.large_value_threshold = 47;
    config.validate().unwrap();
    let key = CatalogKey::Head.encode().unwrap();
    let encoded = CatalogValue::Head(Head {
        database_id: [0x11; 16],
        revision: 2,
        collection_count: 1,
    })
    .encode()
    .unwrap();
    assert_eq!(key, [0]);
    assert_eq!(encoded.len(), 48);

    let value_path = layout.value_log_path(1);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let segment_path = layout.segment_path(0, 1);
    let metadata = SegmentWriter::write(
        SegmentWriteOptions {
            path: &segment_path,
            id: 1,
            level: 0,
            compression: Compression::None,
            accelerator: &CpuAccelerator,
            value_log: &mut value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: 4096,
            partitioned_bloom: None,
            direct_io: false,
        },
        vec![row_in(
            CATALOG_CF,
            &key,
            2,
            StoredValue::Put(encoded.clone()),
        )],
    )
    .unwrap();
    drop(value_log);

    let bytes = fs::read(&segment_path).unwrap();
    let parsed = decode_segment(&bytes, &segment_path, &CpuAccelerator).unwrap();
    assert_eq!(parsed.blocks.len(), 1);
    assert_eq!(parsed.blocks[0].len(), 1);
    let StoredValue::BlobPointer(pointer) = &parsed.blocks[0][0].entry.version.value else {
        panic!("the writer must externalize the 48-byte Head")
    };
    assert_eq!(pointer.path.as_str(), value_path.to_str().unwrap());
    assert_eq!(pointer.offset, 0);
    assert_eq!(pointer.len, 48);
    assert_eq!(pointer.checksum, crc32c(&encoded));
    let value_file = fs::read(&value_path).unwrap();
    assert_eq!(value_file.len(), 60);
    assert_eq!(u64::from_le_bytes(value_file[..8].try_into().unwrap()), 48);
    assert_eq!(
        u32::from_le_bytes(value_file[8..12].try_into().unwrap()),
        crc32c(&encoded)
    );
    assert_eq!(&value_file[12..], encoded.as_slice());

    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    manifest.effective_config = config.persisted();
    for family in &mut manifest.column_families {
        if family.name.starts_with("__praxor_record_") {
            family.large_value_threshold_bytes = config.large_value_threshold;
        }
    }
    *manifest
        .segments
        .iter_mut()
        .find(|segment| segment.id == 1)
        .unwrap() = metadata;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.effective_config, config.persisted());
    assert_eq!(
        manifest
            .column_families
            .iter()
            .find(|family| family.name == CATALOG_CF)
            .unwrap()
            .large_value_threshold_bytes,
        config.large_value_threshold
    );
    (dir, config, lease, manifest, encoded)
}

#[test]
fn private_external_head_resolves_writer_produced_48_bytes_without_tree_mutation() {
    let (dir, config, lease, manifest, expected) = writer_external_head_fixture();
    let root = lease.root();
    let before = snapshot(dir.path());
    assert!(matches!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let head = candidate
            .rows
            .iter()
            .find(|row| row.source.id == 1 && row.cf == CATALOG_CF && row.key == [0])
            .unwrap();
        assert_eq!(
            head.classification,
            PhysicalRowClass::BoundProtected(ProtectedRole::Catalog)
        );
        assert!(matches!(
            &head.value,
            ObservedSegmentValue::Pointer {
                expires_at_ms: None,
                ..
            }
        ));
        let mut probe = ValuePayloadProbe::default();
        let resolved = resolve_catalog_head_external(root, &manifest, head, &mut probe);
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);
        assert_eq!(resolved.unwrap().as_bytes().as_slice(), expected.as_slice());
        assert_eq!(probe.open_attempts, 1);
        assert_eq!(probe.read_attempts, 2);
        assert_eq!(probe.reserve_attempts, 0);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_external_head_rejects_noncanonical_pointer_before_open() {
    let (dir, _config, lease, _manifest, _) = writer_external_head_fixture();
    let root = lease.root();
    let segment_path = DiskLayout::at(root).segment_path(0, 1);
    let mut decoded = decode_segment(
        &fs::read(&segment_path).unwrap(),
        &segment_path,
        &CpuAccelerator,
    )
    .unwrap();
    let StoredValue::BlobPointer(pointer) = &mut decoded.blocks[0][0].entry.version.value else {
        panic!("the writer must produce a pointer before mutation")
    };
    let noncanonical = root.join("outside.tval").to_string_lossy().into_owned();
    pointer.path = noncanonical.clone();
    let rechecksummed = decoded.encode(&CpuAccelerator).unwrap();
    let manifest = replace_first_segment_bytes(root, &rechecksummed);
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let head = candidate
            .rows
            .iter()
            .find(|row| row.source.id == 1 && row.cf == CATALOG_CF && row.key == [0])
            .unwrap();
        let ObservedSegmentValue::Pointer {
            pointer,
            expires_at_ms: None,
        } = &head.value
        else {
            panic!("the rechecksummed segment must expose the claimed pointer")
        };
        assert_eq!(pointer.path, noncanonical);
        let mut probe = ValuePayloadProbe::default();
        let result = resolve_catalog_head_external(root, &manifest, head, &mut probe);
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(probe.open_attempts, 0);
        assert_eq!(probe.read_attempts, 0);
        assert_eq!(probe.reserve_attempts, 0);
        assert_eq!(snapshot(dir.path()), before);
        assert!(
            matches!(&result, Err(PraxisError::Corrupt { .. })),
            "{result:?}"
        );
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_external_head_rejects_atomic_cap_claim_before_payload_read_or_reserve() {
    let (dir, _config, lease, _manifest, _) = writer_external_head_fixture();
    let root = lease.root();
    let segment_path = DiskLayout::at(root).segment_path(0, 1);
    let mut decoded = decode_segment(
        &fs::read(&segment_path).unwrap(),
        &segment_path,
        &CpuAccelerator,
    )
    .unwrap();
    let StoredValue::BlobPointer(pointer) = &mut decoded.blocks[0][0].entry.version.value else {
        panic!("the writer must produce a pointer before mutation")
    };
    pointer.len = MAX_WAL_PAYLOAD_BYTES as u64;
    let rechecksummed = decoded.encode(&CpuAccelerator).unwrap();
    let manifest = replace_first_segment_bytes(root, &rechecksummed);
    assert_eq!(
        manifest
            .segments
            .iter()
            .find(|segment| segment.id == 1)
            .unwrap()
            .file_digest,
        blake3::hash(&rechecksummed).to_hex().to_string()
    );
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let head = candidate
            .rows
            .iter()
            .find(|row| row.source.id == 1 && row.cf == CATALOG_CF && row.key == [0])
            .unwrap();
        let ObservedSegmentValue::Pointer {
            pointer,
            expires_at_ms: None,
        } = &head.value
        else {
            panic!("the rechecksummed segment must expose the claimed pointer")
        };
        assert_eq!(pointer.len, MAX_WAL_PAYLOAD_BYTES as u64);
        let mut probe = ValuePayloadProbe::default();
        let result = resolve_catalog_head_external(root, &manifest, head, &mut probe);
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(probe.open_attempts, 0);
        assert_eq!(probe.read_attempts, 0);
        assert_eq!(probe.reserve_attempts, 0);
        assert_eq!(snapshot(dir.path()), before);
        assert!(
            matches!(&result, Err(PraxisError::Corrupt { .. })),
            "{result:?}"
        );
    });
    assert_eq!(snapshot(dir.path()), before);
}

fn writer_catalog_external_fixture(
    key: CatalogKey<'_>,
    replacement: Option<Vec<u8>>,
    expected_len: usize,
) -> (tempfile::TempDir, WriterLease, Manifest, Vec<u8>, Vec<u8>) {
    let expected_sequence = if matches!(&key, CatalogKey::Anchor) {
        1
    } else {
        2
    };
    let (dir, mut config, lease) = flushed_create_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let segment_path = layout.segment_path(0, 1);
    let decoded = decode_segment(
        &fs::read(&segment_path).unwrap(),
        &segment_path,
        &CpuAccelerator,
    )
    .unwrap();
    let mut rows = decoded
        .blocks
        .into_iter()
        .flatten()
        .map(|raw| raw.entry)
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 7);
    let key_bytes = key.encode().unwrap();
    let target = rows
        .iter()
        .position(|row| row.cf.0 == CATALOG_CF && row.key.as_ref() == key_bytes.as_slice())
        .unwrap();
    assert_eq!(rows[target].version.sequence, expected_sequence);
    let StoredValue::Put(original) = &rows[target].version.value else {
        panic!("the flushed fixture must begin with a literal catalog row")
    };
    let expected = replacement.unwrap_or_else(|| original.to_vec());
    assert_eq!(expected.len(), expected_len);
    let decoded_key = CatalogKey::decode(&key_bytes, &segment_path).unwrap();
    assert_eq!(
        CatalogValue::decode(&decoded_key, &expected, &segment_path)
            .unwrap()
            .encode()
            .unwrap(),
        expected
    );
    rows[target].version.value = StoredValue::Put(expected.clone());
    config.large_value_threshold = 11;
    config.validate().unwrap();

    let value_path = layout.value_log_path(1);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let metadata = SegmentWriter::write(
        SegmentWriteOptions {
            path: &segment_path,
            id: 1,
            level: 0,
            compression: Compression::None,
            accelerator: &CpuAccelerator,
            value_log: &mut value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: config.block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        rows,
    )
    .unwrap();
    drop(value_log);
    let written = decode_segment(
        &fs::read(&segment_path).unwrap(),
        &segment_path,
        &CpuAccelerator,
    )
    .unwrap();
    let target = written
        .blocks
        .iter()
        .flatten()
        .find(|raw| raw.entry.cf.0 == CATALOG_CF && raw.entry.key.as_ref() == key_bytes.as_slice())
        .unwrap();
    assert_eq!(target.entry.version.sequence, expected_sequence);
    let StoredValue::BlobPointer(pointer) = &target.entry.version.value else {
        panic!("the writer must externalize the catalog value")
    };
    assert_eq!(pointer.path.as_str(), value_path.to_str().unwrap());
    assert_eq!(pointer.len, expected_len as u64);
    assert_eq!(pointer.checksum, crc32c(&expected));
    let value_file = fs::read(&value_path).unwrap();
    let offset = usize::try_from(pointer.offset).unwrap();
    let end = offset.checked_add(12 + expected_len).unwrap();
    assert!(end <= value_file.len());
    assert_eq!(
        u64::from_le_bytes(value_file[offset..offset + 8].try_into().unwrap()),
        expected_len as u64
    );
    assert_eq!(
        u32::from_le_bytes(value_file[offset + 8..offset + 12].try_into().unwrap()),
        crc32c(&expected)
    );
    assert_eq!(&value_file[offset + 12..end], expected.as_slice());

    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.segments.len(), 1);
    manifest.effective_config = config.persisted();
    for family in &mut manifest.column_families {
        if family.name.starts_with("__praxor_record_") {
            family.large_value_threshold_bytes = config.large_value_threshold;
        }
    }
    manifest.segments[0] = metadata;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.effective_config, config.persisted());
    for family_name in [CATALOG_CF, "__praxor_record_meta_v1"] {
        assert_eq!(
            manifest
                .column_families
                .iter()
                .find(|family| family.name == family_name)
                .unwrap()
                .large_value_threshold_bytes,
            11
        );
    }
    assert!(
        manifest
            .column_families
            .iter()
            .filter(|family| family.name.starts_with("__praxor_record_"))
            .all(|family| family.large_value_threshold_bytes == 11)
    );
    assert_eq!(manifest.segments.len(), 1);
    assert_eq!(manifest.segments[0].id, 1);
    assert!(value_path.is_file());
    (dir, lease, manifest, key_bytes, expected)
}

fn schema_value_at_limit(short_by_one: bool) -> Vec<u8> {
    let id = CollectionId::new(2).unwrap();
    let namespace = NamespaceId::new(2).unwrap();
    let collection_name = "c".repeat(255);
    let field_names = (1..=128)
        .map(|ordinal| {
            let suffix_len = if short_by_one && ordinal == 128 {
                251
            } else {
                252
            };
            format!("{ordinal:03}{}", "x".repeat(suffix_len))
        })
        .collect::<Vec<_>>();
    assert!(field_names.iter().all(|name| name.len() <= 255));
    let fields = field_names
        .iter()
        .enumerate()
        .map(|(index, name)| Field {
            id: (index + 1) as u16,
            name,
            scalar: ScalarType::Text,
            nullable: false,
        })
        .collect();
    let encoded = CatalogValue::Schema(Schema {
        collection_id: id,
        namespace_id: namespace,
        name: &collection_name,
        fields,
    })
    .encode()
    .unwrap();
    assert_eq!(encoded.len(), if short_by_one { 33_946 } else { 33_947 });
    encoded
}

fn assert_private_catalog_external_positive(
    key: CatalogKey<'_>,
    replacement: Option<Vec<u8>>,
    expected_len: usize,
    expected_sequence: u64,
) {
    let (dir, lease, manifest, key_bytes, expected) =
        writer_catalog_external_fixture(key, replacement, expected_len);
    let root = lease.root();
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        assert_eq!(candidate.witnesses.len(), 1);
        let target = candidate
            .rows
            .iter()
            .find(|row| row.source.id == 1 && row.cf == CATALOG_CF && row.key == key_bytes)
            .unwrap();
        assert_eq!(target.sequence, expected_sequence);
        assert_eq!(
            target.classification,
            PhysicalRowClass::BoundProtected(ProtectedRole::Catalog)
        );
        let ObservedSegmentValue::Pointer {
            pointer,
            expires_at_ms: None,
        } = &target.value
        else {
            panic!("the physical visitor must stage a nonexpiring pointer")
        };
        assert_eq!(pointer.len, expected_len as u64);
        let mut probe = ValuePayloadProbe::default();
        let result = resolve_catalog_external_caps(root, &manifest, target, budget, &mut probe);
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);
        assert_eq!(result.unwrap().as_bytes(), expected.as_slice());
        assert_eq!(probe.open_attempts, 1);
        assert!(probe.read_attempts >= 2);
    });
    assert_eq!(snapshot(dir.path()), before);
}

fn assert_private_catalog_external_cap_plus_one(
    key: CatalogKey<'_>,
    replacement: Option<Vec<u8>>,
    cap: usize,
) {
    let expected_sequence = if matches!(&key, CatalogKey::Anchor) {
        1
    } else {
        2
    };
    let (dir, lease, _manifest, key_bytes, _) =
        writer_catalog_external_fixture(key, replacement, cap);
    let root = lease.root();
    let segment_path = DiskLayout::at(root).segment_path(0, 1);
    let mut decoded = decode_segment(
        &fs::read(&segment_path).unwrap(),
        &segment_path,
        &CpuAccelerator,
    )
    .unwrap();
    let target = decoded
        .blocks
        .iter_mut()
        .flatten()
        .find(|raw| raw.entry.cf.0 == CATALOG_CF && raw.entry.key.as_ref() == key_bytes.as_slice())
        .unwrap();
    let StoredValue::BlobPointer(pointer) = &mut target.entry.version.value else {
        panic!("the writer must produce a pointer before the forged length")
    };
    assert_eq!(pointer.len, cap as u64);
    pointer.len = (cap + 1) as u64;
    let rechecksummed = decoded.encode(&CpuAccelerator).unwrap();
    let manifest = replace_first_segment_bytes(root, &rechecksummed);
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&rechecksummed).to_hex().to_string()
    );
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let target = candidate
            .rows
            .iter()
            .find(|row| row.source.id == 1 && row.cf == CATALOG_CF && row.key == key_bytes)
            .unwrap();
        assert_eq!(target.sequence, expected_sequence);
        let ObservedSegmentValue::Pointer {
            pointer,
            expires_at_ms: None,
        } = &target.value
        else {
            panic!("the rechecksummed visitor must stage a nonexpiring pointer")
        };
        assert_eq!(pointer.len, (cap + 1) as u64);
        let mut probe = ValuePayloadProbe::default();
        let result = resolve_catalog_external_caps(root, &manifest, target, budget, &mut probe);
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);
        assert_eq!(probe.open_attempts, 0);
        assert_eq!(probe.read_attempts, 0);
        assert_eq!(probe.reserve_attempts, 0);
        assert!(
            matches!(&result, Err(PraxisError::Corrupt { .. })),
            "{result:?}"
        );
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_external_anchor_resolves_writer_produced_72_bytes() {
    assert_private_catalog_external_positive(CatalogKey::Anchor, None, 72, 1);
}

#[test]
fn private_external_name_resolves_writer_produced_12_bytes() {
    assert_private_catalog_external_positive(CatalogKey::Name("accounts"), None, 12, 2);
}

#[test]
fn private_external_namespace_resolves_writer_produced_16_bytes() {
    assert_private_catalog_external_positive(
        CatalogKey::Namespace(NamespaceId::new(2).unwrap()),
        None,
        16,
        2,
    );
}

#[test]
fn private_external_schema_resolves_writer_produced_33946_bytes() {
    assert_private_catalog_external_positive(
        CatalogKey::Schema(CollectionId::new(2).unwrap()),
        Some(schema_value_at_limit(true)),
        33_946,
        2,
    );
}

#[test]
fn private_external_schema_resolves_writer_produced_33947_bytes() {
    assert_private_catalog_external_positive(
        CatalogKey::Schema(CollectionId::new(2).unwrap()),
        Some(schema_value_at_limit(false)),
        33_947,
        2,
    );
}

#[test]
fn private_external_anchor_rejects_73_byte_claim_before_io() {
    assert_private_catalog_external_cap_plus_one(CatalogKey::Anchor, None, 72);
}

#[test]
fn private_external_name_rejects_13_byte_claim_before_io() {
    assert_private_catalog_external_cap_plus_one(CatalogKey::Name("accounts"), None, 12);
}

#[test]
fn private_external_namespace_rejects_17_byte_claim_before_io() {
    assert_private_catalog_external_cap_plus_one(
        CatalogKey::Namespace(NamespaceId::new(2).unwrap()),
        None,
        16,
    );
}

#[test]
fn private_external_schema_rejects_33948_byte_claim_before_io() {
    assert_private_catalog_external_cap_plus_one(
        CatalogKey::Schema(CollectionId::new(2).unwrap()),
        Some(schema_value_at_limit(false)),
        33_947,
    );
}

#[test]
fn private_external_head_generalized_resolves_writer_produced_48_bytes() {
    assert_private_catalog_external_positive(CatalogKey::Head, None, 48, 2);
}

#[test]
fn private_external_head_generalized_rejects_opened_hardlink_alias() {
    let (dir, lease, manifest, key_bytes, _) =
        writer_catalog_external_fixture(CatalogKey::Head, None, 48);
    let root = lease.root();
    let value_path = DiskLayout::at(root).value_log_path(1);
    let alias = root.join("external-value-hardlink-alias");
    fs::hard_link(&value_path, &alias).unwrap();
    assert!(value_path.is_file());
    assert!(alias.is_file());
    assert_eq!(file_id(&value_path), file_id(&alias));
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let target = candidate
            .rows
            .iter()
            .find(|row| row.source.id == 1 && row.cf == CATALOG_CF && row.key == key_bytes)
            .unwrap();
        assert_eq!(target.sequence, 2);
        let mut probe = ValuePayloadProbe::default();
        let result = resolve_catalog_external_caps(root, &manifest, target, budget, &mut probe);
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);
        assert_eq!(probe.open_attempts, 1);
        assert_eq!(probe.read_attempts, 0);
        assert_eq!(probe.reserve_attempts, 0);
        assert!(
            matches!(&result, Err(PraxisError::Corrupt { .. })),
            "{result:?}"
        );
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_external_schema_refuses_before_decoder_reserve_at_budget_edge() {
    let (dir, lease, manifest, key_bytes, _) = writer_catalog_external_fixture(
        CatalogKey::Schema(CollectionId::new(2).unwrap()),
        Some(schema_value_at_limit(false)),
        33_947,
    );
    let root = lease.root();
    let before = snapshot(dir.path());
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let target = candidate
            .rows
            .iter()
            .find(|row| row.source.id == 1 && row.cf == CATALOG_CF && row.key == key_bytes)
            .unwrap();
        let raw_capacity_bytes = 256 * std::mem::size_of::<Field<'static>>();
        let policy_allowance = vector_charge::<Field<'static>>(root, 256).unwrap();
        assert!(policy_allowance > raw_capacity_bytes);
        let available = budget.remaining_bytes();
        assert!(available > raw_capacity_bytes);
        let held = available - raw_capacity_bytes;
        budget.charge(root, held).unwrap();
        let mut probe = ValuePayloadProbe::default();
        let result = resolve_catalog_external_caps(root, &manifest, target, budget, &mut probe);
        budget.release(root, held).unwrap();
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);
        assert_eq!(probe.open_attempts, 1);
        assert_eq!(probe.read_attempts, 2);
        assert_eq!(probe.reserve_attempts, 0);
        assert!(
            matches!(&result, Err(PraxisError::Corrupt { .. })),
            "{result:?}"
        );
    });
    assert_eq!(snapshot(dir.path()), before);
}

// A private test-first contract for record value resolution. These tests stage
// real writer-produced pointers, but confer no installed owner authority.
mod record_external_caps_red {
    use super::*;
    use crate::core_catalog::value_witness::{
        ValueFileScanProbe, collect_value_witness, recheck_value_witness,
    };
    use crate::core_records::codec::{Decision, Key as RecordKey, Role as RecordRole, Row};
    use crate::core_records::variable_stream::VariableSummary;

    fn role(key: &RecordKey<'_>) -> RecordRole {
        match key {
            RecordKey::Binding | RecordKey::Allocator | RecordKey::Descriptor(_) => {
                RecordRole::Meta
            }
            RecordKey::Payload(_) => RecordRole::Payload,
            RecordKey::State(_) => RecordRole::State,
            RecordKey::Fact { .. } | RecordKey::Head { .. } => RecordRole::Index,
        }
    }

    fn protected_role(role: RecordRole) -> ProtectedRole {
        match role {
            RecordRole::Meta => ProtectedRole::Meta,
            RecordRole::Payload => ProtectedRole::Payload,
            RecordRole::State => ProtectedRole::State,
            RecordRole::Index => ProtectedRole::Index,
        }
    }

    fn sequence(key: &RecordKey<'_>) -> u64 {
        match key {
            RecordKey::Binding | RecordKey::Allocator | RecordKey::Descriptor(_) => 1,
            _ => 2,
        }
    }

    fn writer_record_external_fixture(
        key: RecordKey<'_>,
        replacement: Option<Vec<u8>>,
        expected_len: usize,
    ) -> (tempfile::TempDir, WriterLease, Manifest, Vec<u8>, Vec<u8>) {
        let (dir, mut config, lease) = flushed_create_fixture();
        let root = lease.root();
        let layout = DiskLayout::at(root);
        let segment_path = layout.segment_path(0, 1);
        let decoded = decode_segment(
            &fs::read(&segment_path).unwrap(),
            &segment_path,
            &CpuAccelerator,
        )
        .unwrap();
        let mut rows = decoded
            .blocks
            .into_iter()
            .flatten()
            .map(|raw| raw.entry)
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 7);
        let key_bytes = key.encode().unwrap();
        let record_role = role(&key);
        assert_eq!(
            RecordKey::decode(record_role, &key_bytes, &segment_path).unwrap(),
            key
        );
        let target = rows.iter().position(|row| {
            row.cf.0 == record_role.cf() && row.key.as_ref() == key_bytes.as_slice()
        });
        let expected = if let Some(target) = target {
            assert!(
                replacement.is_none(),
                "installed row must retain its encoded bytes"
            );
            assert_eq!(rows[target].version.sequence, sequence(&key));
            let StoredValue::Put(bytes) = &rows[target].version.value else {
                panic!("the installed row must start as a literal Put")
            };
            bytes.to_vec()
        } else {
            let bytes = replacement.expect("new private record row needs encoded bytes");
            rows.push(row_in(
                record_role.cf(),
                &key_bytes,
                sequence(&key),
                StoredValue::Put(bytes.clone()),
            ));
            bytes
        };
        assert_eq!(expected.len(), expected_len);
        assert_eq!(
            Row::decode(&key, &expected, &segment_path)
                .unwrap()
                .encode()
                .unwrap(),
            expected
        );

        config.large_value_threshold = 11;
        config.validate().unwrap();
        let value_path = layout.value_log_path(1);
        let mut value_log = ValueLog::open(&value_path).unwrap();
        let metadata = SegmentWriter::write(
            SegmentWriteOptions {
                path: &segment_path,
                id: 1,
                level: 0,
                compression: Compression::None,
                accelerator: &CpuAccelerator,
                value_log: &mut value_log,
                large_value_threshold: config.large_value_threshold,
                block_size: config.block_size,
                partitioned_bloom: None,
                direct_io: false,
            },
            rows,
        )
        .unwrap();
        drop(value_log);

        let written = decode_segment(
            &fs::read(&segment_path).unwrap(),
            &segment_path,
            &CpuAccelerator,
        )
        .unwrap();
        let target = written
            .blocks
            .iter()
            .flatten()
            .find(|raw| {
                raw.entry.cf.0 == record_role.cf() && raw.entry.key.as_ref() == key_bytes.as_slice()
            })
            .unwrap();
        assert_eq!(target.entry.version.sequence, sequence(&key));
        let StoredValue::BlobPointer(pointer) = &target.entry.version.value else {
            panic!("the writer must externalize the record row")
        };
        assert_eq!(pointer.path.as_str(), value_path.to_str().unwrap());
        assert_eq!(pointer.len, expected_len as u64);
        assert_eq!(pointer.checksum, crc32c(&expected));
        let value_file = fs::read(&value_path).unwrap();
        let offset = usize::try_from(pointer.offset).unwrap();
        let end = offset.checked_add(12 + expected_len).unwrap();
        assert!(end <= value_file.len());
        assert_eq!(
            u64::from_le_bytes(value_file[offset..offset + 8].try_into().unwrap()),
            expected_len as u64
        );
        assert_eq!(
            u32::from_le_bytes(value_file[offset + 8..offset + 12].try_into().unwrap()),
            crc32c(&expected)
        );
        assert_eq!(&value_file[offset + 12..end], expected.as_slice());

        let manifest_path = layout.manifest_path();
        let mut manifest =
            Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
        assert_eq!(manifest.segments.len(), 1);
        manifest.effective_config = config.persisted();
        for family in &mut manifest.column_families {
            if family.name.starts_with("__praxor_record_") {
                family.large_value_threshold_bytes = config.large_value_threshold;
            }
        }
        manifest.segments[0] = metadata;
        ManifestStore::new(manifest_path.clone())
            .save(&manifest)
            .unwrap();
        let manifest =
            Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
        assert_eq!(manifest.effective_config, config.persisted());
        assert!(
            manifest
                .column_families
                .iter()
                .filter(|family| family.name.starts_with("__praxor_record_"))
                .all(|family| family.large_value_threshold_bytes == 11)
        );
        assert_eq!(manifest.segments[0].id, 1);
        assert!(value_path.is_file());
        (dir, lease, manifest, key_bytes, expected)
    }

    fn assert_positive(key: RecordKey<'_>, replacement: Option<Vec<u8>>, len: usize) {
        let record_role = role(&key);
        let expected_sequence = sequence(&key);
        let (dir, lease, manifest, key_bytes, encoded) =
            writer_record_external_fixture(key.clone(), replacement, len);
        let root = lease.root();
        let expected = match Row::decode(&key, &encoded, root).unwrap() {
            Row::Payload(user) => UnwitnessedRecordValue::Payload {
                user_len: user.len() as u64,
                digest: blake3::hash(user),
            },
            Row::Descriptor { name, namespace } => UnwitnessedRecordValue::Descriptor {
                encoded_len: encoded.len() as u64,
                encoded_digest: blake3::hash(&encoded),
                name_len: name.len() as u64,
                namespace_len: namespace.len() as u64,
            },
            _ => {
                let mut bytes = [0_u8; 80];
                assert!(encoded.len() <= bytes.len());
                bytes[..encoded.len()].copy_from_slice(&encoded);
                UnwitnessedRecordValue::Fixed {
                    len: encoded.len(),
                    bytes,
                }
            }
        };
        let before = snapshot(dir.path());
        with_wal_budget(root, &manifest, |budget| {
            let balance = budget.remaining_bytes();
            let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
            assert_eq!(candidate.witnesses.len(), 1);
            let target = candidate
                .rows
                .iter()
                .find(|row| {
                    row.source.id == 1 && row.cf == record_role.cf() && row.key == key_bytes
                })
                .unwrap();
            assert_eq!(target.sequence, expected_sequence);
            assert_eq!(
                target.classification,
                PhysicalRowClass::BoundProtected(protected_role(record_role))
            );
            let ObservedSegmentValue::Pointer {
                pointer,
                expires_at_ms: None,
            } = &target.value
            else {
                panic!("the visitor must stage a nonexpiring record pointer")
            };
            assert_eq!(pointer.len, len as u64);
            let mut probe = ValuePayloadProbe::default();
            let result = resolve_record_external_caps(root, &manifest, target, budget, &mut probe);
            candidate.discard(root, budget).unwrap();
            assert_eq!(budget.remaining_bytes(), balance);
            assert_eq!(snapshot(dir.path()), before);
            assert_eq!(result.unwrap(), expected);
            assert_eq!(probe.open_attempts, 1);
            assert!(probe.read_attempts >= 2);
            assert_eq!(probe.reserve_attempts, 0);
        });
        assert_eq!(snapshot(dir.path()), before);
    }

    fn assert_cap_plus_one(
        key: RecordKey<'_>,
        replacement: Option<Vec<u8>>,
        actual_len: usize,
        claimed_len: u64,
    ) {
        let record_role = role(&key);
        let expected_sequence = sequence(&key);
        let (dir, lease, _manifest, key_bytes, _) =
            writer_record_external_fixture(key, replacement, actual_len);
        let root = lease.root();
        let segment_path = DiskLayout::at(root).segment_path(0, 1);
        let mut decoded = decode_segment(
            &fs::read(&segment_path).unwrap(),
            &segment_path,
            &CpuAccelerator,
        )
        .unwrap();
        let target = decoded
            .blocks
            .iter_mut()
            .flatten()
            .find(|raw| {
                raw.entry.cf.0 == record_role.cf() && raw.entry.key.as_ref() == key_bytes.as_slice()
            })
            .unwrap();
        let StoredValue::BlobPointer(pointer) = &mut target.entry.version.value else {
            panic!("the writer must produce a pointer before the forged length")
        };
        assert_eq!(pointer.len, actual_len as u64);
        pointer.len = claimed_len;
        let rechecksummed = decoded.encode(&CpuAccelerator).unwrap();
        let manifest = replace_first_segment_bytes(root, &rechecksummed);
        assert_eq!(
            manifest.segments[0].file_digest,
            blake3::hash(&rechecksummed).to_hex().to_string()
        );
        let before = snapshot(dir.path());
        with_wal_budget(root, &manifest, |budget| {
            let balance = budget.remaining_bytes();
            let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
            let target = candidate
                .rows
                .iter()
                .find(|row| {
                    row.source.id == 1 && row.cf == record_role.cf() && row.key == key_bytes
                })
                .unwrap();
            assert_eq!(target.sequence, expected_sequence);
            assert_eq!(
                target.classification,
                PhysicalRowClass::BoundProtected(protected_role(record_role))
            );
            let ObservedSegmentValue::Pointer {
                pointer,
                expires_at_ms: None,
            } = &target.value
            else {
                panic!("the rechecksummed visitor must stage the record pointer")
            };
            assert_eq!(pointer.len, claimed_len);
            let mut probe = ValuePayloadProbe::default();
            let result = resolve_record_external_caps(root, &manifest, target, budget, &mut probe);
            candidate.discard(root, budget).unwrap();
            assert_eq!(budget.remaining_bytes(), balance);
            assert_eq!(snapshot(dir.path()), before);
            assert_eq!(probe.open_attempts, 0);
            assert_eq!(probe.read_attempts, 0);
            assert_eq!(probe.reserve_attempts, 0);
            assert!(
                matches!(&result, Err(PraxisError::Corrupt { .. })),
                "{result:?}"
            );
        });
        assert_eq!(snapshot(dir.path()), before);
    }

    fn fact_key() -> RecordKey<'static> {
        RecordKey::Fact {
            index: 1,
            incarnation: 1,
            key: b"k",
            raw_sequence: 2,
        }
    }

    fn head_key() -> RecordKey<'static> {
        RecordKey::Head {
            index: 1,
            incarnation: 1,
            key: b"k",
        }
    }

    fn state_value() -> Vec<u8> {
        Row::State {
            live: true,
            payload_length: 1,
        }
        .encode()
        .unwrap()
    }

    fn fact_value() -> Vec<u8> {
        Row::Fact {
            append_ordinal: 1,
            decision: Decision::Put(1),
        }
        .encode()
        .unwrap()
    }

    fn head_value() -> Vec<u8> {
        Row::Head {
            raw_sequence: 2,
            append_ordinal: 1,
            decision: Decision::Put(1),
        }
        .encode()
        .unwrap()
    }

    fn descriptor_value() -> Vec<u8> {
        let namespace = "n".repeat(1024 * 1024);
        Row::Descriptor {
            name: "idx",
            namespace: &namespace,
        }
        .encode()
        .unwrap()
    }

    fn descriptor_with_namespace(namespace: &str) -> Vec<u8> {
        Row::Descriptor {
            name: "idx",
            namespace,
        }
        .encode()
        .unwrap()
    }

    fn payload_value() -> Vec<u8> {
        let user = vec![0x5a; 256 * 1024];
        Row::Payload(&user).encode().unwrap()
    }

    fn assert_private_record_value_file_witness(
        key: RecordKey<'_>,
        encoded: Vec<u8>,
        expected_len: usize,
    ) {
        let is_descriptor = matches!(&key, RecordKey::Descriptor(_));
        let record_role = role(&key);
        let expected_sequence = sequence(&key);
        let (dir, lease, manifest, key_bytes, expected) =
            writer_record_external_fixture(key, Some(encoded), expected_len);
        let root = lease.root();
        let value_path = DiskLayout::at(root).value_log_path(1);
        let value_spelling = value_path.to_str().unwrap();
        let value_file = fs::read(&value_path).unwrap();
        let opened = File::open(&value_path).unwrap();
        let expected_identity = physical_id(&opened, &value_path).unwrap();
        drop(opened);
        let before = snapshot(dir.path());

        let mut config = PraxisConfig::new(root);
        config.compression = Compression::None;
        config.large_value_threshold = 11;
        config.validate().unwrap();
        assert_eq!(manifest.effective_config, config.persisted());
        let owner = inspect_v4_owner(&lease, &config, &CpuAccelerator);
        assert!(
            owner.is_err(),
            "record fixture unexpectedly admitted the public owner: {owner:?}"
        );
        assert_eq!(snapshot(dir.path()), before);

        with_wal_budget(root, &manifest, |budget| {
            let wal_balance = budget.remaining_bytes();
            let segments = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
            let segment_balance = budget.remaining_bytes();
            assert!(segment_balance < wal_balance);
            assert_eq!(segments.witnesses.len(), 1);
            let record = segments
                .rows
                .iter()
                .find(|row| {
                    row.source.id == 1 && row.cf == record_role.cf() && row.key == key_bytes
                })
                .unwrap();
            assert_eq!(record.sequence, expected_sequence);
            assert_eq!(
                record.classification,
                PhysicalRowClass::BoundProtected(protected_role(record_role))
            );
            let ObservedSegmentValue::Pointer {
                pointer,
                expires_at_ms: None,
            } = &record.value
            else {
                panic!("the writer must stage a nonexpiring record pointer")
            };
            assert_eq!(pointer.path, value_spelling);
            assert_eq!(pointer.len, expected_len as u64);
            assert_eq!(pointer.checksum, crc32c(&expected));
            let record_offset = usize::try_from(pointer.offset).unwrap();
            let record_end = record_offset.checked_add(12 + expected_len).unwrap();
            assert!(record_end <= value_file.len());
            assert_eq!(
                u64::from_le_bytes(
                    value_file[record_offset..record_offset + 8]
                        .try_into()
                        .unwrap()
                ),
                expected_len as u64
            );
            assert_eq!(
                u32::from_le_bytes(
                    value_file[record_offset + 8..record_offset + 12]
                        .try_into()
                        .unwrap()
                ),
                crc32c(&expected)
            );
            assert_eq!(
                &value_file[record_offset + 12..record_end],
                expected.as_slice()
            );

            let mut expected_extents = Vec::new();
            for row in &segments.rows {
                let ObservedSegmentValue::Pointer {
                    pointer,
                    expires_at_ms: None,
                } = &row.value
                else {
                    continue;
                };
                assert_ne!(row.classification, PhysicalRowClass::Other);
                assert_eq!(pointer.path, value_spelling);
                let offset = usize::try_from(pointer.offset).unwrap();
                let len = usize::try_from(pointer.len).unwrap();
                let end = offset.checked_add(12).unwrap().checked_add(len).unwrap();
                assert!(end <= value_file.len());
                assert_eq!(
                    u64::from_le_bytes(value_file[offset..offset + 8].try_into().unwrap()),
                    pointer.len
                );
                assert_eq!(
                    u32::from_le_bytes(value_file[offset + 8..offset + 12].try_into().unwrap()),
                    pointer.checksum
                );
                let payload = &value_file[offset + 12..end];
                assert_eq!(crc32c(payload), pointer.checksum);
                expected_extents.push((
                    pointer.offset,
                    pointer.len,
                    pointer.checksum,
                    blake3::hash(payload),
                ));
            }
            expected_extents.sort_by_key(|extent| extent.0);
            assert!(expected_extents.len() >= 2);
            let mut probe = ValueFileScanProbe::default();
            let values = match collect_value_witness(
                root,
                &manifest,
                &segments.rows,
                budget,
                &mut probe,
            ) {
                Ok(values) => values,
                Err(error) => {
                    assert!(
                        matches!(
                            &error,
                            PraxisError::UnsupportedCatalogFeature {
                                feature: "variable-length record extents await streamed value witness"
                            }
                        ),
                        "the fixture failed before the intended variable-record seam: {error}"
                    );
                    assert_eq!(probe.proof_full_file_hashes, 0);
                    assert_eq!(budget.remaining_bytes(), segment_balance);
                    segments.discard(root, budget).unwrap();
                    assert_eq!(budget.remaining_bytes(), wal_balance);
                    assert_eq!(snapshot(dir.path()), before);
                    panic!(
                        "writer-produced variable record reached the unimplemented witness: {error}"
                    );
                }
            };
            assert_eq!(probe.proof_full_file_hashes, 1);
            assert_eq!(values.files.len(), 1);
            assert_eq!(
                values.retained_bytes,
                segment_balance - budget.remaining_bytes()
            );
            assert!(values.retained_bytes > 0);
            let file = &values.files[0];
            assert_eq!(file.id, 1);
            assert_eq!(file.path, value_path);
            assert_eq!(file.identity, expected_identity);
            assert_eq!(file.len, value_file.len() as u64);
            assert_eq!(file.digest, blake3::hash(&value_file));
            assert_eq!(values.extents.len(), expected_extents.len());
            for (observed, &(offset, len, checksum, payload_digest)) in
                values.extents.iter().zip(&expected_extents)
            {
                assert_eq!(observed.file_id, 1);
                assert_eq!(observed.offset, offset);
                assert_eq!(observed.len, len);
                assert_eq!(observed.checksum, checksum);
                assert_eq!(observed.payload_digest, payload_digest);
            }
            assert!(values.extents.iter().any(|extent| {
                extent.file_id == 1
                    && extent.offset == pointer.offset
                    && extent.len == expected_len as u64
                    && extent.checksum == crc32c(&expected)
                    && extent.payload_digest == blake3::hash(&expected)
            }));
            let target_index = values
                .extents
                .iter()
                .position(|extent| {
                    extent.file_id == 1
                        && extent.offset == pointer.offset
                        && extent.len == expected_len as u64
                })
                .unwrap();
            assert_eq!(
                values.variable_summaries.len(),
                values
                    .extents
                    .iter()
                    .filter(|extent| extent.kind.is_some())
                    .count()
            );
            let target_summary = values
                .variable_summaries
                .iter()
                .find(|summary| summary.extent_index == target_index)
                .unwrap();
            let expected_summary = if is_descriptor {
                VariableSummary::Descriptor {
                    name_len: 3,
                    namespace_len: 1_048_576,
                }
            } else {
                VariableSummary::Payload {
                    user_len: 262_144,
                    user_digest: blake3::hash(&expected[12..]),
                }
            };
            assert_eq!(target_summary.summary, expected_summary);
            recheck_value_witness(root, &manifest, &values, &mut probe).unwrap();
            assert_eq!(probe.recheck_full_file_hashes, 1);
            assert_eq!(
                budget.remaining_bytes(),
                segment_balance - values.retained_bytes
            );
            values.discard(root, budget).unwrap();
            assert_eq!(budget.remaining_bytes(), segment_balance);
            segments.discard(root, budget).unwrap();
            assert_eq!(budget.remaining_bytes(), wal_balance);
            assert_eq!(snapshot(dir.path()), before);
        });
        assert_eq!(snapshot(dir.path()), before);
    }

    #[test]
    fn private_record_descriptor_value_file_witnesses_writer_megabyte_namespace() {
        let encoded = descriptor_value();
        assert_eq!(encoded.len(), 1024 * 1024 + 35);
        assert_private_record_value_file_witness(
            RecordKey::Descriptor(1),
            encoded,
            1024 * 1024 + 35,
        );
    }

    #[test]
    fn private_record_payload_value_file_witnesses_writer_quarter_megabyte() {
        let encoded = payload_value();
        assert_eq!(encoded.len(), 256 * 1024 + 12);
        assert_private_record_value_file_witness(RecordKey::Payload(1), encoded, 256 * 1024 + 12);
    }

    #[test]
    fn private_record_binding_resolves_writer_produced_80_bytes() {
        assert_positive(RecordKey::Binding, None, 80);
    }

    #[test]
    fn private_record_allocator_resolves_writer_produced_56_bytes() {
        assert_positive(RecordKey::Allocator, None, 56);
    }

    #[test]
    fn private_record_state_resolves_writer_produced_24_bytes() {
        assert_positive(RecordKey::State(1), Some(state_value()), 24);
    }

    #[test]
    fn private_record_fact_resolves_writer_produced_32_bytes() {
        assert_positive(fact_key(), Some(fact_value()), 32);
    }

    #[test]
    fn private_record_head_resolves_writer_produced_40_bytes() {
        assert_positive(head_key(), Some(head_value()), 40);
    }

    #[test]
    fn private_record_descriptor_resolves_writer_produced_megabyte_namespace() {
        assert_positive(
            RecordKey::Descriptor(1),
            Some(descriptor_value()),
            1024 * 1024 + 35,
        );
    }

    #[test]
    fn private_record_descriptor_streams_valid_utf8_across_chunk_boundary() {
        let mut namespace = "x".repeat(64 * 1024 - 1);
        namespace.push('é');
        namespace.push('z');
        let encoded = descriptor_with_namespace(&namespace);
        assert_eq!(encoded.len(), namespace.len() + 35);
        assert_positive(
            RecordKey::Descriptor(1),
            Some(encoded),
            namespace.len() + 35,
        );
    }

    #[test]
    fn private_record_descriptor_streams_past_half_of_shared_budget() {
        let namespace = "n".repeat(33 * 1024 * 1024);
        let encoded = descriptor_with_namespace(&namespace);
        assert_eq!(encoded.len(), namespace.len() + 35);
        assert_positive(
            RecordKey::Descriptor(1),
            Some(encoded),
            namespace.len() + 35,
        );
    }

    #[test]
    fn private_record_payload_resolves_writer_produced_stream_summary() {
        assert_positive(
            RecordKey::Payload(1),
            Some(payload_value()),
            256 * 1024 + 12,
        );
    }

    #[test]
    fn private_record_binding_rejects_81_byte_claim_before_io() {
        assert_cap_plus_one(RecordKey::Binding, None, 80, 81);
    }

    #[test]
    fn private_record_allocator_rejects_57_byte_claim_before_io() {
        assert_cap_plus_one(RecordKey::Allocator, None, 56, 57);
    }

    #[test]
    fn private_record_state_rejects_25_byte_claim_before_io() {
        assert_cap_plus_one(RecordKey::State(1), Some(state_value()), 24, 25);
    }

    #[test]
    fn private_record_fact_rejects_33_byte_claim_before_io() {
        assert_cap_plus_one(fact_key(), Some(fact_value()), 32, 33);
    }

    #[test]
    fn private_record_head_rejects_41_byte_claim_before_io() {
        assert_cap_plus_one(head_key(), Some(head_value()), 40, 41);
    }

    #[test]
    fn private_record_descriptor_rejects_broad_atomic_cap_plus_one_before_io() {
        assert_cap_plus_one(
            RecordKey::Descriptor(1),
            Some(descriptor_value()),
            1024 * 1024 + 35,
            MAX_WAL_PAYLOAD_BYTES as u64 + 1,
        );
    }

    #[test]
    fn private_record_payload_rejects_broad_atomic_cap_plus_one_before_io() {
        assert_cap_plus_one(
            RecordKey::Payload(1),
            Some(payload_value()),
            256 * 1024 + 12,
            MAX_WAL_PAYLOAD_BYTES as u64 + 1,
        );
    }
}

use super::physical::inspect_v4_owner;
use super::physical_tests::flushed_create_fixture;
use super::segment_witness::{
    ObservedSegmentRow, ObservedSegmentValue, PROTECTED_STAGE_LIMITS, PhysicalRowClass,
    ProtectedRole, ProtectedStage, ProtectedStageLimits, SegmentFileWitness, SegmentSource,
    collect_protected_segment_candidate, collect_protected_segment_candidate_for_test,
    visit_v4_segments,
};
use crate::accel::cpu::scalar::CpuAccelerator;
use crate::config::{Compression, PraxisConfig};
use crate::disk::DiskLayout;
use crate::errors::PraxisError;
use crate::io::crc32c;
use crate::manifest::{Manifest, ManifestStore, SegmentMetadata};
use crate::segments::block::SegmentEntry;
use crate::segments::codec::decode_segment;
use crate::segments::{SegmentWriteOptions, SegmentWriter};
use crate::types::{ColumnFamily, StoredValue, ValuePointer, VersionedValue};
use crate::values::ValueLog;
use crate::wal::catalog_witness::{
    PhysicalWitnessBudget, WalCut, scan_v4_wals_with_budget, vector_charge,
};
use crate::writer_lease::{LOCK_FILE_NAME, WriterLease};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

const CATALOG_CF: &str = "__praxor_record_catalog_v1";

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

fn two_literal_segments(
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
            compression: Compression::None,
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
            compression: Compression::None,
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

#[derive(Debug, Eq, PartialEq)]
struct TreeEntry {
    is_dir: bool,
    bytes: Option<Vec<u8>>,
    file_id: Option<Vec<u8>>,
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
            assert!(!meta.file_type().is_symlink());
            if meta.is_dir() {
                out.insert(
                    relative,
                    TreeEntry {
                        is_dir: true,
                        bytes: None,
                        file_id: None,
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
fn authenticated_compressed_tag_is_explicitly_unsupported() {
    let (dir, _config, lease, _) = two_literal_segments(false);
    let root = lease.root();
    let path = DiskLayout::at(root).segment_path(0, 1);
    let mut bytes = fs::read(&path).unwrap();
    bytes[8] = 1; // The full-file digest is repaired; inner LZ4 bytes are intentionally unread.
    let manifest = replace_first_segment_bytes(root, &bytes);
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
                candidate.retained_witness_bytes
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
    assert_eq!(low.used_bytes(), 0);

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

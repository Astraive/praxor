use super::physical::inspect_v4_owner;
use super::physical_tests::flushed_create_fixture;
use super::segment_witness::{
    ObservedSegmentRow, ObservedSegmentValue, PhysicalRowClass, ProtectedRole, SegmentSource,
    visit_v4_segments,
};
use crate::accel::cpu::scalar::CpuAccelerator;
use crate::config::{Compression, PraxisConfig};
use crate::disk::DiskLayout;
use crate::errors::PraxisError;
use crate::manifest::{Manifest, ManifestStore, SegmentMetadata};
use crate::segments::block::SegmentEntry;
use crate::segments::codec::decode_segment;
use crate::segments::{SegmentWriteOptions, SegmentWriter};
use crate::types::{ColumnFamily, StoredValue, VersionedValue};
use crate::values::ValueLog;
use crate::wal::catalog_witness::{WalCut, scan_v4_wals_with_budget};
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
        // Intentional compiling RED: the stub returns Unsupported here.
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

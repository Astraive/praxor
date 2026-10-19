use super::physical::{InstalledEndpoint, inspect_v4_owner};
use super::{CatalogAuthorityV1, CatalogBindingV1};
use crate::accel::cpu::scalar::CpuAccelerator;
use crate::config::{Compression, PraxisConfig};
use crate::core_records::RecordAuthority;
use crate::disk::DiskLayout;
use crate::manifest::{CheckpointMetadata, ColumnFamilyGeneration, Manifest, ManifestStore};
use crate::segments::block::SegmentEntry;
use crate::segments::{BloomFilter, SegmentWriteOptions, SegmentWriter};
use crate::transactions::WriteBatch;
use crate::types::{ColumnFamily, StoredValue, ValuePointer, VersionedValue};
use crate::values::ValueLog;
use crate::wal::record::WalRecord;
use crate::writer_lease::{LOCK_FILE_NAME, WriterLease};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const ORACLE: &str = include_str!("../../tests/fixtures/catalog_v4_wal_oracle.json");
const BOOTSTRAP_FRAME: &[u8; 563] =
    include_bytes!("../../tests/fixtures/catalog_tag6_bootstrap_s1.bin");
const CREATE_FRAME: &[u8; 424] = include_bytes!("../../tests/fixtures/catalog_tag7_create_s2.bin");
const ID: [u8; 16] = [0x11; 16];

fn bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn oracle_mutation(name: &str) -> Vec<u8> {
    let oracle: serde_json::Value = serde_json::from_str(ORACLE).unwrap();
    let row = oracle["semantic_mutations_rechecksummed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"].as_str() == Some(name))
        .unwrap();
    bytes(row["frame_hex"].as_str().unwrap())
}

fn append_to_active_wal(root: &Path, suffix: &[u8]) {
    let path = root.join("wal/00000000000000000002.wal");
    let mut wal = fs::read(&path).unwrap();
    wal.extend_from_slice(suffix);
    fs::write(path, wal).unwrap();
}

fn installed_rows(include_anchor: bool) -> Vec<SegmentEntry> {
    let oracle: serde_json::Value = serde_json::from_str(ORACLE).unwrap();
    let names = [
        ("record_binding", "__praxor_record_meta_v1"),
        ("record_allocator", "__praxor_record_meta_v1"),
        ("catalog_head_at_1", "__praxor_record_catalog_v1"),
        ("catalog_anchor_at_1", "__praxor_record_catalog_v1"),
    ];
    names
        .into_iter()
        .filter(|(name, _)| include_anchor || *name != "catalog_anchor_at_1")
        .map(|(name, cf)| {
            let row = oracle["bootstrap_tag6"]["operations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["name"].as_str() == Some(name))
                .unwrap();
            SegmentEntry {
                cf: ColumnFamily(cf.into()),
                key: bytes(row["key_hex"].as_str().unwrap()).into(),
                version: VersionedValue {
                    sequence: 1,
                    value: StoredValue::Put(bytes(row["value_hex"].as_str().unwrap())),
                },
            }
        })
        .collect()
}

fn installed_create_rows() -> Vec<SegmentEntry> {
    let oracle: serde_json::Value = serde_json::from_str(ORACLE).unwrap();
    let mut rows = installed_rows(true)
        .into_iter()
        .filter(|row| row.cf.0 == "__praxor_record_meta_v1" || row.key.as_ref() == [4])
        .collect::<Vec<_>>();
    for row in oracle["create_tag7"]["operations"].as_array().unwrap() {
        rows.push(SegmentEntry {
            cf: ColumnFamily(row["cf_utf8"].as_str().unwrap().into()),
            key: bytes(row["key_hex"].as_str().unwrap()).into(),
            version: VersionedValue {
                sequence: 2,
                value: StoredValue::Put(bytes(row["value_hex"].as_str().unwrap())),
            },
        });
    }
    assert_eq!(rows.len(), 7);
    rows
}

fn flushed_create_fixture() -> (tempfile::TempDir, PraxisConfig, WriterLease) {
    let temp_root = std::env::var_os("PRAXOR_TEST_TMP_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = tempfile::tempdir_in(temp_root).unwrap();
    let lease = WriterLease::acquire(dir.path()).unwrap();
    let root = lease.root();
    let layout = DiskLayout::create(root).unwrap();
    let mut config = PraxisConfig::new(root);
    config.compression = Compression::None;
    let mut manifest = v4_manifest(&config);
    manifest.flushed_sequence = 2;
    manifest.last_sequence = 2;
    manifest.flushed_wal_id = 2;
    manifest.active_wal_id = 3;
    manifest.next_wal_id = 4;
    let value_path = layout.value_log_path(1);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let meta = SegmentWriter::write(
        SegmentWriteOptions {
            path: &layout.segment_path(0, 1),
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
        installed_create_rows(),
    )
    .unwrap();
    drop(value_log);
    fs::remove_file(value_path).unwrap();
    manifest.segments.push(meta);
    ManifestStore::new(layout.manifest_path())
        .save(&manifest)
        .unwrap();
    let mut wal_header = Vec::new();
    wal_header.extend(0x5457_4146u32.to_le_bytes());
    wal_header.extend(1u32.to_le_bytes());
    wal_header.extend(3u64.to_le_bytes());
    fs::write(layout.wal_path(3), wal_header).unwrap();
    (dir, config, lease)
}

fn rewrite_flushed_create_rows(
    lease: &WriterLease,
    config: &PraxisConfig,
    rows: Vec<SegmentEntry>,
    compression: Compression,
) {
    let layout = DiskLayout::at(lease.root());
    let value_path = layout.value_log_path(1);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let meta = SegmentWriter::write(
        SegmentWriteOptions {
            path: &layout.segment_path(0, 1),
            id: 1,
            level: 0,
            compression,
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
    fs::remove_file(value_path).unwrap();
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    manifest.segments[0] = meta;
    ManifestStore::new(manifest_path).save(&manifest).unwrap();
}

fn assert_flushed_create_refused_without_mutation(
    dir: &tempfile::TempDir,
    config: &PraxisConfig,
    lease: &WriterLease,
) {
    let before = snapshot(dir.path());
    assert!(inspect_v4_owner(lease, config, &CpuAccelerator).is_err());
    assert_eq!(snapshot(dir.path()), before);
}

fn installed_catalog_row(rows: &[SegmentEntry], key: &[u8]) -> usize {
    rows.iter()
        .position(|row| row.cf.0 == "__praxor_record_catalog_v1" && row.key.as_ref() == key)
        .unwrap()
}

#[test]
fn flushed_create_s2_literal_seven_rows_is_private_installed_endpoint() {
    let (dir, config, lease) = flushed_create_fixture();
    let before = snapshot(dir.path());
    let proof = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap();
    assert_eq!(proof.cut.flushed_sequence, 2);
    assert_eq!(proof.cut.last_sequence, 2);
    assert_eq!(proof.recovered_sequence, 2);
    assert_eq!(proof.effective.head.revision, 2);
    assert_eq!(proof.effective.head.collection_count, 1);
    assert_eq!(proof.effective.rows.len(), 5);
    assert_eq!(proof.recovered_binding, (ID, 0));
    assert_eq!(proof.recovered_allocator, Default::default());
    assert!(proof.bootstrap_effects.is_none());
    let InstalledEndpoint::FlushedCreate(installed) = &proof.installed else {
        panic!("expected installed CREATE endpoint");
    };
    assert_eq!(installed.binding, (ID, 0));
    assert_eq!(installed.allocator, Default::default());
    assert_eq!(installed.head.revision, 2);
    assert_eq!(installed.anchor.database_id, ID);
    let oracle: serde_json::Value = serde_json::from_str(ORACLE).unwrap();
    for row in oracle["create_tag7"]["operations"].as_array().unwrap() {
        let key = bytes(row["key_hex"].as_str().unwrap());
        let value = bytes(row["value_hex"].as_str().unwrap());
        assert_eq!(proof.effective.rows.get(&key), Some(&value));
    }
    assert_eq!(
        proof.effective.rows.get(&[4]),
        Some(&bytes(oracle["anchor_at_1_value_hex"].as_str().unwrap()))
    );
    assert_ne!(
        proof.effective.rows.get(&[0]),
        Some(&bytes(oracle["head_at_1_value_hex"].as_str().unwrap()))
    );
    assert_eq!(proof.wal_witnesses.len(), 1);
    assert_eq!(proof.wal_witnesses[0].id, 3);
    assert_eq!(proof.wal_witnesses[0].record_count, 0);
    assert_eq!(proof.wal_witnesses[0].full_len, 16);
    assert_eq!(proof.wal_witnesses[0].prefix_len, 16);
    assert!(proof.wal_witnesses[0].torn_start.is_none());
    proof.recheck(&lease).unwrap();
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn flushed_create_manifest_counters_and_maintenance_remain_narrow() {
    for change in [
        "f1",
        "l1",
        "l3",
        "wal_cut",
        "next_wal",
        "next_segment",
        "descriptor",
        "checkpoint",
        "authority_id",
        "generation",
    ] {
        let (dir, config, lease) = flushed_create_fixture();
        let path = lease.root().join("MANIFEST");
        let mut manifest = Manifest::decode(&fs::read(&path).unwrap(), &path).unwrap();
        match change {
            "f1" => manifest.flushed_sequence = 1,
            "l1" => manifest.last_sequence = 1,
            "l3" => manifest.last_sequence = 3,
            "wal_cut" => manifest.flushed_wal_id = 1,
            "next_wal" => manifest.next_wal_id = 5,
            "next_segment" => manifest.next_segment_id = 3,
            "descriptor" => {
                manifest
                    .record_authority
                    .as_mut()
                    .unwrap()
                    .index_descriptor_count = 1
            }
            "authority_id" => {
                manifest.record_authority.as_mut().unwrap().database_id =
                    "22222222222222222222222222222222".into();
                manifest.catalog_authority.as_mut().unwrap().database_id =
                    "22222222222222222222222222222222".into();
            }
            "generation" => {
                manifest
                    .catalog_authority
                    .as_mut()
                    .unwrap()
                    .binding
                    .generation = 6
            }
            "checkpoint" => {
                manifest.latest_checkpoint = Some(CheckpointMetadata {
                    id: 1,
                    path: lease
                        .root()
                        .join("checkpoints/00000000000000000001.chk")
                        .to_string_lossy()
                        .into(),
                    sequence: 2,
                    segment_count: 1,
                    file_digest: "00".repeat(32),
                });
            }
            _ => unreachable!(),
        }
        // Preserve valid TOML even for counter combinations that the writer
        // correctly refuses to save; the reader must reject them too.
        fs::write(&path, toml::to_string_pretty(&manifest).unwrap()).unwrap();
        assert_flushed_create_refused_without_mutation(&dir, &config, &lease);
    }
}

#[test]
fn flushed_create_rejects_extra_and_missing_physical_roles() {
    for extra in [
        "root",
        "wal1",
        "wal4",
        "segment",
        "value",
        "checkpoint",
        "tmp",
    ] {
        let (dir, config, lease) = flushed_create_fixture();
        let path = match extra {
            "root" => lease.root().join("unlisted"),
            "wal1" => lease.root().join("wal/00000000000000000001.wal"),
            "wal4" => lease.root().join("wal/00000000000000000004.wal"),
            "segment" => lease.root().join("segments/1/00000000000000000002.tseg"),
            "value" => lease.root().join("values/00000000000000000001.tval"),
            "checkpoint" => lease.root().join("checkpoints/orphan.chk"),
            "tmp" => lease.root().join("tmp/orphan"),
            _ => unreachable!(),
        };
        fs::write(path, b"extra").unwrap();
        assert_flushed_create_refused_without_mutation(&dir, &config, &lease);
    }
    for missing in ["values", "checkpoints", "tmp", "segments/1"] {
        let (dir, config, lease) = flushed_create_fixture();
        fs::remove_dir(lease.root().join(missing)).unwrap();
        assert_flushed_create_refused_without_mutation(&dir, &config, &lease);
    }
}

#[test]
fn flushed_create_refuses_redigested_semantic_segment_mutations() {
    for change in [
        "no_anchor",
        "no_binding",
        "no_allocator",
        "duplicate_binding",
        "duplicate_allocator",
        "head1",
        "head_count",
        "anchor_digest",
        "name_id",
        "schema_name",
        "namespace_id",
        "wrong_sequence",
        "duplicate_role",
        "tombstone",
        "merge",
        "expiry",
        "pointer",
        "extra_user",
    ] {
        let (dir, config, lease) = flushed_create_fixture();
        let mut rows = installed_create_rows();
        match change {
            "no_anchor" => {
                rows.remove(installed_catalog_row(&rows, &[4]));
            }
            "no_binding" => {
                rows.retain(|row| row.cf.0 != "__praxor_record_meta_v1" || row.key.as_ref() != [0]);
            }
            "no_allocator" => {
                rows.retain(|row| row.cf.0 != "__praxor_record_meta_v1" || row.key.as_ref() != [1]);
            }
            "duplicate_binding" => {
                let binding = rows
                    .iter()
                    .find(|row| row.cf.0 == "__praxor_record_meta_v1" && row.key.as_ref() == [0])
                    .unwrap()
                    .clone();
                let index = rows
                    .iter()
                    .position(|row| {
                        row.cf.0 == "__praxor_record_meta_v1" && row.key.as_ref() == [1]
                    })
                    .unwrap();
                rows[index] = binding;
            }
            "duplicate_allocator" => {
                let allocator = rows
                    .iter()
                    .find(|row| row.cf.0 == "__praxor_record_meta_v1" && row.key.as_ref() == [1])
                    .unwrap()
                    .clone();
                let index = rows
                    .iter()
                    .position(|row| {
                        row.cf.0 == "__praxor_record_meta_v1" && row.key.as_ref() == [0]
                    })
                    .unwrap();
                rows[index] = allocator;
            }
            "head1" => {
                rows.push(
                    installed_rows(true)
                        .into_iter()
                        .find(|row| {
                            row.cf.0 == "__praxor_record_catalog_v1" && row.key.as_ref() == [0]
                        })
                        .unwrap(),
                );
            }
            "head_count" => {
                let index = installed_catalog_row(&rows, &[0]);
                let StoredValue::Put(value) = &mut rows[index].version.value else {
                    unreachable!()
                };
                value[40..48].copy_from_slice(&0u64.to_le_bytes());
            }
            "anchor_digest" => {
                let index = installed_catalog_row(&rows, &[4]);
                let StoredValue::Put(value) = &mut rows[index].version.value else {
                    unreachable!()
                };
                value[40] ^= 1;
            }
            "name_id" => {
                let index = rows
                    .iter()
                    .position(|row| {
                        row.cf.0 == "__praxor_record_catalog_v1"
                            && row.key.as_ref().starts_with(&[1])
                    })
                    .unwrap();
                let StoredValue::Put(value) = &mut rows[index].version.value else {
                    unreachable!()
                };
                value[4..12].copy_from_slice(&3u64.to_le_bytes());
            }
            "schema_name" => {
                let index = rows
                    .iter()
                    .position(|row| {
                        row.cf.0 == "__praxor_record_catalog_v1"
                            && row.key.as_ref().starts_with(&[2])
                    })
                    .unwrap();
                let StoredValue::Put(value) = &mut rows[index].version.value else {
                    unreachable!()
                };
                value[27] = b'X';
            }
            "namespace_id" => {
                let index = rows
                    .iter()
                    .position(|row| {
                        row.cf.0 == "__praxor_record_catalog_v1"
                            && row.key.as_ref().starts_with(&[3])
                    })
                    .unwrap();
                let StoredValue::Put(value) = &mut rows[index].version.value else {
                    unreachable!()
                };
                value[8..16].copy_from_slice(&3u64.to_le_bytes());
            }
            "wrong_sequence" => {
                let index = installed_catalog_row(&rows, &[4]);
                rows[index].version.sequence = 2;
            }
            "duplicate_role" => {
                let index = rows
                    .iter()
                    .position(|row| {
                        row.cf.0 == "__praxor_record_catalog_v1"
                            && row.key.as_ref().starts_with(&[3])
                    })
                    .unwrap();
                rows[index] = rows[installed_catalog_row(&rows, &[4])].clone();
            }
            "tombstone" => {
                let index = installed_catalog_row(&rows, &[0]);
                rows[index].version.value = StoredValue::Delete;
            }
            "merge" => {
                let index = installed_catalog_row(&rows, &[0]);
                rows[index].version.value = StoredValue::Merge(vec![1]);
            }
            "expiry" => {
                let index = installed_catalog_row(&rows, &[0]);
                let StoredValue::Put(value) = &rows[index].version.value else {
                    unreachable!()
                };
                rows[index].version.value = StoredValue::PutWithExpiry {
                    value: value.clone(),
                    expires_at_ms: 1,
                };
            }
            "pointer" => {
                let index = installed_catalog_row(&rows, &[0]);
                rows[index].version.value = StoredValue::BlobPointer(ValuePointer {
                    path: "values/00000000000000000001.tval".into(),
                    offset: 0,
                    len: 48,
                    checksum: 0,
                });
            }
            "extra_user" => {
                rows.push(SegmentEntry {
                    cf: ColumnFamily("default".into()),
                    key: b"x".to_vec().into(),
                    version: VersionedValue {
                        sequence: 2,
                        value: StoredValue::Put(b"x".to_vec()),
                    },
                });
            }
            _ => unreachable!(),
        }
        rewrite_flushed_create_rows(&lease, &config, rows, Compression::None);
        assert_flushed_create_refused_without_mutation(&dir, &config, &lease);
    }
}

#[test]
fn flushed_create_refuses_compression_metadata_and_wal_tails() {
    let (dir, config, lease) = flushed_create_fixture();
    rewrite_flushed_create_rows(&lease, &config, installed_create_rows(), Compression::Lz4);
    assert_flushed_create_refused_without_mutation(&dir, &config, &lease);
    for change in [
        "id", "level", "entries", "min", "max", "bloom", "digest", "path",
    ] {
        let (dir, config, lease) = flushed_create_fixture();
        let path = lease.root().join("MANIFEST");
        let mut manifest = Manifest::decode(&fs::read(&path).unwrap(), &path).unwrap();
        let meta = &mut manifest.segments[0];
        match change {
            "id" => meta.id = 2,
            "level" => meta.level = 1,
            "entries" => meta.entries = 8,
            "min" => meta.min_key = b"wrong".to_vec(),
            "max" => meta.max_key = b"wrong".to_vec(),
            "bloom" => meta.bloom_filter = BloomFilter::with_expected_items(1),
            "digest" => meta.file_digest = "00".repeat(32),
            "path" => {
                meta.path = format!(
                    "{}{}.{sep}{}",
                    Path::new(&meta.path).parent().unwrap().display(),
                    std::path::MAIN_SEPARATOR,
                    Path::new(&meta.path).file_name().unwrap().to_string_lossy(),
                    sep = std::path::MAIN_SEPARATOR
                )
            }
            _ => unreachable!(),
        }
        ManifestStore::new(&path).save(&manifest).unwrap();
        assert_flushed_create_refused_without_mutation(&dir, &config, &lease);
    }
    for tail in [
        b"x".as_slice(),
        &CREATE_FRAME[..15],
        CREATE_FRAME.as_slice(),
    ] {
        let (dir, config, lease) = flushed_create_fixture();
        let path = lease.root().join("wal/00000000000000000003.wal");
        let mut wal = fs::read(&path).unwrap();
        wal.extend_from_slice(tail);
        fs::write(path, wal).unwrap();
        assert_flushed_create_refused_without_mutation(&dir, &config, &lease);
    }
    for tail_len in 2..15 {
        let (dir, config, lease) = flushed_create_fixture();
        let path = lease.root().join("wal/00000000000000000003.wal");
        let mut wal = fs::read(&path).unwrap();
        wal.extend_from_slice(&CREATE_FRAME[..tail_len]);
        fs::write(path, wal).unwrap();
        assert_flushed_create_refused_without_mutation(&dir, &config, &lease);
    }
    let (dir, config, lease) = flushed_create_fixture();
    let wal_path = lease.root().join("wal/00000000000000000003.wal");
    let mut wal = fs::read(&wal_path).unwrap();
    wal[8..16].copy_from_slice(&4u64.to_le_bytes());
    fs::write(wal_path, wal).unwrap();
    assert_flushed_create_refused_without_mutation(&dir, &config, &lease);
    let (dir, config, lease) = flushed_create_fixture();
    let segment_path = lease.root().join("segments/0/00000000000000000001.tseg");
    fs::write(segment_path, vec![0u8; 1024 * 1024 + 1]).unwrap();
    assert_flushed_create_refused_without_mutation(&dir, &config, &lease);
}

#[test]
fn flushed_create_refuses_external_hardlink_alias() {
    let (dir, config, lease) = flushed_create_fixture();
    let alias_dir = tempfile::tempdir_in(dir.path().parent().unwrap()).unwrap();
    fs::hard_link(
        lease.root().join("segments/0/00000000000000000001.tseg"),
        alias_dir.path().join("linked.tseg"),
    )
    .unwrap();
    assert_flushed_create_refused_without_mutation(&dir, &config, &lease);
}

#[test]
fn flushed_create_recheck_rejects_changed_sources_and_namespace() {
    for change in [
        "manifest",
        "segment",
        "segment_identity",
        "wal",
        "extra_wal",
        "extra_segment",
        "value",
        "role",
    ] {
        let (dir, config, lease) = flushed_create_fixture();
        let proof = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap();
        let root = lease.root();
        match change {
            "manifest" => {
                let path = root.join("MANIFEST");
                let original = fs::read_to_string(&path).unwrap();
                let altered = original.replacen("last_sequence = 2", "last_sequence = 3", 1);
                assert_ne!(original, altered);
                assert_eq!(original.len(), altered.len());
                fs::write(path, altered).unwrap();
            }
            "segment" => {
                let path = root.join("segments/0/00000000000000000001.tseg");
                let mut content = fs::read(&path).unwrap();
                content[30] ^= 1;
                fs::write(path, content).unwrap();
            }
            "segment_identity" => {
                let path = root.join("segments/0/00000000000000000001.tseg");
                let copy = root.join("segments/0/replacement");
                fs::copy(&path, &copy).unwrap();
                fs::remove_file(&path).unwrap();
                fs::rename(copy, path).unwrap();
            }
            "wal" => {
                let path = root.join("wal/00000000000000000003.wal");
                let mut wal = fs::read(&path).unwrap();
                wal.extend_from_slice(CREATE_FRAME);
                fs::write(path, wal).unwrap();
            }
            "extra_wal" => {
                fs::write(root.join("wal/00000000000000000002.wal"), b"extra").unwrap();
            }
            "extra_segment" => {
                fs::write(root.join("segments/1/00000000000000000002.tseg"), b"extra").unwrap();
            }
            "value" => {
                fs::write(root.join("values/00000000000000000001.tval"), b"extra").unwrap();
            }
            "role" => {
                fs::remove_dir(root.join("tmp")).unwrap();
                fs::write(root.join("tmp"), b"wrong kind").unwrap();
            }
            _ => unreachable!(),
        }
        let before = snapshot(dir.path());
        assert!(proof.recheck(&lease).is_err(), "{change}");
        assert_eq!(snapshot(dir.path()), before, "{change}");
    }
}

fn v4_manifest(config: &PraxisConfig) -> Manifest {
    let mut manifest = Manifest::fresh_records(config, RecordAuthority::new(ID, 0));
    manifest.format_version = 4;
    manifest.next_column_family_generation = 6;
    manifest.catalog_authority = Some(CatalogAuthorityV1 {
        kind: "core_catalog".into(),
        schema_version: 1,
        codec_version: 1,
        database_id: "11111111111111111111111111111111".into(),
        epoch: 1,
        bootstrap_sequence: 1,
        binding: CatalogBindingV1 {
            role: "catalog".into(),
            column_family: "__praxor_record_catalog_v1".into(),
            generation: 5,
        },
    });
    manifest
        .column_families
        .push(CatalogAuthorityV1::descriptor(&manifest));
    manifest.column_family_generations.insert(
        "__praxor_record_catalog_v1".into(),
        ColumnFamilyGeneration {
            id: 5,
            visible_after_sequence: 0,
        },
    );
    manifest.last_sequence = 1;
    manifest.flushed_sequence = 1;
    manifest.flushed_wal_id = 1;
    manifest.active_wal_id = 2;
    manifest.next_wal_id = 3;
    manifest.next_segment_id = 2;
    manifest
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn walk(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let meta = fs::symlink_metadata(&path).unwrap();
            assert!(!meta.file_type().is_symlink());
            if meta.is_dir() {
                out.insert(relative, None);
                walk(root, &path, out);
            } else if relative == Path::new(LOCK_FILE_NAME) {
                // The OS lock denies concurrent read opens on Windows. Its
                // permanent artifact is required to remain an empty file.
                assert_eq!(meta.len(), 0);
                out.insert(relative, Some(Vec::new()));
            } else {
                out.insert(relative, Some(fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn fixture(include_anchor: bool) -> (tempfile::TempDir, PraxisConfig, WriterLease) {
    let temp_root = std::env::var_os("PRAXOR_TEST_TMP_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = tempfile::tempdir_in(temp_root).unwrap();
    let lease = WriterLease::acquire(dir.path()).unwrap();
    let root = lease.root();
    // Keep the tree minimal. A read-only inspection that calls create(root)
    // would add checkpoints/tmp/segments/1 and fail the snapshot assertion.
    fs::create_dir(root.join("wal")).unwrap();
    fs::create_dir_all(root.join("segments/0")).unwrap();
    fs::create_dir(root.join("values")).unwrap();
    let layout = DiskLayout::at(root);
    let mut config = PraxisConfig::new(root);
    config.compression = Compression::None;
    let mut manifest = v4_manifest(&config);
    let value_path = layout.value_log_path(1);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let meta = SegmentWriter::write(
        SegmentWriteOptions {
            path: &layout.segment_path(0, 1),
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
        installed_rows(include_anchor),
    )
    .unwrap();
    drop(value_log);
    fs::remove_file(value_path).unwrap(); // No external pointers exist.
    fs::remove_dir(root.join("values")).unwrap();
    manifest.segments.push(meta);
    ManifestStore::new(layout.manifest_path())
        .save(&manifest)
        .unwrap();
    let mut wal_header = Vec::new();
    wal_header.extend(0x5457_4146u32.to_le_bytes());
    wal_header.extend(1u32.to_le_bytes());
    wal_header.extend(2u64.to_le_bytes());
    fs::write(layout.wal_path(2), wal_header).unwrap();
    (dir, config, lease)
}

fn unflushed_fixture() -> (tempfile::TempDir, PraxisConfig, WriterLease) {
    let temp_root = std::env::var_os("PRAXOR_TEST_TMP_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = tempfile::tempdir_in(temp_root).unwrap();
    let lease = WriterLease::acquire(dir.path()).unwrap();
    let root = lease.root();
    let layout = DiskLayout::create(root).unwrap();
    let mut config = PraxisConfig::new(root);
    config.compression = Compression::None;
    let mut manifest = v4_manifest(&config);
    manifest.flushed_sequence = 0;
    manifest.flushed_wal_id = 0;
    manifest.active_wal_id = 1;
    manifest.next_wal_id = 2;
    manifest.next_segment_id = 1;
    ManifestStore::new(layout.manifest_path())
        .save(&manifest)
        .unwrap();
    let mut wal = Vec::new();
    wal.extend(0x5457_4146u32.to_le_bytes());
    wal.extend(1u32.to_le_bytes());
    wal.extend(1u64.to_le_bytes());
    wal.extend(BOOTSTRAP_FRAME);
    fs::write(layout.wal_path(1), wal).unwrap();
    (dir, config, lease)
}

fn unflushed_wal_path(root: &Path) -> PathBuf {
    root.join("wal/00000000000000000001.wal")
}

fn replace_unflushed_frames(root: &Path, frames: &[u8]) {
    let path = unflushed_wal_path(root);
    let mut wal = fs::read(&path).unwrap();
    wal.truncate(16);
    wal.extend_from_slice(frames);
    fs::write(path, wal).unwrap();
}

fn append_unflushed_frame_bytes(root: &Path, bytes: &[u8]) {
    let path = unflushed_wal_path(root);
    let mut wal = fs::read(&path).unwrap();
    wal.extend_from_slice(bytes);
    fs::write(path, wal).unwrap();
}

fn assert_unflushed_refused_without_mutation(
    dir: &tempfile::TempDir,
    config: &PraxisConfig,
    lease: &WriterLease,
) {
    let before = snapshot(dir.path());
    assert!(inspect_v4_owner(lease, config, &CpuAccelerator).is_err());
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn unflushed_literal_bootstrap_s1_is_private_recovered_endpoint() {
    let (dir, config, lease) = unflushed_fixture();
    let before = snapshot(dir.path());
    let proof = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap();
    assert_eq!(
        (proof.cut.flushed_sequence, proof.cut.last_sequence),
        (0, 1)
    );
    assert_eq!(proof.recovered_sequence, 1);
    assert_eq!(proof.wal_witnesses.len(), 1);
    let wal = &proof.wal_witnesses[0];
    assert_eq!(
        (
            wal.id,
            wal.record_count,
            wal.catalog_bootstraps,
            wal.catalog_creates
        ),
        (1, 1, 1, 0)
    );
    assert_eq!((wal.full_len, wal.prefix_len), (579, 579));
    assert_eq!((wal.first_sequence, wal.last_sequence), (Some(1), Some(1)));
    assert!(wal.torn_start.is_none());
    assert_eq!(proof.effective.head.database_id, ID);
    assert_eq!(
        (
            proof.effective.head.revision,
            proof.effective.head.collection_count
        ),
        (1, 0)
    );
    assert_eq!(proof.effective.rows.len(), 2);
    assert!(matches!(proof.installed, InstalledEndpoint::Empty));
    assert_eq!(proof.recovered_binding, (ID, 0));
    assert_eq!(proof.recovered_allocator, Default::default());
    let oracle: serde_json::Value = serde_json::from_str(ORACLE).unwrap();
    for name in ["catalog_head_at_1", "catalog_anchor_at_1"] {
        let row = oracle["bootstrap_tag6"]["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"].as_str() == Some(name))
            .unwrap();
        let key = bytes(row["key_hex"].as_str().unwrap());
        let value = bytes(row["value_hex"].as_str().unwrap());
        assert_eq!(proof.effective.rows.get(&key), Some(&value));
    }
    let effects = proof.bootstrap_effects.as_ref().unwrap();
    for (effect, oracle) in effects
        .rows
        .iter()
        .zip(oracle["bootstrap_tag6"]["operations"].as_array().unwrap())
    {
        assert_eq!(effect.cf, oracle["cf_utf8"].as_str().unwrap());
        assert_eq!(
            effect.key.as_slice(),
            bytes(oracle["key_hex"].as_str().unwrap())
        );
        assert_eq!(effect.value, bytes(oracle["value_hex"].as_str().unwrap()));
    }
    proof.recheck(&lease).unwrap();
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn unflushed_bootstrap_refuses_missing_partial_wrong_and_mutated_frames() {
    for frames in [
        Vec::new(),
        BOOTSTRAP_FRAME[..200].to_vec(),
        CREATE_FRAME.to_vec(),
        oracle_mutation("bootstrap_anchor_digest_only"),
    ] {
        let (dir, config, lease) = unflushed_fixture();
        replace_unflushed_frames(lease.root(), &frames);
        assert_unflushed_refused_without_mutation(&dir, &config, &lease);
    }
    for extra in [BOOTSTRAP_FRAME.as_slice(), CREATE_FRAME.as_slice()] {
        let (dir, config, lease) = unflushed_fixture();
        append_unflushed_frame_bytes(lease.root(), extra);
        assert_unflushed_refused_without_mutation(&dir, &config, &lease);
    }
}

#[test]
fn unflushed_bootstrap_refuses_every_short_suffix_without_tail_repair() {
    for length in 1..=15 {
        let (dir, config, lease) = unflushed_fixture();
        append_unflushed_frame_bytes(lease.root(), &CREATE_FRAME[..length]);
        let before = snapshot(dir.path());
        let error = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap_err();
        assert!(
            format!("{error}").contains("incomplete or has an extra tail"),
            "suffix length {length}: {error}"
        );
        assert_eq!(snapshot(dir.path()), before);
    }
}

#[test]
fn unflushed_bootstrap_refuses_hidden_content_in_every_empty_role() {
    for role in ["segments/0", "segments/1", "values", "checkpoints", "tmp"] {
        let (dir, config, lease) = unflushed_fixture();
        fs::write(lease.root().join(role).join("hidden"), b"not installed").unwrap();
        assert_unflushed_refused_without_mutation(&dir, &config, &lease);
    }
}

#[test]
fn unflushed_bootstrap_requires_every_creation_layout_directory() {
    for role in ["segments/0", "segments/1", "values", "checkpoints", "tmp"] {
        let (dir, config, lease) = unflushed_fixture();
        fs::remove_dir(lease.root().join(role)).unwrap();
        assert_unflushed_refused_without_mutation(&dir, &config, &lease);

        let (dir, config, lease) = unflushed_fixture();
        fs::remove_dir(lease.root().join(role)).unwrap();
        fs::write(lease.root().join(role), b"wrong role type").unwrap();
        assert_unflushed_refused_without_mutation(&dir, &config, &lease);
    }

    let (dir, config, lease) = unflushed_fixture();
    fs::remove_file(unflushed_wal_path(lease.root())).unwrap();
    fs::remove_dir(lease.root().join("wal")).unwrap();
    assert_unflushed_refused_without_mutation(&dir, &config, &lease);

    let (dir, config, lease) = unflushed_fixture();
    fs::remove_file(unflushed_wal_path(lease.root())).unwrap();
    fs::remove_dir(lease.root().join("wal")).unwrap();
    fs::write(lease.root().join("wal"), b"wrong role type").unwrap();
    assert_unflushed_refused_without_mutation(&dir, &config, &lease);

    for replace in [false, true] {
        let (dir, config, lease) = unflushed_fixture();
        for level in ["0", "1"] {
            fs::remove_dir(lease.root().join("segments").join(level)).unwrap();
        }
        fs::remove_dir(lease.root().join("segments")).unwrap();
        if replace {
            fs::write(lease.root().join("segments"), b"wrong role type").unwrap();
        }
        assert_unflushed_refused_without_mutation(&dir, &config, &lease);
    }
}

#[test]
fn unflushed_bootstrap_refuses_extra_root_or_second_wal() {
    let (dir, config, lease) = unflushed_fixture();
    fs::write(lease.root().join("unlisted"), b"hidden").unwrap();
    assert_unflushed_refused_without_mutation(&dir, &config, &lease);

    let (dir, config, lease) = unflushed_fixture();
    let mut second_header = fs::read(unflushed_wal_path(lease.root())).unwrap()[..16].to_vec();
    second_header[8..16].copy_from_slice(&2u64.to_le_bytes());
    fs::write(
        lease.root().join("wal/00000000000000000002.wal"),
        second_header,
    )
    .unwrap();
    assert_unflushed_refused_without_mutation(&dir, &config, &lease);
}

#[test]
fn unflushed_bootstrap_refuses_manifest_and_wal_hardlink_aliases() {
    for role in ["MANIFEST", "wal/00000000000000000001.wal"] {
        let (dir, config, lease) = unflushed_fixture();
        let alias_dir = tempfile::tempdir_in(dir.path().parent().unwrap()).unwrap();
        fs::hard_link(lease.root().join(role), alias_dir.path().join("alias")).unwrap();
        let before = snapshot(dir.path());
        let error = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap_err();
        assert!(
            format!("{error}").contains("hardlink alias"),
            "{role}: {error}"
        );
        assert_eq!(snapshot(dir.path()), before);
    }
}

#[test]
fn unflushed_bootstrap_recheck_refuses_same_length_wal_and_manifest_replacement() {
    let (dir, config, lease) = unflushed_fixture();
    let proof = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap();
    replace_unflushed_frames(
        lease.root(),
        &oracle_mutation("bootstrap_anchor_digest_only"),
    );
    let before = snapshot(dir.path());
    assert!(proof.recheck(&lease).is_err());
    assert_eq!(snapshot(dir.path()), before);

    let (dir, config, lease) = unflushed_fixture();
    let proof = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap();
    let path = lease.root().join("MANIFEST");
    let bytes = fs::read(&path).unwrap();
    let moved = tempfile::tempdir_in(dir.path().parent().unwrap()).unwrap();
    fs::rename(&path, moved.path().join("original-MANIFEST")).unwrap();
    fs::write(&path, bytes).unwrap();
    let before = snapshot(dir.path());
    assert!(proof.recheck(&lease).is_err());
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn unflushed_bootstrap_recheck_refuses_new_content_in_every_empty_role() {
    for role in ["segments/0", "segments/1", "values", "checkpoints", "tmp"] {
        let (dir, config, lease) = unflushed_fixture();
        let proof = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap();
        fs::write(lease.root().join(role).join("after-proof"), b"hidden").unwrap();
        let before = snapshot(dir.path());
        assert!(proof.recheck(&lease).is_err(), "{role}");
        assert_eq!(snapshot(dir.path()), before);
    }
}

#[test]
fn unflushed_bootstrap_recheck_refuses_replaced_required_directory() {
    let (dir, config, lease) = unflushed_fixture();
    let proof = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap();
    let path = lease.root().join("values");
    fs::remove_dir(&path).unwrap();
    fs::write(&path, b"wrong role type").unwrap();
    let before = snapshot(dir.path());
    assert!(proof.recheck(&lease).is_err());
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn retired_bootstrap_has_four_physical_rows_and_header_only_active_wal() {
    let (dir, config, lease) = fixture(true);
    let before = snapshot(dir.path());
    let proof = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap();
    let InstalledEndpoint::FlushedBootstrap(installed) = &proof.installed else {
        panic!("expected flushed installed endpoint");
    };
    assert_eq!(installed.binding, (ID, 0));
    assert_eq!(installed.allocator, Default::default());
    assert_eq!(installed.head.database_id, ID);
    assert_eq!(installed.head.revision, 1);
    assert_eq!(installed.head.collection_count, 0);
    assert_eq!(installed.anchor.database_id, ID);
    assert_eq!(proof.recovered_binding, (ID, 0));
    assert_eq!(proof.recovered_allocator, Default::default());
    assert!(proof.bootstrap_effects.is_none());
    assert_eq!(proof.cut.flushed_sequence, 1);
    assert_eq!(proof.cut.last_sequence, 1);
    assert_eq!(proof.recovered_sequence, 1);
    assert_eq!(proof.wal_witnesses.len(), 1);
    assert_eq!(proof.wal_witnesses[0].id, 2);
    assert_eq!(proof.wal_witnesses[0].record_count, 0);
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn complete_unreceipted_create_s2_replays_read_only_from_installed_f1() {
    let (dir, config, lease) = fixture(true);
    append_to_active_wal(lease.root(), CREATE_FRAME);
    let before = snapshot(dir.path());
    let proof = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap();
    assert_eq!(proof.cut.flushed_sequence, 1);
    assert_eq!(proof.cut.last_sequence, 1);
    assert_eq!(proof.recovered_sequence, 2);
    assert_eq!(proof.wal_witnesses.len(), 1);
    assert_eq!(proof.wal_witnesses[0].id, 2);
    assert_eq!(proof.wal_witnesses[0].record_count, 1);
    assert_eq!(proof.wal_witnesses[0].catalog_creates, 1);
    assert_eq!(proof.wal_witnesses[0].full_len, 440);
    let InstalledEndpoint::FlushedBootstrap(installed) = &proof.installed else {
        panic!("expected flushed installed endpoint");
    };
    assert_eq!(installed.binding, (ID, 0));
    assert_eq!(installed.allocator, Default::default());
    assert_eq!(installed.head.revision, 1); // installed Head remains separate
    assert_eq!(installed.anchor.database_id, ID);
    assert_eq!(proof.recovered_binding, (ID, 0));
    assert_eq!(proof.recovered_allocator, Default::default());
    assert!(proof.bootstrap_effects.is_none());
    assert_eq!(proof.effective.head.database_id, ID);
    assert_eq!(proof.effective.head.revision, 2);
    assert_eq!(proof.effective.head.collection_count, 1);
    assert_eq!(proof.effective.rows.len(), 5);
    let oracle: serde_json::Value = serde_json::from_str(ORACLE).unwrap();
    for row in oracle["create_tag7"]["operations"].as_array().unwrap() {
        let key = bytes(row["key_hex"].as_str().unwrap());
        let value = bytes(row["value_hex"].as_str().unwrap());
        assert_eq!(proof.effective.rows.get(&key), Some(&value));
    }
    assert_eq!(
        proof.effective.rows.get(&[4]),
        Some(&bytes(oracle["anchor_at_1_value_hex"].as_str().unwrap()))
    );
    proof.recheck(&lease).unwrap();
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn rechecksummed_create_mutations_are_refused_against_installed_head() {
    for (name, expected) in [
        (
            "create_prior_revision_only",
            "catalog CREATE frame relation mismatch",
        ),
        (
            "create_schema_collection_id_only",
            "catalog schema key/namespace ID mismatch",
        ),
    ] {
        let (dir, config, lease) = fixture(true);
        append_to_active_wal(lease.root(), &oracle_mutation(name));
        let before = snapshot(dir.path());
        let error = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap_err();
        assert!(format!("{error}").contains(expected), "{name}: {error}");
        assert_eq!(snapshot(dir.path()), before);
    }
}

#[test]
fn second_complete_s2_or_user_frame_discards_staged_create() {
    for second in [
        CREATE_FRAME.to_vec(),
        WalRecord {
            sequence: 3,
            batch: WriteBatch::new(),
        }
        .encode(),
    ] {
        let (dir, config, lease) = fixture(true);
        append_to_active_wal(lease.root(), CREATE_FRAME);
        append_to_active_wal(lease.root(), &second);
        let before = snapshot(dir.path());
        assert!(inspect_v4_owner(&lease, &config, &CpuAccelerator).is_err());
        assert_eq!(snapshot(dir.path()), before);
    }
}

#[test]
fn standalone_valid_user_s2_is_not_a_catalog_owner() {
    let (dir, config, lease) = fixture(true);
    let user = WalRecord {
        sequence: 2,
        batch: WriteBatch::new(),
    }
    .encode();
    append_to_active_wal(lease.root(), &user);
    let before = snapshot(dir.path());
    let error = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap_err();
    assert!(
        format!("{error}").contains("unexpected v4 WAL frame kind"),
        "{error}"
    );
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn valid_s2_followed_by_any_short_active_frame_prefix_is_not_an_owner() {
    for tail_len in 1..=15 {
        let (dir, config, lease) = fixture(true);
        append_to_active_wal(lease.root(), CREATE_FRAME);
        append_to_active_wal(lease.root(), &CREATE_FRAME[..tail_len]);
        let before = snapshot(dir.path());
        let error = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap_err();
        assert!(
            format!("{error}").contains("incomplete or extra tail"),
            "tail length {tail_len}: {error}"
        );
        assert_eq!(snapshot(dir.path()), before);
    }
}

#[test]
fn private_recheck_rejects_same_length_rechecksummed_wal_replacement() {
    let (dir, config, lease) = fixture(true);
    append_to_active_wal(lease.root(), CREATE_FRAME);
    let proof = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap();
    let path = lease.root().join("wal/00000000000000000002.wal");
    let original_len = fs::metadata(&path).unwrap().len();
    let mut replacement = fs::read(&path).unwrap()[..16].to_vec();
    replacement.extend(oracle_mutation("create_prior_revision_only"));
    assert_eq!(replacement.len() as u64, original_len);
    fs::write(path, replacement).unwrap();
    let before = snapshot(dir.path());
    assert!(proof.recheck(&lease).is_err());
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn manifest_l2_without_complete_s2_fails_closed() {
    let (dir, config, lease) = fixture(true);
    let path = lease.root().join("MANIFEST");
    let mut manifest = Manifest::decode(&fs::read(&path).unwrap(), &path).unwrap();
    manifest.last_sequence = 2;
    ManifestStore::new(&path).save(&manifest).unwrap();
    let before = snapshot(dir.path());
    assert!(inspect_v4_owner(&lease, &config, &CpuAccelerator).is_err());
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn missing_anchor_in_valid_redigested_segment_is_refused_without_mutation() {
    let (dir, config, lease) = fixture(false);
    let before = snapshot(dir.path());
    let error = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap_err();
    assert!(format!("{error}").contains("Anchor"), "{error}");
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn physical_proof_recheck_rejects_same_length_manifest_change() {
    let (dir, config, lease) = fixture(true);
    let proof = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap();
    proof.recheck(&lease).unwrap();
    let path = dir.path().join("MANIFEST");
    let original = fs::read_to_string(&path).unwrap();
    let changed = original.replacen("last_sequence = 1", "last_sequence = 2", 1);
    assert_ne!(changed, original);
    assert_eq!(changed.len(), original.len());
    fs::write(path, changed).unwrap();
    let before = snapshot(dir.path());
    assert!(proof.recheck(&lease).is_err());
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn bootstrap_inspection_rejects_unlisted_root_entry_without_mutation() {
    let (dir, config, lease) = fixture(true);
    fs::write(dir.path().join("unlisted"), b"hidden").unwrap();
    let before = snapshot(dir.path());
    let error = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap_err();
    assert!(format!("{error}").contains("unexpected v4 bootstrap root entry"));
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn canonical_file_with_noncanonical_manifest_segment_label_is_refused() {
    let (dir, config, lease) = fixture(true);
    let manifest_path = lease.root().join("MANIFEST");
    let bytes = fs::read(&manifest_path).unwrap();
    let mut manifest = Manifest::decode(&bytes, &manifest_path).unwrap();
    let canonical = PathBuf::from(&manifest.segments[0].path);
    manifest.segments[0].path = format!(
        "{}{}.{sep}{}",
        canonical.parent().unwrap().display(),
        std::path::MAIN_SEPARATOR,
        canonical.file_name().unwrap().to_string_lossy(),
        sep = std::path::MAIN_SEPARATOR,
    );
    assert_ne!(manifest.segments[0].path, canonical.to_string_lossy());
    ManifestStore::new(&manifest_path).save(&manifest).unwrap();
    let before = snapshot(dir.path());
    let error = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap_err();
    assert!(format!("{error}").contains("metadata mismatch"), "{error}");
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn compressed_bomb_declared_segment_refuses_before_decode_without_mutation() {
    let (dir, config, lease) = fixture(true);
    let layout = DiskLayout::at(lease.root());
    fs::create_dir(lease.root().join("values")).unwrap();
    let value_path = layout.value_log_path(1);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let mut metadata = SegmentWriter::write(
        SegmentWriteOptions {
            path: &layout.segment_path(0, 1),
            id: 1,
            level: 0,
            compression: Compression::Lz4,
            accelerator: &CpuAccelerator,
            value_log: &mut value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: config.block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        installed_rows(true),
    )
    .unwrap();
    drop(value_log);
    fs::remove_file(value_path).unwrap();
    fs::remove_dir(lease.root().join("values")).unwrap();
    let segment_path = layout.segment_path(0, 1);
    let mut segment = fs::read(&segment_path).unwrap();
    assert_eq!(segment[8], 1);
    // The outer block framing, compressed bytes, CRC and footer stay intact.
    // A naive decoder can trust this forged decoded-size claim too early.
    segment[25..29].copy_from_slice(&(512u32 * 1024 * 1024).to_le_bytes());
    fs::write(&segment_path, &segment).unwrap();
    metadata.file_digest = blake3::hash(&segment).to_hex().to_string();
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    manifest.segments[0] = metadata;
    ManifestStore::new(manifest_path).save(&manifest).unwrap();
    let before = snapshot(dir.path());
    let error = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap_err();
    assert!(format!("{error}").contains("compressed v4 bootstrap segment"));
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn dangling_checkpoint_metadata_is_outside_pristine_bootstrap_cut() {
    let (dir, config, lease) = fixture(true);
    let manifest_path = lease.root().join("MANIFEST");
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    manifest.latest_checkpoint = Some(CheckpointMetadata {
        id: 1,
        path: lease
            .root()
            .join("checkpoints/00000000000000000001.chk")
            .to_string_lossy()
            .into(),
        sequence: 1,
        segment_count: 1,
        file_digest: "00".repeat(32),
    });
    ManifestStore::new(&manifest_path).save(&manifest).unwrap();
    let before = snapshot(dir.path());
    let error = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap_err();
    assert!(matches!(
        error,
        crate::errors::PraxisError::UnsupportedCatalogFeature { .. }
    ));
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn external_manifest_hardlink_alias_is_refused_without_mutation() {
    let (dir, config, lease) = fixture(true);
    let alias_dir = tempfile::tempdir_in(dir.path().parent().unwrap()).unwrap();
    fs::hard_link(
        lease.root().join("MANIFEST"),
        alias_dir.path().join("MANIFEST"),
    )
    .unwrap();
    let before = snapshot(dir.path());
    let error = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap_err();
    assert!(format!("{error}").contains("hardlink alias"), "{error}");
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn retired_cut_refuses_unexpected_active_wal_frame_without_mutation() {
    let (dir, config, lease) = fixture(true);
    let path = lease.root().join("wal/00000000000000000002.wal");
    let mut bytes = fs::read(&path).unwrap();
    bytes.extend(BOOTSTRAP_FRAME);
    fs::write(path, bytes).unwrap();
    let before = snapshot(dir.path());
    let error = inspect_v4_owner(&lease, &config, &CpuAccelerator).unwrap_err();
    assert!(
        format!("{error}").contains("unexpected v4 WAL frame"),
        "{error}"
    );
    assert_eq!(snapshot(dir.path()), before);
}

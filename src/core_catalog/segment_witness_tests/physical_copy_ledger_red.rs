use super::*;
use crate::core_catalog::codec::{Anchor, anchor_digest};
use crate::core_catalog::physical_copy::{
    CopyWireOperation, collect_protected_copy_admission, collect_protected_copy_ledger,
};
use crate::core_catalog::value_witness::{
    ValueFileScanProbe, ValueRowLocator, collect_value_witness, validate_inline_catalog_schema_put,
};
use crate::core_records::codec::{
    Allocator as RecordAllocator, Decision as RecordDecision, Envelope as RecordEnvelope,
    Key as RecordKey, Kind as RecordKind, Role as RecordRole, Row as RecordRow,
};
use crate::core_records::intent::{
    IntentKind as RecordIntentKind, Mapping as RecordMapping, NewRecord, RecordIntent,
};
use crate::core_records::transition::{
    Context as RecordContext, Rows as RecordRows, Summary as RecordSummary, check_bootstrap_ops,
    plan as plan_record,
};
use crate::segments::format::SEGMENT_FOOTER_MAGIC;
use crate::transactions::{BatchOp, WriteBatch};
use crate::wal::record::{CoreRecordPrefix, CoreWalRecord, parse_core_record_prefix};

const FIXED_ORACLE: &str = include_str!("../../../tests/fixtures/catalog_v4_wal_oracle.json");
const CATALOG_CREATE_FRAME: &[u8; 424] =
    include_bytes!("../../../tests/fixtures/catalog_tag7_create_s2.bin");

#[test]
fn writer_inline_schema_syntax_is_checked_before_copy_admission_and_refunds() {
    for malformed in [false, true] {
        let (dir, config, lease) = flushed_create_fixture();
        let root = lease.root();
        let layout = DiskLayout::at(root);
        let segment_path = layout.segment_path(0, 1);
        let manifest_path = layout.manifest_path();
        let original_manifest =
            Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
        assert_eq!(original_manifest.flushed_sequence, 2);
        assert_eq!(original_manifest.segments.len(), 1);
        assert_eq!(original_manifest.segments[0].entries, 7);

        let original_bytes = fs::read(&segment_path).unwrap();
        assert_eq!(
            original_manifest.segments[0].file_digest,
            blake3::hash(&original_bytes).to_hex().to_string()
        );
        let original = decode_segment(&original_bytes, &segment_path, &CpuAccelerator).unwrap();
        assert_eq!((original.level, original.id), (0, 1));
        let schema_key = CatalogKey::Schema(CollectionId::new(2).unwrap())
            .encode()
            .unwrap();
        let valid_schema = fixed_copy_oracle(
            "create_tag7",
            "catalog_schema_id_2",
            CATALOG_CF,
            &schema_key,
            2,
        );
        assert_eq!(valid_schema.len(), 65);
        assert!(matches!(
            CatalogValue::decode(
                &CatalogKey::Schema(CollectionId::new(2).unwrap()),
                &valid_schema,
                root,
            )
            .unwrap(),
            CatalogValue::Schema(_)
        ));

        let mut rows = original
            .blocks
            .into_iter()
            .flatten()
            .map(|raw| raw.entry)
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 7);
        let schema_rows = rows
            .iter_mut()
            .filter(|row| {
                row.cf.0 == CATALOG_CF
                    && row.key.as_ref() == schema_key.as_slice()
                    && row.version.sequence == 2
            })
            .collect::<Vec<_>>();
        assert_eq!(schema_rows.len(), 1);
        let schema_row = &mut *schema_rows.into_iter().next().unwrap();
        let StoredValue::Put(schema_bytes) = &mut schema_row.version.value else {
            panic!("writer fixture Schema@2 must be inline")
        };
        assert_eq!(schema_bytes.as_slice(), valid_schema.as_slice());
        if malformed {
            // The final byte is the second field's reserved byte. The writer
            // rechecksums the segment, so only Schema syntax is invalid.
            *schema_bytes.last_mut().unwrap() = 1;
            assert!(matches!(
                CatalogValue::decode(
                    &CatalogKey::Schema(CollectionId::new(2).unwrap()),
                    schema_bytes,
                    root,
                ),
                Err(PraxisError::Corrupt { reason, .. })
                    if reason == "nonzero catalog field reserved bytes"
            ));
        }
        let expected_schema = schema_bytes.clone();
        let expected_entry = schema_row.clone();
        let manifest = rewrite_first_segment(
            root,
            rows,
            Compression::None,
            config.large_value_threshold,
            config.block_size,
        );
        assert_eq!(manifest.segments.len(), 1);
        assert_eq!(manifest.segments[0].entries, 7);
        assert_eq!(manifest.flushed_sequence, 2);
        assert_eq!(manifest.effective_config, config.persisted());
        let written_bytes = fs::read(&segment_path).unwrap();
        assert_eq!(
            manifest.segments[0].file_digest,
            blake3::hash(&written_bytes).to_hex().to_string()
        );
        let written = decode_segment(&written_bytes, &segment_path, &CpuAccelerator).unwrap();
        assert_eq!((written.level, written.id), (0, 1));
        let offsets = literal_block_offsets(&written_bytes, 0, 1, written.blocks.len());
        let expected_location = exact_entry_location(&written, &offsets, &expected_entry);
        let expected_id = physical_id(&File::open(&segment_path).unwrap(), &segment_path).unwrap();
        let before = snapshot(dir.path());

        with_wal_budget(root, &manifest, |budget| {
            let mut observed = Vec::new();
            let witnesses = visit_v4_segments(root, &manifest, budget, |row| {
                observed.push(row);
                Ok(())
            })
            .expect("bounded visitor must accept writer-produced Schema wire bytes");
            assert_eq!(witnesses.len(), 1);
            assert_eq!(
                witnesses[0].source,
                SegmentSource {
                    level: 0,
                    id: 1,
                    manifest_ordinal: 0,
                }
            );
            assert_eq!(witnesses[0].path, segment_path);
            assert_eq!(witnesses[0].len, written_bytes.len() as u64);
            assert_eq!(witnesses[0].digest, blake3::hash(&written_bytes));
            assert_eq!(witnesses[0].identity, expected_id);
            assert_eq!(witnesses[0].observed_rows, 7);
            let staged_schema = observed
                .iter()
                .filter(|row| row.cf == CATALOG_CF && row.key == schema_key && row.sequence == 2)
                .collect::<Vec<_>>();
            assert_eq!(staged_schema.len(), 1);
            let staged_schema = staged_schema[0];
            assert_eq!(
                (staged_schema.block_offset, staged_schema.row_ordinal),
                expected_location
            );
            assert_eq!(
                staged_schema.classification,
                PhysicalRowClass::BoundProtected(ProtectedRole::Catalog)
            );
            assert_eq!(
                staged_schema.value,
                ObservedSegmentValue::Put(expected_schema.clone())
            );
            assert_eq!(snapshot(dir.path()), before);

            let balance = budget.remaining_bytes();
            let direct_syntax = validate_inline_catalog_schema_put(root, staged_schema, budget);
            if malformed {
                assert!(matches!(
                    direct_syntax,
                    Err(PraxisError::Corrupt { reason, .. })
                        if reason == "nonzero catalog field reserved bytes"
                ));
            } else {
                direct_syntax.expect("valid inline Schema must pass charged syntax validation");
            }
            assert_eq!(budget.remaining_bytes(), balance);

            let result = collect_protected_copy_ledger(root, &manifest, budget);
            if malformed {
                assert!(
                    matches!(
                        result,
                        Err(PraxisError::Corrupt { reason, .. })
                            if reason == "nonzero catalog field reserved bytes"
                    ),
                    "malformed inline Schema must be Corrupt before pending admission"
                );
            } else {
                assert!(
                    matches!(
                        result,
                        Err(PraxisError::UnsupportedCatalogFeature {
                            feature: "protected physical-copy bytes await authenticated replay"
                        })
                    ),
                    "valid inline Schema must reach only the pending private gate"
                );
            }
            assert_eq!(budget.remaining_bytes(), balance);
            assert_eq!(snapshot(dir.path()), before);
        });
        assert_eq!(snapshot(dir.path()), before);
    }
}

fn oracle_bytes(hex: &str) -> Vec<u8> {
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn literal_block_offsets(bytes: &[u8], level: u32, id: u64, count: usize) -> Vec<u64> {
    assert!(bytes.len() >= 33);
    assert_eq!(
        &bytes[..4],
        &crate::segments::format::SEGMENT_MAGIC.to_le_bytes()
    );
    assert_eq!(
        &bytes[4..8],
        &crate::segments::format::SEGMENT_VERSION.to_le_bytes()
    );
    assert_eq!(bytes[8], 0, "fixture must be literal and uncompressed");
    assert_eq!(u32::from_le_bytes(bytes[9..13].try_into().unwrap()), level);
    assert_eq!(u64::from_le_bytes(bytes[13..21].try_into().unwrap()), id);
    let trailer = bytes.len() - 12;
    let footer_len = u32::from_le_bytes(bytes[trailer..trailer + 4].try_into().unwrap()) as usize;
    let footer = trailer.checked_sub(footer_len).unwrap();
    assert_eq!(
        u32::from_le_bytes(bytes[trailer + 8..].try_into().unwrap()),
        SEGMENT_FOOTER_MAGIC
    );
    assert_eq!(
        crc32c(&bytes[footer..trailer]),
        u32::from_le_bytes(bytes[trailer + 4..trailer + 8].try_into().unwrap())
    );
    let mut at = 21usize;
    let mut offsets = Vec::new();
    for _ in 0..count {
        assert!(at + 12 <= footer);
        let encoded = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        let decoded = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        let checksum = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap());
        assert_eq!(encoded, decoded);
        let end = at.checked_add(12).unwrap().checked_add(encoded).unwrap();
        assert!(end <= footer);
        assert_eq!(crc32c(&bytes[at + 12..end]), checksum);
        offsets.push(at as u64);
        at = end;
    }
    assert_eq!(at, footer);
    offsets
}

#[test]
fn writer_produced_duplicate_head_at_s2_reaches_private_copy_ledger() {
    let (dir, config, lease) = flushed_create_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.flushed_sequence, 2);
    assert_eq!(manifest.segments.len(), 1);
    assert_eq!(manifest.segments[0].entries, 7);

    // Select the exact valid Head@2 operation from independently decoded
    // writer output, then write a second valid physical segment with it.
    let first_path = layout.segment_path(0, 1);
    assert_eq!(manifest.segments[0].path, first_path.to_str().unwrap());
    let first_bytes = fs::read(&first_path).unwrap();
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&first_bytes).to_hex().to_string()
    );
    let first = decode_segment(&first_bytes, &first_path, &CpuAccelerator).unwrap();
    assert_eq!((first.level, first.id), (0, 1));
    assert_eq!(first.blocks.iter().map(Vec::len).sum::<usize>(), 7);
    let first_offsets = literal_block_offsets(&first_bytes, 0, 1, first.blocks.len());

    // A fixed independent oracle prevents two identically bad writer/decoder
    // results from masquerading as equal protected copies.
    let oracle: serde_json::Value = serde_json::from_str(FIXED_ORACLE).unwrap();
    for (section, name, cf, key, sequence, len) in [
        ("create_tag7", "catalog_head_at_2", CATALOG_CF, [0u8], 2, 48),
        (
            "bootstrap_tag6",
            "record_allocator",
            "__praxor_record_meta_v1",
            [1u8],
            1,
            56,
        ),
        (
            "bootstrap_tag6",
            "catalog_anchor_at_1",
            CATALOG_CF,
            [4u8],
            1,
            72,
        ),
    ] {
        let operation = oracle[section]["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|operation| operation["name"].as_str() == Some(name))
            .unwrap();
        assert_eq!(operation["cf_utf8"].as_str(), Some(cf));
        assert_eq!(
            oracle_bytes(operation["key_hex"].as_str().unwrap()).as_slice(),
            key.as_slice()
        );
        let value = oracle_bytes(operation["value_hex"].as_str().unwrap());
        assert_eq!(value.len(), len);
        let matching = first
            .blocks
            .iter()
            .flatten()
            .filter(|raw| {
                raw.entry.cf.0 == cf
                    && raw.entry.key.as_ref() == key.as_slice()
                    && raw.entry.version.sequence == sequence
            })
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1, "fixed oracle row {name}");
        assert_eq!(matching[0].entry.version.value, StoredValue::Put(value));
        assert!(matching[0].blob_expiry.is_none());
    }
    let head_key = CatalogKey::Head.encode().unwrap();
    let head = first
        .blocks
        .iter()
        .flatten()
        .find(|raw| {
            raw.entry.cf.0 == CATALOG_CF
                && raw.entry.key.as_ref() == head_key.as_slice()
                && raw.entry.version.sequence == 2
        })
        .unwrap()
        .entry
        .clone();
    let StoredValue::Put(ref head_bytes) = head.version.value else {
        panic!("writer fixture Head@2 must be literal")
    };
    assert_eq!(head_bytes.len(), 48);
    assert!(matches!(
        CatalogValue::decode(&CatalogKey::Head, head_bytes, &first_path).unwrap(),
        CatalogValue::Head(Head { revision: 2, .. })
    ));
    let mut first_head_location = None;
    for (block_index, block) in first.blocks.iter().enumerate() {
        for (row_ordinal, raw) in block.iter().enumerate() {
            if raw.entry == head {
                assert!(first_head_location.is_none());
                first_head_location = Some((
                    first_offsets[block_index],
                    u32::try_from(row_ordinal).unwrap(),
                ));
            }
        }
    }
    let first_head_location = first_head_location.unwrap();

    let second_path = layout.segment_path(1, 2);
    fs::create_dir_all(second_path.parent().unwrap()).unwrap();
    let value_path = layout.value_log_path(2);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let second_meta = SegmentWriter::write(
        SegmentWriteOptions {
            path: &second_path,
            id: 2,
            level: 1,
            compression: Compression::None,
            accelerator: &CpuAccelerator,
            value_log: &mut value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: config.block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        vec![head.clone()],
    )
    .unwrap();
    drop(value_log);
    fs::remove_file(value_path).unwrap(); // The copied row has no value pointer.

    let second_bytes = fs::read(&second_path).unwrap();
    assert_eq!(
        second_meta.file_digest,
        blake3::hash(&second_bytes).to_hex().to_string()
    );
    assert_eq!(second_meta.entries, 1);
    assert_eq!(second_meta.path, second_path.to_str().unwrap());
    assert_eq!(second_meta.min_key, head_key);
    assert_eq!(second_meta.max_key, head_key);
    let second = decode_segment(&second_bytes, &second_path, &CpuAccelerator).unwrap();
    assert_eq!((second.level, second.id), (1, 2));
    assert_eq!(second.blocks.len(), 1);
    assert_eq!(second.blocks[0].len(), 1);
    assert_eq!(second.blocks[0][0].entry, head);
    assert_eq!(
        second.blocks[0][0].entry.version.value,
        StoredValue::Put(head_bytes.to_vec())
    );
    assert!(second.blocks[0][0].blob_expiry.is_none());
    let second_offsets = literal_block_offsets(&second_bytes, 1, 2, second.blocks.len());

    manifest.segments.push(second_meta);
    manifest.next_segment_id = 3;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.segments.len(), 2);
    assert_eq!(manifest.segments[1].entries, 1);
    assert_eq!(manifest.next_segment_id, 3);
    let before = snapshot(dir.path());

    // #75 owns public composition. A second segment must not slip through
    // today's deliberately narrow public owner gate.
    assert!(matches!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(dir.path()), before);

    with_wal_budget(root, &manifest, |budget| {
        let mut observed = Vec::new();
        let witnesses = visit_v4_segments(root, &manifest, budget, |row| {
            observed.push(row);
            Ok(())
        })
        .expect("bounded visitor must admit both valid writer segments");
        assert_eq!(witnesses.len(), 2);
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
        ];
        assert_eq!(witnesses[0].source, sources[0]);
        assert_eq!(witnesses[1].source, sources[1]);
        assert_ne!(witnesses[0].identity, witnesses[1].identity);
        assert_eq!(
            (witnesses[0].observed_rows, witnesses[1].observed_rows),
            (7, 1)
        );
        for (witness, path, bytes) in [
            (&witnesses[0], &first_path, &first_bytes),
            (&witnesses[1], &second_path, &second_bytes),
        ] {
            assert_eq!(witness.path, *path);
            assert_eq!(witness.len, bytes.len() as u64);
            assert_eq!(witness.digest, blake3::hash(bytes));
            let opened = File::open(path).unwrap();
            assert_eq!(witness.identity, physical_id(&opened, path).unwrap());
        }
        let heads = observed
            .iter()
            .filter(|row| row.cf == CATALOG_CF && row.key == head_key && row.sequence == 2)
            .collect::<Vec<_>>();
        assert_eq!(heads.len(), 2, "both physical Head@2 copies must survive");
        assert_eq!((heads[0].source, heads[1].source), (sources[0], sources[1]));
        assert_eq!(
            (heads[0].block_offset, heads[0].row_ordinal),
            first_head_location
        );
        assert_eq!(
            (heads[1].block_offset, heads[1].row_ordinal),
            (second_offsets[0], 0)
        );
        assert_eq!(
            heads[0].classification,
            PhysicalRowClass::BoundProtected(ProtectedRole::Catalog)
        );
        assert_eq!(heads[1].classification, heads[0].classification);
        for row in &heads {
            assert_eq!(row.value, ObservedSegmentValue::Put(head_bytes.to_vec()));
        }
        assert_eq!(snapshot(dir.path()), before);

        let balance = budget.remaining_bytes();
        let candidate = collect_protected_copy_admission(root, &manifest, budget)
            .expect("authenticated equal Head@2 copies must stage a private candidate");
        let ledger = candidate
            .consume()
            .expect("all retained source witnesses must survive consumption");
        assert_eq!(ledger.segment_witnesses().len(), 2);
        let head_copies = ledger
            .copies()
            .filter(|copy| {
                copy.cf == CATALOG_CF && copy.key == head_key.as_slice() && copy.sequence == 2
            })
            .collect::<Vec<_>>();
        assert_eq!(head_copies.len(), 2);
        assert!(
            head_copies
                .iter()
                .all(|copy| copy.operation == CopyWireOperation::Put { len: 48 })
        );
        assert_eq!(
            (head_copies[0].source, head_copies[1].source),
            (sources[0], sources[1])
        );
        assert_eq!(
            (head_copies[0].block_offset, head_copies[0].row_ordinal),
            first_head_location
        );
        assert_eq!(
            (head_copies[1].block_offset, head_copies[1].row_ordinal),
            (second_offsets[0], 0)
        );
        assert_eq!(snapshot(dir.path()), before);
        drop(head_copies);
        drop(ledger);
        assert_eq!(
            budget.remaining_bytes(),
            balance,
            "exact owned-receipt refund"
        );
        assert_eq!(snapshot(dir.path()), before);
    });
}

#[derive(Clone, Copy)]
enum NextCopyCase {
    IdenticalAllocator,
    ConflictingHead,
    IdenticalBinding,
    ConflictingBinding,
}

struct NextCopyFixture {
    dir: tempfile::TempDir,
    config: PraxisConfig,
    lease: WriterLease,
    manifest: Manifest,
    original: SegmentEntry,
    written: SegmentEntry,
    first_path: PathBuf,
    second_path: PathBuf,
    first_bytes: Vec<u8>,
    second_bytes: Vec<u8>,
    first_location: (u64, u32),
    second_location: (u64, u32),
    before: BTreeMap<PathBuf, TreeEntry>,
}

fn fixed_copy_oracle(section: &str, name: &str, cf: &str, key: &[u8], sequence: u64) -> Vec<u8> {
    let oracle: serde_json::Value = serde_json::from_str(FIXED_ORACLE).unwrap();
    assert_eq!(oracle[section]["sequence"].as_u64(), Some(sequence));
    let row = oracle[section]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"].as_str() == Some(name))
        .unwrap();
    assert_eq!(row["cf_utf8"].as_str(), Some(cf));
    assert_eq!(oracle_bytes(row["key_hex"].as_str().unwrap()), key);
    let value = oracle_bytes(row["value_hex"].as_str().unwrap());
    assert_eq!(row["value_length"].as_u64(), Some(value.len() as u64));
    value
}

fn exact_entry_location(
    decoded: &crate::segments::codec::RawSegment,
    offsets: &[u64],
    wanted: &SegmentEntry,
) -> (u64, u32) {
    let locations = decoded
        .blocks
        .iter()
        .enumerate()
        .flat_map(|(block_index, block)| {
            block
                .iter()
                .enumerate()
                .filter_map(move |(row_index, row)| {
                    row.entry
                        .eq(wanted)
                        .then_some((offsets[block_index], u32::try_from(row_index).unwrap()))
                })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        locations.len(),
        1,
        "writer row must have one physical locator"
    );
    locations[0]
}

/// Both new tests share a seven-row CREATE segment plus one independently
/// writer-produced literal row; no segment bytes or checksums are hand-edited.
fn next_copy_fixture(case: NextCopyCase) -> NextCopyFixture {
    let (dir, config, lease) = flushed_create_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.flushed_sequence, 2);
    assert_eq!(manifest.segments.len(), 1);
    assert_eq!(manifest.segments[0].entries, 7);

    let first_path = layout.segment_path(0, 1);
    let first_bytes = fs::read(&first_path).unwrap();
    assert_eq!(manifest.segments[0].path, first_path.to_str().unwrap());
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&first_bytes).to_hex().to_string()
    );
    let first = decode_segment(&first_bytes, &first_path, &CpuAccelerator).unwrap();
    assert_eq!((first.level, first.id), (0, 1));
    assert_eq!(first.blocks.iter().map(Vec::len).sum::<usize>(), 7);
    let first_offsets = literal_block_offsets(&first_bytes, 0, 1, first.blocks.len());

    // The fixed JSON ties these cases to independent canonical bytes, including
    // the unique Anchor that the second segment deliberately does not copy.
    for (section, name, cf, key, sequence) in [
        (
            "create_tag7",
            "catalog_head_at_2",
            CATALOG_CF,
            &[0u8][..],
            2,
        ),
        (
            "bootstrap_tag6",
            "record_binding",
            "__praxor_record_meta_v1",
            &[0u8][..],
            1,
        ),
        (
            "bootstrap_tag6",
            "record_allocator",
            "__praxor_record_meta_v1",
            &[1u8][..],
            1,
        ),
        (
            "bootstrap_tag6",
            "catalog_anchor_at_1",
            CATALOG_CF,
            &[4u8][..],
            1,
        ),
    ] {
        let fixed = fixed_copy_oracle(section, name, cf, key, sequence);
        let rows = first
            .blocks
            .iter()
            .flatten()
            .filter(|row| {
                row.entry.cf.0 == cf
                    && row.entry.key.as_ref() == key
                    && row.entry.version.sequence == sequence
            })
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 1, "fixed oracle row {name}");
        assert_eq!(rows[0].entry.version.value, StoredValue::Put(fixed));
        assert!(rows[0].blob_expiry.is_none());
    }

    let (cf, key, sequence) = match case {
        NextCopyCase::IdenticalAllocator => ("__praxor_record_meta_v1", &[1u8][..], 1),
        NextCopyCase::ConflictingHead => (CATALOG_CF, &[0u8][..], 2),
        NextCopyCase::IdenticalBinding | NextCopyCase::ConflictingBinding => {
            ("__praxor_record_meta_v1", &[0u8][..], 1)
        }
    };
    let original = first
        .blocks
        .iter()
        .flatten()
        .find(|row| {
            row.entry.cf.0 == cf
                && row.entry.key.as_ref() == key
                && row.entry.version.sequence == sequence
        })
        .unwrap()
        .entry
        .clone();
    let first_location = exact_entry_location(&first, &first_offsets, &original);
    let mut written = original.clone();
    if matches!(case, NextCopyCase::ConflictingHead) {
        let StoredValue::Put(original_bytes) = &original.version.value else {
            panic!("fixed Head@2 must be literal")
        };
        let CatalogValue::Head(mut changed) =
            CatalogValue::decode(&CatalogKey::Head, original_bytes, &first_path).unwrap()
        else {
            panic!("fixed Head@2 must decode as Head")
        };
        assert_eq!(changed.revision, 2);
        assert_eq!(changed.collection_count, 1);
        changed.collection_count += 1;
        let changed_bytes = CatalogValue::Head(changed).encode().unwrap();
        assert_eq!(changed_bytes.len(), original_bytes.len());
        assert_ne!(&changed_bytes, original_bytes);
        assert_eq!(
            CatalogValue::decode(&CatalogKey::Head, &changed_bytes, &first_path).unwrap(),
            CatalogValue::Head(changed)
        );
        written.version.value = StoredValue::Put(changed_bytes);
    }
    if matches!(case, NextCopyCase::ConflictingBinding) {
        let StoredValue::Put(original_bytes) = &original.version.value else {
            panic!("fixed Binding@1 must be literal")
        };
        let RecordRow::Binding {
            database_id,
            descriptor_count,
        } = RecordRow::decode(&RecordKey::Binding, original_bytes, &first_path).unwrap()
        else {
            panic!("fixed Binding@1 must decode as Binding")
        };
        let changed_count = descriptor_count.checked_add(1).unwrap();
        let changed_bytes = RecordRow::Binding {
            database_id,
            descriptor_count: changed_count,
        }
        .encode()
        .unwrap();
        assert_eq!(changed_bytes.len(), original_bytes.len());
        assert_eq!(changed_bytes.len(), 80);
        assert_ne!(&changed_bytes, original_bytes);
        assert_eq!(
            RecordRow::decode(&RecordKey::Binding, &changed_bytes, &first_path).unwrap(),
            RecordRow::Binding {
                database_id,
                descriptor_count: changed_count,
            }
        );
        written.version.value = StoredValue::Put(changed_bytes);
    }

    let second_path = layout.segment_path(1, 2);
    fs::create_dir_all(second_path.parent().unwrap()).unwrap();
    let value_path = layout.value_log_path(2);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let second_meta = SegmentWriter::write(
        SegmentWriteOptions {
            path: &second_path,
            id: 2,
            level: 1,
            compression: Compression::None,
            accelerator: &CpuAccelerator,
            value_log: &mut value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: config.block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        vec![written.clone()],
    )
    .unwrap();
    drop(value_log);
    fs::remove_file(value_path).unwrap();

    let second_bytes = fs::read(&second_path).unwrap();
    assert_eq!(second_meta.entries, 1);
    assert_eq!(second_meta.path, second_path.to_str().unwrap());
    assert_eq!(second_meta.min_key.as_slice(), key);
    assert_eq!(second_meta.max_key.as_slice(), key);
    assert_eq!(
        second_meta.file_digest,
        blake3::hash(&second_bytes).to_hex().to_string()
    );
    let second = decode_segment(&second_bytes, &second_path, &CpuAccelerator).unwrap();
    assert_eq!((second.level, second.id), (1, 2));
    assert_eq!(second.blocks.len(), 1);
    assert_eq!(second.blocks[0].len(), 1);
    assert_eq!(second.blocks[0][0].entry, written);
    assert!(second.blocks[0][0].blob_expiry.is_none());
    let second_offsets = literal_block_offsets(&second_bytes, 1, 2, second.blocks.len());
    let second_location = exact_entry_location(&second, &second_offsets, &written);
    let first_id = physical_id(&File::open(&first_path).unwrap(), &first_path).unwrap();
    let second_id = physical_id(&File::open(&second_path).unwrap(), &second_path).unwrap();
    assert_ne!(first_id, second_id);

    manifest.segments.push(second_meta);
    manifest.next_segment_id = 3;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.segments.len(), 2);
    assert_eq!(
        manifest.segments[0].entries + manifest.segments[1].entries,
        8
    );
    assert_eq!(manifest.next_segment_id, 3);
    let before = snapshot(dir.path());
    NextCopyFixture {
        dir,
        config,
        lease,
        manifest,
        original,
        written,
        first_path,
        second_path,
        first_bytes,
        second_bytes,
        first_location,
        second_location,
        before,
    }
}

fn exercise_next_copy_case(case: NextCopyCase) {
    let fixture = next_copy_fixture(case);
    let root = fixture.lease.root();
    assert!(matches!(
        inspect_v4_owner(&fixture.lease, &fixture.config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(fixture.dir.path()), fixture.before);

    with_wal_budget(root, &fixture.manifest, |budget| {
        let mut observed = Vec::new();
        let witnesses = visit_v4_segments(root, &fixture.manifest, budget, |row| {
            observed.push(row);
            Ok(())
        })
        .expect("bounded visitor must admit both writer-produced segments");
        assert_eq!(witnesses.len(), 2);
        assert_eq!(observed.len(), 8);
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
        ];
        for (witness, source, path, bytes, count) in [
            (
                &witnesses[0],
                sources[0],
                &fixture.first_path,
                &fixture.first_bytes,
                7,
            ),
            (
                &witnesses[1],
                sources[1],
                &fixture.second_path,
                &fixture.second_bytes,
                1,
            ),
        ] {
            assert_eq!(witness.source, source);
            assert_eq!(witness.path.as_path(), path.as_path());
            assert_eq!(witness.len, bytes.len() as u64);
            assert_eq!(witness.digest, blake3::hash(bytes));
            assert_eq!(witness.observed_rows, count);
            assert_eq!(
                witness.identity,
                physical_id(&File::open(path).unwrap(), path).unwrap()
            );
        }
        assert_ne!(witnesses[0].identity, witnesses[1].identity);
        let copies = observed
            .iter()
            .filter(|row| {
                row.cf == fixture.original.cf.0
                    && row.key.as_slice() == fixture.original.key.as_ref()
                    && row.sequence == fixture.original.version.sequence
            })
            .collect::<Vec<_>>();
        assert_eq!(
            copies.len(),
            2,
            "both physical versions must survive the visitor"
        );
        assert_eq!(
            (copies[0].source, copies[1].source),
            (sources[0], sources[1])
        );
        assert_eq!(
            (copies[0].block_offset, copies[0].row_ordinal),
            fixture.first_location
        );
        assert_eq!(
            (copies[1].block_offset, copies[1].row_ordinal),
            fixture.second_location
        );
        for (observed, expected) in [
            (copies[0], &fixture.original),
            (copies[1], &fixture.written),
        ] {
            assert_eq!(
                observed.classification,
                if expected.cf.0 == CATALOG_CF {
                    PhysicalRowClass::BoundProtected(ProtectedRole::Catalog)
                } else {
                    PhysicalRowClass::BoundProtected(ProtectedRole::Meta)
                }
            );
            let StoredValue::Put(bytes) = &expected.version.value else {
                panic!("both writer rows must be literal puts")
            };
            assert_eq!(observed.value, ObservedSegmentValue::Put(bytes.clone()));
        }
        assert_eq!(snapshot(fixture.dir.path()), fixture.before);

        let balance = budget.remaining_bytes();
        let result = collect_protected_copy_admission(root, &fixture.manifest, budget);
        match (case, result) {
            (NextCopyCase::IdenticalAllocator, Ok(candidate)) => {
                let ledger = candidate
                    .consume()
                    .expect("all retained source witnesses must survive consumption");
                assert_eq!(ledger.segment_witnesses().len(), 2);
                let admitted = ledger
                    .copies()
                    .filter(|row| {
                        row.cf == fixture.original.cf.0
                            && row.key == fixture.original.key.as_ref()
                            && row.sequence == 1
                    })
                    .collect::<Vec<_>>();
                assert_eq!(admitted.len(), 2);
                assert!(
                    admitted
                        .iter()
                        .all(|row| row.operation == CopyWireOperation::Put { len: 56 })
                );
                assert_eq!(
                    (admitted[0].source, admitted[1].source),
                    (sources[0], sources[1])
                );
                assert_eq!(
                    (admitted[0].block_offset, admitted[0].row_ordinal),
                    fixture.first_location
                );
                assert_eq!(
                    (admitted[1].block_offset, admitted[1].row_ordinal),
                    fixture.second_location
                );
                assert_eq!(snapshot(fixture.dir.path()), fixture.before);
                drop(admitted);
                drop(ledger);
            }
            (NextCopyCase::IdenticalAllocator, Err(error)) => {
                panic!("authenticated equal Allocator@1 copies must stage: {error:?}")
            }
            (NextCopyCase::ConflictingHead, Err(PraxisError::Corrupt { reason, .. })) => {
                assert_eq!(
                    reason.as_str(),
                    "protected physical-copy actual bytes conflict"
                );
            }
            (NextCopyCase::ConflictingHead, Err(error)) => {
                panic!("rechecksummed Head@2 conflict must be Corrupt: {error:?}")
            }
            (NextCopyCase::ConflictingHead, Ok(_)) => {
                panic!("candidate admitted rechecksummed conflicting Head@2 copies")
            }
            (NextCopyCase::IdenticalBinding | NextCopyCase::ConflictingBinding, _) => {
                unreachable!("Binding cases use dedicated tests")
            }
        }
        assert_eq!(
            budget.remaining_bytes(),
            balance,
            "exact owned-receipt refund"
        );
        assert_eq!(snapshot(fixture.dir.path()), fixture.before);
    });
}

#[test]
fn writer_produced_duplicate_allocator_at_s1_requires_private_copy_admission() {
    exercise_next_copy_case(NextCopyCase::IdenticalAllocator);
}

#[test]
fn rechecksummed_equal_length_head_at_s2_conflict_requires_private_copy_corrupt() {
    exercise_next_copy_case(NextCopyCase::ConflictingHead);
}

#[test]
fn staged_private_candidate_rechecks_segment_mutation_and_refunds() {
    let fixture = next_copy_fixture(NextCopyCase::IdenticalAllocator);
    let root = fixture.lease.root();
    assert_eq!(snapshot(fixture.dir.path()), fixture.before);
    with_wal_budget(root, &fixture.manifest, |budget| {
        let balance = budget.remaining_bytes();
        let candidate = collect_protected_copy_admission(root, &fixture.manifest, budget)
            .expect("valid equal Allocator copies must stage");
        let mut mutator = OpenOptions::new()
            .write(true)
            .open(&fixture.second_path)
            .unwrap();
        mutator.seek(SeekFrom::Start(13)).unwrap();
        mutator.write_all(&[fixture.second_bytes[13] ^ 1]).unwrap();
        mutator.sync_data().unwrap();
        assert!(matches!(
            candidate.consume(),
            Err(PraxisError::Corrupt { .. })
        ));
        mutator.seek(SeekFrom::Start(13)).unwrap();
        mutator.write_all(&fixture.second_bytes[13..14]).unwrap();
        mutator.sync_data().unwrap();
        drop(mutator);
        assert_eq!(
            budget.remaining_bytes(),
            balance,
            "consume error must refund"
        );
        assert_eq!(snapshot(fixture.dir.path()), fixture.before);
    });
    assert_eq!(snapshot(fixture.dir.path()), fixture.before);
}

#[derive(Clone, Copy)]
enum CandidateBoundary {
    ConsumptionCap,
    CandidateUnwind,
    LedgerUnwind,
}

fn exercise_candidate_boundary(boundary: CandidateBoundary) {
    let fixture = next_copy_fixture(NextCopyCase::IdenticalAllocator);
    let root = fixture.lease.root();
    assert!(matches!(
        inspect_v4_owner(&fixture.lease, &fixture.config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(fixture.dir.path()), fixture.before);
    with_wal_budget(root, &fixture.manifest, |budget| {
        let balance = budget.remaining_bytes();
        match boundary {
            CandidateBoundary::ConsumptionCap => {
                let mut candidate =
                    collect_protected_copy_admission(root, &fixture.manifest, budget)
                        .expect("equal Allocator copies must stage");
                assert!(candidate.replay_reads_for_test() > 0);
                candidate.exhaust_replay_reads_for_test();
                assert!(matches!(
                    candidate.consume(),
                    Err(PraxisError::UnsupportedCatalogFeature {
                        feature: "physical-copy replay reads exceed proof profile"
                    })
                ));
            }
            CandidateBoundary::CandidateUnwind => {
                let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _candidate =
                        collect_protected_copy_admission(root, &fixture.manifest, budget)
                            .expect("equal Allocator copies must stage");
                    panic!("intentional candidate unwind");
                }));
                assert!(panic.is_err());
            }
            CandidateBoundary::LedgerUnwind => {
                let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let candidate =
                        collect_protected_copy_admission(root, &fixture.manifest, budget)
                            .expect("equal Allocator copies must stage");
                    let _ledger = candidate
                        .consume()
                        .expect("all retained witnesses must survive consumption");
                    panic!("intentional consumed-ledger unwind");
                }));
                assert!(panic.is_err());
            }
        }
        assert_eq!(budget.remaining_bytes(), balance, "cap/unwind must refund");
        assert_eq!(snapshot(fixture.dir.path()), fixture.before);
    });
    assert_eq!(snapshot(fixture.dir.path()), fixture.before);
}

#[test]
fn private_candidate_consumption_cap_refunds_retained_meter() {
    exercise_candidate_boundary(CandidateBoundary::ConsumptionCap);
}

#[test]
fn private_candidate_unwind_refunds_owned_receipts() {
    exercise_candidate_boundary(CandidateBoundary::CandidateUnwind);
}

#[test]
fn private_ledger_unwind_refunds_owned_receipts() {
    exercise_candidate_boundary(CandidateBoundary::LedgerUnwind);
}

fn writer_record_binding_pair_case(conflicting: bool) {
    let fixture = next_copy_fixture(if conflicting {
        NextCopyCase::ConflictingBinding
    } else {
        NextCopyCase::IdenticalBinding
    });
    let root = fixture.lease.root();
    let key = RecordKey::Binding.encode().unwrap();
    assert_eq!(key, [0]);
    let canonical = fixed_copy_oracle(
        "bootstrap_tag6",
        "record_binding",
        "__praxor_record_meta_v1",
        &key,
        1,
    );
    assert_eq!(canonical.len(), 80);
    assert_eq!(
        fixture.original.version.value,
        StoredValue::Put(canonical.clone())
    );
    let StoredValue::Put(peer) = &fixture.written.version.value else {
        panic!("writer-produced Binding peer must remain a literal Put")
    };
    assert_eq!(peer.len(), 80);
    assert_eq!(peer == &canonical, !conflicting);
    let binding_id = fixture
        .manifest
        .record_authority
        .as_ref()
        .unwrap()
        .identity(root)
        .unwrap();
    for value in [&canonical, peer] {
        assert!(matches!(
            RecordRow::decode(&RecordKey::Binding, value, root).unwrap(),
            RecordRow::Binding { database_id, .. } if database_id == binding_id
        ));
    }
    assert!(matches!(
        inspect_v4_owner(&fixture.lease, &fixture.config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(fixture.dir.path()), fixture.before);

    with_wal_budget(root, &fixture.manifest, |budget| {
        let balance = budget.remaining_bytes();
        let staged = collect_protected_segment_candidate(root, &fixture.manifest, budget)
            .expect("both writer-produced Binding segments must be witnessed");
        assert_eq!(staged.witnesses.len(), 2);
        assert_eq!(staged.rows.len(), 8);
        for (index, (witness, path, bytes, count)) in [
            (
                &staged.witnesses[0],
                &fixture.first_path,
                &fixture.first_bytes,
                7,
            ),
            (
                &staged.witnesses[1],
                &fixture.second_path,
                &fixture.second_bytes,
                1,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                witness.source,
                SegmentSource {
                    level: index as u32,
                    id: index as u64 + 1,
                    manifest_ordinal: index,
                }
            );
            assert_eq!(witness.path.as_path(), path.as_path());
            assert_eq!(witness.len, bytes.len() as u64);
            assert_eq!(witness.digest, blake3::hash(bytes));
            assert_eq!(witness.observed_rows, count);
            assert_eq!(
                witness.identity,
                physical_id(&File::open(path).unwrap(), path).unwrap()
            );
        }
        assert_ne!(staged.witnesses[0].identity, staged.witnesses[1].identity);
        let copies = staged
            .rows
            .iter()
            .filter(|row| {
                row.cf == "__praxor_record_meta_v1" && row.key == key && row.sequence == 1
            })
            .collect::<Vec<_>>();
        assert_eq!(copies.len(), 2);
        for (index, (row, expected)) in copies
            .iter()
            .zip([&fixture.original, &fixture.written])
            .enumerate()
        {
            assert_eq!(row.source, staged.witnesses[index].source);
            assert_eq!(
                (row.block_offset, row.row_ordinal),
                [fixture.first_location, fixture.second_location][index]
            );
            assert_eq!(
                row.classification,
                PhysicalRowClass::BoundProtected(ProtectedRole::Meta)
            );
            let StoredValue::Put(expected_bytes) = &expected.version.value else {
                unreachable!("the Binding fixture writes only literal Puts")
            };
            assert_eq!(row.value, ObservedSegmentValue::Put(expected_bytes.clone()));
        }
        drop(copies);
        staged.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);

        let error = match collect_protected_copy_ledger(root, &fixture.manifest, budget) {
            Ok(candidate) => {
                candidate.discard(root, budget).unwrap();
                panic!("Binding copies unexpectedly reached the legacy private gate")
            }
            Err(error) => error,
        };
        if conflicting {
            match error {
                PraxisError::Corrupt { reason, .. } => {
                    assert_eq!(reason, "protected physical-copy actual bytes conflict")
                }
                other => panic!(
                    "RED: two valid, changed Binding@1 Puts need authenticated byte conflict after complete fences: {other:?}"
                ),
            }
        } else {
            assert!(matches!(
                error,
                PraxisError::UnsupportedCatalogFeature {
                    feature: "protected physical-copy bytes await authenticated replay"
                }
            ));
        }
        assert_eq!(budget.remaining_bytes(), balance, "exact witness refund");
        assert_eq!(snapshot(fixture.dir.path()), fixture.before);

        match collect_protected_copy_admission(root, &fixture.manifest, budget) {
            Ok(candidate) if !conflicting => {
                let ledger = candidate
                    .consume()
                    .expect("equal Binding copies must survive consumption fences");
                assert_eq!(ledger.segment_witnesses().len(), 2);
                let admitted = ledger
                    .copies()
                    .filter(|copy| {
                        copy.cf == "__praxor_record_meta_v1"
                            && copy.key == key.as_slice()
                            && copy.sequence == 1
                    })
                    .collect::<Vec<_>>();
                assert_eq!(admitted.len(), 2);
                for (index, copy) in admitted.iter().enumerate() {
                    assert_eq!(
                        copy.source,
                        SegmentSource {
                            level: index as u32,
                            id: index as u64 + 1,
                            manifest_ordinal: index,
                        }
                    );
                    assert_eq!(
                        (copy.block_offset, copy.row_ordinal),
                        [fixture.first_location, fixture.second_location][index]
                    );
                    assert_eq!(copy.operation, CopyWireOperation::Put { len: 80 });
                }
                drop(admitted);
                drop(ledger);
            }
            Err(PraxisError::Corrupt { reason, .. }) if conflicting => {
                assert_eq!(reason, "protected physical-copy actual bytes conflict");
            }
            Ok(candidate) => {
                drop(candidate);
                panic!("changed Binding copies reached a private candidate");
            }
            Err(error) => panic!("Binding candidate failed at the wrong gate: {error:?}"),
        }
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(fixture.dir.path()), fixture.before);
    });
    assert_eq!(snapshot(fixture.dir.path()), fixture.before);
}

#[test]
fn writer_equal_record_binding_at_s1_reaches_named_private_gate() {
    writer_record_binding_pair_case(false);
}

#[test]
fn writer_valid_changed_record_binding_at_s1_requires_actual_byte_conflict() {
    writer_record_binding_pair_case(true);
}

fn writer_record_state_pair_case(conflicting: bool) {
    let (dir, config, lease) = flushed_create_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!((manifest.flushed_sequence, manifest.last_sequence), (2, 2));
    assert_eq!(manifest.segments.len(), 1);
    assert_eq!(manifest.segments[0].entries, 7);
    let database_id = manifest
        .record_authority
        .as_ref()
        .unwrap()
        .identity(root)
        .unwrap();

    // The State key is a nonzero big-endian RID in the bound State CF. Its
    // fixed PRS1 value is exactly 24 bytes; changing only payload_length to 5
    // preserves a valid codec and the same (CF,key,sequence) copy group.
    let state_key = RecordKey::State(1).encode().unwrap();
    assert_eq!(state_key, [1, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(
        RecordKey::decode(RecordRole::State, &state_key, root).unwrap(),
        RecordKey::State(1)
    );
    let canonical = RecordRow::State {
        live: true,
        payload_length: 4,
    }
    .encode()
    .unwrap();
    assert_eq!(
        canonical,
        oracle_bytes("505253310100000001000000000000000400000000000000")
    );
    assert_eq!(canonical.len(), 24);
    let payload = RecordRow::Payload(b"docs").encode().unwrap();
    let allocator = RecordRow::Allocator(RecordAllocator {
        last_rid: 1,
        compatibility_sequence: 1,
        append_ordinal: 1,
        live_count: 1,
        dead_count: 0,
        live_payload_bytes: 4,
    })
    .encode()
    .unwrap();
    let mut batch = WriteBatch::new();
    batch.put(
        RecordRole::Payload.cf(),
        RecordKey::Payload(1).encode().unwrap(),
        payload,
    );
    batch.put(RecordRole::State.cf(), state_key.clone(), canonical.clone());
    batch.put(
        RecordRole::Meta.cf(),
        RecordKey::Allocator.encode().unwrap(),
        allocator,
    );
    let envelope = RecordEnvelope {
        kind: RecordKind::Create,
        database_id,
        prior_rid: 0,
        new_rid: 1,
        prior_compatibility_sequence: 0,
        new_compatibility_sequence: 1,
        prior_append_ordinal: 0,
        new_append_ordinal: 1,
        record_count: 1,
        logical_entry_count: 1,
    };
    let frame = CoreWalRecord::Record {
        sequence: 3,
        envelope: envelope.clone(),
        batch,
    }
    .try_encode()
    .unwrap();
    assert_eq!(&frame[..4], &crate::wal::record::WAL_V2_MAGIC.to_le_bytes());
    assert_eq!(
        crc32c(&frame[..12]),
        u32::from_le_bytes(frame[12..16].try_into().unwrap())
    );
    assert_eq!(
        crc32fast::hash(&frame[16..]),
        u32::from_le_bytes(frame[8..12].try_into().unwrap())
    );
    let CoreRecordPrefix::Complete {
        record,
        encoded_len,
    } = parse_core_record_prefix(&frame, root).unwrap()
    else {
        panic!("writer-produced Record CREATE frame must be complete")
    };
    assert_eq!(encoded_len, frame.len());
    assert_eq!(record.try_encode().unwrap(), frame);
    let CoreWalRecord::Record {
        sequence,
        envelope: decoded_envelope,
        batch: decoded_batch,
    } = record
    else {
        panic!("sequence 3 must remain a Record CREATE frame")
    };
    assert_eq!(sequence, 3);
    assert_eq!(decoded_envelope, envelope);
    assert_eq!(decoded_batch.len(), 3);
    let state_in_wal = decoded_batch
        .ops()
        .iter()
        .filter_map(|op| match op {
            BatchOp::Put { cf, key, value }
                if cf.0 == RecordRole::State.cf() && key == &state_key =>
            {
                Some(value)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(state_in_wal.len(), 1);
    assert_eq!(state_in_wal[0].as_slice(), canonical.as_slice());
    assert_eq!(
        RecordRow::decode(&RecordKey::State(1), state_in_wal[0], root).unwrap(),
        RecordRow::State {
            live: true,
            payload_length: 4,
        }
    );

    // Retired WAL 2 carries the independent fixed Catalog CREATE S2 frame
    // followed by this writer-encoded Record CREATE S3. Active WAL 3 remains
    // header-only, so the installed cut is fully flushed and still private.
    let CoreRecordPrefix::Complete {
        record: CoreWalRecord::Catalog { sequence: 2, .. },
        encoded_len: catalog_len,
    } = parse_core_record_prefix(CATALOG_CREATE_FRAME, root).unwrap()
    else {
        panic!("fixed Catalog CREATE S2 frame must be complete")
    };
    assert_eq!(catalog_len, CATALOG_CREATE_FRAME.len());
    let mut wal_two = Vec::with_capacity(16 + catalog_len + frame.len());
    wal_two.extend(0x5457_4146u32.to_le_bytes());
    wal_two.extend(1u32.to_le_bytes());
    wal_two.extend(2u64.to_le_bytes());
    wal_two.extend(CATALOG_CREATE_FRAME);
    wal_two.extend(&frame);
    let retired_path = layout.wal_path(2);
    fs::write(&retired_path, &wal_two).unwrap();

    // Segment 2 contains all three actual Record CREATE operations decoded
    // from the CRC-checked WAL frame. Segment 3 contains only the State peer.
    let rows = decoded_batch
        .ops()
        .iter()
        .map(|op| match op {
            BatchOp::Put { cf, key, value } => SegmentEntry {
                cf: cf.clone(),
                key: key.clone().into(),
                version: VersionedValue {
                    sequence: 3,
                    value: StoredValue::Put(value.clone()),
                },
            },
            _ => panic!("Record CREATE fixture must contain only Put operations"),
        })
        .collect::<Vec<_>>();
    let original = rows
        .iter()
        .find(|row| row.cf.0 == RecordRole::State.cf() && row.key.as_ref() == state_key.as_slice())
        .unwrap()
        .clone();
    assert_eq!(original.version.value, StoredValue::Put(canonical.clone()));
    let mut peer = original.clone();
    if conflicting {
        let changed = RecordRow::State {
            live: true,
            payload_length: 5,
        }
        .encode()
        .unwrap();
        assert_eq!(changed.len(), canonical.len());
        assert_ne!(changed, canonical);
        assert_eq!(
            RecordRow::decode(&RecordKey::State(1), &changed, root).unwrap(),
            RecordRow::State {
                live: true,
                payload_length: 5,
            }
        );
        peer.version.value = StoredValue::Put(changed);
    }

    let mut state_locations = Vec::new();
    let mut file_facts = Vec::new();
    for (level, id, entries, wanted) in [
        (1, 2, rows, original.clone()),
        (2, 3, vec![peer.clone()], peer.clone()),
    ] {
        let path = layout.segment_path(level, id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let value_path = layout.value_log_path(id);
        let mut value_log = ValueLog::open(&value_path).unwrap();
        let meta = SegmentWriter::write(
            SegmentWriteOptions {
                path: &path,
                id,
                level,
                compression: Compression::None,
                accelerator: &CpuAccelerator,
                value_log: &mut value_log,
                large_value_threshold: config.large_value_threshold,
                block_size: config.block_size,
                partitioned_bloom: None,
                direct_io: false,
            },
            entries,
        )
        .unwrap();
        drop(value_log);
        fs::remove_file(value_path).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert_eq!(meta.path, path.to_str().unwrap());
        assert_eq!(meta.file_digest, blake3::hash(&bytes).to_hex().to_string());
        assert_eq!(meta.entries, if id == 2 { 3 } else { 1 });
        let decoded = decode_segment(&bytes, &path, &CpuAccelerator).unwrap();
        assert_eq!((decoded.level, decoded.id), (level, id));
        assert_eq!(
            decoded.blocks.iter().map(Vec::len).sum::<usize>() as u64,
            meta.entries
        );
        let offsets = literal_block_offsets(&bytes, level, id, decoded.blocks.len());
        let location = exact_entry_location(&decoded, &offsets, &wanted);
        assert!(
            decoded
                .blocks
                .iter()
                .flatten()
                .all(|row| row.blob_expiry.is_none())
        );
        state_locations.push(location);
        file_facts.push((path, bytes, meta.entries));
        manifest.segments.push(meta);
    }
    manifest.flushed_sequence = 3;
    manifest.last_sequence = 3;
    manifest.next_segment_id = 4;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!((manifest.flushed_sequence, manifest.last_sequence), (3, 3));
    assert_eq!((manifest.flushed_wal_id, manifest.active_wal_id), (2, 3));
    assert_eq!(manifest.segments.len(), 3);
    assert_eq!(
        manifest
            .segments
            .iter()
            .map(|meta| meta.entries)
            .sum::<u64>(),
        11
    );
    let first_path = layout.segment_path(0, 1);
    let first_bytes = fs::read(&first_path).unwrap();
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&first_bytes).to_hex().to_string()
    );
    let first = decode_segment(&first_bytes, &first_path, &CpuAccelerator).unwrap();
    assert_eq!(first.blocks.iter().map(Vec::len).sum::<usize>(), 7);
    let _first_offsets = literal_block_offsets(&first_bytes, 0, 1, first.blocks.len());
    assert_eq!(fs::read_dir(layout.value_root()).unwrap().count(), 0);
    let before = snapshot(dir.path());
    assert!(matches!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(dir.path()), before);

    let cut = WalCut {
        flushed_sequence: manifest.flushed_sequence,
        last_sequence: manifest.last_sequence,
        flushed_wal_id: manifest.flushed_wal_id,
        active_wal_id: manifest.active_wal_id,
        next_wal_id: manifest.next_wal_id,
    };
    let mut frames = Vec::new();
    let (wal_witnesses, mut budget) = scan_v4_wals_with_budget(root, cut, |id, start, end, row| {
        frames.push((id, start, end, row.sequence()));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        frames,
        [
            (2, 16, 16 + catalog_len as u64, 2),
            (2, 16 + catalog_len as u64, wal_two.len() as u64, 3),
        ]
    );
    assert_eq!(wal_witnesses.len(), 2);
    assert_eq!(wal_witnesses[0].id, 2);
    assert_eq!(wal_witnesses[0].path, retired_path);
    assert_eq!(wal_witnesses[0].full_len, wal_two.len() as u64);
    assert_eq!(wal_witnesses[0].full_digest, blake3::hash(&wal_two));
    assert_eq!(wal_witnesses[0].prefix_len, wal_two.len() as u64);
    assert_eq!(wal_witnesses[0].prefix_digest, blake3::hash(&wal_two));
    assert_eq!(wal_witnesses[0].record_count, 2);
    assert_eq!(
        (
            wal_witnesses[0].first_sequence,
            wal_witnesses[0].last_sequence
        ),
        (Some(2), Some(3))
    );
    assert_eq!(wal_witnesses[0].catalog_creates, 1);
    assert!(wal_witnesses[0].torn_start.is_none());
    assert_eq!(wal_witnesses[1].id, 3);
    assert_eq!(wal_witnesses[1].path, layout.wal_path(3));
    assert_eq!(wal_witnesses[1].record_count, 0);
    assert_eq!(wal_witnesses[1].full_len, 16);
    let active_bytes = fs::read(layout.wal_path(3)).unwrap();
    assert_eq!(wal_witnesses[1].full_digest, blake3::hash(&active_bytes));
    crate::wal::catalog_witness::recheck_v4_wals(root, cut, &wal_witnesses).unwrap();
    assert_eq!(snapshot(dir.path()), before);

    let balance = budget.remaining_bytes();
    let staged = collect_protected_segment_candidate(root, &manifest, &mut budget)
        .expect("all three writer-produced segments must be witnessed");
    assert_eq!((staged.witnesses.len(), staged.rows.len()), (3, 11));
    for (index, (witness, path, bytes, count)) in [
        (&staged.witnesses[0], &first_path, &first_bytes, 7),
        (
            &staged.witnesses[1],
            &file_facts[0].0,
            &file_facts[0].1,
            file_facts[0].2,
        ),
        (
            &staged.witnesses[2],
            &file_facts[1].0,
            &file_facts[1].1,
            file_facts[1].2,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            witness.source,
            SegmentSource {
                level: index as u32,
                id: index as u64 + 1,
                manifest_ordinal: index,
            }
        );
        assert_eq!(witness.path.as_path(), path.as_path());
        assert_eq!(witness.len, bytes.len() as u64);
        assert_eq!(witness.digest, blake3::hash(bytes));
        assert_eq!(witness.observed_rows, count);
        assert_eq!(
            witness.identity,
            physical_id(&File::open(path).unwrap(), path).unwrap()
        );
    }
    assert_ne!(staged.witnesses[1].identity, staged.witnesses[2].identity);
    let copies = staged
        .rows
        .iter()
        .filter(|row| row.cf == RecordRole::State.cf() && row.key == state_key && row.sequence == 3)
        .collect::<Vec<_>>();
    assert_eq!(copies.len(), 2);
    for (index, (row, expected)) in copies.iter().zip([&original, &peer]).enumerate() {
        assert_eq!(row.source, staged.witnesses[index + 1].source);
        assert_eq!((row.block_offset, row.row_ordinal), state_locations[index]);
        assert_eq!(
            row.classification,
            PhysicalRowClass::BoundProtected(ProtectedRole::State)
        );
        let StoredValue::Put(expected_bytes) = &expected.version.value else {
            panic!("both writer-produced State copies must be literal Puts")
        };
        assert_eq!(row.value, ObservedSegmentValue::Put(expected_bytes.clone()));
    }
    drop(copies);
    staged.discard(root, &mut budget).unwrap();
    assert_eq!(budget.remaining_bytes(), balance, "staged witness refund");
    assert_eq!(snapshot(dir.path()), before);

    let error = match collect_protected_copy_ledger(root, &manifest, &mut budget) {
        Ok(candidate) => {
            candidate.discard(root, &mut budget).unwrap();
            panic!("State copies unexpectedly passed the private pending gate")
        }
        Err(error) => error,
    };
    if conflicting {
        match error {
            PraxisError::Corrupt { reason, .. } => {
                assert_eq!(reason, "protected physical-copy actual bytes conflict")
            }
            other => panic!(
                "RED: codec-valid changed State@3 copy needs authenticated byte conflict: {other:?}"
            ),
        }
    } else {
        assert!(matches!(
            error,
            PraxisError::UnsupportedCatalogFeature {
                feature: "protected physical-copy bytes await authenticated replay"
            }
        ));
    }
    assert_eq!(
        budget.remaining_bytes(),
        balance,
        "copy-ledger exact refund"
    );
    assert_eq!(snapshot(dir.path()), before);
    assert!(matches!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn writer_equal_record_state_at_s3_reaches_named_private_gate() {
    writer_record_state_pair_case(false);
}

#[test]
fn writer_valid_changed_record_state_at_s3_requires_actual_byte_conflict() {
    writer_record_state_pair_case(true);
}

fn writer_record_fact_pair_case(conflicting: bool) {
    let (dir, config, lease) = flushed_create_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!((manifest.flushed_sequence, manifest.last_sequence), (2, 2));
    assert_eq!(manifest.segments.len(), 1);
    assert_eq!(manifest.segments[0].entries, 7);
    let database_id = manifest
        .record_authority
        .as_ref()
        .unwrap()
        .identity(root)
        .unwrap();
    let context = RecordContext {
        id: database_id,
        descriptors: 1,
        source: root,
    };

    // Establish a real one-index S1 bootstrap. The original fixed fixture has
    // Binding/Allocator but no Descriptor; retain its five Catalog rows and
    // replace the record prefix with a transition-validated writer batch.
    let first_path = layout.segment_path(0, 1);
    let old_bytes = fs::read(&first_path).unwrap();
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&old_bytes).to_hex().to_string()
    );
    let old = decode_segment(&old_bytes, &first_path, &CpuAccelerator).unwrap();
    assert_eq!((old.level, old.id), (0, 1));
    assert_eq!(old.blocks.iter().map(Vec::len).sum::<usize>(), 7);
    let _old_offsets = literal_block_offsets(&old_bytes, 0, 1, old.blocks.len());
    let mut first_rows = old
        .blocks
        .into_iter()
        .flatten()
        .map(|raw| raw.entry)
        .collect::<Vec<_>>();
    let old_binding = first_rows
        .iter()
        .find(|row| row.cf.0 == RecordRole::Meta.cf() && row.key.as_ref() == [0])
        .unwrap();
    assert_eq!(
        old_binding.version.value,
        StoredValue::Put(fixed_copy_oracle(
            "bootstrap_tag6",
            "record_binding",
            RecordRole::Meta.cf(),
            &[0],
            1,
        ))
    );
    assert_eq!(
        first_rows
            .iter()
            .filter(|row| row.cf.0 == RecordRole::Meta.cf())
            .count(),
        2
    );
    first_rows.retain(|row| row.cf.0 != RecordRole::Meta.cf());
    assert_eq!(first_rows.len(), 5);
    let mut bootstrap = WriteBatch::new();
    bootstrap.put(
        RecordRole::Meta.cf(),
        RecordKey::Binding.encode().unwrap(),
        RecordRow::Binding {
            database_id,
            descriptor_count: 1,
        }
        .encode()
        .unwrap(),
    );
    bootstrap.put(
        RecordRole::Meta.cf(),
        RecordKey::Allocator.encode().unwrap(),
        RecordRow::Allocator(RecordAllocator::default())
            .encode()
            .unwrap(),
    );
    bootstrap.put(
        RecordRole::Meta.cf(),
        RecordKey::Descriptor(1).encode().unwrap(),
        RecordRow::Descriptor {
            name: "kv",
            namespace: "docs",
        }
        .encode()
        .unwrap(),
    );
    check_bootstrap_ops(bootstrap.ops(), &context).unwrap();
    let mut prior = RecordRows::new();
    for op in bootstrap.ops() {
        let BatchOp::Put { cf, key, value } = op else {
            panic!("indexed bootstrap must contain only Put operations")
        };
        let role = RecordRole::from_cf(&cf.0).unwrap();
        assert_eq!(role, RecordRole::Meta);
        assert!(
            prior
                .insert(
                    (role, key.clone()),
                    Some(RecordSummary::decode(role, key, value, root).unwrap()),
                )
                .is_none()
        );
        first_rows.push(SegmentEntry {
            cf: cf.clone(),
            key: key.clone().into(),
            version: VersionedValue {
                sequence: 1,
                value: StoredValue::Put(value.clone()),
            },
        });
    }
    assert_eq!(first_rows.len(), 8);
    manifest
        .record_authority
        .as_mut()
        .unwrap()
        .index_descriptor_count = 1;
    let first_value_path = layout.value_log_path(1);
    let mut first_value_log = ValueLog::open(&first_value_path).unwrap();
    let first_meta = SegmentWriter::write(
        SegmentWriteOptions {
            path: &first_path,
            id: 1,
            level: 0,
            compression: Compression::None,
            accelerator: &CpuAccelerator,
            value_log: &mut first_value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: config.block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        first_rows,
    )
    .unwrap();
    drop(first_value_log);
    fs::remove_file(first_value_path).unwrap();
    assert_eq!(first_meta.entries, 8);
    assert_eq!(first_meta.path, first_path.to_str().unwrap());
    let first_bytes = fs::read(&first_path).unwrap();
    assert_eq!(
        first_meta.file_digest,
        blake3::hash(&first_bytes).to_hex().to_string()
    );
    let first = decode_segment(&first_bytes, &first_path, &CpuAccelerator).unwrap();
    assert_eq!(first.blocks.iter().map(Vec::len).sum::<usize>(), 8);
    let _first_offsets = literal_block_offsets(&first_bytes, 0, 1, first.blocks.len());
    manifest.segments[0] = first_meta;

    // Use the real record planner rather than inventing an IndexPut batch. A
    // single CREATE at core S3 allocates RID 1 and then emits the Fact/Head
    // mapping pair at raw sequence 2 and append ordinal 2.
    let intent = RecordIntent::new(RecordIntentKind::Create(vec![NewRecord {
        payload: b"docs".to_vec(),
        mappings: vec![RecordMapping {
            index: 1,
            key: b"k".to_vec(),
        }],
    }]))
    .unwrap();
    let planned = plan_record(&intent, 3, &context, &mut |role, key| {
        Ok(prior.get(&(role, key.to_vec())).cloned().flatten())
    })
    .unwrap();
    assert_eq!(planned.receipt.core_sequence, 3);
    assert_eq!(planned.receipt.compatibility_sequence, 2);
    let frame = planned.record.try_encode().unwrap();
    assert_eq!(frame.len(), planned.encoded_len);
    assert_eq!(&frame[..4], &crate::wal::record::WAL_V2_MAGIC.to_le_bytes());
    assert_eq!(
        crc32c(&frame[..12]),
        u32::from_le_bytes(frame[12..16].try_into().unwrap())
    );
    assert_eq!(
        crc32c(&frame[16..]),
        u32::from_le_bytes(frame[8..12].try_into().unwrap())
    );
    let CoreRecordPrefix::Complete {
        record,
        encoded_len,
    } = parse_core_record_prefix(&frame, root).unwrap()
    else {
        panic!("writer-planned mapped Record CREATE frame must be complete")
    };
    assert_eq!(encoded_len, frame.len());
    assert_eq!(record, planned.record);
    assert_eq!(record.try_encode().unwrap(), frame);
    let CoreWalRecord::Record {
        sequence,
        envelope,
        batch,
    } = record
    else {
        panic!("S3 must remain a Record CREATE frame")
    };
    assert_eq!(sequence, 3);
    assert_eq!(envelope.kind, RecordKind::Create);
    assert_eq!(envelope.database_id, database_id);
    assert_eq!(
        (
            envelope.prior_rid,
            envelope.new_rid,
            envelope.prior_compatibility_sequence,
            envelope.new_compatibility_sequence,
            envelope.prior_append_ordinal,
            envelope.new_append_ordinal,
            envelope.record_count,
            envelope.logical_entry_count,
        ),
        (0, 1, 0, 2, 0, 2, 1, 2)
    );
    assert_eq!(batch.len(), 5);
    let fact_key = RecordKey::Fact {
        index: 1,
        incarnation: 1,
        key: b"k",
        raw_sequence: 2,
    }
    .encode()
    .unwrap();
    assert_eq!(
        fact_key,
        oracle_bytes("01000000010000000000000001010000006b0000000000000002")
    );
    assert_eq!(fact_key.len(), 26);
    assert_eq!(
        RecordKey::decode(RecordRole::Index, &fact_key, root).unwrap(),
        RecordKey::Fact {
            index: 1,
            incarnation: 1,
            key: b"k",
            raw_sequence: 2,
        }
    );
    let canonical = RecordRow::Fact {
        append_ordinal: 2,
        decision: RecordDecision::Put(1),
    }
    .encode()
    .unwrap();
    assert_eq!(
        canonical,
        oracle_bytes("5052463101000000020000000000000001000000000000000100000000000000")
    );
    assert_eq!(canonical.len(), 32);
    let fact_in_wal = batch
        .ops()
        .iter()
        .filter_map(|op| match op {
            BatchOp::Put { cf, key, value }
                if cf.0 == RecordRole::Index.cf() && key == &fact_key =>
            {
                Some(value)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(fact_in_wal.len(), 1);
    assert_eq!(fact_in_wal[0].as_slice(), canonical.as_slice());
    assert_eq!(
        RecordRow::decode(
            &RecordKey::decode(RecordRole::Index, &fact_key, root).unwrap(),
            fact_in_wal[0],
            root,
        )
        .unwrap(),
        RecordRow::Fact {
            append_ordinal: 2,
            decision: RecordDecision::Put(1),
        }
    );
    let head_key = RecordKey::Head {
        index: 1,
        incarnation: 1,
        key: b"k",
    }
    .encode()
    .unwrap();
    assert_eq!(
        head_key,
        oracle_bytes("02000000010000000000000001010000006b")
    );
    let head_value = RecordRow::Head {
        raw_sequence: 2,
        append_ordinal: 2,
        decision: RecordDecision::Put(1),
    }
    .encode()
    .unwrap();
    assert_eq!(head_value.len(), 40);
    let head_in_wal = batch
        .ops()
        .iter()
        .filter_map(|op| match op {
            BatchOp::Put { cf, key, value }
                if cf.0 == RecordRole::Index.cf() && key == &head_key =>
            {
                Some(value)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(head_in_wal.len(), 1);
    assert_eq!(head_in_wal[0].as_slice(), head_value.as_slice());

    // The independently frozen Catalog S2 frame matches the four S2 rows in
    // the rewritten first segment. Retired WAL 2 then carries the mapped
    // writer-planned S3 frame; active WAL 3 stays header-only.
    let CoreRecordPrefix::Complete {
        record:
            CoreWalRecord::Catalog {
                sequence: 2,
                control,
                batch: catalog_batch,
            },
        encoded_len: catalog_len,
    } = parse_core_record_prefix(CATALOG_CREATE_FRAME, root).unwrap()
    else {
        panic!("fixed Catalog CREATE S2 frame must be complete")
    };
    assert!(matches!(
        control,
        crate::core_catalog::CatalogControl::Create { .. }
    ));
    assert_eq!(catalog_len, CATALOG_CREATE_FRAME.len());
    assert_eq!(catalog_batch.len(), 4);
    for op in catalog_batch.ops() {
        let BatchOp::Put { cf, key, value } = op else {
            panic!("fixed Catalog CREATE frame must contain only Put operations")
        };
        assert!(
            first.blocks.iter().flatten().any(|raw| {
                let row = &raw.entry;
                row.cf == *cf
                    && row.key.as_ref() == key.as_slice()
                    && row.version.sequence == 2
                    && matches!(&row.version.value, StoredValue::Put(bytes) if bytes == value)
            }),
            "Catalog S2 WAL operation must match one installed source row"
        );
    }
    let mut wal_two = Vec::with_capacity(16 + catalog_len + frame.len());
    wal_two.extend(0x5457_4146u32.to_le_bytes());
    wal_two.extend(1u32.to_le_bytes());
    wal_two.extend(2u64.to_le_bytes());
    wal_two.extend(CATALOG_CREATE_FRAME);
    wal_two.extend(&frame);
    let retired_path = layout.wal_path(2);
    fs::write(&retired_path, &wal_two).unwrap();

    // Segment 2 is exactly the decoded S3 batch; segment 3 retains a second
    // physical copy of the same Fact event. The changed peer is another
    // codec-valid PRF1 decision at the same (CF,key,core sequence).
    let rows = batch
        .ops()
        .iter()
        .map(|op| match op {
            BatchOp::Put { cf, key, value } => SegmentEntry {
                cf: cf.clone(),
                key: key.clone().into(),
                version: VersionedValue {
                    sequence: 3,
                    value: StoredValue::Put(value.clone()),
                },
            },
            _ => panic!("writer-planned Record CREATE must contain only Puts"),
        })
        .collect::<Vec<_>>();
    let original = rows
        .iter()
        .find(|row| row.cf.0 == RecordRole::Index.cf() && row.key.as_ref() == fact_key.as_slice())
        .unwrap()
        .clone();
    assert_eq!(original.version.sequence, 3);
    assert_eq!(original.version.value, StoredValue::Put(canonical.clone()));
    let mut peer = original.clone();
    if conflicting {
        let changed = RecordRow::Fact {
            append_ordinal: 2,
            decision: RecordDecision::Delete,
        }
        .encode()
        .unwrap();
        assert_eq!(
            changed,
            oracle_bytes("5052463101000000020000000000000002000000000000000000000000000000")
        );
        assert_eq!(changed.len(), canonical.len());
        assert_ne!(changed, canonical);
        assert_eq!(
            RecordRow::decode(
                &RecordKey::decode(RecordRole::Index, &fact_key, root).unwrap(),
                &changed,
                root,
            )
            .unwrap(),
            RecordRow::Fact {
                append_ordinal: 2,
                decision: RecordDecision::Delete,
            }
        );
        peer.version.value = StoredValue::Put(changed);
    }
    let mut fact_locations = Vec::new();
    let mut file_facts = Vec::new();
    for (level, id, entries, wanted) in [
        (1, 2, rows, original.clone()),
        (2, 3, vec![peer.clone()], peer.clone()),
    ] {
        let path = layout.segment_path(level, id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let value_path = layout.value_log_path(id);
        let mut value_log = ValueLog::open(&value_path).unwrap();
        let meta = SegmentWriter::write(
            SegmentWriteOptions {
                path: &path,
                id,
                level,
                compression: Compression::None,
                accelerator: &CpuAccelerator,
                value_log: &mut value_log,
                large_value_threshold: config.large_value_threshold,
                block_size: config.block_size,
                partitioned_bloom: None,
                direct_io: false,
            },
            entries,
        )
        .unwrap();
        drop(value_log);
        fs::remove_file(value_path).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert_eq!(meta.path, path.to_str().unwrap());
        assert_eq!(meta.file_digest, blake3::hash(&bytes).to_hex().to_string());
        assert_eq!(meta.entries, if id == 2 { 5 } else { 1 });
        let decoded = decode_segment(&bytes, &path, &CpuAccelerator).unwrap();
        assert_eq!((decoded.level, decoded.id), (level, id));
        assert_eq!(
            decoded.blocks.iter().map(Vec::len).sum::<usize>() as u64,
            meta.entries
        );
        let offsets = literal_block_offsets(&bytes, level, id, decoded.blocks.len());
        fact_locations.push(exact_entry_location(&decoded, &offsets, &wanted));
        assert!(
            decoded
                .blocks
                .iter()
                .flatten()
                .all(|row| row.blob_expiry.is_none())
        );
        file_facts.push((path, bytes, meta.entries));
        manifest.segments.push(meta);
    }
    manifest.flushed_sequence = 3;
    manifest.last_sequence = 3;
    manifest.next_segment_id = 4;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    manifest.validate_v4(root).unwrap();
    assert_eq!((manifest.flushed_sequence, manifest.last_sequence), (3, 3));
    assert_eq!((manifest.flushed_wal_id, manifest.active_wal_id), (2, 3));
    assert_eq!(
        manifest
            .record_authority
            .as_ref()
            .unwrap()
            .index_descriptor_count,
        1
    );
    assert_eq!(manifest.segments.len(), 3);
    assert_eq!(
        manifest
            .segments
            .iter()
            .map(|meta| meta.entries)
            .sum::<u64>(),
        14
    );
    assert_eq!(fs::read_dir(layout.value_root()).unwrap().count(), 0);
    let before = snapshot(dir.path());
    assert!(matches!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(dir.path()), before);

    let cut = WalCut {
        flushed_sequence: manifest.flushed_sequence,
        last_sequence: manifest.last_sequence,
        flushed_wal_id: manifest.flushed_wal_id,
        active_wal_id: manifest.active_wal_id,
        next_wal_id: manifest.next_wal_id,
    };
    let mut frames = Vec::new();
    let (wal_witnesses, mut budget) = scan_v4_wals_with_budget(root, cut, |id, start, end, row| {
        frames.push((id, start, end, row.sequence()));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        frames,
        [
            (2, 16, 16 + catalog_len as u64, 2),
            (2, 16 + catalog_len as u64, wal_two.len() as u64, 3),
        ]
    );
    assert_eq!(wal_witnesses.len(), 2);
    assert_eq!(wal_witnesses[0].id, 2);
    assert_eq!(wal_witnesses[0].path, retired_path);
    assert_eq!(wal_witnesses[0].full_len, wal_two.len() as u64);
    assert_eq!(wal_witnesses[0].full_digest, blake3::hash(&wal_two));
    assert_eq!(wal_witnesses[0].prefix_len, wal_two.len() as u64);
    assert_eq!(wal_witnesses[0].prefix_digest, blake3::hash(&wal_two));
    assert_eq!(wal_witnesses[0].record_count, 2);
    assert_eq!(
        (
            wal_witnesses[0].first_sequence,
            wal_witnesses[0].last_sequence
        ),
        (Some(2), Some(3))
    );
    assert_eq!(wal_witnesses[0].catalog_creates, 1);
    assert!(wal_witnesses[0].torn_start.is_none());
    assert_eq!(wal_witnesses[1].id, 3);
    assert_eq!(wal_witnesses[1].path, layout.wal_path(3));
    assert_eq!(wal_witnesses[1].record_count, 0);
    assert_eq!(wal_witnesses[1].full_len, 16);
    let active_bytes = fs::read(layout.wal_path(3)).unwrap();
    assert_eq!(wal_witnesses[1].full_digest, blake3::hash(&active_bytes));
    crate::wal::catalog_witness::recheck_v4_wals(root, cut, &wal_witnesses).unwrap();
    assert_eq!(snapshot(dir.path()), before);

    let balance = budget.remaining_bytes();
    let staged = collect_protected_segment_candidate(root, &manifest, &mut budget)
        .expect("all three writer-produced segments must be witnessed");
    assert_eq!((staged.witnesses.len(), staged.rows.len()), (3, 14));
    for (index, (witness, path, bytes, count)) in [
        (&staged.witnesses[0], &first_path, &first_bytes, 8),
        (
            &staged.witnesses[1],
            &file_facts[0].0,
            &file_facts[0].1,
            file_facts[0].2,
        ),
        (
            &staged.witnesses[2],
            &file_facts[1].0,
            &file_facts[1].1,
            file_facts[1].2,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            witness.source,
            SegmentSource {
                level: index as u32,
                id: index as u64 + 1,
                manifest_ordinal: index,
            }
        );
        assert_eq!(witness.path.as_path(), path.as_path());
        assert_eq!(witness.len, bytes.len() as u64);
        assert_eq!(witness.digest, blake3::hash(bytes));
        assert_eq!(witness.observed_rows, count);
        assert_eq!(
            witness.identity,
            physical_id(&File::open(path).unwrap(), path).unwrap()
        );
    }
    assert_ne!(staged.witnesses[1].identity, staged.witnesses[2].identity);
    let copies = staged
        .rows
        .iter()
        .filter(|row| row.cf == RecordRole::Index.cf() && row.key == fact_key && row.sequence == 3)
        .collect::<Vec<_>>();
    assert_eq!(copies.len(), 2);
    for (index, (row, expected)) in copies.iter().zip([&original, &peer]).enumerate() {
        assert_eq!(row.source, staged.witnesses[index + 1].source);
        assert_eq!((row.block_offset, row.row_ordinal), fact_locations[index]);
        assert_eq!(
            row.classification,
            PhysicalRowClass::BoundProtected(ProtectedRole::Index)
        );
        let StoredValue::Put(expected_bytes) = &expected.version.value else {
            panic!("both writer-produced Fact copies must be literal Puts")
        };
        assert_eq!(row.value, ObservedSegmentValue::Put(expected_bytes.clone()));
    }
    drop(copies);
    staged.discard(root, &mut budget).unwrap();
    assert_eq!(budget.remaining_bytes(), balance, "staged witness refund");
    assert_eq!(snapshot(dir.path()), before);

    let error = match collect_protected_copy_ledger(root, &manifest, &mut budget) {
        Ok(candidate) => {
            candidate.discard(root, &mut budget).unwrap();
            panic!("Fact copies unexpectedly passed the private pending gate")
        }
        Err(error) => error,
    };
    if conflicting {
        match error {
            PraxisError::Corrupt { reason, .. } => {
                assert_eq!(reason, "protected physical-copy actual bytes conflict")
            }
            other => panic!(
                "RED: codec-valid changed Fact@3 needs authenticated byte conflict: {other:?}"
            ),
        }
    } else {
        assert!(matches!(
            error,
            PraxisError::UnsupportedCatalogFeature {
                feature: "protected physical-copy bytes await authenticated replay"
            }
        ));
    }
    assert_eq!(
        budget.remaining_bytes(),
        balance,
        "copy-ledger exact refund"
    );
    assert_eq!(snapshot(dir.path()), before);
    assert!(matches!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn writer_equal_record_fact_at_s3_reaches_named_private_gate() {
    writer_record_fact_pair_case(false);
}

#[test]
fn writer_valid_changed_record_fact_at_s3_requires_actual_byte_conflict() {
    writer_record_fact_pair_case(true);
}

fn compressed_head_copy_fixture(conflicting: bool) -> NextCopyFixture {
    // The original fixture pins Head@2 to the independent WAL oracle and
    // produces a valid, equal-length rechecksummed conflict when requested.
    let mut fixture = next_copy_fixture(NextCopyCase::ConflictingHead);
    if !conflicting {
        fixture.written = fixture.original.clone();
    }
    let root = fixture.lease.root();
    let layout = DiskLayout::at(root);
    let value_path = layout.value_log_path(2);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let second_meta = SegmentWriter::write(
        SegmentWriteOptions {
            path: &fixture.second_path,
            id: 2,
            level: 1,
            compression: Compression::Lz4,
            accelerator: &CpuAccelerator,
            value_log: &mut value_log,
            large_value_threshold: fixture.config.large_value_threshold,
            block_size: fixture.config.block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        vec![fixture.written.clone()],
    )
    .unwrap();
    drop(value_log);
    fs::remove_file(value_path).unwrap();

    let bytes = fs::read(&fixture.second_path).unwrap();
    assert_eq!(
        &bytes[..4],
        &crate::segments::format::SEGMENT_MAGIC.to_le_bytes()
    );
    assert_eq!(
        &bytes[4..8],
        &crate::segments::format::SEGMENT_VERSION.to_le_bytes()
    );
    assert_eq!(bytes[8], 1, "writer must emit an LZ4 segment");
    assert_eq!(u32::from_le_bytes(bytes[9..13].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(bytes[13..21].try_into().unwrap()), 2);
    let (encoded, decoded_len, block_crc) = writer_block_frame(&bytes, 21);
    assert_eq!(crc32c(encoded), block_crc);
    let decoded_block = decode_block(Compression::Lz4, encoded).unwrap();
    assert_eq!(decoded_block.len() as u64, decoded_len);
    let decoded_rows = decode_entries(&decoded_block, &fixture.second_path).unwrap();
    assert_eq!(decoded_rows.len(), 1);
    assert_eq!(decoded_rows[0].entry, fixture.written);
    assert!(decoded_rows[0].blob_expiry.is_none());
    let trailer = bytes.len() - 12;
    let footer_len = u32::from_le_bytes(bytes[trailer..trailer + 4].try_into().unwrap()) as usize;
    let footer = trailer.checked_sub(footer_len).unwrap();
    assert_eq!(21 + 12 + encoded.len(), footer, "one complete LZ4 block");
    assert_eq!(
        crc32c(&bytes[footer..trailer]),
        u32::from_le_bytes(bytes[trailer + 4..trailer + 8].try_into().unwrap())
    );
    assert_eq!(
        u32::from_le_bytes(bytes[trailer + 8..].try_into().unwrap()),
        SEGMENT_FOOTER_MAGIC
    );
    assert_eq!(second_meta.entries, 1);
    assert_eq!(second_meta.min_key.as_slice(), fixture.written.key.as_ref());
    assert_eq!(second_meta.max_key.as_slice(), fixture.written.key.as_ref());
    assert_eq!(second_meta.path, fixture.second_path.to_str().unwrap());
    assert_eq!(
        second_meta.file_digest,
        blake3::hash(&bytes).to_hex().to_string()
    );
    let parsed = decode_segment(&bytes, &fixture.second_path, &CpuAccelerator).unwrap();
    assert_eq!((parsed.level, parsed.id), (1, 2));
    assert_eq!(parsed.blocks.len(), 1);
    assert_eq!(parsed.blocks[0].len(), 1);
    fixture.second_location = exact_entry_location(&parsed, &[21], &fixture.written);
    assert_eq!(fixture.second_location, (21, 0));

    let manifest_path = layout.manifest_path();
    fixture.manifest.segments[1] = second_meta;
    ManifestStore::new(manifest_path.clone())
        .save(&fixture.manifest)
        .unwrap();
    fixture.manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    fixture.manifest.validate_v4(&manifest_path).unwrap();
    assert_eq!(fixture.manifest.segments.len(), 2);
    assert_eq!(fixture.manifest.next_segment_id, 3);
    fixture.second_bytes = bytes;
    fixture.before = snapshot(fixture.dir.path());
    assert_ne!(
        physical_id(
            &File::open(&fixture.first_path).unwrap(),
            &fixture.first_path
        )
        .unwrap(),
        physical_id(
            &File::open(&fixture.second_path).unwrap(),
            &fixture.second_path
        )
        .unwrap()
    );
    fixture
}

fn exercise_compressed_head_copy_ledger(conflicting: bool) {
    let fixture = compressed_head_copy_fixture(conflicting);
    let root = fixture.lease.root();
    let head_key = CatalogKey::Head.encode().unwrap();
    assert_eq!(fixture.original.cf.0, CATALOG_CF);
    assert_eq!(fixture.original.key.as_ref(), head_key.as_slice());
    assert_eq!(fixture.original.version.sequence, 2);
    let (StoredValue::Put(first), StoredValue::Put(second)) = (
        &fixture.original.version.value,
        &fixture.written.version.value,
    ) else {
        panic!("both writer-produced Head@2 copies must be logical Puts")
    };
    assert_eq!(first.len(), second.len());
    assert_eq!(first == second, !conflicting);
    assert!(matches!(
        inspect_v4_owner(&fixture.lease, &fixture.config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(fixture.dir.path()), fixture.before);

    with_wal_budget(root, &fixture.manifest, |budget| {
        let mut observed = Vec::new();
        let witnesses = visit_v4_segments(root, &fixture.manifest, budget, |row| {
            observed.push(row);
            Ok(())
        })
        .expect("bounded visitor must authenticate both installed writer segments");
        assert_eq!(witnesses.len(), 2);
        assert_eq!(observed.len(), 8);
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
        ];
        for (witness, source, path, bytes, count) in [
            (
                &witnesses[0],
                sources[0],
                &fixture.first_path,
                &fixture.first_bytes,
                7,
            ),
            (
                &witnesses[1],
                sources[1],
                &fixture.second_path,
                &fixture.second_bytes,
                1,
            ),
        ] {
            assert_eq!(witness.source, source);
            assert_eq!(witness.path.as_path(), path.as_path());
            assert_eq!(witness.len, bytes.len() as u64);
            assert_eq!(witness.digest, blake3::hash(bytes));
            assert_eq!(witness.observed_rows, count);
            assert_eq!(
                witness.identity,
                physical_id(&File::open(path).unwrap(), path).unwrap()
            );
        }
        assert_ne!(witnesses[0].identity, witnesses[1].identity);
        let copies = observed
            .iter()
            .filter(|row| row.cf == CATALOG_CF && row.key == head_key && row.sequence == 2)
            .collect::<Vec<_>>();
        assert_eq!(copies.len(), 2);
        for (index, (copy, expected)) in copies
            .iter()
            .zip([&fixture.original, &fixture.written])
            .enumerate()
        {
            assert_eq!(copy.source, sources[index]);
            assert_eq!(
                (copy.block_offset, copy.row_ordinal),
                if index == 0 {
                    fixture.first_location
                } else {
                    fixture.second_location
                }
            );
            assert_eq!(
                copy.classification,
                PhysicalRowClass::BoundProtected(ProtectedRole::Catalog)
            );
            assert_eq!(
                copy.value,
                ObservedSegmentValue::Put(match &expected.version.value {
                    StoredValue::Put(bytes) => bytes.clone(),
                    _ => unreachable!(),
                })
            );
        }
        assert_eq!(snapshot(fixture.dir.path()), fixture.before);

        let balance = budget.remaining_bytes();
        let error = match collect_protected_copy_ledger(root, &fixture.manifest, budget) {
            Ok(candidate) => {
                candidate.discard(root, budget).unwrap();
                panic!("compressed Head copies must remain private until owner composition")
            }
            Err(error) => error,
        };
        assert_eq!(budget.remaining_bytes(), balance, "exact witness refund");
        assert_eq!(snapshot(fixture.dir.path()), fixture.before);
        match error {
            PraxisError::UnsupportedCatalogFeature {
                feature: "compressed physical-copy replay not implemented",
            } => panic!("RED: authenticated LZ4 Head copy replay is missing"),
            PraxisError::UnsupportedCatalogFeature {
                feature: "protected physical-copy bytes await authenticated replay",
            } if !conflicting => {}
            PraxisError::Corrupt { reason, .. } if conflicting => {
                assert_eq!(
                    reason.as_str(),
                    "protected physical-copy actual bytes conflict"
                );
            }
            other => panic!("unexpected compressed Head copy outcome: {other:?}"),
        }

        // The legacy collector remains deliberately nonadmitting. The new
        // candidate must independently prove the same selected LZ4 copies and
        // retain every file receipt through its consumption boundary.
        match (
            conflicting,
            collect_protected_copy_admission(root, &fixture.manifest, budget),
        ) {
            (false, Ok(candidate)) => {
                let ledger = candidate
                    .consume()
                    .expect("equal LZ4 Head copies must survive all witness rechecks");
                assert_eq!(ledger.segment_witnesses().len(), 2);
                let admitted = ledger
                    .copies()
                    .filter(|copy| {
                        copy.cf == CATALOG_CF
                            && copy.key == head_key.as_slice()
                            && copy.sequence == 2
                    })
                    .collect::<Vec<_>>();
                assert_eq!(admitted.len(), 2);
                assert_eq!(
                    (admitted[0].source, admitted[1].source),
                    (sources[0], sources[1])
                );
                assert_eq!(
                    (admitted[0].block_offset, admitted[0].row_ordinal),
                    fixture.first_location
                );
                assert_eq!(
                    (admitted[1].block_offset, admitted[1].row_ordinal),
                    fixture.second_location
                );
                assert!(
                    admitted
                        .iter()
                        .all(|copy| copy.operation == CopyWireOperation::Put { len: 48 })
                );
                assert_eq!(snapshot(fixture.dir.path()), fixture.before);
                drop(admitted);
                drop(ledger);
            }
            (false, Err(error)) => panic!("equal LZ4 copies must stage: {error:?}"),
            (true, Err(PraxisError::Corrupt { reason, .. })) => {
                assert_eq!(
                    reason.as_str(),
                    "protected physical-copy actual bytes conflict"
                );
            }
            (true, Err(error)) => panic!("LZ4 Head conflict must be Corrupt: {error:?}"),
            (true, Ok(_)) => panic!("conflicting LZ4 Head copies produced a candidate"),
        }
        assert_eq!(
            budget.remaining_bytes(),
            balance,
            "candidate must refund exactly"
        );
        assert_eq!(snapshot(fixture.dir.path()), fixture.before);
    });
    assert_eq!(snapshot(fixture.dir.path()), fixture.before);
}

#[test]
fn writer_equal_lz4_head_copies_prove_private_candidate() {
    exercise_compressed_head_copy_ledger(false);
}

#[test]
fn writer_rechecksummed_lz4_head_conflict_refunds_without_writes() {
    exercise_compressed_head_copy_ledger(true);
}

#[test]
fn duplicate_allocator_metadata_reaches_pending_replay_and_refunds() {
    let fixture = next_copy_fixture(NextCopyCase::IdenticalAllocator);
    let root = fixture.lease.root();
    assert_eq!(fixture.original, fixture.written);
    assert_eq!(fixture.original.version.sequence, 1);
    assert_eq!(fixture.manifest.segments.len(), 2);
    assert_eq!(fixture.manifest.segments[0].entries, 7);
    assert_eq!(fixture.manifest.segments[1].entries, 1);
    assert_eq!(snapshot(fixture.dir.path()), fixture.before);
    assert!(matches!(
        inspect_v4_owner(&fixture.lease, &fixture.config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));

    with_wal_budget(root, &fixture.manifest, |budget| {
        let before = budget.remaining_bytes();
        let result = collect_protected_copy_ledger(root, &fixture.manifest, budget);
        assert!(matches!(
            result,
            Err(PraxisError::UnsupportedCatalogFeature {
                feature: "protected physical-copy bytes await authenticated replay"
            })
        ));
        assert_eq!(
            budget.remaining_bytes(),
            before,
            "collector must refund its receipts"
        );
        assert_eq!(snapshot(fixture.dir.path()), fixture.before);
    });

    assert!(matches!(
        inspect_v4_owner(&fixture.lease, &fixture.config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(fixture.dir.path()), fixture.before);
}

#[test]
fn second_writer_produced_anchor_refuses_before_copy_replay_and_refunds() {
    let (dir, config, lease) = flushed_create_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let first_path = layout.segment_path(0, 1);
    let first_bytes = fs::read(&first_path).unwrap();
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&first_bytes).to_hex().to_string()
    );
    let first = decode_segment(&first_bytes, &first_path, &CpuAccelerator).unwrap();
    let anchor_key = CatalogKey::Anchor.encode().unwrap();
    let anchor = first
        .blocks
        .iter()
        .flatten()
        .find(|row| {
            row.entry.cf.0 == CATALOG_CF
                && row.entry.key.as_ref() == anchor_key.as_slice()
                && row.entry.version.sequence == 1
        })
        .unwrap()
        .entry
        .clone();
    let StoredValue::Put(ref anchor_bytes) = anchor.version.value else {
        panic!("writer fixture Anchor@1 must be literal")
    };
    assert_eq!(
        anchor_bytes,
        &fixed_copy_oracle(
            "bootstrap_tag6",
            "catalog_anchor_at_1",
            CATALOG_CF,
            &anchor_key,
            1,
        )
    );

    let second_path = layout.segment_path(1, 2);
    fs::create_dir_all(second_path.parent().unwrap()).unwrap();
    let value_path = layout.value_log_path(2);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let second_meta = SegmentWriter::write(
        SegmentWriteOptions {
            path: &second_path,
            id: 2,
            level: 1,
            compression: Compression::None,
            accelerator: &CpuAccelerator,
            value_log: &mut value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: config.block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        vec![anchor.clone()],
    )
    .unwrap();
    drop(value_log);
    fs::remove_file(value_path).unwrap();
    let second_bytes = fs::read(&second_path).unwrap();
    assert_eq!(
        second_meta.file_digest,
        blake3::hash(&second_bytes).to_hex().to_string()
    );
    let second = decode_segment(&second_bytes, &second_path, &CpuAccelerator).unwrap();
    assert_eq!(second.blocks.iter().flatten().count(), 1);
    assert_eq!(second.blocks[0][0].entry, anchor);
    assert_eq!(
        literal_block_offsets(&second_bytes, 1, 2, second.blocks.len()).len(),
        second.blocks.len()
    );
    assert_ne!(
        physical_id(&File::open(&first_path).unwrap(), &first_path).unwrap(),
        physical_id(&File::open(&second_path).unwrap(), &second_path).unwrap()
    );

    manifest.segments.push(second_meta);
    manifest.next_segment_id = 3;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let before = snapshot(dir.path());
    assert!(matches!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        match collect_protected_copy_ledger(root, &manifest, budget).unwrap_err() {
            PraxisError::Corrupt { reason, .. } => {
                assert!(reason.contains("Anchor must have one physical copy"));
            }
            other => panic!("second physical Anchor must be Corrupt: {other:?}"),
        }
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[derive(Clone, Copy)]
enum OrderedHeadGroupCase {
    Identical,
    Reordered,
    ChangedLastMember,
    ShorterPeer,
}

fn fixed_record_head_bytes(append_ordinal: u64, rid: u64) -> Vec<u8> {
    let mut bytes = b"PRH1\x01\0\0\0".to_vec();
    bytes.extend_from_slice(&2u64.to_le_bytes());
    bytes.extend_from_slice(&append_ordinal.to_le_bytes());
    bytes.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&rid.to_le_bytes());
    assert_eq!(bytes.len(), 40);
    bytes
}

fn ordered_record_head_group_case(case: OrderedHeadGroupCase) {
    let (dir, config, lease) = flushed_create_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.flushed_sequence, 2);
    assert_eq!(manifest.segments.len(), 1);

    // This is a physical-copy fixture. #83/#84 still own the relationship
    // between these decoded Head events, their Facts, and the durable WAL.
    let head_key = RecordKey::Head {
        index: 1,
        incarnation: 1,
        key: b"ordered-copy",
    }
    .encode()
    .unwrap();
    let head_cf = RecordRole::Index.cf();
    let first_value = RecordRow::Head {
        raw_sequence: 2,
        append_ordinal: 1,
        decision: RecordDecision::Put(1),
    }
    .encode()
    .unwrap();
    let last_value = RecordRow::Head {
        raw_sequence: 2,
        append_ordinal: 2,
        decision: RecordDecision::Put(2),
    }
    .encode()
    .unwrap();
    let changed_last = RecordRow::Head {
        raw_sequence: 2,
        append_ordinal: 2,
        decision: RecordDecision::Put(3),
    }
    .encode()
    .unwrap();
    assert_eq!(first_value, fixed_record_head_bytes(1, 1));
    assert_eq!(last_value, fixed_record_head_bytes(2, 2));
    assert_eq!(changed_last, fixed_record_head_bytes(2, 3));
    assert_eq!(last_value.len(), changed_last.len());
    assert_ne!(last_value, changed_last);
    let first_group = vec![
        row_in(head_cf, &head_key, 2, StoredValue::Put(first_value.clone())),
        row_in(head_cf, &head_key, 2, StoredValue::Put(last_value.clone())),
    ];
    let second_group = match case {
        OrderedHeadGroupCase::Identical => first_group.clone(),
        OrderedHeadGroupCase::Reordered => vec![first_group[1].clone(), first_group[0].clone()],
        OrderedHeadGroupCase::ChangedLastMember => vec![
            first_group[0].clone(),
            row_in(head_cf, &head_key, 2, StoredValue::Put(changed_last)),
        ],
        // Synthetic co-residency only. Real ordinary compaction retires the
        // input source and supplies no authenticated row-level provenance.
        OrderedHeadGroupCase::ShorterPeer => vec![first_group[1].clone()],
    };

    let write_group = |level: u32, id: u64, rows: &[SegmentEntry]| {
        let path = layout.segment_path(level, id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let value_path = layout.value_log_path(id);
        let mut value_log = ValueLog::open(&value_path).unwrap();
        let metadata = SegmentWriter::write(
            SegmentWriteOptions {
                path: &path,
                id,
                level,
                compression: Compression::None,
                accelerator: &CpuAccelerator,
                value_log: &mut value_log,
                large_value_threshold: config.large_value_threshold,
                block_size: 1,
                partitioned_bloom: None,
                direct_io: false,
            },
            rows.to_vec(),
        )
        .unwrap();
        drop(value_log);
        fs::remove_file(value_path).unwrap();
        (path, metadata)
    };
    let (first_path, first_meta) = write_group(0, 2, &first_group);
    let (second_path, second_meta) = write_group(1, 3, &second_group);
    let paths = [first_path, second_path];
    let metadata = [first_meta, second_meta];
    let groups = [first_group, second_group];
    let mut block_offsets = Vec::new();
    let mut file_bytes = Vec::new();
    for (index, ((path, meta), expected)) in paths
        .iter()
        .zip(metadata.iter())
        .zip(groups.iter())
        .enumerate()
    {
        let level = u32::try_from(index).unwrap();
        let id = u64::try_from(index + 2).unwrap();
        let bytes = fs::read(path).unwrap();
        assert_eq!(meta.entries, expected.len() as u64);
        assert_eq!(meta.path, path.to_str().unwrap());
        assert_eq!(meta.file_digest, blake3::hash(&bytes).to_hex().to_string());
        let decoded = decode_segment(&bytes, path, &CpuAccelerator).unwrap();
        assert_eq!((decoded.level, decoded.id), (level, id));
        assert_eq!(
            decoded.blocks.len(),
            expected.len(),
            "one same-key row per literal block"
        );
        assert!(decoded.blocks.iter().all(|block| block.len() == 1));
        let offsets = literal_block_offsets(&bytes, level, id, decoded.blocks.len());
        for (row, entry) in decoded.blocks.iter().flatten().zip(expected) {
            assert_eq!(&row.entry, entry);
            assert!(row.blob_expiry.is_none());
            assert_eq!(
                RecordKey::decode(RecordRole::Index, &row.entry.key, path).unwrap(),
                RecordKey::Head {
                    index: 1,
                    incarnation: 1,
                    key: b"ordered-copy",
                }
            );
            let StoredValue::Put(value) = &row.entry.version.value else {
                panic!("ordered Head must be literal Put")
            };
            assert!(matches!(
                RecordRow::decode(
                    &RecordKey::Head {
                        index: 1,
                        incarnation: 1,
                        key: b"ordered-copy",
                    },
                    value,
                    path,
                )
                .unwrap(),
                RecordRow::Head {
                    raw_sequence: 2,
                    ..
                }
            ));
        }
        assert_ne!(
            physical_id(&File::open(path).unwrap(), path).unwrap(),
            physical_id(
                &File::open(layout.segment_path(0, 1)).unwrap(),
                &layout.segment_path(0, 1)
            )
            .unwrap()
        );
        block_offsets.push(offsets);
        file_bytes.push(bytes);
    }
    assert_ne!(
        physical_id(&File::open(&paths[0]).unwrap(), &paths[0]).unwrap(),
        physical_id(&File::open(&paths[1]).unwrap(), &paths[1]).unwrap()
    );
    manifest.segments.extend(metadata);
    manifest.next_segment_id = 4;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.segments.len(), 3);
    let before = snapshot(dir.path());
    assert!(matches!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(dir.path()), before);

    with_wal_budget(root, &manifest, |budget| {
        let mut observed = Vec::new();
        let witnesses = visit_v4_segments(root, &manifest, budget, |row| {
            observed.push(row);
            Ok(())
        })
        .expect("bounded visitor must retain both complete Head groups");
        assert_eq!(witnesses.len(), 3);
        assert_eq!(
            observed.len(),
            7 + groups.iter().map(Vec::len).sum::<usize>()
        );
        let head_rows = observed
            .iter()
            .filter(|row| row.cf == head_cf && row.key == head_key && row.sequence == 2)
            .collect::<Vec<_>>();
        assert_eq!(head_rows.len(), groups.iter().map(Vec::len).sum::<usize>());
        for (index, ((witness, expected), offsets)) in witnesses[1..]
            .iter()
            .zip(groups.iter())
            .zip(block_offsets.iter())
            .enumerate()
        {
            let path = &paths[index];
            assert_eq!(witness.path, *path);
            assert_eq!(witness.len, file_bytes[index].len() as u64);
            assert_eq!(witness.digest, blake3::hash(&file_bytes[index]));
            assert_eq!(witness.observed_rows, expected.len() as u64);
            assert_eq!(
                witness.identity,
                physical_id(&File::open(path).unwrap(), path).unwrap()
            );
            let source = SegmentSource {
                level: u32::try_from(index).unwrap(),
                id: u64::try_from(index + 2).unwrap(),
                manifest_ordinal: index + 1,
            };
            assert_eq!(witness.source, source);
            let group = head_rows
                .iter()
                .filter(|row| row.source == source)
                .collect::<Vec<_>>();
            assert_eq!(group.len(), expected.len());
            for (position, (row, entry)) in group.iter().zip(expected).enumerate() {
                assert_eq!((row.block_offset, row.row_ordinal), (offsets[position], 0));
                let StoredValue::Put(value) = &entry.version.value else {
                    unreachable!()
                };
                assert_eq!(row.value, ObservedSegmentValue::Put(value.clone()));
            }
        }
        assert_eq!(snapshot(dir.path()), before);
        let balance = budget.remaining_bytes();
        let result = collect_protected_copy_admission(root, &manifest, budget);
        match (case, result) {
            (OrderedHeadGroupCase::Identical, Ok(candidate)) => {
                let ledger = candidate
                    .consume()
                    .expect("the complete ordered Head source set must survive consumption");
                assert_eq!(ledger.segment_witnesses().len(), 3);
                let admitted = ledger
                    .copies()
                    .filter(|copy| {
                        copy.cf == head_cf && copy.key == head_key.as_slice() && copy.sequence == 2
                    })
                    .collect::<Vec<_>>();
                assert_eq!(admitted.len(), head_rows.len());
                for (copy, observed) in admitted.iter().zip(&head_rows) {
                    assert_eq!(copy.source, observed.source);
                    assert_eq!(
                        (copy.block_offset, copy.row_ordinal),
                        (observed.block_offset, observed.row_ordinal)
                    );
                    assert_eq!(copy.operation, CopyWireOperation::Put { len: 40 });
                }
                assert_eq!(snapshot(dir.path()), before);
                drop(admitted);
                drop(ledger);
            }
            (OrderedHeadGroupCase::Identical, Err(error)) => {
                panic!("equal complete Head groups must stage: {error:?}")
            }
            (
                OrderedHeadGroupCase::Reordered | OrderedHeadGroupCase::ChangedLastMember,
                Err(PraxisError::Corrupt { reason, .. }),
            ) => assert_eq!(
                reason.as_str(),
                "ordered record Head physical-copy bytes conflict"
            ),
            (
                OrderedHeadGroupCase::Reordered | OrderedHeadGroupCase::ChangedLastMember,
                Err(error),
            ) => panic!("conflicting complete Head groups must be Corrupt: {error:?}"),
            (OrderedHeadGroupCase::Reordered | OrderedHeadGroupCase::ChangedLastMember, Ok(_)) => {
                panic!("conflicting complete Head groups produced a candidate")
            }
            (
                OrderedHeadGroupCase::ShorterPeer,
                Err(PraxisError::UnsupportedCatalogFeature {
                    feature:
                        "record-index Head unequal source-group cardinality awaits provenance proof",
                }),
            ) => {}
            (OrderedHeadGroupCase::ShorterPeer, Err(error)) => {
                panic!("shorter Head group must refuse provenance: {error:?}")
            }
            (OrderedHeadGroupCase::ShorterPeer, Ok(_)) => {
                panic!("shorter Head group produced an unproved candidate")
            }
        }
        assert_eq!(
            budget.remaining_bytes(),
            balance,
            "exact owned-receipt refund"
        );
        assert_eq!(snapshot(dir.path()), before);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn exact_ordered_record_head_groups_require_private_copy_admission() {
    ordered_record_head_group_case(OrderedHeadGroupCase::Identical);
}

#[test]
fn reordered_record_head_group_requires_private_copy_corrupt() {
    ordered_record_head_group_case(OrderedHeadGroupCase::Reordered);
}

#[test]
fn rechecksummed_record_head_group_byte_conflict_requires_private_copy_corrupt() {
    ordered_record_head_group_case(OrderedHeadGroupCase::ChangedLastMember);
}

#[test]
fn shorter_co_resident_record_head_group_refuses_without_provenance() {
    ordered_record_head_group_case(OrderedHeadGroupCase::ShorterPeer);
}

fn exercise_external_anchor_manifest_identity(foreign_identity: bool, mutate_at_consume: bool) {
    assert!(!(foreign_identity && mutate_at_consume));
    let (dir, mut config, lease) = flushed_create_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.segments.len(), 1);
    let manifest_id = manifest
        .record_authority
        .as_ref()
        .unwrap()
        .identity(root)
        .unwrap();

    let retired_path = layout.segment_path(0, 1);
    let retired_bytes = fs::read(&retired_path).unwrap();
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&retired_bytes).to_hex().to_string()
    );
    let original = decode_segment(&retired_bytes, &retired_path, &CpuAccelerator).unwrap();
    let mut rows = original
        .blocks
        .into_iter()
        .flatten()
        .map(|raw| raw.entry)
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 7);
    let anchor_key = CatalogKey::Anchor.encode().unwrap();
    let anchor_position = rows
        .iter()
        .position(|row| {
            row.cf.0 == CATALOG_CF
                && row.key.as_ref() == anchor_key.as_slice()
                && row.version.sequence == 1
        })
        .unwrap();
    let StoredValue::Put(original_bytes) = &rows[anchor_position].version.value else {
        panic!("flushed CREATE Anchor@1 must be literal")
    };
    let CatalogValue::Anchor(original_anchor) =
        CatalogValue::decode(&CatalogKey::Anchor, original_bytes, &retired_path).unwrap()
    else {
        panic!("flushed CREATE Anchor@1 must decode")
    };
    assert_eq!(original_anchor.database_id, manifest_id);
    let mut anchor_id = manifest_id;
    if foreign_identity {
        anchor_id[15] ^= 1;
    }
    let encoded_anchor = CatalogValue::Anchor(Anchor {
        database_id: anchor_id,
        head_at_1_digest: anchor_digest(anchor_id).unwrap(),
    })
    .encode()
    .unwrap();
    assert_eq!(encoded_anchor.len(), 72);
    assert_eq!(anchor_id == manifest_id, !foreign_identity);
    assert_eq!(
        CatalogValue::decode(&CatalogKey::Anchor, &encoded_anchor, &retired_path).unwrap(),
        CatalogValue::Anchor(Anchor {
            database_id: anchor_id,
            head_at_1_digest: anchor_digest(anchor_id).unwrap(),
        })
    );
    rows[anchor_position].version.value = StoredValue::Put(encoded_anchor.clone());

    config.large_value_threshold = 11;
    config.validate().unwrap();
    let segment_path = layout.segment_path(0, 2);
    let value_path = layout.value_log_path(2);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let metadata = SegmentWriter::write(
        SegmentWriteOptions {
            path: &segment_path,
            id: 2,
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
    let segment_bytes = fs::read(&segment_path).unwrap();
    assert_eq!(metadata.entries, 7);
    assert_eq!(metadata.path, segment_path.to_str().unwrap());
    assert_eq!(
        metadata.file_digest,
        blake3::hash(&segment_bytes).to_hex().to_string()
    );
    assert_ne!(
        physical_id(&File::open(&retired_path).unwrap(), &retired_path).unwrap(),
        physical_id(&File::open(&segment_path).unwrap(), &segment_path).unwrap()
    );
    let written = decode_segment(&segment_bytes, &segment_path, &CpuAccelerator).unwrap();
    assert_eq!(written.blocks.iter().flatten().count(), 7);
    let anchor_rows = written
        .blocks
        .iter()
        .flatten()
        .filter(|raw| {
            raw.entry.cf.0 == CATALOG_CF
                && raw.entry.key.as_ref() == anchor_key.as_slice()
                && raw.entry.version.sequence == 1
        })
        .collect::<Vec<_>>();
    assert_eq!(anchor_rows.len(), 1);
    let StoredValue::BlobPointer(pointer) = &anchor_rows[0].entry.version.value else {
        panic!("replacement writer must externalize the sole Anchor@1")
    };
    assert_eq!(pointer.path.as_str(), value_path.to_str().unwrap());
    assert_eq!(pointer.len, 72);
    assert_eq!(pointer.checksum, crc32c(&encoded_anchor));
    assert_ne!(
        physical_id(&File::open(&segment_path).unwrap(), &segment_path).unwrap(),
        physical_id(&File::open(&value_path).unwrap(), &value_path).unwrap()
    );
    let value_bytes = fs::read(&value_path).unwrap();
    let offset = usize::try_from(pointer.offset).unwrap();
    let end = offset.checked_add(12 + encoded_anchor.len()).unwrap();
    assert!(end <= value_bytes.len());
    assert_eq!(
        u64::from_le_bytes(value_bytes[offset..offset + 8].try_into().unwrap()),
        pointer.len
    );
    assert_eq!(
        u32::from_le_bytes(value_bytes[offset + 8..offset + 12].try_into().unwrap()),
        pointer.checksum
    );
    assert_eq!(&value_bytes[offset + 12..end], encoded_anchor.as_slice());

    fs::remove_file(&retired_path).unwrap();
    manifest.segments = vec![metadata];
    manifest.next_segment_id = 3;
    manifest.effective_config = config.persisted();
    for family in &mut manifest.column_families {
        if family.name.starts_with("__praxor_record_") {
            family.large_value_threshold_bytes = config.large_value_threshold;
        }
    }
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.segments.len(), 1);
    assert_eq!(manifest.segments[0].id, 2);
    assert_eq!(manifest.segments[0].path, segment_path.to_str().unwrap());
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&segment_bytes).to_hex().to_string()
    );
    assert_eq!(manifest.next_segment_id, 3);
    assert_eq!(manifest.effective_config, config.persisted());
    manifest.validate_v4(root).unwrap();
    assert!(!retired_path.exists());
    let before = snapshot(dir.path());

    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let segment = collect_protected_segment_candidate(root, &manifest, budget)
            .expect("replacement segment must pass the bounded visitor");
        assert_eq!(segment.witnesses.len(), 1);
        assert_eq!(segment.rows.len(), 7);
        let observed_anchor = segment
            .rows
            .iter()
            .filter(|row| {
                row.cf == CATALOG_CF
                    && row.key.as_slice() == anchor_key.as_slice()
                    && row.sequence == 1
            })
            .collect::<Vec<_>>();
        assert_eq!(observed_anchor.len(), 1);
        assert!(matches!(
            &observed_anchor[0].value,
            ObservedSegmentValue::Pointer {
                expires_at_ms: None,
                ..
            }
        ));
        let segment_balance = budget.remaining_bytes();
        let mut probe = crate::core_catalog::value_witness::ValueFileScanProbe::default();
        let values = crate::core_catalog::value_witness::collect_value_witness(
            root,
            &manifest,
            &segment.rows,
            budget,
            &mut probe,
        )
        .expect("self-consistent external Anchor must pass the value witness");
        assert_eq!(values.files.len(), 1);
        assert!(!values.extents.is_empty());
        assert_eq!(probe.proof_full_file_hashes, 1);
        values.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), segment_balance);
        segment.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);

        let result = collect_protected_copy_ledger(root, &manifest, budget);
        if foreign_identity {
            match result {
                Err(PraxisError::Corrupt { reason, .. }) => {
                    assert!(reason.contains("Anchor") && reason.contains("MANIFEST"));
                }
                other => panic!(
                    "foreign external Anchor must be Corrupt at the private identity check: {other:?}"
                ),
            }
        } else {
            match result {
                Err(PraxisError::UnsupportedCatalogFeature {
                    feature: "protected physical-copy bytes await authenticated replay",
                }) => {}
                Ok(candidate) => candidate.discard(root, budget).unwrap(),
                other => {
                    panic!("same-identity external Anchor must reach the next gate: {other:?}")
                }
            }
        }
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);

        if !foreign_identity {
            let candidate = collect_protected_copy_admission(root, &manifest, budget)
                .expect("bound external Anchor must stage a private candidate");
            let ledger = candidate
                .consume()
                .expect("unchanged segment and value receipts must survive consumption");
            assert_eq!(ledger.segment_witnesses().len(), 1);
            let anchors = ledger
                .copies()
                .filter(|copy| {
                    copy.cf == CATALOG_CF && copy.key == anchor_key.as_slice() && copy.sequence == 1
                })
                .collect::<Vec<_>>();
            assert_eq!(anchors.len(), 1);
            assert_eq!(anchors[0].operation, CopyWireOperation::Pointer { len: 72 });
            assert_eq!(snapshot(dir.path()), before);
            drop(anchors);
            drop(ledger);
            assert_eq!(budget.remaining_bytes(), balance, "value receipt refund");
            assert_eq!(snapshot(dir.path()), before);
        }

        if mutate_at_consume {
            let candidate = collect_protected_copy_admission(root, &manifest, budget)
                .expect("bound external Anchor must stage a private candidate");
            let mut mutator = OpenOptions::new().write(true).open(&value_path).unwrap();
            mutator.seek(SeekFrom::Start(0)).unwrap();
            mutator.write_all(&[value_bytes[0] ^ 1]).unwrap();
            mutator.sync_data().unwrap();
            assert!(matches!(
                candidate.consume(),
                Err(PraxisError::Corrupt { .. })
            ));
            mutator.seek(SeekFrom::Start(0)).unwrap();
            mutator.write_all(&value_bytes[..1]).unwrap();
            mutator.sync_data().unwrap();
            drop(mutator);
            assert_eq!(
                budget.remaining_bytes(),
                balance,
                "value refusal must refund"
            );
            assert_eq!(snapshot(dir.path()), before);
        }
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn writer_external_anchor_matching_manifest_identity_reaches_next_private_gate() {
    exercise_external_anchor_manifest_identity(false, false);
}

#[test]
fn rechecksummed_external_anchor_foreign_manifest_identity_requires_corrupt() {
    exercise_external_anchor_manifest_identity(true, false);
}

#[test]
fn staged_private_candidate_rechecks_value_mutation_and_refunds() {
    exercise_external_anchor_manifest_identity(false, true);
}

fn writer_schema_pair_case(conflicting: bool) {
    let (dir, config, lease) = flushed_create_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.segments.len(), 1);
    let first_path = layout.segment_path(0, 1);
    let first_bytes = fs::read(&first_path).unwrap();
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&first_bytes).to_hex().to_string()
    );
    let first = decode_segment(&first_bytes, &first_path, &CpuAccelerator).unwrap();
    let schema_key = CatalogKey::Schema(CollectionId::new(2).unwrap())
        .encode()
        .unwrap();
    let mut copy = first
        .blocks
        .iter()
        .flatten()
        .find(|raw| {
            raw.entry.cf.0 == CATALOG_CF
                && raw.entry.key.as_ref() == schema_key.as_slice()
                && raw.entry.version.sequence == 2
        })
        .expect("flushed CREATE has Schema@2")
        .entry
        .clone();
    let StoredValue::Put(original_bytes) = &copy.version.value else {
        panic!("writer Schema@2 must be a literal Put")
    };
    let original_bytes = original_bytes.clone();
    assert_eq!(
        original_bytes,
        fixed_copy_oracle(
            "create_tag7",
            "catalog_schema_id_2",
            CATALOG_CF,
            &schema_key,
            2,
        )
    );
    assert_eq!(original_bytes.len(), 65);
    let mut expected_peer = original_bytes.clone();
    if conflicting {
        let CatalogValue::Schema(mut schema) = CatalogValue::decode(
            &CatalogKey::Schema(CollectionId::new(2).unwrap()),
            &original_bytes,
            &first_path,
        )
        .unwrap() else {
            panic!("writer Schema@2 must decode as Schema")
        };
        schema.fields[0].nullable = !schema.fields[0].nullable;
        expected_peer = CatalogValue::Schema(schema).encode().unwrap();
        assert_eq!(expected_peer.len(), original_bytes.len());
        assert_ne!(expected_peer, original_bytes);
        assert!(matches!(
            CatalogValue::decode(
                &CatalogKey::Schema(CollectionId::new(2).unwrap()),
                &expected_peer,
                &first_path,
            ),
            Ok(CatalogValue::Schema(_))
        ));
        copy.version.value = StoredValue::Put(expected_peer.clone());
    }

    let second_path = layout.segment_path(1, 2);
    fs::create_dir_all(second_path.parent().unwrap()).unwrap();
    let value_path = layout.value_log_path(2);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let second_meta = SegmentWriter::write(
        SegmentWriteOptions {
            path: &second_path,
            id: 2,
            level: 1,
            compression: Compression::None,
            accelerator: &CpuAccelerator,
            value_log: &mut value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: config.block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        vec![copy.clone()],
    )
    .unwrap();
    drop(value_log);
    fs::remove_file(value_path).unwrap();
    let second_bytes = fs::read(&second_path).unwrap();
    assert_eq!(
        second_meta.file_digest,
        blake3::hash(&second_bytes).to_hex().to_string()
    );
    let second = decode_segment(&second_bytes, &second_path, &CpuAccelerator).unwrap();
    assert_eq!(second.blocks.len(), 1);
    assert_eq!(second.blocks[0].len(), 1);
    assert_eq!(second.blocks[0][0].entry, copy);
    assert_eq!(copy.version.value, StoredValue::Put(expected_peer.clone()));
    assert_ne!(
        physical_id(&File::open(&first_path).unwrap(), &first_path).unwrap(),
        physical_id(&File::open(&second_path).unwrap(), &second_path).unwrap()
    );
    manifest.segments.push(second_meta);
    manifest.next_segment_id = 3;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    manifest.validate_v4(root).unwrap();
    let before = snapshot(dir.path());

    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let candidate = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let schemas = candidate
            .rows
            .iter()
            .filter(|row| row.cf == CATALOG_CF && row.key == schema_key && row.sequence == 2)
            .collect::<Vec<_>>();
        assert_eq!(schemas.len(), 2);
        assert_eq!(
            schemas[0].value,
            ObservedSegmentValue::Put(original_bytes.clone())
        );
        assert_eq!(
            schemas[1].value,
            ObservedSegmentValue::Put(expected_peer.clone())
        );
        assert_ne!(schemas[0].source, schemas[1].source);
        candidate.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);

        let result = collect_protected_copy_ledger(root, &manifest, budget);
        if conflicting {
            let error = match result {
                Err(error) => error,
                Ok(candidate) => {
                    candidate.discard(root, budget).unwrap();
                    panic!("conflicting Schema@2 copies reached a private candidate")
                }
            };
            assert_eq!(
                budget.remaining_bytes(),
                balance,
                "refusal must refund exactly"
            );
            assert_eq!(snapshot(dir.path()), before, "refusal must not edit files");
            match error {
                PraxisError::Corrupt { reason, .. }
                    if reason == "protected physical-copy actual bytes conflict" => {}
                other => panic!(
                    "RED: valid, equal-length Schema@2 copies with different bytes must be Corrupt: {other:?}"
                ),
            }
        } else {
            match result {
                Err(PraxisError::UnsupportedCatalogFeature {
                    feature: "protected physical-copy bytes await authenticated replay",
                }) => {}
                other => {
                    panic!("identical Schema@2 copies must reach the next private gate: {other:?}")
                }
            }
            assert_eq!(budget.remaining_bytes(), balance);
            assert_eq!(snapshot(dir.path()), before);
        }

        match collect_protected_copy_admission(root, &manifest, budget) {
            Ok(candidate) if !conflicting => {
                let ledger = candidate
                    .consume()
                    .expect("equal Schema copies must survive the consumption fence");
                let admitted = ledger
                    .copies()
                    .filter(|copy| {
                        copy.cf == CATALOG_CF
                            && copy.key == schema_key.as_slice()
                            && copy.sequence == 2
                    })
                    .collect::<Vec<_>>();
                assert_eq!(admitted.len(), 2);
                assert!(admitted.iter().all(|copy| {
                    copy.operation
                        == CopyWireOperation::Put {
                            len: original_bytes.len() as u64,
                        }
                }));
                drop(admitted);
                drop(ledger);
            }
            Err(PraxisError::Corrupt { reason, .. }) if conflicting => {
                assert_eq!(reason, "protected physical-copy actual bytes conflict");
            }
            Ok(candidate) => {
                drop(candidate);
                panic!("changed Schema copies reached a private candidate");
            }
            Err(error) => panic!("Schema candidate failed at the wrong gate: {error:?}"),
        }
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn writer_identical_schema_pair_reaches_next_private_gate() {
    writer_schema_pair_case(false);
}

#[test]
fn writer_equal_length_schema_byte_conflict_requires_private_corrupt() {
    writer_schema_pair_case(true);
}

#[derive(Clone, Copy, Debug)]
enum SchemaPairTopology {
    SharedValueFile,
    SeparateValueFiles,
    InlineThenExternal,
    ExternalThenInline,
}

#[derive(Clone, Copy, Debug)]
enum SchemaPeerChange {
    Equal,
    DifferentNullable,
    LongerName,
}

fn schema_peer_bytes(
    original: &[u8],
    key: &CatalogKey<'_>,
    root: &Path,
    change: SchemaPeerChange,
) -> Vec<u8> {
    if matches!(change, SchemaPeerChange::Equal) {
        return original.to_vec();
    }
    let CatalogValue::Schema(mut schema) = CatalogValue::decode(key, original, root).unwrap()
    else {
        panic!("fixed WAL oracle Schema must decode")
    };
    match change {
        SchemaPeerChange::Equal => unreachable!(),
        SchemaPeerChange::DifferentNullable => {
            schema.fields[0].nullable = !schema.fields[0].nullable;
        }
        SchemaPeerChange::LongerName => {
            schema.name = "schema_copy_longer_name";
        }
    }
    let encoded = CatalogValue::Schema(schema).encode().unwrap();
    assert_ne!(encoded, original);
    assert_eq!(
        encoded.len() == original.len(),
        matches!(change, SchemaPeerChange::DifferentNullable)
    );
    assert!(matches!(
        CatalogValue::decode(key, &encoded, root),
        Ok(CatalogValue::Schema(_))
    ));
    encoded
}

/// Check writer framing independently of the selected-value replay API.
fn assert_catalog_value_frame(pointer: &ValuePointer, expected: &[u8]) {
    let path = Path::new(&pointer.path);
    let file = fs::read(path).unwrap();
    let offset = usize::try_from(pointer.offset).unwrap();
    let end = offset.checked_add(12 + expected.len()).unwrap();
    assert!(end <= file.len());
    assert_eq!(pointer.len, expected.len() as u64);
    assert_eq!(pointer.checksum, crc32c(expected));
    assert_eq!(
        u64::from_le_bytes(file[offset..offset + 8].try_into().unwrap()),
        pointer.len
    );
    assert_eq!(
        u32::from_le_bytes(file[offset + 8..offset + 12].try_into().unwrap()),
        pointer.checksum
    );
    assert_eq!(&file[offset + 12..end], expected);
}

fn append_catalog_value_frame(path: &Path, bytes: &[u8]) -> ValuePointer {
    let mut writer = ValueLog::open(path).unwrap();
    writer.append(bytes).unwrap()
}

fn expected_schema_observation(value: &StoredValue) -> ObservedSegmentValue {
    match value {
        StoredValue::Put(bytes) => ObservedSegmentValue::Put(bytes.clone()),
        StoredValue::BlobPointer(pointer) => ObservedSegmentValue::Pointer {
            pointer: pointer.clone(),
            expires_at_ms: None,
        },
        other => panic!("Schema test has an unexpected wire operation: {other:?}"),
    }
}

fn writer_schema_pair_topology_case(topology: SchemaPairTopology, change: SchemaPeerChange) {
    let (dir, config, lease) = flushed_create_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.segments.len(), 1);
    let first_path = layout.segment_path(0, 1);
    let first_original = fs::read(&first_path).unwrap();
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&first_original).to_hex().to_string()
    );
    let original = decode_segment(&first_original, &first_path, &CpuAccelerator).unwrap();
    let mut first_rows = original
        .blocks
        .into_iter()
        .flatten()
        .map(|row| row.entry)
        .collect::<Vec<_>>();
    assert_eq!(first_rows.len(), 7);
    let schema_key = CatalogKey::Schema(CollectionId::new(2).unwrap());
    let key_bytes = schema_key.encode().unwrap();
    let first_position = first_rows
        .iter()
        .position(|row| {
            row.cf.0 == CATALOG_CF
                && row.key.as_ref() == key_bytes.as_slice()
                && row.version.sequence == 2
        })
        .expect("flushed CREATE must have Schema@2");
    let StoredValue::Put(original_bytes) = &first_rows[first_position].version.value else {
        panic!("writer Schema@2 must begin as an inline Put")
    };
    let original_bytes = original_bytes.clone();
    assert_eq!(
        original_bytes,
        fixed_copy_oracle(
            "create_tag7",
            "catalog_schema_id_2",
            CATALOG_CF,
            &key_bytes,
            2
        )
    );
    let peer_bytes = schema_peer_bytes(&original_bytes, &schema_key, root, change);
    let (first_external, second_external) = match topology {
        SchemaPairTopology::SharedValueFile | SchemaPairTopology::SeparateValueFiles => {
            (true, true)
        }
        SchemaPairTopology::InlineThenExternal => (false, true),
        SchemaPairTopology::ExternalThenInline => (true, false),
    };
    let first_value_path = match topology {
        SchemaPairTopology::SharedValueFile => layout.value_log_path(2),
        _ => layout.value_log_path(1),
    };
    let second_value_path = layout.value_log_path(2);
    let first_pointer =
        first_external.then(|| append_catalog_value_frame(&first_value_path, &original_bytes));
    let second_pointer =
        second_external.then(|| append_catalog_value_frame(&second_value_path, &peer_bytes));
    if let Some(pointer) = &first_pointer {
        assert_catalog_value_frame(pointer, &original_bytes);
        first_rows[first_position].version.value = StoredValue::BlobPointer(pointer.clone());
    }
    let first_entry = first_rows[first_position].clone();
    let mut second_entry = first_entry.clone();
    second_entry.version.value = match &second_pointer {
        Some(pointer) => StoredValue::BlobPointer(pointer.clone()),
        None => StoredValue::Put(peer_bytes.clone()),
    };
    if let Some(pointer) = &second_pointer {
        assert_catalog_value_frame(pointer, &peer_bytes);
    }
    if let (Some(first), Some(second)) = (&first_pointer, &second_pointer) {
        let first_file = Path::new(&first.path);
        let second_file = Path::new(&second.path);
        if matches!(topology, SchemaPairTopology::SharedValueFile) {
            assert_eq!(first_file, second_file);
            assert_eq!(first.offset, 0);
            assert_eq!(second.offset, 12 + first.len);
            assert_eq!(
                fs::metadata(first_file).unwrap().len(),
                second.offset + 12 + second.len
            );
        } else {
            assert_ne!(first_file, second_file);
            assert_eq!((first.offset, second.offset), (0, 0));
            assert_ne!(
                physical_id(&File::open(first_file).unwrap(), first_file).unwrap(),
                physical_id(&File::open(second_file).unwrap(), second_file).unwrap()
            );
        }
    }

    // Both segment files and every referenced value frame come from writers.
    let mut first_value_log = ValueLog::open(layout.value_log_path(1)).unwrap();
    let first_meta = SegmentWriter::write(
        SegmentWriteOptions {
            path: &first_path,
            id: 1,
            level: 0,
            compression: Compression::None,
            accelerator: &CpuAccelerator,
            value_log: &mut first_value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: config.block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        first_rows,
    )
    .unwrap();
    drop(first_value_log);
    if !first_external || matches!(topology, SchemaPairTopology::SharedValueFile) {
        fs::remove_file(layout.value_log_path(1)).unwrap();
    }
    let second_path = layout.segment_path(1, 2);
    fs::create_dir_all(second_path.parent().unwrap()).unwrap();
    let mut second_value_log = ValueLog::open(&second_value_path).unwrap();
    let second_meta = SegmentWriter::write(
        SegmentWriteOptions {
            path: &second_path,
            id: 2,
            level: 1,
            compression: Compression::None,
            accelerator: &CpuAccelerator,
            value_log: &mut second_value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: config.block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        vec![second_entry.clone()],
    )
    .unwrap();
    drop(second_value_log);
    if !second_external && !matches!(topology, SchemaPairTopology::SharedValueFile) {
        fs::remove_file(&second_value_path).unwrap();
    }
    // The final writer calls must not have appended hidden frames or tail
    // bytes after the earlier pointer checks. Recheck raw bytes and EOF now.
    if let Some(pointer) = &first_pointer {
        assert_catalog_value_frame(pointer, &original_bytes);
    }
    if let Some(pointer) = &second_pointer {
        assert_catalog_value_frame(pointer, &peer_bytes);
    }
    match topology {
        SchemaPairTopology::SharedValueFile => {
            let first = first_pointer.as_ref().unwrap();
            let second = second_pointer.as_ref().unwrap();
            assert_eq!(first.path, second.path);
            assert_eq!(first.offset, 0);
            assert_eq!(second.offset, 12 + first.len);
            assert_eq!(
                fs::metadata(&first.path).unwrap().len(),
                second.offset + 12 + second.len
            );
        }
        SchemaPairTopology::SeparateValueFiles => {
            let first = first_pointer.as_ref().unwrap();
            let second = second_pointer.as_ref().unwrap();
            assert_ne!(first.path, second.path);
            for pointer in [first, second] {
                assert_eq!(pointer.offset, 0);
                assert_eq!(fs::metadata(&pointer.path).unwrap().len(), 12 + pointer.len);
            }
            assert_ne!(
                physical_id(&File::open(&first.path).unwrap(), Path::new(&first.path)).unwrap(),
                physical_id(&File::open(&second.path).unwrap(), Path::new(&second.path)).unwrap()
            );
        }
        SchemaPairTopology::InlineThenExternal => {
            let pointer = second_pointer.as_ref().unwrap();
            assert!(first_pointer.is_none());
            assert_eq!(pointer.offset, 0);
            assert_eq!(fs::metadata(&pointer.path).unwrap().len(), 12 + pointer.len);
        }
        SchemaPairTopology::ExternalThenInline => {
            let pointer = first_pointer.as_ref().unwrap();
            assert!(second_pointer.is_none());
            assert_eq!(pointer.offset, 0);
            assert_eq!(fs::metadata(&pointer.path).unwrap().len(), 12 + pointer.len);
        }
    }
    let first_written = fs::read(&first_path).unwrap();
    let second_written = fs::read(&second_path).unwrap();
    assert_eq!(
        first_meta.file_digest,
        blake3::hash(&first_written).to_hex().to_string()
    );
    assert_eq!(
        second_meta.file_digest,
        blake3::hash(&second_written).to_hex().to_string()
    );
    let first_decoded = decode_segment(&first_written, &first_path, &CpuAccelerator).unwrap();
    let second_decoded = decode_segment(&second_written, &second_path, &CpuAccelerator).unwrap();
    let first_offsets = literal_block_offsets(&first_written, 0, 1, first_decoded.blocks.len());
    let second_offsets = literal_block_offsets(&second_written, 1, 2, second_decoded.blocks.len());
    let locations = [
        exact_entry_location(&first_decoded, &first_offsets, &first_entry),
        exact_entry_location(&second_decoded, &second_offsets, &second_entry),
    ];
    assert_eq!(second_decoded.blocks.iter().flatten().count(), 1);
    assert_ne!(
        physical_id(&File::open(&first_path).unwrap(), &first_path).unwrap(),
        physical_id(&File::open(&second_path).unwrap(), &second_path).unwrap()
    );
    manifest.segments[0] = first_meta;
    manifest.segments.push(second_meta);
    manifest.next_segment_id = 3;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    manifest.validate_v4(root).unwrap();
    let before = snapshot(dir.path());

    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let segment = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let schema_rows = segment
            .rows
            .iter()
            .filter(|row| row.cf == CATALOG_CF && row.key == key_bytes && row.sequence == 2)
            .collect::<Vec<_>>();
        assert_eq!(schema_rows.len(), 2);
        for (index, (row, expected)) in schema_rows
            .iter()
            .zip([&first_entry, &second_entry])
            .enumerate()
        {
            assert_eq!(
                row.source,
                SegmentSource {
                    level: index as u32,
                    id: index as u64 + 1,
                    manifest_ordinal: index,
                }
            );
            assert_eq!((row.block_offset, row.row_ordinal), locations[index]);
            assert_eq!(
                row.classification,
                PhysicalRowClass::BoundProtected(ProtectedRole::Catalog)
            );
            assert_eq!(
                row.value,
                expected_schema_observation(&expected.version.value)
            );
        }
        let mut probe = ValueFileScanProbe::default();
        let value = collect_value_witness(root, &manifest, &segment.rows, budget, &mut probe)
            .expect("writer-framed Schema pointer(s) must authenticate");
        let expected_files = if matches!(topology, SchemaPairTopology::SeparateValueFiles) {
            2
        } else {
            1
        };
        assert_eq!(value.files.len(), expected_files);
        assert_eq!(
            value.extents.len(),
            first_external as usize + second_external as usize
        );
        assert_eq!(probe.proof_full_file_hashes, expected_files);
        for row in &schema_rows {
            let ObservedSegmentValue::Pointer { pointer, .. } = &row.value else {
                continue;
            };
            let locator = ValueRowLocator {
                source: row.source,
                block_offset: row.block_offset,
                row_ordinal: row.row_ordinal,
            };
            let extents = value
                .extents
                .iter()
                .filter(|extent| extent.locator == locator)
                .collect::<Vec<_>>();
            assert_eq!(
                extents.len(),
                1,
                "each pointer needs its exact physical locator"
            );
            let extent = extents[0];
            assert_eq!(
                (extent.offset, extent.len, extent.checksum),
                (pointer.offset, pointer.len, pointer.checksum)
            );
            let file = value
                .files
                .iter()
                .find(|file| file.id == extent.file_id)
                .unwrap();
            assert_eq!(file.path.as_path(), Path::new(&pointer.path));
            let bytes = fs::read(&file.path).unwrap();
            assert_eq!(file.len, bytes.len() as u64);
            assert_eq!(file.digest, blake3::hash(&bytes));
            assert_eq!(
                file.identity,
                physical_id(&File::open(&file.path).unwrap(), &file.path).unwrap()
            );
        }
        value.discard(root, budget).unwrap();
        segment.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);

        let result = collect_protected_copy_ledger(root, &manifest, budget);
        let error = match result {
            Err(error) => error,
            Ok(candidate) => {
                candidate.discard(root, budget).unwrap();
                panic!("Schema pair unexpectedly reached a private candidate")
            }
        };
        assert_eq!(
            budget.remaining_bytes(),
            balance,
            "refusal must refund exactly"
        );
        assert_eq!(snapshot(dir.path()), before, "refusal must not edit files");
        match change {
            SchemaPeerChange::Equal => assert!(matches!(
                error,
                PraxisError::UnsupportedCatalogFeature {
                    feature: "protected physical-copy bytes await authenticated replay"
                }
            )),
            SchemaPeerChange::DifferentNullable | SchemaPeerChange::LongerName => match error {
                PraxisError::Corrupt { reason, .. }
                    if reason == "protected physical-copy actual bytes conflict" => {}
                other => panic!(
                    "RED: valid Schema pair {topology:?}/{change:?} must conflict after complete fences: {other:?}"
                ),
            },
        }

        match collect_protected_copy_admission(root, &manifest, budget) {
            Ok(candidate) if matches!(change, SchemaPeerChange::Equal) => {
                let ledger = candidate
                    .consume()
                    .expect("equal Schema topology must survive consumption fences");
                assert_eq!(ledger.segment_witnesses().len(), 2);
                let admitted = ledger
                    .copies()
                    .filter(|copy| {
                        copy.cf == CATALOG_CF
                            && copy.key == key_bytes.as_slice()
                            && copy.sequence == 2
                    })
                    .collect::<Vec<_>>();
                assert_eq!(admitted.len(), 2);
                for (index, copy) in admitted.iter().enumerate() {
                    assert_eq!(
                        copy.source,
                        SegmentSource {
                            level: index as u32,
                            id: index as u64 + 1,
                            manifest_ordinal: index,
                        }
                    );
                    assert_eq!((copy.block_offset, copy.row_ordinal), locations[index]);
                    assert_eq!(
                        copy.operation,
                        if [first_external, second_external][index] {
                            CopyWireOperation::Pointer {
                                len: [&original_bytes, &peer_bytes][index].len() as u64,
                            }
                        } else {
                            CopyWireOperation::Put {
                                len: [&original_bytes, &peer_bytes][index].len() as u64,
                            }
                        }
                    );
                }
                drop(admitted);
                drop(ledger);
            }
            Err(PraxisError::Corrupt { reason, .. })
                if !matches!(change, SchemaPeerChange::Equal) =>
            {
                assert_eq!(reason, "protected physical-copy actual bytes conflict");
            }
            Ok(candidate) => {
                drop(candidate);
                panic!("changed Schema topology reached a private candidate");
            }
            Err(error) => panic!("Schema topology candidate failed at the wrong gate: {error:?}"),
        }
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn writer_schema_shared_value_file_equal_control() {
    writer_schema_pair_topology_case(SchemaPairTopology::SharedValueFile, SchemaPeerChange::Equal);
}

#[test]
fn writer_schema_shared_value_file_unequal_length_conflict() {
    writer_schema_pair_topology_case(
        SchemaPairTopology::SharedValueFile,
        SchemaPeerChange::LongerName,
    );
}

#[test]
fn writer_schema_separate_value_files_equal_control() {
    writer_schema_pair_topology_case(
        SchemaPairTopology::SeparateValueFiles,
        SchemaPeerChange::Equal,
    );
}

#[test]
fn writer_schema_separate_value_files_valid_byte_conflict() {
    writer_schema_pair_topology_case(
        SchemaPairTopology::SeparateValueFiles,
        SchemaPeerChange::DifferentNullable,
    );
}

#[test]
fn writer_schema_inline_then_external_equal_control() {
    writer_schema_pair_topology_case(
        SchemaPairTopology::InlineThenExternal,
        SchemaPeerChange::Equal,
    );
}

#[test]
fn writer_schema_inline_then_external_valid_byte_conflict() {
    writer_schema_pair_topology_case(
        SchemaPairTopology::InlineThenExternal,
        SchemaPeerChange::DifferentNullable,
    );
}

#[test]
fn writer_schema_external_then_inline_equal_control() {
    writer_schema_pair_topology_case(
        SchemaPairTopology::ExternalThenInline,
        SchemaPeerChange::Equal,
    );
}

#[test]
fn writer_schema_external_then_inline_unequal_length_conflict() {
    writer_schema_pair_topology_case(
        SchemaPairTopology::ExternalThenInline,
        SchemaPeerChange::LongerName,
    );
}

#[derive(Clone, Copy, Debug)]
enum FixedCatalogPair {
    Name,
    Namespace,
}

fn writer_fixed_catalog_pair_case(role: FixedCatalogPair, conflicting: bool) {
    let (dir, config, lease) = flushed_create_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.segments.len(), 1);
    let first_path = layout.segment_path(0, 1);
    let first_bytes = fs::read(&first_path).unwrap();
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&first_bytes).to_hex().to_string()
    );
    let first = decode_segment(&first_bytes, &first_path, &CpuAccelerator).unwrap();
    let (key, oracle_name, width) = match role {
        FixedCatalogPair::Name => (CatalogKey::Name("accounts"), "catalog_name_accounts", 12),
        FixedCatalogPair::Namespace => (
            CatalogKey::Namespace(NamespaceId::new(2).unwrap()),
            "catalog_namespace_id_2",
            16,
        ),
    };
    let key_bytes = key.encode().unwrap();
    let original_bytes = fixed_copy_oracle("create_tag7", oracle_name, CATALOG_CF, &key_bytes, 2);
    assert_eq!(original_bytes.len(), width);
    let mut peer = first
        .blocks
        .iter()
        .flatten()
        .find(|row| {
            row.entry.cf.0 == CATALOG_CF
                && row.entry.key.as_ref() == key_bytes.as_slice()
                && row.entry.version.sequence == 2
        })
        .expect("flushed CREATE has this catalog role")
        .entry
        .clone();
    assert_eq!(peer.version.value, StoredValue::Put(original_bytes.clone()));
    assert!(matches!(
        CatalogValue::decode(&key, &original_bytes, root),
        Ok(CatalogValue::Name(_)) | Ok(CatalogValue::Namespace(_))
    ));
    let peer_bytes = if conflicting {
        assert!(matches!(role, FixedCatalogPair::Name));
        let changed = CatalogValue::Name(CollectionId::new(3).unwrap())
            .encode()
            .unwrap();
        assert_eq!(changed.len(), width);
        assert_ne!(changed, original_bytes);
        assert!(matches!(
            CatalogValue::decode(&key, &changed, root),
            Ok(CatalogValue::Name(_))
        ));
        peer.version.value = StoredValue::Put(changed.clone());
        changed
    } else {
        original_bytes.clone()
    };
    let first_offsets = literal_block_offsets(&first_bytes, 0, 1, first.blocks.len());
    let original_entry = first
        .blocks
        .iter()
        .flatten()
        .find(|row| {
            row.entry.cf.0 == CATALOG_CF
                && row.entry.key.as_ref() == key_bytes.as_slice()
                && row.entry.version.sequence == 2
        })
        .unwrap()
        .entry
        .clone();
    let first_location = exact_entry_location(&first, &first_offsets, &original_entry);
    let second_path = layout.segment_path(1, 2);
    fs::create_dir_all(second_path.parent().unwrap()).unwrap();
    let value_path = layout.value_log_path(2);
    let mut value_log = ValueLog::open(&value_path).unwrap();
    let second_meta = SegmentWriter::write(
        SegmentWriteOptions {
            path: &second_path,
            id: 2,
            level: 1,
            compression: Compression::None,
            accelerator: &CpuAccelerator,
            value_log: &mut value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: config.block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        vec![peer.clone()],
    )
    .unwrap();
    drop(value_log);
    fs::remove_file(value_path).unwrap();
    let second_bytes = fs::read(&second_path).unwrap();
    assert_eq!(
        second_meta.file_digest,
        blake3::hash(&second_bytes).to_hex().to_string()
    );
    let second = decode_segment(&second_bytes, &second_path, &CpuAccelerator).unwrap();
    assert_eq!(second.blocks.iter().flatten().count(), 1);
    assert_eq!(second.blocks[0][0].entry, peer);
    let second_offsets = literal_block_offsets(&second_bytes, 1, 2, second.blocks.len());
    let second_location = exact_entry_location(&second, &second_offsets, &peer);
    assert_ne!(
        physical_id(&File::open(&first_path).unwrap(), &first_path).unwrap(),
        physical_id(&File::open(&second_path).unwrap(), &second_path).unwrap()
    );
    manifest.segments.push(second_meta);
    manifest.next_segment_id = 3;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    manifest.validate_v4(root).unwrap();
    let before = snapshot(dir.path());

    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let staged = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let copies = staged
            .rows
            .iter()
            .filter(|row| row.cf == CATALOG_CF && row.key == key_bytes && row.sequence == 2)
            .collect::<Vec<_>>();
        assert_eq!(copies.len(), 2);
        for (index, (row, bytes)) in copies
            .iter()
            .zip([&original_bytes, &peer_bytes])
            .enumerate()
        {
            assert_eq!(
                row.source,
                SegmentSource {
                    level: index as u32,
                    id: index as u64 + 1,
                    manifest_ordinal: index,
                }
            );
            assert_eq!(
                (row.block_offset, row.row_ordinal),
                [first_location, second_location][index]
            );
            assert_eq!(
                row.classification,
                PhysicalRowClass::BoundProtected(ProtectedRole::Catalog)
            );
            assert_eq!(row.value, ObservedSegmentValue::Put(bytes.to_vec()));
        }
        staged.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);

        let result = collect_protected_copy_ledger(root, &manifest, budget);
        let error = match result {
            Err(error) => error,
            Ok(candidate) => {
                candidate.discard(root, budget).unwrap();
                panic!("fixed catalog pair unexpectedly reached a private candidate")
            }
        };
        assert_eq!(
            budget.remaining_bytes(),
            balance,
            "refusal must refund exactly"
        );
        assert_eq!(snapshot(dir.path()), before, "refusal must not edit files");
        if conflicting {
            match error {
                PraxisError::Corrupt { reason, .. }
                    if reason == "protected physical-copy actual bytes conflict" => {}
                other => panic!(
                    "RED: valid different Name@2 bytes must conflict after complete fences: {other:?}"
                ),
            }
        } else {
            assert!(matches!(
                error,
                PraxisError::UnsupportedCatalogFeature {
                    feature: "protected physical-copy bytes await authenticated replay"
                }
            ));
        }

        match collect_protected_copy_admission(root, &manifest, budget) {
            Ok(candidate) if !conflicting => {
                let ledger = candidate
                    .consume()
                    .expect("equal fixed Catalog copies must survive consumption fences");
                assert_eq!(ledger.segment_witnesses().len(), 2);
                let admitted = ledger
                    .copies()
                    .filter(|copy| {
                        copy.cf == CATALOG_CF
                            && copy.key == key_bytes.as_slice()
                            && copy.sequence == 2
                    })
                    .collect::<Vec<_>>();
                assert_eq!(admitted.len(), 2);
                for (index, copy) in admitted.iter().enumerate() {
                    assert_eq!(
                        copy.source,
                        SegmentSource {
                            level: index as u32,
                            id: index as u64 + 1,
                            manifest_ordinal: index,
                        }
                    );
                    assert_eq!(
                        (copy.block_offset, copy.row_ordinal),
                        [first_location, second_location][index]
                    );
                    assert_eq!(copy.operation, CopyWireOperation::Put { len: width as u64 });
                }
                drop(admitted);
                drop(ledger);
            }
            Err(PraxisError::Corrupt { reason, .. }) if conflicting => {
                assert_eq!(reason, "protected physical-copy actual bytes conflict");
            }
            Ok(candidate) => {
                drop(candidate);
                panic!("changed fixed Catalog copies reached a private candidate");
            }
            Err(error) => panic!("fixed Catalog candidate failed at the wrong gate: {error:?}"),
        }
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn writer_identical_catalog_name_pair_reaches_next_private_gate() {
    writer_fixed_catalog_pair_case(FixedCatalogPair::Name, false);
}

#[test]
fn writer_valid_catalog_name_copy_conflict_requires_corrupt() {
    writer_fixed_catalog_pair_case(FixedCatalogPair::Name, true);
}

#[test]
fn writer_identical_catalog_namespace_pair_reaches_next_private_gate() {
    writer_fixed_catalog_pair_case(FixedCatalogPair::Namespace, false);
}

#[derive(Clone, Copy, Debug)]
enum CatalogNameExternalTopology {
    SharedValueFile,
    SeparateValueFiles,
}

fn writer_external_catalog_name_pair_case(
    topology: CatalogNameExternalTopology,
    conflicting: bool,
) {
    let (dir, config, lease) = flushed_create_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.segments.len(), 1);
    let first_path = layout.segment_path(0, 1);
    let first_original = fs::read(&first_path).unwrap();
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&first_original).to_hex().to_string()
    );
    let original = decode_segment(&first_original, &first_path, &CpuAccelerator).unwrap();
    let mut first_rows = original
        .blocks
        .into_iter()
        .flatten()
        .map(|row| row.entry)
        .collect::<Vec<_>>();
    assert_eq!(first_rows.len(), 7);
    let name_key = CatalogKey::Name("accounts");
    let key_bytes = name_key.encode().unwrap();
    let name_position = first_rows
        .iter()
        .position(|row| {
            row.cf.0 == CATALOG_CF
                && row.key.as_ref() == key_bytes.as_slice()
                && row.version.sequence == 2
        })
        .expect("flushed CREATE has Name@2");
    let original_bytes = fixed_copy_oracle(
        "create_tag7",
        "catalog_name_accounts",
        CATALOG_CF,
        &key_bytes,
        2,
    );
    assert_eq!(original_bytes.len(), 12);
    assert_eq!(
        first_rows[name_position].version.value,
        StoredValue::Put(original_bytes.clone())
    );
    assert!(matches!(
        CatalogValue::decode(&name_key, &original_bytes, root),
        Ok(CatalogValue::Name(_))
    ));
    let peer_bytes = if conflicting {
        let changed = CatalogValue::Name(CollectionId::new(3).unwrap())
            .encode()
            .unwrap();
        assert_eq!(changed.len(), 12);
        assert_ne!(changed, original_bytes);
        assert!(matches!(
            CatalogValue::decode(&name_key, &changed, root),
            Ok(CatalogValue::Name(_))
        ));
        changed
    } else {
        original_bytes.clone()
    };

    let first_value_path = match topology {
        CatalogNameExternalTopology::SharedValueFile => layout.value_log_path(2),
        CatalogNameExternalTopology::SeparateValueFiles => layout.value_log_path(1),
    };
    let second_value_path = layout.value_log_path(2);
    let first_pointer = append_catalog_value_frame(&first_value_path, &original_bytes);
    let second_pointer = append_catalog_value_frame(&second_value_path, &peer_bytes);
    assert_eq!(first_pointer.offset, 0);
    match topology {
        CatalogNameExternalTopology::SharedValueFile => {
            assert_eq!(first_pointer.path, second_pointer.path);
            assert_eq!(second_pointer.offset, 12 + first_pointer.len);
        }
        CatalogNameExternalTopology::SeparateValueFiles => {
            assert_ne!(first_pointer.path, second_pointer.path);
            assert_eq!(second_pointer.offset, 0);
            assert_ne!(
                physical_id(&File::open(&first_value_path).unwrap(), &first_value_path).unwrap(),
                physical_id(&File::open(&second_value_path).unwrap(), &second_value_path).unwrap()
            );
        }
    }
    first_rows[name_position].version.value = StoredValue::BlobPointer(first_pointer.clone());
    let first_entry = first_rows[name_position].clone();
    let mut second_entry = first_entry.clone();
    second_entry.version.value = StoredValue::BlobPointer(second_pointer.clone());

    let mut first_value_log = ValueLog::open(layout.value_log_path(1)).unwrap();
    let first_meta = SegmentWriter::write(
        SegmentWriteOptions {
            path: &first_path,
            id: 1,
            level: 0,
            compression: Compression::None,
            accelerator: &CpuAccelerator,
            value_log: &mut first_value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: config.block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        first_rows,
    )
    .unwrap();
    drop(first_value_log);
    if matches!(topology, CatalogNameExternalTopology::SharedValueFile) {
        fs::remove_file(layout.value_log_path(1)).unwrap();
    }
    let second_path = layout.segment_path(1, 2);
    fs::create_dir_all(second_path.parent().unwrap()).unwrap();
    let mut second_value_log = ValueLog::open(&second_value_path).unwrap();
    let second_meta = SegmentWriter::write(
        SegmentWriteOptions {
            path: &second_path,
            id: 2,
            level: 1,
            compression: Compression::None,
            accelerator: &CpuAccelerator,
            value_log: &mut second_value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: config.block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        vec![second_entry.clone()],
    )
    .unwrap();
    drop(second_value_log);

    // Check raw length, CRC, payload bytes and exact EOF independently of the
    // value witness. The full-file digest is then compared with its receipt.
    assert_catalog_value_frame(&first_pointer, &original_bytes);
    assert_catalog_value_frame(&second_pointer, &peer_bytes);
    let first_value_raw = fs::read(&first_value_path).unwrap();
    let second_value_raw = fs::read(&second_value_path).unwrap();
    match topology {
        CatalogNameExternalTopology::SharedValueFile => {
            assert_eq!(first_value_raw, second_value_raw);
            assert_eq!(
                first_value_raw.len() as u64,
                second_pointer.offset + 12 + second_pointer.len
            );
        }
        CatalogNameExternalTopology::SeparateValueFiles => {
            assert_eq!(first_value_raw.len() as u64, 12 + first_pointer.len);
            assert_eq!(second_value_raw.len() as u64, 12 + second_pointer.len);
        }
    }
    let first_written = fs::read(&first_path).unwrap();
    let second_written = fs::read(&second_path).unwrap();
    assert_eq!(
        first_meta.file_digest,
        blake3::hash(&first_written).to_hex().to_string()
    );
    assert_eq!(
        second_meta.file_digest,
        blake3::hash(&second_written).to_hex().to_string()
    );
    let first_decoded = decode_segment(&first_written, &first_path, &CpuAccelerator).unwrap();
    let second_decoded = decode_segment(&second_written, &second_path, &CpuAccelerator).unwrap();
    assert_eq!(second_decoded.blocks.iter().flatten().count(), 1);
    assert_eq!(second_decoded.blocks[0][0].entry, second_entry);
    let first_offsets = literal_block_offsets(&first_written, 0, 1, first_decoded.blocks.len());
    let second_offsets = literal_block_offsets(&second_written, 1, 2, second_decoded.blocks.len());
    let locations = [
        exact_entry_location(&first_decoded, &first_offsets, &first_entry),
        exact_entry_location(&second_decoded, &second_offsets, &second_entry),
    ];
    assert_ne!(
        physical_id(&File::open(&first_path).unwrap(), &first_path).unwrap(),
        physical_id(&File::open(&second_path).unwrap(), &second_path).unwrap()
    );
    manifest.segments[0] = first_meta;
    manifest.segments.push(second_meta);
    manifest.next_segment_id = 3;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    manifest.validate_v4(root).unwrap();
    let before = snapshot(dir.path());

    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let segment = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let copies = segment
            .rows
            .iter()
            .filter(|row| row.cf == CATALOG_CF && row.key == key_bytes && row.sequence == 2)
            .collect::<Vec<_>>();
        assert_eq!(copies.len(), 2);
        for (index, (row, pointer)) in copies
            .iter()
            .zip([&first_pointer, &second_pointer])
            .enumerate()
        {
            assert_eq!(
                row.source,
                SegmentSource {
                    level: index as u32,
                    id: index as u64 + 1,
                    manifest_ordinal: index,
                }
            );
            assert_eq!((row.block_offset, row.row_ordinal), locations[index]);
            assert_eq!(
                row.classification,
                PhysicalRowClass::BoundProtected(ProtectedRole::Catalog)
            );
            assert_eq!(
                row.value,
                ObservedSegmentValue::Pointer {
                    pointer: (*pointer).clone(),
                    expires_at_ms: None,
                }
            );
        }
        let mut probe = ValueFileScanProbe::default();
        let value = collect_value_witness(root, &manifest, &segment.rows, budget, &mut probe)
            .expect("two writer-framed Name pointers must authenticate");
        let expected_files = if matches!(topology, CatalogNameExternalTopology::SharedValueFile) {
            1
        } else {
            2
        };
        assert_eq!(value.files.len(), expected_files);
        assert_eq!(value.extents.len(), 2);
        assert_eq!(probe.proof_full_file_hashes, expected_files);
        for file in &value.files {
            let raw = if file.path == first_value_path {
                &first_value_raw
            } else {
                assert_eq!(file.path, second_value_path);
                &second_value_raw
            };
            assert_eq!(file.len, raw.len() as u64);
            assert_eq!(file.digest, blake3::hash(raw));
            assert_eq!(
                file.identity,
                physical_id(&File::open(&file.path).unwrap(), &file.path).unwrap()
            );
        }
        if matches!(topology, CatalogNameExternalTopology::SeparateValueFiles) {
            assert_ne!(value.files[0].identity, value.files[1].identity);
        }
        for (row, pointer) in copies.iter().zip([&first_pointer, &second_pointer]) {
            let locator = ValueRowLocator {
                source: row.source,
                block_offset: row.block_offset,
                row_ordinal: row.row_ordinal,
            };
            let extents = value
                .extents
                .iter()
                .filter(|extent| extent.locator == locator)
                .collect::<Vec<_>>();
            assert_eq!(extents.len(), 1);
            let extent = extents[0];
            let file = value
                .files
                .iter()
                .find(|file| file.id == extent.file_id)
                .unwrap();
            assert_eq!(file.path.as_path(), Path::new(&pointer.path));
            assert_eq!(
                (extent.offset, extent.len, extent.checksum),
                (pointer.offset, pointer.len, pointer.checksum)
            );
        }
        value.discard(root, budget).unwrap();
        segment.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);

        let error = match collect_protected_copy_ledger(root, &manifest, budget) {
            Err(error) => error,
            Ok(candidate) => {
                candidate.discard(root, budget).unwrap();
                panic!("{topology:?} external Name pair unexpectedly reached a private candidate")
            }
        };
        assert_eq!(
            budget.remaining_bytes(),
            balance,
            "refusal must refund exactly"
        );
        assert_eq!(snapshot(dir.path()), before, "refusal must not edit files");
        if conflicting {
            match error {
                PraxisError::Corrupt { reason, .. }
                    if reason == "protected physical-copy actual bytes conflict" => {}
                other => panic!("{topology:?} external Name bytes must conflict: {other:?}"),
            }
        } else {
            match error {
                PraxisError::UnsupportedCatalogFeature {
                    feature: "protected physical-copy bytes await authenticated replay",
                } => {}
                other => {
                    panic!("equal {topology:?} external Name copies must reach pending: {other:?}")
                }
            }
        }

        match collect_protected_copy_admission(root, &manifest, budget) {
            Ok(candidate) if !conflicting => {
                let ledger = candidate
                    .consume()
                    .expect("equal external Name copies must survive consumption fences");
                assert_eq!(ledger.segment_witnesses().len(), 2);
                let admitted = ledger
                    .copies()
                    .filter(|copy| {
                        copy.cf == CATALOG_CF
                            && copy.key == key_bytes.as_slice()
                            && copy.sequence == 2
                    })
                    .collect::<Vec<_>>();
                assert_eq!(admitted.len(), 2);
                for (index, copy) in admitted.iter().enumerate() {
                    assert_eq!(
                        copy.source,
                        SegmentSource {
                            level: index as u32,
                            id: index as u64 + 1,
                            manifest_ordinal: index,
                        }
                    );
                    assert_eq!((copy.block_offset, copy.row_ordinal), locations[index]);
                    assert_eq!(
                        copy.operation,
                        CopyWireOperation::Pointer {
                            len: [first_pointer.len, second_pointer.len][index],
                        }
                    );
                }
                drop(admitted);
                drop(ledger);
            }
            Err(PraxisError::Corrupt { reason, .. }) if conflicting => {
                assert_eq!(reason, "protected physical-copy actual bytes conflict");
            }
            Ok(candidate) => {
                drop(candidate);
                panic!("changed external Name copies reached a private candidate");
            }
            Err(error) => panic!("external Name candidate failed at the wrong gate: {error:?}"),
        }
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn writer_shared_external_catalog_name_equal_reaches_private_gate() {
    writer_external_catalog_name_pair_case(CatalogNameExternalTopology::SharedValueFile, false);
}

#[test]
fn writer_shared_external_catalog_name_valid_conflict_requires_corrupt() {
    writer_external_catalog_name_pair_case(CatalogNameExternalTopology::SharedValueFile, true);
}

#[test]
fn writer_separate_external_catalog_name_equal_reaches_private_gate() {
    writer_external_catalog_name_pair_case(CatalogNameExternalTopology::SeparateValueFiles, false);
}

#[test]
fn writer_separate_external_catalog_name_valid_conflict_requires_corrupt() {
    writer_external_catalog_name_pair_case(CatalogNameExternalTopology::SeparateValueFiles, true);
}

fn writer_mixed_catalog_name_pair_case(first_external: bool, conflicting: bool) {
    let (dir, config, lease) = flushed_create_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(manifest.segments.len(), 1);
    let first_path = layout.segment_path(0, 1);
    let first_original = fs::read(&first_path).unwrap();
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&first_original).to_hex().to_string()
    );
    let original = decode_segment(&first_original, &first_path, &CpuAccelerator).unwrap();
    let mut first_rows = original
        .blocks
        .into_iter()
        .flatten()
        .map(|row| row.entry)
        .collect::<Vec<_>>();
    assert_eq!(first_rows.len(), 7);
    let name_key = CatalogKey::Name("accounts");
    let key_bytes = name_key.encode().unwrap();
    let name_position = first_rows
        .iter()
        .position(|row| {
            row.cf.0 == CATALOG_CF
                && row.key.as_ref() == key_bytes.as_slice()
                && row.version.sequence == 2
        })
        .expect("flushed CREATE has Name@2");
    let original_bytes = fixed_copy_oracle(
        "create_tag7",
        "catalog_name_accounts",
        CATALOG_CF,
        &key_bytes,
        2,
    );
    assert_eq!(original_bytes.len(), 12);
    assert_eq!(
        first_rows[name_position].version.value,
        StoredValue::Put(original_bytes.clone())
    );
    assert!(matches!(
        CatalogValue::decode(&name_key, &original_bytes, root),
        Ok(CatalogValue::Name(_))
    ));
    let peer_bytes = if conflicting {
        let changed = CatalogValue::Name(CollectionId::new(3).unwrap())
            .encode()
            .unwrap();
        assert_eq!(changed.len(), original_bytes.len());
        assert_ne!(changed, original_bytes);
        assert!(matches!(
            CatalogValue::decode(&name_key, &changed, root),
            Ok(CatalogValue::Name(_))
        ));
        changed
    } else {
        original_bytes.clone()
    };

    // One writer-framed value is external; the other remains a literal Put.
    // Value file 2 is independent of the first segment writer's output file.
    let value_path = layout.value_log_path(2);
    let external_bytes = if first_external {
        &original_bytes
    } else {
        &peer_bytes
    };
    let pointer = append_catalog_value_frame(&value_path, external_bytes);
    assert_eq!(Path::new(&pointer.path), value_path.as_path());
    assert_eq!(pointer.offset, 0);
    if first_external {
        first_rows[name_position].version.value = StoredValue::BlobPointer(pointer.clone());
    }
    let first_entry = first_rows[name_position].clone();
    let mut second_entry = first_entry.clone();
    second_entry.version.value = if first_external {
        StoredValue::Put(peer_bytes.clone())
    } else {
        StoredValue::BlobPointer(pointer.clone())
    };

    let first_value_path = layout.value_log_path(1);
    let mut first_value_log = ValueLog::open(&first_value_path).unwrap();
    let first_meta = SegmentWriter::write(
        SegmentWriteOptions {
            path: &first_path,
            id: 1,
            level: 0,
            compression: Compression::None,
            accelerator: &CpuAccelerator,
            value_log: &mut first_value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: config.block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        first_rows,
    )
    .unwrap();
    drop(first_value_log);
    fs::remove_file(&first_value_path).unwrap();
    let second_path = layout.segment_path(1, 2);
    fs::create_dir_all(second_path.parent().unwrap()).unwrap();
    let mut second_value_log = ValueLog::open(&value_path).unwrap();
    let second_meta = SegmentWriter::write(
        SegmentWriteOptions {
            path: &second_path,
            id: 2,
            level: 1,
            compression: Compression::None,
            accelerator: &CpuAccelerator,
            value_log: &mut second_value_log,
            large_value_threshold: config.large_value_threshold,
            block_size: config.block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        vec![second_entry.clone()],
    )
    .unwrap();
    drop(second_value_log);

    // Recheck framing after both segment writers, including the exact EOF.
    assert_catalog_value_frame(&pointer, external_bytes);
    let value_raw = fs::read(&value_path).unwrap();
    assert_eq!(value_raw.len() as u64, 12 + pointer.len);
    let value_digest = blake3::hash(&value_raw);
    let first_written = fs::read(&first_path).unwrap();
    let second_written = fs::read(&second_path).unwrap();
    assert_eq!(
        first_meta.file_digest,
        blake3::hash(&first_written).to_hex().to_string()
    );
    assert_eq!(
        second_meta.file_digest,
        blake3::hash(&second_written).to_hex().to_string()
    );
    let first_decoded = decode_segment(&first_written, &first_path, &CpuAccelerator).unwrap();
    let second_decoded = decode_segment(&second_written, &second_path, &CpuAccelerator).unwrap();
    assert_eq!(second_decoded.blocks.iter().flatten().count(), 1);
    assert_eq!(second_decoded.blocks[0][0].entry, second_entry);
    let first_offsets = literal_block_offsets(&first_written, 0, 1, first_decoded.blocks.len());
    let second_offsets = literal_block_offsets(&second_written, 1, 2, second_decoded.blocks.len());
    let locations = [
        exact_entry_location(&first_decoded, &first_offsets, &first_entry),
        exact_entry_location(&second_decoded, &second_offsets, &second_entry),
    ];
    assert_ne!(
        physical_id(&File::open(&first_path).unwrap(), &first_path).unwrap(),
        physical_id(&File::open(&second_path).unwrap(), &second_path).unwrap()
    );
    manifest.segments[0] = first_meta;
    manifest.segments.push(second_meta);
    manifest.next_segment_id = 3;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();
    let manifest = Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    manifest.validate_v4(root).unwrap();
    assert!(matches!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    let before = snapshot(dir.path());

    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let segment = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let copies = segment
            .rows
            .iter()
            .filter(|row| row.cf == CATALOG_CF && row.key == key_bytes && row.sequence == 2)
            .collect::<Vec<_>>();
        assert_eq!(copies.len(), 2);
        for (index, (row, expected)) in copies.iter().zip([&first_entry, &second_entry]).enumerate()
        {
            assert_eq!(
                row.source,
                SegmentSource {
                    level: index as u32,
                    id: index as u64 + 1,
                    manifest_ordinal: index,
                }
            );
            assert_eq!((row.block_offset, row.row_ordinal), locations[index]);
            assert_eq!(
                row.classification,
                PhysicalRowClass::BoundProtected(ProtectedRole::Catalog)
            );
            let expected_value = match &expected.version.value {
                StoredValue::Put(bytes) => ObservedSegmentValue::Put(bytes.clone()),
                StoredValue::BlobPointer(pointer) => ObservedSegmentValue::Pointer {
                    pointer: pointer.clone(),
                    expires_at_ms: None,
                },
                other => panic!("Name copy has an unexpected wire operation: {other:?}"),
            };
            assert_eq!(row.value, expected_value);
        }
        let mut probe = ValueFileScanProbe::default();
        let value = collect_value_witness(root, &manifest, &segment.rows, budget, &mut probe)
            .expect("mixed writer-framed Name pointer must authenticate");
        assert_eq!(value.files.len(), 1);
        assert_eq!(value.extents.len(), 1);
        assert_eq!(probe.proof_full_file_hashes, 1);
        let file = &value.files[0];
        assert_eq!(file.path.as_path(), value_path.as_path());
        assert_eq!(file.len, value_raw.len() as u64);
        assert_eq!(file.digest, value_digest);
        assert_eq!(
            file.identity,
            physical_id(&File::open(&value_path).unwrap(), &value_path).unwrap()
        );
        let external_index = if first_external { 0 } else { 1 };
        let external_row = copies[external_index];
        let extent = &value.extents[0];
        assert_eq!(extent.file_id, file.id);
        assert_eq!(
            extent.locator,
            ValueRowLocator {
                source: external_row.source,
                block_offset: external_row.block_offset,
                row_ordinal: external_row.row_ordinal,
            }
        );
        assert_ne!(
            extent.locator,
            ValueRowLocator {
                source: copies[1 - external_index].source,
                block_offset: copies[1 - external_index].block_offset,
                row_ordinal: copies[1 - external_index].row_ordinal,
            }
        );
        assert_eq!(
            (extent.offset, extent.len, extent.checksum),
            (pointer.offset, pointer.len, pointer.checksum)
        );
        value.discard(root, budget).unwrap();
        segment.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);

        let error = match collect_protected_copy_ledger(root, &manifest, budget) {
            Err(error) => error,
            Ok(candidate) => {
                candidate.discard(root, budget).unwrap();
                panic!("mixed Name pair unexpectedly reached a private candidate")
            }
        };
        assert_eq!(
            budget.remaining_bytes(),
            balance,
            "refusal must refund exactly"
        );
        assert_eq!(snapshot(dir.path()), before, "refusal must not edit files");
        if conflicting {
            match error {
                PraxisError::Corrupt { reason, .. }
                    if reason == "protected physical-copy actual bytes conflict" => {}
                other => panic!("valid mixed Name bytes must conflict: {other:?}"),
            }
        } else {
            assert!(matches!(
                error,
                PraxisError::UnsupportedCatalogFeature {
                    feature: "protected physical-copy bytes await authenticated replay"
                }
            ));
        }

        match collect_protected_copy_admission(root, &manifest, budget) {
            Ok(candidate) if !conflicting => {
                let ledger = candidate
                    .consume()
                    .expect("equal mixed Name copies must survive consumption fences");
                assert_eq!(ledger.segment_witnesses().len(), 2);
                let admitted = ledger
                    .copies()
                    .filter(|copy| {
                        copy.cf == CATALOG_CF
                            && copy.key == key_bytes.as_slice()
                            && copy.sequence == 2
                    })
                    .collect::<Vec<_>>();
                assert_eq!(admitted.len(), 2);
                for (index, copy) in admitted.iter().enumerate() {
                    assert_eq!(
                        copy.source,
                        SegmentSource {
                            level: index as u32,
                            id: index as u64 + 1,
                            manifest_ordinal: index,
                        }
                    );
                    assert_eq!((copy.block_offset, copy.row_ordinal), locations[index]);
                    assert_eq!(
                        copy.operation,
                        if [first_external, !first_external][index] {
                            CopyWireOperation::Pointer { len: pointer.len }
                        } else {
                            CopyWireOperation::Put {
                                len: original_bytes.len() as u64,
                            }
                        }
                    );
                }
                drop(admitted);
                drop(ledger);
            }
            Err(PraxisError::Corrupt { reason, .. }) if conflicting => {
                assert_eq!(reason, "protected physical-copy actual bytes conflict");
            }
            Ok(candidate) => {
                drop(candidate);
                panic!("changed mixed Name copies reached a private candidate");
            }
            Err(error) => panic!("mixed Name candidate failed at the wrong gate: {error:?}"),
        }
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn writer_inline_then_external_catalog_name_equal_reaches_private_gate() {
    writer_mixed_catalog_name_pair_case(false, false);
}

#[test]
fn writer_inline_then_external_catalog_name_valid_conflict_requires_corrupt() {
    writer_mixed_catalog_name_pair_case(false, true);
}

#[test]
fn writer_external_then_inline_catalog_name_equal_reaches_private_gate() {
    writer_mixed_catalog_name_pair_case(true, false);
}

#[test]
fn writer_external_then_inline_catalog_name_valid_conflict_requires_corrupt() {
    writer_mixed_catalog_name_pair_case(true, true);
}

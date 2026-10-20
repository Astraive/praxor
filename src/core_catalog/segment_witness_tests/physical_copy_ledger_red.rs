use super::*;
use crate::core_catalog::physical_copy::{
    admit_protected_physical_copies, collect_protected_copy_ledger,
};
use crate::core_records::codec::{
    Decision as RecordDecision, Key as RecordKey, Role as RecordRole, Row as RecordRow,
};
use crate::segments::format::SEGMENT_FOOTER_MAGIC;

const FIXED_ORACLE: &str = include_str!("../../../tests/fixtures/catalog_v4_wal_oracle.json");

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

        // Expected compiling RED: only the new private ledger Unsupported
        // remains after the bounded visitor, witness and public-fence checks.
        let balance = budget.remaining_bytes();
        let result =
            admit_protected_physical_copies(root, &manifest, &observed, &witnesses, budget);
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);
        let ledger = match result {
            Ok(ledger) => ledger,
            Err(PraxisError::UnsupportedCatalogFeature {
                feature: "protected physical-copy ledger not implemented",
            }) => {
                panic!("RED: the private physical-copy ledger has not admitted valid Head@2 copies")
            }
            Err(other) => panic!("unexpected private copy-ledger error: {other:?}"),
        };
        assert_eq!(ledger.segment_witnesses.len(), 2);
        let head_copies = ledger
            .copies
            .iter()
            .filter(|copy| copy.cf == CATALOG_CF && copy.key == head_key && copy.sequence == 2)
            .collect::<Vec<_>>();
        assert_eq!(head_copies.len(), 2);
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
    });
}

#[derive(Clone, Copy)]
enum NextCopyCase {
    IdenticalAllocator,
    ConflictingHead,
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
        let result =
            admit_protected_physical_copies(root, &fixture.manifest, &observed, &witnesses, budget);
        match case {
            NextCopyCase::IdenticalAllocator => {
                let ledger = match result {
                    Ok(ledger) => ledger,
                    Err(PraxisError::UnsupportedCatalogFeature {
                        feature: "protected physical-copy ledger not implemented",
                    }) => panic!("RED: valid Allocator@1 copies await private copy admission"),
                    Err(other) => panic!("unexpected allocator copy-ledger error: {other:?}"),
                };
                // A correct future candidate may retain a charged receipt until
                // its explicit discard/consume API exists; it cannot mint budget.
                assert!(budget.remaining_bytes() <= balance);
                assert_eq!(ledger.segment_witnesses.len(), 2);
                let admitted = ledger
                    .copies
                    .iter()
                    .filter(|row| {
                        row.cf == fixture.original.cf.0
                            && row.key.as_slice() == fixture.original.key.as_ref()
                            && row.sequence == 1
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
            }
            NextCopyCase::ConflictingHead => match result {
                Err(PraxisError::Corrupt { reason, .. }) => {
                    assert!(reason.contains("copy"), "wrong ledger rejection: {reason}");
                    assert_eq!(
                        budget.remaining_bytes(),
                        balance,
                        "refusal must refund exactly"
                    );
                }
                Err(PraxisError::UnsupportedCatalogFeature {
                    feature: "protected physical-copy ledger not implemented",
                }) => {
                    panic!("RED: equal-length, rechecksummed Head@2 conflict awaits ledger Corrupt")
                }
                Err(other) => panic!("unexpected conflicting-copy error: {other:?}"),
                Ok(_) => panic!("ledger admitted rechecksummed conflicting Head@2 copies"),
            },
        }
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
    let first_group = [
        row_in(head_cf, &head_key, 2, StoredValue::Put(first_value.clone())),
        row_in(head_cf, &head_key, 2, StoredValue::Put(last_value.clone())),
    ];
    let second_group = match case {
        OrderedHeadGroupCase::Identical => first_group.clone(),
        OrderedHeadGroupCase::Reordered => [first_group[1].clone(), first_group[0].clone()],
        OrderedHeadGroupCase::ChangedLastMember => [
            first_group[0].clone(),
            row_in(head_cf, &head_key, 2, StoredValue::Put(changed_last)),
        ],
    };

    let write_group = |level: u32, id: u64, rows: &[SegmentEntry; 2]| {
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
        assert_eq!(meta.entries, 2);
        assert_eq!(meta.path, path.to_str().unwrap());
        assert_eq!(meta.file_digest, blake3::hash(&bytes).to_hex().to_string());
        let decoded = decode_segment(&bytes, path, &CpuAccelerator).unwrap();
        assert_eq!((decoded.level, decoded.id), (level, id));
        assert_eq!(
            decoded.blocks.len(),
            2,
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
        assert_eq!(observed.len(), 11);
        let head_rows = observed
            .iter()
            .filter(|row| row.cf == head_cf && row.key == head_key && row.sequence == 2)
            .collect::<Vec<_>>();
        assert_eq!(head_rows.len(), 4);
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
            assert_eq!(witness.observed_rows, 2);
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
            assert_eq!(group.len(), 2);
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
        let result = collect_protected_copy_ledger(root, &manifest, budget);
        match case {
            OrderedHeadGroupCase::Identical => {
                let candidate = match result {
                    Ok(candidate) => candidate,
                    Err(PraxisError::UnsupportedCatalogFeature {
                        feature: "protected physical-copy bytes await authenticated replay",
                    }) => panic!("RED: exact ordered Head groups await physical-copy replay"),
                    Err(other) => panic!("exact Head groups must be admitted: {other:?}"),
                };
                candidate.discard(root, budget).unwrap();
            }
            OrderedHeadGroupCase::Reordered | OrderedHeadGroupCase::ChangedLastMember => {
                match result {
                    Err(PraxisError::Corrupt { reason, .. }) => {
                        assert!(reason.contains("copy") || reason.contains("group"));
                    }
                    Err(PraxisError::UnsupportedCatalogFeature {
                        feature: "protected physical-copy bytes await authenticated replay",
                    }) => panic!("RED: conflicting full Head groups await physical comparison"),
                    other => panic!("conflicting full Head groups must be Corrupt: {other:?}"),
                }
            }
        }
        assert_eq!(budget.remaining_bytes(), balance);
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

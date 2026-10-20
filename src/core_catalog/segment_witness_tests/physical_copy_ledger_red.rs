use super::*;
use crate::core_catalog::physical_copy::admit_protected_physical_copies;
use crate::segments::format::SEGMENT_FOOTER_MAGIC;

const FIXED_ORACLE: &str = include_str!("../../../tests/fixtures/catalog_v4_wal_oracle.json");

fn oracle_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    hex.as_bytes()
        .chunks_exact(2)
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

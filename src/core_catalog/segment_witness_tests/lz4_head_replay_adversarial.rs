use super::*;
use crate::core_catalog::segment_witness::{
    CopyReplayWork, ExpectedLiteralPut, PhysicalRowLocator, ProtectedSegmentCandidate,
    recheck_all_copy_replay_witnesses, with_authenticated_literal_put,
};

struct Lz4HeadFixture {
    lease: WriterLease,
    manifest: Manifest,
    candidate: ProtectedSegmentCandidate,
    budget: PhysicalWitnessBudget,
    before: BTreeMap<PathBuf, TreeEntry>,
    baseline: usize,
    expected_head: Vec<u8>,
    dir: tempfile::TempDir,
}

impl Lz4HeadFixture {
    fn new() -> Self {
        let (dir, config, lease) = flushed_create_fixture();
        let root = lease.root();
        let layout = DiskLayout::at(root);
        let path = layout.segment_path(0, 1);
        let original_bytes = fs::read(&path).unwrap();
        let original = decode_segment(&original_bytes, &path, &CpuAccelerator).unwrap();
        assert_eq!(original.blocks.iter().map(Vec::len).sum::<usize>(), 7);
        let rows = original
            .blocks
            .iter()
            .flatten()
            .map(|raw| {
                assert!(raw.blob_expiry.is_none());
                raw.entry.clone()
            })
            .collect::<Vec<_>>();
        let key = CatalogKey::Head.encode().unwrap();
        let original_head = rows
            .iter()
            .find(|row| {
                row.cf.0 == CATALOG_CF
                    && row.key.as_ref() == key.as_slice()
                    && row.version.sequence == 2
            })
            .unwrap()
            .clone();
        let StoredValue::Put(expected_head) = &original_head.version.value else {
            panic!("writer Head@2 must be a plain Put")
        };
        let expected_head = expected_head.clone();
        assert_eq!(expected_head.len(), 48);
        assert!(matches!(
            CatalogValue::decode(&CatalogKey::Head, &expected_head, &path).unwrap(),
            CatalogValue::Head(Head { revision: 2, .. })
        ));

        let manifest = rewrite_first_segment(
            root,
            rows,
            Compression::Lz4,
            config.large_value_threshold,
            config.block_size,
        );
        let manifest_path = layout.manifest_path();
        manifest.validate_v4(&manifest_path).unwrap();
        assert_eq!(manifest.segments.len(), 1);
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes[8], 1, "writer must emit LZ4");
        assert_eq!(
            manifest.segments[0].file_digest,
            blake3::hash(&bytes).to_hex().to_string()
        );
        let parsed = decode_segment(&bytes, &path, &CpuAccelerator).unwrap();
        assert_eq!(parsed.compression, Compression::Lz4);
        assert_eq!(parsed.blocks.len(), 1);
        assert_eq!(parsed.blocks[0].len(), 7);
        let (encoded, decoded_len, checksum) = writer_block_frame(&bytes, 21);
        assert_eq!(crc32c(encoded), checksum);
        let decoded = decode_block(Compression::Lz4, encoded).unwrap();
        assert_eq!(decoded.len() as u64, decoded_len);
        assert_eq!(decode_entries(&decoded, &path).unwrap().len(), 7);
        let compressed_head = parsed.blocks[0]
            .iter()
            .find(|row| {
                row.entry.cf.0 == CATALOG_CF
                    && row.entry.key.as_ref() == key.as_slice()
                    && row.entry.version.sequence == 2
            })
            .unwrap();
        assert_eq!(compressed_head.entry, original_head);

        let cut = WalCut {
            flushed_sequence: manifest.flushed_sequence,
            last_sequence: manifest.last_sequence,
            flushed_wal_id: manifest.flushed_wal_id,
            active_wal_id: manifest.active_wal_id,
            next_wal_id: manifest.next_wal_id,
        };
        let (wals, mut budget) = scan_v4_wals_with_budget(root, cut, |_, _, _, _| Ok(())).unwrap();
        assert_eq!(wals.len(), 1);
        let baseline = budget.remaining_bytes();
        let candidate = collect_protected_segment_candidate(root, &manifest, &mut budget).unwrap();
        assert_eq!(candidate.witnesses.len(), 1);
        assert_eq!(candidate.rows.len(), 7);
        let (head, witness) = selected_head(&candidate);
        assert_eq!(head.block_offset, 21);
        assert_eq!(head.value, ObservedSegmentValue::Put(expected_head.clone()));
        assert_eq!(witness.path, path);
        assert_eq!(witness.len, bytes.len() as u64);
        assert_eq!(witness.digest, blake3::hash(&bytes));
        assert_eq!(witness.observed_rows, 7);
        assert_eq!(
            witness.identity,
            physical_id(&File::open(&path).unwrap(), &path).unwrap()
        );
        let before = snapshot(dir.path());
        Self {
            lease,
            manifest,
            candidate,
            budget,
            before,
            baseline,
            expected_head,
            dir,
        }
    }

    fn finish(self) {
        let Self {
            lease,
            candidate,
            mut budget,
            baseline,
            dir,
            ..
        } = self;
        candidate.discard(lease.root(), &mut budget).unwrap();
        assert_eq!(budget.remaining_bytes(), baseline);
        drop(lease);
        drop(dir);
    }
}

fn selected_head(
    candidate: &ProtectedSegmentCandidate,
) -> (&ObservedSegmentRow, &SegmentFileWitness) {
    let key = CatalogKey::Head.encode().unwrap();
    let row = candidate
        .rows
        .iter()
        .find(|row| {
            row.cf == CATALOG_CF && row.key.as_slice() == key.as_slice() && row.sequence == 2
        })
        .unwrap();
    let witness = candidate
        .witnesses
        .iter()
        .find(|witness| witness.source == row.source)
        .unwrap();
    (row, witness)
}

#[test]
fn writer_lz4_head_wrong_block_and_row_locator_refund_without_callback() {
    let mut fixture = Lz4HeadFixture::new();
    let root = fixture.lease.root();
    let (head, witness) = selected_head(&fixture.candidate);
    let exact = PhysicalRowLocator {
        source: head.source,
        block_offset: head.block_offset,
        row_ordinal: head.row_ordinal,
    };
    let expected = ExpectedLiteralPut {
        cf: &head.cf,
        key: &head.key,
        sequence: head.sequence,
    };
    let balance = fixture.budget.remaining_bytes();
    for (label, wrong) in [
        (
            "block",
            PhysicalRowLocator {
                block_offset: exact.block_offset + 1,
                ..exact
            },
        ),
        (
            "row",
            PhysicalRowLocator {
                row_ordinal: u32::MAX,
                ..exact
            },
        ),
    ] {
        let mut work = CopyReplayWork::production();
        let mut callbacks = 0;
        let error = with_authenticated_literal_put(
            root,
            &fixture.manifest,
            witness,
            wrong,
            expected,
            &mut work,
            &mut fixture.budget,
            |_| {
                callbacks += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(fixture.budget.remaining_bytes(), balance, "{label} refund");
        if matches!(
            &error,
            PraxisError::UnsupportedCatalogFeature {
                feature: "compressed physical-copy replay not implemented"
            }
        ) {
            panic!("RED: LZ4 Head exact {label} locator replay is missing");
        }
        assert!(
            matches!(&error, PraxisError::Corrupt { path, reason }
                if path == &witness.path && reason == "compressed Head exact row locator changed"),
            "wrong {label} locator returned {error}"
        );
        assert_eq!(callbacks, 0, "wrong {label} locator reached callback");
        assert_eq!(snapshot(fixture.dir.path()), fixture.before);
    }
    let mut fence_work = CopyReplayWork::production();
    let fence = recheck_all_copy_replay_witnesses(
        root,
        &fixture.manifest,
        &fixture.candidate.witnesses,
        &mut fence_work,
    )
    .unwrap();
    assert!(fence.confirms(&fixture.candidate.witnesses));
    assert_eq!(fixture.budget.remaining_bytes(), balance);
    fixture.finish();
}

#[test]
fn writer_lz4_head_callback_mutation_fails_same_handle_and_refunds() {
    let mut fixture = Lz4HeadFixture::new();
    let root = fixture.lease.root();
    let (head, witness) = selected_head(&fixture.candidate);
    let locator = PhysicalRowLocator {
        source: head.source,
        block_offset: head.block_offset,
        row_ordinal: head.row_ordinal,
    };
    let expected = ExpectedLiteralPut {
        cf: &head.cf,
        key: &head.key,
        sequence: head.sequence,
    };
    let path = witness.path.clone();
    let identity = witness.identity;
    let original = fs::read(&path).unwrap();
    let expected_bytes = fixture.expected_head.clone();
    let mut mutator = OpenOptions::new().write(true).open(&path).unwrap();
    let mut callbacks = 0;
    let mut work = CopyReplayWork::production();
    let balance = fixture.budget.remaining_bytes();
    let result = with_authenticated_literal_put(
        root,
        &fixture.manifest,
        witness,
        locator,
        expected,
        &mut work,
        &mut fixture.budget,
        |bytes| {
            callbacks += 1;
            assert_eq!(bytes, expected_bytes.as_slice());
            mutator.seek(SeekFrom::Start(0))?;
            mutator.write_all(&[original[0] ^ 1])?;
            mutator.sync_data()?;
            Ok(())
        },
    );
    let changed = fs::read(&path).unwrap();
    let changed_identity = physical_id(&File::open(&path).unwrap(), &path).unwrap();
    mutator.seek(SeekFrom::Start(0)).unwrap();
    mutator.write_all(&original[..1]).unwrap();
    mutator.sync_data().unwrap();
    drop(mutator);
    assert_eq!(fixture.budget.remaining_bytes(), balance);
    assert_eq!(snapshot(fixture.dir.path()), fixture.before);
    let error = result.unwrap_err();
    if matches!(
        &error,
        PraxisError::UnsupportedCatalogFeature {
            feature: "compressed physical-copy replay not implemented"
        }
    ) {
        panic!("RED: LZ4 Head callback-time same-handle replay is missing");
    }
    assert_eq!(callbacks, 1);
    assert_ne!(changed, original);
    assert_eq!(changed[0], original[0] ^ 1);
    assert_eq!(changed_identity, identity);
    assert_eq!(
        physical_id(&File::open(&path).unwrap(), &path).unwrap(),
        identity
    );
    assert!(
        matches!(&error, PraxisError::Corrupt { path: error_path, reason }
            if error_path == &path && reason == "compressed Head same-handle recheck failed"),
        "callback mutation returned {error}"
    );
    let mut fence_work = CopyReplayWork::production();
    let fence = recheck_all_copy_replay_witnesses(
        root,
        &fixture.manifest,
        &fixture.candidate.witnesses,
        &mut fence_work,
    )
    .unwrap();
    assert!(fence.confirms(&fixture.candidate.witnesses));
    assert_eq!(fixture.budget.remaining_bytes(), balance);
    fixture.finish();
}

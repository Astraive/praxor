use super::*;
use crate::core_catalog::physical_copy::{
    collect_protected_copy_admission, collect_protected_copy_ledger,
};

#[derive(Clone, Copy, Debug)]
enum HeadAdmissionEdge {
    SequenceZero,
    BeyondFlushed,
    PutWithExpiry,
    Merge,
    Delete,
}

impl HeadAdmissionEdge {
    fn reason(self) -> &'static str {
        match self {
            Self::SequenceZero | Self::BeyondFlushed => {
                "protected copy sequence is outside the installed cut"
            }
            Self::PutWithExpiry | Self::Merge => "protected copy has an invalid wire operation",
            Self::Delete => "catalog copy has forbidden Delete",
        }
    }
}

fn writer_head_admission_edge(case: HeadAdmissionEdge) {
    let (dir, config, lease) = flushed_create_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let segment_path = layout.segment_path(0, 1);
    let manifest_path = layout.manifest_path();
    let original_manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    assert_eq!(
        (
            original_manifest.flushed_sequence,
            original_manifest.last_sequence
        ),
        (2, 2)
    );
    assert_eq!(original_manifest.segments.len(), 1);
    assert_eq!(original_manifest.segments[0].entries, 7);
    let original_bytes = fs::read(&segment_path).unwrap();
    assert_eq!(
        original_manifest.segments[0].file_digest,
        blake3::hash(&original_bytes).to_hex().to_string()
    );
    let original = decode_segment(&original_bytes, &segment_path, &CpuAccelerator).unwrap();
    let mut rows = original
        .blocks
        .into_iter()
        .flatten()
        .map(|raw| raw.entry)
        .collect::<Vec<_>>();
    let head_key = CatalogKey::Head.encode().unwrap();
    assert_eq!(
        rows.iter()
            .filter(|row| row.cf.0 == CATALOG_CF && row.key.as_ref() == head_key.as_slice())
            .count(),
        1
    );
    let head = rows
        .iter_mut()
        .find(|row| row.cf.0 == CATALOG_CF && row.key.as_ref() == head_key.as_slice())
        .unwrap();
    assert_eq!(head.version.sequence, 2);
    let StoredValue::Put(valid_head_bytes) = &head.version.value else {
        panic!("CREATE Head@2 must start as a writer-produced literal Put")
    };
    assert_eq!(valid_head_bytes.len(), 48);
    assert!(matches!(
        CatalogValue::decode(&CatalogKey::Head, valid_head_bytes, root),
        Ok(CatalogValue::Head(_))
    ));
    let valid_head_bytes = valid_head_bytes.clone();
    match case {
        HeadAdmissionEdge::SequenceZero => head.version.sequence = 0,
        HeadAdmissionEdge::BeyondFlushed => {
            head.version.sequence = original_manifest.flushed_sequence + 1;
        }
        HeadAdmissionEdge::PutWithExpiry => {
            head.version.value = StoredValue::PutWithExpiry {
                value: valid_head_bytes,
                expires_at_ms: 73,
            };
        }
        HeadAdmissionEdge::Merge => head.version.value = StoredValue::Merge(valid_head_bytes),
        HeadAdmissionEdge::Delete => head.version.value = StoredValue::Delete,
    }
    let changed_head = head.clone();

    // Re-encode all seven rows through the real segment writer with one row
    // per literal block; no raw test patch can bypass its CRC or footer.
    let manifest = rewrite_first_segment(root, rows, Compression::None, usize::MAX, 1);
    manifest.validate_v4(root).unwrap();
    assert_eq!((manifest.flushed_sequence, manifest.last_sequence), (2, 2));
    assert_eq!(manifest.segments.len(), 1);
    assert_eq!(manifest.segments[0].entries, 7);
    let file = fs::read(&segment_path).unwrap();
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&file).to_hex().to_string()
    );
    let decoded = decode_segment(&file, &segment_path, &CpuAccelerator).unwrap();
    assert_eq!((decoded.level, decoded.id), (0, 1));
    assert_eq!(decoded.blocks.len(), 7);
    assert!(decoded.blocks.iter().all(|block| block.len() == 1));
    let mut offsets = Vec::new();
    let mut offset = 21_u64;
    for _ in &decoded.blocks {
        let (payload, decoded_len, checksum) = writer_block_frame(&file, offset);
        assert_eq!(decoded_len, payload.len() as u64);
        assert_eq!(crc32c(payload), checksum);
        offsets.push(offset);
        offset += 12 + payload.len() as u64;
    }
    let physical_heads = decoded
        .blocks
        .iter()
        .enumerate()
        .filter(|(_, block)| {
            let row = &block[0].entry;
            row.cf.0 == CATALOG_CF && row.key.as_ref() == head_key.as_slice()
        })
        .collect::<Vec<_>>();
    assert_eq!(physical_heads.len(), 1);
    let (head_block, block) = physical_heads[0];
    assert_eq!(block[0].entry, changed_head);
    assert!(block[0].blob_expiry.is_none(), "the edge must stay inline");
    let expected_offset = offsets[head_block];
    let expected_source = SegmentSource {
        level: 0,
        id: 1,
        manifest_ordinal: 0,
    };
    let expected_identity =
        physical_id(&File::open(&segment_path).unwrap(), &segment_path).unwrap();
    let expected_value = match &changed_head.version.value {
        StoredValue::Put(bytes) => ObservedSegmentValue::Put(bytes.clone()),
        StoredValue::PutWithExpiry {
            value,
            expires_at_ms,
        } => ObservedSegmentValue::PutWithExpiry {
            value: value.clone(),
            expires_at_ms: *expires_at_ms,
        },
        StoredValue::Merge(bytes) => ObservedSegmentValue::Merge(bytes.clone()),
        StoredValue::Delete => ObservedSegmentValue::Delete,
        StoredValue::BlobPointer(_) => unreachable!("writer edge must be inline"),
    };
    let before = snapshot(dir.path());

    // The public narrow owner is never a fallback when the private ledger
    // refuses an installed physical row.
    assert!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator).is_err(),
        "{case:?} cannot grant a public owner"
    );
    assert_eq!(snapshot(dir.path()), before);
    with_wal_budget(root, &manifest, |budget| {
        let mut observed = Vec::new();
        let witnesses = visit_v4_segments(root, &manifest, budget, |row| {
            observed.push(row);
            Ok(())
        })
        .expect("writer segment must survive bounded authenticated visitation");
        assert_eq!(witnesses.len(), 1);
        assert_eq!(witnesses[0].source, expected_source);
        assert_eq!(witnesses[0].path, segment_path);
        assert_eq!(witnesses[0].len, file.len() as u64);
        assert_eq!(witnesses[0].digest, blake3::hash(&file));
        assert_eq!(witnesses[0].identity, expected_identity);
        assert_eq!(witnesses[0].observed_rows, 7);
        assert_eq!(observed.len(), 7);
        let seen = observed
            .iter()
            .filter(|row| row.cf == CATALOG_CF && row.key == head_key)
            .collect::<Vec<_>>();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].source, expected_source);
        assert_eq!(
            (seen[0].block_offset, seen[0].row_ordinal),
            (expected_offset, 0)
        );
        assert_eq!(
            seen[0].classification,
            PhysicalRowClass::BoundProtected(ProtectedRole::Catalog)
        );
        assert_eq!(seen[0].sequence, changed_head.version.sequence);
        assert_eq!(seen[0].value, expected_value);
        assert_eq!(snapshot(dir.path()), before);

        let balance = budget.remaining_bytes();
        let candidate_error = match collect_protected_copy_admission(root, &manifest, budget) {
            Err(error) => error,
            Ok(candidate) => {
                drop(candidate);
                panic!("{case:?} unexpectedly exposed a private candidate")
            }
        };
        match candidate_error {
            PraxisError::Corrupt { path, reason } => {
                assert_eq!(path.as_path(), root);
                assert_eq!(reason, case.reason(), "{case:?}");
            }
            other => panic!("{case:?} must be Corrupt at private admission: {other:?}"),
        }
        assert_eq!(
            budget.remaining_bytes(),
            balance,
            "{case:?} candidate refund"
        );
        assert_eq!(snapshot(dir.path()), before);

        let ledger_error = match collect_protected_copy_ledger(root, &manifest, budget) {
            Err(error) => error,
            Ok(ledger) => {
                ledger.discard(root, budget).unwrap();
                panic!("{case:?} unexpectedly exposed a private ledger")
            }
        };
        match ledger_error {
            PraxisError::Corrupt { path, reason } => {
                assert_eq!(path.as_path(), root);
                assert_eq!(reason, case.reason(), "{case:?}");
            }
            other => panic!("{case:?} must be Corrupt at private ledger: {other:?}"),
        }
        assert_eq!(budget.remaining_bytes(), balance, "{case:?} ledger refund");
        assert_eq!(snapshot(dir.path()), before);
    });
    assert!(inspect_v4_owner(&lease, &config, &CpuAccelerator).is_err());
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn writer_head_s0_refuses_private_admission_and_refunds() {
    writer_head_admission_edge(HeadAdmissionEdge::SequenceZero);
}

#[test]
fn writer_head_above_flushed_cut_refuses_private_admission_and_refunds() {
    writer_head_admission_edge(HeadAdmissionEdge::BeyondFlushed);
}

#[test]
fn writer_head_expiry_refuses_private_admission_and_refunds() {
    writer_head_admission_edge(HeadAdmissionEdge::PutWithExpiry);
}

#[test]
fn writer_head_merge_refuses_private_admission_and_refunds() {
    writer_head_admission_edge(HeadAdmissionEdge::Merge);
}

#[test]
fn writer_head_tombstone_refuses_private_admission_and_refunds() {
    writer_head_admission_edge(HeadAdmissionEdge::Delete);
}

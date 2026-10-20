use super::*;
use crate::core_catalog::value_witness::{
    ValueFileScanProbe as ValueFileScanProbeRed,
    collect_value_witness as collect_value_witness_red,
    recheck_value_witness as recheck_value_witness_red,
};

fn catalog_pointer<'a>(rows: &'a [ObservedSegmentRow], key: &[u8]) -> &'a ValuePointer {
    let row = rows
        .iter()
        .find(|row| row.cf == CATALOG_CF && row.key == key)
        .expect("writer-produced catalog row must be staged");
    assert_eq!(
        row.classification,
        PhysicalRowClass::BoundProtected(ProtectedRole::Catalog)
    );
    let ObservedSegmentValue::Pointer {
        pointer,
        expires_at_ms: None,
    } = &row.value
    else {
        panic!("writer-produced catalog row must have a nonexpiring value pointer")
    };
    pointer
}

fn expected_extents(
    rows: &[ObservedSegmentRow],
    path: &Path,
    bytes: &[u8],
) -> Vec<(u64, u64, u32, blake3::Hash)> {
    let mut expected = Vec::new();
    for row in rows {
        let ObservedSegmentValue::Pointer {
            pointer,
            expires_at_ms: None,
        } = &row.value
        else {
            continue;
        };
        assert_ne!(row.classification, PhysicalRowClass::Other);
        assert_eq!(Path::new(&pointer.path), path);
        let offset = usize::try_from(pointer.offset).unwrap();
        let len = usize::try_from(pointer.len).unwrap();
        let end = offset.checked_add(12).unwrap().checked_add(len).unwrap();
        assert!(end <= bytes.len());
        assert_eq!(
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()),
            pointer.len
        );
        assert_eq!(
            u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()),
            pointer.checksum
        );
        let payload = &bytes[offset + 12..end];
        assert_eq!(crc32c(payload), pointer.checksum);
        expected.push((
            pointer.offset,
            pointer.len,
            pointer.checksum,
            blake3::hash(payload),
        ));
    }
    expected.sort_by_key(|extent| extent.0);
    assert!(expected.len() >= 2);
    assert!(expected.windows(2).all(|pair| {
        pair[0]
            .0
            .checked_add(12)
            .unwrap()
            .checked_add(pair[0].1)
            .unwrap()
            <= pair[1].0
    }));
    expected
}

fn assert_unsupported_seam(error: &PraxisError) {
    assert!(
        matches!(
            error,
            PraxisError::UnsupportedCatalogFeature {
                feature: "external value-file and extent witness is not implemented"
            }
        ),
        "the writer-produced fixture failed before the intended witness seam: {error}"
    );
}

#[test]
fn private_value_file_witnesses_head_and_near_cap_schema_as_distinct_extents_in_one_scan() {
    let (dir, lease, manifest, schema_key, expected_schema) = writer_catalog_external_fixture(
        CatalogKey::Schema(CollectionId::new(2).unwrap()),
        Some(schema_value_at_limit(true)),
        33_946,
    );
    let root = lease.root();
    let value_path = DiskLayout::at(root).value_log_path(1);
    assert!(1 < manifest.next_segment_id);
    assert_eq!(manifest.segments.len(), 1);
    let before = snapshot(dir.path());

    let mut config = PraxisConfig::new(root);
    config.compression = Compression::None;
    config.large_value_threshold = 11;
    config.validate().unwrap();
    assert_eq!(manifest.effective_config, config.persisted());
    let owner_result = inspect_v4_owner(&lease, &config, &CpuAccelerator);
    assert!(
        matches!(&owner_result, Err(PraxisError::Corrupt { .. })),
        "external value fixture unexpectedly admitted or changed owner fence: {owner_result:?}"
    );
    assert_eq!(snapshot(dir.path()), before);

    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let segments = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let segment_balance = budget.remaining_bytes();
        assert!(segment_balance < balance);
        assert_eq!(segments.witnesses.len(), 1);

        let head = catalog_pointer(&segments.rows, &[0]);
        let schema = catalog_pointer(&segments.rows, &schema_key);
        assert_eq!(head.len, 48);
        assert_eq!(schema.len, expected_schema.len() as u64);
        assert_ne!(head.offset, schema.offset);
        assert_eq!(Path::new(&head.path), value_path);
        assert_eq!(Path::new(&schema.path), value_path);

        let value_file = fs::read(&value_path).unwrap();
        let expected = expected_extents(&segments.rows, &value_path, &value_file);
        let schema_offset = usize::try_from(schema.offset).unwrap();
        assert_eq!(
            &value_file[schema_offset + 12..schema_offset + 12 + expected_schema.len()],
            expected_schema.as_slice()
        );
        let opened = File::open(&value_path).unwrap();
        let expected_identity = physical_id(&opened, &value_path).unwrap();
        drop(opened);

        let mut probe = ValueFileScanProbeRed::default();
        let value_witness =
            match collect_value_witness_red(root, &manifest, &segments.rows, budget, &mut probe) {
                Ok(value_witness) => value_witness,
                Err(error) => {
                    assert_unsupported_seam(&error);
                    segments.discard(root, budget).unwrap();
                    assert_eq!(budget.remaining_bytes(), balance);
                    assert_eq!(snapshot(dir.path()), before);
                    panic!(
                        "writer-produced extents reached the unimplemented value witness: {error}"
                    );
                }
            };
        assert_eq!(probe.proof_full_file_hashes, 1);
        assert_eq!(value_witness.files.len(), 1);
        assert_eq!(
            value_witness.retained_bytes,
            segment_balance - budget.remaining_bytes()
        );
        assert!(value_witness.retained_bytes > 0);
        let file = &value_witness.files[0];
        assert_eq!(file.id, 1);
        assert_eq!(file.path, value_path);
        assert_eq!(file.identity, expected_identity);
        assert_eq!(file.len, value_file.len() as u64);
        assert_eq!(file.digest, blake3::hash(&value_file));
        assert_eq!(value_witness.extents.len(), expected.len());
        for (observed, &(offset, len, checksum, payload_digest)) in
            value_witness.extents.iter().zip(&expected)
        {
            assert_eq!(observed.file_id, 1);
            assert_eq!(observed.offset, offset);
            assert_eq!(observed.len, len);
            assert_eq!(observed.checksum, checksum);
            assert_eq!(observed.payload_digest, payload_digest);
        }
        recheck_value_witness_red(root, &manifest, &value_witness, &mut probe).unwrap();
        assert_eq!(probe.recheck_full_file_hashes, 1);
        assert_eq!(
            budget.remaining_bytes(),
            segment_balance - value_witness.retained_bytes
        );
        value_witness.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), segment_balance);
        segments.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
        assert_eq!(snapshot(dir.path()), before);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_value_file_rejects_normalized_path_aliases_before_scanning() {
    let (dir, lease, manifest, _, _) =
        writer_catalog_external_fixture(CatalogKey::Name("accounts"), None, 12);
    let root = lease.root();
    let value_path = DiskLayout::at(root).value_log_path(1);
    let canonical = value_path.to_str().unwrap();
    let parent = value_path.parent().unwrap().to_str().unwrap();
    let name = value_path.file_name().unwrap().to_str().unwrap();
    let sep = std::path::MAIN_SEPARATOR;
    let before = snapshot(dir.path());

    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let segments = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let segment_balance = budget.remaining_bytes();
        assert!(
            segments
                .rows
                .iter()
                .filter(|row| matches!(&row.value, ObservedSegmentValue::Pointer { .. }))
                .count()
                >= 2
        );

        // The writer's own spelling is accepted and leaves no retained debit.
        assert!(
            segments
                .rows
                .iter()
                .filter_map(|row| match &row.value {
                    ObservedSegmentValue::Pointer { pointer, .. } => Some(pointer.path.as_str()),
                    _ => None,
                })
                .all(|path| path == canonical)
        );
        let mut good_probe = ValueFileScanProbeRed::default();
        let good =
            collect_value_witness_red(root, &manifest, &segments.rows, budget, &mut good_probe)
                .unwrap();
        assert_eq!(good_probe.proof_full_file_hashes, 1);
        good.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), segment_balance);

        let aliases = [
            format!("{parent}{sep}{sep}{name}"),
            format!("{parent}{sep}.{sep}{name}"),
        ];
        for alias in aliases {
            assert_ne!(alias, canonical);
            for all_pointers in [true, false] {
                let mut aliased = segments.rows.clone();
                if all_pointers {
                    for row in &mut aliased {
                        if let ObservedSegmentValue::Pointer { pointer, .. } = &mut row.value {
                            pointer.path = alias.clone();
                        }
                    }
                } else {
                    let last = aliased
                        .iter_mut()
                        .rev()
                        .find_map(|row| match &mut row.value {
                            ObservedSegmentValue::Pointer { pointer, .. } => Some(pointer),
                            _ => None,
                        })
                        .unwrap();
                    last.path = alias.clone();
                }
                let mut probe = ValueFileScanProbeRed::default();
                let error =
                    collect_value_witness_red(root, &manifest, &aliased, budget, &mut probe)
                        .unwrap_err();
                assert!(matches!(error, PraxisError::Corrupt { .. }), "{error}");
                assert_eq!(probe.proof_full_file_hashes, 0);
                drop(aliased);
                assert_eq!(budget.remaining_bytes(), segment_balance);
                assert_eq!(snapshot(dir.path()), before);
            }
        }

        #[cfg(windows)]
        {
            let alias = format!("{parent}/{name}");
            assert_ne!(alias, canonical);
            let mut aliased = segments.rows.clone();
            for row in &mut aliased {
                if let ObservedSegmentValue::Pointer { pointer, .. } = &mut row.value {
                    pointer.path = alias.clone();
                }
            }
            let mut probe = ValueFileScanProbeRed::default();
            let error = collect_value_witness_red(root, &manifest, &aliased, budget, &mut probe)
                .unwrap_err();
            assert!(matches!(error, PraxisError::Corrupt { .. }), "{error}");
            assert_eq!(probe.proof_full_file_hashes, 0);
            drop(aliased);
            assert_eq!(budget.remaining_bytes(), segment_balance);
            assert_eq!(snapshot(dir.path()), before);
        }

        segments.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_value_file_recheck_rejects_same_length_change_in_unreferenced_tail() {
    let (dir, lease, manifest, _, _) =
        writer_catalog_external_fixture(CatalogKey::Name("accounts"), None, 12);
    let root = lease.root();
    let value_path = DiskLayout::at(root).value_log_path(1);
    let mut log = ValueLog::open(&value_path).unwrap();
    let tail = log.append(b"unused writer-produced tail").unwrap();
    drop(log);
    assert_eq!(Path::new(&tail.path), value_path);
    assert!(tail.len > 1);
    let original = fs::read(&value_path).unwrap();
    let before = snapshot(dir.path());

    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let segments = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let segment_balance = budget.remaining_bytes();
        let expected = expected_extents(&segments.rows, &value_path, &original);
        assert!(expected.iter().all(|(offset, len, _, _)| {
            offset
                .checked_add(12)
                .and_then(|end| end.checked_add(*len))
                .is_some_and(|end| end <= tail.offset)
        }));
        let mut probe = ValueFileScanProbeRed::default();
        let value_witness =
            match collect_value_witness_red(root, &manifest, &segments.rows, budget, &mut probe) {
                Ok(value_witness) => value_witness,
                Err(error) => {
                    assert_unsupported_seam(&error);
                    segments.discard(root, budget).unwrap();
                    assert_eq!(budget.remaining_bytes(), balance);
                    assert_eq!(snapshot(dir.path()), before);
                    panic!(
                        "writer-produced extents reached the unimplemented value witness: {error}"
                    );
                }
            };
        assert_eq!(probe.proof_full_file_hashes, 1);
        assert_eq!(value_witness.files.len(), 1);
        assert_eq!(value_witness.files[0].digest, blake3::hash(&original));
        assert_eq!(
            value_witness.retained_bytes,
            segment_balance - budget.remaining_bytes()
        );
        assert!(value_witness.retained_bytes > 0);
        recheck_value_witness_red(root, &manifest, &value_witness, &mut probe).unwrap();
        assert_eq!(probe.recheck_full_file_hashes, 1);

        let mutation_at = tail.offset + 12;
        let mut writer = OpenOptions::new().write(true).open(&value_path).unwrap();
        writer.seek(SeekFrom::Start(mutation_at)).unwrap();
        writer.write_all(b"U").unwrap();
        writer.flush().unwrap();
        drop(writer);
        let changed = fs::read(&value_path).unwrap();
        assert_eq!(changed.len(), original.len());
        assert_eq!(
            &changed[..usize::try_from(tail.offset).unwrap()],
            &original[..usize::try_from(tail.offset).unwrap()]
        );
        assert_ne!(blake3::hash(&changed), value_witness.files[0].digest);
        let changed_tree = snapshot(dir.path());
        let rechecked = recheck_value_witness_red(root, &manifest, &value_witness, &mut probe);
        assert!(matches!(rechecked, Err(PraxisError::Corrupt { .. })));
        assert_eq!(probe.recheck_full_file_hashes, 2);
        assert_eq!(snapshot(dir.path()), changed_tree);
        value_witness.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), segment_balance);
        segments.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);
    });
    assert_ne!(snapshot(dir.path()), before);
}

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

fn writer_two_file_catalog_external_fixture() -> (
    tempfile::TempDir,
    WriterLease,
    Manifest,
    Vec<u8>,
    Vec<u8>,
    ValuePointer,
    PraxisConfig,
) {
    let (dir, lease, mut manifest, schema_key, schema_bytes) = writer_catalog_external_fixture(
        CatalogKey::Schema(CollectionId::new(2).unwrap()),
        Some(schema_value_at_limit(true)),
        33_946,
    );
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let first_path = layout.value_log_path(1);
    let second_path = layout.value_log_path(2);
    let first_spelling = first_path.to_str().unwrap();
    let second_spelling = second_path.to_str().unwrap();
    let segment_path = layout.segment_path(0, 1);

    let mut second_log = ValueLog::open(&second_path).unwrap();
    let second_pointer = second_log.append(&schema_bytes).unwrap();
    drop(second_log);
    assert_eq!(second_pointer.path, second_spelling);
    assert_eq!(second_pointer.len, 33_946);
    assert_eq!(second_pointer.checksum, crc32c(&schema_bytes));
    let mut rows = decode_segment(
        &fs::read(&segment_path).unwrap(),
        &segment_path,
        &CpuAccelerator,
    )
    .unwrap()
    .blocks
    .into_iter()
    .flatten()
    .map(|raw| raw.entry)
    .collect::<Vec<_>>();
    assert_eq!(rows.len(), 7);
    let schema_row = rows
        .iter_mut()
        .find(|row| row.cf.0 == CATALOG_CF && row.key.as_ref() == schema_key.as_slice())
        .unwrap();
    let StoredValue::BlobPointer(original) = &schema_row.version.value else {
        panic!("the first writer must externalize Schema")
    };
    assert_eq!(original.path, first_spelling);
    assert_eq!(original.len, second_pointer.len);
    schema_row.version.value = StoredValue::BlobPointer(second_pointer.clone());

    let mut config = PraxisConfig::new(root);
    config.compression = Compression::None;
    config.large_value_threshold = 11;
    config.validate().unwrap();
    assert_eq!(manifest.effective_config, config.persisted());
    let mut first_log = ValueLog::open(&first_path).unwrap();
    let rewritten = SegmentWriter::write(
        SegmentWriteOptions {
            path: &segment_path,
            id: 1,
            level: 0,
            compression: Compression::None,
            accelerator: &CpuAccelerator,
            value_log: &mut first_log,
            large_value_threshold: config.large_value_threshold,
            block_size: config.block_size,
            partitioned_bloom: None,
            direct_io: false,
        },
        rows,
    )
    .unwrap();
    drop(first_log);
    manifest.segments[0] = rewritten;
    manifest.next_segment_id = 3;
    manifest = save_strict_manifest(root, &manifest);
    assert_eq!(manifest.segments.len(), 1);
    assert_eq!(manifest.segments[0].id, 1);
    assert!(2 < manifest.next_segment_id);
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&fs::read(&segment_path).unwrap())
            .to_hex()
            .to_string()
    );
    (
        dir,
        lease,
        manifest,
        schema_key,
        schema_bytes,
        second_pointer,
        config,
    )
}

#[test]
fn private_value_inventory_witnesses_two_writer_files_once_each() {
    let (dir, lease, manifest, schema_key, schema_bytes, second_pointer, config) =
        writer_two_file_catalog_external_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let first_path = layout.value_log_path(1);
    let second_path = layout.value_log_path(2);
    let first_spelling = first_path.to_str().unwrap();
    let second_spelling = second_path.to_str().unwrap();

    let first_bytes = fs::read(&first_path).unwrap();
    let second_bytes = fs::read(&second_path).unwrap();
    let second_offset = usize::try_from(second_pointer.offset).unwrap();
    assert_eq!(
        &second_bytes[second_offset + 12..second_offset + 12 + schema_bytes.len()],
        schema_bytes.as_slice()
    );
    let first_opened = File::open(&first_path).unwrap();
    let second_opened = File::open(&second_path).unwrap();
    let first_identity = physical_id(&first_opened, &first_path).unwrap();
    let second_identity = physical_id(&second_opened, &second_path).unwrap();
    assert_ne!(first_identity, second_identity);
    drop(first_opened);
    drop(second_opened);
    let before = snapshot(dir.path());

    let owner_result = inspect_v4_owner(&lease, &config, &CpuAccelerator);
    assert!(
        matches!(
            &owner_result,
            Err(PraxisError::UnsupportedCatalogFeature {
                feature: "v4 installed cut beyond narrow D0 bootstrap"
            })
        ),
        "the public owner admitted a private two-file fixture: {owner_result:?}"
    );
    assert_eq!(snapshot(dir.path()), before);

    with_wal_budget(root, &manifest, |budget| {
        let wal_balance = budget.remaining_bytes();
        let segments = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let segment_balance = budget.remaining_bytes();
        assert!(segment_balance < wal_balance);
        assert_eq!(segments.witnesses.len(), 1);
        let head = catalog_pointer(&segments.rows, &[0]);
        let schema = catalog_pointer(&segments.rows, &schema_key);
        assert_eq!(head.len, 48);
        assert_eq!(head.path, first_spelling);
        assert_eq!(schema, &second_pointer);

        let mut expected = Vec::new();
        for row in &segments.rows {
            let ObservedSegmentValue::Pointer {
                pointer,
                expires_at_ms: None,
            } = &row.value
            else {
                continue;
            };
            assert_ne!(row.classification, PhysicalRowClass::Other);
            let (id, bytes) = match pointer.path.as_str() {
                path if path == first_spelling => (1, first_bytes.as_slice()),
                path if path == second_spelling => (2, second_bytes.as_slice()),
                other => panic!("writer emitted a noncanonical value path: {other}"),
            };
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
                id,
                pointer.offset,
                pointer.len,
                pointer.checksum,
                blake3::hash(payload),
            ));
        }
        expected.sort_by_key(|extent| (extent.0, extent.1));
        assert!(expected.iter().filter(|extent| extent.0 == 1).count() >= 2);
        assert_eq!(expected.iter().filter(|extent| extent.0 == 2).count(), 1);
        assert!(expected.windows(2).all(|pair| {
            pair[0].0 != pair[1].0
                || pair[0]
                    .1
                    .checked_add(12)
                    .and_then(|end| end.checked_add(pair[0].2))
                    .is_some_and(|end| end <= pair[1].1)
        }));

        let mut probe = ValueFileScanProbeRed::default();
        let values =
            match collect_value_witness_red(root, &manifest, &segments.rows, budget, &mut probe) {
                Ok(values) => values,
                Err(error) => {
                    assert!(
                        matches!(
                            error,
                            PraxisError::UnsupportedCatalogFeature {
                                feature: "multiple referenced value files await the inventory cut"
                            }
                        ),
                        "the fixture failed before the intended multi-file seam: {error}"
                    );
                    assert_eq!(probe.proof_full_file_hashes, 0);
                    assert_eq!(budget.remaining_bytes(), segment_balance);
                    segments.discard(root, budget).unwrap();
                    assert_eq!(budget.remaining_bytes(), wal_balance);
                    assert_eq!(snapshot(dir.path()), before);
                    panic!("two writer-produced value files reached the inventory seam: {error}");
                }
            };
        assert_eq!(probe.proof_full_file_hashes, 2);
        assert_eq!(values.files.len(), 2);
        assert_eq!(
            values.retained_bytes,
            segment_balance - budget.remaining_bytes()
        );
        assert!(values.retained_bytes > 0);
        for (observed, (id, path, bytes, identity)) in values.files.iter().zip([
            (1, &first_path, &first_bytes, first_identity),
            (2, &second_path, &second_bytes, second_identity),
        ]) {
            assert_eq!(observed.id, id);
            assert_eq!(&observed.path, path);
            assert_eq!(observed.identity, identity);
            assert_eq!(observed.len, bytes.len() as u64);
            assert_eq!(observed.digest, blake3::hash(bytes));
        }
        assert_eq!(values.extents.len(), expected.len());
        for (observed, &(id, offset, len, checksum, payload_digest)) in
            values.extents.iter().zip(&expected)
        {
            assert_eq!(observed.file_id, id);
            assert_eq!(observed.offset, offset);
            assert_eq!(observed.len, len);
            assert_eq!(observed.checksum, checksum);
            assert_eq!(observed.payload_digest, payload_digest);
        }
        recheck_value_witness_red(root, &manifest, &values, &mut probe).unwrap();
        assert_eq!(probe.recheck_full_file_hashes, 2);
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
fn private_value_inventory_refunds_after_second_file_corruption() {
    #[derive(Clone, Copy, Debug)]
    enum Damage {
        Missing,
        ShortHeader,
        ShortPayload,
        HeaderLength,
        HeaderChecksum,
        Payload,
    }

    for damage in [
        Damage::Missing,
        Damage::ShortHeader,
        Damage::ShortPayload,
        Damage::HeaderLength,
        Damage::HeaderChecksum,
        Damage::Payload,
    ] {
        let (dir, lease, manifest, schema_key, schema_bytes, second_pointer, config) =
            writer_two_file_catalog_external_fixture();
        let root = lease.root();
        let layout = DiskLayout::at(root);
        let first_path = layout.value_log_path(1);
        let second_path = layout.value_log_path(2);
        assert_eq!(Path::new(&second_pointer.path), second_path);
        assert_eq!(second_pointer.len, schema_bytes.len() as u64);
        let intact_tree = snapshot(dir.path());

        let flip = |offset: u64| {
            let original = fs::read(&second_path).unwrap();
            let at = usize::try_from(offset).unwrap();
            assert!(at < original.len());
            let mut file = OpenOptions::new().write(true).open(&second_path).unwrap();
            file.seek(SeekFrom::Start(offset)).unwrap();
            file.write_all(&[original[at] ^ 1]).unwrap();
            file.flush().unwrap();
        };
        match damage {
            Damage::Missing => fs::remove_file(&second_path).unwrap(),
            Damage::ShortHeader => {
                OpenOptions::new()
                    .write(true)
                    .open(&second_path)
                    .unwrap()
                    .set_len(second_pointer.offset + 11)
                    .unwrap();
            }
            Damage::ShortPayload => {
                OpenOptions::new()
                    .write(true)
                    .open(&second_path)
                    .unwrap()
                    .set_len(second_pointer.offset + 12 + second_pointer.len - 1)
                    .unwrap();
            }
            Damage::HeaderLength => flip(second_pointer.offset),
            Damage::HeaderChecksum => flip(second_pointer.offset + 8),
            Damage::Payload => flip(second_pointer.offset + 12 + 16_384),
        }
        let damaged_tree = snapshot(dir.path());
        assert_ne!(damaged_tree, intact_tree, "{damage:?}");

        let owner_result = inspect_v4_owner(&lease, &config, &CpuAccelerator);
        assert!(
            matches!(
                &owner_result,
                Err(PraxisError::UnsupportedCatalogFeature {
                    feature: "v4 installed cut beyond narrow D0 bootstrap"
                }) | Err(PraxisError::Corrupt { .. })
            ),
            "the public owner admitted a damaged private fixture: {owner_result:?}"
        );
        assert_eq!(snapshot(dir.path()), damaged_tree, "{damage:?}");

        with_wal_budget(root, &manifest, |budget| {
            let wal_balance = budget.remaining_bytes();
            let segments = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
            let segment_balance = budget.remaining_bytes();
            assert!(segment_balance < wal_balance);
            assert_eq!(
                catalog_pointer(&segments.rows, &[0]).path,
                first_path.to_str().unwrap()
            );
            assert_eq!(
                catalog_pointer(&segments.rows, &schema_key),
                &second_pointer
            );

            let mut probe = ValueFileScanProbeRed::default();
            let error =
                collect_value_witness_red(root, &manifest, &segments.rows, budget, &mut probe)
                    .unwrap_err();
            assert!(
                matches!(&error, PraxisError::Corrupt { .. }),
                "{damage:?} failed before the value witness corruption path: {error}"
            );
            let PraxisError::Corrupt { path, .. } = &error else {
                unreachable!("the preceding assertion checked the error variant")
            };
            assert_eq!(path, &second_path, "{damage:?} must fail at file 2");
            assert_eq!(
                probe.proof_full_file_hashes,
                if matches!(damage, Damage::Missing) {
                    1
                } else {
                    2
                },
                "{damage:?} must reach the second file after witnessing the first"
            );
            assert_eq!(probe.recheck_full_file_hashes, 0);
            assert_eq!(budget.remaining_bytes(), segment_balance, "{damage:?}");
            segments.discard(root, budget).unwrap();
            assert_eq!(budget.remaining_bytes(), wal_balance, "{damage:?}");
            assert_eq!(snapshot(dir.path()), damaged_tree, "{damage:?}");
        });
        assert_eq!(snapshot(dir.path()), damaged_tree, "{damage:?}");
    }
}

fn assert_two_file_owner_remains_fenced(
    dir: &tempfile::TempDir,
    lease: &WriterLease,
    config: &PraxisConfig,
) {
    let before = snapshot(dir.path());
    let owner_result = inspect_v4_owner(lease, config, &CpuAccelerator);
    assert!(
        matches!(
            &owner_result,
            Err(PraxisError::UnsupportedCatalogFeature {
                feature: "v4 installed cut beyond narrow D0 bootstrap"
            })
        ),
        "the public owner admitted a private two-file fixture: {owner_result:?}"
    );
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn private_value_inventory_rejects_second_file_lexical_alias_before_any_scan() {
    let (dir, lease, manifest, schema_key, _, second_pointer, config) =
        writer_two_file_catalog_external_fixture();
    let root = lease.root();
    let second_path = DiskLayout::at(root).value_log_path(2);
    let parent = second_path.parent().unwrap().to_str().unwrap();
    let name = second_path.file_name().unwrap().to_str().unwrap();
    let sep = std::path::MAIN_SEPARATOR;
    let alias = format!("{parent}{sep}.{sep}{name}");
    assert_ne!(alias, second_pointer.path);
    assert_eq!(fs::read(&alias).unwrap(), fs::read(&second_path).unwrap());
    let before = snapshot(dir.path());
    assert_two_file_owner_remains_fenced(&dir, &lease, &config);

    with_wal_budget(root, &manifest, |budget| {
        let wal_balance = budget.remaining_bytes();
        let segments = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let segment_balance = budget.remaining_bytes();
        assert!(segment_balance < wal_balance);
        assert_eq!(
            catalog_pointer(&segments.rows, &schema_key),
            &second_pointer
        );
        let mut aliased = segments.rows.clone();
        let schema = aliased
            .iter_mut()
            .find(|row| row.cf == CATALOG_CF && row.key == schema_key)
            .unwrap();
        let ObservedSegmentValue::Pointer { pointer, .. } = &mut schema.value else {
            panic!("writer-produced Schema must retain a pointer")
        };
        pointer.path = alias.clone();

        let mut probe = ValueFileScanProbeRed::default();
        let error =
            collect_value_witness_red(root, &manifest, &aliased, budget, &mut probe).unwrap_err();
        assert!(matches!(&error, PraxisError::Corrupt { .. }), "{error}");
        assert_eq!(probe.proof_full_file_hashes, 0);
        assert_eq!(probe.recheck_full_file_hashes, 0);
        drop(aliased);
        assert_eq!(budget.remaining_bytes(), segment_balance);
        segments.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), wal_balance);
        assert_eq!(snapshot(dir.path()), before);
    });
    assert_eq!(snapshot(dir.path()), before);
}

fn assert_second_file_physical_alias_refused(mutate: impl FnOnce(&Path)) {
    let (dir, lease, manifest, schema_key, _, second_pointer, config) =
        writer_two_file_catalog_external_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let first_path = layout.value_log_path(1);
    let second_path = layout.value_log_path(2);
    let intact_tree = snapshot(dir.path());
    mutate(&second_path);
    let aliased_tree = snapshot(dir.path());
    assert_ne!(aliased_tree, intact_tree);
    assert_two_file_owner_remains_fenced(&dir, &lease, &config);

    with_wal_budget(root, &manifest, |budget| {
        let wal_balance = budget.remaining_bytes();
        let segments = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
        let segment_balance = budget.remaining_bytes();
        assert!(segment_balance < wal_balance);
        assert_eq!(
            catalog_pointer(&segments.rows, &[0]).path,
            first_path.to_str().unwrap()
        );
        assert_eq!(
            catalog_pointer(&segments.rows, &schema_key),
            &second_pointer
        );

        let mut probe = ValueFileScanProbeRed::default();
        let error = collect_value_witness_red(root, &manifest, &segments.rows, budget, &mut probe)
            .unwrap_err();
        let PraxisError::Corrupt { path, .. } = &error else {
            panic!("the second-file alias escaped the private witness: {error}")
        };
        assert_eq!(path, &second_path);
        assert_eq!(probe.proof_full_file_hashes, 1);
        assert_eq!(probe.recheck_full_file_hashes, 0);
        assert_eq!(budget.remaining_bytes(), segment_balance);
        segments.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), wal_balance);
        assert_eq!(snapshot(dir.path()), aliased_tree);
    });
    assert_eq!(snapshot(dir.path()), aliased_tree);
}

#[test]
fn private_value_inventory_rejects_second_file_hardlink_alias() {
    assert_second_file_physical_alias_refused(|second_path| {
        let alias_path = second_path.with_extension("hardlink");
        fs::hard_link(second_path, alias_path).unwrap();
    });
}

#[cfg(unix)]
#[test]
fn private_value_inventory_rejects_second_file_symlink_leaf() {
    use std::os::unix::fs::symlink;

    assert_second_file_physical_alias_refused(|second_path| {
        let parked = second_path.with_extension("parked");
        fs::rename(second_path, &parked).unwrap();
        symlink(parked, second_path).unwrap();
    });
}

#[test]
fn private_value_recheck_rejects_second_file_replacement_or_referenced_mutation() {
    #[derive(Clone, Copy, Debug)]
    enum Change {
        ByteIdenticalReplacement,
        ReferencedPayloadMutation,
    }

    for change in [
        Change::ByteIdenticalReplacement,
        Change::ReferencedPayloadMutation,
    ] {
        let (dir, lease, manifest, schema_key, schema_bytes, second_pointer, config) =
            writer_two_file_catalog_external_fixture();
        let root = lease.root();
        let second_path = DiskLayout::at(root).value_log_path(2);
        let original = fs::read(&second_path).unwrap();
        let intact_tree = snapshot(dir.path());
        assert_two_file_owner_remains_fenced(&dir, &lease, &config);

        with_wal_budget(root, &manifest, |budget| {
            let wal_balance = budget.remaining_bytes();
            let segments = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
            let segment_balance = budget.remaining_bytes();
            assert!(segment_balance < wal_balance);
            assert_eq!(
                catalog_pointer(&segments.rows, &schema_key),
                &second_pointer
            );
            let mut probe = ValueFileScanProbeRed::default();
            let values =
                collect_value_witness_red(root, &manifest, &segments.rows, budget, &mut probe)
                    .unwrap();
            assert_eq!(probe.proof_full_file_hashes, 2);
            assert_eq!(values.files.len(), 2);
            assert_eq!(values.files[1].id, 2);
            assert_eq!(values.files[1].path, second_path);
            assert_eq!(values.files[1].len, original.len() as u64);
            assert_eq!(values.files[1].digest, blake3::hash(&original));
            assert_eq!(
                values.retained_bytes,
                segment_balance - budget.remaining_bytes()
            );

            match change {
                Change::ByteIdenticalReplacement => {
                    let replacement = second_path.with_extension("replacement");
                    fs::copy(&second_path, &replacement).unwrap();
                    let opened = File::open(&replacement).unwrap();
                    assert_ne!(
                        physical_id(&opened, &replacement).unwrap(),
                        values.files[1].identity
                    );
                    drop(opened);
                    fs::remove_file(&second_path).unwrap();
                    fs::rename(replacement, &second_path).unwrap();
                }
                Change::ReferencedPayloadMutation => {
                    assert_eq!(second_pointer.len, schema_bytes.len() as u64);
                    let offset = second_pointer.offset + 12 + 16_384;
                    let at = usize::try_from(offset).unwrap();
                    assert!(at < original.len());
                    let mut opened = OpenOptions::new().write(true).open(&second_path).unwrap();
                    opened.seek(SeekFrom::Start(offset)).unwrap();
                    opened.write_all(&[original[at] ^ 1]).unwrap();
                    opened.flush().unwrap();
                }
            }
            let changed = fs::read(&second_path).unwrap();
            assert_eq!(changed.len(), original.len());
            let opened = File::open(&second_path).unwrap();
            let changed_id = physical_id(&opened, &second_path).unwrap();
            drop(opened);
            match change {
                Change::ByteIdenticalReplacement => {
                    assert_eq!(changed, original);
                    assert_eq!(blake3::hash(&changed), values.files[1].digest);
                    assert_ne!(changed_id, values.files[1].identity);
                }
                Change::ReferencedPayloadMutation => {
                    assert_ne!(changed, original);
                    assert_ne!(blake3::hash(&changed), values.files[1].digest);
                    assert_eq!(changed_id, values.files[1].identity);
                }
            }
            let changed_tree = snapshot(dir.path());
            assert_ne!(changed_tree, intact_tree);

            let error =
                recheck_value_witness_red(root, &manifest, &values, &mut probe).unwrap_err();
            let PraxisError::Corrupt { path, .. } = &error else {
                panic!("{change:?} escaped the private recheck: {error}")
            };
            assert_eq!(path, &second_path);
            assert_eq!(
                probe.recheck_full_file_hashes,
                if matches!(change, Change::ByteIdenticalReplacement) {
                    1
                } else {
                    2
                }
            );
            assert_eq!(
                budget.remaining_bytes(),
                segment_balance - values.retained_bytes
            );
            assert_eq!(snapshot(dir.path()), changed_tree);
            values.discard(root, budget).unwrap();
            assert_eq!(budget.remaining_bytes(), segment_balance);
            segments.discard(root, budget).unwrap();
            assert_eq!(budget.remaining_bytes(), wal_balance);
            assert_eq!(snapshot(dir.path()), changed_tree);
        });
        assert_ne!(snapshot(dir.path()), intact_tree);
    }
}

#[test]
fn private_value_inventory_rejects_forged_head_claims_before_any_reservation_or_scan() {
    #[derive(Clone, Copy, Debug)]
    enum Forgery {
        AtomicLength,
        OverflowingOffset,
    }

    for forgery in [Forgery::AtomicLength, Forgery::OverflowingOffset] {
        let (dir, lease, _, schema_key, _, second_pointer, config) =
            writer_two_file_catalog_external_fixture();
        let root = lease.root();
        let layout = DiskLayout::at(root);
        let segment_path = layout.segment_path(0, 1);
        let first_path = layout.value_log_path(1);
        let second_path = layout.value_log_path(2);
        let first_bytes = fs::read(&first_path).unwrap();
        let second_bytes = fs::read(&second_path).unwrap();
        assert!(first_bytes.len() < 1024 * 1024);
        assert!(second_bytes.len() < 1024 * 1024);

        let mut decoded = decode_segment(
            &fs::read(&segment_path).unwrap(),
            &segment_path,
            &CpuAccelerator,
        )
        .unwrap();
        let head = decoded
            .blocks
            .iter_mut()
            .flatten()
            .find(|raw| raw.entry.cf.0 == CATALOG_CF && raw.entry.key.as_ref() == &[0_u8][..])
            .expect("the writer must emit a Head row");
        let StoredValue::BlobPointer(pointer) = &mut head.entry.version.value else {
            panic!("the writer must externalize Head")
        };
        assert_eq!(pointer.path, first_path.to_str().unwrap());
        assert_eq!(pointer.len, 48);
        let original_checksum = pointer.checksum;
        let (expected_offset, expected_len, expected_path, expected_reason) = match forgery {
            Forgery::AtomicLength => {
                pointer.len = MAX_WAL_PAYLOAD_BYTES as u64;
                (
                    pointer.offset,
                    pointer.len,
                    root,
                    "external catalog pointer exceeds its key cap",
                )
            }
            Forgery::OverflowingOffset => {
                pointer.offset = u64::MAX - 5;
                (
                    pointer.offset,
                    pointer.len,
                    first_path.as_path(),
                    "external value extent overflows",
                )
            }
        };
        assert_eq!(pointer.checksum, original_checksum);
        let rechecksummed = decoded.encode(&CpuAccelerator).unwrap();
        let manifest = replace_first_segment_bytes(root, &rechecksummed);
        assert_eq!(
            manifest.segments[0].file_digest,
            blake3::hash(&rechecksummed).to_hex().to_string()
        );
        assert_eq!(fs::read(&first_path).unwrap(), first_bytes);
        assert_eq!(fs::read(&second_path).unwrap(), second_bytes);
        assert_two_file_owner_remains_fenced(&dir, &lease, &config);
        let before = snapshot(dir.path());

        with_wal_budget(root, &manifest, |budget| {
            let wal_balance = budget.remaining_bytes();
            let segments = collect_protected_segment_candidate(root, &manifest, budget).unwrap();
            let segment_balance = budget.remaining_bytes();
            assert!(segment_balance < wal_balance);
            let head = catalog_pointer(&segments.rows, &[0]);
            assert_eq!(head.path, first_path.to_str().unwrap());
            assert_eq!((head.offset, head.len), (expected_offset, expected_len));
            assert_eq!(head.checksum, original_checksum);
            assert_eq!(
                catalog_pointer(&segments.rows, &schema_key),
                &second_pointer
            );

            // If metadata is reserved before the key cap and checked extent,
            // this exhausted shared WAL + segment ledger changes the error.
            let held = budget.remaining_bytes();
            assert!(held > 0);
            budget.charge(root, held).unwrap();
            assert_eq!(budget.remaining_bytes(), 0);
            let mut probe = ValueFileScanProbeRed::default();
            let error =
                collect_value_witness_red(root, &manifest, &segments.rows, budget, &mut probe)
                    .unwrap_err();
            assert!(
                matches!(&error, PraxisError::Corrupt { path, reason }
                    if path.as_path() == expected_path && reason == expected_reason),
                "{forgery:?} failed outside the private pre-I/O pointer check: {error}"
            );
            assert_eq!(probe.proof_full_file_hashes, 0);
            assert_eq!(probe.recheck_full_file_hashes, 0);
            assert_eq!(budget.remaining_bytes(), 0);
            budget.release(root, held).unwrap();
            assert_eq!(budget.remaining_bytes(), segment_balance);
            segments.discard(root, budget).unwrap();
            assert_eq!(budget.remaining_bytes(), wal_balance);
            assert_eq!(snapshot(dir.path()), before);
        });
        assert_eq!(snapshot(dir.path()), before);
    }
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

use super::*;
use crate::core_catalog::physical_copy::{
    collect_protected_copy_admission, collect_protected_copy_ledger,
};
use crate::core_records::codec::{Key as RecordKey, Role as RecordRole, Row as RecordRow};

#[derive(Clone, Copy)]
enum InvalidVariableSequence {
    DescriptorAfterBootstrap,
    PayloadBeforeCreate,
    PayloadDeleteBeforeCreate,
    PayloadPointerBeforeCreate,
}

fn malformed_variable_sequence_case(case: InvalidVariableSequence) {
    let (dir, mut config, lease) = flushed_create_fixture();
    let root = lease.root();
    let layout = DiskLayout::at(root);
    let path = layout.segment_path(0, 1);
    let decoded = decode_segment(&fs::read(&path).unwrap(), &path, &CpuAccelerator).unwrap();
    let mut rows = decoded
        .blocks
        .into_iter()
        .flatten()
        .map(|raw| raw.entry)
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 7);
    let manifest_path = layout.manifest_path();
    let mut manifest =
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
    let authority = manifest.record_authority.as_mut().unwrap();
    assert_eq!(authority.index_descriptor_count, 0);
    let database_id = authority.identity(root).unwrap();
    authority.index_descriptor_count = 1;
    ManifestStore::new(manifest_path.clone())
        .save(&manifest)
        .unwrap();

    // The original bootstrap declares zero descriptors. Keep the binding and
    // MANIFEST consistent, and install the canonical Descriptor(1) at S=1,
    // so the later S=2 copy has only the sequence defect under test.
    let binding_key = RecordKey::Binding.encode().unwrap();
    let binding_rows = rows
        .iter_mut()
        .filter(|row| {
            row.cf.0 == RecordRole::Meta.cf()
                && row.key.as_ref() == binding_key
                && row.version.sequence == 1
        })
        .collect::<Vec<_>>();
    assert_eq!(binding_rows.len(), 1);
    let binding = &mut *binding_rows.into_iter().next().unwrap();
    let StoredValue::Put(binding_bytes) = &mut binding.version.value else {
        panic!("the bootstrap Binding must be an inline Put")
    };
    assert!(matches!(
        RecordRow::decode(&RecordKey::Binding, binding_bytes, root).unwrap(),
        RecordRow::Binding {
            database_id: id,
            descriptor_count: 0
        } if id == database_id
    ));
    *binding_bytes = RecordRow::Binding {
        database_id,
        descriptor_count: 1,
    }
    .encode()
    .unwrap();
    let descriptor_key = RecordKey::Descriptor(1).encode().unwrap();
    let descriptor_value = RecordRow::Descriptor {
        name: "idx",
        namespace: "n",
    }
    .encode()
    .unwrap();
    rows.push(row_in(
        RecordRole::Meta.cf(),
        &descriptor_key,
        1,
        StoredValue::Put(descriptor_value.clone()),
    ));
    let (role, key, value, sequence, expected_reason, external_payload) = match case {
        InvalidVariableSequence::DescriptorAfterBootstrap => (
            RecordRole::Meta,
            RecordKey::Descriptor(1),
            StoredValue::Put(descriptor_value.clone()),
            2,
            "record Descriptor copy is outside bootstrap sequence",
            false,
        ),
        InvalidVariableSequence::PayloadBeforeCreate => (
            RecordRole::Payload,
            RecordKey::Payload(1),
            StoredValue::Put(RecordRow::Payload(b"p").encode().unwrap()),
            1,
            "record Payload Put copy is before Create sequence",
            false,
        ),
        InvalidVariableSequence::PayloadDeleteBeforeCreate => (
            RecordRole::Payload,
            RecordKey::Payload(1),
            // A canonical DeleteRecords frame can tombstone only an RID that
            // was allocated by an earlier Create; S=1 is the bootstrap.
            StoredValue::Delete,
            1,
            "record Payload Delete copy is before Create sequence",
            false,
        ),
        InvalidVariableSequence::PayloadPointerBeforeCreate => (
            RecordRole::Payload,
            RecordKey::Payload(1),
            StoredValue::Put(RecordRow::Payload(&[0x5a; 256]).encode().unwrap()),
            1,
            "record Payload Put copy is before Create sequence",
            true,
        ),
    };
    let key_bytes = key.encode().unwrap();
    assert_eq!(RecordKey::decode(role, &key_bytes, root).unwrap(), key);
    if let StoredValue::Put(bytes) = &value {
        assert_eq!(
            RecordRow::decode(&key, bytes, root)
                .unwrap()
                .encode()
                .unwrap(),
            *bytes
        );
    }
    rows.push(row_in(role.cf(), &key_bytes, sequence, value.clone()));
    let manifest = if external_payload {
        // Preserve the bootstrap rows inline while making the new S=1 Payload
        // a genuine writer-produced pointer into a retained value file.
        config.large_value_threshold = 255;
        config.validate().unwrap();
        let value_path = layout.value_log_path(1);
        let mut value_log = ValueLog::open(&value_path).unwrap();
        let first = SegmentWriter::write(
            SegmentWriteOptions {
                path: &path,
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
            rows,
        )
        .unwrap();
        drop(value_log);
        let mut manifest =
            Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
        manifest.effective_config = config.persisted();
        for family in &mut manifest.column_families {
            if family.name == CATALOG_CF || family.name.starts_with("__praxor_record_") {
                family.large_value_threshold_bytes = config.large_value_threshold;
            }
        }
        manifest.segments[0] = first;
        ManifestStore::new(manifest_path.clone())
            .save(&manifest)
            .unwrap();
        Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap()
    } else {
        rewrite_first_segment(
            root,
            rows,
            Compression::None,
            config.large_value_threshold,
            config.block_size,
        )
    };
    manifest.validate_v4(root).unwrap();
    assert_eq!(manifest.flushed_sequence, 2);
    assert_eq!(manifest.segments.len(), 1);
    assert_eq!(manifest.segments[0].entries, 9);
    assert_eq!(
        manifest
            .record_authority
            .as_ref()
            .unwrap()
            .index_descriptor_count,
        1
    );
    let written = fs::read(&path).unwrap();
    assert_eq!(
        manifest.segments[0].file_digest,
        blake3::hash(&written).to_hex().to_string()
    );
    let decoded = decode_segment(&written, &path, &CpuAccelerator).unwrap();
    let bootstrap_descriptors = decoded
        .blocks
        .iter()
        .flatten()
        .filter(|raw| {
            raw.entry.cf.0 == RecordRole::Meta.cf()
                && raw.entry.key.as_ref() == descriptor_key
                && raw.entry.version.sequence == 1
                && matches!(
                    &raw.entry.version.value,
                    StoredValue::Put(bytes) if bytes == &descriptor_value
                )
        })
        .count();
    assert_eq!(bootstrap_descriptors, 1);
    let binding = decoded
        .blocks
        .iter()
        .flatten()
        .find(|raw| {
            raw.entry.cf.0 == RecordRole::Meta.cf()
                && raw.entry.key.as_ref() == binding_key
                && raw.entry.version.sequence == 1
        })
        .unwrap();
    let StoredValue::Put(binding_bytes) = &binding.entry.version.value else {
        panic!("rewritten bootstrap Binding must be an inline Put")
    };
    assert!(matches!(
        RecordRow::decode(&RecordKey::Binding, binding_bytes, root).unwrap(),
        RecordRow::Binding {
            database_id: id,
            descriptor_count: 1
        } if id == database_id
    ));
    let matching = decoded
        .blocks
        .iter()
        .flatten()
        .filter(|raw| {
            raw.entry.cf.0 == role.cf()
                && raw.entry.key.as_ref() == key_bytes
                && raw.entry.version.sequence == sequence
        })
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].entry.version.sequence, sequence);
    assert_eq!(matching[0].blob_expiry, None);
    let written_value = matching[0].entry.version.value.clone();
    let external_value_identity = if external_payload {
        let StoredValue::Put(bytes) = &value else {
            unreachable!("the external fixture starts with an encoded Payload Put")
        };
        let StoredValue::BlobPointer(pointer) = &written_value else {
            panic!("the segment writer must externalize the S=1 Payload")
        };
        let value_path = layout.value_log_path(1);
        let value_file = fs::read(&value_path).unwrap();
        assert_eq!(pointer.path, value_path.to_str().unwrap());
        assert_eq!(pointer.offset, 0);
        assert_eq!(pointer.len, bytes.len() as u64);
        assert_eq!(pointer.checksum, crc32c(bytes));
        assert_eq!(value_file.len(), 12 + bytes.len());
        assert_eq!(
            u64::from_le_bytes(value_file[..8].try_into().unwrap()),
            pointer.len
        );
        assert_eq!(
            u32::from_le_bytes(value_file[8..12].try_into().unwrap()),
            pointer.checksum
        );
        assert_eq!(&value_file[12..], bytes.as_slice());
        let value_file_handle = File::open(&value_path).unwrap();
        Some(physical_id(&value_file_handle, &value_path).unwrap())
    } else {
        assert_eq!(written_value, value);
        None
    };
    assert_eq!(decoded.blocks.len(), 1);
    assert_eq!(decoded.blocks[0].len(), 9);
    let target_ordinal = u32::try_from(
        decoded.blocks[0]
            .iter()
            .position(|raw| {
                raw.entry.cf.0 == role.cf()
                    && raw.entry.key.as_ref() == key_bytes
                    && raw.entry.version.sequence == sequence
            })
            .unwrap(),
    )
    .unwrap();
    let expected_observed = match &written_value {
        StoredValue::Put(bytes) => ObservedSegmentValue::Put(bytes.clone()),
        StoredValue::Delete => ObservedSegmentValue::Delete,
        StoredValue::BlobPointer(pointer) => ObservedSegmentValue::Pointer {
            pointer: pointer.clone(),
            expires_at_ms: None,
        },
        _ => unreachable!("the fixture writes only Put, Delete, or external Put"),
    };
    let before = snapshot(dir.path());
    assert!(matches!(
        inspect_v4_owner(&lease, &config, &CpuAccelerator),
        Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 installed cut beyond narrow D0 bootstrap"
        })
    ));
    assert_eq!(snapshot(dir.path()), before, "public owner must not write");

    with_wal_budget(root, &manifest, |budget| {
        let balance = budget.remaining_bytes();
        let staged = collect_protected_segment_candidate(root, &manifest, budget)
            .expect("writer-encoded row must reach the private variable shape guard");
        assert_eq!(staged.witnesses.len(), 1);
        assert_eq!(staged.rows.len(), 9);
        let segment_file = File::open(&path).unwrap();
        assert_eq!(staged.witnesses[0].path, path);
        assert_eq!(
            staged.witnesses[0].identity,
            physical_id(&segment_file, &path).unwrap()
        );
        assert_eq!(staged.witnesses[0].len, written.len() as u64);
        assert_eq!(staged.witnesses[0].digest, blake3::hash(&written));
        assert_eq!(staged.witnesses[0].observed_rows, 9);
        assert_eq!(
            staged
                .rows
                .iter()
                .filter(|row| {
                    row.cf == RecordRole::Meta.cf()
                        && row.key == descriptor_key
                        && row.sequence == 1
                        && matches!(
                            &row.value,
                            ObservedSegmentValue::Put(bytes) if bytes == &descriptor_value
                        )
                })
                .count(),
            1
        );
        let matching = staged
            .rows
            .iter()
            .filter(|row| row.cf == role.cf() && row.key == key_bytes && row.sequence == sequence)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1);
        assert_eq!(
            matching[0].classification,
            PhysicalRowClass::BoundProtected(match role {
                RecordRole::Meta => ProtectedRole::Meta,
                RecordRole::Payload => ProtectedRole::Payload,
                _ => unreachable!("the two fixtures use only Meta and Payload"),
            })
        );
        assert_eq!(matching[0].source, staged.witnesses[0].source);
        assert_eq!(matching[0].block_offset, 21);
        assert_eq!(matching[0].row_ordinal, target_ordinal);
        assert_eq!(matching[0].value, expected_observed);
        staged.discard(root, budget).unwrap();
        assert_eq!(budget.remaining_bytes(), balance);

        let legacy = match collect_protected_copy_ledger(root, &manifest, budget) {
            Ok(candidate) => {
                candidate.discard(root, budget).unwrap();
                None
            }
            Err(error) => Some(error),
        };
        assert_eq!(budget.remaining_bytes(), balance, "legacy witness refund");
        assert_eq!(
            snapshot(dir.path()),
            before,
            "legacy collector must not write"
        );
        let admission = match collect_protected_copy_admission(root, &manifest, budget) {
            Ok(candidate) => {
                drop(candidate);
                None
            }
            Err(error) => Some(error),
        };
        assert_eq!(
            budget.remaining_bytes(),
            balance,
            "candidate witness refund"
        );
        assert_eq!(
            snapshot(dir.path()),
            before,
            "private candidate must not write"
        );
        for (entry, result) in [
            ("private candidate", admission),
            ("legacy collector", legacy),
        ] {
            match result {
                Some(PraxisError::Corrupt { path, reason }) => {
                    assert_eq!(path.as_path(), root, "{entry}");
                    assert_eq!(reason, expected_reason, "{entry}");
                }
                Some(other) => {
                    panic!("RED: {entry} needs a named variable-sequence corrupt guard: {other:?}")
                }
                None => panic!("RED: {entry} admitted a malformed variable-record sequence"),
            }
        }
        assert_eq!(budget.remaining_bytes(), balance, "exact witness refund");
        assert_eq!(
            snapshot(dir.path()),
            before,
            "collector must not change bytes or identities"
        );
    });
    assert_eq!(snapshot(dir.path()), before);
    if let Some(identity) = external_value_identity {
        let value_path = layout.value_log_path(1);
        assert_eq!(
            physical_id(&File::open(&value_path).unwrap(), &value_path).unwrap(),
            identity,
            "the external value file identity must survive both collectors"
        );
    }
}

#[test]
fn rechecksummed_record_descriptor_after_bootstrap_refuses_before_copy_replay() {
    malformed_variable_sequence_case(InvalidVariableSequence::DescriptorAfterBootstrap);
}

#[test]
fn rechecksummed_record_payload_before_create_refuses_before_copy_replay() {
    malformed_variable_sequence_case(InvalidVariableSequence::PayloadBeforeCreate);
}

#[test]
fn rechecksummed_record_payload_delete_before_create_refuses_before_copy_replay() {
    malformed_variable_sequence_case(InvalidVariableSequence::PayloadDeleteBeforeCreate);
}

#[test]
fn writer_external_record_payload_before_create_refuses_before_copy_replay() {
    malformed_variable_sequence_case(InvalidVariableSequence::PayloadPointerBeforeCreate);
}

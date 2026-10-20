use super::*;
use crate::core_catalog::physical_copy::{
    collect_protected_copy_admission, collect_protected_copy_ledger,
};
use crate::core_records::codec::{Key as RecordKey, Role as RecordRole, Row as RecordRow};

#[derive(Clone, Copy)]
enum InvalidVariableSequence {
    DescriptorAfterBootstrap,
    PayloadBeforeCreate,
}

fn malformed_variable_sequence_case(case: InvalidVariableSequence) {
    let (dir, config, lease) = flushed_create_fixture();
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
    let (role, key, value, sequence, expected_reason) = match case {
        InvalidVariableSequence::DescriptorAfterBootstrap => (
            RecordRole::Meta,
            RecordKey::Descriptor(1),
            descriptor_value.clone(),
            2,
            "record Descriptor copy is outside bootstrap sequence",
        ),
        InvalidVariableSequence::PayloadBeforeCreate => (
            RecordRole::Payload,
            RecordKey::Payload(1),
            RecordRow::Payload(b"p").encode().unwrap(),
            1,
            "record Payload Put copy is before Create sequence",
        ),
    };
    let key_bytes = key.encode().unwrap();
    assert_eq!(RecordKey::decode(role, &key_bytes, root).unwrap(), key);
    assert_eq!(
        RecordRow::decode(&key, &value, root)
            .unwrap()
            .encode()
            .unwrap(),
        value
    );
    rows.push(row_in(
        role.cf(),
        &key_bytes,
        sequence,
        StoredValue::Put(value.clone()),
    ));
    let manifest = rewrite_first_segment(
        root,
        rows,
        Compression::None,
        config.large_value_threshold,
        config.block_size,
    );
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
    assert_eq!(
        matching[0].entry.version.value,
        StoredValue::Put(value.clone())
    );
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
        assert_eq!(matching[0].value, ObservedSegmentValue::Put(value));
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
}

#[test]
fn rechecksummed_record_descriptor_after_bootstrap_refuses_before_copy_replay() {
    malformed_variable_sequence_case(InvalidVariableSequence::DescriptorAfterBootstrap);
}

#[test]
fn rechecksummed_record_payload_before_create_refuses_before_copy_replay() {
    malformed_variable_sequence_case(InvalidVariableSequence::PayloadBeforeCreate);
}

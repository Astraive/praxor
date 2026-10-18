use crate::errors::{PraxisError, Result};
use crate::manifest::{
    ColumnFamilyDescriptor, ColumnFamilyGeneration, ColumnFamilyOptions, Manifest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

pub(crate) const RESERVED_PREFIX: &str = "__praxor_record_";
pub(crate) const ROLES: [(&str, &str); 4] = [
    ("meta", "__praxor_record_meta_v1"),
    ("payload", "__praxor_record_payload_v1"),
    ("state", "__praxor_record_state_v1"),
    ("index", "__praxor_record_index_v1"),
];

/// Immutable built-in mapping declaration. Namespace is an opaque UTF-8 label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingDescriptor {
    pub name: String,
    pub namespace: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecordAuthorityOptions {
    pub indexes: Vec<MappingDescriptor>,
}

impl RecordAuthorityOptions {
    pub(crate) fn canonicalize(mut self) -> Result<Self> {
        self.indexes
            .sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        u32::try_from(self.indexes.len())
            .map_err(|_| PraxisError::InvalidConfig("too many record indexes".into()))?;
        let mut previous = None;
        for descriptor in &self.indexes {
            if descriptor.name.is_empty() || previous == Some(descriptor.name.as_str()) {
                return Err(PraxisError::InvalidConfig(
                    "record index names must be nonempty and unique".into(),
                ));
            }
            for field in [&descriptor.name, &descriptor.namespace] {
                u32::try_from(field.len()).map_err(|_| {
                    PraxisError::InvalidConfig("record index label exceeds u32 length".into())
                })?;
            }
            previous = Some(&descriptor.name);
        }
        Ok(self)
    }
}

/// Mandatory v3 manifest authority; absent fields never activate defaults.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordAuthority {
    pub kind: String,
    pub schema_version: u32,
    pub database_id: String,
    pub epoch: u64,
    pub bootstrap_sequence: u64,
    pub index_descriptor_count: u32,
    pub roles: Vec<RecordRoleBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordRoleBinding {
    pub role: String,
    pub column_family: String,
    pub generation: u64,
}

impl RecordAuthority {
    pub(crate) fn new(database_id: [u8; 16], index_descriptor_count: u32) -> Self {
        Self {
            kind: "core_records".into(),
            schema_version: 1,
            database_id: database_id
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            epoch: 1,
            bootstrap_sequence: 1,
            index_descriptor_count,
            roles: ROLES
                .iter()
                .enumerate()
                .map(|(index, (role, cf))| RecordRoleBinding {
                    role: (*role).into(),
                    column_family: (*cf).into(),
                    generation: index as u64 + 1,
                })
                .collect(),
        }
    }

    pub(crate) fn identity(&self, source: &Path) -> Result<[u8; 16]> {
        let bytes = self.database_id.as_bytes();
        if bytes.len() != 32
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(corrupt(
                source,
                "record database ID must be 32 lowercase hexadecimal bytes",
            ));
        }
        let mut id = [0; 16];
        for (slot, pair) in id.iter_mut().zip(bytes.as_chunks::<2>().0) {
            let digit = |byte: u8| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            *slot = digit(pair[0]) * 16 + digit(pair[1]);
        }
        if id == [0; 16] {
            return Err(corrupt(source, "record database ID is zero"));
        }
        Ok(id)
    }

    /// Fixed identity/role contract; owner admission separately validates the
    /// complete manifest inventory. Token capture need not scan user families.
    pub(crate) fn validate_binding(&self, source: &Path) -> Result<()> {
        self.identity(source)?;
        if self.kind != "core_records"
            || self.schema_version != 1
            || self.epoch != 1
            || self.bootstrap_sequence != 1
        {
            return Err(corrupt(
                source,
                "unsupported record authority kind/schema/epoch/bootstrap",
            ));
        }
        if self.roles.len() != 4 {
            return Err(corrupt(
                source,
                "incomplete record authority roles/counters",
            ));
        }
        let mut seen = BTreeSet::new();
        for binding in &self.roles {
            let Some(index) = ROLES.iter().position(|(role, _)| *role == binding.role) else {
                return Err(corrupt(source, "unknown record role"));
            };
            if !seen.insert(index)
                || binding.column_family != ROLES[index].1
                || binding.generation != index as u64 + 1
            {
                return Err(corrupt(source, "duplicate or altered record role binding"));
            }
        }
        Ok(())
    }

    pub(crate) fn validate(&self, manifest: &Manifest, source: &Path) -> Result<()> {
        self.validate_binding(source)?;
        if manifest.next_column_family_generation < 5 || manifest.last_sequence < 1 {
            return Err(corrupt(
                source,
                "incomplete record authority roles/counters",
            ));
        }
        for binding in &self.roles {
            let index = ROLES
                .iter()
                .position(|(role, _)| *role == binding.role)
                .expect("validated role binding");
            let expected = self.descriptor(index, manifest);
            if manifest
                .column_families
                .iter()
                .find(|cf| cf.name == binding.column_family)
                != Some(&expected)
                || manifest
                    .column_family_generations
                    .get(&binding.column_family)
                    != Some(&ColumnFamilyGeneration {
                        id: binding.generation,
                        visible_after_sequence: 0,
                    })
            {
                return Err(corrupt(
                    source,
                    "record role descriptor/incarnation mismatch",
                ));
            }
        }
        if manifest.column_families.iter().any(|cf| {
            cf.name.starts_with(RESERVED_PREFIX) && !ROLES.iter().any(|(_, name)| *name == cf.name)
        }) {
            return Err(corrupt(source, "unbound reserved record column family"));
        }
        for family in &manifest.column_families {
            if family.name == "default" || ROLES.iter().any(|(_, name)| *name == family.name) {
                continue;
            }
            let generation = manifest
                .column_family_generations
                .get(&family.name)
                .ok_or_else(|| {
                    corrupt(
                        source,
                        "record owner user family lacks incarnation metadata",
                    )
                })?;
            if generation.id < 5 || generation.visible_after_sequence < self.bootstrap_sequence {
                return Err(corrupt(
                    source,
                    "record owner user family predates its fresh authority",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn descriptor(&self, index: usize, manifest: &Manifest) -> ColumnFamilyDescriptor {
        ColumnFamilyDescriptor {
            name: ROLES[index].1.into(),
            write_buffer_size_bytes: manifest.effective_config.memtable_flush_threshold_bytes,
            large_value_threshold_bytes: manifest.effective_config.large_value_threshold,
            bloom_enabled: true,
            options: ColumnFamilyOptions {
                memtable_kind: manifest.effective_config.default_memtable_kind,
                compaction_strategy: manifest.effective_config.default_compaction_strategy,
                ..ColumnFamilyOptions::default()
            },
        }
    }
}

pub(crate) fn corrupt(source: &Path, reason: impl Into<String>) -> PraxisError {
    PraxisError::Corrupt {
        path: source.to_path_buf(),
        reason: reason.into(),
    }
}

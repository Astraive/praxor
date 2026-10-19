use crate::core_records::RecordAuthority;
use crate::errors::{PraxisError, Result};
use crate::manifest::{ColumnFamilyDescriptor, ColumnFamilyOptions, Manifest};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub(crate) const CATALOG_CF: &str = "__praxor_record_catalog_v1";

/// The independent, mandatory v4 binding for the core catalog role.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogAuthorityV1 {
    pub kind: String,
    pub schema_version: u32,
    pub codec_version: u16,
    pub database_id: String,
    pub epoch: u64,
    pub bootstrap_sequence: u64,
    pub binding: CatalogBindingV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogBindingV1 {
    pub role: String,
    pub column_family: String,
    pub generation: u64,
}

impl CatalogAuthorityV1 {
    pub(crate) fn validate(&self, record: &RecordAuthority, source: &Path) -> Result<()> {
        let corrupt = |reason: &str| PraxisError::Corrupt {
            path: source.to_path_buf(),
            reason: reason.into(),
        };
        if self.kind != "core_catalog"
            || self.schema_version != 1
            || self.codec_version != 1
            || self.epoch != 1
            || self.bootstrap_sequence != 1
            || self.binding.role != "catalog"
            || self.binding.column_family != CATALOG_CF
            || self.binding.generation != 5
        {
            return Err(corrupt("unsupported catalog authority binding"));
        }
        let raw = self.database_id.as_bytes();
        if raw.len() != 32
            || !raw
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(corrupt(
                "catalog database ID must be 32 lowercase hexadecimal bytes",
            ));
        }
        let mut id = [0u8; 16];
        for (slot, pair) in id.iter_mut().zip(raw.as_chunks::<2>().0) {
            let hex = |byte: u8| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            *slot = hex(pair[0]) * 16 + hex(pair[1]);
        }
        if id == [0; 16] || id != record.identity(source)? {
            return Err(corrupt("catalog and record database identities differ"));
        }
        Ok(())
    }

    pub(crate) fn descriptor(manifest: &Manifest) -> ColumnFamilyDescriptor {
        ColumnFamilyDescriptor {
            name: CATALOG_CF.into(),
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

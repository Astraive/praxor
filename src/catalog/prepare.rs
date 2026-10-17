use super::*;
use std::fs::Metadata;

pub(super) struct PreparedCatalogSave {
    files: [PreparedCatalogFile; 10],
}

struct PreparedCatalogFile {
    path: PathBuf,
    bytes: Vec<u8>,
}

impl PreparedCatalogSave {
    pub(super) fn publish(self) -> Result<()> {
        self.publish_files(|_| Ok(()))
    }

    fn publish_files(self, mut after_file: impl FnMut(usize) -> Result<()>) -> Result<()> {
        for (index, file) in self.files.into_iter().enumerate() {
            write_catalog(&file.path, &file.bytes)?;
            after_file(index)?;
        }
        Ok(())
    }

    /// Per-call tests pause or inject an actual IO fault only after publication.
    #[cfg(test)]
    pub(super) fn publish_with_hook(
        self,
        after_file: impl FnMut(usize) -> Result<()>,
    ) -> Result<()> {
        self.publish_files(after_file)
    }
}

pub(super) fn prepare_catalog(
    snapshot: &CatalogSnapshot,
    layout: &PraxisLayout,
) -> Result<PreparedCatalogSave> {
    prepare_with_limit(snapshot, layout, u32::MAX)
}

// The per-call limit lets tests exercise late length rejection without making
// multi-gigabyte allocations. Production always uses the existing v1 range.
fn prepare_with_limit(
    snapshot: &CatalogSnapshot,
    layout: &PraxisLayout,
    limit: u32,
) -> Result<PreparedCatalogSave> {
    let sizes = checked_payload_sizes(snapshot, limit)?;
    // Every count/string/total is checked above before any legacy encoder can
    // narrow a length. All ten payloads and envelopes exist before publication.
    let payloads = [
        ("collections.cat", encode_collections(&snapshot.collections)),
        ("entities.cat", encode_entities(&snapshot.entities)),
        (
            "fixed_attrs.cat",
            encode_fixed_attrs(&snapshot.fixed_attributes),
        ),
        (
            "dynamic_attrs.cat",
            encode_dynamic_attrs(&snapshot.dynamic_attributes),
        ),
        ("indexes.cat", encode_indexes(&snapshot.indexes)),
        (
            "vector_models.cat",
            encode_vector_models(&snapshot.vector_models),
        ),
        ("fulltext.cat", encode_fulltext(&snapshot.fulltext)),
        ("graph.cat", encode_graph(&snapshot.graph)),
        ("shards.cat", encode_shards(&snapshot.shards)),
        ("users.cat", encode_users(&snapshot.users)),
    ];
    let mut files = Vec::with_capacity(10);
    for ((name, payload), size) in payloads.into_iter().zip(sizes) {
        if payload.len() != size {
            return Err(invalid(
                "catalog encoder length disagrees with checked shape",
            ));
        }
        let mut writer = BinaryWriter::new();
        writer.write_u32(CATALOG_MAGIC);
        writer.write_u8(CATALOG_VERSION);
        writer.write_u32(checked_u32(payload.len(), limit)?);
        writer.write_u32(crc32c(&payload));
        writer.write_bytes(&payload);
        files.push(PreparedCatalogFile {
            path: layout.catalog_root().join(name),
            bytes: writer.into_inner(),
        });
    }
    let parent = layout.catalog_root();
    let metadata = std::fs::symlink_metadata(&parent)?;
    if !metadata.is_dir() || is_alias(&metadata) {
        return corrupt(&parent, "catalog parent must be a real directory");
    }
    for file in &files {
        preflight_destination(&file.path)?;
        preflight_destination(&file.path.with_extension("tmp"))?;
    }
    let files = files
        .try_into()
        .map_err(|_| invalid("catalog preparation requires ten files"))?;
    Ok(PreparedCatalogSave { files })
}

fn preflight_destination(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !is_alias(&metadata) => Ok(()),
        Ok(_) => corrupt(path, "catalog destination must be a regular file or absent"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn is_alias(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn checked_payload_sizes(snapshot: &CatalogSnapshot, limit: u32) -> Result<[usize; 10]> {
    Ok([
        table_size(
            &snapshot.collections,
            12,
            |entry| {
                [
                    entry.name.len(),
                    entry.retention_policy.as_deref().unwrap_or_default().len(),
                ]
            },
            limit,
        )?,
        table_size(
            &snapshot.entities,
            18,
            |entry| {
                [
                    entry.name.len(),
                    entry.primary_key.as_deref().unwrap_or_default().len(),
                ]
            },
            limit,
        )?,
        table_size(
            &snapshot.fixed_attributes,
            14,
            |entry| [entry.name.len()],
            limit,
        )?,
        table_size(
            &snapshot.dynamic_attributes,
            14,
            |entry| [entry.name.len()],
            limit,
        )?,
        table_size(
            &snapshot.indexes,
            20,
            |entry| {
                [
                    entry.name.len(),
                    entry.kind.len(),
                    entry.pointer_target.len(),
                ]
            },
            limit,
        )?,
        table_size(
            &snapshot.vector_models,
            16,
            |entry| [entry.name.len(), entry.metric.len()],
            limit,
        )?,
        table_size(
            &snapshot.fulltext,
            12,
            |entry| [entry.analyzer.len(), entry.language.len()],
            limit,
        )?,
        table_size(&snapshot.graph, 9, |entry| [entry.edge_label.len()], limit)?,
        table_size(
            &snapshot.shards,
            16,
            |entry| [entry.range_start.len(), entry.range_end.len()],
            limit,
        )?,
        table_size(
            &snapshot.users,
            12,
            |entry| [entry.name.len(), entry.role.len()],
            limit,
        )?,
    ])
}

fn table_size<T, const N: usize>(
    entries: &[T],
    fixed: usize,
    lengths: impl Fn(&T) -> [usize; N],
    limit: u32,
) -> Result<usize> {
    checked_u32(entries.len(), limit)?;
    let mut size = 4_usize;
    for entry in entries {
        size = checked_add(size, fixed)?;
        for len in lengths(entry) {
            checked_u32(len, limit)?;
            size = checked_add(size, len)?;
        }
    }
    checked_u32(size, limit)?;
    checked_add(size, 13)?;
    Ok(size)
}

fn checked_u32(value: usize, limit: u32) -> Result<u32> {
    let value =
        u32::try_from(value).map_err(|_| invalid("catalog length/count exceeds v1 range"))?;
    if value > limit {
        return Err(invalid(
            "catalog length/count exceeds checked encoding limit",
        ));
    }
    Ok(value)
}

fn checked_add(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right)
        .ok_or_else(|| invalid("catalog encoded length overflow"))
}

fn invalid(reason: &str) -> PraxisError {
    PraxisError::InvalidConfig(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Aid, FieldId};
    use crate::record::PageDatabase;

    #[test]
    fn catalog_size_arithmetic_checks_wire_and_address_space_limits_without_allocating() {
        assert_eq!(checked_u32(u32::MAX as usize, u32::MAX).unwrap(), u32::MAX);
        if let Some(too_wide) = (u32::MAX as usize).checked_add(1) {
            assert!(checked_u32(too_wide, u32::MAX).is_err());
        }
        assert!(checked_add(usize::MAX, 1).is_err());
        assert_eq!(checked_add(usize::MAX - 13, 13).unwrap(), usize::MAX);
        assert!(table_size(&[()], usize::MAX, |_| [0], u32::MAX).is_err());
    }

    #[test]
    fn late_users_shape_rejection_precedes_all_publication_and_leaves_owner_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let database = PageDatabase::open(dir.path()).unwrap();
        let catalog = CatalogStore::new(database.clone());
        let mut page = database.entity(Cid(1), Eid(2)).unwrap();
        let rid = page
            .put(&[(FieldId::Fixed(Aid(1)), b"acknowledged")])
            .unwrap();
        catalog.save(&CatalogSnapshot::default()).unwrap();
        let before: Vec<_> = std::fs::read_dir(catalog.layout().catalog_root())
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (path.clone(), std::fs::read(path).unwrap())
            })
            .collect();
        let snapshot = CatalogSnapshot {
            users: vec![UserCatalogEntry {
                user_id: 1,
                name: "X".repeat(128),
                role: String::new(),
            }],
            ..CatalogSnapshot::default()
        };
        let result = database.with_root_mutation(
            |layout| prepare_with_limit(&snapshot, layout, 64),
            |_, prepared| prepared.publish(),
        );
        assert!(matches!(result, Err(PraxisError::InvalidConfig(_))));
        for (path, bytes) in before {
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
        assert_eq!(catalog.load().unwrap(), CatalogSnapshot::default());
        assert_eq!(page.get(rid).unwrap(), b"acknowledged");
        catalog.save(&CatalogSnapshot::default()).unwrap();
    }
}

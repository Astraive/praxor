use super::*;
use crate::io::BinaryReader;
use std::fs::Metadata;

pub(super) fn load_snapshot(layout: &PraxisLayout) -> Result<CatalogSnapshot> {
    let root = layout.catalog_root();
    let metadata = std::fs::symlink_metadata(&root)?;
    if !metadata.is_dir() || is_alias(&metadata) {
        return corrupt(&root, "catalog parent must be a real directory");
    }
    Ok(CatalogSnapshot {
        collections: read_optional(&root.join("collections.cat"), decode_collections)?,
        entities: read_optional(&root.join("entities.cat"), decode_entities)?,
        fixed_attributes: read_optional(&root.join("fixed_attrs.cat"), decode_fixed_attrs)?,
        dynamic_attributes: read_optional(&root.join("dynamic_attrs.cat"), decode_dynamic_attrs)?,
        indexes: read_optional(&root.join("indexes.cat"), decode_indexes)?,
        vector_models: read_optional(&root.join("vector_models.cat"), decode_vector_models)?,
        fulltext: read_optional(&root.join("fulltext.cat"), decode_fulltext)?,
        graph: read_optional(&root.join("graph.cat"), decode_graph)?,
        shards: read_optional(&root.join("shards.cat"), decode_shards)?,
        users: read_optional(&root.join("users.cat"), decode_users)?,
    })
}

pub(super) fn read_optional<T>(
    path: &Path,
    decode: fn(&[u8], &Path) -> Result<Vec<T>>,
) -> Result<Vec<T>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || is_alias(&metadata) {
        return corrupt(path, "catalog input must be a regular file or absent");
    }
    if metadata.len() == 0 {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(path)?;
    decode(catalog_payload(&bytes, path)?, path)
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

fn catalog_payload<'a>(bytes: &'a [u8], path: &Path) -> Result<&'a [u8]> {
    if bytes.len() < 13 {
        return corrupt(path, "truncated catalog file");
    }
    if u32::from_le_bytes(bytes[..4].try_into().unwrap()) != CATALOG_MAGIC {
        return corrupt(path, "bad catalog magic");
    }
    if bytes[4] != CATALOG_VERSION {
        return corrupt(path, &format!("unsupported catalog version {}", bytes[4]));
    }
    let len = usize::try_from(u32::from_le_bytes(bytes[5..9].try_into().unwrap()))
        .map_err(|_| malformed(path, "catalog payload length exceeds address space"))?;
    if len.checked_add(13) != Some(bytes.len()) {
        return corrupt(path, "catalog envelope length disagrees with file length");
    }
    let expected = u32::from_le_bytes(bytes[9..13].try_into().unwrap());
    let payload = &bytes[13..];
    let actual = crc32c(payload);
    if actual != expected {
        return corrupt(
            path,
            &format!("catalog checksum mismatch: expected {expected:#010x}, got {actual:#010x}"),
        );
    }
    Ok(payload)
}

/// Each minimum includes the row's fixed fields and empty-string prefixes.
/// Prove the count against actual bytes after the count before reserving rows.
fn decode_rows<T>(
    bytes: &[u8],
    path: &Path,
    minimum: usize,
    mut decode: impl FnMut(&mut BinaryReader<'_>) -> Result<T>,
) -> Result<Vec<T>> {
    let mut reader = BinaryReader::new(bytes, path);
    let count = usize::try_from(reader.read_u32()?)
        .map_err(|_| malformed(path, "catalog row count exceeds address space"))?;
    if count > reader.remaining() / minimum {
        return corrupt(path, "catalog row count exceeds available payload");
    }
    let mut out = Vec::new();
    out.try_reserve_exact(count)
        .map_err(|error| malformed(path, &format!("cannot reserve catalog rows: {error}")))?;
    for _ in 0..count {
        out.push(decode(&mut reader)?);
    }
    if reader.remaining() != 0 {
        return corrupt(path, "trailing catalog payload bytes");
    }
    Ok(out)
}

pub(super) fn decode_collections(bytes: &[u8], path: &Path) -> Result<Vec<CollectionCatalogEntry>> {
    decode_rows(bytes, path, 12, |reader| {
        Ok(CollectionCatalogEntry {
            cid: Cid(reader.read_u32()?),
            name: read_string(reader, path)?,
            retention_policy: empty_to_none(read_string(reader, path)?),
        })
    })
}

pub(super) fn decode_entities(bytes: &[u8], path: &Path) -> Result<Vec<EntityCatalogEntry>> {
    decode_rows(bytes, path, 18, |reader| {
        Ok(EntityCatalogEntry {
            cid: Cid(reader.read_u32()?),
            eid: Eid(reader.read_u32()?),
            name: read_string(reader, path)?,
            storage_model: tag_to_storage_model(reader.read_u8()?, path)?,
            primary_key: empty_to_none(read_string(reader, path)?),
            compression: tag_to_compression(reader.read_u8()?, path)?,
        })
    })
}

fn decode_fixed_attrs(bytes: &[u8], path: &Path) -> Result<Vec<FixedAttributeCatalogEntry>> {
    decode_rows(bytes, path, 14, |reader| {
        Ok(FixedAttributeCatalogEntry {
            eid: Eid(reader.read_u32()?),
            aid: Aid(read_attribute_id(reader, path)?),
            name: read_string(reader, path)?,
            type_code: reader.read_u8()?,
            nullable: read_flag(reader, path)?,
        })
    })
}

fn decode_dynamic_attrs(bytes: &[u8], path: &Path) -> Result<Vec<DynamicAttributeCatalogEntry>> {
    decode_rows(bytes, path, 14, |reader| {
        let eid = Eid(reader.read_u32()?);
        let did = Did(read_attribute_id(reader, path)?);
        let name = read_string(reader, path)?;
        let has_type = read_flag(reader, path)?;
        // The unused byte remains opaque when the v1 presence flag is zero.
        let type_code = reader.read_u8()?;
        Ok(DynamicAttributeCatalogEntry {
            eid,
            did,
            name,
            inferred_type_code: has_type.then_some(type_code),
        })
    })
}

fn decode_indexes(bytes: &[u8], path: &Path) -> Result<Vec<IndexCatalogEntry>> {
    decode_rows(bytes, path, 20, |reader| {
        Ok(IndexCatalogEntry {
            eid: Eid(reader.read_u32()?),
            index_id: reader.read_u32()?,
            name: read_string(reader, path)?,
            kind: read_string(reader, path)?,
            pointer_target: read_string(reader, path)?,
        })
    })
}

fn decode_vector_models(bytes: &[u8], path: &Path) -> Result<Vec<VectorModelCatalogEntry>> {
    decode_rows(bytes, path, 16, |reader| {
        Ok(VectorModelCatalogEntry {
            model_id: reader.read_u32()?,
            name: read_string(reader, path)?,
            dimensions: reader.read_u32()?,
            metric: read_string(reader, path)?,
        })
    })
}

fn decode_fulltext(bytes: &[u8], path: &Path) -> Result<Vec<FullTextCatalogEntry>> {
    decode_rows(bytes, path, 12, |reader| {
        Ok(FullTextCatalogEntry {
            eid: Eid(reader.read_u32()?),
            analyzer: read_string(reader, path)?,
            language: read_string(reader, path)?,
        })
    })
}

fn decode_graph(bytes: &[u8], path: &Path) -> Result<Vec<GraphCatalogEntry>> {
    decode_rows(bytes, path, 9, |reader| {
        Ok(GraphCatalogEntry {
            eid: Eid(reader.read_u32()?),
            edge_label: read_string(reader, path)?,
            directed: read_flag(reader, path)?,
        })
    })
}

fn decode_shards(bytes: &[u8], path: &Path) -> Result<Vec<ShardCatalogEntry>> {
    decode_rows(bytes, path, 16, |reader| {
        Ok(ShardCatalogEntry {
            shard_id: reader.read_u32()?,
            cid: Cid(reader.read_u32()?),
            range_start: read_string(reader, path)?,
            range_end: read_string(reader, path)?,
        })
    })
}

fn decode_users(bytes: &[u8], path: &Path) -> Result<Vec<UserCatalogEntry>> {
    decode_rows(bytes, path, 12, |reader| {
        Ok(UserCatalogEntry {
            user_id: reader.read_u32()?,
            name: read_string(reader, path)?,
            role: read_string(reader, path)?,
        })
    })
}

fn read_string(reader: &mut BinaryReader<'_>, path: &Path) -> Result<String> {
    let bytes = reader.read_len_slice()?;
    let value = std::str::from_utf8(bytes)
        .map_err(|error| malformed(path, &format!("invalid catalog UTF-8: {error}")))?;
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|error| malformed(path, &format!("cannot reserve catalog string: {error}")))?;
    owned.push_str(value);
    Ok(owned)
}

fn read_attribute_id(reader: &mut BinaryReader<'_>, path: &Path) -> Result<u16> {
    u16::try_from(reader.read_u32()?)
        .map_err(|_| malformed(path, "catalog attribute ID exceeds u16 range"))
}

fn read_flag(reader: &mut BinaryReader<'_>, path: &Path) -> Result<bool> {
    match reader.read_u8()? {
        0 => Ok(false),
        1 => Ok(true),
        value => corrupt(path, &format!("invalid catalog flag {value}")),
    }
}

fn empty_to_none(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn tag_to_storage_model(tag: u8, path: &Path) -> Result<EntityStorageModel> {
    match tag {
        1 => Ok(EntityStorageModel::Sql),
        2 => Ok(EntityStorageModel::NoSql),
        3 => Ok(EntityStorageModel::Graph),
        4 => Ok(EntityStorageModel::Vector),
        5 => Ok(EntityStorageModel::FullText),
        6 => Ok(EntityStorageModel::Hybrid),
        _ => corrupt(path, &format!("invalid entity storage model tag {tag}")),
    }
}

fn tag_to_compression(tag: u8, path: &Path) -> Result<Compression> {
    match tag {
        0 => Ok(Compression::None),
        1 => Ok(Compression::Lz4),
        2 => Ok(Compression::Zstd),
        _ => corrupt(path, &format!("invalid compression tag {tag}")),
    }
}

fn malformed(path: &Path, reason: &str) -> PraxisError {
    PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    }
}

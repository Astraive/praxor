mod prepare;
#[cfg(test)]
mod publication_tests;
pub mod schema;

pub use schema::{
    AttributeSchema, AttributeType, BitType, Catalog, CollectionSchema, CollectionType,
    DistanceMetric, EmbeddingModelConfig, EmbeddingOptions, EmbeddingProvider, FloatType,
    FullTextOptions, GeoType, GraphOptions, IntegerType, NetworkType, PitRefType, ScalarType,
    StorageClass, TemporalType, TimeSeriesOptions, VectorOptions,
};

use crate::config::Compression;
use crate::errors::{PraxisError, Result};
use crate::identity::{Aid, Cid, Did, Eid};
use crate::io::{BinaryReader, BinaryWriter, crc32c};
use crate::layout::PraxisLayout;
use crate::record::PageDatabase;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const CATALOG_MAGIC: u32 = 0x5443_4154;
const CATALOG_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EntityStorageModel {
    Sql,
    NoSql,
    Graph,
    Vector,
    FullText,
    Hybrid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CollectionCatalogEntry {
    pub cid: Cid,
    pub name: String,
    pub retention_policy: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EntityCatalogEntry {
    pub cid: Cid,
    pub eid: Eid,
    pub name: String,
    pub storage_model: EntityStorageModel,
    pub primary_key: Option<String>,
    pub compression: Compression,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixedAttributeCatalogEntry {
    pub eid: Eid,
    pub aid: Aid,
    pub name: String,
    pub type_code: u8,
    pub nullable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DynamicAttributeCatalogEntry {
    pub eid: Eid,
    pub did: Did,
    pub name: String,
    pub inferred_type_code: Option<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexCatalogEntry {
    pub eid: Eid,
    pub index_id: u32,
    pub name: String,
    pub kind: String,
    pub pointer_target: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VectorModelCatalogEntry {
    pub model_id: u32,
    pub name: String,
    pub dimensions: u32,
    pub metric: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FullTextCatalogEntry {
    pub eid: Eid,
    pub analyzer: String,
    pub language: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GraphCatalogEntry {
    pub eid: Eid,
    pub edge_label: String,
    pub directed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShardCatalogEntry {
    pub shard_id: u32,
    pub cid: Cid,
    pub range_start: String,
    pub range_end: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserCatalogEntry {
    pub user_id: u32,
    pub name: String,
    pub role: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogSnapshot {
    pub collections: Vec<CollectionCatalogEntry>,
    pub entities: Vec<EntityCatalogEntry>,
    pub fixed_attributes: Vec<FixedAttributeCatalogEntry>,
    pub dynamic_attributes: Vec<DynamicAttributeCatalogEntry>,
    pub indexes: Vec<IndexCatalogEntry>,
    pub vector_models: Vec<VectorModelCatalogEntry>,
    pub fulltext: Vec<FullTextCatalogEntry>,
    pub graph: Vec<GraphCatalogEntry>,
    pub shards: Vec<ShardCatalogEntry>,
    pub users: Vec<UserCatalogEntry>,
}

#[derive(Clone, Debug)]
pub struct CatalogStore {
    database: PageDatabase,
}

impl CatalogStore {
    pub fn open(base: impl Into<PathBuf>) -> Result<Self> {
        Ok(Self::new(PageDatabase::open(base)?))
    }

    /// Share the supplied page owner without opening or initializing storage.
    pub fn new(database: PageDatabase) -> Self {
        Self { database }
    }

    pub fn layout(&self) -> &PraxisLayout {
        self.database.layout()
    }

    pub fn save(&self, snapshot: &CatalogSnapshot) -> Result<()> {
        self.save_prepared(snapshot, prepare::PreparedCatalogSave::publish)
    }

    fn save_prepared(
        &self,
        snapshot: &CatalogSnapshot,
        publish: impl FnOnce(prepare::PreparedCatalogSave) -> Result<()>,
    ) -> Result<()> {
        self.database.with_root_mutation(
            |layout| prepare::prepare_catalog(snapshot, layout),
            |_, prepared| publish(prepared),
        )
    }
    pub fn load(&self) -> Result<CatalogSnapshot> {
        self.database.with_root_read(load_snapshot)
    }
}
fn load_snapshot(layout: &PraxisLayout) -> Result<CatalogSnapshot> {
    Ok(CatalogSnapshot {
        collections: read_if_exists(
            &layout.catalog_root().join("collections.cat"),
            decode_collections,
        )?,
        entities: read_if_exists(&layout.catalog_root().join("entities.cat"), decode_entities)?,
        fixed_attributes: read_if_exists(
            &layout.catalog_root().join("fixed_attrs.cat"),
            decode_fixed_attrs,
        )?,
        dynamic_attributes: read_if_exists(
            &layout.catalog_root().join("dynamic_attrs.cat"),
            decode_dynamic_attrs,
        )?,
        indexes: read_if_exists(&layout.catalog_root().join("indexes.cat"), decode_indexes)?,
        vector_models: read_if_exists(
            &layout.catalog_root().join("vector_models.cat"),
            decode_vector_models,
        )?,
        fulltext: read_if_exists(&layout.catalog_root().join("fulltext.cat"), decode_fulltext)?,
        graph: read_if_exists(&layout.catalog_root().join("graph.cat"), decode_graph)?,
        shards: read_if_exists(&layout.catalog_root().join("shards.cat"), decode_shards)?,
        users: read_if_exists(&layout.catalog_root().join("users.cat"), decode_users)?,
    })
}

fn write_catalog(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, bytes)?;
    #[cfg(windows)]
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    std::fs::rename(tmp_path, path)?;
    Ok(())
}
fn read_catalog(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    if bytes.len() < 13 {
        return corrupt(path, "truncated catalog file");
    }
    if u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != CATALOG_MAGIC {
        return corrupt(path, "bad catalog magic");
    }
    if bytes[4] != CATALOG_VERSION {
        return corrupt(path, &format!("unsupported catalog version {}", bytes[4]));
    }
    let len = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
    let expected = u32::from_le_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]);
    if bytes.len() < 13 + len {
        return corrupt(path, "truncated catalog payload");
    }
    let payload = bytes[13..13 + len].to_vec();
    let actual = crc32c(&payload);
    if actual != expected {
        return corrupt(
            path,
            &format!("catalog checksum mismatch: expected {expected:#010x}, got {actual:#010x}"),
        );
    }
    Ok(payload)
}

fn read_if_exists<T>(path: &Path, decode: fn(&[u8], &Path) -> Result<Vec<T>>) -> Result<Vec<T>> {
    if path.exists() && path.metadata()?.len() > 0 {
        decode(&read_catalog(path)?, path)
    } else {
        Ok(Vec::new())
    }
}

fn encode_collections(entries: &[CollectionCatalogEntry]) -> Vec<u8> {
    let mut writer = BinaryWriter::new();
    writer.write_u32(entries.len() as u32);
    for entry in entries {
        writer.write_u32(entry.cid.0);
        writer.write_len_bytes(entry.name.as_bytes());
        writer.write_len_bytes(
            entry
                .retention_policy
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        );
    }
    writer.into_inner()
}

fn decode_collections(bytes: &[u8], path: &Path) -> Result<Vec<CollectionCatalogEntry>> {
    let mut reader = BinaryReader::new(bytes, path.to_path_buf());
    let count = reader.read_u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(CollectionCatalogEntry {
            cid: Cid(reader.read_u32()?),
            name: read_string(&mut reader)?,
            retention_policy: empty_to_none(read_string(&mut reader)?),
        });
    }
    Ok(out)
}

fn encode_entities(entries: &[EntityCatalogEntry]) -> Vec<u8> {
    let mut writer = BinaryWriter::new();
    writer.write_u32(entries.len() as u32);
    for entry in entries {
        writer.write_u32(entry.cid.0);
        writer.write_u32(entry.eid.0);
        writer.write_len_bytes(entry.name.as_bytes());
        writer.write_u8(storage_model_to_tag(entry.storage_model));
        writer.write_len_bytes(entry.primary_key.as_deref().unwrap_or_default().as_bytes());
        writer.write_u8(compression_to_tag(entry.compression));
    }
    writer.into_inner()
}

fn decode_entities(bytes: &[u8], path: &Path) -> Result<Vec<EntityCatalogEntry>> {
    let mut reader = BinaryReader::new(bytes, path.to_path_buf());
    let count = reader.read_u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(EntityCatalogEntry {
            cid: Cid(reader.read_u32()?),
            eid: Eid(reader.read_u32()?),
            name: read_string(&mut reader)?,
            storage_model: tag_to_storage_model(reader.read_u8()?, path)?,
            primary_key: empty_to_none(read_string(&mut reader)?),
            compression: tag_to_compression(reader.read_u8()?, path)?,
        });
    }
    Ok(out)
}

fn encode_fixed_attrs(entries: &[FixedAttributeCatalogEntry]) -> Vec<u8> {
    let mut writer = BinaryWriter::new();
    writer.write_u32(entries.len() as u32);
    for entry in entries {
        writer.write_u32(entry.eid.0);
        writer.write_u32(entry.aid.0 as u32);
        writer.write_len_bytes(entry.name.as_bytes());
        writer.write_u8(entry.type_code);
        writer.write_u8(u8::from(entry.nullable));
    }
    writer.into_inner()
}

fn decode_fixed_attrs(bytes: &[u8], path: &Path) -> Result<Vec<FixedAttributeCatalogEntry>> {
    let mut reader = BinaryReader::new(bytes, path.to_path_buf());
    let count = reader.read_u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(FixedAttributeCatalogEntry {
            eid: Eid(reader.read_u32()?),
            aid: Aid(reader.read_u32()? as u16),
            name: read_string(&mut reader)?,
            type_code: reader.read_u8()?,
            nullable: reader.read_u8()? != 0,
        });
    }
    Ok(out)
}

fn encode_dynamic_attrs(entries: &[DynamicAttributeCatalogEntry]) -> Vec<u8> {
    let mut writer = BinaryWriter::new();
    writer.write_u32(entries.len() as u32);
    for entry in entries {
        writer.write_u32(entry.eid.0);
        writer.write_u32(entry.did.0 as u32);
        writer.write_len_bytes(entry.name.as_bytes());
        writer.write_u8(u8::from(entry.inferred_type_code.is_some()));
        writer.write_u8(entry.inferred_type_code.unwrap_or_default());
    }
    writer.into_inner()
}

fn decode_dynamic_attrs(bytes: &[u8], path: &Path) -> Result<Vec<DynamicAttributeCatalogEntry>> {
    let mut reader = BinaryReader::new(bytes, path.to_path_buf());
    let count = reader.read_u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let eid = Eid(reader.read_u32()?);
        let did = Did(reader.read_u32()? as u16);
        let name = read_string(&mut reader)?;
        let has_type = reader.read_u8()? != 0;
        let type_code = reader.read_u8()?;
        out.push(DynamicAttributeCatalogEntry {
            eid,
            did,
            name,
            inferred_type_code: has_type.then_some(type_code),
        });
    }
    Ok(out)
}

fn encode_indexes(entries: &[IndexCatalogEntry]) -> Vec<u8> {
    let mut writer = BinaryWriter::new();
    writer.write_u32(entries.len() as u32);
    for entry in entries {
        writer.write_u32(entry.eid.0);
        writer.write_u32(entry.index_id);
        writer.write_len_bytes(entry.name.as_bytes());
        writer.write_len_bytes(entry.kind.as_bytes());
        writer.write_len_bytes(entry.pointer_target.as_bytes());
    }
    writer.into_inner()
}

fn decode_indexes(bytes: &[u8], path: &Path) -> Result<Vec<IndexCatalogEntry>> {
    let mut reader = BinaryReader::new(bytes, path.to_path_buf());
    let count = reader.read_u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(IndexCatalogEntry {
            eid: Eid(reader.read_u32()?),
            index_id: reader.read_u32()?,
            name: read_string(&mut reader)?,
            kind: read_string(&mut reader)?,
            pointer_target: read_string(&mut reader)?,
        });
    }
    Ok(out)
}

fn encode_vector_models(entries: &[VectorModelCatalogEntry]) -> Vec<u8> {
    let mut writer = BinaryWriter::new();
    writer.write_u32(entries.len() as u32);
    for entry in entries {
        writer.write_u32(entry.model_id);
        writer.write_len_bytes(entry.name.as_bytes());
        writer.write_u32(entry.dimensions);
        writer.write_len_bytes(entry.metric.as_bytes());
    }
    writer.into_inner()
}

fn decode_vector_models(bytes: &[u8], path: &Path) -> Result<Vec<VectorModelCatalogEntry>> {
    let mut reader = BinaryReader::new(bytes, path.to_path_buf());
    let count = reader.read_u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(VectorModelCatalogEntry {
            model_id: reader.read_u32()?,
            name: read_string(&mut reader)?,
            dimensions: reader.read_u32()?,
            metric: read_string(&mut reader)?,
        });
    }
    Ok(out)
}

fn encode_fulltext(entries: &[FullTextCatalogEntry]) -> Vec<u8> {
    let mut writer = BinaryWriter::new();
    writer.write_u32(entries.len() as u32);
    for entry in entries {
        writer.write_u32(entry.eid.0);
        writer.write_len_bytes(entry.analyzer.as_bytes());
        writer.write_len_bytes(entry.language.as_bytes());
    }
    writer.into_inner()
}

fn decode_fulltext(bytes: &[u8], path: &Path) -> Result<Vec<FullTextCatalogEntry>> {
    let mut reader = BinaryReader::new(bytes, path.to_path_buf());
    let count = reader.read_u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(FullTextCatalogEntry {
            eid: Eid(reader.read_u32()?),
            analyzer: read_string(&mut reader)?,
            language: read_string(&mut reader)?,
        });
    }
    Ok(out)
}

fn encode_graph(entries: &[GraphCatalogEntry]) -> Vec<u8> {
    let mut writer = BinaryWriter::new();
    writer.write_u32(entries.len() as u32);
    for entry in entries {
        writer.write_u32(entry.eid.0);
        writer.write_len_bytes(entry.edge_label.as_bytes());
        writer.write_u8(u8::from(entry.directed));
    }
    writer.into_inner()
}

fn decode_graph(bytes: &[u8], path: &Path) -> Result<Vec<GraphCatalogEntry>> {
    let mut reader = BinaryReader::new(bytes, path.to_path_buf());
    let count = reader.read_u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(GraphCatalogEntry {
            eid: Eid(reader.read_u32()?),
            edge_label: read_string(&mut reader)?,
            directed: reader.read_u8()? != 0,
        });
    }
    Ok(out)
}

fn encode_shards(entries: &[ShardCatalogEntry]) -> Vec<u8> {
    let mut writer = BinaryWriter::new();
    writer.write_u32(entries.len() as u32);
    for entry in entries {
        writer.write_u32(entry.shard_id);
        writer.write_u32(entry.cid.0);
        writer.write_len_bytes(entry.range_start.as_bytes());
        writer.write_len_bytes(entry.range_end.as_bytes());
    }
    writer.into_inner()
}

fn decode_shards(bytes: &[u8], path: &Path) -> Result<Vec<ShardCatalogEntry>> {
    let mut reader = BinaryReader::new(bytes, path.to_path_buf());
    let count = reader.read_u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(ShardCatalogEntry {
            shard_id: reader.read_u32()?,
            cid: Cid(reader.read_u32()?),
            range_start: read_string(&mut reader)?,
            range_end: read_string(&mut reader)?,
        });
    }
    Ok(out)
}

fn encode_users(entries: &[UserCatalogEntry]) -> Vec<u8> {
    let mut writer = BinaryWriter::new();
    writer.write_u32(entries.len() as u32);
    for entry in entries {
        writer.write_u32(entry.user_id);
        writer.write_len_bytes(entry.name.as_bytes());
        writer.write_len_bytes(entry.role.as_bytes());
    }
    writer.into_inner()
}

fn decode_users(bytes: &[u8], path: &Path) -> Result<Vec<UserCatalogEntry>> {
    let mut reader = BinaryReader::new(bytes, path.to_path_buf());
    let count = reader.read_u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(UserCatalogEntry {
            user_id: reader.read_u32()?,
            name: read_string(&mut reader)?,
            role: read_string(&mut reader)?,
        });
    }
    Ok(out)
}

fn read_string(reader: &mut BinaryReader<'_>) -> Result<String> {
    let bytes = reader.read_len_bytes()?;
    String::from_utf8(bytes).map_err(|err| PraxisError::InvalidConfig(err.to_string()))
}

fn empty_to_none(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn storage_model_to_tag(model: EntityStorageModel) -> u8 {
    match model {
        EntityStorageModel::Sql => 1,
        EntityStorageModel::NoSql => 2,
        EntityStorageModel::Graph => 3,
        EntityStorageModel::Vector => 4,
        EntityStorageModel::FullText => 5,
        EntityStorageModel::Hybrid => 6,
    }
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

fn compression_to_tag(compression: Compression) -> u8 {
    match compression {
        Compression::None => 0,
        Compression::Lz4 => 1,
        Compression::Zstd => 2,
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

fn corrupt<T>(path: &Path, reason: &str) -> Result<T> {
    Err(PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    })
}

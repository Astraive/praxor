mod decode;
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
use crate::io::{BinaryWriter, crc32c};
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
        self.database.with_root_read(decode::load_snapshot)
    }
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

fn compression_to_tag(compression: Compression) -> u8 {
    match compression {
        Compression::None => 0,
        Compression::Lz4 => 1,
        Compression::Zstd => 2,
    }
}

fn corrupt<T>(path: &Path, reason: &str) -> Result<T> {
    Err(PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    })
}

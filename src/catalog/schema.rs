use crate::document::Record;
use crate::errors::{PraxisError, Result};
use crate::query::AlterAction;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum DistanceMetric {
    #[default]
    Cosine,
    Dot,
    Euclidean,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Catalog {
    collections: BTreeMap<String, CollectionSchema>,
}

impl Catalog {
    pub fn new() -> Self {
        Self {
            collections: BTreeMap::new(),
        }
    }

    pub fn create_collection(&mut self, schema: CollectionSchema) -> Result<()> {
        if self.collections.contains_key(&schema.name) {
            return Err(PraxisError::Catalog(format!(
                "collection '{}' already exists",
                schema.name
            )));
        }
        self.collections.insert(schema.name.clone(), schema);
        Ok(())
    }

    pub fn collection(&self, name: &str) -> Result<&CollectionSchema> {
        self.collections
            .get(name)
            .ok_or_else(|| PraxisError::Catalog(format!("collection '{name}' not found")))
    }

    pub fn drop_collection(&mut self, name: &str) -> Result<()> {
        if self.collections.remove(name).is_none() {
            return Err(PraxisError::Catalog(format!(
                "collection '{name}' not found"
            )));
        }
        Ok(())
    }

    pub fn alter_collection(&mut self, name: &str, actions: &[AlterAction]) -> Result<()> {
        let schema = self
            .collections
            .get_mut(name)
            .ok_or_else(|| PraxisError::Catalog(format!("collection '{name}' not found")))?;
        for action in actions {
            match action {
                AlterAction::AddAttribute {
                    name: attr_name,
                    type_name,
                    nullable,
                } => {
                    let attr_type = AttributeType::from_type_name(type_name);
                    schema.attributes.insert(
                        attr_name.clone(),
                        AttributeSchema {
                            name: attr_name.clone(),
                            attribute_type: attr_type,
                            nullable: *nullable,
                            indexed: false,
                        },
                    );
                }
                AlterAction::DropAttribute { name: attr_name } => {
                    schema.attributes.remove(attr_name);
                }
            }
        }
        Ok(())
    }

    pub fn collections(&self) -> impl Iterator<Item = &CollectionSchema> {
        self.collections.values()
    }

    /// Preserve the map key alongside its schema for admission checks before
    /// a detached query authority can rekey schemas by `schema.name`.
    pub(crate) fn collection_entries(&self) -> impl Iterator<Item = (&str, &CollectionSchema)> {
        self.collections
            .iter()
            .map(|(name, schema)| (name.as_str(), schema))
    }

    pub fn validate_record(&self, record: &Record) -> Result<()> {
        self.collection(&record.id.collection)?
            .validate_record(record)
    }
}

impl Default for Catalog {
    fn default() -> Self {
        Self::new()
    }
}

/// Schema mode controlling how strictly the collection enforces its schema.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum SchemaMode {
    /// All attributes must be declared in the schema. Unknown attributes are rejected.
    Strict,
    /// Any attribute is allowed. Only declared attributes are validated.
    #[default]
    Loose,
    /// Declared attributes are validated (strict for those), undeclared attributes are allowed.
    Mixed,
}

/// A computed field that derives its value from other attributes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputedField {
    /// Name of the computed field.
    pub name: String,
    /// Expression to compute the value (e.g., "price * quantity", "first_name + ' ' + last_name").
    pub expression: String,
    /// The type of the computed value.
    pub result_type: AttributeType,
}

/// Schema version entry for migration history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaVersion {
    pub version: u32,
    pub timestamp_ms: u64,
    pub description: String,
    pub changes: Vec<SchemaChange>,
}

/// A single schema change in a migration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SchemaChange {
    AddAttribute {
        name: String,
        type_name: String,
        nullable: bool,
    },
    DropAttribute {
        name: String,
    },
    AlterAttribute {
        name: String,
        changes: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CollectionSchema {
    pub name: String,
    pub attributes: BTreeMap<String, AttributeSchema>,
    /// Schema enforcement mode.
    pub mode: SchemaMode,
    /// Current schema version.
    pub version: u32,
    /// Schema migration history.
    pub versions: Vec<SchemaVersion>,
    /// Computed/virtual fields derived from other attributes.
    pub computed_fields: BTreeMap<String, ComputedField>,
}

impl CollectionSchema {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            attributes: BTreeMap::new(),
            mode: SchemaMode::default(),
            version: 1,
            versions: Vec::new(),
            computed_fields: BTreeMap::new(),
        }
    }

    pub fn with_mode(mut self, mode: SchemaMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_attribute(mut self, attribute: AttributeSchema) -> Self {
        self.attributes.insert(attribute.name.clone(), attribute);
        self
    }

    pub fn with_computed(mut self, field: ComputedField) -> Self {
        self.computed_fields.insert(field.name.clone(), field);
        self
    }

    /// Bump schema version and record a migration.
    pub fn migrate(&mut self, description: impl Into<String>, changes: Vec<SchemaChange>) {
        self.version += 1;
        self.versions.push(SchemaVersion {
            version: self.version,
            timestamp_ms: now_ms(),
            description: description.into(),
            changes,
        });
    }

    /// Validate a record against this schema.
    pub fn validate_record(&self, record: &Record) -> Result<()> {
        for attribute in self.attributes.values() {
            match &attribute.attribute_type {
                AttributeType::Vector(options) => {
                    if let Some(vector) = record.vectors.get(&attribute.name) {
                        if options.enabled && vector.len() != options.dimensions {
                            return Err(PraxisError::Catalog(format!(
                                "vector '{}' expected {} dimensions but got {}",
                                attribute.name,
                                options.dimensions,
                                vector.len()
                            )));
                        }
                    } else if !attribute.nullable {
                        return Err(PraxisError::Catalog(format!(
                            "required vector '{}' missing",
                            attribute.name
                        )));
                    }
                }
                AttributeType::Embedding(options) => {
                    if let Some(vector) = record.vectors.get(&attribute.name) {
                        if options.enabled && vector.len() != options.dimensions {
                            return Err(PraxisError::Catalog(format!(
                                "embedding '{}' expected {} dimensions but got {}",
                                attribute.name,
                                options.dimensions,
                                vector.len()
                            )));
                        }
                    } else if !attribute.nullable {
                        return Err(PraxisError::Catalog(format!(
                            "required embedding '{}' missing",
                            attribute.name
                        )));
                    }
                }
                attribute_type => {
                    let Some(value) = record.attributes.get(&attribute.name) else {
                        if attribute.nullable {
                            continue;
                        }
                        return Err(PraxisError::Catalog(format!(
                            "required attribute '{}' missing",
                            attribute.name
                        )));
                    };
                    if !attribute_type.accepts_json(value) {
                        return Err(PraxisError::Catalog(format!(
                            "attribute '{}' does not match {:?}",
                            attribute.name, attribute_type
                        )));
                    }
                }
            }
        }

        // In Strict mode, reject unknown attributes
        if self.mode == SchemaMode::Strict {
            for key in record.attributes.keys() {
                if !self.attributes.contains_key(key) && !self.computed_fields.contains_key(key) {
                    return Err(PraxisError::Catalog(format!(
                        "strict mode: unknown attribute '{}' on collection '{}'",
                        key, self.name
                    )));
                }
            }
        }

        Ok(())
    }

    /// Evaluate computed fields for a record.
    pub fn evaluate_computed(&self, record: &mut Record) {
        for field in self.computed_fields.values() {
            if let Some(value) = evaluate_expression(&field.expression, record) {
                record.attributes.insert(field.name.clone(), value);
            }
        }
    }
}

/// Simple expression evaluator for computed fields.
/// Supports: attribute references, basic arithmetic (+, -, *, /), string concatenation.
fn evaluate_expression(expr: &str, record: &Record) -> Option<Value> {
    let expr = expr.trim();

    // Simple attribute reference: just a field name
    if let Some(value) = record.attributes.get(expr) {
        return Some(value.clone());
    }

    // String concatenation: "field1 + ' ' + field2"
    if expr.contains('+') && (expr.contains('\'') || expr.contains('"')) {
        let parts: Vec<&str> = expr.split('+').map(|s| s.trim()).collect();
        let mut result = String::new();
        for part in parts {
            let part = part.trim().trim_matches('\'').trim_matches('"');
            if let Some(value) = record.attributes.get(part) {
                match value {
                    Value::String(s) => result.push_str(s),
                    Value::Number(n) => result.push_str(&n.to_string()),
                    Value::Bool(b) => result.push_str(&b.to_string()),
                    _ => result.push_str(&value.to_string()),
                }
            } else {
                result.push_str(part);
            }
        }
        return Some(Value::String(result));
    }

    // Arithmetic: "field1 * field2" or "field1 + 100"
    for op in &["*", "/", "-", "+"] {
        if let Some((left, right)) = expr.split_once(op) {
            let left = left.trim();
            let right = right.trim();
            let left_val = resolve_numeric(left, record);
            let right_val = resolve_numeric(right, record);
            if let (Some(l), Some(r)) = (left_val, right_val) {
                let result = match *op {
                    "+" => l + r,
                    "-" => l - r,
                    "*" => l * r,
                    "/" if r != 0.0 => l / r,
                    "/" => 0.0,
                    _ => 0.0,
                };
                return Some(Value::from(result));
            }
        }
    }

    None
}

fn resolve_numeric(expr: &str, record: &Record) -> Option<f64> {
    let expr = expr.trim();
    if let Ok(n) = expr.parse::<f64>() {
        return Some(n);
    }
    record.attributes.get(expr).and_then(|v| v.as_f64())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttributeSchema {
    pub name: String,
    pub attribute_type: AttributeType,
    pub nullable: bool,
    pub indexed: bool,
}

impl AttributeSchema {
    pub fn new(name: impl Into<String>, attribute_type: AttributeType) -> Self {
        Self {
            name: name.into(),
            attribute_type,
            nullable: true,
            indexed: false,
        }
    }

    pub fn indexed(mut self) -> Self {
        self.indexed = true;
        self
    }

    pub fn required(mut self) -> Self {
        self.nullable = false;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttributeType {
    Scalar(ScalarType),
    Integer(IntegerType),
    Float(FloatType),
    Numeric,
    Boolean,
    Text,
    Json,
    Jsonb,
    Uuid,
    Temporal(TemporalType),
    Binary,
    Collection(CollectionType),
    Range(Box<AttributeType>),
    Money(Option<String>),
    Enum(String),
    Bit(BitType),
    Document,
    Vector(VectorOptions),
    Embedding(EmbeddingOptions),
    SparseVector,
    Graph(GraphOptions),
    EdgeRef,
    EdgeList,
    Path,
    Subgraph,
    FullText(FullTextOptions),
    TimeSeries(TimeSeriesOptions),
    Geo(GeoType),
    Network(NetworkType),
    PitRef(PitRefType),
    RidRef(String),
    KeyValue,
}

impl AttributeType {
    pub fn storage_class(&self) -> StorageClass {
        match self {
            AttributeType::Scalar(_)
            | AttributeType::Integer(_)
            | AttributeType::Float(_)
            | AttributeType::Boolean
            | AttributeType::Uuid
            | AttributeType::Temporal(_)
            | AttributeType::Range(_)
            | AttributeType::Money(_)
            | AttributeType::Enum(_)
            | AttributeType::Bit(BitType::Fixed(_))
            | AttributeType::Geo(GeoType::Point)
            | AttributeType::Network(_)
            | AttributeType::PitRef(_)
            | AttributeType::RidRef(_) => StorageClass::Inline,
            AttributeType::Numeric
            | AttributeType::Text
            | AttributeType::Json
            | AttributeType::Jsonb
            | AttributeType::Binary
            | AttributeType::Collection(_)
            | AttributeType::Bit(BitType::Variable(_))
            | AttributeType::Document
            | AttributeType::Path
            | AttributeType::Subgraph
            | AttributeType::Geo(GeoType::Shape)
            | AttributeType::KeyValue => StorageClass::External,
            AttributeType::Vector(_)
            | AttributeType::Embedding(_)
            | AttributeType::SparseVector
            | AttributeType::Graph(_)
            | AttributeType::EdgeRef
            | AttributeType::EdgeList
            | AttributeType::FullText(_)
            | AttributeType::TimeSeries(_) => StorageClass::Segment,
        }
    }

    pub fn accepts_json(&self, value: &Value) -> bool {
        match self {
            AttributeType::Scalar(scalar) => scalar.accepts_json(value),
            AttributeType::Integer(_) => value.as_i64().is_some() || value.as_u64().is_some(),
            AttributeType::Float(_) | AttributeType::Numeric | AttributeType::Money(_) => {
                value.is_number()
            }
            AttributeType::Boolean => value.is_boolean(),
            AttributeType::Text
            | AttributeType::Uuid
            | AttributeType::Enum(_)
            | AttributeType::Bit(_)
            | AttributeType::PitRef(_)
            | AttributeType::RidRef(_)
            | AttributeType::Network(_) => value.is_string(),
            AttributeType::Json | AttributeType::Jsonb => true,
            AttributeType::Temporal(_) => value.is_string() || value.is_number(),
            AttributeType::Binary => value.is_string(),
            AttributeType::Collection(CollectionType::List(_))
            | AttributeType::Collection(CollectionType::Set(_)) => value.is_array(),
            AttributeType::Collection(CollectionType::Dict(_, _)) => value.is_object(),
            AttributeType::Range(_) => value.is_object() || value.is_array(),
            AttributeType::Document => value.is_object() || value.is_array(),
            AttributeType::Vector(_)
            | AttributeType::Embedding(_)
            | AttributeType::SparseVector => false,
            AttributeType::Graph(_)
            | AttributeType::EdgeRef
            | AttributeType::EdgeList
            | AttributeType::Path
            | AttributeType::Subgraph => value.is_object() || value.is_array() || value.is_string(),
            AttributeType::FullText(_) => value.is_string(),
            AttributeType::TimeSeries(_) => value.is_number() || value.is_string(),
            AttributeType::Geo(GeoType::Point) => value
                .as_object()
                .map(|object| object.contains_key("latitude") && object.contains_key("longitude"))
                .unwrap_or(false),
            AttributeType::Geo(GeoType::Shape) => value.is_object(),
            AttributeType::KeyValue => !value.is_null(),
        }
    }

    pub fn from_type_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "string" | "text" => AttributeType::Text,
            "int" | "integer" => AttributeType::Integer(IntegerType::Int8),
            "int2" | "smallint" => AttributeType::Integer(IntegerType::Int2),
            "int4" => AttributeType::Integer(IntegerType::Int4),
            "int8" | "bigint" => AttributeType::Integer(IntegerType::Int8),
            "float" | "float8" | "double" => AttributeType::Float(FloatType::Float8),
            "float4" | "real" => AttributeType::Float(FloatType::Float4),
            "bool" | "boolean" => AttributeType::Boolean,
            "json" => AttributeType::Json,
            "jsonb" => AttributeType::Jsonb,
            "uuid" => AttributeType::Uuid,
            "timestamp" => AttributeType::Temporal(TemporalType::Timestamp),
            "date" => AttributeType::Temporal(TemporalType::Date),
            "time" => AttributeType::Temporal(TemporalType::Time),
            "binary" | "bytes" => AttributeType::Binary,
            "document" => AttributeType::Document,
            "sparse_vector" => AttributeType::SparseVector,
            "keyvalue" | "kv" => AttributeType::KeyValue,
            _ => AttributeType::Text, // default to text for unknown types
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum StorageClass {
    Inline,
    External,
    Segment,
    Catalog,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntegerType {
    Int2,
    Int4,
    Int8,
    Uint8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FloatType {
    Float4,
    Float8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TemporalType {
    Date,
    Time,
    TimeTz,
    Timestamp,
    TimestampTz,
    Interval,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CollectionType {
    List(Box<AttributeType>),
    Set(Box<AttributeType>),
    Dict(Box<AttributeType>, Box<AttributeType>),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BitType {
    Fixed(u32),
    Variable(u32),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum GeoType {
    Point,
    Shape,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkType {
    Cidr,
    Inet,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PitRefType {
    Commit,
    Branch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScalarType {
    Boolean,
    Integer,
    Float,
    Text,
    Bytes,
    Timestamp,
}

impl ScalarType {
    pub fn accepts_json(&self, value: &Value) -> bool {
        match self {
            ScalarType::Boolean => value.is_boolean(),
            ScalarType::Integer => value.as_i64().is_some() || value.as_u64().is_some(),
            ScalarType::Float => value.is_number(),
            ScalarType::Text => value.is_string(),
            ScalarType::Bytes => value.is_string(),
            ScalarType::Timestamp => value.is_string() || value.is_number(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VectorOptions {
    pub dimensions: usize,
    pub metric: DistanceMetric,
    pub enabled: bool,
    pub embedding: EmbeddingModelConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmbeddingOptions {
    pub dimensions: usize,
    pub model: String,
    pub metric: DistanceMetric,
    pub enabled: bool,
    pub provider: EmbeddingProvider,
    pub source_attribute: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmbeddingModelConfig {
    pub provider: EmbeddingProvider,
    pub model: String,
    pub source_attribute: Option<String>,
}

impl EmbeddingModelConfig {
    pub fn best_local_default(dimensions: usize) -> Self {
        Self {
            provider: EmbeddingProvider::Local,
            model: default_local_embedding_model(dimensions).into(),
            source_attribute: None,
        }
    }

    pub fn api(
        provider: impl Into<String>,
        model: impl Into<String>,
        source_attribute: Option<String>,
    ) -> Self {
        Self {
            provider: EmbeddingProvider::Api {
                provider: provider.into(),
            },
            model: model.into(),
            source_attribute,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EmbeddingProvider {
    Local,
    Api { provider: String },
}

fn default_local_embedding_model(dimensions: usize) -> &'static str {
    match dimensions {
        0..=384 => "praxis-local-minilm-l6-v2",
        385..=768 => "praxis-local-e5-base-v2",
        _ => "praxis-local-bge-large-en-v1.5",
    }
}

#[cfg(test)]
mod catalog_entry_tests {
    use super::{Catalog, CollectionSchema};

    #[test]
    fn deserialized_entry_exposes_original_collection_map_key() {
        let serialized = serde_json::json!({
            "collections": {
                "wrong-key": CollectionSchema::new("canonical")
            }
        });
        let catalog: Catalog = serde_json::from_value(serialized).unwrap();

        let entries: Vec<_> = catalog
            .collection_entries()
            .map(|(key, schema)| (key, schema.name.as_str()))
            .collect();

        assert_eq!(entries, vec![("wrong-key", "canonical")]);
    }

    #[test]
    fn deserialized_entries_preserve_duplicate_schema_names_under_distinct_keys() {
        let schema = CollectionSchema::new("logical");
        let serialized = serde_json::json!({
            "collections": {
                "logical": schema,
                "shadow": schema
            }
        });
        let catalog: Catalog = serde_json::from_value(serialized).unwrap();

        let entries: Vec<_> = catalog
            .collection_entries()
            .map(|(key, schema)| (key, schema.name.as_str()))
            .collect();

        assert_eq!(entries, vec![("logical", "logical"), ("shadow", "logical")]);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FullTextOptions {
    pub source_attribute: String,
    pub bm25_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphOptions {
    pub directed: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeSeriesOptions {
    pub timestamp_attribute: String,
    pub retention_days: Option<u32>,
}

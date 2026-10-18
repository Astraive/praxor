//! Scan-only, retained-view query gateway for a controlled v1 fixture root.

use super::compile::{
    BoundSelect, CompileInput, CompiledStatement, ExplainV1, ProjectedRow, QueryCatalogAuthority,
    QueryCatalogView, QueryCompileError, TypedParameters, compile, execute_in_memory,
};
use super::fixture_v1::{
    FixtureBudgetDecodeError, FixtureDecodeReason, decode_document_with_attribute_budget,
};
use crate::PraxisError;
use crate::catalog::schema::{AttributeType, Catalog, IntegerType, ScalarType, SchemaMode};
use crate::core_records::{
    CoreDatabase, CoreRecordScanError, CoreRecordSnapshot, CoreRecordStore, RecordScanLimits,
};
use crate::document::{Record, RecordId as LogicalRecordId};
use crate::store::RecordId as CoreRecordId;
use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

const MAX_COLLECTIONS: usize = 16;
const MAX_COLLECTION_NAME_BYTES: usize = 255;
const MAX_TOTAL_COLLECTION_NAME_BYTES: usize = 4_096;
const MAX_DECLARED_ATTRIBUTES: usize = 256;
const MAX_ATTRIBUTE_NAME_BYTES: usize = 128;
const MAX_TOTAL_ATTRIBUTE_NAME_BYTES: usize = 16_384;
const MAX_DECODED_ATTRIBUTE_ENTRIES: usize = 65_536;
const MAX_LOGICAL_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
struct GatewayLimits {
    decoded_attribute_entries: usize,
    logical_output_bytes: u64,
}

impl Default for GatewayLimits {
    fn default() -> Self {
        Self {
            decoded_attribute_entries: MAX_DECODED_ATTRIBUTE_ENTRIES,
            logical_output_bytes: MAX_LOGICAL_OUTPUT_BYTES,
        }
    }
}

/// Explicitly attached to a controlled v1 fixture root, with one fixed
/// process-local Loose catalog. Attachment does not validate stored rows.
pub struct QueryGateway {
    records: CoreRecordStore,
    catalog: QueryCatalogAuthority,
    identity: Arc<()>,
    limits: GatewayLimits,
    #[cfg(test)]
    test_hooks: GatewayTestHooks,
}

/// Opaque retained row/catalog capability; clones share one core pin.
#[derive(Clone)]
pub struct QueryReadView {
    core: CoreRecordSnapshot,
    catalog: QueryCatalogView,
    identity: Arc<()>,
    // Clones carry the same read identity for Stage 3d's synthetic certificate.
    read_identity: Arc<()>,
}

impl fmt::Debug for QueryReadView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryReadView").finish_non_exhaustive()
    }
}

/// Complete query outcome, with no partial row success on a late fault.
pub enum QueryResult {
    Rows(Vec<ProjectedRow>),
    Explain(ExplainV1),
}

impl fmt::Debug for QueryResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rows(rows) => f.debug_tuple("Rows").field(&rows.len()).finish(),
            Self::Explain(explain) => f.debug_tuple("Explain").field(explain).finish(),
        }
    }
}

/// Typed refusal or failure from the controlled fixture gateway.
#[derive(Debug, thiserror::Error)]
pub enum QueryReadError {
    #[error("fixture catalog invalid: {code}")]
    FixtureCatalog { code: &'static str },
    #[error("query view belongs to another gateway")]
    ForeignGateway,
    #[error("query compilation failed: {0}")]
    Compile(#[source] QueryCompileError),
    #[error("query storage read failed: {0}")]
    Storage(#[source] PraxisError),
    #[error("invalid fixture document at physical {core_rid}: {reason:?}")]
    Document {
        core_rid: CoreRecordId,
        reason: FixtureDecodeReason,
    },
    #[error("duplicate fixture logical ID at physical {core_rid}")]
    DuplicateLogicalId { core_rid: CoreRecordId },
    #[error("query resource limit exceeded: {code}")]
    ResourceLimit { code: &'static str },
}

#[cfg(test)]
#[derive(Default)]
struct GatewayTestHooks {
    scan_calls: std::sync::atomic::AtomicUsize,
    before_final: parking_lot::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

fn fixture_catalog_error(code: &'static str) -> QueryReadError {
    QueryReadError::FixtureCatalog { code }
}

/// Admission is over raw stored map entries, before the Q1 authority rekeys by
/// schema name. This fixed Loose catalog is process-local binding metadata.
fn admit_catalog(catalog: &Catalog) -> Result<(), QueryReadError> {
    if catalog.collection_entries().count() > MAX_COLLECTIONS {
        return Err(fixture_catalog_error("collection_count"));
    }
    let mut collection_name_bytes = 0usize;
    let mut attribute_count = 0usize;
    let mut attribute_name_bytes = 0usize;
    for (key, schema) in catalog.collection_entries() {
        if key != schema.name {
            return Err(fixture_catalog_error("collection_key"));
        }
        if !(1..=MAX_COLLECTION_NAME_BYTES).contains(&schema.name.len())
            || schema.name.chars().any(char::is_control)
        {
            return Err(fixture_catalog_error("collection_name"));
        }
        collection_name_bytes = collection_name_bytes
            .checked_add(schema.name.len())
            .ok_or_else(|| fixture_catalog_error("collection_name_bytes"))?;
        if collection_name_bytes > MAX_TOTAL_COLLECTION_NAME_BYTES {
            return Err(fixture_catalog_error("collection_name_bytes"));
        }
        if schema.mode != SchemaMode::Loose {
            return Err(fixture_catalog_error("schema_mode"));
        }
        if schema.version != 1 {
            return Err(fixture_catalog_error("schema_version"));
        }
        if !schema.versions.is_empty() {
            return Err(fixture_catalog_error("schema_history"));
        }
        if !schema.computed_fields.is_empty() {
            return Err(fixture_catalog_error("computed_fields"));
        }
        attribute_count = attribute_count
            .checked_add(schema.attributes.len())
            .ok_or_else(|| fixture_catalog_error("attribute_count"))?;
        if attribute_count > MAX_DECLARED_ATTRIBUTES {
            return Err(fixture_catalog_error("attribute_count"));
        }
        for (attribute_key, attribute) in &schema.attributes {
            if attribute_key != &attribute.name {
                return Err(fixture_catalog_error("attribute_key"));
            }
            if !(1..=MAX_ATTRIBUTE_NAME_BYTES).contains(&attribute.name.len())
                || attribute.name.chars().any(char::is_control)
            {
                return Err(fixture_catalog_error("attribute_name"));
            }
            attribute_name_bytes = attribute_name_bytes
                .checked_add(attribute.name.len())
                .ok_or_else(|| fixture_catalog_error("attribute_name_bytes"))?;
            if attribute_name_bytes > MAX_TOTAL_ATTRIBUTE_NAME_BYTES {
                return Err(fixture_catalog_error("attribute_name_bytes"));
            }
            if attribute.indexed {
                return Err(fixture_catalog_error("indexed_attribute"));
            }
            match &attribute.attribute_type {
                AttributeType::Integer(
                    IntegerType::Int2 | IntegerType::Int4 | IntegerType::Int8 | IntegerType::Uint8,
                )
                | AttributeType::Scalar(
                    ScalarType::Integer | ScalarType::Boolean | ScalarType::Text,
                )
                | AttributeType::Boolean
                | AttributeType::Text => {}
                _ => return Err(fixture_catalog_error("attribute_type")),
            }
        }
    }
    Ok(())
}

fn scanner_error(error: CoreRecordScanError) -> QueryReadError {
    match error {
        CoreRecordScanError::Storage(error) => QueryReadError::Storage(error),
        CoreRecordScanError::ResourceLimit { code } => QueryReadError::ResourceLimit { code },
    }
}

impl QueryGateway {
    /// Attach a validated fixed catalog to an already-open core fixture root.
    /// This neither persists the catalog nor certifies existing payloads.
    pub fn attach_fixture_v1(db: &CoreDatabase, catalog: Catalog) -> Result<Self, QueryReadError> {
        admit_catalog(&catalog)?;
        Ok(Self {
            records: db.records(),
            catalog: QueryCatalogAuthority::new(catalog),
            identity: Arc::new(()),
            limits: GatewayLimits::default(),
            #[cfg(test)]
            test_hooks: GatewayTestHooks::default(),
        })
    }

    /// Register one retained core pin and capture this gateway's catalog view.
    pub fn begin_read(&self) -> Result<QueryReadView, QueryReadError> {
        let view = QueryReadView {
            core: self
                .records
                .pin_snapshot()
                .map_err(QueryReadError::Storage)?,
            catalog: self.catalog.view(),
            identity: Arc::clone(&self.identity),
            read_identity: Arc::new(()),
        };
        self.validate(&view, None, false)?;
        Ok(view)
    }

    /// Compile and evaluate one Q1 SELECT, or return a value-free EXPLAIN.
    /// Every live fixture envelope is decoded before a SELECT can return.
    pub fn query(
        &self,
        view: &QueryReadView,
        sql: &str,
        params: &TypedParameters,
    ) -> Result<QueryResult, QueryReadError> {
        self.validate(view, None, false)?;
        match compile(CompileInput::Sql(sql), params, &view.catalog)
            .map_err(QueryReadError::Compile)?
        {
            CompiledStatement::Explain(explain) => {
                self.validate(view, None, true)?;
                Ok(QueryResult::Explain(explain))
            }
            CompiledStatement::Select(bound) => {
                let rows = self.execute_bound(view, &bound)?;
                self.validate(view, Some(&bound), true)?;
                Ok(QueryResult::Rows(rows))
            }
        }
    }

    pub(crate) fn execute_bound(
        &self,
        view: &QueryReadView,
        bound: &BoundSelect,
    ) -> Result<Vec<ProjectedRow>, QueryReadError> {
        self.validate(view, Some(bound), false)?;
        let rows = self.scan_collection(view, bound.collection())?;
        self.check_logical_output_budget(
            bound,
            &rows.records,
            rows.pinned_payload_bytes,
            rows.requested_pair_bytes,
        )?;
        let projected = execute_in_memory(&self.catalog, bound, &rows.records)
            .map_err(QueryReadError::Compile)?;
        self.validate(view, Some(bound), true)?;
        Ok(projected)
    }

    /// Same ordering for public query and direct internal bound execution.
    /// The final check is the successful result's owner/catalog linearization.
    fn validate(
        &self,
        view: &QueryReadView,
        bound: Option<&BoundSelect>,
        final_check: bool,
    ) -> Result<(), QueryReadError> {
        #[cfg(test)]
        if final_check {
            let hook = self.test_hooks.before_final.lock().clone();
            if let Some(hook) = hook {
                hook();
            }
        }
        #[cfg(not(test))]
        let _ = final_check;
        // The shared read identity is intentionally opaque until Stage 3d binds
        // a synthetic candidate certificate to it.
        let _ = &view.read_identity;
        if !Arc::ptr_eq(&self.identity, &view.identity) {
            return Err(QueryReadError::ForeignGateway);
        }
        self.catalog
            .validate_view(&view.catalog)
            .map_err(QueryReadError::Compile)?;
        self.records
            .validate_snapshot(&view.core)
            .map_err(QueryReadError::Storage)?;
        if let Some(bound) = bound {
            self.catalog
                .validate_bound(bound)
                .map_err(QueryReadError::Compile)?;
        }
        Ok(())
    }

    fn scan_collection(
        &self,
        view: &QueryReadView,
        requested_collection: &str,
    ) -> Result<CompleteCollectionRows, QueryReadError> {
        #[cfg(test)]
        self.test_hooks
            .scan_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let physical_rows = self
            .records
            .scan_live_at_snapshot(&view.core, RecordScanLimits::fixture_v1())
            .map_err(scanner_error)?;
        let mut decoded_attribute_entries = 0usize;
        let mut pinned_payload_bytes = 0u64;
        let mut requested_pair_bytes = 0u64;
        let mut logical_ids = BTreeSet::<LogicalRecordId>::new();
        let mut records = Vec::new();
        for (core_rid, payload) in physical_rows {
            let payload_bytes =
                u64::try_from(payload.len()).map_err(|_| QueryReadError::ResourceLimit {
                    code: "logical_output_bytes",
                })?;
            pinned_payload_bytes = pinned_payload_bytes.checked_add(payload_bytes).ok_or(
                QueryReadError::ResourceLimit {
                    code: "logical_output_bytes",
                },
            )?;
            let remaining = self
                .limits
                .decoded_attribute_entries
                .checked_sub(decoded_attribute_entries)
                .ok_or(QueryReadError::ResourceLimit {
                    code: "attribute_entries",
                })?;
            let (record, used) = decode_document_with_attribute_budget(&payload, remaining)
                .map_err(|error| match error {
                    FixtureBudgetDecodeError::Document(reason) => {
                        QueryReadError::Document { core_rid, reason }
                    }
                    FixtureBudgetDecodeError::AttributeBudget => QueryReadError::ResourceLimit {
                        code: "attribute_entries",
                    },
                })?;
            decoded_attribute_entries = decoded_attribute_entries.checked_add(used).ok_or(
                QueryReadError::ResourceLimit {
                    code: "attribute_entries",
                },
            )?;
            if record.id.collection == requested_collection {
                if !logical_ids.insert(record.id.clone()) {
                    return Err(QueryReadError::DuplicateLogicalId { core_rid });
                }
                let pair_bytes = record
                    .id
                    .collection
                    .len()
                    .checked_add(record.id.key.len())
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .ok_or(QueryReadError::ResourceLimit {
                        code: "logical_output_bytes",
                    })?;
                requested_pair_bytes = requested_pair_bytes.checked_add(pair_bytes).ok_or(
                    QueryReadError::ResourceLimit {
                        code: "logical_output_bytes",
                    },
                )?;
                records.push(record);
            }
        }
        Ok(CompleteCollectionRows {
            records,
            pinned_payload_bytes,
            requested_pair_bytes,
        })
    }

    fn check_logical_output_budget(
        &self,
        bound: &BoundSelect,
        records: &[Record],
        pinned_payload_bytes: u64,
        requested_pair_bytes: u64,
    ) -> Result<(), QueryReadError> {
        fn limit() -> QueryReadError {
            QueryReadError::ResourceLimit {
                code: "logical_output_bytes",
            }
        }
        let projection = bound.projection_names();
        let projection_bytes = projection.iter().try_fold(0u64, |total, name| {
            total
                .checked_add(u64::try_from(name.len()).map_err(|_| limit())?)
                .ok_or_else(limit)
        })?;
        let field_count = u64::try_from(projection.len()).map_err(|_| limit())?;
        let row_count = u64::try_from(records.len()).map_err(|_| limit())?;
        let per_row = field_count
            .checked_mul(64)
            .and_then(|bytes| bytes.checked_add(64))
            .and_then(|bytes| bytes.checked_add(projection_bytes))
            .ok_or_else(limit)?;
        let total = row_count
            .checked_mul(per_row)
            .and_then(|bytes| bytes.checked_add(requested_pair_bytes))
            .and_then(|bytes| bytes.checked_add(pinned_payload_bytes))
            .ok_or_else(limit)?;
        if total > self.limits.logical_output_bytes {
            return Err(limit());
        }
        Ok(())
    }
}

struct CompleteCollectionRows {
    records: Vec<Record>,
    pinned_payload_bytes: u64,
    requested_pair_bytes: u64,
}

#[cfg(test)]
#[path = "gateway_tests.rs"]
mod tests;

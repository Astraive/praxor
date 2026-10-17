//! Logical record service over an explicitly injected core record owner.

use super::{
    DeleteRecordRequest, DeleteRecordResponse, FlushRequest, FlushResponse, GetRecordRequest,
    GetRecordResponse, PutRecordBatchRequest, PutRecordBatchResponse, PutRecordRequest,
    PutRecordResponse, emit_service_event,
};
use crate::core_records::CoreRecordStore;
use crate::errors::{PraxisError, Result};
use crate::store::BatchRecord;
use std::time::Instant;

/// Static support of this bounded core record service, independent of owner
/// health, readiness or authorization. Retained historical payload views are
/// available through `records()`; numeric raw ceilings do not retain payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreRecordServiceCapability {
    LogicalCrud,
    FixedMappingIndex,
    DurableFlush,
    LegacyPhysicalAdmin,
    DynamicPluginAttachment,
    DynamicCatalogDdl,
    HistoricalPayload,
}

/// A capability outside the core service's API, rather than a storage failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("core record service does not support {capability:?}")]
pub struct UnsupportedCoreRecordServiceCapability {
    pub capability: CoreRecordServiceCapability,
}

/// Cloneable logical service sharing the injected store's lease, health,
/// commit queue and WAL. Construction does no IO and never opens an owner.
///
/// Requests reuse the legacy logical DTOs. `records()` also exposes retained
/// process-local views and requested history reclaim on the same owner, without
/// adding a token or compaction DTO. A bare RecordId is interpreted within the
/// injected database; it is not a cross-database token.
#[derive(Clone)]
pub struct CorePrimitiveStorageService {
    records: CoreRecordStore,
}

impl CorePrimitiveStorageService {
    pub fn new(records: CoreRecordStore) -> Self {
        Self { records }
    }

    /// Retain the same owner and expose mapping operations plus process-local
    /// snapshot pin/read/reclaim; no independent owner or wire token is made.
    pub fn records(&self) -> CoreRecordStore {
        self.records.clone()
    }

    /// Check static support without accessing storage or checking its health.
    pub fn require_capability(
        &self,
        capability: CoreRecordServiceCapability,
    ) -> std::result::Result<(), UnsupportedCoreRecordServiceCapability> {
        match capability {
            CoreRecordServiceCapability::LogicalCrud
            | CoreRecordServiceCapability::FixedMappingIndex
            | CoreRecordServiceCapability::DurableFlush
            | CoreRecordServiceCapability::HistoricalPayload => Ok(()),
            _ => Err(UnsupportedCoreRecordServiceCapability { capability }),
        }
    }

    /// Preserve core errors, including ambiguous commit errors. No automatic
    /// retry or rollback promise is added by the service.
    pub fn put_record(&self, request: PutRecordRequest) -> Result<PutRecordResponse> {
        let started = Instant::now();
        let result = self
            .records
            .put(&request.value, &request.indexes)
            .map(|record_id| PutRecordResponse { record_id });
        emit_service_event(
            &request.context,
            "put_record",
            request.value.len() as u64,
            result.is_ok(),
            started,
        );
        result
    }

    /// Submit the complete input in one core record batch. ID order, duplicate
    /// mappings and healthy/poisoned empty-batch behavior remain the store's.
    pub fn put_record_batch(
        &self,
        request: PutRecordBatchRequest,
    ) -> Result<PutRecordBatchResponse> {
        let started = Instant::now();
        let bytes = request.records.iter().fold(0u64, |sum, record| {
            sum.saturating_add(record.value.len() as u64)
        });
        let borrowed: Vec<_> = request
            .records
            .iter()
            .map(|record| BatchRecord::new(&record.value, &record.indexes))
            .collect();
        let result = self
            .records
            .put_batch(&borrowed)
            .map(|record_ids| PutRecordBatchResponse { record_ids });
        emit_service_event(
            &request.context,
            "put_record_batch",
            bytes,
            result.is_ok(),
            started,
        );
        result
    }

    /// Only a missing/null/dead RID becomes absence. IO, corruption and common
    /// owner recovery errors are returned unchanged.
    pub fn get_record(&self, request: GetRecordRequest) -> Result<GetRecordResponse> {
        let started = Instant::now();
        let result = match self.records.fetch(request.record_id) {
            Ok(value) => Ok(GetRecordResponse { value: Some(value) }),
            Err(PraxisError::KeyNotFound) => Ok(GetRecordResponse { value: None }),
            Err(error) => Err(error),
        };
        let bytes = result
            .as_ref()
            .ok()
            .and_then(|response| response.value.as_ref())
            .map_or(0, |value| value.len() as u64);
        emit_service_event(
            &request.context,
            "get_record",
            bytes,
            result.is_ok(),
            started,
        );
        result
    }

    /// A known dead RID is an idempotent successful deletion. Unknown/null RIDs
    /// retain the store's KeyNotFound error rather than returning deleted=false.
    pub fn delete_record(&self, request: DeleteRecordRequest) -> Result<DeleteRecordResponse> {
        let started = Instant::now();
        let result = self
            .records
            .delete_record(request.record_id)
            .map(|()| DeleteRecordResponse { deleted: true });
        emit_service_event(
            &request.context,
            "delete_record",
            0,
            result.is_ok(),
            started,
        );
        result
    }

    /// Order a durable barrier then core flush, including under Never policy.
    /// This does not promise a newly created checkpoint for an empty memtable.
    pub fn flush(&self, request: FlushRequest) -> Result<FlushResponse> {
        let started = Instant::now();
        let result = self.records.flush().map(|()| FlushResponse { ok: true });
        emit_service_event(&request.context, "flush", 0, result.is_ok(), started);
        result
    }
}

#[cfg(test)]
mod tests;

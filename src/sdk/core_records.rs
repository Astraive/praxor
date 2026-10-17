//! Local client for an explicitly injected core logical record service.

use crate::api::service::{
    BatchRecordInput, CorePrimitiveStorageService, CoreRecordServiceCapability,
    DeleteRecordRequest, DeleteRecordResponse, FlushRequest, FlushResponse, GetRecordRequest,
    GetRecordResponse, PutRecordBatchRequest, PutRecordBatchResponse, PutRecordRequest,
    PutRecordResponse, RequestContext, UnsupportedCoreRecordServiceCapability,
};
use crate::core_records::CoreRecordStore;
use crate::errors::Result;
use crate::store::{IndexInsert, RecordId};

/// A local client retaining the service's one core owner. Its constructor has
/// no path, IO, cache or independent ownership. Legacy local clients are unchanged.
#[derive(Clone)]
pub struct LocalCorepraxisClient {
    service: CorePrimitiveStorageService,
}

impl LocalCorepraxisClient {
    pub fn new(service: CorePrimitiveStorageService) -> Self {
        Self { service }
    }

    /// Share the service owner for process-local retained views and requested
    /// history reclaim, without a token DTO or independent connection.
    pub fn records(&self) -> CoreRecordStore {
        self.service.records()
    }

    /// Static API support, not an owner health/readiness check.
    pub fn require_capability(
        &self,
        capability: CoreRecordServiceCapability,
    ) -> std::result::Result<(), UnsupportedCoreRecordServiceCapability> {
        self.service.require_capability(capability)
    }

    pub fn put_record(
        &self,
        context: RequestContext,
        value: Vec<u8>,
        indexes: Vec<IndexInsert>,
    ) -> Result<PutRecordResponse> {
        self.service.put_record(PutRecordRequest {
            context,
            value,
            indexes,
        })
    }

    pub fn put_record_batch(
        &self,
        context: RequestContext,
        records: Vec<BatchRecordInput>,
    ) -> Result<PutRecordBatchResponse> {
        self.service
            .put_record_batch(PutRecordBatchRequest { context, records })
    }

    pub fn get_record(
        &self,
        context: RequestContext,
        record_id: RecordId,
    ) -> Result<GetRecordResponse> {
        self.service
            .get_record(GetRecordRequest { context, record_id })
    }

    pub fn delete_record(
        &self,
        context: RequestContext,
        record_id: RecordId,
    ) -> Result<DeleteRecordResponse> {
        self.service
            .delete_record(DeleteRecordRequest { context, record_id })
    }

    /// Delegate the store's ordered durable barrier and core flush.
    pub fn flush(&self, context: RequestContext) -> Result<FlushResponse> {
        self.service.flush(FlushRequest { context })
    }
}

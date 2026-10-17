use crate::errors::Result;
use crate::identity::{Aid, Cid, Did, Eid, FieldId, Rid};
use crate::kernel::{KernelSnapshot, StorageKernel};
use crate::record::{PageDatabase, PageRecordStore};
use crate::slog;
use crate::store::{
    BatchRecord, CompactionStats, IndexInsert, RecordId, StorageEngine, StorageEngineStats,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

mod core_records;
pub use core_records::{
    CorePrimitiveStorageService, CoreRecordServiceCapability,
    UnsupportedCoreRecordServiceCapability,
};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequestContext {
    pub request_id: String,
    pub tenant_id: Option<String>,
    pub trace_id: Option<String>,
}

impl RequestContext {
    pub fn new(request_id: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            tenant_id: None,
            trace_id: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PutRecordRequest {
    pub context: RequestContext,
    pub value: Vec<u8>,
    pub indexes: Vec<IndexInsert>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PutRecordResponse {
    pub record_id: RecordId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BatchRecordInput {
    pub value: Vec<u8>,
    pub indexes: Vec<IndexInsert>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PutRecordBatchRequest {
    pub context: RequestContext,
    pub records: Vec<BatchRecordInput>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PutRecordBatchResponse {
    pub record_ids: Vec<RecordId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GetRecordRequest {
    pub context: RequestContext,
    pub record_id: RecordId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GetRecordResponse {
    pub value: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeleteRecordRequest {
    pub context: RequestContext,
    pub record_id: RecordId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeleteRecordResponse {
    pub deleted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StatsRequest {
    pub context: RequestContext,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StatsResponse {
    pub stats: StorageEngineStats,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotRequest {
    pub context: RequestContext,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotResponse {
    pub snapshot: KernelSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlushRequest {
    pub context: RequestContext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlushResponse {
    pub ok: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompactRequest {
    pub context: RequestContext,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompactResponse {
    pub stats: CompactionStats,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PrimitiveFieldId {
    Fixed(u16),
    Dynamic(u16),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrimitiveFieldBytes {
    pub field: PrimitiveFieldId,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PutPageRecordRequest {
    pub context: RequestContext,
    pub cid: Cid,
    pub eid: Eid,
    pub fields: Vec<PrimitiveFieldBytes>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PutPageRecordResponse {
    pub rid: Rid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GetPageRecordRequest {
    pub context: RequestContext,
    pub cid: Cid,
    pub eid: Eid,
    pub rid: Rid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GetPageRecordResponse {
    pub body: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeletePageRecordRequest {
    pub context: RequestContext,
    pub cid: Cid,
    pub eid: Eid,
    pub rid: Rid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeletePageRecordResponse {
    pub deleted: bool,
}

#[derive(Clone)]
pub struct PrimitiveStorageService {
    engine: Arc<Mutex<StorageEngine>>,
}

#[derive(Clone)]
pub struct PagePrimitiveStorageService {
    database: PageDatabase,
}

impl PrimitiveStorageService {
    pub fn new(engine: StorageEngine) -> Self {
        Self {
            engine: Arc::new(Mutex::new(engine)),
        }
    }

    pub fn put_record(&self, request: PutRecordRequest) -> Result<PutRecordResponse> {
        let started = Instant::now();
        let bytes = request.value.len() as u64;
        let result = self
            .engine
            .lock()
            .expect("storage service mutex poisoned")
            .put(&request.value, &request.indexes)
            .map(|record_id| PutRecordResponse { record_id });
        emit_service_event(
            &request.context,
            "put_record",
            bytes,
            result.is_ok(),
            started,
        );
        result
    }

    pub fn put_record_batch(
        &self,
        request: PutRecordBatchRequest,
    ) -> Result<PutRecordBatchResponse> {
        let started = Instant::now();
        let bytes = request
            .records
            .iter()
            .map(|record| record.value.len() as u64)
            .sum();
        let borrowed: Vec<BatchRecord<'_>> = request
            .records
            .iter()
            .map(|record| BatchRecord::new(&record.value, &record.indexes))
            .collect();
        let result = self
            .engine
            .lock()
            .expect("storage service mutex poisoned")
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

    pub fn get_record(&self, request: GetRecordRequest) -> Result<GetRecordResponse> {
        let started = Instant::now();
        let result = self
            .engine
            .lock()
            .expect("storage service mutex poisoned")
            .fetch(request.record_id)
            .map(|value| GetRecordResponse { value: Some(value) });
        let response = match result {
            Ok(response) => Ok(response),
            Err(crate::errors::PraxisError::KeyNotFound) => Ok(GetRecordResponse { value: None }),
            Err(error) => Err(error),
        };
        emit_service_event(
            &request.context,
            "get_record",
            response
                .as_ref()
                .ok()
                .and_then(|response| response.value.as_ref())
                .map(|value| value.len() as u64)
                .unwrap_or(0),
            response.is_ok(),
            started,
        );
        response
    }

    pub fn delete_record(&self, request: DeleteRecordRequest) -> Result<DeleteRecordResponse> {
        let started = Instant::now();
        let result = self
            .engine
            .lock()
            .expect("storage service mutex poisoned")
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

    pub fn stats(&self, request: StatsRequest) -> Result<StatsResponse> {
        let started = Instant::now();
        let stats = self
            .engine
            .lock()
            .expect("storage service mutex poisoned")
            .stats();
        emit_service_event(&request.context, "stats", 0, true, started);
        Ok(StatsResponse { stats })
    }

    pub fn snapshot(&self, request: SnapshotRequest) -> Result<SnapshotResponse> {
        let started = Instant::now();
        let snapshot = self
            .engine
            .lock()
            .expect("storage service mutex poisoned")
            .snapshot();
        emit_service_event(&request.context, "snapshot", 0, true, started);
        Ok(SnapshotResponse { snapshot })
    }

    pub fn flush(&self, request: FlushRequest) -> Result<FlushResponse> {
        let started = Instant::now();
        let result = self
            .engine
            .lock()
            .expect("storage service mutex poisoned")
            .flush()
            .map(|()| FlushResponse { ok: true });
        emit_service_event(&request.context, "flush", 0, result.is_ok(), started);
        result
    }

    pub fn compact(&self, request: CompactRequest) -> Result<CompactResponse> {
        let started = Instant::now();
        let result = self
            .engine
            .lock()
            .expect("storage service mutex poisoned")
            .compact_primary()
            .map(|stats| CompactResponse { stats });
        emit_service_event(&request.context, "compact", 0, result.is_ok(), started);
        result
    }
}

impl PagePrimitiveStorageService {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        Ok(Self::new(PageDatabase::open(root)?))
    }

    pub fn new(database: PageDatabase) -> Self {
        Self { database }
    }

    pub fn put_page_record(&self, request: PutPageRecordRequest) -> Result<PutPageRecordResponse> {
        let started = Instant::now();
        let bytes = request
            .fields
            .iter()
            .map(|field| field.bytes.len() as u64)
            .sum();
        let result = self.with_store(request.cid, request.eid, |store| {
            let borrowed: Vec<(FieldId, &[u8])> = request
                .fields
                .iter()
                .map(|field| (field.field.into(), field.bytes.as_slice()))
                .collect();
            store
                .put(&borrowed)
                .map(|rid| PutPageRecordResponse { rid })
        });
        emit_service_event(
            &request.context,
            "put_page_record",
            bytes,
            result.is_ok(),
            started,
        );
        result
    }

    pub fn get_page_record(&self, request: GetPageRecordRequest) -> Result<GetPageRecordResponse> {
        let started = Instant::now();
        let result = self.with_store(request.cid, request.eid, |store| {
            store
                .get(request.rid)
                .map(|body| GetPageRecordResponse { body: Some(body) })
        });
        let response = match result {
            Ok(response) => Ok(response),
            Err(crate::errors::PraxisError::KeyNotFound) => {
                Ok(GetPageRecordResponse { body: None })
            }
            Err(error) => Err(error),
        };
        emit_service_event(
            &request.context,
            "get_page_record",
            response
                .as_ref()
                .ok()
                .and_then(|response| response.body.as_ref())
                .map(|body| body.len() as u64)
                .unwrap_or(0),
            response.is_ok(),
            started,
        );
        response
    }

    pub fn delete_page_record(
        &self,
        request: DeletePageRecordRequest,
    ) -> Result<DeletePageRecordResponse> {
        let started = Instant::now();
        let result = self.with_store(request.cid, request.eid, |store| {
            store
                .delete(request.rid)
                .map(|()| DeletePageRecordResponse { deleted: true })
        });
        emit_service_event(
            &request.context,
            "delete_page_record",
            0,
            result.is_ok(),
            started,
        );
        result
    }

    fn with_store<T>(
        &self,
        cid: Cid,
        eid: Eid,
        operation: impl FnOnce(&mut PageRecordStore) -> Result<T>,
    ) -> Result<T> {
        operation(&mut self.database.entity(cid, eid)?)
    }
}

impl From<PrimitiveFieldId> for FieldId {
    fn from(value: PrimitiveFieldId) -> Self {
        match value {
            PrimitiveFieldId::Fixed(aid) => Self::Fixed(Aid(aid)),
            PrimitiveFieldId::Dynamic(did) => Self::Dynamic(Did(did)),
        }
    }
}

fn emit_service_event(
    context: &RequestContext,
    operation: &str,
    bytes: u64,
    ok: bool,
    started: Instant,
) {
    slog::storage(
        "api_service_request",
        slog::context()
            .with_str("request_id", context.request_id.clone())
            .with_str("operation", operation)
            .with_str("model", "storage")
            .with_str("execution_mode", "primitive")
            .with_u64("bytes", bytes)
            .with_u64("duration_ms", started.elapsed().as_millis() as u64)
            .with_str("outcome", if ok { "success" } else { "error" }),
    );
}

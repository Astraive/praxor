use crate::api::service::{
    BatchRecordInput, DeleteRecordRequest, DeleteRecordResponse, GetRecordRequest,
    GetRecordResponse, PagePrimitiveStorageService, PrimitiveFieldBytes, PrimitiveStorageService,
    PutRecordBatchRequest, PutRecordBatchResponse, PutRecordRequest, PutRecordResponse,
    RequestContext, StatsRequest, StatsResponse,
};
use crate::errors::Result;
use crate::identity::{Cid, Eid, Rid};
use crate::store::{IndexInsert, RecordId, StorageEngine};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

mod core_records;
pub use core_records::LocalCorepraxisClient;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SdkTransport {
    Local,
    Rest,
    Grpc,
    GraphQl,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RemoteStorageRequest {
    pub transport: SdkTransport,
    pub request_id: String,
    pub operation: String,
    pub path: String,
    pub body: Vec<u8>,
}

pub struct LocalpraxisClient {
    service: PrimitiveStorageService,
}

pub struct LocalPagepraxisClient {
    service: PagePrimitiveStorageService,
}

impl LocalpraxisClient {
    pub fn new(engine: StorageEngine) -> Self {
        Self {
            service: PrimitiveStorageService::new(engine),
        }
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

    pub fn stats(&self, context: RequestContext) -> Result<StatsResponse> {
        self.service.stats(StatsRequest { context })
    }
}

impl LocalPagepraxisClient {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        Ok(Self::new(PagePrimitiveStorageService::open(root)?))
    }

    pub fn new(service: PagePrimitiveStorageService) -> Self {
        Self { service }
    }

    pub fn put_page_record(
        &self,
        context: RequestContext,
        cid: Cid,
        eid: Eid,
        fields: Vec<PrimitiveFieldBytes>,
    ) -> Result<crate::api::service::PutPageRecordResponse> {
        self.service
            .put_page_record(crate::api::service::PutPageRecordRequest {
                context,
                cid,
                eid,
                fields,
            })
    }

    pub fn get_page_record(
        &self,
        context: RequestContext,
        cid: Cid,
        eid: Eid,
        rid: Rid,
    ) -> Result<crate::api::service::GetPageRecordResponse> {
        self.service
            .get_page_record(crate::api::service::GetPageRecordRequest {
                context,
                cid,
                eid,
                rid,
            })
    }

    pub fn delete_page_record(
        &self,
        context: RequestContext,
        cid: Cid,
        eid: Eid,
        rid: Rid,
    ) -> Result<crate::api::service::DeletePageRecordResponse> {
        self.service
            .delete_page_record(crate::api::service::DeletePageRecordRequest {
                context,
                cid,
                eid,
                rid,
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestpraxisClient {
    endpoint: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpcpraxisClient {
    endpoint: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphQlpraxisClient {
    endpoint: String,
}

impl RestpraxisClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    pub fn put_record_request(
        &self,
        context: RequestContext,
        body: Vec<u8>,
    ) -> RemoteStorageRequest {
        remote_request(
            SdkTransport::Rest,
            context,
            "put_record",
            format!("{}/v1/records", self.endpoint),
            body,
        )
    }

    pub fn put_record_batch_request(
        &self,
        context: RequestContext,
        body: Vec<u8>,
    ) -> RemoteStorageRequest {
        remote_request(
            SdkTransport::Rest,
            context,
            "put_record_batch",
            format!("{}/v1/records:batchPut", self.endpoint),
            body,
        )
    }
}

impl GrpcpraxisClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    pub fn put_record_request(
        &self,
        context: RequestContext,
        body: Vec<u8>,
    ) -> RemoteStorageRequest {
        remote_request(
            SdkTransport::Grpc,
            context,
            "praxis.storage.v1.RecordService/PutRecord",
            self.endpoint.clone(),
            body,
        )
    }

    pub fn put_record_batch_request(
        &self,
        context: RequestContext,
        body: Vec<u8>,
    ) -> RemoteStorageRequest {
        remote_request(
            SdkTransport::Grpc,
            context,
            "praxis.storage.v1.RecordService/PutRecordBatch",
            self.endpoint.clone(),
            body,
        )
    }
}

impl GraphQlpraxisClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    pub fn put_record_request(
        &self,
        context: RequestContext,
        body: Vec<u8>,
    ) -> RemoteStorageRequest {
        remote_request(
            SdkTransport::GraphQl,
            context,
            "mutation.putRecord",
            self.endpoint.clone(),
            body,
        )
    }

    pub fn put_record_batch_request(
        &self,
        context: RequestContext,
        body: Vec<u8>,
    ) -> RemoteStorageRequest {
        remote_request(
            SdkTransport::GraphQl,
            context,
            "mutation.putRecordBatch",
            self.endpoint.clone(),
            body,
        )
    }
}

fn remote_request(
    transport: SdkTransport,
    context: RequestContext,
    operation: impl Into<String>,
    path: impl Into<String>,
    body: Vec<u8>,
) -> RemoteStorageRequest {
    RemoteStorageRequest {
        transport,
        request_id: context.request_id,
        operation: operation.into(),
        path: path.into(),
        body,
    }
}

/// Response from a remote storage request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteStorageResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Trait for implementing remote transport (HTTP, gRPC, etc.).
///
/// Implementors provide the actual network communication.
/// Users can implement this trait to use their preferred HTTP client.
pub trait RemoteTransport: Send + Sync {
    /// Send a remote storage request and return the response.
    fn send(&self, request: &RemoteStorageRequest) -> Result<RemoteStorageResponse>;
}

/// A client that can execute remote storage operations.
pub struct RemotepraxisClient {
    transport: Box<dyn RemoteTransport>,
}

impl RemotepraxisClient {
    pub fn new(transport: impl RemoteTransport + 'static) -> Self {
        Self {
            transport: Box::new(transport),
        }
    }

    /// Execute a remote storage request.
    pub fn execute(&self, request: &RemoteStorageRequest) -> Result<RemoteStorageResponse> {
        self.transport.send(request)
    }

    /// Put a record via REST.
    pub fn put_record(
        &self,
        endpoint: &str,
        key: &str,
        value: Vec<u8>,
    ) -> Result<RemoteStorageResponse> {
        let request = RemoteStorageRequest {
            transport: SdkTransport::Rest,
            request_id: format!(
                "{:016x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ),
            operation: "put_record".to_string(),
            path: format!("{}/v1/kv/{}", endpoint, key),
            body: value,
        };
        self.execute(&request)
    }

    /// Get a record via REST.
    pub fn get_record(&self, endpoint: &str, key: &str) -> Result<RemoteStorageResponse> {
        let request = RemoteStorageRequest {
            transport: SdkTransport::Rest,
            request_id: format!(
                "{:016x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ),
            operation: "get_record".to_string(),
            path: format!("{}/v1/kv/{}", endpoint, key),
            body: Vec::new(),
        };
        self.execute(&request)
    }

    /// Delete a record via REST.
    pub fn delete_record(&self, endpoint: &str, key: &str) -> Result<RemoteStorageResponse> {
        let request = RemoteStorageRequest {
            transport: SdkTransport::Rest,
            request_id: format!(
                "{:016x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ),
            operation: "delete_record".to_string(),
            path: format!("{}/v1/kv/{}", endpoint, key),
            body: Vec::new(),
        };
        self.execute(&request)
    }

    /// Execute a query via REST.
    pub fn execute_query(&self, endpoint: &str, query: &str) -> Result<RemoteStorageResponse> {
        let request = RemoteStorageRequest {
            transport: SdkTransport::Rest,
            request_id: format!(
                "{:016x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ),
            operation: "execute_query".to_string(),
            path: format!("{}/v1/query", endpoint),
            body: serde_json::to_vec(&serde_json::json!({ "query": query })).unwrap_or_default(),
        };
        self.execute(&request)
    }
}

use praxis::api::service::{
    BatchRecordInput, PrimitiveFieldBytes, PrimitiveFieldId, RequestContext,
};
use praxis::identity::{Cid, Eid};
use praxis::sdk::{
    GraphQlpraxisClient, GrpcpraxisClient, LocalPagepraxisClient, LocalpraxisClient,
    RestpraxisClient, SdkTransport,
};
use praxis::store::{IndexInsert, StorageEngine};
use tempfile::tempdir;

#[test]
fn local_sdk_executes_primitive_record_flow() {
    let dir = tempdir().unwrap();
    let engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    let client = LocalpraxisClient::new(engine);

    let put = client
        .put_record(
            RequestContext::new("sdk-local-put"),
            b"sdk-value".to_vec(),
            Vec::new(),
        )
        .unwrap();
    let get = client
        .get_record(RequestContext::new("sdk-local-get"), put.record_id)
        .unwrap();

    assert_eq!(get.value, Some(b"sdk-value".to_vec()));
    assert!(
        client
            .delete_record(RequestContext::new("sdk-local-delete"), put.record_id)
            .unwrap()
            .deleted
    );
}

#[test]
fn local_sdk_executes_primitive_batch_record_flow() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    engine
        .register_index(
            "kv",
            "default",
            Box::new(praxis::storage::lsm::LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();
    let client = LocalpraxisClient::new(engine);

    let batch = client
        .put_record_batch(
            RequestContext::new("sdk-local-batch-put"),
            vec![
                BatchRecordInput {
                    value: b"batch-a".to_vec(),
                    indexes: vec![IndexInsert::new("kv", b"a".to_vec())],
                },
                BatchRecordInput {
                    value: b"batch-b".to_vec(),
                    indexes: vec![IndexInsert::new("kv", b"b".to_vec())],
                },
            ],
        )
        .unwrap();

    assert_eq!(batch.record_ids.len(), 2);
    assert_eq!(
        client
            .get_record(
                RequestContext::new("sdk-local-batch-get-a"),
                batch.record_ids[0]
            )
            .unwrap()
            .value,
        Some(b"batch-a".to_vec())
    );
    assert_eq!(
        client
            .get_record(
                RequestContext::new("sdk-local-batch-get-b"),
                batch.record_ids[1]
            )
            .unwrap()
            .value,
        Some(b"batch-b".to_vec())
    );
}

#[test]
fn local_page_sdk_executes_cid_eid_rid_flow() {
    let dir = tempdir().unwrap();
    let client = LocalPagepraxisClient::open(dir.path()).unwrap();

    let put = client
        .put_page_record(
            RequestContext::new("sdk-page-put"),
            Cid(1),
            Eid(2),
            vec![PrimitiveFieldBytes {
                field: PrimitiveFieldId::Fixed(1),
                bytes: b"page-sdk-value".to_vec(),
            }],
        )
        .unwrap();
    let get = client
        .get_page_record(RequestContext::new("sdk-page-get"), Cid(1), Eid(2), put.rid)
        .unwrap();

    assert_eq!(get.body, Some(b"page-sdk-value".to_vec()));
    assert!(
        client
            .delete_page_record(
                RequestContext::new("sdk-page-delete"),
                Cid(1),
                Eid(2),
                put.rid
            )
            .unwrap()
            .deleted
    );
}

#[test]
fn remote_sdk_clients_preserve_request_ids_and_transport() {
    let rest = RestpraxisClient::new("http://127.0.0.1:8080")
        .put_record_request(RequestContext::new("rest-1"), b"body".to_vec());
    let grpc = GrpcpraxisClient::new("http://127.0.0.1:50051")
        .put_record_request(RequestContext::new("grpc-1"), b"body".to_vec());
    let graphql = GraphQlpraxisClient::new("http://127.0.0.1:8080/graphql")
        .put_record_request(RequestContext::new("graphql-1"), b"body".to_vec());
    let rest_batch = RestpraxisClient::new("http://127.0.0.1:8080")
        .put_record_batch_request(RequestContext::new("rest-batch-1"), b"batch".to_vec());
    let grpc_batch = GrpcpraxisClient::new("http://127.0.0.1:50051")
        .put_record_batch_request(RequestContext::new("grpc-batch-1"), b"batch".to_vec());
    let graphql_batch = GraphQlpraxisClient::new("http://127.0.0.1:8080/graphql")
        .put_record_batch_request(RequestContext::new("graphql-batch-1"), b"batch".to_vec());

    assert_eq!(rest.transport, SdkTransport::Rest);
    assert_eq!(rest.request_id, "rest-1");
    assert_eq!(grpc.transport, SdkTransport::Grpc);
    assert_eq!(grpc.request_id, "grpc-1");
    assert_eq!(graphql.transport, SdkTransport::GraphQl);
    assert_eq!(graphql.request_id, "graphql-1");
    assert_eq!(rest_batch.operation, "put_record_batch");
    assert_eq!(rest_batch.request_id, "rest-batch-1");
    assert_eq!(
        grpc_batch.operation,
        "praxis.storage.v1.RecordService/PutRecordBatch"
    );
    assert_eq!(grpc_batch.request_id, "grpc-batch-1");
    assert_eq!(graphql_batch.operation, "mutation.putRecordBatch");
    assert_eq!(graphql_batch.request_id, "graphql-batch-1");
}

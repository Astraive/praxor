# Core record service and local client

`CorePrimitiveStorageService` and `LocalCorepraxisClient` adapt the explicit
`CoreDatabase` record view. Obtain `db.records()` and inject it; neither adapter
opens a path or creates another engine, allocator, lease, WAL, queue or cache.
Clones and `records()` retain the same owner, including its health and writer
lease, until the final retained view is dropped.

```rust,no_run
use praxis::{CoreDatabase, MappingDescriptor, PraxisConfig, RecordAuthorityOptions};
use praxis::api::service::{CorePrimitiveStorageService, RequestContext};
use praxis::sdk::LocalCorepraxisClient;
use praxis::store::IndexInsert;

# fn example() -> praxis::Result<()> {
let db = CoreDatabase::create_fresh(
    PraxisConfig::new("new-core-database"),
    RecordAuthorityOptions {
        indexes: vec![MappingDescriptor {
            name: "by-name".into(),
            namespace: "people".into(),
        }],
    },
)?;
let service = CorePrimitiveStorageService::new(db.records());
let client = LocalCorepraxisClient::new(service);
let rid = client.put_record(
    RequestContext::new("put-1"),
    b"payload".to_vec(),
    vec![IndexInsert::new("by-name", b"Ada".to_vec())],
)?.record_id;
assert_eq!(client.get_record(RequestContext::new("get-1"), rid)?.value,
           Some(b"payload".to_vec()));
client.flush(RequestContext::new("flush-1"))?;
let held = client.records().pin_snapshot()?;
client.delete_record(RequestContext::new("delete-1"), rid)?;
client.flush(RequestContext::new("flush-2"))?;
client.records().reclaim_snapshot_history()?;
assert_eq!(client.records().fetch_at_snapshot(rid, &held)?, b"payload");
drop(held);
# Ok(())
# }
```

The service accepts the existing `PutRecordRequest`, `PutRecordBatchRequest`,
`GetRecordRequest`, `DeleteRecordRequest` and `FlushRequest` DTOs and returns their
existing response DTOs. The local client keeps the corresponding logical
argument shapes. Existing DTO serde, `PrimitiveStorageService`,
`LocalpraxisClient`, page service/client constructors and `StorageKernel` are
unchanged; callers opt into this surface explicitly. A bare `RecordId` is scoped
by the injected database, without a foreign-database identity check.

| Operation | Core service behavior |
| --- | --- |
| Put | Pass payload/index bytes to the record view; return its RID. |
| Batch put | Submit the entire ordered input in one record batch. IDs follow input order and duplicate mappings preserve the store's ordering. A healthy empty input returns no IDs without advancing sequence; a poisoned owner rejects it. |
| Get | Convert only `KeyNotFound` (null, unknown or dead RID) to `value: None`. Preserve `Io`, `Corrupt`, `RecoveryRequired` and other errors. |
| Delete | Return `deleted: true` after a successful store delete, including repeated deletes of known dead RIDs. Null/unknown RIDs retain `KeyNotFound`. Existing stale mapping behavior is preserved. |
| Flush | Execute the record view's ordered durable barrier, then core flush, including with `WalSyncPolicy::Never`. Preserve errors; an empty memtable need not create a new checkpoint. |
| Retained payload view | Through `records()`, pin the current published core view and read by RID or mapping at that token. The same owner retains the bytes through flush, compaction and requested history reclaim until the token's last clone drops. There is no token request DTO. |

No retry or rollback guarantee is added. A failed append/sync or an ambiguous
postcommit failure can require closing every retained view and explicitly
reopening the database. Request context is passed to the existing service event
logger; it does not introduce authorization or a durable audit record.

`records()` returns a cloned `CoreRecordStore`, exposing its existing
`put_index`, `delete_index`, `lookup_rid`, `lookup_rid_at`, `fetch_by_index`,
`delete_by_index` and cleanup methods without another protocol. Prefer its
combined `fetch_by_index` when one read view is required. It also exposes
`pin_snapshot`, `fetch_at_snapshot`, `lookup_rid_at_snapshot`,
`fetch_by_index_at_snapshot` and `reclaim_snapshot_history`. A pin captures the
current published core view; token clones keep that view and the owner alive.
The token is process-local and bound to the live owner. A restored or separately
opened database rejects it with `ForeignRecordSnapshot`, even if the persisted
database identity matches. A held token can keep the writer lease active after
service and client handles are dropped, so close the final token before reopening
the same path. Once relevant tokens are gone, a requested reclaim may remove
obsolete protected versions; its report distinguishes logical versions removed
from whole-file garbage-collection counts and bytes. Reclaim does not create a
durable historical selector or a remote token protocol.

`IndexInsert` uses the immutable mapping registry created with the database;
unknown names retain `InvalidConfig`. Numeric raw mapping ceilings select
mapping facts at a current core view and do not retain historical payloads. See
[core record authority](core-record-authority.md) for these sequence domains and
the persisted authority contract.

`require_capability` is a static, IO-free API support check. The finite
`CoreRecordServiceCapability` enum supports `LogicalCrud`, `FixedMappingIndex`
`DurableFlush` and `HistoricalPayload` on both service and local client. The
historical capability means process-local retained-token reads through
`records()`, not numeric `AS OF` payload lookup. `LegacyPhysicalAdmin`,
`DynamicPluginAttachment` and `DynamicCatalogDdl` return the separate typed
`UnsupportedCoreRecordServiceCapability` error carrying the requested value.
This check is not a health, readiness or authorization check: supported
capabilities remain supported when an actual operation would fail with
`RecoveryRequired`. Pin, read and reclaim operations on a poisoned owner do
fail with `RecoveryRequired`.

There is no `StorageKernel` implementation, physical `.trec` statistics/path,
`KernelSnapshot`, compaction facade, plugin registration or stats response on
these types. Retained payload views use the existing `CoreRecordStore` token
contract rather than a service wire request. This adapter does not import legacy
pages, change runtime/query ownership, implement catalog DDL or retire any
legacy writer.

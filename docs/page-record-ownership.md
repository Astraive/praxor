# Page database ownership and compatibility

Page records use collection-scoped `identity::Rid` values. They are a distinct protocol from the core engine and pointer store's `store::RecordId`. Equal page RIDs in different collections are valid.

Open one explicit owner and obtain entity views from it:

```rust
use praxis::config::WalSyncPolicy;
use praxis::identity::{Aid, Cid, Eid, FieldId};
use praxis::record::PageDatabase;

fn example() -> praxis::Result<()> {
    let database = PageDatabase::open("example-page-data")?;
    let mut first = database.entity(Cid(1), Eid(2))?;
    let mut second = database.entity(Cid(1), Eid(3))?;
    let mut wal = database.page_wal(WalSyncPolicy::EveryBatch)?;
    let first_rid = first.put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"first")])?;
    let second_rid = second.put(&[(FieldId::Fixed(Aid(1)), b"second")])?;
    assert_ne!(first_rid, second_rid);
    Ok(())
}
```

The owner shares one collection directory and RID allocator, independent page/slot cursors per entity and frame, and one canonical page WAL writer. Entity and service clones retain the same live state. A root mutex serializes page operations and root-wide manifest updates, including their IO. This is a correctness boundary, not a concurrency throughput claim.

The common OS lease excludes independent writers at the caller's canonical base. Every view and WAL handle retains ownership after its creating facade drops. Drop the final owner before independently reopening. A lease coordinates supported library writers; it does not sandbox arbitrary filesystem writes or public low-level codecs.

Page database opens inspect physical storage format under that lease before reading a WAL or initializing the namespace. Foreign engine roots, reserved identities, aliases, and incomplete namespaces are refused without changing durable data. Ordinary application siblings are permitted. An exact v1 header-only page WAL is accepted on a complete empty page scaffold. This page-open integration is one part of [#40](https://github.com/Astraive/praxor/issues/40); [#48](https://github.com/Astraive/praxor/issues/48) separately tracks catalog constructors.

## Intentional source changes in 0.0

- `PagePrimitiveStorageService::open` and `LocalPagepraxisClient::open` return `Result`. Propagate the error with `?`. Their `new` constructors accept an existing explicit database/service owner.
- `PageRecordStore::open(base,cid,eid)` remains a fallible independent open. Additional entities use `PageDatabase::entity`; simultaneous independent opens return `AlreadyOpen`.
- `PageRecordStore::directory()` returns `Result<RidDirectory>`, a current owned snapshot. Resource equality derives were removed; cloning a view shares ownership.
- Obtain writable WAL handles with `database.page_wal(policy)`. Raw path writer construction and raw append methods are private. `path()` remains available; `bytes_written()` is fallible. Durable store methods reject another owner's handle before IO.
- All handles use one writer/sequence allocator. Conflicting sync policies are rejected. `EveryBatch` and `GroupCommit` currently sync every operation; the latter does not implement group batching here. `Never` stays unsynced until explicit `sync()`.

Page, RID-directory, manifest, and PageWal v1 bytes remain unchanged, including the actual IEEE CRC32 checksum bytes historically named `crc32c`. Headerless v1 page logs remain readable and appendable when otherwise valid.

## Reopen, replay, and failure outcomes

Normal open validates the whole canonical log and its identities against the intact directory, and reserves known WAL allocations. It never automatically replays records. Existing tombstones remain barriers to older logged puts. Replay rejects conflicting entity/payload assignments and invalid ordering before publishing records.

Within a log, repeated puts must retain the exact field IDs, boundaries, order, and bytes, and a delete prevents a later put from reusing that RID. Comparing a logged put with an existing raw v1 page can verify only its concatenated body: raw page slots do not persist the field tuple layout. No stronger field-layout verification against existing raw pages is claimed.

`recover_from_page_wal` applies a strictly validated canonical log against an intact validated RID directory/high-water. A missing directory for physical data or known WAL history returns `PageRecoveryRequired`, even if the log looks complete. V1 cannot prove that all acknowledged allocations and deletes were logged. Identical payloads and page LSNs cannot reconstruct identity or the lost allocator floor. Decoded records may be applied explicitly to a fresh target as a new database containing the logged subset; that does not recover omitted source history.

Format admission may reject an incomplete namespace earlier with a typed storage-format error, including a record-bearing WAL with no other valid page authority. It never adopts such a partial root to obtain a recovery handle.

`PageWal::replay(path)` currently returns a forensic valid prefix. Prefix success does not authorize writable open or complete recovery. Invalid middle records, incomplete suffixes, and sequence regressions are refused for writing; this change does not truncate or repair them. [#39](https://github.com/Astraive/praxor/issues/39) tracks framing and suffix repair.

Pure validation/size/exhaustion errors leave the owner usable. After uncertain durable IO, the first operation returns its error and every view/handle fails closed with `PageRecoveryRequired`; the lease remains held until final drop. The durable outcome of an errored operation can be unknown. These changes do not make the page, metadata, sidecar, and manifest files one crash-atomic transaction. [#41](https://github.com/Astraive/praxor/issues/41) tracks that publication/recovery boundary and a durable completeness witness.

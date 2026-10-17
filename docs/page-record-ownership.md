# Page database ownership and compatibility

Page records use collection-scoped `identity::Rid` values. They are a distinct protocol from the core engine and pointer store's `store::RecordId`. Equal page RIDs in different collections are valid.

Open one explicit owner and obtain entity views from it:

```rust
use praxis::config::WalSyncPolicy;
use praxis::identity::{Aid, Cid, Eid, FieldId};
use praxis::catalog::CatalogStore;
use praxis::record::PageDatabase;

fn example() -> praxis::Result<()> {
    let database = PageDatabase::open("example-page-data")?;
    let catalog = CatalogStore::new(database.clone());
    let _catalog_snapshot = catalog.load()?;
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

Page database and independent catalog opens inspect physical storage format under that lease before reading a WAL or initializing the namespace. Foreign engine roots, reserved identities, aliases, and incomplete namespaces are refused without changing durable data. Ordinary application siblings are permitted. An exact valid v1 or v2 header-only page WAL is accepted on a complete empty page scaffold. Catalog constructors share this admission/ownership path through [#48](https://github.com/Astraive/praxor/issues/48), completing the catalog portion of [#40](https://github.com/Astraive/praxor/issues/40).

## Intentional source changes in 0.0

- `PagePrimitiveStorageService::open` and `LocalPagepraxisClient::open` return `Result`. Propagate the error with `?`. Their `new` constructors accept an existing explicit database/service owner.
- `PageRecordStore::open(base,cid,eid)` remains a fallible independent open. Additional entities use `PageDatabase::entity`; simultaneous independent opens return `AlreadyOpen`.
- `CatalogStore::open(base)` independently owns the same page root. Use `CatalogStore::new(database.clone())` to share it with page and WAL views. Catalog clones retain ownership; resource equality derives were removed while snapshot equality remains unchanged. `layout()` keeps its existing return shape.
- `PageRecordStore::directory()` returns `Result<RidDirectory>`, a current owned snapshot. Resource equality derives were removed; cloning a view shares ownership.
- Obtain writable WAL handles with `database.page_wal(policy)`. Raw path writer construction and raw append methods are private. `path()` remains available; `bytes_written()` is fallible. Durable store methods reject another owner's handle before IO.
- All handles use one writer/sequence allocator. Conflicting sync policies are rejected. `EveryBatch` and `GroupCommit` currently sync every operation; the latter does not implement group batching here. `Never` omits per-append sync; explicit `sync()` requests a barrier. Format-integrity barriers still synchronize, including writable activation of an existing v2 file, and can persist earlier bytes.

Page, RID-directory, manifest, and historical PageWal v1 bytes retain their encodings, including the actual IEEE CRC32 checksum bytes historically named `crc32c`. New WAL writes use authenticated v2 file/record framing. Clean v1/headerless logs remain readable unchanged; writable activation stages a v2 header with byte-identical legacy frames before replacing the canonical pathname, as described in [page WAL framing](page-wal-framing.md).

Catalog loads and saves hold the same root guard as page/WAL operations. Load does not create or repair missing optional catalogs. Save validates and prepares all ten v1 payloads and destinations before publication; pure preparation errors leave shared views healthy. Catalog-only legacy roots remain supported without page manifests or RID directories, and existing zero/duplicate IDs and optional-string encodings retain their behavior. Catalog publications keep the existing per-file temporary/rename behavior; PageWal sync policies do not make catalog saves durable or make ten files one atomic transaction.

Supported live catalog loads wait for a complete successful save, or fail closed after an uncertain publication error. After all owners drop, v1 can still contain individually valid catalog files from different publication attempts. The format has no durable catalog generation witness to prove that all ten files belong to one completed save; [#41](https://github.com/Astraive/praxor/issues/41) tracks that crash/recovery boundary. [V1 catalog decoding](catalog-decoding.md) describes the checked count, string, ID, tag, envelope and input-role contract added for [#51](https://github.com/Astraive/praxor/issues/51).

[V1 page manifest decoding](page-manifest-decoding.md) documents the separate checked inventory codec. Managed startup checks [known v1 writer-role presence](page-inventory-presence.md) under the current root before WAL reads/repair and layout initialization, even when an entire non-WAL collection is missing. Unknown annotations, legacy manifest absence and exact-current-path checksum selection retain their behavior. #41 remains open for inventory and acknowledgement completeness; this check does not make multi-file publication crash atomic.

## Reopen, replay, and failure outcomes

Normal open classifies the canonical log and validates every directory, allocation high-water and complete-prefix semantic fact before a proven interrupted v2 append can be repaired and synced. Corrupt or ambiguous legacy tails refuse unchanged. Normal open reserves only complete validated WAL allocations and never automatically replays records. Existing tombstones remain barriers to older logged puts. Replay rejects conflicting entity/payload assignments and invalid ordering before publishing records.

Within a log, repeated puts must retain the exact field IDs, boundaries, order, and bytes, and a delete prevents a later put from reusing that RID. Comparing a logged put with an existing raw v1 page can verify only its concatenated body: raw page slots do not persist the field tuple layout. No stronger field-layout verification against existing raw pages is claimed.

`recover_from_page_wal` applies a strictly validated canonical log against an intact validated RID directory/high-water. A missing directory for physical data or known WAL history returns `PageRecoveryRequired`, even if the log looks complete. V1 cannot prove that all acknowledged allocations and deletes were logged. Identical payloads and page LSNs cannot reconstruct identity or the lost allocator floor. Decoded records may be applied explicitly to a fresh target as a new database containing the logged subset; that does not recover omitted source history.

Format admission may reject an incomplete namespace earlier with a typed storage-format error, including a record-bearing WAL with no other valid page authority. It never adopts such a partial root to obtain a recovery handle.

`PageWal::replay(path)` requires a complete clean scan. `PageWal::replay_prefix(path)` returns an explicit forensic report with the valid records, lengths, file format and typed stop reason. Both APIs are read-only; prefix success does not authorize writable open or complete recovery. Invalid middle records, corrupt suffixes and sequence regressions refuse unchanged. Only the leased owner can repair a proven interrupted v2 suffix after the complete validation described above and in [page WAL framing](page-wal-framing.md).

Pure validation/size/exhaustion errors leave the owner usable. After uncertain durable IO, the first operation returns its error and every view/handle fails closed with `PageRecoveryRequired`; the lease remains held until final drop. The durable outcome of an errored operation can be unknown. These changes do not make the page, metadata, sidecar, and manifest files one crash-atomic transaction. [#41](https://github.com/Astraive/praxor/issues/41) tracks that publication/recovery boundary and a durable completeness witness.

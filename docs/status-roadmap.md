# Praxor status and delivery roadmap

Evidence checkpoint: merged main `4a276cfaca0ee6291f965f8788e0d8ca905c7682`, read on 2026-11-06. This is a capability map with explicit limits. It is not a release certification or a claim that all historical checks were rerun today.

[PR 103](https://github.com/Astraive/praxor/pull/103), “map remaining Praxor release work,” was **open and draft** at this checkpoint. Its head is not merged-main evidence. The native [engine epic](https://github.com/Astraive/praxor/issues/3), [SuperDB master issue](https://github.com/Astraive/poiesis/issues/8) and [Project 2](https://github.com/orgs/Astraive/projects/2) remain the delivery references.

## Merged bounded foundations

| Capability | Evidence entry point | Limit |
| --- | --- | --- |
| Recovery/flush/GC and scan/version safety | [Durability report](../reports/verification/2026-10-17-durability-batch-01.md) | Specific retained formats/failure models; no blanket power-cut claim |
| Owned descriptor memory and bounded cache metadata | [Memory report](../reports/verification/2026-10-17-memory-batch-02.md), [cache report](../reports/verification/2026-10-17-cache-recency.md) | Measurements apply to recorded workloads/revisions |
| Atomic primary/index groups and ordered group commit | [Storage WAL report](../reports/verification/2026-10-17-atomic-storage-wal-batch-02.md), [group commit](group-commit.md) | Not complete SQL transactions or a general distributed commit protocol |
| Writer leases and compatible-root admission | [Writer ownership](writer-ownership.md), [root formats](storage-root-formats.md) | Cooperative current writers; no automatic migration/adoption |
| Captured source-independent core backup | [Core backup](core-backup.md) | Supported core subset; no implicit v4/v5/history export |
| Fresh shared v3 record authority | [Record authority](core-record-authority.md) | Explicit fresh activation, fixed mappings; not populated legacy import |
| Same-owner primitive service/local client | [Record service](core-record-service.md) | Finite capabilities; no public protocol/security integration |
| Owner-bound retained payload snapshots | [Snapshot report](../reports/verification/2026-10-18-core-record-snapshots.md) | Process-local pins, not durable branch roots or numeric history |
| Bounded typed SELECT compiler | [Compiler report](../reports/verification/2026-10-18-query-compiler.md), [query readiness](query-readiness.md) | Process-local catalog and declared subset; no general SQL |
| Fallible retained fixture gateway | [Gateway report](../reports/verification/2026-10-18-query-gateway.md) | Controlled v1 document envelopes and scan-only production adapter |
| Standalone PVD1/H80/H64 decoders | [PVD1](provenance/pvd1-directory-v1.md), [H80](provenance/wal-v5-h80.md), [H64](provenance/wal-v5-h64.md) | Read-only untrusted bytes; no v5 writer/recovery/repair authority |

Historical closed work is not recreated because old audit text still says TODO. Conversely, closing one bounded slice does not close its broader parent. The [snapshot issue](https://github.com/Astraive/praxor/issues/29) remains open for product/Pit adoption despite merged engine-local F3 acceptance.

## Catalog and provenance boundaries

`src/core_catalog/database.rs` currently refuses successful creation/opening of a v4 catalog owner. Private codecs and witness modules support bounded proof work; they do not establish a writable persisted catalog. [The catalog issue](https://github.com/Astraive/praxor/issues/63) owns the first CREATE-only persisted schema operation. Its design does not make arbitrary v3 byte records into collection members or ship schema-bound DML.

Keep these existing open scopes distinct:

| Scope | Existing tracker |
| --- | --- |
| Recoverable multi-file page publication | [Page publication](https://github.com/Astraive/praxor/issues/41) |
| Broader facade/plugin parity/legacy import and cutover | [Consolidation](https://github.com/Astraive/praxor/issues/46) |
| Physical owner and WAL witness admission | [Physical owner](https://github.com/Astraive/praxor/issues/73), [WAL witnesses](https://github.com/Astraive/praxor/issues/74), [installed owner](https://github.com/Astraive/praxor/issues/75) |
| Private checked reopen and rotation recovery | [Reopen handoff](https://github.com/Astraive/praxor/issues/76), [rotation](https://github.com/Astraive/praxor/issues/77) |
| Physical-copy equality and installed relation | [Copy comparison](https://github.com/Astraive/praxor/issues/82), [installed relation](https://github.com/Astraive/praxor/issues/83) |
| Retained/unflushed history and writable handoff | [History proof](https://github.com/Astraive/praxor/issues/84), [handoff recheck](https://github.com/Astraive/praxor/issues/85) |
| Fixed/variable physical copies and admission tests | [Fixed copies](https://github.com/Astraive/praxor/issues/91), [variable copies](https://github.com/Astraive/praxor/issues/92), [admission boundaries](https://github.com/Astraive/praxor/issues/93) |
| Protected row origin through compaction | [Origin preservation](https://github.com/Astraive/praxor/issues/94) |
| Read-only active-v5 terminal-prefix classification | [Tail classifier](https://github.com/Astraive/praxor/issues/100) |

The closed [PVD1](https://github.com/Astraive/praxor/issues/95), [H80](https://github.com/Astraive/praxor/issues/97) and [H64](https://github.com/Astraive/praxor/issues/99) work does not authorize live format-5 activation, path/handle proof, installed-effect validation, truncation, writer restart or ancestry claims.

## Full engine destination

The destination remains broad. It is sequenced by dependency and evidence, not reduced to the currently bounded implementation.

| Phase | Required engine outcomes |
| --- | --- |
| Foundation | One canonical semantic owner, explicit format/identity/capability contracts, safe current-main admission and accurate evidence |
| Correctness | Complete applicable publication/recovery contracts, transaction isolation, bounded reads/work and durable acknowledgement behavior |
| Relational | Persisted catalog membership and DML, typed constraints, joins/aggregates, bounded CTE/window expansion, compatible result/error semantics |
| Multimodel | Missing/null documents and atomic patches, identified edges and reverse projections, bounded traversal, typed vector/text/geo/time operators and coherent index generations |
| Versioning | Engine retained-root and atomic delta-application capabilities integrated with Pit's refs, conflicts and reachability |
| Operations | Resource limits, cancellation, diagnostics, supported backup/restore/upgrades and runtime/client adoption |
| Distributed | Crash-safe terms/votes/log continuity, genuine peer quorums and transport-driven replication before wider failover or partitioning promises |
| Release | Equivalent-semantic correctness/performance evidence and the integrated SuperDB demonstration |

These are destination contracts, not assertions that each has an approved implementation-ready leaf today. New issues must have source-backed requirements, tests, size and native prerequisites. [GIT.md](../GIT.md) defines Draft/In review/Approved/Implemented/Superseded specification states and the milestone/project workflow.

The query target includes SQL and PQL front doors to one engine representation. It does not imply PostgreSQL extension or complete SQL/SurrealQL compatibility. Exact and approximate retrieval, global-top-k filtering and eligible-set top-k must remain distinguishable. Planner reordering requires semantic proof; benchmark wins require equivalent workloads and disclosed limits.

## Cross-repository responsibilities

Poiesis owns sessions, authorization, public protocols, configuration and operational orchestration. Pit owns commit graph, refs, branch policy, AS OF resolution, diff/revert and merge decisions. PoiesisQL owns optional tooling over engine contracts. Poietica owns the operator UI. WASM/client packaging is qualified separately. Engine runtime adoption reuses [the existing runtime routing issue](https://github.com/Astraive/poiesis/issues/5); optional tooling reuses [its existing baseline](https://github.com/Astraive/poiesisql/issues/2).

The final product gate needs a realistic dataset, supported SQL/PQL reads and writes, an explainable combined query, isolated branch changes/diff/merge, restart/recovery, consistent authorization and public client/UI behavior, plus reproducible comparison evidence. A completed engine decoder, catalog design or local query fixture satisfies only its own portion.

## Updating this page

Change status only with a real merged commit and scope-specific evidence. Identify exact source, platform, command exits, fixture/oracle and unsupported cases. A draft PR, accepted syntax, serialized type, green feature build or historical report is not proof of broader runtime readiness. Preserve issue and format authority limits when documenting progress.

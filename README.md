# Praxor

Praxor is the Rust database engine for the Poiesis ecosystem. The repository is `Astraive/praxor`; its current Cargo package, library and binary are named `praxis`, version `0.0.1`. This documentation does not rename those interfaces.

Praxor owns storage, recovery, transactions, indexes and the canonical parser, binder, planner, executor and semantic catalog. Poiesis supplies the product runtime, authorization and protocols. Optional PoiesisQL tooling consumes engine contracts; it does not own a second compiler or catalog authority.

The destination is a unified database: relational SQL and constraints, flexible documents, identified graph relationships, vector/full-text/spatial/time retrieval, and Pit-integrated history over shared correctness guarantees. That destination is broader than the currently verified engine.

## Current capability boundaries

| Surface | What current main establishes | Boundary |
| --- | --- | --- |
| Core KV and storage | WAL-backed batches, recovery, snapshots, maintenance and explicit writer ownership, with checked format/admission contracts | Physical power-cut guarantees and supported formats must be read in their specific reports; API success is not universal durability proof |
| Fresh v3 core record authority | Explicit `CoreDatabase`, shared `CoreRecordStore`, durable logical CRUD/batches and fixed mappings under one core owner | No automatic adoption of populated legacy roots, arbitrary plugin parity or persisted SQL schema membership |
| Retained record reads | Owner-bound process-local snapshot tokens preserve payloads through supported maintenance | Tokens are not serializable, remote, numeric AS OF selectors or durable Pit history |
| Local core service/client | Explicit same-owner adapters with finite capabilities and preserved errors | No implicit authorization, dynamic DDL, legacy physical administration or protocol rollout |
| Bounded Q1 compiler | Typed parameters, SELECT projection/filter compilation and read-only EXPLAIN against a process-local catalog | Joins, grouping, ordering, limits, history, mutations and specialized retrieval are outside this bounded path |
| Bounded Q2 gateway | Fallible, retained-view reads over controlled v1 fixture documents; production adapter is scan-only | The fixture envelope/catalog is not a general persisted collection schema or production SQL backend |
| v4 catalog work | Checked private codecs/witnesses and fail-closed entry points | `CatalogDatabase` cannot currently construct a successful writable catalog owner; CREATE and schema-bound DML are not shipped |
| v5 provenance formats | Read-only PVD1 directory, H80 WAL header and H64 typed-frame decoders | No v5 live writer, owner admission, replay/repair, ancestry guarantee or backup support follows from decoding |

The legacy parser/planner/executor exposes additional models and experimental paths. A reachable type, accepted syntax or successful plan construction does not prove execution semantics. Consult [query readiness](docs/query-readiness.md), the [current status and roadmap](docs/status-roadmap.md), and the linked verification reports before relying on a feature.

## Build and inspect

Use the pinned Rust `1.99.0` toolchain, with `rustfmt` and `clippy`, from [rust-toolchain.toml](rust-toolchain.toml). Native builds need a platform C/C++ toolchain for dependencies. Python 3 and PowerShell 7 support the repository's validation scripts; Docker is optional for the existing container verification path.

```sh
cargo check --locked --jobs 2 --benches --tests
cargo test --locked --jobs 2 --all
cargo run --locked -- --help
```

Run commands from this repository. Do not add sibling checkouts, absolute-path dependencies or preserved unpublished source to make a build pass. See [development](docs/development.md) for focused checks, native platform evidence and the distinction between quick local feedback and release qualification.

The default feature is `cpu`. GPU feature names exist for `gpu-wgpu`, `gpu-cuda`, `gpu-vulkan` and `gpu-metal`; a feature compiling does not establish a real accelerated implementation or a throughput claim. CPU behavior remains the correctness reference for any qualified acceleration.

## Storage and API orientation

`PraxisEngine` is the core KV surface. `CoreDatabase` explicitly activates the fresh protected v3 record authority and supplies a `CoreRecordStore` sharing its owner. The older pointer-oriented `store::StorageEngine`, standalone `RecordStore` and page-based owners retain their own documented compatibility protocols. They must not be merged by deleting modules or opening one physical root through an unrelated constructor.

Logical `document::RecordId { collection, key }`, core `store::RecordId(u64)` and page `identity::Rid` are separate domains. Neither matching numbers nor delimiter-concatenated strings authorize a conversion. Indexes normally reference canonical records; a declared lossy summary is not a second source of payload truth.

| Read next | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | Ownership, semantic/storage separation and current authority boundaries |
| [Core record authority](docs/core-record-authority.md) | Fresh v3 format, durable request ordering, protected roles and integrity limits |
| [Core record service](docs/core-record-service.md) | Explicit local service/client adapters and retained-token behavior |
| [Query readiness](docs/query-readiness.md) | Legacy observations, bounded compiler and query gates |
| [Storage source ownership](docs/storage-source-ownership.md) | Retained live owners and completed dead-source removal |
| [Root admission](docs/storage-root-formats.md) and [writer ownership](docs/writer-ownership.md) | Compatible opens, cooperative leases and refusal behavior |
| [Core backup](docs/core-backup.md) | Captured source-independent core backup/restore contract |
| [Checksum contract](docs/checksum-contract.md) | Historical IEEE bytes versus true v5 Castagnoli CRC32C |
| [PVD1](docs/provenance/pvd1-directory-v1.md), [H80](docs/provenance/wal-v5-h80.md), [H64](docs/provenance/wal-v5-h64.md) | Exact read-only provenance wire contracts |
| [Verification reports](reports/verification) | Revision-bound methods, results and limits |

## Contributing and delivery

Start with an approved bounded specification, a concrete oracle and the appropriate existing issue. [GIT.md](GIT.md) defines native issue hierarchy/blockers, labels, project/milestone fields, commits and normal merges. [AGENTS.md](AGENTS.md) gives the short operational rules for coding agents.

The cross-repository roadmap is tracked in the [SuperDB master issue](https://github.com/Astraive/poiesis/issues/8) and [Astraive Project 2](https://github.com/orgs/Astraive/projects/2). The existing [engine epic](https://github.com/Astraive/praxor/issues/3) remains active. A large backlog, a closed decoder issue or a draft completion document does not mean the unified database is finished.

This README describes merged main at `4a276cfaca0ee6291f965f8788e0d8ca905c7682`, read on 2026-11-06. [PR 103](https://github.com/Astraive/praxor/pull/103) was open and draft at that checkpoint; its completion document is not merged evidence.

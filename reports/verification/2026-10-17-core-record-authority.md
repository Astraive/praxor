# Shared core record authority verification — 2026-10-17

This F1 change introduces explicit fresh `CoreDatabase` creation/open and a
cloneable `CoreRecordStore` sharing the existing core KV owner. Allocation,
payload/state/counters and fixed mapping facts commit through the same bounded
queue, WAL, recovery authority, lease, health and maintenance. No legacy root is
adopted or migrated. Foundation and usable durable CRUD ship together.

Base: `8742d62dbfbea1cb085d4d960d6f4d8b2a1ef841`. Isolated tree:
`D:/poiesis-worktrees/phase-05-core-record-authority`, branch
`codex/phase-05-core-record-authority`. Reviewed source commit:
`e62c00e697ed28735fac4de874223cd82b7b0889`.
The branch preserves substantive foundation, queue and planner checkpoints and
the ordinary merge of the verified page-inventory default; no published history
was rewritten. Dependencies are locked, Rust is pinned to 1.99, and Cargo jobs
are limited to two per invocation. Windows and Linux use separate F: targets.

## Final verification

| Gate | Actual result |
| --- | --- |
| Frozen focused record suites | 120 passed, 0 failed; exit 0 |
| Public record integration suite | 9 passed, 0 failed; exit 0 |
| Native Windows full suite | 934 passed, 0 failed, 8 ignored across 96 result groups; exit 0 |
| WSL Ubuntu/Linux full suite | 932 passed, 0 failed, 8 ignored across 96 result groups; exit 0 |
| Strict all-target/all-feature Clippy | Windows exit 0 (9.87 s); Linux exit 0 (1 min 23 s) |
| Fmt, storage logging, storage boundary, diff | Each exit 0 on the frozen source |
| Independent public model/lifecycle harness | Strict Rust 1.99 build, run and rerun each exit 0; nine trace/policy cases per run match the prepared transcript |
| Actual supported old-writer refusal | Five old owner families refused a populated public-facade v3 root unchanged; final current reopen passed; all gate exits 0 |

The focused/public final logs use `core-record-f1b-checkpoint3-{focused,public}-v2`
under `D:/poiesis-worktrees/`. Full/platform/strict log names and explicit exit
files are recorded in
`D:/poiesis-worktrees/core-record-f1b-checkpoint3-gate-evidence-final.json`
(SHA-256 `70f502c402015adf129fee1e8e5c03b01bc76b4dddbbfa5e887b1d69581e721c`).
The explicit shared fmt/slog/boundary/diff exits and logs use the companion
`core-record-f1b-checkpoint3-final-repo-gates.json` and `final-*.log` files.
Full suites use default CPU
features; all-feature Clippy checks compilation and does not claim GPU execution.
Earlier checkpoint full counts
are historical evidence, not relabeled as these final platform results.
The first Linux inline command wrapper lost its shell-status variables and
exited 2 despite passing focused summaries. It is retained as runner failure
evidence. The authoritative rerun/full/strict use an external LF shell script
with immediately captured status and fail-fast sequencing; no blank status is
treated as success.

Both parent and an independent storage reviewer found the frozen source ready.
Before and after review, all 40 task inputs and 445 captured repository inputs
matched their SHA-256 inventories. Final inventories are
`core-record-f1b-checkpoint3-source-freeze-v3.json` (SHA-256
`0f531419a82951a173d20975017e7cfa5a85279430fcdc40ba995b5adb87b7b3`)
and `core-record-f1b-checkpoint3-all-input-freeze-v3.json` (SHA-256
`2c623e68cd5fea17444254350749bba329c6c3e79f3d4421fca983bca3d561d0`).
Default normal-library provenance is in the companion frozen-artifacts-v3 JSON.
The independently linked harnesses use those normal libraries, not cfg(test)
objects or a second Cargo build.

The final Cargo gates are reproducible from the reviewed source with explicit
external targets (substitute `/mnt/f/...-linux` for the Linux target):

```powershell
cargo test --locked --jobs 2 --target-dir F:/poiesis-targets/phase-05-core-record-authority --lib record
cargo test --locked --jobs 2 --target-dir F:/poiesis-targets/phase-05-core-record-authority --test core_record_store
cargo test --locked --jobs 2 --target-dir F:/poiesis-targets/phase-05-core-record-authority
cargo clippy --locked --jobs 2 --target-dir F:/poiesis-targets/phase-05-core-record-authority --all-targets --all-features -- -D warnings
cargo fmt --all --check
./scripts/verify_slog_storage.ps1
./scripts/verify_storage_boundary.ps1
git diff --check
```

Historical external proof inputs retain original HEAD `034a4a1` plus the frozen
candidate patch. Their HEAD/hash guards deliberately refuse a changed checkout;
later reproduction requires freshly approved metadata, without editing the
historical proof records.

## What was exercised

- Explicit empty-root activation, interrupted activation cuts and unchanged
  refusal of incompatible roots; v3 identity/epoch/role/incarnation/options and
  bootstrap binding; public forged/direct/CAS/transaction/CF access protection.
- Sealed record intents with typed receipts, accepted-only scratch overlays,
  valid/invalid/valid groups, RID/counter overflow, duplicate mapping inputs,
  unknown/null/known-dead deletes, blind explicit cleanup and stale mappings.
  The exact 64 MiB WAL payload boundary is accepted; exceeding that payload
  limit fails before rotation/append. Outer framing bytes are separate.
- Actual record durability under EveryBatch, GroupCommit and Never, sync failure
  and shared poison, queued completion, ordered no-frame barriers and Never
  rotation coverage. Healthy empty batches do not acknowledge a durability
  barrier or advance counters; poisoned empty requests fail.
- Actual interrupted record-frame recovery, semantic retained WAL/segment proof,
  available same-sequence equality, immutable payload/Fact correlation,
  birth/death/mapping causality, allocator cuts and ordered mapping intervals.
  The proof compares actual retained evidence and permits absent pruned history;
  it neither iterates declared RID ranges nor reconstructs an imaginary history.
- One current pin across combined mapping/state/payload reads, including a
  deterministic delete/compaction/GC pause. A separately reproduced concurrent
  future-Fact enumeration race now skips versions invisible at the captured pin.
  Missing/malformed live payloads propagate corruption/IO rather than absence.
- Exact descriptor/incarnation/L32 binary-key ranges, empty/NUL/FF/prefix
  neighbors, zero/MAX raw ceilings and immutable sorted-registry lookup. No new
  history cap or whole-database key enumeration is introduced for these reads.
- Shared automatic flush, all three compaction strategies with actual rewrites,
  externalized protected rows, GC, repeated reopen, portable backup/restore and
  retained lease lifetime across record/KV/database views.
- Semantic v3 verify rejects CRC-valid authority corruption in active and
  retained flushed WALs. One captured RAM authority and exact WAL prefixes remain
  stable while clone appends proceed. Verify performs no sync/repair/write;
  checkpoint hashing runs after live capture releases the writer. Offline
  checkpoint preflight still precedes restore-destination creation.

Actual RED logs for the two semantic-verify cases, concurrent range race and
legacy/v3 offline checkpoint ordering are retained under the checkpoint3 prefix.
Their corrected controls pass. Earlier recovery-review RED/positive matrices
are retained under the checkpoint2 and causal/retained-head/counter-cutoff/
final-matrix prefixes; their final finite matrix contains 31 passing cases.
The initial interrupted checkpoint2 full run is explicitly an interrupted run,
not successful full evidence.

The external logical model uses request-derived payload tables and append facts,
not the production protected codec, planner or recovery implementation. It
separates the 34-event fresh logical sequence from legacy's 35-entry physical
trace: legacy primary relocation consumes an entry, whereas fresh maintenance
keeps logical 29 at 29. Sequential public oracle calls do not claim one closed
commit group. The 1,025-fact binary-key case is a finite correctness sentinel,
not a benchmark or proof of arbitrary history. Both actual transcripts and the
prepared expectation have SHA-256
`070aa78e51483b356e48f4581646e48341bbb78c453d868b89ca260ef1fd4752`.
Source HEAD, all 445 captured inputs and both approved normal libraries matched
before and after execution. External source, runner, expected/actual output and
provenance use `D:/poiesis-benchmarks/core-record-public-parity-*`.

The actual old executable is frozen from supported baseline
`4230104b436070ab8e283cf6d9ae5f5b643a3a36`, SHA-256
`c82b5152046a7a1355f21d6f961b875f94710f75aa15f8e1bcec78b2c6143293`.
Core/pointer/standalone-record/page/catalog legacy positive controls passed;
the page control opens its writable owner rather than claiming a page CRUD test.
All five then refused a populated public v3 fixture with RIDs 1 dead, 2/3 live,
stale/same-batch mappings, raw watermark 8, payload bytes 47 and a KV marker.
Each call checks exact entry/byte equality except the neutral root lease file.
The new facade passes two initial reopens and another after all old writers.
Logs, fixture source, runner and provenance use
`D:/poiesis-benchmarks/core-record-facade-old-writer-*`.

Initial external fixture compile errors and harness artifact defects are
retained separately: array-reference conversion at a generic KV call, hashing
an open controller log, and CRLF versus LF in prepared text artifacts. Only
external harness arguments/log handling/line endings changed; every semantic
golden line stayed the same. The corrected actual runs found no production
parity mismatch. These attempts are not counted as production behavioral REDs.

## Scope and limits

This is additive fresh-root logical record authority. Legacy constructors,
physical stores, page/catalog writers and existing callers remain available
under their existing formats. Fixed mapping descriptors are immutable. F2
service adoption (#64) and plugin parity, F3 checked historical payload tokens (#29), F4 validated
disjoint import/cutover, catalog atomicity, query execution, Pit and the dependent
ecosystem remain tracked work. This change references #46 and does not close it.

Mapping raw ceilings select mapping decisions at a current core pin. They are
not historical payload snapshots and are not interchangeable with legacy raw
numbers or core commit sequences. Process pins do not establish durable Pit
retention. Available-evidence validation is an integrity check, not proof against
coherent arbitrary file rewrites or missing unobserved historical facts.

Verification byte counts include complete checked segments/checkpoint, captured
WAL prefixes and unique referenced value extents plus their 12-byte headers;
unreferenced file bytes and repeated physical IO are not counted. The encoding
workspace observer bounds one concrete encoded-frame allocation case, not RSS
or production throughput. No broad database performance claim is made.

Fault fixtures exercise API/IO/publication boundaries and supported recovery.
They do not qualify physical power-cut behavior. Existing Unix directory sync
and non-Unix directory-persistence limits remain. Old-writer refusal covers the
tested supported admission baseline, not arbitrary binaries predating it.

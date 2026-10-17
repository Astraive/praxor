# Core record service and local client verification — 2026-10-17

This F2 adapter adds `CorePrimitiveStorageService` and `LocalCorepraxisClient`
for an explicitly injected `CoreRecordStore`. CRUD, one-call atomic batches,
index access and durable flush use the same core owner, health, WAL and lease.
Existing legacy/page constructors, logical DTO serialization and `StorageKernel`
remain unchanged. This is the bounded adapter task #64 under #46.

Base: `ed0f6d504ebed158cc5a76cbbdc78a1595e525fb` (merged F1 PR65).
Isolated worktree: `D:/poiesis-worktrees/phase-06-core-service-adapter`, branch
`codex/phase-06-core-service-adapter`. Reviewed source commit: `4ba4782370741d37a8722c92564dd19dfae018e1`.
Rust is pinned to 1.99.0, dependencies are locked and each Cargo invocation
uses two jobs. Separate Windows and WSL Ubuntu/Linux targets are under D:.
Frozen F1 targets and preexisting dirty checkouts are preserved.

## Final verification

| Gate | Actual result |
| --- | --- |
| Public adapter integration | 7 passed, 0 failed; exit 0 |
| Relevant existing API/SDK and record-directory contracts | 8 passed, 0 failed; exit 0 |
| Private real blob IO/checksum and measured Never barrier | 2 passed, 0 failed; exit 0 |
| Actual queued append/sync failure matrix | 1 passed, 0 failed; exit 0 |
| Native Windows full suite | 944 passed, 0 failed, 8 ignored across 97 result groups; exit 0 |
| WSL Ubuntu/Linux focused/full | Focused 15 + private 2 + queued fault 1 passed; full 942 passed, 0 failed, 8 ignored across 97 groups; each exit 0 |
| Strict all-target/all-feature Clippy | Windows exit 0 (36.58 s); Linux exit 0 (1 min 12 s) |
| Fmt, storage logging/boundary and diff gates | Each exit 0 on the frozen source |

The final eight task files and all 451 captured repository inputs are hashed in
`D:/poiesis-worktrees/core-record-f2-source-freeze.json` (SHA-256
`747f1473fd11e16ab46deb366d9350db6475f9eef5efc44e05181d0155c811c1`)
and `core-record-f2-all-input-freeze.json` (SHA-256
`3788dfe822d4b662a850c9b883c9da132ef5698afd1b87a50094efbae471bf1b`).
Parent and independent storage review found this bounded source ready, with
zero task-file hash changes before/after their review. All 451 hashes and their file set match before/after both platform gates and after the source commit. The verification report is the sole file added afterward; it is not compiled input.
Final command exits, log hashes and source/file-set checks: `D:/poiesis-worktrees/core-record-f2-final-gate-evidence.json` (SHA-256 `5ab1c31cb1c961e41e72205f0545839ded148edffb5eb61979a17f81cb9e7be9`).

## Behavior exercised

- One whole batch remains one core atomic intent, including input ID order,
  duplicate mapping heads, healthy empty input and invalid later descriptor
  refusal without advancing core/record counters or allocating a RID.
- Only `KeyNotFound` becomes get absence. Null/unknown delete errors and known
  dead RID idempotent success remain distinct. Actual removed blob-file IO and
  payload CRC failures propagate through both service and client.
- Service/client/direct record clones and ordinary KV writes share ordered
  publication. Concurrent operations are read back before and after reopen
  under all three sync policies.
- A measured `Never` flush performs the durable barrier before core flush,
  covers preceding ordinary KV writes and survives actual WAL rotation/reopen.
- Real append and sync faults with queued service/client batches poison the
  common owner. Callers, reads of existing/missing rows, empty batches, delete,
  flush and direct record/KV writes fail closed. Prior acknowledged data remains
  after explicit reopen; failed requests are not promised rolled back.
- Constructor/static capability checks preserve the database tree. On Windows,
  the exclusive root lock is checked for presence/length; other file bytes and
  all directory entries are compared. No locked-file byte read is claimed.
  Final retained record views keep the lease after database/service/client
  handles drop; duplicate open fails until the last owner view drops.
- Literal existing DTO serde fixtures and legacy service/client/page/kernel
  constructor contracts remain compatible. Index methods are reached through
  the cloned existing record view; combined reads use its one-pin method.

The finite support query is static and IO-free, including on poisoned owners.
Logical CRUD, fixed mapping indexes and durable flush are supported. Physical
administration, dynamic plugins/catalog and historical payloads return a
separate typed unsupported capability. No new global storage error, report,
allocator, lock, cache, opener, retry loop or independent payload authority is
introduced. Request context uses the existing service event logger.

## Evidence boundaries and initial failures

The initial missing-symbol E0432 compilation failed before the new API existed;
that is build/TDD RED, not a behavioral failure. Correct direct delegation was
not deliberately broken to manufacture RED. The first public behavioral run
passed six tests and failed one fixture before constructor execution because
Windows denies reads of the exclusive lock artifact. The fixture now compares
that artifact's presence/length. The first private read/barrier run passed one
and failed one fixture because flush retained an inline RAM version; reopening
obtained the actual persisted external pointer. These initial logs are retained
and are not attributed to product behavior defects.

Focused logs and the external progress file use the `core-record-f2-` prefix
under `D:/poiesis-worktrees/`. This adapter does not implement retained snapshot
history, a coherent diagnostics report, dynamic DDL/plugins, legacy page import,
query execution or Poiesis/Pit/PQL/Poietica/WASM adoption. Those remain separate
tracked phases. Full default CPU tests and all-feature static compilation do
not claim GPU execution, performance gains or hardware power-cut qualification.




## Reproduce the candidate gates

Run from the reviewed clean source; use a separate explicit per-task Linux
`/mnt/d/poiesis-targets/phase-06-core-service-adapter-linux` target under WSL.
The external LF Linux driver captures each actual status immediately, writes
sidecars and fails before the next gate on error. Windows and Linux sessions
39971 and 97250 both completed with exit 0. Every gate log hash matches the
final evidence file, independently checked by the parent.

```powershell
cargo test --locked --jobs 2 --target-dir D:/poiesis-targets/phase-06-core-service-adapter --test core_record_service_adapter --test api_sdk_contracts --test kv_record_directory
cargo test --locked --jobs 2 --target-dir D:/poiesis-targets/phase-06-core-service-adapter --all
cargo clippy --locked --jobs 2 --target-dir D:/poiesis-targets/phase-06-core-service-adapter --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
pwsh -NoProfile -File scripts/verify_slog_storage.ps1
pwsh -NoProfile -File scripts/verify_storage_boundary.ps1
git diff --check
```

Full-suite log SHA-256 values are
`0970ba89b67b5d8d507e9600e70a7d290e89b21e34768d25e38e873f419ca7f7`
(Windows) and
`e80aa7e89c9f45cddfc0d197ed26456d6c46566ff9ac47218c05cf11476082a1`
(Linux). The final evidence also records the private/error gate commands and
all completed focused, strict, repository and input-proof results. Parent
`core-record-f2-parent-{windows,linux}-full.json` files independently summarize
the actual full logs and explicit exit sidecars. Earlier failures remain in
the external progress record; none is relabeled as final success.

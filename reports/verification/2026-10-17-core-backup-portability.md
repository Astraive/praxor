# Core backup portability and capture (#42)

Issue: https://github.com/Astraive/praxor/issues/42

Implemented in `codex/phase-04-backup-portability`, originally based on6840d4a,
then synchronized with default fb49a216f06ddacca3283fe9ba164a33e54be20f before
final verification. Independently reviewed source and tests are committed as
`959fb98bfc02eb314066423c842a21bf1f532e1c`; this report and contract documentation
follow in a separate documentation commit.
Owned worktree stash backups were explicitly retained at
`abc02bb3365b027a0c484a1258708a0e1ab78349` and
`cce7645d00fa2d1c5cfdb85603b2fc2b7f3656ad` through those synchronizations.

## Change

Backup captures in-memory authority and exact WAL byte lengths under maintenance
then writer serialization, releases writer before bulk IO, and retains maintenance
through publication. Required WAL IDs and complete all-record sequence coverage
prove the unflushed suffix through the captured sequence. Restore reads a supplied
offline bundle, never a persisted source-path fallback.

One lossless checked segment codec serves readers, writers and backup relocation.
It preserves all retained entry/order/TTL metadata and raw expiry-blob pointers.
Typed role/file-ID resolution validates local digests and blob records, copies
older referenced value logs, rewrites only validated final target paths, and
regenerates checksummed segments, checkpoint and manifest metadata. Compression
output lengths are validated before untrusted output reservations: LZ4 has a
nonallocating length/offset preflight, Zstd checks available content-size metadata
then streams with fallible growth bounded by the outer block size. Native decoder
internal allocations remain library-managed; the allocator regressions measure
Rust output buffers, not a universal native-memory ceiling.

Staging remains inside the final canonical destination. A synced private prepared
marker is renamed to the fixed `CORE_COPY_INCOMPLETE` sentinel before deletion.
MANIFEST authority is removed before dependencies and installed last; final static
role/digest validation precedes marker removal. All live admission paths, including
the page-base helper, refuse marker presence. Explicit copy retry accepts exact
marker bytes and a strict Core-only layout, preserving permanent root/primary
locks and refusing malformed, foreign or mixed authority without deletion.
First publication and explicit retry both synchronize the marker file and parent
before deleting old authority, including when a previous rename's sync failed.

## Regression evidence

Logs reside in `D:/poiesis-worktrees/`; every Cargo command used `--locked`,
`--jobs 2` and target `F:/poiesis-targets/phase-04-backup-portability`.

- `backup-42-agent-red.log`: actual seven intended source-independence/history/
  expiry/compression/GC failures before implementation, exit101.
- `backup-42-capture-publication-red.log`: actual three capture/publication failures,
  including GC escaping retention, exit101. An invalid too-small WAL-size fixture
  was corrected before this evidence.
- `backup-42-foreign-marker-red.log`: actual two unsafe marker-admission failures,
  exit101.
- `backup-42-review-red.log`: missing required WAL and whole missing committed frame
  both restored incorrectly, two intended failures, exit101.
- `backup-42-decode-limits-red.log`: malformed tiny Zstd input allocated128MiB of
  Rust output before rejection, exit101. The LZ4 test in this same run was mutex
  poisoned; it is not independent negative allocation evidence.
- `backup-42-sentinel-preparation-red.log`: prepared-marker obstruction incorrectly
  allowed replacement, one intended failure, exit101.
- `backup-42-final-focused.log`:40passed/0failed across backup8, validation5,
  format-codec3, allocation-bound4, ownership20. Includes explicit source C: to
  bundle/restore F: evidence with source and bundle subsequently hidden.
- `backup-42-final-publication-green.log`:8private capture/publication/abandoned-stage
  tests passed. A later relative-label fixture restored correctly but initially
  used mismatched reopen configuration; the test configuration was corrected.
- `backup-42-final-full.log`:660passed/0failed/8ignored across78reported targets,
  exit0, including all9private capture/publication/relative-label tests. The only
  subsequent source change moved the cfg(test) hooks module to file end for Clippy.
- `backup-42-final-clippy.log`: initial strict all-target/all-feature run exited101
  only for `items_after_test_module`. After that ordering-only correction,
  `backup-42-final-clippy-retry.log` exited0, finished in13.49s.
- `cargo fmt --all --check`, `scripts/verify_slog_storage.ps1`,
  `scripts/verify_storage_boundary.ps1` and `git diff --check`:exit0. Formatting and
  whitespace were rechecked after the module-order correction.
- Final review additionally found a retry-marker sync ordering gap. The Windows
  sharing-denial regression in `backup-42-retry-marker-red.log` observed an unsafe
  successful copy on the old path, exit101. An earlier readonly-attribute fixture
  was ineffective and was corrected before this evidence. After unconditional
  marker-file/parent sync before deletion, all10private tests passed in
  `backup-42-retry-marker-green.log`, including source write health and later retry.
  The earlier660-test run is retained as pre-correction evidence.
- `backup-42-final-combined-full.log`: exact final source on fb49a216 plus this patch,
  661passed/0failed/8ignored across78reported targets, exit0. Includes all10private
  capture/publication/relative-label/retry-sync tests.
- `backup-42-final-combined-clippy.log`: exact final source, strict all-target/
  all-feature Clippy exit0,8.82s. Final fmt, slog gate, storage-boundary gate and
  whitespace checks also exited0 after this complete-suite rerun.

Independent phase01 review is READY after narrow confirmation of this final
ordering correction; the reviewer ran no builds and found no remaining concrete
blocker in codec, capture, role relocation, publication or retry/cleanup scope.

Ownership coverage retains all live-writer denial/process/drop/alias tests.
Previous fixtures that expected stopped foreign Pointer/Record roots or arbitrary
alias destinations to be erased now assert refusal and unchanged bytes. Core and
neutral-primary lock-container replacement and repeated backup/restore reuse stay
covered. This is the deliberate Core/Empty destination-admission contract.

## Limits

Current-platform path spelling and separate-volume copies are exercised. Relative
legacy labels are resolved by role without following the working directory; cross-OS
spellings may be explicitly refused. Opaque auxiliary application files are not
included. Ordinary engine opens do not relocate moved databases; restore performs
that relocation. Unprovable sparse/equal/decreasing legacy WAL suffixes are refused
by backup while ordinary replay remains unchanged.

Replacement is synchronous and nontransactional, with maintenance paused for its
duration. A failure after sentinel publication can require explicit retry from a
valid source; the old backup is not guaranteed available. Tests simulate in-process
failure boundaries and ordinary reopen, not power loss. Non-Unix parent-directory
sync retains its existing no-op limitation. Older binaries/raw tools ignoring the
ownership or sentinel protocol remain unsupported. No new identity migration,
permanent MVCC layer, physical pin registry, atomic rollback or power-cut durability
claim is introduced.

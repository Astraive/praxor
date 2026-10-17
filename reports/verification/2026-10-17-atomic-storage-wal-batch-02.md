# Atomic primary and index WAL groups

This batch fixes issue #11. It was independently reviewed, including revisions
for composite deletes, validation before mutation, partial compaction failures,
and cleanup of already tombstoned records.

## Durable contract and compatibility

`StorageWal::append_batch` writes one ordered, checksummed v2 envelope for all
entries. Recovery admits the entire group or none of an interrupted suffix;
complete corruption remains an error. Existing v1 binary and JSON entries are
read as singleton groups, including legacy unsegmented WAL prefixes alongside
new segmented files. Older readers cannot read newly written v2 groups.

The group payload contains magic, version, mirrored payload length and entry
count, followed by length-prefixed v1 binary entries. The existing outer
length/checksum frame remains. Payloads, including nested metadata, are limited
to 64 MiB; the outer frame contributes eight additional bytes. Groups rotate
before append and are never split at the segment size target.

Primary records are prepared without publishing live mappings. Payload sync and
the atomic WAL group precede primary/index publication. Composite cleanup deletes
journal secondary and primary tombstones together. Unknown record IDs fail
preflight before WAL mutation; known tombstones preserve idempotent deletion and
stale-index cleanup. Index insertion continues to require a live record.

Ambiguous append/sync failures, post-WAL publication errors and failed mutating
compaction require close/reopen. A poisoned handle rejects reads, writes and
maintenance. Recovery may find committed records from an unsuccessful call;
such an error does not promise that no bytes reached durable storage.

## Verification

Integrated on merged default `2ebe0634f8e8c35b28ab7fa9a993d68e3d0f20d2`, on Windows
with pinned Rust 1.99.0:

```powershell
cargo test --locked --jobs 2 --target-dir F:/poiesis-targets/phase-02-atomic-wal
cargo fmt --check
cargo clippy --locked --jobs 2 --target-dir F:/poiesis-targets/phase-02-atomic-wal --all-targets --all-features -- -D warnings
./scripts/verify_slog_storage.ps1
```

The integrated locked suite passed 402 tests, failed none, and ignored eight.
Formatting, strict Clippy and storage logging checks passed.

Fourteen dedicated integration regressions plus a partial-compaction unit
regression cover every-byte truncation of grouped mutations and cleanup deletes,
primary/index agreement, mixed legacy/current replay, legacy base-file migration,
repair followed by append, rotation, malformed lengths/counts/versions, checksum
corruption, payload limits, staged publication, poisoning and delete preflight.
The baseline failures were recorded before each corresponding correction.

These tests simulate truncated files and injected in-process failures. They do
not establish machine power-loss behavior or Windows directory persistence. This
batch does not change the separate core KV WAL framing or implement concurrent
group commit.

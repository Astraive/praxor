# Transaction reads of staged writes

This batch fixes issue #15 on merged default
`2ebe0634f8e8c35b28ab7fa9a993d68e3d0f20d2` and was independently reviewed.

Transaction `get` now overlays matching staged operations in batch order on the
pinned transaction snapshot. Puts, deletes and explicitly expired puts mask
earlier values. Merge-only chains resolve against the pinned base using the
configured column-family operator. Operations on other keys or families do not
participate. Clones retain independent staged batches and their shared snapshot
pin. Commit conflict checks retain the original snapshot watermark.

No public API or persisted format changes. Automatic column-family TTL remains
normalized during commit, while explicit absolute expiries use the canonical
resolver. Staged reads do not publish values, allocate sequences or write WAL.

Six public and seven internal variant regressions failed against the old
snapshot-only `get`, then passed with the overlay. They cover operation ordering,
empty/binary keys and values, abort, clones, untouched-key snapshot visibility,
external write conflicts, merge operators, delete/expired-put barriers, family
isolation and automatic TTL behavior.

On Windows with pinned Rust 1.99.0:

```powershell
cargo test --locked --jobs 2 --target-dir D:/poiesis-targets/phase-02-transaction-local-reads
cargo fmt --check
cargo clippy --locked --jobs 2 --target-dir D:/poiesis-targets/phase-02-transaction-local-reads --all-targets --all-features -- -D warnings
./scripts/verify_slog_storage.ps1
```

The integrated locked suite passed 400 tests, failed none, and ignored eight.
Formatting, strict Clippy and the storage logging gate passed.

# Column-family incarnation recovery

Issue: [#25](https://github.com/Astraive/praxor/issues/25). Base: merged default
`c0934652ea1572094b2f48a284cf0115d8d6efe4`.

Dropping a column family removed its live state, but reopening replayed its old
WAL operations and flushed versions. Recreating the same name could therefore
restore retired keys or use an old value as a replacement family's merge base.
Queued writes could also retain policies from a family that had been replaced.

The v2 manifest records active incarnation IDs and sequence floors plus an
independent checked allocation counter. Recovery filters retired versions before
deduplication or insertion, while observing every durable WAL sequence watermark.
Admission captures incarnation IDs and policies together; the writer rejects an
obsolete whole batch before assigning a sequence or appending its WAL record.
Other valid cohort members remain eligible. Checkpoints and backup manifests
carry the same metadata.

## Regression evidence

Before production changes, the three original public recovery tests failed:
retired WAL replay after reopen/recreate, retired flushed keys in a replacement,
and a replacement merge using the retired base. Extended tests produced six
failing integrations, and all 16 malformed-v2 fixtures were accepted by the old
loader. A deterministic coordinator test also failed because an admitted mixed
batch normalized under the old family's TTL could enter its replacement.

The final tests cover WAL and segment filtering through repeated reopen,
flush/compaction/GC, merge isolation, mixed default/family preservation, distinct
IDs without intervening writes, legacy active and empty-family migration,
sequence-zero legacy replay, filtered-record watermarks, strict v2 validation,
stale-policy cohort rejection, counter exhaustion, checkpoint/backup metadata,
and pinned snapshots across family drop. Existing persistence-failure tests also
assert that failed CF transitions preserve incarnation maps and counters.

Integration caught an intermediate compatibility error: decoding through generic
`toml::Value` rejects full-width unsigned integers used by existing configuration
and Bloom metadata. A small typed presence header followed by the original typed
manifest model preserves that range; the existing recovery tests pass.

## Verification

Windows, Rust 1.99.0, locked dependencies, two Cargo jobs, explicit
`F:/poiesis-targets/phase-03-cf-generations` target:

- Full suite: **451 passed, 0 failed, 8 ignored**, across 58 test targets.
- `cargo fmt --all -- --check`: passed.
- Storage slog and boundary gates: passed.
- `cargo clippy --locked --all-targets --all-features --jobs 2 -- -D warnings`:
  passed.
- Independent read-only review: ready, no blockers.

Local evidence: `D:/poiesis-worktrees/cf-generations-{red,extended-red,admission-red,full,clippy}.log`.
These are recovery and deterministic admission tests, not simulated power-loss
or filesystem durability experiments.

## Compatibility limits

Version-1 active families become explicit legacy ID 0/floor 0 in memory; the
next structural save persists complete v2 metadata. The default family retains
that identity. Newly created families use positive IDs even at sequence zero.
Neither WAL records nor segment encodings change in this patch.

Old binaries do not check manifest versions, so downgrade after writing v2 is
unsupported; the version field cannot force those binaries to reject the file.
Missing historical DDL intent cannot be reconstructed for already mixed legacy
incarnations. A data snapshot does not preserve access to a dropped family.
Public optimistic transactions currently operate only on the default family;
adding multi-family transactions will require an explicit schema lifetime
contract.

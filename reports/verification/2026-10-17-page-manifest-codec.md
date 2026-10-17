# Page manifest codec verification — 2026-10-17

This candidate validates the exact v1 page manifest representation, bounds row
allocation by actual input, and checks format-version/flag domains. Managed
startup decodes a present inventory before WAL repair/layout writes even with
zero collections, sharing that inventory across startup collection checks.
The existing new-entity wrapper still loads its current inventory. Save,
encoding, upsert and raw ownership behavior remain unchanged.

Base: `9ffb90ab101ca0be194dbe60df6a64692143e50c`, worktree
`D:/poiesis-worktrees/phase-04-page-manifest-codec`, branch
`codex/phase-04-page-manifest-codec`, plus the candidate patch. All builds use
the repository-pinned Rust 1.99, locked dependencies, jobs 2 and dedicated target
`F:/poiesis-targets/phase-04-page-manifest-codec`. No original checkout or the
independently owned #46 source was changed. Parent owns commit/PR/integration.

Verified production/test commit: `3963c9ae38172a750fedb4ea17ecb617248ad4a2`
(`fix(manifest): bound page inventory decoding before recovery`). The full suite
and strict gates used the unchanged five-file physical hashes listed below;
the parent independently parsed all 90 result groups and checked all gate exits.
Strict Clippy completed in 37.42 seconds on this host. Documentation is recorded
in the following commit; required current-head Linux CI remains the merge gate.

## Regression evidence

Logs below are in `D:/poiesis-benchmarks/`.

| Check | Log | Result |
| --- | --- | --- |
| Ported actual public RED before production changes | page-manifest-codec-versioned-red.log | exit 101, 3 controls passed / 5 intended failures |
| Expanded raw/managed RED before production changes | page-manifest-validation-red.log | exit 101, 3 controls passed / 3 intended failures |
| Frozen focused seven binaries | page-manifest-focused-green.log | exit 0, 40/0 |
| Full locked suite | page-manifest-final-full.log | exit 0, 788 passed / 0 failed / 8 ignored, 90 result groups |
| Strict all-target/all-feature Clippy | page-manifest-final-clippy.log | exit 0, warnings denied |
| Fmt/slog/boundary/diff | page-manifest-final-{fmt,slog,boundary,diffcheck}.log | each exit 0 |

The public eight-test harness was versioned before production edits. A 17-byte
file with count 65536 requested one 5,242,880-byte allocation before rejection.
After the fix, its largest observed allocation is 118 bytes. The thread-local
observer covers only synchronous load, excluding setup; it records the maximum
individual successful allocation/reallocation request, not total/retained/RSS
memory or allocations on other threads. No multi-GiB count was executed.
Other actual REDs were version 65537 aliasing 1, recoverable flag 2, and ignored
payload/outer trailing bytes. Controls preserve writer bytes, duplicates/order,
u16::MAX, missing/empty inventory and existing truncation/checksum refusal.

The added validation suite covers each string's invalid UTF-8/claimed extent,
every minimal-row payload truncation, exact envelope length/overflow claim,
unknown header identity/version, zero/MAX versions, both flags, empty/multibyte/
opaque strings and duplicate order. All runtime fixtures use portable tempdirs.
An initial wrong public import path in the new test was corrected before its
behavioral RED; `page-manifest-validation-compile.log` retains that compile
attempt. It is not counted as a behavioral failure or missing-API RED.

Managed RED proved malformed manifests could expose a zero-collection owner
and recreate a missing optional layout file. With an independently authoritative
managed v2 root and recognized seven-byte torn frame, malformed inventory allowed
actual WAL repair from 23 to 16 bytes. GREEN requires refusal with every entry/byte
unchanged before repair/layout. Restoring valid manifest bytes permits existing
#39 repair and healthy page mutation. A valid unresolved inventory control stays
accepted and supports two collections' mutations/reopen; there is no presence
walk or new schema/reference-integrity policy.

## Verification method and review

Source/tests are frozen for focused, full and strict checks; documentation
completion follows. Parent and phase01 independent source reviews are READY. Both confirmed the
frozen five-file source/test checkpoint; the independent reviewer compared all
five hashes before and after review with no differences. All five physical source/test hashes were checked again after the gates with
no differences. No source/test change followed focused verification. The serial
full/strict process exited 0 and was closed before handoff; there are no worker
build sessions left running. Exact exits are retained in
`D:/poiesis-benchmarks/page-manifest-final-exits.json`. The final changed-file
inventory and evidence-log hashes are in
`D:/poiesis-benchmarks/page-manifest-final-provenance.json`. Any later source change
requires affected verification.

```powershell
cargo test --locked --jobs 2 --target-dir F:/poiesis-targets/phase-04-page-manifest-codec --test page_manifest_codec --test page_manifest_validation --test durability_page_manifest --test page_wal_owned_framing --test page_wal_admission --test page_collection_state --test catalog_shared_concurrency -- --nocapture
cargo test --locked --jobs 2 --target-dir F:/poiesis-targets/phase-04-page-manifest-codec --no-fail-fast
cargo clippy --locked --jobs 2 --target-dir F:/poiesis-targets/phase-04-page-manifest-codec --all-targets --all-features -- -D warnings
cargo fmt --all --check
./scripts/verify_slog_storage.ps1
./scripts/verify_storage_boundary.ps1
git diff --check
```

## Source authority and scope

Frozen physical Windows worktree SHA-256 hashes, before Git newline filtering,
are retained in `D:/poiesis-benchmarks/page-manifest-frozen-source.json`:

| File | SHA-256 |
| --- | --- |
| src/manifest/page.rs | 9ea2bdb2af91ee8df702231c485c06d79080c7b7f7502a677f8ee2e33d2efa74 |
| src/record/database.rs | 67663153df870afab32b38b450f021444eef2241a75ea45004abd5a39f1e8d6c |
| src/record/recovery.rs | 0f14c3601cb5e81b7bee9726f06a377694b7a19ce40ad934a0f43cfbc66def8e |
| tests/page_manifest_codec.rs | 3624baae4c59985a92a7502409429a68d6f89389ab3c45d10591ec3a1175ab6c |
| tests/page_manifest_validation.rs | 2fa7f48cabd9ca7e09f4d574ceefb284976f67e601acd0866ac03228528fa27e |

See [page-manifest-decoding.md](../../docs/page-manifest-decoding.md).
This addresses [#57](https://github.com/Astraive/praxor/issues/57). It does not
change v1 publication, raw utility ownership, default missing-manifest meaning,
or physical path portability. Strict representation does not make an inventory
complete or make files crash-atomic. The separate whole-collection-loss RED and
all completion-witness/generation/recovery guarantees remain
[#41](https://github.com/Astraive/praxor/issues/41). No additional format,
acknowledgement, historical retention or power-loss guarantee is claimed.

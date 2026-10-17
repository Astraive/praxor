# Catalog codec bounds verification — 2026-10-17

The ten v1 catalog decoders reserved an untrusted row count before proving the
actual payload could contain those rows. Attribute IDs narrowed to u16, inner
and outer trailing bytes were ignored, boolean flags accepted any nonzero byte,
and optional-file checks followed aliases or treated some malformed roles as
absent. The candidate validates the wire/input boundaries while preserving the
merged catalog owner, save preparation, valid v1 bytes and semantic compatibility.

Worktree: `D:/poiesis-worktrees/phase-04-catalog-codec-bounds`, branch
`codex/phase-04-catalog-codec-bounds`, exact verified merged #48 baseline
`94869e2ff0a71e105ecd4bc61769d5e6c4c86ff9` plus the candidate patch. Original
dirty checkouts and the prior ownership worktree were preserved. The parent
owns commit, push, PR and integration.

The final locked Windows suite exited **0: 730 passed, 0 failed, 8 ignored**,
across 86 result summaries including the ignored doctest. All-target/all-feature
Clippy with warnings denied, formatting, slog, storage boundary and diff checks
exited 0. Parent independent source review and the private-helper adaptation
re-review are READY. Source/test hashes were rechecked after all gates and are
unchanged. Documentation completion followed without another source edit.

## Regression evidence

All local logs are under `D:/poiesis-benchmarks/`.

| Check | Log | Result |
| --- | --- | --- |
| Original public RED, before production changes | catalog-codec-merged48-red.log | exit101, 1 control passed /14 intended failures |
| Expanded validation RED, before production changes | catalog-codec-validation-red.log | exit101, 4 controls passed /6 intended failures |
| Unchanged all-ten golden baseline, before changes | catalog-codec-golden-baseline.log | exit0, 3/0 |
| Final focused seven integration binaries | catalog-codec-final-focused.log | exit0, 51/0 |
| Private publication/preparation tests after module adaptation | catalog-codec-private-green.log | exit0, 5/0 |
| Full locked suite | catalog-codec-final-full.log | exit0, 730/0/8 across 86 groups |
| All targets/features Clippy, warnings denied | catalog-codec-final-clippy.log | exit0 |
| Formatting | catalog-codec-final-fmt.log | exit0 |
| Slog/storage boundary/diff | catalog-codec-final-slog.log, catalog-codec-final-boundary.log, catalog-codec-final-diffcheck.log | all exit0 |

The ported public `tests/catalog_codec_bounds.rs` is the actual parent harness,
then formatted and instrumented to print the successful allocation observations.
Each count fixture is a 17-byte file with count 65,536 and no rows. A thread-local
observer surrounds only the synchronous `CatalogStore::load`, excluding setup.
It records the largest individual requested allocation/reallocation, not total
requested bytes, retained/live bytes, RSS or other threads. Before the fix,
requests were 2,097,152–5,242,880 bytes (2–5 MiB; indexes requested 5,242,880).
Afterward all ten loads had a largest observed request of 896 bytes. No multi-GiB
count allocation was attempted.

The validation matrix covers all ten tables' minimal valid row shapes, every
truncated payload prefix, trailing payloads, truncated/excess/overflow-claim
envelopes, bad magic/version/checksum, every string field's actual-length and
UTF-8 checks, both attribute-ID narrowing defects, unknown closed tags and
nonboolean flags. Rejected reads preserve entries/bytes and acknowledged page
data. A separate control proves catalog clones, later catalog save/load, durable
page writes and managed WAL sync remain healthy after a malformed load.

Read-role controls cover directories, a non-directory parent, regular and
dangling leaf aliases, an aliased parent, missing/zero-length regular optional
files and a Windows exclusive-open non-NotFound IO error. Alias tests snapshot
the outside target too. Runtime fixtures use portable temporary directories;
the Windows-specific IO error case is conditionally compiled.

Compatibility controls preserve all ten original literal complete TCAT golden
files; zero/repeated IDs and row order; the full u16 attribute-ID range; empty
and multibyte UTF-8 strings; opaque type codes/kind/metric/pointer targets; all
six storage and three compression tags; `None`/`Some(0)`/`Some(255)`; and an
ignored arbitrary type byte when the presence flag is zero. Optional empty
strings retain the established decode-to-None behavior.

The first full attempt exposed six compile-scope errors in existing private
publication tests after moving the decoder module; no tests executed in that
attempt. `catalog-codec-full-compile-scope.log` preserves it. Three raw disk
assertions now call the new private read/decoder helpers with catalog-parent
visibility, preserving their real partial-publication observations without
reentering the held root guard. The save preparer, PageDatabase and public
golden tests remain unchanged.

## Verification method

All builds run serially in the dedicated F: target using the repository-pinned
toolchain, locked dependencies and two jobs. Final source and tests are frozen
through focused, full and strict checks; documentation completion follows.

```powershell
cargo test --locked --jobs 2 --target-dir F:/poiesis-targets/phase-04-catalog-codec-bounds --test catalog_codec_bounds --test catalog_codec_validation --test catalog_wire_compat --test catalog_preflight --test catalog_ownership --test catalog_shared_concurrency --test catalog_store -- --nocapture
cargo test --locked --jobs 2 --target-dir F:/poiesis-targets/phase-04-catalog-codec-bounds --lib catalog::
cargo test --locked --jobs 2 --target-dir F:/poiesis-targets/phase-04-catalog-codec-bounds --no-fail-fast
cargo clippy --locked --jobs 2 --target-dir F:/poiesis-targets/phase-04-catalog-codec-bounds --all-targets --all-features -- -D warnings
cargo fmt --all --check
./scripts/verify_slog_storage.ps1
./scripts/verify_storage_boundary.ps1
git diff --check
```

## Contract and limits

See [catalog-decoding.md](../../docs/catalog-decoding.md). The new private decoder
checks exact envelope length/CRC, proves row count against actual bytes after the
count before fallible reservation, borrows checked UTF-8 before fallible string
allocation, rejects out-of-range attribute IDs, and validates existing closed
tags/flags. It reads only regular nonalias roles and recognizes optional absence
only for NotFound or the existing zero-length regular-file convention.

There is no public API, writer coordination, wire version, semantic schema,
reference-integrity or generation change. Actual physical files are still read
into memory; the checked row/string allocations are not a fixed whole-process
memory budget or protection against arbitrary external path-replacement races.
The existing shared live root guard does not prove crash-atomic publication of
ten files. [#41](https://github.com/Astraive/praxor/issues/41) retains durable
generation/recovery completeness. This work addresses
[#51](https://github.com/Astraive/praxor/issues/51).

## Frozen source authority

Physical Windows SHA-256 hashes of the frozen source/tests before Git newline
normalization (also retained in
`D:/poiesis-benchmarks/catalog-codec-frozen-source.json`):

| File | SHA-256 |
| --- | --- |
| src/catalog/mod.rs | 72a33311b1e319fae6519314005a1004c76903edda95319da21c162d3b42163f |
| src/catalog/decode.rs | 647ab7ae6d313ace8ea5378da7ccfd8ea1ff7887345cf77749026599556d9d4c |
| src/catalog/publication_tests.rs | 1855595ea80d17f32ded9085ad3bc7b25f05bf7b8288aaab88c5535741958bb2 |
| tests/catalog_codec_bounds.rs | c67887fc9fe4b67047bc90adc0176362c806ed2ea55906ac182b9c628172b496 |
| tests/catalog_codec_validation.rs | 9b11a04955960975844faa02bacd6d73eeb06e159482a52dea693804d11ee57b |

The candidate was verified as an uncommitted patch. The parent owns commit/PR
and exact-head CI; this record does not substitute local checks for Linux CI or
claim verification of a future default composition. All worker sessions are
closed, and no additional build or source change is pending.

Verified source/test commit: `da09f002c90e63acead5623cacb835e0a05ed5a7`.


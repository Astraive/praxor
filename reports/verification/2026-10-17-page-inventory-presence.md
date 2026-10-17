# Page inventory presence verification — 2026-10-17

This candidate checks the current-root presence of the three known v1 page
writer roles before WAL reads/repair, layout creation or owner exposure. It uses
the strictly decoded startup manifest and private typed terminal grammars;
manifest labels are never IO destinations. Save, upsert, codec, selected-file
checksum ordering and directory/page body validation are unchanged.

Base: `6090422231aab665ea7c4300d60eda7b530977ab`. Owned tree:
`D:/poiesis-worktrees/phase-04-page-inventory-presence`, branch
`codex/phase-04-page-inventory-presence`. Repository-pinned Rust 1.99,
locked dependencies, jobs 2; dedicated target
`F:/poiesis-targets/phase-04-page-inventory-presence`. Original checkouts and
the independently owned #46 source are untouched. Parent owns integration.

Reviewed source/test commit: `47efe79b43fcad547b6c587c0e65591a57f6511d`.
The subsequent documentation commit records the same frozen verification.

## Actual regression and compatibility evidence

All logs below are under `D:/poiesis-benchmarks/`.

| Check | Log | Actual result |
| --- | --- | --- |
| Versioned public baseline RED before production edits | page-inventory-presence-red.log | exit 101; 4 controls passed / 6 failed across two binaries |
| Initial bounded implementation | page-inventory-presence-green.log | exit 0; 10 passed |
| Final focused page/manifest/WAL suites | page-inventory-focused-green.log | exit 0; 52 passed across eight binaries |
| Private independent literal parser cases | page-inventory-parser-green.log | exit 0; 3 passed |
| Full locked suite | page-inventory-final-full.log | exit 0; 804 passed / 0 failed / 8 ignored, 92 result groups (native Windows) |
| Strict all-target/all-feature Clippy | page-inventory-final-clippy.log | exit 0; warnings denied |
| Fmt, slog, boundary, diff | page-inventory-final-{fmt,slog,boundary,diffcheck}.log | each exit 0 |

The public baseline accepted whole acknowledged non-WAL collection loss with a
surviving manifest. The reversible owned-fixture move restored the exact tree
and acknowledged read before the capability assertion failed; no allocator or
entity operation was attempted on the damaged root. Baseline also accepted a
missing known slot directory, its directory/alias substitutes and absent known
evidence with a false recoverability flag. For a real managed v2 WAL with a
proven seven-byte torn frame, missing slot evidence allowed repair from 23 to
16 bytes and optional-layout initialization. GREEN requires a typed refusal
with all entries and bytes unchanged except the exact permanent root lock.
Existing later directory/page refusal for other losses is now preceded by the
explicit known-role check. These are namespace-loss simulations, not a claimed
legacy v1 completeness guarantee, crash test or power-cut qualification.

The first versioned test compile had an owned `PathBuf` where an existing API
required `&Path`. It was corrected before behavioral RED and retained separately
in `page-inventory-presence-compile.log`; that attempt is not counted as RED.

Controls preserve ordinary mutation/read/reopen, absent manifest, empty inventory,
catalog-only roots and opaque unknown formats/versions. Independent literal
Unix, Windows, verbatim and UNC labels resolve to the current root; malformed
suffixes, traversal, extra/mixed separators, zero/overflow/noncanonical IDs and
annotation/role mismatch refuse. MAX u32 IDs remain valid. Slot-body bytes are
deliberately not parsed. A surviving old source cannot supply missing current
evidence. Nonfile leaves/ancestors, file/directory symlinks and an actual Windows
junction with attribute `0x400` refuse without changing root or peer bytes.

The versioned parent relocation control performs checked A-to-B-to-C moves with
old roots absent, supported writes and reopens. It observes three, six, then nine
raw manifest aliases. A bad first exact-current-path checksum still refuses
despite stale aliases; a bad later exact duplicate remains ignored, preserving
baseline first-match ordering. Foreign-label checksums are not reinterpreted.
This controls annotation relocation, not all typed blobs or cross-platform DB
portability. Runtime test fixtures use portable temporary directories. The
native Windows candidate adds 12 presence tests, one relocation test and three
private parser tests; Linux omits the Windows-only junction case. Counts from
one platform are not claimed for the other.

## Reproduction and review

```powershell
cargo test --locked --jobs 2 --target-dir F:/poiesis-targets/phase-04-page-inventory-presence --no-fail-fast --test page_inventory_presence --test page_inventory_relocation -- --nocapture
cargo test --locked --jobs 2 --target-dir F:/poiesis-targets/phase-04-page-inventory-presence --no-fail-fast --test page_inventory_presence --test page_inventory_relocation --test page_manifest_codec --test page_manifest_validation --test durability_page_manifest --test page_collection_state --test page_wal_owned_framing --test page_wal_admission -- --nocapture
cargo test --locked --jobs 2 --target-dir F:/poiesis-targets/phase-04-page-inventory-presence --lib record::inventory::tests -- --nocapture
cargo test --locked --jobs 2 --target-dir F:/poiesis-targets/phase-04-page-inventory-presence --no-fail-fast
cargo clippy --locked --jobs 2 --target-dir F:/poiesis-targets/phase-04-page-inventory-presence --all-targets --all-features -- -D warnings
cargo fmt --all --check
./scripts/verify_slog_storage.ps1
./scripts/verify_storage_boundary.ps1
git diff --check
```

Parent and phase01 independent source reviews are READY with no blocker. The
independent reviewer compared all five freeze hashes twice with no differences,
reviewed the helper/hook/tests/docs and confirmed the existing selected-file
validation and manifest save/upsert remained byte-identical to the baseline.
Production and tests remained frozen across focused, full
and strict checks, with all five hashes matching again after the gates. The
serial build/test process exited 0 and is closed; no worker build sessions remain.
Exact command exits are in
`D:/poiesis-benchmarks/page-inventory-final-exits.json`; changed-file inventory
and evidence-log hashes are in
`D:/poiesis-benchmarks/page-inventory-final-provenance.json`. The storage gates
were launched in separate PowerShell processes for explicit native exit codes.
Documentation completion does not change the source/test checkpoint.
Physical Windows file SHA-256 values before
Git newline filtering are in
`D:/poiesis-benchmarks/page-inventory-frozen-source.json`:

| File | SHA-256 |
| --- | --- |
| src/record/inventory.rs | 26c02da4d041ecce387e2785ae583ad6b9fa6c16011f8dfae4cfa248a3e55e26 |
| src/record/database.rs | 7d005cbce50ff9d2c6e8e75149ac74831966c86d28034daf34f2a4adeae87894 |
| src/record/mod.rs | 42cff1f833e959eddc0a9c4a4711f89e0e6f6e51900f230e97ce4dafbb09a9fc |
| tests/page_inventory_presence.rs | 52b9e79beefd59e5c29647b98ae791e4f09b840ba0f93c8bc6c025b355fc41ba |
| tests/page_inventory_relocation.rs | e17bc7dcfe6bedf6c53c19b1a2b4cd402af30818b8b8a5ec00e78e4b01c04e5e |

## Coverage limits

See [known inventory presence](../../docs/page-inventory-presence.md). This is
`Refs #41`; [#41](https://github.com/Astraive/praxor/issues/41) stays open. Both
flag values require presence only for the exact recognized v1 formats. Unknown
annotations do not become required-file authority. Missing manifests retain
legacy absence, so loss of the inventory itself is not detected here. Presence
does not prove inventory completeness/origin, all relocated checksums, slot
sidecar schema, blob/catalog/WAL completeness, acknowledged-state preservation,
or crash-atomic publication. No new format, witness, journal, generation,
normalization/upsert, replay or repair protocol is introduced. Broader #41
design options remain unapproved and are not represented as implemented.

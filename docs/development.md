# Praxor development

Use this guide with [GIT.md](../GIT.md) for issue/specification, identity and merge rules. It describes a reproducible local feedback path; release decisions still require the issue's exact native platform and compatibility evidence.

## Establish a clean baseline

Inspect `git status`, remote and current commit. Preserve unrelated work. Record the main/base revision and use a dedicated branch or clean worktree. The engine builds independently: no sibling repositories, absolute-path Cargo dependencies or unpublished source imports are required.

The repository currently uses Cargo package `praxis`, edition 2024, version `0.0.1`. [rust-toolchain.toml](../rust-toolchain.toml) pins Rust `1.99.0`, rustfmt and clippy. Install the native C/C++ build tools required by dependencies. Python 3 and PowerShell 7 are needed for current CI validation scripts. Docker supports the existing container path; it is not a substitute for native Windows evidence.

```sh
git status --short
git rev-parse HEAD
rustc --version
cargo --version
python --version
pwsh --version
```

Use `Cargo.lock` and `--locked`. Treat a dependency/toolchain update as a reviewed change with its own validation; do not regenerate the lockfile opportunistically while fixing another issue. Existing vendor/platform checks remain part of the native CI gate.

## Quick feedback and meaningful tests

```sh
cargo fmt --check
cargo check --locked --jobs 2 --benches --tests
cargo clippy --locked --jobs 2 --all-targets -- -D warnings
```

Choose tests for the changed contract rather than relying on one all-green command. Examples of existing integration targets:

```sh
cargo test --locked --jobs 2 --test query_compiler_public
cargo test --locked --jobs 2 --test query_gateway_public
cargo test --locked --jobs 2 --test core_record_snapshots
cargo test --locked --jobs 2 --test wal_record_framing
cargo test --locked --jobs 2 --test page_wal_owned_framing
cargo test --locked --jobs 2 --test backup_source_independence
cargo test --locked --jobs 2 --all
```

The target names above are present in the inspected source tree and auto-discovered by Cargo. Confirm exact names and test discovery after changing the manifest. A missing-symbol compile failure does not substitute for a behavioral regression that executes against the old implementation.

For parser/executor changes, assert exact logical IDs, values, multiplicities and errors from an independent oracle. For formats, check fixed literal bytes, every meaningful cut, bad counts/lengths, trailing data, unsupported versions and independently recomputed checksums. For concurrency, preserve the barrier schedule and a legal sequential-history oracle. For durable publication, exercise relevant append/sync/install/reopen boundaries and distinguish acknowledged operations from ambiguous outcomes.

Read [query readiness](query-readiness.md) before extending a query path. The Q1 compiler, Q2 fixture gateway and legacy parser/executor are different evidence surfaces. Additional legacy model fields do not establish supported retained execution. Read [source ownership](storage-source-ownership.md) before removing code: completed uncompiled-source cleanup does not authorize deleting one of the retained live protocols.

## Storage and logging checks

```sh
pwsh -NoProfile -File scripts/verify_slog_storage.ps1
pwsh -NoProfile -File scripts/verify_storage_boundary.ps1
python scripts/governance.py check
python scripts/governance.py self-test
```

The governance commands accompany this documentation/governance rollout. Keep their tests and hook instructions aligned with [GIT.md](../GIT.md). They supplement the existing storage/query checks.

Production storage paths emit structured `slog` wide events. Preserve existing operation/outcome/error and measured resource fields without logging sensitive payloads. Do not replace a durable error with empty results or add an unrelated logging framework to work around a gate. See [observability](observability.md).

## Native CI and feature checks

The checked-in [CI workflow](../.github/workflows/ci.yml) includes a native Linux storage gate and native Windows PR/manual gate, exact-source/evidence validation, feature checks and benchmark checks. The platform runner script records setup, source, toolchain, focused/full test discovery/results and storage gates. It is a CI harness with required environment and resource expectations; read it before running it outside CI.

`scripts/verify.ps1` also provides an existing PowerShell/container verification route. Its Docker behavior is explicit in the script; use its documented switches deliberately and inspect the whole command flow rather than assuming every switch skips every container operation.

The manifest defaults to `cpu`. Check the relevant GPU feature configurations when touching acceleration or shared feature code, including their combined configuration:

```sh
cargo check --locked --jobs 2 --benches --tests --features gpu-wgpu
cargo check --locked --jobs 2 --benches --tests --features gpu-cuda,gpu-vulkan,gpu-metal,gpu-wgpu
cargo check --locked --jobs 2 --benches
```

Compiled GPU scaffolding is not evidence of device execution, correctness, throughput or portability. A real backend needs CPU parity, device/environment disclosure and fallback tests. Scheduled ignored stress jobs are distinct from ordinary PR checks; a skipped stress job is recorded as skipped, never passed.

## Evidence and benchmarks

Keep issue-specific evidence bound to source: head/tree, command, environment, raw output, exit code, fixture identity and any exclusions. Update evidence after relevant changes. Cite existing reports with their historical revision rather than presenting old suite counts as new runs.

Use the [benchmarking guide](benchmarking.md) and [write amplification matrix](write-amplification-matrix.md). Report actual atomic batch sizes, sync policy, concurrency, manifest cardinality, allocator instrumentation and observed OS calls separately. Do not infer physical sync from an application counter, production scalability from short NVMe samples or a universal competitor win from a microbenchmark.

Tests for process exit, OS crash and power loss demonstrate different guarantees. Native Windows file persistence and directory behavior require explicit evidence. A valid checksum proves the declared byte-integrity property; it does not establish physical provenance, authorized ownership or durable ancestry.

## Complete a scoped change

Before opening or updating a PR, check the approved specification and concrete blockers, run relevant checks, review the diff and update affected documentation. Use real issue URLs and accurate `Refs`/`Closes` language. Use your own accurate author and committer identity; standard co-author trailers are allowed when they truthfully credit collaborators. Follow normal two-parent merge and exact-head verification rules in [GIT.md](../GIT.md).

Status advances only for the verified scope. Completing a decoder, fresh format, fixture gateway or local service adapter does not complete persisted SQL, legacy migration, durable history, public protocol adoption or the unified SuperDB demonstration.

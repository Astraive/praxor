# Contributing to Praxor

Praxor is the canonical Rust database engine in the Poiesis ecosystem. Start with the
[README](README.md), [architecture and authority map](docs/architecture.md), [development and
verification guide](docs/development.md), [current status and roadmap](docs/status-roadmap.md),
[specification index](docs/specs/README.md), [GitHub workflow](GIT.md) and concise [agent
instructions](AGENTS.md).

## Ownership boundaries

Praxor owns canonical query parsing, binding, logical representation, planning, execution,
semantic catalog behavior, storage, recovery, transactions and indexes. Poiesis owns product
APIs, sessions, authorization and protocol context. Pit owns version graph and ref/history
behavior. PoiesiSQL is optional tooling and must not introduce another semantic pipeline.

A type or route in the source does not prove supported behavior. Read the current readiness
documents and revision-bound reports before extending legacy or experimental paths. Keep
compatibility owners and physical storage authorities separate unless an approved specification
establishes a safe transition.

## Start from tracked work

Find the existing [engine epic](https://github.com/Astraive/praxor/issues/3) and the issue that
owns the exact change. Reuse existing scopes; do not open a duplicate for a closed finding
without a current reproducer. For cross-repository work, link the issue in its canonical owner
and name the contract or exact artifact required to unblock you.

Before implementation, link an approved specification or settle the bounded contract in the
issue. Define observable success and failure, compatibility, format/version impact, resource
bounds and an independent test oracle. Use GitHub's native parent/sub-issue and blocked-by
relationships, labels, milestone and [Project #2](https://github.com/orgs/Astraive/projects/2)
fields. A parent groups work; a child is an independently reviewable deliverable.

## Make a focused change

Work from a clean task branch or isolated worktree at a recorded base. Preserve unrelated and
unpublished files. Keep storage format, query semantics, product integration and documentation
governance changes separately reviewable when their acceptance or rollback differs. Avoid
sibling-checkout dependencies and machine-specific paths.

For durable storage changes, identify the owning protocol and exact visibility/acknowledgement
point. Exercise valid prefixes, malformed complete records, partial tails, reopen, retries and
publication failures as relevant. For concurrency changes, state the legal ordering oracle. For
query changes, verify result values, types, multiplicity, null handling, errors and context
using expected results independent of the implementation.

## Verification

Use the pinned Rust toolchain and committed Cargo.lock. Run checks for the changed behavior plus
the applicable full gate; do not treat formatting, compilation or a benchmark as a substitute
for correctness.

    cargo fmt --check
    cargo check --locked --jobs 2 --benches --tests
    cargo clippy --locked --jobs 2 --all-targets -- -D warnings
    cargo test --locked --jobs 2 --all
    python scripts/governance.py check

The exact focused integration targets and native platform gates are listed in
docs/development.md. Use a unique task CARGO_TARGET_DIR on D: or F: when needed; do not share an
active build target or delete another task's outputs. GPU feature compilation is not proof of
device execution or acceleration.

## Commit and review

Use your own accurate Git identity. Standard Co-authored-by trailers are welcome when they
truthfully credit collaborators. Keep each subject in type(scope): message form and within 120
characters.

Open a focused PR with the real issue, specification, compatibility/risk notes, exact commands
and observed outcomes, platform, tested revision and limitations. Attach it to its issue and
Project #2 when applicable. Obtain independent review and current-head required checks;
revalidate evidence after the candidate changes. Use a normal merge commit without squash or
rebase-merge. A direct push is appropriate only when a maintainer explicitly authorizes it and
repository protections allow it.

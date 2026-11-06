# Git and delivery workflow

This repository uses specification-led changes, native GitHub planning relationships and reviewable commits. The rules apply to human and agent contributions. They preserve the engine's durable formats and authority boundaries; they do not establish product completeness by process alone.

## Work from the right repository and revision

Confirm the remote is [Astraive/praxor](https://github.com/Astraive/praxor), inspect `git status`, and record the base commit before editing. Preserve unrelated or unpublished changes. Use a clean branch or isolated worktree when work needs separation. Do not reset, clean, force-push or import another checkout to manufacture a clean baseline.

Use a descriptive branch such as `codex/praxor-bounded-query-read` or `fix/praxor-value-extent`. Product code, format changes and documentation governance should remain separately reviewable. Never commit credentials, local machine paths as dependencies, raw confidential datasets or one-time bulk issue-publication scripts.

## Native issue hierarchy and dependencies

The [SuperDB master issue](https://github.com/Astraive/poiesis/issues/8) coordinates the six-repository destination. The [Praxor engine epic](https://github.com/Astraive/praxor/issues/3) retains existing engine completion work. Link new epics and leaf issues through GitHub's **parent/sub-issue** relationship, not only checklist prose. Parent progress summarizes deliverables; a parent is not an implementation prerequisite of its own child.

Use native **blocked-by** relationships for real prerequisites. A leaf depends on a concrete contract, implementation or verification result, not completion of its containing epic. Keep relationships acyclic. Explain the required artifact in the issue so a reviewer can tell when a blocker is satisfied. Cross-repository dependencies must link the existing issue in its owning repository; do not create an engine duplicate of a runtime, Pit, UI or tooling task.

Before opening an issue, inspect open and closed work. Reuse an existing scope when it already owns the problem. Closed findings stay fixed unless a new current-head reproducer demonstrates a regression. An old unchecked box in a closed issue body is not permission to recreate it. In particular, retain the scopes of [registered snapshots](https://github.com/Astraive/praxor/issues/29), [page publication](https://github.com/Astraive/praxor/issues/41), [consolidation](https://github.com/Astraive/praxor/issues/46), [persisted catalog](https://github.com/Astraive/praxor/issues/63), [physical owner proof](https://github.com/Astraive/praxor/issues/73), [origin preservation](https://github.com/Astraive/praxor/issues/94) and [active-tail classification](https://github.com/Astraive/praxor/issues/100).

Every implementable leaf needs:

1. A concrete problem, affected contract and evidence revision.
2. Scope and explicit exclusions, including repository ownership.
3. At least two independently falsifiable requirements and acceptance criteria.
4. Concrete positive, negative and boundary/fault inputs with independent expected outcomes.
5. Actual path hints distinguished from proposed new locations.
6. A reviewable S/M/L estimate, priority, phase and real prerequisites.

Split work larger than L into bounded deliverables. XL is for coordinating epics or features with bounded sub-issues. A bug needs a meaningful current reproduction before its proposed repair is treated as established fact; a design issue may define a new contract but must not claim implementation evidence.

## Labels and project fields

Use the existing repository label vocabulary. Avoid synonyms such as adding another spelling of storage or performance when an appropriate label already exists. Choose the most specific maintained label and reconcile any legacy overlap deliberately.

| Dimension | Convention |
| --- | --- |
| Type | One primary `type:bug`, `type:feature`, `type:task`, `type:test`, `type:docs`, `type:chore`, `type:spike` or `type:epic` |
| Priority | One `priority:P0` through `priority:P3`; mirror the Project Priority field |
| Size | One `size:S`, `size:M` or `size:L` for a leaf; `size:XL` for epics; mirror Project Size |
| Area | Existing `area:*`, such as `area:query`, `area:durability`, `area:transactions`, `area:indexes`, `area:graph` or `area:replication` |
| Platform | `platform:all` for genuinely shared work, or precise affected platforms such as `platform:windows` and `platform:linux` |
| Evidence need | `needs-spec`, `needs-repro` or `needs-verification` where the named gate remains unresolved |
| Severity | Existing `severity:S1` through `severity:S4` for measured impact where appropriate; severity is separate from scheduling priority |

P0 is a demonstrated correctness/security hazard or critical-path blocker of the assigned milestone; P1 is required phase delivery; P2 is planned follow-up or expansion; P3 is lower urgency, not necessarily outside the full destination. Record the reason and the exact blocked gate.

Add delivery issues to [Astraive Project 2](https://github.com/orgs/Astraive/projects/2). Its current fields are Status (`Todo`, `In Progress`, `Done`), Priority (`P0`–`P3`), Size (`S`–`XL`), Phase and Spec status. Phase options are Foundation, Correctness, Relational, Multimodel, Versioning, Operations, Distributed and Release. Spec status options are Draft, In review, Approved, Implemented and Superseded. **Todo does not mean approved for implementation.**

Use the matching repository milestone:

| Milestone | Delivery boundary |
| --- | --- |
| M0 · Foundation and ownership | Canonical owners, explicit contracts and safe admission |
| M1 · Single-node correctness | Durable effects, recovery and shared visibility |
| M2 · Relational and SQL | Typed relational semantics and constraints |
| M3 · Multimodel and hybrid retrieval | Documents, edges and combined retrieval |
| M4 · Integrated versioning | Engine/Pit history integration |
| M5 · Operations and clients | Supported operations and external adoption |
| M6 · Distributed and managed operation | Replication and distributed delivery |
| M7 · Release validation and comparison | Reproducible product and benchmark evidence |

These names and fields were read on 2026-11-06. Recheck live metadata rather than inventing a field option if the project changes.

## Specification to implementation

Move Spec status from Draft to In review when the contract, limits and test oracles are concrete. Obtain the appropriate design review before Approved. For changes to WAL, manifest, protected roles, catalog, provenance or owner admission, freeze the exact wire/effect matrix and failure states before implementation. Valid bytes alone never confer writer, repair or ancestry authority.

Implement the approved leaf in bounded commits. Keep tests independent enough to detect an incorrect implementation: literal wire goldens, a separate mathematical/full-scan oracle, explicit concurrent schedules and meaningful fault boundaries are preferable to regenerating expected values with the code under test. Preserve supported old-reader/refusal behavior and distinguish preappend rejection from unknown postappend outcomes.

Update the specification if implementation changes the contract. Do not mark it Implemented while requirements or current-head verification remain open. Mark superseded designs explicitly and link their replacement; retain historical evidence with its original revision and limitations.

## Commit identity and messages

Every new commit must have **both author and committer** exactly:

```text
NeerajCodz <neerajcodz@gmail.com>
```

Configure this repository locally and verify the resulting commit object:

```sh
git config --local user.name NeerajCodz
git config --local user.email neerajcodz@gmail.com
git var GIT_AUTHOR_IDENT
git var GIT_COMMITTER_IDENT
```

Do not add `Co-authored-by` trailers. Do not rewrite unrelated existing history to satisfy this rule. Resolve an identity mismatch before creating a new commit. Server-side merges are forbidden for this authorized work. Construct the normal merge locally and verify its exact author and committer.

Use substantive conventional subjects: `fix(wal): reject inconsistent frame lengths`, `feat(query): retain one fallible read view`, `test(records): cover final-pin reclamation`, `docs(status): distinguish decoders from writer readiness`. The subject describes behavior, not a vague activity such as “updates.” The body explains material rationale and evidence when useful.

## Checks and pull requests

Run the repository governance checks included with this workflow:

```sh
python scripts/governance.py check
python scripts/governance.py self-test
```

Install/use the supplied repository hooks according to their checked-in instructions. Hooks and governance validation complement the storage, query, format and native platform gates; they do not replace them. [Development](docs/development.md) describes relevant commands. Do not bypass a failing check merely to make a commit or merge possible.

A pull request must link the real issue, identify the problem and resulting behavior, summarize changes and exact validation, and disclose unsupported cases. Use `Closes` only when the issue's full scoped acceptance is complete. Use `Refs` for partial progress. Keep broader epics and dependent issues open.

Record the tested head, tree, toolchain, platform and command exit statuses. A later code change invalidates exact-head evidence for affected checks. A skipped job is not a passed job. Preserve raw evidence when release decisions rely on it. Do not promote process-exit tests to physical power-loss guarantees or feature compilation to hardware acceleration.

## Normal merges only

Merge reviewed, passing changes with a normal **two-parent merge commit**. Do not squash, rebase-merge, force-update main or bypass required checks. Verify that the merge parents are the intended base and reviewed feature head, the merge tree contains the approved changes, and author/committer identity matches the required values without coauthor trailers.

After merge, confirm the default branch contains the expected commit and inspect relevant current-head checks. Update native relationships, project Status/Spec status and issue acceptance based on what actually shipped. Preserve open parent/release gates when only one bounded slice completed.


## Identity-preserving integration procedure

This authorized project work uses a locally authored normal two-parent merge. Do not use the web merge button, `gh pr merge`, squash or rebase-merge: a hosting service can substitute its own committer. Use a clean isolated integration worktree and the reviewed PR head. Fetch main, verify the exact current head's checks and independent review, then create the merge with both Git identities set to NeerajCodz <neerajcodz@gmail.com> and a conventional subject such as `chore(merge): integrate verified documentation`.

Compare the merge tree with the reviewed intended result. Push the merge to main without force only if the fetched base is still current; a rejected non-fast-forward push requires a fresh integration and revalidation. Respect server protections; if the authorized identity-preserving route is rejected, report it rather than bypassing required checks. Read back the published tree, author, committer, PR merged state and resulting checks. Update native issue/Project state and delete the completed remote branch with `gh api --method DELETE repos/OWNER/REPO/git/refs/heads/BRANCH` only after confirming its PR is merged. Preserve unfinished branches and dirty worktrees.

The commit-msg hook requires Python 3.12+. In a standalone checkout use `git config core.hooksPath .githooks`; in a linked worktree with worktree configuration enabled use `git config --worktree core.hooksPath .githooks` to avoid changing another checkout. Run `python scripts/governance.py self-test` and `python scripts/governance.py check`; CI additionally checks only the new base-to-head commit range and PR issue/spec/evidence metadata. Keep the subject within 120 characters. Metadata forms request Project #2 automatically only when their submitter can write that project; maintainers verify actual membership and fields for every issue.

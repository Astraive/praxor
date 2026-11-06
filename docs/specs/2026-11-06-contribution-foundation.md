# praxor contribution foundation

Status: implements the user-authorized documentation/governance rollout; exact-head PR review is the merge gate.
Owner: Astraive/praxor
Issue: https://github.com/Astraive/praxor/issues/104
Baseline revision: 4a276cfaca0ee6291f965f8788e0d8ca905c7682

## Intent and scope

Provide truthful repository-specific README, maintainer GIT notes, concise AGENTS instructions, architecture/development/status docs and a reproducible contribution workflow. This repository's owning surfaces are storage, transactions, query compilation, catalog, retrieval and replication. Existing product implementation and build/evidence workflows remain separate acceptance boundaries.

## Requirements and design

1. README and docs distinguish committed behavior, local unpublished work and target architecture. AGENTS is a short entry point; detailed policy belongs in GIT/docs.
2. Task, bug, epic, specification and verification forms capture concrete scope, requirements, fixtures, acceptance, references, dependencies and tracking. Maintainers configure native parent/blocker links and actual metadata; prose IDs alone are insufficient.
3. Issue type/area/priority/size/platform labels, milestone and Project #2 values agree. Todo does not imply specification approval. Native org types are used where available; personal Pit uses type labels.
4. New commit subjects use type(scope): message, with at most 120 characters. This authorized work uses NeerajCodz <neerajcodz@gmail.com> as both author and committer and rejects co-author trailers. Historical base commits are excluded from new-commit validation.
5. A POSIX commit-msg hook supports Git Bash/Linux/macOS with Python 3.12+. CI checks the actual PR head with full history and reads PR JSON as inert data, using read-only permissions. Existing product CI remains intact.
6. PRs link an actual owning issue and an existing in-repo spec path or HTTPS spec URL; a not-applicable exemption needs a reason. Required evidence sections and canonical ticket title are checked.
7. Current-head checks and independent review precede a normal two-parent merge with exact project attribution. Close only the completed scope and clean up its branch.
8. One-time issue publication scripts, catalogs, credentials and run ledgers stay outside this repository.

## Verification and limits

The governance self-tests accept valid conventional/merge and CRLF messages and reject malformed subjects, coauthors, wrong author/committer, missing issue/spec metadata and broken checked Markdown targets. Local relative inline/reference Markdown links are checked; remote page availability, heading anchors, server-required check settings, Project permissions and semantic completeness still require review/readback. CI runs on Linux and Windows. Documentation checks do not prove engine/runtime/UI/WASM behavior.

## Acceptance

- [ ] Custom documentation accurately describes this repo and links to real owning work.
- [ ] Local checks and new-commit/PR cases pass; hook shebang/mode and cross-platform CI are verified.
- [ ] Independent review resolves factual and governance findings at the tested head.
- [ ] PR is normally merged, exact published attribution is verified and completed scope is reflected in GitHub tracking.

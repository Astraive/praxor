# Exclusive durable writer ownership

Issue #35 was reproduced through public APIs before the repair. Two core
engines opened at the same root acknowledged sequence 1 independently; a flush
from one retired the shared WAL and lost the other's acknowledged key. Two
record stores also allocated the same RID and payload offset. Separate tests
then reproduced backup deletion of an unrelated live descendant database.

Source commit `8783bab8b458577ffe3837e4af951291f8db7698` retains a nonblocking
OS file lease through core Arc clones/transactions, pointer storage and its
physical primary, and standalone record stores. The lock artifact is permanent
and never truncated or replaced. Independent owners fail with typed
`AlreadyOpen` before manifest/WAL initialization. Canonical aliases contend on
the same root. Failed opens and process termination release the handles.

Pointer primary ownership is transferred explicitly. A standalone root named
`primary` also retains its parent lease. Other nested roots are unsupported:
existing ancestors are checked before initialization and again after acquiring
the child's artifact, while copy operations retain their root before inspecting
descendants. Early refusal avoids leaving a nested lock during the usual denied
open; a racing refusal may leave conservative evidence, which is never unlinked.

Backup/restore reject unrelated descendant writer artifacts before deletion,
guard primary aliases, preserve permanent locks, and require disjoint roots.
Restore retains its source lease; backup uses its existing owner. These changes
do not establish online snapshot consistency, transactional replacement, blob
relocation, or power-loss durability. Old binaries and raw filesystem utilities
that ignore the cooperative protocol remain unsupported concurrent writers.
Page ownership is tracked separately in #36. See
[the ownership contract](../../docs/writer-ownership.md).

## Verification

- Initial ownership regressions: 9 intended failures, followed by focused GREEN.
- Additional nested-copy, nesting and early-refusal regressions were each
  confirmed RED before their corresponding repairs.
- Final focused suite: **20 passed, 0 failed**, including subprocess exclusion,
  kill/reopen, retained clone/transaction lifetime, failed-open cleanup,
  core/pointer and parent/primary exclusion, aliases, unchanged denied-open data,
  repeated backup/restore, and nested destination/source refusal.
- Full locked Windows suite on `5a3e2ef` plus the production patch:
  **506 passed, 0 failed, 8 ignored across 63 targets**.
- Fast-forwarded the unchanged production patch onto default `7b4e32f`, which
  adds only uncompiled-source cleanup and benchmark/report artifacts. The only
  test follow-up boxes a large helper enum variant. Focused 20/20, formatting,
  strict all-target/all-feature Clippy, logging and storage-boundary gates all
  passed again. The unchanged full suite was not repeated solely for those
  disjoint changes; current-head Linux CI remains the PR integration gate.
- Independent review: ready after the nested-copy blocker was repaired.

All Cargo commands used Rust 1.99.0, `--locked --jobs 2` and explicit target
`F:/poiesis-targets/phase-04-writer-ownership`. External logs:

```text
D:/poiesis-worktrees/writer-ownership-red.log
D:/poiesis-worktrees/writer-ownership-nested-red.log
D:/poiesis-worktrees/writer-ownership-containment-red.log
D:/poiesis-worktrees/writer-ownership-refusal-red.log
D:/poiesis-worktrees/writer-ownership-final-full.log
D:/poiesis-worktrees/writer-ownership-combined-{focused,clippy,fmt,slog,boundary}.log
```

This is process/drop/reopen and cooperative ownership evidence. It does not
simulate power failure or prove physical device flush behavior.

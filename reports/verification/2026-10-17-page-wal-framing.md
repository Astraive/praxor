# Page WAL framing and owned activation verification

Issue: [#39](https://github.com/Astraive/praxor/issues/39). Implementation base:
`4230104b436070ab8e283cf6d9ae5f5b643a3a36`, including the reviewed backup sentinel,
typed/catalog decoders, isolated ownership tests and shared catalog owner. Worktree:
`D:/poiesis-worktrees/phase-04-page-wal-framing`. Rust 1.99.0, locked dependencies,
two build jobs. Original dirty workspaces were preserved. No commits, push or
GitHub writes were performed by the implementation worker.

## Behavioral evidence

Actual historical REDs used executable APIs before the corresponding fixes:

| Evidence | Observed result |
| --- | --- |
| Existing public decode/encode/replay baseline, `page-wal-framing-red.log` | 7 intended behavioral failures, 2 legacy/already-fixed controls passed; exit101 |
| Checked private v1 bridge checkpoint | Writable v2 refusal test failed before its temporary guard; guard was removed only with reviewed v2 activation |
| V1 prefix after a v2 record | Partial-v1 transition incorrectly ambiguous before the classified transition fix |
| Present bytes of a partial v2 header CRC | Cut14 with a flipped present CRC byte incorrectly Torn before the prefix checksum fix |
| Typed semantic-prefix matrix, `page-wal-semantic-prefix-red.log` | 3 tests failed: complete impossible metadata, authenticated-total infeasibility, nonmonotonic complete sequence incorrectly Torn |
| Owned activation/open matrix, `page-wal-owned-framing-red.log` | 5 failures, 1 corruption/legacy-refusal control passed; exit101 |
| Retry publication fence, `page-wal-retry-fence-red.log` | All four create/upgrade × file/parent fresh-owner retry faults incorrectly returned usable clean-v2 writers; exit101 |
| Unix mode compatibility, `page-wal-unix-mode-red.log` | Public activation changed `0600` to `0644`; exit101 |

The first nine tests did not treat missing new APIs or compilation failures as
RED. Counts/narrowing/inner consumption, existing private-writer refusal,
sequence exhaustion, cross-owner checks and root poison from #36 remain controls.

Final focused coverage includes all true v2 frame/file-header cuts; malformed
semantic prefixes and checksum contradictions; exact strict versus forensic API
behavior; valid large/headerless v1 read compatibility; staged byte-identical
legacy activation; exact empty-v2 scaffold admission across page/service/SDK/
recovery/catalog facades; unchanged corrupt/ambiguous roots; every collection and
whole-prefix semantic check before repair; shared repaired-owner sequencing
across collections; stale-sibling non-adoption; and two reopens after repair.

Private per-operation faults cover header write/sync/parent barrier, repair
open/truncate/header/sync/rescan, stage create/write/sync/validation, replacement,
parent barrier, canonical reopen/validation, append seek/write/partial write and
sync. Page/WAL/catalog clones fail closed after uncertain IO. These test hooks
are absent from production state and are not public fault constructors.

## Platform and compatibility gates

Windows tests perform actual replacement with closed internal handles, deny
replacement through a handle without share-delete, and refuse a read-only target
without unlinking it. Test cleanup restores the exact original Permissions.
Linux has an actual retained-descriptor test: the old FD sees unchanged legacy
bytes while managed append targets the replacement inode at the canonical path.
Unix stage creation starts at `0600` and restores the original canonical Permissions
on the held stage file before any header/payload is written. Both `0600` and `0640`
public activation regressions pass. No owner/ACL preservation is claimed.
Every activation of a validated canonical file performs file and parent fences,
including clean v2 and Never policy, so a previous ambiguous publication cannot
silently bypass its failed barrier on a fresh-owner retry.

An external helper linked to this implementation produced a real managed v2 WAL.
The frozen baseline f9fed833 public-reader executable accepted a v1 control
(exit0) and refused this actual v2 output (exit1). A separate owner executable
linked to retained pre-#39 typed-decoder build artifacts likewise accepted the
v1 control and refused the actual v2 root before writer exposure (exit0/exit1).
Directory entries and every file's bytes were unchanged by these old programs.
Evidence: `D:/poiesis-benchmarks/page-wal-actual-old-binary-gate.log`; the baseline
reader executable SHA256 is
`1f26a9c95a61ca62021f01a8ca5aab58929b86ca5d33b7d6a9aa47b0fecf608d`.

The private activation mechanism also preserves a valid legacy frame above the
new 64-MiB write cap without re-encoding it. Existing page semantic/physical slot
limits remain independent; this does not newly admit oversized page records.

## Final verification

| Gate | Result | Log under `D:/poiesis-benchmarks/` |
| --- | --- | --- |
| Fixed-source Windows focused, including #51 | 293 passed, 0 failed, 1 ignored; exit0 | `page-wal-fixed-checkpoint-focused.log` |
| Final Windows full | 774 passed, 0 failed, 8 ignored; exit0 | `page-wal-windows-full.log` |
| Windows all-target/all-feature Clippy `-D warnings` | exit0, 11.15s | `page-wal-windows-clippy.log` |
| Final Linux focused | 291 passed, 0 failed, 1 ignored; exit0 | `page-wal-linux-focused.log` |
| Linux full | 773 passed, 0 failed, 8 ignored; exit0 | `page-wal-linux-full.log` |
| Linux all-target/all-feature Clippy `-D warnings` | exit0, 1m26s | `page-wal-linux-clippy.log` |
| Linux retry and Unix mode narrow GREEN | 1 pass each; exit0 | `page-wal-linux-refence-green.log`, `page-wal-unix-mode-green.log` |
| Formatting / storage boundary / logging / diff | Passed on frozen source | Direct command outputs |

Windows target: `F:/poiesis-targets/phase-04-page-wal-framing`. Linux target:
`/mnt/f/poiesis-targets/phase-04-page-wal-linux`, WSL Ubuntu with explicit
`cargo +1.99.0`. Full suites run with `--all --no-fail-fast`; strict Clippy runs
serially after each platform's full suite. Targets are separate, and no same-target
test/Clippy/compiler sessions overlap.

An initial Linux invocation completed its test suite but its inline shell wrapper
lost the captured exit variable. That runner failure is retained separately in
`page-wal-linux-focused-runner-error.log`; the authoritative focused run uses an
external LF/login-Bash script and records actual cargo exit0. An initial Windows
Clippy test-cleanup lint was corrected by restoring original Permissions; the
earlier Windows full746/0/8 and strict logs were moved to `*-pre-refence.log`
after independent review found the retry-fence and Unix-mode blockers. The first
Linux full was deliberately interrupted before source edits (exit130), retained
as `page-wal-linux-full-interrupted-pre-refence.log`. These are historical evidence,
not final gates for the corrected candidate on4230104.

Task1 received independent phase01 review and parent approval. Task2's initial
approval was withdrawn when independent review found both later blockers. Parent
and independent phase01 narrow re-review then approved the corrected frozen
source with actual RED/GREEN evidence and no remaining source findings. Renewed
full/platform/strict verification passed on that frozen source. All owned build
and test sessions completed before final handoff; the worker made no commits or
GitHub writes.

## Limits

Strict/public forensic reads never repair. Only the retained owner can repair a
proven v2 cut after every directory/high-water/semantic check; normal open never
replays intents. Unknown/corrupt/unsupported or ambiguous legacy tails remain
unchanged. Stale stages never become authority. GroupCommit still syncs each
operation rather than batching; Never omits per-append sync and supports explicit
sync. Format-integrity barriers always sync and can persist earlier bytes.

These are process-error/restart and OS-call observations, not physical power-cut
proof or universal filesystem guarantees. Portable parent-directory syncing is
unavailable on non-Unix. #41's missing acknowledgement/completeness witness and
multi-file page/catalog publication limits remain. Framing cannot distinguish
every external truncation of acknowledged data from an interrupted append.

Verified source/test commit: `9e8aee8cb1e77add691501f891c9e3dc56f565a9`. Parent independently parsed both complete suite logs: 88 result groups each, with recorded command exit 0.


# Linux ownership-test isolation for PR52

The exact PR52 head `49d9412180bdc76b4ffa0f55f91264fb1a13e15e` had one failing
Linux storage run 39041124703 while run 39041134374 passed. The failure was an
immediate post-drop `backup_to` reacquisition returning `AlreadyOpen` at the
former `tests/writer_ownership.rs:315`. It was investigated before changing code
or treating another CI run as resolution.

## Cause and negative evidence

The process-spawning test ran inside the same multithreaded libtest binary as
immediate drop/reopen assertions. Linux fork/clone temporarily inherits all parent
file descriptors. A child in the interval before exec can therefore retain an
unrelated test's flock after that test has dropped its owner. Close-on-exec applies
at exec, not fork. This is the documented inherited-descriptor lifetime in
[Rust File locking](https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock)
and [Linux flock](https://man7.org/linux/man-pages/man2/flock.2.html); it does not
establish a parent Arc leak or missing close-on-exec flag.

Actual probes on WSL Ubuntu with Rust 1.99.0:

- The unchanged parallel 20-test binary failed on its first local invocation:
 19 passed/1 failed, another immediate post-drop `AlreadyOpen` in `all_live_root...`.
 Log: `D:/poiesis-worktrees/backup-52-linux-parallel-1.log`.
- The original CI-failing test alone passed 40/40 fresh invocations.
- A deterministic std-only Rust Command/pre_exec probe outside the checkout
 verified `FD_CLOEXEC=1`, parent file drop followed by `WouldBlock` while the child
 remained pre-exec, and successful immediate reacquisition after child exec.
 Log: `backup-52-fork-probe.log`; probe source remains outside the product tree.
- A 200 ms exec-entry delay applied with strace to the unchanged parallel suite
 produced 17 passed/3 failed, all post-drop reacquisitions. In
 `backup-52-linux-exec-delay.strace`, line 4166 clones child 751, line 4177 closes
 the parent's fd 12 for `/tmp/.tmpi5Vp9d/.praxor.writer.lock`, line 4181 gets EAGAIN
 from a fresh flock, and line 4298 completes that child's delayed exec. The parent
 close happened; a still-inherited open description explains the retained lock.
 Original log/trace are preserved under `D:/poiesis-worktrees/`.

## Bounded correction

Move the two process tests into `tests/writer_ownership_process.rs`. Keep 18
ordinary ownership tests parallel in `tests/writer_ownership.rs`. Both binaries
use `tests/support/writer_ownership.rs` for the unchanged fixture/assertion code.
An independent reconstruction check confirms all 20 test bodies and the process
guard are preserved verbatim; common helper changes are module visibility only.

The process test retains all three owner kinds, child readiness, negative live
ownership assertions, unchanged-data checks, kill, wait and immediate recovery.
The ordinary tests retain immediate reacquisition assertions without retries.
No production lease, unlock, error-handling or persistence behavior changed.

The integrated baseline was merged from verified default `f9fed83303cf41315393acc23afd6dc06c811cb1`.
Only the unpublished merge subject was amended to the required conventional form:
`86c98d98b8f9abb5a77cf955de277a7b19180559`, same parents 49d941+f9fed833 and
same tree `b64ccc88db49b75909e0b6924278b8a4a27129b4`. Published ancestry was not rewritten.

## Verification

- Linux focused suite: 18+2 passed/0 failed, `backup-52-linux-isolation-green.log`.
- 80 complete parallel invocations of the 18-test ordinary binary and 80 of the
 two-test process binary passed: 160 invocations/1600 parent harness test cases.
- Both separated binaries pass with the same 200 ms exec-entry delay. Logs:
 `backup-52-linux-ordinary-exec-delay-green.log` and
 `backup-52-linux-process-exec-delay-green.log`.
- Windows integrated full suite: 676 passed, 0 failed, 8 ignored across 80 reported
 targets; `backup-52-windows-combined-full.log`, exit 0.
- Linux integrated full suite: 676 passed, 0 failed, 8 ignored across 80 reported
 targets; `backup-52-linux-combined-full.log`, exit 0. Initial complete build on
 the requested target volume took 6m35s.
- Strict all-target/all-feature Clippy: Windows exit 0 (12.49s), Linux exit 0
 (1m19s); `backup-52-windows-strict-clippy.log` and
 `backup-52-linux-strict-clippy.log`.
- The full runs exposed one unused import left after helper extraction. Only
 that import was removed afterward; no test body or production behavior changed.
 Both final strict runs compile the cleaned source. The final Linux focused
 rerun passed 18+2 tests after cleanup, exit 0:
 `backup-52-linux-final-focused.log`.
- Final format, whitespace, storage logging and storage-boundary gates: exit 0.

The root independently reviewed the test-only delta READY; the original #42
production review remains unchanged. Worker changes remain uncommitted for parent
commit/push and renewed exact-head CI. Existing stash backups were preserved.

Cargo verification uses `--locked --jobs 2` and distinct explicit targets:
Windows `F:/poiesis-targets/phase-04-backup-portability`; Linux
`/mnt/f/poiesis-targets/phase-04-backup-linux`. Diagnostic tools/probes are outside
the checkout. This repairs test isolation; it does not claim a product lock leak
was fixed or weaken the cooperative writer-ownership contract.

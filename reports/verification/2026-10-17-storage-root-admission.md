# Storage root admission

The public constructors previously initialized incompatible existing layouts.
Six initial public-API regressions reproduced this; a modern pointer `.swal`
database could reopen as an apparently empty core engine. This slice of #40
adds pure physical-format inspection and guards core, pointer and standalone
record constructors after retained ownership and before mutable initialization.
It does not migrate data or activate a new identity format.

Inspection composes the pointer primary, recognizes supported legacy controls
and recovery scaffolds, and reports typed mismatch, ambiguity, incomplete and
unsupported errors. Proven matching owners preserve opaque application/plugin
siblings without inspecting or adopting them. Reserved roles and foreign
anchors still fail closed. Diagnostic budgets remain explicit; standard opens
scale with actual control bytes and directory entries, preserving valid large
tables and roots beyond the diagnostic convenience limits.

The parent/primary callback executes before a missing child is created. Exact
empty or independently complete standalone primary roots remain usable, while
new pointer owners cannot adopt populated orphan data. Copy overlap preflight
resolves existing components before parent traversal and rejects non-directory
components before creating or clearing anything.

## Verification

Tested on default `6840d4a6b679689fb3107077d167307970dd067a` plus this patch,
using Rust1.99.0 and Cargo `--locked --jobs 2` with explicit target
`F:/poiesis-targets/phase-04-root-format-guards`.

- Final focused suite: **131 passed, 0 failed**: 35 detector checks, 17 public
  open/cardinality/path checks, 20 retained ownership checks and 59 unchanged
  pointer/custom-index tests.
- Final complete locked suite: **560 passed, 0 failed, 8 ignored**, across
  66 result groups including doctests.
- Strict all-target/all-feature Clippy, formatting, storage logging/boundary
  gates and diff whitespace checks passed.
- Independent whole-slice review found no remaining blockers. The parent also
  reviewed the final narrow precreated-empty-primary compatibility fix.

Additional actual RED cases preceded fixes for standalone-primary reopen,
100,000-record control metadata above8MiB, more than4,096 actual segments,
page-base orphan physical files, reserved namespace aliases, destructive
`FILE/../target` resolution, nested primary foreign anchors and precreated
empty standalone primary initialization. Refusal tests snapshot directory
entries as well as bytes, exempting only exact supported permanent lock files.
The existing raw custom-plugin composition layout remains unchanged.

External evidence is retained under `D:/poiesis-worktrees/`:

```text
root-format-open-red.log
root-format-{standalone-primary,actual-cardinality,page-orphan}-red.log
root-format-{copy-file-parent,page-namespace-alias,primary-component}-red.log
root-format-precreated-primary-red.log
root-format-stable-{focused,full,clippy}.log
```

An earlier full attempt hit Windows executable sharing error32 because a worker
overlapped tests using its own target. It is partial evidence only. The final
focused, full and strict runs above executed sequentially and completed
successfully; no passing total is inferred from that interrupted attempt.

## Remaining boundary

The pure page-base helper is included, but PageDatabase's writable hook and
cross-format page matrix belong to the pending #36 integration. **#40 stays
open** after this slice. Inspection is not payload fsck, a snapshot, backup
relocation or migration. #42 tracks source-independent coherent backup; the
existing path semantics are unchanged here. Reserved future identity markers
remain refused, and old binaries/raw filesystem writers can ignore the
cooperative protocol. No power-interruption guarantee is inferred from these
process and filesystem tests.

See [storage root formats](../../docs/storage-root-formats.md) and
[writer ownership](../../docs/writer-ownership.md).

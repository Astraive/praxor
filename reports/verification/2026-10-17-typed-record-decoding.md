# Checked typed metadata and selected blob reads (#49)

Base: merged default `fb49a216f06ddacca3283fe9ba164a33e54be20f`.
Source/regressions: `b6c2c7de8dd1a38024e682f58401e24f8269a9c6`.
Branch: `codex/phase-04-typed-page-decoder`.

The typed v1 decoder now checks exact envelope/payload consumption, proves cell
counts from actual remaining input before fallible reservation, rejects field-ID
narrowing and validates every class/pointer/role shape before field selection or
external lookup. Recognized type tags, zero/repeated IDs and valid writer bytes
retain their previous meaning. Blob reads use existing-file views, reject unsafe
leaf shapes, validate checked file/record bounds before reservation, and seek to
the selected payload rather than loading the entire file.

## Actual regressions

`D:/poiesis-benchmarks/typed-page-decode-red.log`, linked to the already verified
#50 library, exited101: one valid control passed, seven intended failures.
A CRC-valid17-byte body declaring65536 cells requested4194304bytes; a13-byte blob
declaring65536bytes requested65536bytes. Both field kinds accepted `0x10001` as ID1;
both outer and payload trailing bytes were ignored; a malformed later cell's
storage/pointer mismatch was ignored when selecting an earlier field.

The first fixture tried reading the live Windows lease while snapshotting files;
that helper error was corrected before the retained behavioral RED run. The
bounded65536 fixtures never passed an unguarded multi-GiB count to old code.

`typed-blob-whole-file-red.log` independently exited101: an existing five-byte
payload in a modest8MiB sparse file requested8388608bytes in the old reader. The
new reader reserves only the proven selected payload. Allocation observations
measure requested Rust buffer sizes, not RSS, native allocations or physical
allocated blocks. Logical file bounds can include sparse storage.

## Final verification

Windows Rust1.99, locked dependencies, jobs2, explicit target
`F:/poiesis-targets/phase-04-typed-page-decoder`; logs in
`D:/poiesis-benchmarks/`:

- `typed-page-decode-final-full.log`: **649passed,0failed,8ignored**,76resultgroups
  including doctests, exit0 on final source/test behavior.
- `typed-page-decode-final-clippy.log`: strict all-target/all-feature Clippy,
  exit0,34.88seconds.
- Formatting, storage logging/boundary gates and `git diff --check`: exit0.

The new Windows target has15tests; Unix additionally exercises a symlink leaf.
Coverage includes all40 recognized TypeCode tags,23 writer cases covering all22
PraxisValue variants and all storage families, full-u16 IDs of both kinds,
zero/repeated IDs, malformed tags/pointers/lengths, missing/directory blob leaves,
read-only failure/owner health and two opens of acknowledged valid typed data.
The final full run followed the portable temporary-directory and Windows reparse
guard corrections; an earlier647-test run predates those final fixtures.

Independent review found and resolved a test portability issue and requested an
explicit Windows reparse-point refusal matching the existing nonalias contract.
Its final source verdict is READY, with no remaining concrete blocker. The
reviewer performed no builds. PR current-head Linux checks remain a merge gate;
Windows results do not claim Unix execution.

## Limits

No wire format/checksum changes, new schema policy, filesystem repair, record
recovery completeness, historical blob generation or multi-file crash protocol
is added. Missing/malformed read evidence does not poison the shared owner.
Cooperative ownership does not sandbox external raw mutation or path replacement
races. Catalog decoder hardening is tracked separately in#51; page WAL framing
and crash publication remain#39/#41.

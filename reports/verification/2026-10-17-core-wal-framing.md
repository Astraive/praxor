# Core WAL header integrity and bounded decoding

Issue: [#28](https://github.com/Astraive/praxor/issues/28). Final integration base:
`a3a2137599280569501edc9d78daea111ae6b5f6`.

A length-field bit flip in the final complete core WAL record could make it
look like an interrupted append. Recovery silently discarded an acknowledged
write and truncated the file. An external two-write reproduction reduced a
130-byte log to 70 bytes and recovered sequence 1 instead of acknowledged
sequence 2. Initial focused regression testing produced eight failures before
production changes, including that loss and malformed decoding/allocation cases.

## Change

New records have a distinct v2 magic and a 16-byte header: magic, payload length,
payload checksum, then checksum of the preceding 12 bytes. Recovery authenticates
the complete header before trusting its length or classifying EOF as a torn
append. Direct decode and sequential replay share one framing/parser authority.
The existing 16-byte file container header remains unchanged; v1/v2 records can
coexist in containers or headerless streams.

For legacy v1 oversized outer lengths, a borrowed self-delimiting body probe
detects an intact payload whose original checksum matches despite the wrong
outer length. It rejects proven corruption without modifying the file. Genuine
incomplete legacy bodies retain torn-tail recovery. Simultaneous legacy body and
length corruption cannot be retroactively authenticated; the docs state that
limit.

Checked, allocation-free size calculation validates u32 fields/counts, arithmetic
and a 64 MiB new-record payload cap before admission, sequence assignment,
pressure maintenance, rotation or WAL IO. Writers use fallible encoding. Existing
infallible encoder/sizing signatures document panic behavior for invalid new
inputs. The cap applies only to new records; legacy reads retain their u32 wire
range. Strict decoding checks remaining input before field allocation, rejects
invalid UTF-8/tags/counts and requires exact frame/payload consumption.

## Evidence

Sixteen framing integrations cover acknowledged final-header corruption,
intact legacy length corruption in final/middle frames, malformed allocation
guards, strict decoding, checked v2 sizing, limits, mixed/headerless records,
every torn cut before repair/append/second reopen, and every v2 header-byte
corruption. A unit probe checks size/u32/overflow boundaries without allocating
multi-gigabyte fixtures. Existing sizing and torn-tail regressions also pass.

The first frozen patch on `c093465` passed **455 tests, 0 failed, 8 ignored**.
After CF-generation PR #30 merged, integration preserved generation/policy
capture and generation-bearing admission while moving checked sizing before
pressure IO. The two new CF admission-test sizing helpers use the checked API.
Independent review accepted both the original patch and this narrow integration.

Final Windows Rust 1.99.0 verification, locked dependencies, two Cargo jobs,
explicit `D:/poiesis-targets/phase-03-wal-framing` target:

- Full integrated suite: **468 passed, 0 failed, 8 ignored**, 59 test targets.
- Format, diff, storage slog and storage boundary checks: passed.
- Strict all-target/all-feature warnings-denied Clippy: passed.
- Independent review: ready, no blockers.

Logs: `D:/poiesis-worktrees/wal-framing-{red,focused-green,limits,full,clippy,integrated-full,integrated-clippy}.log`.
These tests exercise file truncation/corruption and deterministic recovery; they
do not simulate physical power loss. A matching partial terminal header remains
repairable under the documented existing policy.

## Compatibility

Existing valid v1 data remains readable; old encoders did not emit invalid UTF-8
or trailing bytes now rejected by strict parsing. V2 output requires an upgraded
reader. Downgrade is unsupported because old permissive readers may silently
stop at new record magic. The checksum helper remains unchanged; this patch does
not rename or change its underlying checksum algorithm. StorageEngine grouped
WALs and PageWal are distinct live protocols and remain separate work.

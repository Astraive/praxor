# Page WAL framing and owned activation (#39)

The classified codec is shared by strict replay, explicit forensic inspection,
owned-open preflight and the private writer. New managed files and records use
v2. Writable activation upgrades clean v1/headerless logs under the existing
PageDatabase lease and mutex. No new public independent writer exists.

`PageWalRecord::try_encode` emits v2; `checked_encoded_len` checks the complete
size before output allocation. `encode` remains a convenience wrapper and panics
on invalid input. New payloads are limited to 64 MiB. The fallible managed path
checks borrowed field totals before copying them for its WAL request. Valid
historical v1 data, including larger records, remains readable.

The v2 record header is 17 bytes: record magic `0x54505732`, version byte 2,
payload length u32, payload IEEE CRC32 u32, and header IEEE CRC32 u32. Integers
are little-endian; the header checksum covers the first 13 bytes. It is checked
before trusting the length, enforcing the cap, or calling a body incomplete.
The payload retains v1's ordered binary fields and identity layout.

The v2 file header is 16 bytes: existing file magic `0x54505746`, version u32 2,
required flags u32 0, and IEEE CRC32 of the first 12 bytes. Legacy file version 1
requires its eight reserved bytes to be zero. Headerless streams are recognized
legacy v1 only. A v2 file may hold complete v1 prefix frames followed by v2;
returning to v1 after a v2 frame is corruption.

`PageWal::replay` now requires the complete log to be clean and never repairs it.
The missing-path empty-vector convenience is retained. `replay_prefix` explicitly
returns records, validated and physical lengths, file format and a typed stop:
clean, proven v2 torn, legacy ambiguous tail, corruption, or unsupported format.
Missing and existing-empty files are distinguished. Prefix success proves neither
complete committed history nor permission to recover or append.

A complete bad checksum/header/tag/identity is never a repairable tail. Present
bytes of a partial header checksum must agree with its computable prefix. After
authenticating a v2 header, a borrowed semantic probe rejects already-complete
invalid identities, tags, field IDs or sequences, and claims that cannot fit the
declared total. Field extents leave room for every remaining minimum field header;
a complete semantic body before the declared end is also corruption. Incomplete
integers and opaque binary values remain eligible for a valid completion. An
intact self-delimiting legacy body with its original CRC proves a disagreeing outer
length corrupt. Remaining incomplete legacy records are ambiguous and cannot be
automatically truncated. A recognized v2 incomplete frame can be reported as torn.
Partial file headers remain ambiguous
until their available bytes establish the v2 identity. Arbitrary short garbage
is corruption. The scanner never searches forward for another magic.

Every complete payload uses the same borrowed probe before semantic allocation.
Complete counts are bounded by actual remaining bytes, IDs narrow with checks,
and both payload and exact-decoder outer consumption must be exact. Whole-log
sequences are nonzero and strictly increasing; gaps remain valid. Field order,
duplicate-field behavior and arbitrary binary field bytes are retained.

Replay currently reads the actual whole file and returns collected records, so
memory scales with real input and returned payloads. Bounds and fallible reserves
prevent allocation based solely on claimed counts/lengths; they are not a promise
that arbitrarily large valid files fit memory. Read-only classification leaves
bytes unchanged and does not poison a PageDatabase owner.

Ordinary owner open never auto-replays intents. Under the retained exclusive
lease it first classifies read-only, loads and validates every collection's
directory/high-water and pages, and validates the complete canonical prefix's
semantics. Only then can a proven v2 EOF cut be repaired. Frame repair truncates
to the validated prefix; a known partial v2 file header is completed. Both sync
and rescan cleanly before layout creation or owner exposure. Failed preflight
leaves all durable entries and bytes unchanged. Repair failures return no owner;
the next open validates only the canonical pathname. Structured `page_wal_repair`
diagnostics retain the original stop, lengths and validated record count.

An independently authoritative page root is required to reach torn-header
repair. On a complete empty scaffold, only exact full 16-byte v1 or checksum-valid
flags-zero v2 headers are permitted. Partial/zero-byte headers, extra bytes,
record-bearing logs, unknown names and logs-only roots do not establish authority.
Page, service, SDK, recovery and catalog facades share this admission boundary.

Read-only open preserves a clean historical log. Requesting its writable WAL
stages a create-new sibling with a v2 header and byte-identical complete legacy
frames, validates/syncs it, closes internal handles, and uses one same-filesystem
`std::fs::rename` replacement. It syncs the parent where supported, reopens the
canonical path and validates it before append. There is no remove-first fallback,
temp adoption or append through an old inode. A failed replacement/parent sync/
reopen poisons every existing page, WAL and catalog view. Pre-install failures
preserve canonical bytes and can clean only that attempt's exact regular sibling;
uncertain installation preserves diagnostics. Stale siblings are never authority
or overwritten. An empty scaffold with a stale sibling can require offline action.
Every writable activation synchronizes the validated canonical file and its parent,
even when it already contains clean v2 bytes: those bytes cannot prove that an
earlier creation/replacement fence succeeded. Unix staging starts with mode `0600`
and applies the original canonical permissions before writing content. This
preserves ordinary Unix permission bits without claiming owner or ACL preservation.

The activation mechanism preserves legacy frames above the new encoding cap;
the owner's existing physical page-size and semantic constraints remain independent.
EveryBatch and GroupCommit synchronize each append; GroupCommit does not batch
here. Never omits per-append sync; explicit `sync` requests a barrier. File-header,
repair, upgrade and writable-activation barriers always synchronize for format
integrity and can persist earlier bytes.

Windows replacement/sharing/readonly and private lifecycle fault tests exercise
process-visible outcomes. Linux retained-descriptor replacement has a separate
platform test. Passing OS calls/process restart tests are not physical power-cut
proof or a guarantee for every remote/share filesystem. Non-Unix parent syncing
remains unavailable in the existing portable helper. #41's missing completeness
witness and multi-file publication boundary remain unchanged. External truncation
of an acknowledged record can resemble an interrupted append: the framing has no
independent acknowledgement ledger and relies on the supported append-only writer.

# Core KV WAL framing

The canonical core KV WAL is `src/wal`; its record parser is shared by direct
decoding and file replay. The container header remains the existing 16-byte
magic/version/segment-ID header. Record versions can coexist in a container or
in a headerless stream. Opening a file does not rewrite acknowledged legacy
records or replace its container header.

New records use little-endian v2 framing:

| Offset | Field |
| --- | --- |
| 0 | v2 record magic `0x54574132` (u32) |
| 4 | payload byte length (u32) |
| 8 | payload checksum (u32) |
| 12 | checksum of the preceding 12 header bytes (u32) |
| 16 | existing sequence/count/operation payload |

Both checksums use IEEE CRC32, exposed as `io::crc32_ieee` and the historical
`io::crc32c` alias, backed by `crc32fast`. See the
[persisted checksum contract](checksum-contract.md). This naming correction
does not alter existing checksum bytes. A complete
v2 header must pass its checksum before a declared payload extending beyond EOF
can be classified as an interrupted append. A bad complete header, bad payload
checksum, unsupported magic, invalid UTF-8 family name, unknown operation tag,
impossible count, or trailing payload bytes is corruption. Direct record decoding
also rejects bytes after its frame; sequential replay accepts subsequent frames.

New payloads are limited to 64 MiB, excluding the 16-byte record header. Every
field and operation count must fit its u32 wire field, and size arithmetic is
checked without encoding or allocating the payload. The segment size remains a
rotation target: one valid record can exceed that target, but not the payload
limit. Admission validates the normalized batch before sequence assignment,
pressure maintenance, rotation or WAL IO. `try_encoded_len` and `try_encode`
return invalid-input errors. Existing `encoded_len` and `encode` signatures
remain available and panic for those invalid inputs; storage writers use the
fallible methods. `WAL_RECORD_HEADER_LEN` describes the current 16-byte encoder.

V1 retains its 12-byte `[magic, length, payload checksum]` header and existing
u32 wire-length read range; the new 64 MiB cap does not reject previously valid
larger legacy records. Reads check field lengths against actual remaining input
before allocating. Canonical legacy records require valid tags/UTF-8, the stated
operation count and exact payload consumption, as emitted by the old encoder.

A legacy outer length has no independent checksum. Before treating an oversized
legacy length as a torn tail, recovery probes its self-delimiting body without
allocating fields. A complete body with its original matching checksum proves
that the outer length is corrupt, including when later records follow it. Replay
and open fail without truncating that file. This does not retroactively
authenticate incomplete legacy headers or simultaneous length/body corruption;
genuinely incomplete legacy bodies retain the previous torn-tail policy.

The established short terminal-header policy also remains: after a valid prefix,
fewer than 12 suffix bytes can be discarded, including malformed short suffixes.
A recognized v2 magic with only 12 through 15 available header bytes is also an
incomplete append. Matching partial container headers (0 through 15 bytes) can be
completed; invalid prefixes, versions and segment IDs are rejected. A repaired
tail is truncated and synced before append, allowing subsequent records to
survive another reopen.

Compatibility is old-data read compatibility, not downgrade compatibility.
New v2 records require an upgraded reader. Older strict readers reject the new
record magic; older permissive readers may stop silently. Do not open a WAL
containing v2 records with an older executable. Store-engine grouped WALs and
page WALs are separate protocols and are not changed by this format.

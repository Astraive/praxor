# PVD1 directory v1: standalone decode contract

Issue [#95](https://github.com/Astraive/praxor/issues/95) freezes this small,
read-only subset of the proposed [#94](https://github.com/Astraive/praxor/issues/94)
format-5 provenance design. The r3 design and independent review permit a
synthetic PVD1 decoder, while live format-5 open, writer, owner, backup and
ancestry admission remain held. This wire format has no effect on the current
v3/v4 MANIFEST or database paths.

The later #94 r4 design (SHA-256
`845D560C13E1476FECE637590C306F061615FD3B23B239F29C37EFDF7BC266D4`)
revises mutable/immutable WAL and `MANIFEST.tmp` states while retaining r3's
PVD1 directory contract. It does not change the PVD1 fields or this decoder
boundary.

## Canonical bytes

All integer fields are unsigned little-endian. There is no padding, optional
field, extension field or text encoding.

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII magic `PVD1` (`50 56 44 31`) |
| 4 | 2 | version `1` |
| 6 | 2 | flags `0`; any other bit is unknown and refused |
| 8 | 8 | entry count `N` |
| 16 | 8 | payload length, exactly `45 * N` |
| 24 | `45 * N` | sorted entries |
| `24 + 45 * N` | 4 | CRC32C/Castagnoli of every preceding byte, little-endian |

Each 45-byte entry is `(node_id[32], pack_id:u64, record_index:u32, kind:u8)`.
The `node_id` bytes are an opaque content-derived logical ID; they must be
nonzero and **strictly increasing** in bytewise lexicographic order. Duplicate
or descending IDs are refused. `pack_id` is nonzero. `record_index` is
one-based, nonzero and at most 131,072, the total PVP1 record cap. `kind` is
`1` BirthV1, `2` EdgeV1 or `3` InstallDeltaV1; all other tags are refused.
An empty directory is permitted only as an untrusted synthetic/genesis value;
later MANIFEST and pack checks decide whether it is valid in an installed
database. No pack path appears in PVD1. A later MANIFEST decoder must validate
canonical relative paths, nonalias identity and referenced pack IDs.

`N <= 131,072`, and the entire file, including its 24-byte header and 4-byte
CRC trailer, must be at most 8 MiB (8,388,608 bytes). The largest legal entry
payload is 5,898,240 bytes and the largest legal complete PVD1 is 5,898,268
bytes. The narrower private P0 profile may separately require `N <= 8,192`
and file length `<= 512 KiB`; those are **not** global parser limits. Decode
checks `N * 45` and total length with checked arithmetic before narrowing to
`usize`, applying caps, indexing or allocating. It then requires the header's
payload length and supplied byte length to match exactly. A short header,
entry or trailer is truncation; any extra byte is trailing data. CRC32C is
checked before accepting semantic entries. Validation order is magic/version/
flags, checked arithmetic and caps, exact lengths, CRC, then entry fields and
strict order. This order makes hostile tiny headers refuse without allocating
the advertised size.

The CRC is **true Castagnoli CRC32C** (reflected polynomial `0x82f63b78`,
initial/final XOR `0xffffffff`, check value `e3069283` for `123456789`).
`crate::io::crc32c` is a historical misnomer for IEEE CRC32 with check value
`cbf43926`; it must not be used for this format. CRC32C diagnoses torn or
accidentally damaged bytes. It does not authenticate a directory or protect
against deliberate replacement. The Castagnoli polynomial is specified in
[RFC 3720](https://www.rfc-editor.org/rfc/rfc3720.html); this directory's
little-endian trailer is a local format choice, not an iSCSI wire convention.

## Authority boundary

The result is named `UntrustedPvd1` and grants no provenance, ownership or
ancestry authority. Future verified open must compare BLAKE3 over the **entire
PVD1 file** to the current trusted MANIFEST's directory ref, authenticate each
MANIFEST-listed PVP1 pack by its full digest, and prove a complete one-to-one
directory/pack-record bijection, body-ID hashes, kinds and referenced logical
IDs. A standalone PVD1 decoder cannot verify any of those conditions and
must not be called from `ManifestStore::save_with_policy`, current open,
recovery, WAL append/rotation, flush, compaction, cleanup, backup or
`CatalogOwnerProof` in this slice. It does not resolve a pack path.

There is deliberately no production encoder in the first read-only slice:
PVD1 writing would precede the unresolved live format-5 transition design.
The strict decoder will retain and expose the canonical input bytes unchanged,
so a caller can compare their exact wire image. The synthetic fixture builder
is deterministic and independent of production parsing. A later writer slice
must add an encoder with byte-for-byte roundtrip tests before it can install
a directory. Neither retention nor CRC substitutes for MANIFEST-bound BLAKE3.

## Decoder verification boundary

The test-first patch established a compiling decoder seam with deliberate
`Unsupported` results after fixed-header checks. The strict standalone parser
now checks CRC32C before entry semantics and returns a crate-private
`UntrustedPvd1` with the exact input image and decoded entries. Synthetic
fixtures require a valid sorted directory and empty genesis candidate to
decode, including one fixed, independent 73-byte golden vector. They also
require specific refusals for wrong magic/version/flags, truncated/trailing
input, count multiplication overflow, count and length caps, payload-length
mismatch, zero/duplicate/descending node IDs, zero pack/record indices,
record index over cap, unknown kind and damaged CRC. Malformed semantic
fixtures recompute CRC to isolate the error. An allocation observer requires
zero allocations for tiny hostile count/length headers before the parser
returns their bounds errors. These tests establish only a bounded syntactic
codec; no live v5 database or ancestry authority is supported.

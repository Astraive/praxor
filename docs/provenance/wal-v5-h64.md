# Version 5 WAL typed frames (H64)

This is the complete byte grammar for a v5 frame after a separately validated
80-byte `PWH5` WAL header. All integers are unsigned little-endian; offsets are
zero-based, half-open byte ranges. A decoded frame is **untrusted**: its valid
checksum and hash establish byte integrity under a trusted-writer model, not a
WAL owner, a valid relational effect, provenance, active-tail repair permission,
or protection against an adversary who can rewrite the file and its hashes.
The read-only `src/wal/v5_frame.rs` decoder accepts one complete synthetic frame
image and a separately supplied `FrameContext`; it does not scan installed WALs.

## Frame shell and chain

A frame is exactly `H64 || payload[payload_len] || crc32c_le[4] || trailer[32]`.
No padding or suffix is part of that frame. Its 64-byte H64 is:

| Bytes | Field | Required value |
| --- | --- | --- |
| `[0,4)` | Magic | ASCII `PWF5` |
| `[4,6)` | Format version | `5` |
| `[6,8)` | Flags | `0` |
| `[8,12)` | `total_len:u32` | Exactly `100 + payload_len` using checked arithmetic |
| `[12,20)` | `sequence:u64` | The checked successor of the preceding complete frame sequence, or of the H80 `start_after_sequence` for the first frame; zero is invalid |
| `[20,21)` | Kind | `1=User`, `2=Record`, `3=CatalogBootstrap`, `4=CatalogCreate`; all others invalid |
| `[21,24)` | Reserved | Three zero bytes |
| `[24,28)` | `batch_count:u32` | `0..=4096`, counting only ordinary operations |
| `[28,32)` | `payload_len:u32` | At most `67,108,864` bytes (64 MiB) |
| `[32,64)` | `previous_hash` | H80 `header_digest` for the first frame, otherwise exactly the preceding complete frame's 32-byte trailer |

For kinds 3 and 4, `total_len <= 1,048,576` bytes as well. Consequently
`total_len <= 67,108,964` for every frame. Test the length equation, kind,
count, minimum payload, and caps with checked arithmetic before reading or
allocating from an untrusted declared length. A complete decoder must receive
exactly `total_len` bytes, not an arbitrary trailing suffix.

The four CRC bytes are the **true reflected Castagnoli CRC32C** of exactly
`H64 || payload`, stored little-endian. Its standard check value is
`CRC32C("123456789") = 0xe3069283`. The legacy `crate::io::crc32c` alias is
IEEE CRC32 and cannot validate v5 bytes. The trailer is the raw 32-byte

```text
BLAKE3(ASCII("praxor/wal-frame/v5") || header_digest || previous_hash ||
       H64 || payload || crc32c_le)
```

with no separator or NUL after the ASCII domain. `header_digest` is the
separately validated 32-byte
`BLAKE3(ASCII("praxor/wal-header/v5") || 0x00 || H80)`; it is not stored in
H64. Validate the CRC and trailer against the exact bytes, then parse the
closed payload grammar. The expected sequence, previous hash, header digest,
and database ID come from a separately trusted context, not from this frame.
No sequence gap, hash-chain reset, or alternate framing is legal.

## Payload and ordinary operations

The payload is exactly:

```text
control_len:u32 || control_bytes[control_len] || op[0] ... op[batch_count-1]
```

There is one kind-specific control prefix, which is not counted as an ordinary
operation. Its only legal lengths for User, Record, CatalogBootstrap, and
CatalogCreate are respectively `0`, `88`, `120`, and `64`. Thus zero-operation
payload minima are `4`, `92`, `124`, and `68` bytes, and frame minima are
`104`, `192`, `224`, and `168` bytes. Each ordinary operation uses at least
20 bytes, so `payload_len >= 4 + control_len + 20 * batch_count`. The decoded
control plus exactly `batch_count` operations must consume every payload byte.
Zero-operation User is legal. Zero-operation typed controls are structurally
decodable, but a later relational validator may reject a required effect that
is absent. There is no second control, extension, or v2 control operation.

Each ordinary operation appears in its original physical batch order, without
sorting, deduplication, Unicode normalization, or case folding:

| Field in wire order | Encoding and constraint |
| --- | --- |
| `ordinal` | `u32`, exactly the zero-based physical operation index `0..batch_count-1` |
| `op_tag` | `u8`: `1=Put`, `2=Delete`, `3=PutWithExpiry`, `4=Merge`; every other tag invalid |
| `cf_generation` | `u64`, nonzero |
| `cf_len`, `cf` | `u16` in `1..=255`, followed by exactly that many valid UTF-8 bytes containing no NUL (`U+0000`) |
| `key_len`, `key` | `u32` in `0..=1,048,576`, followed by that many uninterpreted bytes |
| `value_len`, `value` | Only for Put, PutWithExpiry, Merge: `u32` in `0..=67,108,864`, then that many bytes; absent for Delete |
| `expires_at_ms` | Only for PutWithExpiry: `u64`; absent for the other three tags |

An empty key or value is allowed by this wire grammar. The frame and catalog
caps still apply to the sum. A complete frame with extra bytes, a truncated
field, a repeated or skipped ordinal, a malformed name, or an unknown opcode
is corrupt even if its CRC and trailer are recomputed.

## Closed typed controls

All typed controls carry the same nonzero 16-byte database ID as the validated
H80 and `epoch=LE64(1)`. Their first 32 bytes use `[0,4)` ASCII magic,
`[4,6)` `codec=LE16(1)`, `[6,8)` kind/flags as specified below, `[8,24)` the
opaque database ID, and `[24,32)` the epoch. No other codec or flag is legal.

The 88-byte Record control has magic `PRR1`, `[6]` control kind and `[7]=0`.
Its remaining fields are:

| Bytes | Field |
| --- | --- |
| `[32,40)` | `prior_rid:u64` |
| `[40,48)` | `new_rid:u64` |
| `[48,56)` | `prior_compatibility_sequence:u64` |
| `[56,64)` | `new_compatibility_sequence:u64` |
| `[64,72)` | `prior_append_ordinal:u64` |
| `[72,80)` | `new_append_ordinal:u64` |
| `[80,84)` | `record_count:u32` |
| `[84,88)` | `logical_entry_count:u32` |

Its control kind is closed: `1=Bootstrap`, `2=Create`, `3=DeleteRecords`,
`4=IndexPut`, `5=IndexDelete`, `6=DeleteWithIndexCleanup`. Bootstrap requires
frame sequence 1 and all six counters and both counts zero. Every other kind
requires sequence greater than 1 and `logical_entry_count > 0`; checked
`prior_compatibility_sequence + logical_entry_count` must equal the new
compatibility sequence, and checked `prior_append_ordinal +
logical_entry_count` must equal the new append ordinal. Additional constraints:

| Control kind | Required record/RID relation |
| --- | --- |
| Create | `record_count > 0`, `logical_entry_count >= record_count`, checked `prior_rid + record_count = new_rid` |
| DeleteRecords | `record_count > 0`, `logical_entry_count = record_count`, `new_rid = prior_rid` |
| IndexPut or IndexDelete | `record_count = 0`, `logical_entry_count = 1`, `new_rid = prior_rid` |
| DeleteWithIndexCleanup | `record_count = 1`, `logical_entry_count >= 2`, `new_rid = prior_rid` |

The 120-byte CatalogBootstrap control has magic `PCB1`, `[6,8)=[0,0]`,
the shared database ID and epoch, and `[32,120)` a **complete** 88-byte
`PRR1` Bootstrap control with the same database ID. Its frame sequence is 1.
The 64-byte CatalogCreate control has magic `PCC1`, `[6,8)=[0,0]`, the
shared database ID and epoch, then:

| Bytes | Field and constraint |
| --- | --- |
| `[32,40)` | `prior_revision:u64`, greater than zero |
| `[40,48)` | `prior_collection_count:u64` |
| `[48,56)` | `new_revision:u64`, equal to this frame sequence and greater than `prior_revision` |
| `[56,64)` | `new_collection_count:u64`, equal to checked `prior_collection_count + 1` |

These are **static byte and arithmetic constraints**. They do not verify that
the prior revision, counters, collection, record IDs, CF generation, or
protected-row effects match installed history. Retained-WAL validation must
independently check every complete frame in physical WAL-ID and frame-offset
order, including frames at or below its watermark, before allowing an owner.
It must compare installed effects, live CF generations, predecessor controls,
and protected roles. A User frame cannot gain protected-role write permission
merely by passing this parser. The v1/v2 `CoreWalRecord` count, first-control
slot, and IEEE CRC are incompatible with this v5 grammar; there is no fallback.

## Incomplete input and golden bytes

`inspect_h64_prefix` checks visible fixed bytes, the expected sequence/hash,
partial little-endian residues, the coupled total/payload length equation,
kind, count, minima, and caps. It returns `IncompleteUnclassified` for a
feasible H64 prefix. That result does **not** mean a truncated active frame is
a valid tear, and it cannot authorize truncation, replay, or repair. The exact
existential classifier for a terminal prefix, including partial controls,
operation fields, CRC, and trailer, is separate issue #100. A complete invalid
CRC, trailer, control, or operation is corruption, including at EOF. Sealed
WALs do not get an active-tail exception.

`tests/fixtures/wal_v5_r6.json` contains the full hexadecimal H80 and four
full hexadecimal frames, with separate payload, CRC, trailer, and length
fields. The fixed H80 has database ID
`00112233445566778899aabbccddeeff`, ID 1, start-after sequence 0, CRC bytes
`bc89bfe1`, and `header_digest`:

```text
193b67f43552ad15b4c2bbd0ef52a7804a21b6a303f1b0dd04d63302b9bc1faa
```

The expected complete-frame checkpoints are:

| Fixture | Kind / sequence / ordinary count | Payload / total bytes | CRC32C LE | Trailer |
| --- | --- | --- | --- | --- |
| `record_bootstrap` | `2 / 1 / 0` | `92 / 192` | `f9527d9d` | `af5becef72a0f9b536ba076a411804eda453cc9fc91c4d86a3f2a4ae425057f3` |
| `user_put` | `1 / 2 / 1` | `30 / 130` | `4ecd81d5` | `fe657e60373b22f17c51cbf5b2ca33a6d1ef9a1dfc82ab984c543943ebce7540` |
| `catalog_bootstrap` | `3 / 1 / 0` | `124 / 224` | `8555e911` | `1ba3b66ed91070f661975b8b435886a9407c49bbc25058dc31265aa0335de06b` |
| `catalog_create` | `4 / 2 / 0` | `68 / 168` | `5dd1d1c4` | `ad5dabcc9740e36dacc81cf5d90088f47f1a7353c1d5526c7579f5f866ee067a` |

`record_bootstrap` chains to `user_put`; `catalog_bootstrap` chains to
`catalog_create` on a separate history. The UserPut operation uses ordinal 0,
CF `x`, generation 1, key `k`, and value `v`. These vectors are structural
wire fixtures, not proof that a zero-operation typed frame has the required
relational effect. Independent implementations should reproduce the complete
fixture bytes from the field tables, true CRC32C, and BLAKE3 domains above.

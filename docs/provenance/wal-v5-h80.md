# Version 5 WAL header (H80)

This is the byte contract for the read-only `PWH5` header decoder in
`src/wal/v5_header.rs` (issue #97). A decoded header is untrusted. It does not
establish a WAL owner, authorize replay or repair, prove provenance, or make a
v5 writer available. Frame decoding belongs to issue #99.

All integer fields are unsigned and little-endian. Byte ranges are half-open.
There is exactly one 80-byte representation; no extension, padding, or trailing
byte is part of H80.

| Bytes | Field | Required value |
| --- | --- | --- |
| `[0,4)` | Magic | ASCII `PWH5` |
| `[4,6)` | Format version | `5` |
| `[6,8)` | Header length | `80` |
| `[8,12)` | Flags and reserved | Zero |
| `[12,28)` | Database ID | Nonzero; equal to the expected descriptor |
| `[28,44)` | Writer incarnation | Nonzero; equal to the expected descriptor |
| `[44,52)` | WAL ID | `1 <= id < u64::MAX`; equal to the expected descriptor |
| `[52,68)` | Creation nonce | First eight bytes equal `LE64(id)`; all 16 bytes equal the expected descriptor |
| `[68,76)` | Start-after sequence | Equal to the expected descriptor |
| `[76,80)` | CRC32C | True Castagnoli CRC32C over exactly `[0,76)`, stored little-endian |

The nonce's upper eight bytes are chosen once from OS randomness when the
future WAL reservation is created and retained in its descriptor. The decoder
checks the supplied nonce against the bytes on disk; it cannot prove that those
bytes were random. It also cannot prove the preceding sequence watermark from
H80 alone.

The descriptor's separate 32-byte `header_digest` is
`BLAKE3(ASCII("praxor/wal-header/v5") || 0x00 || H80)`. It is not appended to
the header or hashed into itself. This digest is the initial previous-hash
input for future frame validation. A digest match is never a substitute for
the field, path, and CRC checks. CRC32C here uses the Castagnoli polynomial:
the reference input `123456789` yields `0xe3069283`. The historical v1/v2
checksum alias in `crate::io::crc32c` is IEEE and must not validate H80.

For WAL ID `id`, the only canonical relative path is
`wal/{id:020}.wal`: lowercase `wal`, one `/`, exactly 20 zero-padded decimal
digits, and lowercase `.wal`. ID 1 uses
`wal/00000000000000000001.wal`. The expected descriptor must supply this
exact path. Alias spellings, copied headers, and changed identity fields are
conflicts even if their checksums are recomputed.

The read-only API compares one installed header *window* to the descriptor:
the window must be exactly H80. A caller inspecting an installed WAL must
separately bind a held file/path and validate any bytes after this window as
frames. For a pending `WalCreate` or `WalRotate` reserved-file image, the only
accepted states are an absent path, each exact prefix of the unique expected
H80 at lengths 0 through 79, or exactly H80. H80 plus even one byte is not a
valid pending header-only image. The descriptor is validated first, including
when the path is absent. These byte classifications do not authorize a live
pending-state transition or active-tail truncation.

The fixed golden vector is:

```text
database_id        = 00112233445566778899aabbccddeeff
writer_incarnation = 102132435465768798a9bacbdcedfe0f
wal_id             = 1
creation_nonce     = 0100000000000000a0a1a2a3a4a5a6a7
start_after        = 0
relative_path      = wal/00000000000000000001.wal
H80                = 50574835050050000000000000112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f01000000000000000100000000000000a0a1a2a3a4a5a6a70000000000000000bc89bfe1
CRC32C[76,80)      = bc89bfe1
header_digest      = 193b67f43552ad15b4c2bbd0ef52a7804a21b6a303f1b0dd04d63302b9bc1faa
```

The inline fixed vector in `src/wal/v5_header.rs` and its tests pins these
bytes independently of the decoder. Every installed cut shorter than 80 is
rejected; pending cuts 0 through 79 are accepted only when byte-identical to
the corresponding prefix. Malformed descriptor, wrong path, altered fields,
bad Castagnoli CRC, wrong digest domain, v1/v2 bytes, a supplied installed
header window longer than H80, or any suffix on a pending header-only image is
rejected.

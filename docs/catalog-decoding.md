# V1 catalog decoding

`CatalogStore::load` holds the existing `PageDatabase` root guard for the whole
snapshot. Its private decoder reads the existing ten TCAT v1 tables. The save
preparer and encoders retain their original bytes and ownership behavior.

Each nonempty file must contain exactly a 13-byte envelope plus the declared
payload: magic, version, little-endian u32 payload length, IEEE CRC32, then
payload. The decoder checks length arithmetic, the exact physical length and
checksum before borrowing the payload. It rejects trailing envelope and payload
bytes.

After reading a table's four-byte row count, the decoder proves the count fits
the actual remaining bytes before a fallible row reservation. Minimum row sizes
include every fixed field and empty-string length prefix:

| Table | Minimum bytes per row |
| --- | ---: |
| collections | 12 |
| entities | 18 |
| fixed attributes | 14 |
| dynamic attributes | 14 |
| indexes | 20 |
| vector models | 16 |
| full text | 12 |
| graph | 9 |
| shards | 16 |
| users | 12 |

Strings borrow a checked length-prefixed slice, validate UTF-8, then reserve their
owned bytes fallibly. Attribute IDs must fit their public u16 `Aid`/`Did` types.
Storage-model and compression tags must be known, and boolean/presence flags
must be 0 or 1. These malformed representations return `PraxisError::Corrupt`
with their catalog path.

Valid v1 behavior is preserved: zero and repeated IDs, row ordering, the full
u16 ID range, empty and multibyte strings, free-form `type_code`, `kind`, `metric`
and opaque `pointer_target`, and all existing storage/compression variants.
Dynamic type values `None`, `Some(0)` and `Some(255)` remain distinct. When the
presence flag is zero, its unused type byte is ignored. Optional empty strings
keep their existing decode-to-`None` behavior. No reference-integrity or schema
policy is added.

The catalog parent must be a real directory and each selected leaf must be a
regular nonalias file. A missing optional leaf is empty only for `NotFound`;
zero-length regular files retain their existing empty meaning. Directories,
regular or dangling aliases (including Windows reparse points), and other IO
failures are errors. Loads do not create, repair or poison the shared owner;
acknowledged page data remains available after a rejected catalog read.

This closes the parsing/role defects in
[#51](https://github.com/Astraive/praxor/issues/51). Allocations are checked against
the actual input shape, with fallible row/string reservations; this is not a
fixed whole-process memory budget for genuinely large physical files. Metadata
checks do not provide protection against arbitrary external path replacement
between checks and reads. The shared live guard and v1 file checks do not prove
that ten files belong to one crash-atomic publication. Durable generation and
recovery completeness remain tracked by
[#41](https://github.com/Astraive/praxor/issues/41).

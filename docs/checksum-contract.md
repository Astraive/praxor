# Persisted checksum contract

The shared `io::crc32_ieee` helper computes **IEEE CRC32**, also known as
CRC-32/ISO-HDLC. Its standard check value for ASCII `123456789` is `0xcbf43926`;
the empty input produces zero. The implementation uses
[`crc32fast`](https://docs.rs/crc32fast/latest/crc32fast/), whose documented
algorithm is IEEE CRC32.

The historical public name `io::crc32c` computes exactly the same bytes. It
remains a source-compatible alias without a deprecation warning, so existing
storage call sites and downstream strict builds keep working. New callers
should use `crc32_ieee`. The name `crc32c` must not be interpreted as selecting
the Castagnoli polynomial; replacing its implementation with a CRC32C library
would break existing persisted checksums.

No payload checksum, header checksum, magic, version, field order or file is
rewritten by this naming correction. The core WAL, page primitives and other
existing users of the historical helper retain their current checksum bytes.
Choosing another algorithm requires an explicit versioned format and compatible
reader/activation protocol.

Historical reports that name the `io::crc32c` function refer to this IEEE
implementation. Their recorded source/binary hashes and measured samples remain
unchanged; the helper name does not establish a Castagnoli benchmark result.

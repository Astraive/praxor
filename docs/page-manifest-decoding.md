# V1 page manifest decoding

`PageManifestStore::load` validates an exact 13-byte envelope plus payload:
magic, version 1, checked little-endian u32 payload length, and the existing IEEE
CRC32. It rejects outer and payload trailing bytes. No writer bytes, format
version, save/publication order or raw utility ownership protocol changes.

After the four-byte row count, each row needs at least 17 actual bytes: three
length prefixes, a u32 format version and one recoverability flag. The decoder
proves that count fits before a fallible vector reservation. It borrows strings,
checks their actual extents/UTF-8, requires format_version to fit u16 and flags
to be 0 or 1, then owns the validated row's strings through fallible reservations.
Malformed data returns `PraxisError::Corrupt` with its manifest path.

Writer-produced v1 files retain row order, duplicates, empty/opaque UTF-8 strings,
format versions 0 through 65535 and both boolean values. Path, format and checksum
strings remain opaque metadata; loading does not access those paths or impose
a new format-name/digest policy. A missing manifest still means empty inventory;
an existing zero-byte file is corrupt. There is no arbitrary lower row/string
cap or fixed whole-process memory budget for genuinely large physical inputs.

`PageDatabase::open` validates the present manifest after lease/format admission
and before reading/repairing the canonical WAL or initializing layout, including
when no collections are discovered. It shares one decoded inventory across
startup collection checks. The existing pure format inspector still performs
its own bounded structural probe. A later new-entity load keeps its existing
fresh-manifest wrapper and uses the same private collection-validation helper.

This codec addresses [#57](https://github.com/Astraive/praxor/issues/57), separately
from the ten catalog table decoders. Managed startup additionally checks
[known v1 writer-role presence](page-inventory-presence.md) using current-layout
identities. Unknown annotations remain opaque; selected canonical files retain
the existing checksum checks. [#41](https://github.com/Astraive/praxor/issues/41)
still owns inventory completeness and multi-file publication/recovery guarantees.
Neither check adds a mandatory manifest, a generation or completion witness,
relocated checksum provenance, repair inference, or crash atomicity.

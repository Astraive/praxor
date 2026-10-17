# v1 typed-record read validation

Typed page records retain their existing v1 magic, type tags, storage tags,
length fields and IEEE CRC32 bytes. Valid field IDs include the full u16 range;
zero and repeated IDs keep their previous behavior. A repeated field lookup
returns its first cell. This boundary validates the typed metadata; it does not
add semantic validation of every registered type's opaque value bytes.

Reads require exact outer and inner payload consumption. Cell counts are proven
against actual remaining input before fallible reservation; field IDs cannot
narrow from u32 into another ID. All cells' class/pointer pairs are validated
before field selection or external lookup. Inline cells have no pointer, and
external, segment and catalog cells carry only their matching pointer with empty
inline bytes. The fixed page overflow/segment roles use file ID 1; offsets must
include the existing five-byte blob header and have checked record bounds.
Catalog names remain opaque data and never select a filesystem path.

Page reads construct existing-file blob views without initializing missing files
or directories. Blob reads require a regular nonalias leaf, validate header,
identity, checked file bounds and record metadata, then reserve and read only the
selected payload before verifying its checksum. They do not read the entire blob
file into memory. Validated file length bounds allocations without introducing an
arbitrary small blob-size cap; allocation failure returns an error.

Malformed metadata and missing/corrupt blobs return read errors. Reads do not
repair files, consume RIDs, publish candidate state or poison the shared owner.
External raw modifications and path replacement races remain outside cooperative
ownership guarantees. This change does not add multi-file crash atomicity,
historical blob generations or recovery completeness; issue #41 tracks that work.

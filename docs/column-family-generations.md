# Column-family incarnations

The core KV manifest uses format version 2. Each active family has an incarnation
ID and a `visible_after_sequence` floor. Creation allocates a checked increasing
ID and records the current committed sequence; drop removes the active entry
while keeping the allocation counter. Drop/recreate therefore changes identity
even when no data writes occur between those operations. The default family and
migrated legacy families use ID 0 with floor 0.

Recovery filters every segment version and WAL operation using the active family
and its floor before merging versions. Nonlegacy families accept only sequences
strictly above their floor. Legacy ID 0 retains sequence-zero compatibility. All
durable WAL sequence watermarks still advance the allocator, even when every
operation in a record is filtered out. The WAL record format is unchanged.

Pending writes capture used-family IDs and normalization policies together under
one manifest lock. Before append, the writer validates those IDs against the
current active incarnations. A dropped/replaced family rejects the whole batch
with retryable `WriteStalled`, without consuming a sequence or poisoning the
handle. Resubmit the whole logical batch against the current family policies.
Other valid members of its commit group can proceed. A pinned snapshot retains
data versions within an active incarnation; it does not retain access to a
dropped family or transfer old data into a replacement incarnation.

Version-1 manifests are upgraded in memory to explicit legacy entries, including
the legacy empty-family repair. The next structural manifest save persists the
complete v2 map and counter. Checkpoints and backup manifests carry that same
metadata. Version 2 requires exact active-name coverage, unique nonzero IDs,
complete generation fields, valid sequence floors and a counter beyond allocated
IDs. Invalid and future versions are rejected.

Switching a v2 database back to an older binary is unsupported. Older binaries
lack manifest-version checks and can ignore or discard incarnation metadata;
writing version 2 alone cannot prevent them from opening the database. Historic
version-1 drops cannot be reconstructed when their DDL metadata was never saved.
This migration does not claim to identify already mixed legacy incarnations.
Tests cover recovery, migration and deterministic admission boundaries; they do
not simulate power loss.

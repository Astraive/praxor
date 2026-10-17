# Core record authority checkpoints (#46 F1a/F1b)

This F1 slice adds the explicit `CoreDatabase` and cloneable `CoreRecordStore`
over one core authority. Foundation and CRUD form one reviewed format change.
Historical payload snapshots, legacy import, plugin parity and product adoption
remain separate phases of #46.

F1b checkpoint 1 adds private typed User/Barrier requests and Write/Barrier
outcomes, with per-request Configured/Durable requirements. A barrier is a
positive-charged FIFO fence that actually syncs the covering core WAL; it writes
no frame and consumes no core sequence. It holds no maintenance/WAL/manifest
guard while waiting. Durable accepted requests sync even under Never without
changing persisted policy; rejected requests do not force IO. The helper remains
private and serves the record facade. No record intent/planner is exposed.

Checkpoint 2 adds private sealed owned record intents and typed RID receipts to
that same queue. Its canonical builder/parser covers the six envelope kinds;
DeleteByIndex lowers to cleanup or an index tombstone under the writer. Accepted
intents alone advance the request-local overlay, RID/counters and core sequence.
Receipts and exact frame size are prepared before merging. Every accepted record
request is Durable. Conservative owned-memory admission may exceed the wire cap
as an oversized singleton; exact materialized frames obey the existing 64 MiB
payload limit before rotation or append. Checkpoint 3 adds public batch handling,
current reads, ordered record flush and semantic v3 verification.

`CoreDatabase::records()` returns a view of the same owner. It reuses `RecordId`,
`store::IndexInsert` and `store::BatchRecord` and offers logical put/batch, fetch,
index mapping reads/writes, primary deletes and cleanup. Methods take `&self`;
clones share the queue and retained lease. Live/dead/byte counters and the fresh
`compatibility_sequence()` watermark are fallible reads. Healthy empty create or
delete batches return success without a frame, RID/counter advancement or sync
claim; shared poison is checked first. Every accepted nonempty record mutation
is durable under all three KV sync policies. A later automatic flush error can
be returned after commit and is therefore ambiguous.

Each record read holds one current core pin through all of its resolutions.
`fetch_by_index` uses that same pin for Head, State and Payload. Unknown/dead RIDs
are absence; live State with missing/malformed Payload is corruption or IO error,
never index absence. Record reads/counters fail closed on common poison, while
ordinary KV retains its documented last-published-read behavior.

`lookup_rid_at` is mapping-only at a raw ceiling, including zero and `u64::MAX`.
It selects greatest eligible append ordinal, including delete decisions, using
an exact descriptor/incarnation/L32 binary-key range. Key capture uses ordered
tier ranges; locks are released before point resolution. A concurrent future
fact absent at the captured pin is skipped. Registry lookup binary-searches the
validated immutable sorted descriptors without a new cache. Range scratch space
follows matching keys; the work includes per-tier range lookup/deduplication and
canonical resolution of those keys, not a whole-database scan or a throughput
claim. There is no public numeric late pin or historical payload API.

Record `flush()` waits for a real ordered durable barrier before core flush,
including covering earlier Never writes across WAL rotations. It consumes no
logical entry/core sequence and changes no sync policy.

V3 `kv().verify()` captures one RAM manifest and exact retained WAL prefix lengths
under maintenance then writer, releases writer and retains maintenance through
the shared owner/backup semantic evidence proof. Clone appends can continue;
they do not enlarge that capture. Verification syncs/repairs/writes nothing.
Its report counts validated segments/checkpoints, unique value files having
referenced validated extents, and bytes comprising complete segments/checkpoint,
exact WAL prefixes and unique referenced value extents including each 12-byte
header. It does not count unreferenced value-file bytes, repeated physical reads,
or RAM manifest bytes as checked disk bytes. Legacy verify accounting remains
unchanged. Verification is an integrity check, not a durability acknowledgement.

Reopen and captured backup validation share the canonical parser. Complete old
envelopes prove their own RID ranges and counter relationships: floors never
decrease across retained evidence, and a complete core-sequence chain requires
exact counter continuity through ordinary user requests. Missing old sequences
reset equality, not monotonicity; old priors are never equated with today's
allocator or current RID liveness. Installed state at the flush cutoff is checked
before exact stateful suffix transitions. Repeated known-dead deletes legitimately
advance counters without allocating IDs or creating facts.

Installed proof walks actual rows and checked RID adjacency, never a claimed RID
range or allocation count. It checks payload/state/counter consistency, globally
unique immutable fact ordinals and matching latest heads. Retained state cannot
resurrect an ID; payload summaries cannot change or reappear after tombstones;
allocator floors and dead count are monotone. Counter lower bounds include each
allocated RID, first delete and actual immutable mapping fact, without claiming
they explain all repeated deletes. Payload evidence retains lengths and digests,
not a second payload corpus; validation storage follows actual retained metadata,
versions and facts. Blob rows are resolved one bounded row at a time. These are
integrity checks, not a whole-process memory bound or arbitrary tamper detection.
Available immutable payload witnesses and live-state lengths agree across both
segments and retained WALs, even when the current RID is dead; absent compacted
history is not required. Available allocator and primary copies at the same
core sequence agree across segments and WALs, including tombstones and dead
states; same-sequence heads preserve last input order. A fresh mapping Put's raw
sequence must exceed its RID, a necessary allocation-before-mapping floor rather
than proof of every historical event when its original WAL has been retired.
Available live primary evidence precedes the earliest available death for that
RID. A death covered by the installed flush cutoff requires the installed state
to be dead, before replaying any newer suffix; pruning cannot erase that known
fact and a later suffix delete cannot mask a contradictory installed live row.
Fresh F1 has no payload-update operation: available live State/Payload copies
for one RID share its creation sequence. Mapping Put facts are live-at-event
witnesses, at or after an available birth and before an available death. Known
births follow actual RID allocation order, allowing equal sequences for a batch
and missing pruned births. These fresh-format checks do not define future update
or imported legacy history semantics.
Every available Head, including intermediate same-sequence puts, binds to its
exact immutable Fact value and core sequence. Facts keep one core sequence across
WAL and segment copies. Available allocator cuts agree at one sequence and have
monotone RID/dead floors and advancing fresh counters. Known births, RID events
and Fact raw positions respect earlier/later available cuts; actual Fact raw
intervals advance across core sequences even where intermediate cuts are gone.
This temporary proof walks actual metadata and never manufactures missing cuts
or claims to detect an entirely coherent rewrite of all historical evidence.

Fresh compatibility counters describe logical CRUD/index entries. Legacy primary
physical relocation consumes its own raw sequence; fresh maintenance fabricates
no relocation fact. Numeric ceilings are not interchangeable between those
backend domains. Snapshot/import/adapter work remains separate.

Commit sync attempts/successes/duration include closed write groups and ordered
barriers; rotation/header/checkpoint syncs remain separate. Earlier rotated WALs
are covered by the existing sync-before-install protocol. Sync failure poisons
the common owner and completes later queued requests. A current allocation test
checks live workspace for one 1 MiB ordinary payload against one encoded frame
plus 512 bytes; this is not a whole-process memory or throughput measurement.
Both ordinary and typed WAL encoding use the shared borrowed operation writer.

`CoreDatabase::create_fresh` creates only an absent/empty root (its permanent
writer lock is neutral). `CoreDatabase::open` requires an existing supported v3
manifest. `kv()` clones the same `PraxisEngine` owner: lease, queue, health, core
WAL, maintenance and snapshot manager are shared. Closing or dropping one view
does not release the lease while another view/transaction retains it.

Creation validates registry names, exact encoded size and configuration before
format IO. It writes the v2-framed bootstrap record at sequence 1, syncs its WAL
and directory, and only then publishes the complete v3 manifest through the
existing durable temporary-file/rename path. No legacy open, load-or-create,
interim v2 manifest or independent activation marker participates. A failure
after final publication is ambiguous: a later explicit open may find a complete
authority. No-final-manifest activation remnants are preserved and refused.

V3 requires a nonzero OS-random opaque 128-bit identity, epoch 1, schema 1 and all
four immutable role/CF/generation bindings. Exact descriptors disallow TTL,
merge and policy overrides. V1/v2 reject any attempted `record_authority` field;
they keep their existing user CF names, including names in the reserved range.
Ordinary `PraxisEngine::open` returns `RecordAuthorityOpenRequired` for v3. The
pointer, standalone record, page and Catalog constructors refuse the foreign
root through the merged format/ownership admission baseline.

Later v3 user CFs have generation IDs at least 5 and visibility floors at least
bootstrap sequence 1. Legacy generation-zero families remain valid in v1/v2.

V3 public KV calls reject the protected CF range before normalization/admission
and again under writer serialization. Reads/scans, forged CF handles, direct
batches, savepoint/nested output, optimistic commit output and CF create/drop
share the central check. User CFs and arbitrary default/user key bytes retain
their meaning; a user key containing a protected CF name is ordinary data.
Protected descriptors are omitted from ordinary CF listings. The authority
accessor returns an immutable metadata copy, not a writable system handle.

Private `CoreWalRecord` retains the 88-byte authority envelope. Public ordinary
WAL decode/replay/open returns `RecordAuthorityWalRequired` rather than silently
dropping it or repairing its tail. Row/key/envelope decoders check actual byte
availability before copying fields and reject unknown schema, flags, tags,
reserved bytes, trailing bytes and checked counter overflow. The outer framing,
64 MiB payload ceiling and CRC-32/IEEE bytes are unchanged.

Explicit v3 reopen validates all segment rows and complete WAL records, including
retained files below the flush cutoff, before reconciliation, manifest writes,
directory creation, tail truncation or writable WAL open. Protected pointers are
resolved only after their exact owned value-file role, actual bounds and row
limit have been checked; threshold 1 externalization is supported. Bootstrap
binding/registry/allocator evidence must exist and match. Missing counters are
never synthesized. A valid unacknowledged torn ordinary suffix can be repaired
only after this complete-evidence validation succeeds.

Unknown reserved segment CFs are corruption, including evidence that would
otherwise be discarded by a generation filter. Every v3 segment version is
covered by the installed flush cutoff; ordinary rows are strictly newer than
bootstrap sequence 1. Complete retained WAL records remain strictly ordered
even below that cutoff. Legacy sequence-zero/overlap behavior is unchanged.

Backup retains typed records through #42 coverage and protected validation. A
v3 capture records exact prefixes for retained old WAL evidence as well as the
unflushed files to copy. Original evidence is checked before staging, and staged
and final role-relocated copies are checked before/after publication under the
existing incomplete-copy protocol. It does not follow source labels as a file
fallback. Necessary WAL/checkpoint/compaction redundancy is separate from
canonical record payload ownership.

Raw byte-file utilities (manifest/segment/WAL/value-file tools) remain trusted
offline tools with caller-managed exclusive ownership. They are not owner
factories or a supported way to mutate a live v3 root. This is an integrity and
cooperative ownership protocol, not protection against arbitrary filesystem
writes or old binaries that ignore the protocol. The minimum writer-family
refusal baseline includes completed #40/#48 admission; no writable downgrade or
universal old-binary claim is made.

Fault tests emulate API/IO boundaries and verify unchanged entries/bytes on
refusal. They do not prove physical power-cut durability. Unix directory sync
and the existing non-Unix limitation remain the platform contract.

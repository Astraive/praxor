# Core record authority foundation (#46 F1a)

This is an unshipped review checkpoint within the complete F1 branch. It has no
public record writer. Nonbootstrap record envelopes and protected states return
an explicit unsupported error until F1b installs sealed logical intents and their
complete transition validator. F1a and F1b must ship together; this checkpoint
does not establish record CRUD, record durability barriers, historical payload
snapshots, legacy import, plugin parity, or product adoption.

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

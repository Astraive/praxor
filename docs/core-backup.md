# Core backup and relocation

`PraxisEngine::backup_to` captures one committed sequence and CF schema under
maintenance then writer serialization. It synchronizes the active WAL, captures
the in-memory manifest and exact WAL lengths, and releases writer serialization
before copying. Maintenance remains held until completion: clone writes and WAL
rotation can continue, while flush, compaction, GC and structural CF changes wait.
An operation whose automatic maintenance waits can therefore finish after backup.

The result preserves every retained version and same-sequence operation in the
captured segment set, including tombstones, merge operands and expiry metadata.
It preserves CF options/incarnations and older referenced value logs. History
already removed by compaction cannot be recreated. Expiry still uses wall time.

Segment and checkpoint paths and blob pointers are relocated to the final
canonical target. A supplied bundle's path labels identify exact role/file IDs
under one original root label. They never authorize reading the original source.
Segments are transcoded through the same checked framing/value codec as ordinary
readers; tag-4 expiry blobs remain pointers during relocation. Blob contents stay
in value logs, with unchanged offsets, lengths and checksums. All three existing
compression modes and existing on-disk versions retain their byte contracts.

The published backup opens at its created location without the source. To move a
bundle, use `restore_from_backup(moved_bundle, final_target)` before opening it;
ordinary engine opens do not relocate a moved database's persisted paths.
The target is independent of both the original source and the supplied bundle.
Current-platform spelling, ordinary relative legacy labels, and separate-volume
destinations are supported. Unsupported cross-OS spellings, conflicting origins,
aliases and missing/corrupt referenced files are refused. Backup includes managed
database authority and its dependencies; opaque application auxiliary files are
not copied or adopted. Unknown destination entries are conservatively refused.

Required WAL IDs must cover `(flushed_wal_id, active_wal_id]`. Complete parsed
records must prove contiguous committed sequences `(flushed_sequence, C]` across
those files, including batches whose CF operations have since retired. Legacy
sequence-zero records remain byte-for-byte in copied WALs; they do not prove any
positive sequence. Unprovable sparse/equal/decreasing legacy suffixes are refused
by backup/restore rather than guessed complete. Ordinary legacy WAL replay is
unchanged. The checks cannot detect forged metadata that falsely claims a flush
or a different final sequence; this is a consistency check, not authentication.

## Replacement and retry

Source and destination must be disjoint and exclusively owned. Restore leases
its offline source; backup uses the live engine's retained source lease. Permanent
root/known-primary lock files survive all replacement and cleanup paths. A stopped
Pointer/Page/Record database is still foreign authority and is never overwritten
as a core-copy target.

Copy stages in `target/tmp/backup-stage-*`, encoding final target paths, and
validates all dependencies there. Failure during staging leaves the old authority
intact. Before deleting anything, publication writes and syncs a fixed private
stage marker, renames that file to `CORE_COPY_INCOMPLETE`, and syncs its parent.
It removes old MANIFEST authority before dependencies, installs and syncs copied
files, publishes MANIFEST last, then statically validates the final role/digest
state. Only afterward does it remove and parent-sync the incomplete marker.
Restore returns `Result<()>`; it does not validation-open an engine.
An explicit retry re-synchronizes the existing marker file and its parent before
any deletion, even when a previous attempt left the exact marker bytes behind.

Any root marker presence makes ordinary core/pointer/record/page admission refuse
the root. After an interrupted replacement, explicitly retry backup or restore
with a valid source. Retry accepts only the exact fixed marker and a strict known
core layout, including a neutral primary lock container. Malformed markers,
foreign/mixed anchors, aliases and unrelated files refuse without destructive
cleanup. Recognized abandoned staging roles, including signature-prefix prepared
markers and numeric checkpoint `.tmp` files, can be discarded by that explicit
copy retry; their contents are never published as authority.

This is synchronous, nontransactional replacement. A failure after marker
publication can leave the previous backup unavailable until an explicit retry.
In-process publication fault tests and ordinary reopen tests do not demonstrate
power-loss safety. Parent directory sync remains limited by platform support;
the existing non-Unix helper is a no-op. Older binaries and raw tools that ignore
writer ownership or the marker protocol are outside the supported concurrency
contract. No new identity marker, file-format migration or atomic rollback is
introduced by this repair.

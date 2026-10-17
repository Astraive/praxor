# Exclusive writer ownership

`PraxisEngine`, pointer `StorageEngine`, and standalone `RecordStore` retain an
exclusive OS lock on `.praxor.writer.lock` in their canonical root. An independent
open of an owned root returns `PraxisError::AlreadyOpen { path }` before loading
or repairing its WAL or manifest. Filesystem/locking errors propagate; ownership
never falls back to a PID check or an in-memory-only mutex.

The lock file is permanent. Its existence does not indicate a live writer; the
OS lock on the retained file handle does. Opening does not truncate its contents.
Drop, recovery, backup and restore do not unlink or replace it. Replacing the
file could let a second writer lock a different inode at the same pathname.

Core clones and optimistic transactions share `EngineInner` and retain the same
lease. `close(&self)` flushes and does not release ownership while handles remain
usable. Drop every engine/transaction owner and stop/join background workers
before opening the database independently again. Process termination releases
the OS handles; ordinary recovery validates the stored data on the next open.

Pointer storage acquires its root lease and the `primary` child lease before
initializing mutable state. It passes that child lease into its nested record
store. Standalone `RecordStore::open(root/primary)` therefore conflicts with the
parent engine in either ordering without a nested acquisition deadlock: a
standalone record root whose canonical final component is `primary` retains both
its parent and child leases. The reserved primary directory cannot be an alias.
Private lease transfer does not make independent mutable stores share their state.

Roots are created as needed and canonicalized before acquiring ownership and
constructing storage paths. Existing directory symlink/junction aliases resolve
to the same lock. This does not rewrite file paths already persisted inside
manifests or blob pointers.

Arbitrary ancestor/descendant database layouts are unsupported. An independent
opener first rejects already recognized ancestors without creating a lock
artifact, then repeats that validation after locking its own permanent artifact
to close the race with a newly appearing parent. The only private exception is
the owned `primary` child. A racing refusal can leave a conservative lock
artifact, but happens before store initialization; it is never unlinked to hide
that race.
Symlink or non-file lock artifacts are rejected instead of followed.

## Backup and restore destinations

Backup and restore acquire the destination root and any existing primary child
lease before checkpoint/copy cleanup. An owned destination is left unchanged.
Restore also leases its source root, refusing a live source; backup uses its
already retained source lease. Existing source primary children are explicitly
leased. Source and destination preflight reject every other descendant writer
artifact, even when inactive, before copying/deleting data. The root lock alone
does not authorize erasing unrelated nested databases. New independent nested
opens refuse recognized ancestors, closing the race with that preflight under
the cooperative protocol.
Cleanup retains permanent lock files recursively and removes directory aliases
without traversing their targets. Copy omits lock files and rejects source-tree
symbolic links. Source and destination must be disjoint: neither may contain the
other. The supported built-in layout uses separate `live`, `backup` and `restore`
roots. Failed acquisition or copy releases the newly acquired leases.

`restore_from_backup` still copies and returns `Result<()>`; it does not open or
validate the restored engine. Replacement is not a transactional restore, and
these changes do not relocate existing absolute/relative blob references or
establish backup portability or power-loss durability.

## Scope and offline utilities

Page storage and its collection/entity coordination are separate work in #36.
The private lease is reusable by that coordinator, which must also share its
mutable directory and allocation state.

Low-level `Wal`, `StorageWal`, `PageWal`, `RecordSegment`, indirection and manifest
utilities remain physical/offline building blocks. Their direct constructors
and mutation methods must not be used concurrently with an engine owning the
same files. Recovery tools must stop all live owners before editing physical
state. This cooperative lock protocol cannot protect against older binaries,
raw utilities or external programs that ignore it. A live database is shared
through engine clones or an explicitly shared engine handle, rather than by
independently reopening its files.

After acquiring ownership, supported core/pointer/record opens apply the
[storage root format contract](storage-root-formats.md) before mutable initialization.
The page admission helper is ready for the separate #36 coordinator integration.

# Storage root formats and admission

Core `PraxisEngine`, pointer `StorageEngine`, and standalone `RecordStore` identify
an existing physical layout after acquiring writer ownership and before creating
layout directories, opening mutable primary segments, repairing WALs, or writing
manifests. A closed pointer database can no longer be opened as an apparently
empty core database. An incompatible open returns a typed format error and leaves
its data and directory entries unchanged, apart from exact permanent ownership
artifacts required by [writer ownership](writer-ownership.md).

## Recognized authority

| Supplied path | Recognition |
| --- | --- |
| Core root | Typed `MANIFEST` TOML, supported format versions 1/2; known core WAL prefixes and exact owned directory boundaries. |
| Pointer root | Typed JSON `MANIFEST.store`, its nested `primary` record component, and legacy `storage.wal` or segmented `.swal` WALs. `StorageManifest.version` is a metadata revision, **not** a physical schema discriminator. |
| Standalone record root | Typed `indirection.tind` and record segment headers. An unwritten store containing only the valid header-only initial segment is also supported. |
| Page namespace | `.praxis` with bounded page-manifest, RID-directory, or catalog-control probes; an exact complete empty scaffold is distinguished from populated page authority. |

The inspector composes a pointer's nested primary into its parent owner. An exact
empty primary prepared by a standalone caller may become a pointer scaffold.
A caller-precreated empty standalone primary can initialize when its parent
contains only that primary and the permanent root lock. A populated standalone
primary can reopen under its own complete record authority; it cannot be silently
adopted by a new pointer engine without a pointer manifest. A missing primary
directory is never created before its parent passes admission under the retained
parent lease.

Known matching formats retain their established recovery semantics, including
headerless core WALs, interrupted file headers, torn terminal appends, deferred
pointer indirection updates repaired from the WAL, and complete offline pointer
assemblies without a WAL directory. A valid final manifest remains authoritative
over its own interrupted temporary write. Foreign temporary control syntax still
blocks admission. No generic hidden-file or `*.tmp` exclusion exists.

## Opaque auxiliary entries and locks

Under proven core, pointer, or record authority, unrelated application files and
raw-plugin directories are reported as `auxiliary_entries`. They are not read,
traversed, followed, adopted, or removed by inspection. This preserves existing
`RecordStore` plus raw index-plugin composition. An auxiliary directory does not
become part of the engine's ownership or recovery inventory. Recognized foreign
anchors, reserved-role aliases, unsupported control versions, and reserved future
identity markers still refuse admission. A root containing only unknown entries
has no authority and is refused.

Only an exact regular `.praxor.writer.lock` at a supported ownership scope is
exempt. Pointer primary ownership is a supported nested scope. Backup/restore
can retain an exact lock-only `primary` directory under core authority to avoid
replacing its permanent lock inode; adding any payload stops that exemption.
A symlink, reparse point, directory, or unrelated nested lock is not exempt.
Page ownership belongs to the caller's base: neither `.praxis` nor a collection
directory has an independent lock exemption.

## Read-only inspection and bounds

`storage::root_format::inspect_storage_root(path, options)` creates no files or
locks and never invokes engine opens, replay, repair, plugin loading, or cleanup.
Its report preserves the requested/canonical paths, evidence, typed diagnostics,
opaque auxiliaries, and lexical metadata path references. External metadata
references and data payloads are not opened merely to diagnose ownership.

Public diagnostic defaults are 8 MiB cumulative control bytes, 4,096 cumulative
inspected entries, and 64 KiB of fixed header probes. Exceeding a supplied budget
returns `Incomplete/InspectionLimit`, never guessed emptiness. Ordinary writable
opens use a separate admission profile so these diagnostic convenience limits do
not cap existing database cardinality. Control reads use their actual physical
stat length, checked conversion, fallible reservation, and at most one additional
change-detection byte. Entry collections grow with actual enumerated entries;
untrusted binary counts never determine a reserve before remaining-byte checks.
Admission cost therefore scales with real control metadata and shallow physical
directories, without scanning every record body or page.

`RootInspection::require_compatible(owner)` evaluates captured evidence only.
It supplies no lease or concurrent-writer guarantee. Writable callers inspect
while retaining ownership; inspection is not an fsck, stable snapshot, backup
consistency check, or proof of blob portability.

## Page integration boundary

`require_page_base_compatible(base, options)` examines only exact foreign controls
and bounded shallow physical-role artifacts at the application base, then checks
the exact `base/.praxis` namespace. It permits ordinary application siblings and
empty directories without claiming them. Namespace aliases, foreign core/pointer/
record artifacts, and reserved markers are refused without following aliases.
`PageNamespace` inspection never appends a second `.praxis`.

The shared helper is available in this phase. Its writable `PageDatabase` hook
and page wrong-open matrix remain part of #36/#40; existing page constructors
must not be described as guarded until that integration is merged.

## Refusal and compatibility limits

Errors distinguish `StorageFormatMismatch`, `StorageFormatAmbiguous`,
`StorageFormatIncomplete`, and `StorageFormatUnsupported`, with evidence paths.
Live exact-root ownership still returns `AlreadyOpen` before format diagnosis.
There is no force/adopt/migrate flag. Unknown or incomplete layouts require an
offline recovery decision while all writers are stopped.

`PRAXOR_ROOT` and `PRAXOR_ROOT.tmp` are reserved and fail closed. This change does
not write or interpret an active UUID/epoch schema, migrate rows, rewrite paths,
or establish a downgrade barrier. Older executables and raw physical utilities
can ignore these cooperative contracts. Existing absolute/relative large-value
references retain their semantics; successful inline restore tests do not prove
that copied large blobs remain readable after the source disappears.

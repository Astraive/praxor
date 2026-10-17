# V1 known page inventory presence

After lease and format admission, `PageDatabase::open` strictly decodes the page
manifest once and checks recognized v1 writer roles before reading or repairing
the WAL, initializing layout, or exposing a writer. This also covers an entire
missing non-WAL collection that would not be discovered from surviving data.

| Exact format/version | Required current-layout role |
| --- | --- |
| `record-page`, 1 | `.praxis/data/<cid>/entities/<eid>/pages/frames/<fid>/pages/<pid>.page` |
| `slot-directory`, 1 | `.praxis/data/<cid>/entities/<eid>/slots/<fid>/<pid>/slot.directory` |
| `rid-directory`, 1 | `.praxis/data/<cid>/kv/critical/rid_to_slot.kv` |

A private parser recognizes only those terminal grammars. All IDs must be
nonzero u32 values in exact lowercase `to_hex` spelling, with minimum width four
and maximum width eight; IDs above `0xffff` and `u32::MAX` remain supported.
The terminal suffix uses one consistent `/` or `\` separator. Source prefixes,
including Unix, Windows verbatim and UNC prefixes, are opaque labels. The parser
does not normalize traversal, extra components, case or URL escapes.

Parsed IDs resolve through the current owner's `PraxisLayout`. Admission never
canonicalizes, stats, reads, or falls back to the old manifest label. Every
current ancestor beneath the owned base must be a real directory, and the leaf
must be a regular file. Symlinks and Windows reparse points are refused. Missing
known roles, unresolvable known labels, aliases and wrong node kinds return
`PageRecoveryRequired`; other metadata IO errors propagate. Existing earlier
lease/format/codec refusals retain their ordering. No repair or ancestor creation
occurs on a failed presence pass.

Both recoverability flag values require presence for known v1 roles. Unknown
formats or versions remain opaque and confer no required-file authority. An
absent manifest, valid empty inventory and legacy catalog-only root retain their
existing behavior. The raw manifest codec and writer encodings are unchanged.

Relocation checks presence only. Supported writes after A-to-B-to-C moves can
leave three, six, then nine raw path rows for the same three roles. Those rows
and their differing checksums are preserved. Existing selected-file validation
still uses its first exact current-path match; there is no newest, best-match or
foreign-checksum fallback, no role-keyed upsert and no manifest rewriting.

This is a bounded slice of [#41](https://github.com/Astraive/praxor/issues/41),
which remains open. It detects current files named by surviving recognized
inventory, without proving that inventory complete or authentic. It does not
make a missing manifest mandatory, decode slot-sidecar contents, establish
relocated checksum provenance, cover every blob/catalog/WAL role, recover lost
acknowledgements, or make multi-file publication crash atomic. The tests simulate
owned namespace loss; they are not process-crash or physical power-cut evidence.
Annotation relocation is not universal typed-blob or cross-platform database
portability.

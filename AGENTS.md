# Praxor agent instructions

- Read README.md, GIT.md, the relevant architecture/development docs, and the linked issue/spec first.
- Confirm the current default-branch revision; distinguish committed behavior from historical reports and unpublished sources.
- Praxor owns canonical parsing, binding, planning, execution, catalog, storage, transactions, and indexes.
- Keep runtime/session/auth work in Poiesis, history/ref/merge work in Pit, optional tooling in PoiesiSQL, and UI work in Poietica.
- Preserve existing public package names and unrelated checkout changes; use an isolated branch/worktree.
- Implement only after the spec is approved and prerequisites are resolved; native parent/blocker links and Project #2 fields are authoritative.
- Keep issue scope bounded, and never make a child depend on its own ancestor.
- Preserve wire, storage, and recovery invariants; unsupported paths must fail explicitly rather than route through a legacy fallback.
- Use locked Rust dependencies, two build jobs, and an explicit target directory on D: or F:; record the exact revision, command, and result.
- Verify durability, recovery, and performance only with the required fault/restart or benchmark evidence.
- Use your own accurate Git identity and type(scope): message subjects; standard co-author trailers are allowed for accurate shared credit.
- Follow GIT.md for review and normal merge rules; update status claims only from verified evidence.

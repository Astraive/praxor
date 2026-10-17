# Engine query ownership and readiness contracts — 2026-10-18

Q0 [#60](https://github.com/Astraive/praxor/issues/60) records the existing
public query API and literal serialization shapes, characterizes a bounded
execution path, and assigns the canonical semantic pipeline to Praxor. It
changes no parser, planner, executor, catalog writer, storage or product code.
Ignored or incomplete semantics remain explicit gaps for #61–#63.

Base: merged default `259c6a6b9523879c6ee8733151ddd38cc8f988f4`.
Reviewed source commit: `bd7e0aca8e7ee9b71f8c111d73bb390548a37570`.
Isolated branch: `codex/phase-08-query-contracts` in
`D:/poiesis-worktrees/phase-08-query-contracts`.
Rust 1.99.0, locked dependencies, two Cargo jobs and the dedicated
`F:/poiesis-targets/phase-08-query-contracts` target were used. The original
dirty checkouts were not modified.

## Executed evidence

| Gate | Observed result |
| --- | --- |
| First public contract/readiness/serde baseline, before prose edits | 15 passed, 0 failed in 3 groups; exit 0 |
| Final public contract and relevant SQL/graph/hybrid/GraphQL tests | 25 passed, 0 failed in 7 groups; exit 0 |
| Existing parser unit tests | 5 passed, 0 failed; exit 0 |
| Strict Clippy, all targets and features | Exit 0 |
| Format, storage logging, storage boundary, diff whitespace guard | Each exit 0 |

The first behavioral run was green; no failing implementation was manufactured
to claim a RED. The final source commit contains 12 reviewed files: three
public test modules, six independent literal JSON fixtures and three
ownership/readiness documents. Parent and independent review checked the
public imports, fixture values, source-backed readiness labels and frozen
source. The final 12-file freeze is
`D:/poiesis-worktrees/query-q0-source-freeze-final.json` (SHA-256
`c048789c999eb878891efb530f4f04ce91dbbbbff3e06ed823574c875f7976fd`).
All 462 tracked/new inputs matched
`D:/poiesis-worktrees/query-q0-all-input-freeze-final.json` (SHA-256
`4f2b7e74339a1d7e739d281c632dace864170a5507fcb99d7b1935b084e621f6`)
with no path-set or hash difference after that commit. This report is the sole
subsequent repository addition. The original freeze and actual gate logs remain
under the `query-q0-` prefix at `D:/poiesis-worktrees/`.

The first/final focused log SHA-256 values are respectively
`0049c2f4efabdd347b784942e50b4eff92d9f4bd09120829f9c5766a8d60d314`
and `e3162651704783b533e6619ea54e1ce3733c196bfe988851108d2c28b5aaf3f5`.
The existing-parser log is
`6be710d375bfa4a1f3a74c26fb48915a1e5bd30b5c5bbe87d19029d870aaaf3b`.
`D:/poiesis-worktrees/query-q0-final-gate-evidence.json` records each later
command, explicit exit and log hash. A final historical remote-status prose
correction came after those gates; it changed no compiled input. The parent
rehash and diff check covered that correction. Exact-head CI is the merge gate.

## Readiness boundary

The executed SELECT oracle uses a tiny in-memory provider. It verifies a
filter/order/offset/limit result and one scalar index-versus-scan match.
Characterization tests also demonstrate missing projection, `IS NULL`,
`AS OF`, `GROUP BY`, parameter metadata and trailing-input enforcement, and a
GraphQL response containing a plan rather than stored rows. The guide labels
other cells as source review or model/serde reachability where appropriate.
No durable backend, historical payload, SQL completeness, measured speedup or
end-to-end product execution is inferred from those observations.

The canonical semantic pipeline is engine-owned. Poiesis owns product
session/authorization/protocol context; optional PoiesiSQL tools consume
engine contracts; Pit history is separate. Public Rust/serde observations
remain experimental and diagnostic cost reason text is not a stable explain
promise. Q1 #61, Q2 #62 and Q3 #63 own subsequent compilation/capability,
fallible retained-view reads and persisted catalog operations. The previously
merged F2 full-engine Windows/Linux suites are baseline evidence for that
unchanged default, not newly run Q0 tests.

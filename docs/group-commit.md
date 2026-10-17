# Core KV group commit

`WalSyncPolicy::GroupCommit` admits owned write batches to one FIFO. A leader
acquires the writer mutex, closes a prefix of already admitted ordinary writes,
appends their independent checksummed WAL records, and syncs once. It publishes
the complete group before advancing the committed snapshot or completing calls.
There is no deliberate collection delay. Arrivals during IO belong to later
groups. CAS and optimistic commits form singleton barriers and validate against
the preceding published state. Their original transaction pins stay alive while
the committing caller waits.

Admission includes the active group and is limited to 64 requests and one
configured WAL segment of encoded bytes. Ticket order prevents small requests
from bypassing a waiting large request. A request larger than that byte budget
is admitted alone. A closed group fits the WAL segment payload budget, except
for such a singleton. Waiting callers retain their own batches outside the
admitted budget; applications must also bound their outstanding calls.

`EveryBatch` uses singleton groups and syncs every batch. `Never` also uses
singleton groups and omits the commit sync; structural rotation/flush may still
sync files. Grouping changes neither the WAL record format nor the atomicity
boundary: different callers remain independent batches, including during replay.

An uncertain append/sync failure or an unwinding leader completes all admitted
and waiting calls with `RecoveryRequired`. Future writes and destructive
maintenance require dropping all handle clones and reopening. Reads keep the
last published view; complete records from failed calls can appear on recovery,
so an error is not a promise that the write is absent. A failure to open the
prospective WAL before installing it leaves the original authority and can be
retried. Automatic flush starts after group leadership has been handed off; as
before, a flush failure can make an already committed call return an error.

Metrics distinguish successful commit syncs from WAL header and rotation syncs:
`commit_syncs` (successes), `commit_sync_attempts`, `commit_groups`, `commit_batches`, `write_admissions`, cumulative
`commit_queue_wait_ns` (submission through selection, including backpressure),
and `commit_sync_ns` (including failed attempts). `stats().write_state.recovery_required` reports poisoning.

The `group_commit` release benchmark compares durable EveryBatch and GroupCommit
at 1/2/4/8/16 threads and reports actual syncs per commit, throughput, queue time,
and call latency percentiles. Set `PRAXIS_BENCH_WRITES_PER_THREAD` and optionally
`PRAXIS_BENCH_DATA_DIR`; redirect stdout to NUL and capture JSON summaries on
stderr. Setup, cleanup and recovery verification are outside timing. Results
include the existing per-write logging overhead and require repeated runs on
the intended storage device. Unit/integration tests do not simulate power loss.

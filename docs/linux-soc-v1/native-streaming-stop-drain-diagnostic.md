# Native streaming Stop, Drain and CLOSED diagnostic

## Scope and preservation

2026-10-16, SOC baseline `0ee341b2ef19d08b3fd0e7ec868848f69e3e08d0`;
ML unchanged at `e1a01260f0463a38d4d778859bc2a86f8e9cfbde`.
The index was empty. Private SHA inventories record 122 existing SOC changes,
10 ML changes, the 14 failed-session files and existing research model files.
No original session file, database, dataset or artifact was edited. SQLite
inspection used read-only immutable connections after confirming no WAL files
were present. Recovery tests use temporary fixtures, never this native session.

Evidence summary:
[native-streaming-stop-drain-evidence.json](native-streaming-stop-drain-evidence.json).
It contains relative file identities, hashes and sanitized statistics, not packets,
addresses, credentials or raw log payloads. No new capture, privilege command,
test traffic, namespace, OS security response or model training was executed.

## 1. Native session: confirmed findings

Directory: `session-57b97b62b6124766a211e6c712aac9fd`.
Protocol session ID: `10f7c294-c6d7-48ea-8695-156fc8ee9f33`.
The code generates directory and protocol UUIDs separately; their difference is
not a binding error. session.json and STREAM_STARTED bind the same digest:
`59d90bc64770b38e05e543cdd423cf4df4c9265a18d4bd93b0fb1d94c1b56c27`.

| Evidence | Observed value |
|---|---|
| Helper exit | 0, **USER_REPORTED**; no stored independent process-exit record |
| READY | Present, authenticated receipt recorded in runtime audit |
| READY counters | COUNTER_VERIFIED, sequence 1, kernel total 0, drops total 0 |
| READY capability state | Eff/Prm/Inh/Amb=0, Bnd=8192, NoNewPrivs=1, normal UID/GID |
| Last periodic counter observation | Sequence 418, kernel total 404, drops 0 |
| Last periodic helper receive/send observation | 404 raw frames / 202 metadata packets |
| Last periodic uptime | 5.028746926 monotonic seconds |
| Last periodic parent RSS / helper RSS peak | 298,905,600 / 196,157,440 bytes |
| Last periodic parent CPU / helper CPU | 1.601665189 / 3.737282 seconds |
| Last periodic flow state | 4 active, 0 completed, 0 eligible, 126,158 retained metadata bytes |
| Last periodic transport state | Queue depth 0, high-water 12; reader running |
| transport-unprocessed.json | Delivered 248, queued 4; default reason EXPLICIT_STOP_BEFORE_PERSISTENCE |
| VERIFIED CLOSED / counter-failure / transport-failure files | MISSING |
| Quality / Edge receipts | 0 / 0 |
| Investigation / workflow trace / checkpoint | 0 / 0 / 0 |

The user explicitly reports **no GUI Stop and no Ctrl+C**. The stored audit
independently establishes an automatic Controller failure:

1. STREAM_HELPER_READY at 09:12:47.363689 UTC.
2. STREAM_ABORTED with **STREAM_TIME_REVERSED** at 09:12:53.200665 UTC.
3. STREAM_RESTART_GAP with automatic capture/inference retry=false.

That is a 5.836976-second UTC interval, not a proven full helper duration.
The last monotonic sample is an observation lower bound, not a CLOSED receipt.
Final elapsed time, raw frame total, sent total and kernel drop total are UNKNOWN.
Last interval drop=0 must not be generalized to the whole session.
The periodic gap_count=0 also predates the abort and signed restart-gap marker;
no final numerical gap count was persisted and a gap-free session is not established.

## 2. Root cause boundaries

**Confirmed Controller stop trigger:** the streaming aggregator rejected reversed
packet event time and `_native()` invoked `_failure()`. `_failure()` closed the
transport immediately; inherited close() sent STOP and disconnected the channel.
The old default close reason was EXPLICIT_STOP_BEFORE_PERSISTENCE even for this
automatic failure. That text does not establish human intent.

The original packet metadata was memory-only and released. We cannot recover the
two conflicting timestamps, reversal magnitude, or determine whether kernel
timestamps, clock adjustment, receive ordering or conversion caused the reversal.
There is no basis to attribute it to WSL2 synchronization or to reorder/restamp
packets. STREAM_TIME_REVERSED remains fail-closed. Future failures record only
the previous/rejected event nanoseconds and packet sequence, without packet data.

**CLOSED failure stage: UNKNOWN.** No retained evidence proves whether the helper
never attempted CLOSED, attempted a failed send, sent data that the Controller
did not receive, or encountered validation/persistence failure. The audit and
code establish Controller disconnect on automatic abort. They do not establish
the helper's final send outcome. No success receipt is reconstructed.

## 3. Deadline, frame/rate budget and exit=0 analysis

The bound session policy is lo, seconds=300, rate token refill=128 raw frames/s,
burst=256, frame budget=38,656. Last stored uptime 5.0287s and 404 raw frames
show neither deadline nor frame-budget exhaustion at that observation. They are
not final totals. No rate-budget-exceeded error is stored. The Controller's
explicit abort error is event-time reversal, not resource exhaustion.

Approved helper normal-return paths are:

- Main loop reaches approximately seconds-1; the independent finite watchdog
  remains armed until finalization.
- Raw frame count reaches session.max_packets.
- Control receive is anything other than PING, including STOP or peer EOF.
- SIGINT/SIGTERM sets the bounded stop flag.

Every entered capture attempts final counter sampling and CLOSED in finally.
However, the existing approved helper catches OSError from the final send and
can return normally with no delivered CLOSED. Mock tests reproduce a normal
return after a broken-pipe CLOSED send, alongside deadline, frame guard and peer
disconnect. Thus exit=0 alone never establishes capture quality or persistence.
Watchdog, rate failure, counter UNKNOWN and actual drop remain failure paths.

The observed automatic Controller disconnect is compatible with a STOP/EOF
normal return and failed final send. Which control condition the actual helper
observed remains UNKNOWN. The helper was not modified to add a new exit contract.

## 4. Persistence accounting

All seven SQLite files pass integrity_check. Network and base Source Stores each
contain 0 operational sources; both flow/event queues contain 0 events of any
status. Research incidents, receipts, audit entries, checkpoints and traces are
also 0. Collection audit maintenance entries are 0; an empty chain is not proof
of complete capture. The runtime audit has 6 valid chained entries, head digest:
`6008709e248e319f5e9b5abf745de9fc84a819a5c0369c1406548467c24e39b2`.

This managed mode persists **eligible finalized flows**, not every packet.
Delivered=248 means metadata was removed from the transport queue and handed to
the processor; it does not prove 248 persisted packets or 248 accepted samples.
The final successful in-memory aggregate count is not stored. The last periodic
accepted count is 202. Four queued records were explicitly counted by close(),
then released on fail-closed abort. Their contents were not persisted and cannot
be replayed from the counts file. This is not evidence of four failed SQLite
INSERTs. No eligible flow handoff had been committed.

The saved nested network finalization=RUNNING and last_error=null are stale
periodic values. The owning Authentication runtime's top-level STOPPED is a
different state. Neither indicates a successful streaming drain. Original files
remain untouched. The corrected retained view can derive BLOCKED and the error
from a verified abort audit if an older periodic sample lacks terminal fields.

## 5. Independently reproduced implementation defects and fixes

The historical event-time abort and these nonprivileged reproduction findings
are distinct. The normal-close race below raises
STREAM_CAPTURE_COMPLETION_UNVERIFIED, not the historical STREAM_TIME_REVERSED.

- **Terminal state persistence:** failures left the DB's previous RUNNING sample.
  The corrected path persists BLOCKED, causal Last Error, released active state,
  last observed transport/counter metrics, UNKNOWN final counters if no CLOSED,
  and no-retry recovery status. It avoids normal resource publishing when the
  original failure itself is a resource-budget error.
- **Misclassified cleanup:** automatic abort now passes
  CONTROLLER_ABORT:<error>; task exit and clean completion have separate cleanup
  reasons. Existing old reason files are immutable evidence, not rewritten.
- **Delayed STOP:** Stop (drain) now sends its single control request before
  waiting for slow SQLite/observe processing. Reader and channel remain available
  for CLOSED and the already admitted queue. Duplicate Stop sends one request.
- **Empty-receive/CLOSED race:** Reader may enqueue PACKETs and CLOSED after the
  processor returned an empty receive. Controller now drains that finite queue
  before checking completion. A barrier-based test failed deterministically
  before this fix; pending data is not ignored or declared persisted.
- **CLOSED write ordering:** Reader publishes terminal readiness only after the
  evidence file write succeeds. Injected write failure leaves terminal unset,
  produces a blocked outcome and never allows finalization success. This is not
  a new power-loss/fsync durability guarantee.
- **GUI close:** backend close requests the existing bounded graceful stop;
  explicit Abort remains separate. GUI shutdown waits for its backend result.
- **Recovery view:** current failures store terminal fields; older stale views
  are downgraded using the verified lifecycle audit. No model is recalled and no
  historical DB is repaired or approved automatically.

Normal automatic completion sequence:

```mermaid
sequenceDiagram
    participant H as Helper
    participant R as Reader
    participant C as Controller
    participant Q as Flow Queue / Model Worker
    H->>R: Sequenced counter intervals and PACKET metadata
    H->>R: Final counters and CLOSED
    R->>R: Validate counters / capability state; write CLOSED
    R->>C: Terminal available; bounded packet prefix remains
    C->>C: Drain prefix; verify exact sent / delivered / queue counts
    C->>Q: Finalize eligible handoffs; bounded worker drain
    C->>C: Incomplete flows SHUTDOWN; audit / STOPPED / cleanup
```

For Stop (drain), a STOP request precedes this sequence. For event-time reversal,
counter UNKNOWN, drop, source/audit/storage failure or drain timeout, abort and
BLOCKED remain appropriate; invalid inputs are not drained into the model. Missing
CLOSED never becomes VERIFIED merely because the process exited normally.

## 6. Model, investigation and security result

This actual native session has **no Quality or Edge inference receipt**, no
Advisory, no Investigation and no Checkpoint. Quality/Edge native inference is
BLOCKED. Valid runtime audit structure alone does not verify E2E recovery or
recover lost transient inputs. Authentication collection was not started here.

Fixture protocol tests use real ordinary-user Unix sockets with peer/raw-socket
attestation explicitly mocked; native-shaped metadata is not real AF_PACKET
evidence and produces no model receipt in these short-flow tests. Existing
separate RF/LR research tests use actual pinned artifacts on explicit fixtures.
No research output is promoted to an operational finding. RESEARCH_ONLY,
NOT_INFERABLE, OPERATIONAL_INFERENCE_BLOCKED and WRITE_DENIED remain.

Helper SHA remains:
`1cc1c1f39007d1e8f53207dcd5f79f2128b12ea8077d5d09fcb6a72c5d037c84`.
Legacy live helper SHA remains:
`a8a0cafe7494922a0296a250129ab5695b681dbbec6febf512509b023ef44856`.
Neither helper, Producer contract nor model artifact was changed. A fresh Native
session still requires the user's separate execution approval; no command from
the failed session is reusable.

## 7. Tests and independent export

Nonprivileged coverage includes normal CLOSED, synthetic helper deadline/frame
guard, helper exit racing Reader, pending queue drain, slow persistence, empty
receive race, parent disconnect, reader heartbeat timeout, missing CLOSED despite
fresh heartbeats (bounded Stop deadline), counter UNKNOWN, actual drop, duplicate
packet, CLOSED file write failure, SQLite update failure, duplicate Stop, backend
close during drain, worker UNKNOWN/crash/no-retry and recovery/audit validation.

Runs overlap; they are not summed as unique coverage:

| Run | Actual result |
|---|---|
| Original new four-case regression | 2 failed / 2 passed; stale failure state and delayed STOP reproduced |
| Intermediate four cases | 3 passed / 1 failed; exposed normal-close race |
| Deterministic race regression before fix | 1 failed with STREAM_CAPTURE_COMPLETION_UNVERIFIED |
| After race fix, initial five cases | 5 passed, 4.20s |
| Extended shutdown + mocked helper cases | 24 passed, 10.11s |
| Broader workspace live/streaming/research/runtime | 312 passed / 1 failed / 1 skipped, 199.32s |
| Actual WSLg streaming + legacy live GUI | 2 passed, 41.26s |
| Isolated control-send failure | 1 passed, 1.25s |
| Final shutdown lifecycle suite | 15 passed, 15.15s |
| Unchanged clean baseline Authentication timing test | 1 passed, 3.26s |
| Independent export including current shutdown cases and actual WSLg | 317 passed / 1 skipped, 233.81s |

The broad workspace failure is
test_continuous_fixture_lifecycle_dedup_resume_and_read_guard: its 1.5-second
monitor run left one PENDING finding instead of two DONE_READ_ONLY. This test and
Authentication service are not task changes. The same failure was reported in
earlier streaming work; its isolated baseline pass does **not** establish the
cause or a fix. It remains a disclosed intermittent timing regression, not a
silently discarded failure. The skip requires an explicit retained-session opt-in.

Final shutdown suite: **15 passed**. Independent export: **317 passed / 1 skipped**,
including the Authentication timing test that failed in the workspace run. This
later pass does not resolve its intermittent failure or replace that run's result.
All guarded runs reported zero blocked network-socket attempts. SOC Ruff src/tests,
whole-tree format and diff checks pass; the clean export's Ruff/format also pass.
ML was not modified and has no task commit.

The export contains baseline SOC and ML git archives plus only the task files;
Replay, user changes, operational DBs and model binaries are excluded. It uses
explicit trusted artifact/interpreter references and clean exported Producer
source. Packet/IPv4/IPv6 socket creation is guarded; Unix fixtures are permitted.

## 8. Native verdict and next decision

Overall **PARTIAL**, with native AI E2E **BLOCKED**:

- HELPER_EXIT_ZERO: user-reported only.
- READY_VERIFIED: yes; full-session counters remain UNKNOWN.
- CLOSED_MISSING and TRANSPORT_PARTIAL: unchanged historical facts.
- PERSISTENCE_PARTIAL: initialized stores verified; eligible flow commits=0;
  four unprocessed metadata records cannot be recovered from a counts-only file.
- QUALITY_INFERENCE_BLOCKED / EDGE_INFERENCE_BLOCKED: zero receipts.
- AUDIT integrity verified; complete native AUDIT_RECOVERY remains BLOCKED.

Remaining blockers are the underlying event-time reversal (exact fields absent
in the original evidence), a fresh independently approved native CLOSED/drain
qualification, eligible native flows and actual native model receipts. The new
failure context aids future diagnosis without changing time or eligibility.
No new capture is authorized by this report. Do not reinterpret fixture success
as Native success or retry the failed session.

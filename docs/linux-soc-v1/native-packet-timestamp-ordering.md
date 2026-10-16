# Native packet timestamp ordering and streaming stability

## 1. Baseline and Native failure evidence

Validation date: 2026-10-16. SOC baseline
`94c60037e602f4b9a0f8ecc965654c526503d876`; ML baseline
`e1a01260f0463a38d4d778859bc2a86f8e9cfbde`. Both matched main and recorded
origin/main; both indexes were empty. Private inventories hash 122 existing SOC
changes, 10 ML changes, 14 native-session files and 16 model files. None is a
task change. Raw datasets, old reports and artifacts were not rewritten.

Retained session: `session-57b97b62b6124766a211e6c712aac9fd`, protocol UUID
`10f7c294-c6d7-48ea-8695-156fc8ee9f33`. Its files were read without modification;
the monitor SQLite connection used mode=ro and immutable=1 after confirming no
WAL file existed. The hash-chained runtime audit still records STREAM_TIME_REVERSED,
automatic abort and restart-gap, not a user Stop. Its detailed counts and file
hashes remain in [the preceding evidence](native-streaming-stop-drain-evidence.json).

| Historical item | What is actually retained |
|---|---|
| Last accepted packet event timestamp | UNKNOWN |
| Rejected event timestamp / regression magnitude | UNKNOWN / UNKNOWN |
| Failing flow identity / packet direction | UNKNOWN / UNKNOWN |
| Failing helper/controller/reader packet sequence | UNKNOWN individually |
| Transport close diagnostic | Delivered 248, queued 4 |
| Last periodic counter sequence | 418; not the failing packet's recorded window |
| Last periodic kernel frames / drops | 404 / 0; not final totals |
| Gap | Last periodic gap_count=0; later chained abort/restart-gap exists |
| CLOSED | MISSING |
| Source / flow queue / model receipts / investigation | 0 / 0 / 0 / 0 |

There is no packet journal or old time_context to recover the missing fields.
Transport delivered count is not substituted for a missing event sequence.
The directory and protocol UUIDs are generated independently and bind through
session.json and the audited session digest. No historical timestamp is rebuilt
from wall time or a new fixture. **Historical underlying root cause: UNKNOWN.**

## 2. Kernel timestamp contract

PacketCapture enables socket option 35 (SO_TIMESTAMPNS on this target), receives
ancillary timespec values, computes `seconds * 10**9 + nanos` using integers,
and creates UTC datetime using integer seconds plus nanos//1000. The observed
native Python ABI uses 16-byte `@ll`; this work does not qualify 32-bit/time64
portability or change the helper's ABI.

SO_TIMESTAMPNS describes CLOCK_REALTIME receive timestamps, not a monotonic
duration clock. A wall-clock adjustment is therefore a compatible candidate;
it is not proof of what happened in this session. Linux documents the underlying
system-time mechanism as potentially nonmonotonic. No kernel defect or clock
adjustment is inferred from the application exception alone.
[Linux timestamping documentation](https://docs.kernel.org/networking/timestamping.html),
[Linux socket manual](https://man7.org/linux/man-pages/man7/socket.7.html).

Kernel event time remains separate from helper/controller monotonic deadlines,
heartbeat, rate budgets and worker timeout. The old UTC rollback observation
was a different probe, without the failed packets, and supplies no contemporaneous
causal binding. No clock, NTP setting or WSL lifecycle was changed here.

## 3. Conversion and serialization

UTC datetime intentionally contains microseconds; it can represent two distinct
nanosecond events with the same displayed datetime. Native metadata additionally
retains the exact strict integer capture_timestamp_ns. PacketObservation checks
that its truncated UTC representation matches. JSON/Pydantic preserve that integer;
the Reader does not convert it to float. timestamp_ns(), incremental statistics
and the ML Packet input use the integer, not datetime.timestamp() or current UTC.

Mock recvmsg/parse/JSON tests cover epoch second boundaries, 1ns, 999ns, 1000ns
and 999,999,999ns. A 1ns regression inside a single datetime microsecond is rejected.
Float nanoseconds, missing native nanoseconds and mismatched datetime are rejected.
No precision defect was observed in these tested paths. Actual failed ancillary
records are absent, so this is contract/fixture evidence, not an original-kernel
packet measurement or a universal conversion proof.

Diagnostic FlowSummary UTC start/end and duration_seconds remain based on the
microsecond datetime representation. Sub-microsecond spans can therefore appear
as zero in that diagnostic summary. They are not substituted for the Network14
duration/IAT, which come from exact packet ns. This existing representation
boundary is documented, not silently changed or claimed to have nanosecond
precision; it does not explain the integer comparison rejection.

## 4. Transport, Reader and loopback ordering

The helper sends sequential PACKET records through one Unix SOCK_SEQPACKET
connection. That transport preserves message boundaries and send order.
[Linux Unix-domain socket manual](https://man7.org/linux/man-pages/man7/unix.7.html).
The single Reader validates helper sequence before its bounded FIFO; queue and
counter-seal updates use the same lock, and receive checks delivered sequence
against the seal. Normal Unix fixture delivery preserves order; explicit wire
sequence corruption and Reader queue/seal corruption fail closed with different
errors. They are deliberately injected faults, not evidence of normal reordering.

Loopback OUTBOUND filtering selects a subsequence in original receive order.
It cannot sort two selected timestamps. A mocked helper receiving outbound/inbound
clones at 2s then 1s sends sequence 1 then 2 with timestamps 2s then 1s. The
Controller rejects that event-time regression even though transport sequence is
correct. Inbound clones are not forwarded; identical outbound content is not
silently deduplicated, since legitimate repeated packets affect model features.

## 5. Cause classification

| Candidate | Current evidence / decision |
|---|---|
| KERNEL_TIMESTAMP_REGRESSION | UNKNOWN for historical input; original ns values missing |
| UTC_CLOCK_ADJUSTMENT | Mechanism compatible with CLOCK_REALTIME; no contemporaneous proof |
| TIMESTAMP_CONVERSION_DEFECT | Not observed in tested integer/UTC/JSON paths; lossy inputs rejected |
| TRANSPORT_REORDERING | Not observed normally; injected sequence fault rejected |
| READER_QUEUE_REORDERING | Not observed normally; FIFO/seal checks and corruption rejection verified |
| LOOPBACK_DIRECTION_DUPLICATION | Filtering behavior verified in mock; historical clones unavailable |
| FLOW_EVENT_TIME_MISMATCH | Rejection code retained; historical GLOBAL versus FLOW scope absent |
| UNKNOWN | Retained underlying incident classification |

No candidate is promoted solely because a fixture can reproduce its failure.
Global event-time ordering remains enforced: cross-flow regression is not newly
accepted just because individual flows might be ordered. Timeout eviction relies
on that event-time progression. Equal timestamps remain distinct packets with
unique identities; strictly lower timestamps remain errors of every tested size.

## 6. Reordering buffer decision

**No buffer added.** There is no evidence that normal transport/Reader order is
wrong, and no measured displacement distribution from which to derive a window.
An arbitrary window would hide kernel-time regression, alter first-seen direction,
flow timeouts or source/feature binding. No clamp, wall-time substitution,
timestamp correction, sorting, counter relaxation or silent drop is introduced.

## 7. Minimal diagnostic changes

- PacketTimeReversed preserves the existing ValueError code STREAM_TIME_REVERSED
  while carrying the exact failing comparison and GLOBAL/FLOW scope. It changes
  no accepted timestamp, feature calculation, timeout or Producer contract.
- Error audit/persisted metrics add previous/rejected ns, positive regression_ns,
  packet/helper/counter sequences, ordering scope, timestamp/source origins,
  direction and a hash of the bidirectional flow key. Root cause remains UNKNOWN.
  The key hash is not a newly finalized model-flow identity. Addresses, payloads
  and DNS names are not added to the diagnostic.
  Packet sequence means the last attempted Controller input, including a rejected
  packet; it is separate from the accepted packets_collected count.
- Timestamp status starts UNKNOWN, becomes ORDERED_PREFIX_ONLY for accepted
  metadata, and FAILED_EVENT_TIME_ORDER on rejection. Prefix status never implies
  verified future packets or a complete/gap-free kernel capture.
- GUI displays backend timestamp integrity, packet sequence and abort reason.
  Missing fields remain UNKNOWN. ERROR does not remain LIVE. Legacy abort recovery
  can report failed ordering from the verified audit but does not invent the absent
  timestamps, sequence or context. Original native files remain immutable.

Audit verification means local chain/digest consistency, not an external digital
signature, tamper-proof storage or recovery of packets absent from the ledger.

No helper or capture/parsing code changed. Diagnostics are bounded per-session
scalars and one abort context; no new retention queue or packet recorder exists.

## 8. Producer parity and sorted-input comparison

Network Producer 1.1.0, all 14 names/order, float32 conversion and configuration
digest remain unchanged. Existing arithmetic and cross-origin reference tests
run alongside new integer-nanosecond references. For three packets at t, t+1ns,
t+2ns the independent duration is float32(2e-9), mean/max IAT float32(1e-9).
Both incremental and unchanged batch Producer match. Existing hand reference
40/60/80 IP bytes, F/B/F, 0/0.5/1 seconds also matches every feature.

Raw decreasing input is rejected by both aggregation and Producer. It has **no
approved raw feature vector** to compare. A hypothetical sorted arithmetic input
can be evaluated separately but is not fed to the model as a repaired native flow.
For equal-time packets, swapping first-seen direction changes forward/backward
counts and bytes (2/1,120/60 becomes 1/2,60/120) and source binding. Equal-time
events must not be deduplicated or arbitrarily permuted. Feature/source digests
bind origin and identity; vector parity across origins does not imply equal
digests or captured-source attestation. NaN/Inf, gap and eligibility gates remain.

## 9. Actual research model Fixture and investigation

[Current actual-model evidence](native-packet-timestamp-fixture-evidence.json):
run `7c21d723-5a87-42da-b694-88cfda07eb75`, explicit synthetic FIXTURE input,
4 packets, 1 eligible timeout flow, 1 SHUTDOWN exclusion, queue DONE=1,
2 actual worker receipts, 2 READ-only investigations and checkpoint restoration.
Transient inputs and active metadata are released; reopen makes 0 new inferences.
This is not historical Native execution, PCAP acquisition or new model training.

| Model | Artifact SHA256 | Fixture result |
|---|---|---|
| Quality RF | 53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603 | CLASS_0, score 0.140625, threshold 0.35 |
| Edge LR | 661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882 | CLASS_0, score 0.08766025304794312, threshold 0.8 |

Scores are uncalibrated research output. Both feature digests for this bound
fixture flow are `3eed32bde52cc7ecc0cf02db2d9db217364d466a225bff63143dff954ad1c973`.
Audit digest: `f994a7844bfdecde11e5bb65a522a2c5cfef0ee3ae1a9f2c80ba69d112044228`.
Receipt/provenance/investigation bindings and worker resource measurements are in
the evidence JSON. No operational Finding or security WRITE was generated.

## 10. Stability and GUI

Scoped regression covers event-time IDLE 30s / ACTIVE 120s, SHUTDOWN exclusion,
Reader delay, queue overflow/backpressure, counters/drop, worker crash/restart,
Stop/drain, CLOSED races, duplicate prevention and audit recovery. Packet-free
idle time does not invent an event watermark. No timeout contract changed.

The prior real-time 1,800.978905-second fixture soak result remains present
(SHA256 `b8d958c2254ce5780b9dc4127552162c9cf6b0254910cb227752e4879caff2df`):
3,679 synthetic packets, 50 eligible handoffs, one mock UNKNOWN/circuit-open call,
zero actual model inferences. This is prior evidence, not a 30-minute run of the
new diagnostics. Since only error observability/GUI fields changed, no new long
soak was claimed; resource qualification of real native collection stays pending.

Actual WSLg tests verify the normal Fixture model results and 1920/1366/1280 layouts,
then a separate fixture timestamp failure: ERROR, failed timestamp status,
packet sequence 2, STREAM_TIME_REVERSED abort, audit VERIFIED, no LIVE and zero
inference. GUI values come from backend metrics; no fake Live data is plotted.

An expanded export exposed a separate existing preparation-state race: an older
STOPPED poll could enable Start while preparation awaited I/O; READY updated text
without restoring the disabled button, and prepare_active ignored the interval
before task creation. Two deterministic regressions failed before the fix.
READY now disables Start, and preparation is reported active before the task
exists. This changes GUI state accuracy, not timestamp acceptance or capture
authority. The subsequent targeted run passed both regressions and WSLg tests.

## 11. Tests, quality and export

Run counts overlap and must not be summed:

| Run | Actual result |
|---|---|
| Initial new arithmetic fixtures | 12 passed / 3 failed; test DNS/source-identity setup violated existing validators |
| Intermediate arithmetic fixtures | 13 passed / 2 failed; remaining test source identities were corrected |
| Corrected arithmetic fixture suite | 15 passed, 0.37s |
| Expanded arithmetic/schema suite | 18 passed, 0.42s |
| Unix protocol/context fixtures | 7 passed, 4.47s |
| Capture/streaming/parity targeted regression | 225 passed, 62.88s (before 3 additional schema cases) |
| Actual WSLg streaming GUI | 2 passed, 27.66s |
| Standalone actual RF/LR Fixture evidence | 2 real receipts / 2 READ-only investigations; restored without replay |
| First expanded independent export | 428 passed / 1 failed / 1 skipped, 223.65s; GUI preparation-state assertion |
| Deterministic GUI preparation regressions before fix | 2 failed; missing READY button update and prepare_active flag |
| After GUI preparation fix: unit regressions + actual WSLg | 4 passed, 27.43s |
| Final independent export, including WSLg and Runtime | 431 passed / 1 skipped, 241.48s |

The new test setups were corrected to use the existing DNS-header stripping and
valid synthetic source-identity contracts; no product validator was weakened.
The known intermittent Authentication 1.5-second lifecycle assertion is distinct
from timestamp-ordering tests. A later pass cannot establish that its cause is
fixed; this task changes neither its service nor its time budget.

Final independent export: **431 passed / 1 skipped**, with zero blocked network
socket attempts. The skip requires explicit read-only retained-session opt-in.
SOC Ruff src/tests, whole-tree format and diff checks pass. Export Ruff/format
also pass. The Authentication timing test passed in this run; its earlier
intermittent failure is not claimed resolved. No ML task change or commit exists.

Export uses
baseline git archives of both repositories plus only task files, with clean ML
Producer source and explicit trusted external interpreter/artifact references.
No Replay, user changes, native DB or model binary is included. Tests deny new
AF_PACKET/IPv4/IPv6 sockets while allowing ordinary-user Unix fixtures. Runtime
timestamps/invocation IDs are not compared as identical across separate runs.

## 12. Security, verdict and next approval scope

RESEARCH_ONLY / NOT_INFERABLE / WRITE_DENIED / OPERATIONAL_PROMOTION_BLOCKED
remain. No root GUI, password storage, permanent capability, new capture, test
traffic, automatic privileged execution, raw-payload retention or model change
was introduced. Negative protocol and timestamp cases remain fail-closed.

Overall **PARTIAL**:

- TIMESTAMP_ROOT_CAUSE_UNKNOWN and KERNEL_TIMESTAMP_UNKNOWN for historical failure.
- TRANSPORT_ORDERING_VERIFIED / READER_ORDERING_VERIFIED for scoped Unix fixtures.
- NETWORK14_PARITY_VERIFIED for unchanged arithmetic/contract references.
- STREAMING_STABILITY_VERIFIED for scoped fixtures; Native stability still pending.
- QUALITY_FIXTURE_INFERENCE_VERIFIED / EDGE_FIXTURE_INFERENCE_VERIFIED.
- AUDIT_RECOVERY_VERIFIED for Fixture; historical Native end-to-end remains blocked.
- NATIVE_CONTINUOUS_E2E_PENDING; OPERATIONAL_PROMOTION_BLOCKED.

No new helper was created. Current unchanged streaming helper SHA256:
`1cc1c1f39007d1e8f53207dcd5f79f2128b12ea8077d5d09fcb6a72c5d037c84`.
The previous session approval is not reused for a fresh execution.

Proposed **separate user approval**: one new lo-only session, max 300s, token refill
128 raw frames/s plus 256 burst, max 38,656 frames, dedicated temporary CAP_NET_RAW,
ordinary UID/GID and immediate capability removal, metadata-only retention,
bounded workers, no operational promotion or OS security WRITE. No new traffic
generator is included. After approval, launch the normal-user GUI with
`.venv/bin/python -m soc_agent.gui`, create Streaming Monitoring, review the new
policy/session digest and helper SHA, and execute only that newly generated
command in the user's own authenticated terminal. Never reuse the failed session.
If ordering fails again, preserve the new time_context/Audit alongside READY,
counter sequence, CLOSED/transport disposition, receipts and finalization.
Codex has not run any privileged command or Capture. No Native success is claimed.

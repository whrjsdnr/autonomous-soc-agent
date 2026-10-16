# Native streaming rate budget failure analysis

## Baseline and scope

Validation date: 2026-10-16. SOC baseline/main/origin/main:
`f264d0892730f475e36493656e29912ff53e823d`. ML:
`e1a01260f0463a38d4d778859bc2a86f8e9cfbde`. Both indexes were empty.
Private pre-edit inventories hash 122 existing SOC files, 10 ML files,
14 failed-session files and 16 Network research artifact/package files.
Existing user changes and Reliability Replay are excluded from this change.

No privileged command, AF_PACKET capture, test traffic, clock adjustment,
model training, artifact replacement or operational promotion was performed.
Native evidence was opened read-only; SQLite used mode=ro, immutable=1 with
no WAL files present. The actual failed session was not restored or rewritten.

## Failure evidence

Directory identity: `session-f90447e9c934464492bdc8aa206ac9c6`.
Protocol session: `f093632d-48bf-4b54-b738-63acd4ffee8f`.
Audited/session.json digest:
`694c2dee45f09a46c62cc3c40e5b5c62af8a5bd48331ed7f25dbed0b13f0f6d4`.
Its pinned seven-file helper bundle matches the current unchanged files.
Helper exit=1 and the STREAM_RATE_BUDGET_EXCEEDED traceback are **user-reported**;
there is no separately retained exit-status record or terminal traceback file.

| Item | Retained evidence / limit of interpretation |
|---|---|
| READY | Verified, counter sequence 1, kernel total 2, drops 0 |
| Initial tokens | 256 by pinned RateBudget code; no runtime token snapshot |
| Initial/last refill monotonic time | UNKNOWN; not persisted |
| Error-time token balance / previous-consume delta | UNKNOWN; not persisted |
| Raw frames / metadata packets | Last persisted usage 374 / 187 |
| Successful token consumes | 373 inferred **if** the reported exception was raised on raw frame 374; not an independently logged count |
| Actual burst interval / frame count | UNKNOWN / UNKNOWN; no per-consume monotonic trace |
| Last accepted counter | Sequence 375; kernel cumulative 376; drops 0; counter_issue=null |
| Final CLOSED receipt | verified-closed.json MISSING; rejected wire body not retained |
| Transport | 561 records read, 187 delivered, 0 queued, high-water 19/512, unadmitted 0 |
| Transport error | HELPER_UNCLEAN_SHUTDOWN |
| Timestamp integrity | ORDERED_PREFIX_ONLY, attempted packet sequence 187; no timestamp abort |
| Finalization / collection | BLOCKED / ERROR; gap_count=1 |
| Final counter status | UNKNOWN for session completion; last accepted interval remains COUNTER_VERIFIED |
| Source rows / flow queue / finalized flows | 0 / 0 / 0 |
| Quality / Edge receipts / investigation | 0 / 0 / 0 |

READY's kernel total 2 is the first reset interval, not the failing capture's
volume. The later total 376 also differs from consumed raw frames: kernel queue
accounting is not the token bucket's receive counter. No missing value is filled
with zero. The retained capture_uptime_seconds=0.015753937001136364 is a stale
periodic Controller observation, **not** the Helper's final elapsed time. The
READY-to-abort UTC audit span is approximately 0.905066 seconds; it is neither
a monotonic capture duration nor a timestamped burst window. Neither value is
used to declare ACTUAL_BURST_CONFIRMED or to size a larger allowance.

All seven SQLite integrity checks return `ok`. Runtime state digest is valid.
The six-entry audit chain (INITIALIZED, NETWORK_CONFIGURED, STREAM_STARTED,
STREAM_HELPER_READY, STREAM_ABORTED, STREAM_RESTART_GAP) verifies through:
`5f4b9866108055bee7503a9e025f3882acc7b15e603ba90f1b3e67f173fd0270`.
The abort records HELPER_UNCLEAN_SHUTDOWN and automatic_retry=false.

Transport-delivered metadata is not a durable packet journal. Flow-based Source
and Queue handoff happens at eligible finalization; this abort released the
in-memory active state with an explicit gap before that handoff. There is no
evidence of successful model input or inference to recover from these 187 packets.

## Rate limiter contract and expected behavior

The unchanged bucket starts full (256) at time.monotonic(), before connect/open.
Every non-None raw capture receive increments received_frames and calls consume
**before** parsing or OUTBOUND filtering. Inbound loopback clones, non-IP frames
and frames that yield no forwarded metadata still consume this budget.
Metadata packet rate and raw receive rate must not be equated.

For each consume at monotonic time t:

```text
if t < previous: reject STREAM_MONOTONIC_CLOCK_REVERSED
tokens = min(256, tokens + (t - previous) * 128)
previous = t
if tokens < 1: reject STREAM_RATE_BUDGET_EXCEEDED
tokens -= 1
```

Fractional tokens survive; equal times add no credit. Frame 256 at an unchanged
clock is accepted; frame 257 is rejected. A long receiver pause refills to 256,
never an unbounded accumulated allowance. This is a token bucket, not a hard
128-packets-in-every-one-second-window rule. Backpressure can cause queued kernel
frames to be consumed rapidly later; no such scheduling trace survives here.
The separate total frame guard is 300*128+256=38,656. The finite deadline and
total guard do not make a burst overrun acceptable. A rejected consume does not
forward its packet. The Helper re-raises the error (exit 1) without retry.

Independent Fraction.from_float arithmetic in tests uses the exact observed
float clock inputs, not a second call to RateBudget. It agrees for sustained
128/129/256/1000 FPS, including monotonic values around 3,090,000 seconds,
the first rejection and a 300-second maximum-envelope example. These bounded
tests found no arithmetic defect. They do not recover the native clock inputs
or prove correctness for every possible float/input/environment.

## CLOSED delivery and confirmed diagnostic defect

The approved Helper already catches the rate exception, samples its last reset
interval before socket close and attempts CLOSED with the explicit error,
received_frames, sent_packets and elapsed_seconds, then propagates the exception.
Mock tests exercise both a forced rate error and exhaustion of the real bucket
by 257 raw inbound frames without any forwarded PACKET.

In the baseline receiver, HELPER_UNCLEAN_SHUTDOWN is emitted by the CLOSED
error/capability rejection branch, **after** counter acceptance and usage update.
The saved marker, sequence and usage therefore support CLOSED reception and
rejection, rather than concluding that no CLOSED was sent merely because the
success file is absent. The original error string, elapsed_seconds and capability
comparison were discarded. The wire body is unavailable, so the stored evidence
cannot independently distinguish rate error from another unrecognized Helper
error or capability mismatch. User-reported traceback supplies the rate-error
observation separately. Counter verification is not successful session completion.

Confirmed implementation defect: a known rate error loses its identity and the
rejected CLOSED details are not retained. Actual native burst and a native
token-calculation defect remain UNKNOWN; no limit or arithmetic change is justified.

## Minimal fix

- `helper_transport.py`: fixed allowlist preserves known Helper error codes.
  Capability mismatch still yields an unclean shutdown. Unrecognized error text
  is not copied into public diagnostics. Counter validation keeps precedence over
  Helper-reported rate errors; UNKNOWN, drops and sequence corruption still reject.
- A bounded private `rejected-closed.json` records session/counter identity,
  raw/metadata counts, elapsed time, CPU/RSS, capability-match boolean and rejection
  reason. It excludes packet data, command lines, credentials and addresses.
  completion_verified=false is explicit. No terminal or verified-closed.json is
  published for this failure. Diagnostic write failure also fails closed.
- `stream_service.py`: Abort Audit binds the diagnostic's canonical JSON digest;
  persisted metrics also retain that digest. The existing Last Error path exposes
  STREAM_RATE_BUDGET_EXCEEDED to the GUI and restart recovery without UI changes.
  No previously failed native session is modified or reclassified.

New diagnostics preserve future rejected CLOSED evidence but do **not** add
per-consume token telemetry to the approved Helper. Exact native token balance,
last refill and burst window therefore remain unavailable. Instrumenting those
would require a separate Helper/bundle change and fresh user approval; this work
does not pretend that Controller counters can reconstruct them.

## Security boundaries and approval

Both Helper code and all seven pinned dependencies are unchanged. SHA256:

```text
stream_helper.py
1cc1c1f39007d1e8f53207dcd5f79f2128b12ea8077d5d09fcb6a72c5d037c84
stream_session.py
3763da1ce40af8bc713562826c984334e64950dcaa9dbac53ba8517c3f21f0de
```

No new Helper SHA is issued. No reapproval is required for changed privileged
code because none was changed; a **new native run** still awaits separate user
authorization. Existing failed session commands must not be reused. Proposed
scope stays lo, <=300 seconds, 128 raw frames/s, burst 256, <=38,656 frames,
temporary CAP_NET_RAW with post-open capability drop, metadata only and no retry.
Only the user may perform the approved terminal authentication/execution after
preparing a new listener/session. No rate/burst/frame/deadline increase is proposed.

For a separately approved manual validation, reopen the GUI with
`.venv/bin/python -m soc_agent.gui`, prepare a fresh Streaming Network session,
verify its helper SHA/bundle and the unchanged policy, and use only that session's
displayed command. The agent does not execute that command. If another rate abort
occurs, retain rejected-closed.json, transport-failure.json and the runtime audit;
do not retry or treat the rejected receipt as a clean finalization. An exact burst
diagnosis still needs separately reviewed Helper token telemetry, not repeated
uninstrumented captures.

RESEARCH_ONLY, NOT_INFERABLE, OPERATIONAL_INFERENCE_BLOCKED and WRITE_DENIED
remain enforced. Counter UNKNOWN, drops, timestamp regression and unclean CLOSED
cannot authorize inference. Neither SHUTDOWN nor unfinished flows are promoted.

## Test results and independent export

Results are recorded per invocation, not summed. No native capture was used.

| Invocation | Result | Elapsed |
|---|---|---|
| New tests against baseline | 6 passed, 4 failed: reproduced lost error/evidence | 3.32 s |
| First diagnostic patch | 7 passed, 3 failed: counter-failure CLOSED recording still absent | 3.45 s |
| Corrected focused tests | 10 passed | 3.27 s |
| Expanded counter/helper checks | 65 passed, 1 failed: diagnostic dereferenced absent READY in isolated receiver fixture | 6.17 s |
| Corrected expanded checks | 66 passed | 5.98 s |
| Final helper/rate diagnostic supplement | 20 passed | 6.99 s |
| Working-tree regression | 444 passed, 1 skipped | 271.62 s |
| Independent export, final six files | 445 passed, 1 skipped | 253.05 s |

The transient implementation failures were corrected, not counted as successful
validation. The isolated no-READY diagnostic now records capabilities_match=false.
The final supplement adds a real-bucket raw-burst Mock case after the working-tree
regression's collection; the independent export includes that additional case.

Regression groups: unit/network_capture, unit/streaming_network,
integration/streaming_network, unit/live_network, integration/live_network,
integration/research_adapter, integration/linux_runtime, gui_streaming_checks.py
and gui_live_network_checks.py. The skip requires explicit retained-session opt-in;
it is not a successful native replay. Rate/counter error precedence, rejected CLOSED,
diagnostic write failure, capability mismatch, unknown error sanitization,
Abort Audit digest, restart without inference, real Unix FIFO/backpressure,
deadline/stop/drain, timestamp rejection and actual Quality/Edge Fixture workers
are covered. Existing WSLg checks prepare ordinary-user listeners, run explicit
model Fixtures and reopen retained results; no privileged Helper is executed.
All these test invocations report zero network socket attempts blocked by the
AF_PACKET/IPv4/IPv6 guard. Unix test sockets are permitted.

Working-tree Ruff check passes; format check passes (999 files); git diff --check
passes. No ML files were changed or reformatted. Independent-export Ruff and
format pass (955 files; user files excluded).

The export consists of clean git archives of the recorded SOC and ML HEADs plus
only this report, helper_transport.py, stream_service.py, test_rate_budget.py,
test_rate_failure.py and test_helper.py. All five source/test hashes match the
tested export; the final report is copied and compared after recording results.
External Artifact/interpreter references retain their verified local locations;
model binaries, native databases, raw datasets, user changes and Replay are not
copied. Producer source is the clean ML export. The final export includes actual
Quality/Edge Fixture inference, read-only investigation, audit/recovery, GUI and
failure-path regressions. No assertion depends on the missing native token trace.

Final preservation checks retain every baseline user-file SHA, all 14 native file
SHAs, all 16 Network package SHAs and both helper bundle identities. Only these
six task files are eligible for staging. No ML commit is necessary.

No new long soak is claimed. Changes affect rejection diagnostics/error handling
and add one metrics/audit digest; capture pacing, clocks, Flow14 calculations and
worker lifecycle are unchanged. The preceding 30-minute Fixture evidence remains
historical evidence, not a new performance or native-capture qualification.

Quality RF artifact SHA256 remains
`53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603`;
Edge scaler/LR remains
`661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882`.

## Verdict and remaining blockers

- RATE_BUDGET_EXCEEDED: user traceback; current stored audit has only generic error.
- ACTUAL_BURST_UNKNOWN: consume timestamps/token trajectory absent.
- TOKEN_BUCKET_DEFECT_UNKNOWN: no arithmetic discrepancy in tested fixtures.
- DIAGNOSTIC_DEFECT_CONFIRMED: error identity and rejected CLOSED evidence loss.
- CAPTURE_COUNTER_STATUS: last accepted prefix COUNTER_VERIFIED/drop 0;
  successful final CLOSED/completion UNKNOWN.
- NATIVE_E2E_BLOCKED: no finalized eligible flow, actual model receipt or investigation.
- NEXT_APPROVAL_REQUIRED: a separately authorized fresh native session only;
  no automatic capture, retry or relaxation. Overall result **PARTIAL**.

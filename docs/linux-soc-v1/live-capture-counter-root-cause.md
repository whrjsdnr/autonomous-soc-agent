# AF_PACKET statistics assessment and Live Helper v2

Date: 2026-10-16. SOC HEAD: `df96d37d951e0fdf3ba047768aa024dbf353052a`.
ML HEAD: `e1a01260f0463a38d4d778859bc2a86f8e9cfbde` (unchanged).

**Historical failure: ROOT_CAUSE_UNKNOWN.** Confirmed **IMPLEMENTATION_DEFECT** in
error classification/evidence retention is corrected and tested. Normal,
unavailable, and dropped counters are verified only with mocks/fixtures here.
No privileged helper execution, real AF_PACKET capture, network test traffic,
model promotion, or OS security WRITE was performed.

## Confirmed facts and limits

The approved old helper combined `statistics() is None` and nonzero drops into
`HELPER_CAPTURE_DROP_OR_COUNTER_UNKNOWN`. `PacketCapture.statistics()` returned
None for an unopened socket, OSError, or a short reply without recording which
condition occurred. The helper subsequently sent only the exception class
(`ValueError`) in CLOSED; the receiver rejected it as
`HELPER_UNCLEAN_SHUTDOWN`, without a successful terminal receipt.

Read-only examination of the retained failed session found READY `(0, 0)` and a
Runtime state with 388 kernel packets, 42 collected metadata packets, Drop UNKNOWN,
Gap 2, and `HELPER_UNCLEAN_SHUTDOWN`. The failing interval/errno/buffer length is
not retained. Therefore neither actual kernel drops nor counter unavailability
can be established as the historical cause. Gap 2 is not a measured kernel drop
count. Kernel socket counts and filtered/parsed metadata counts measure different
things; subtracting 42 from 388 does not establish 346 dropped packets.

These user-produced files were only read and hashed. Existing receipts, DBs,
datasets, models, Replay changes, stages, and earlier reports were preserved.

## Kernel contract and cause separation

Linux documents PACKET_STATISTICS as two unsigned 32-bit counters, reset when
read; TPACKET_V3 has a different structure. See [packet(7)](https://man7.org/linux/man-pages/man7/packet.7.html).
The inspected [Linux packet_getsockopt implementation](https://github.com/torvalds/linux/blob/master/net/packet/af_packet.c)
clears statistics and exchanges the drop counter, returns 8 bytes for ordinary
sockets or 12 for V3, and limits the response to the requested buffer size.
These sources establish the API contract, not a new test of this WSL kernel.

The old 12-byte request already accepted an 8-byte reply (`len >= 8`), so the
request length is not an established cause. No additional capability check is
present in the inspected PACKET_STATISTICS branch; capability removal alone is
not evidence of a statistics permission failure.

| Condition | Evidence/result |
| --- | --- |
| Socket not open | `SOCKET_NOT_OPEN`, counters None |
| Query OSError | Sanitized `GETSOCKOPT_FAILED_ERRNO_<number/UNKNOWN>`; no exception text |
| Invalid reply length | `INVALID_STATISTICS_LENGTH`; only 8/12-byte layouts accepted |
| Nonzero kernel drops | Explicit `HELPER_CAPTURE_DROPS_DETECTED` |
| Later zero after reset | Only the latest interval; does not erase earlier loss/UNKNOWN |
| Closed socket | EBADF if descriptor closed externally; SOCKET_NOT_OPEN after normal close |
| Slow helper / transport pressure | Possible contributor to loss; historical causality unproven |
| Transport send timeout | `HELPER_TRANSPORT_TIMEOUT`, no retry, cleanup; missing delivered interval rejected |

No batching, receive-buffer enlargement, cadence tuning, or performance
optimization was applied. Real loss/performance must first be measured separately.

## v2 counter contract and fail-closed changes

`PacketCapture.statistics()` preserves its public `(packets, drops) | None` API.
It adds sanitized diagnostic state and rejects malformed lengths.

The helper has one statistics reader, `CaptureCounters`, used for READY, each
HEARTBEAT, and the final CLOSED sample **before socket close**. Each sample carries:

- `counter_sequence`, beginning at 1; bounded by the receiver.
- `kernel_packets` / `capture_drops`: reset-on-read interval deltas.
- `kernel_packets_total` / `capture_drops_total`: sums of known intervals, not
  previously accumulated totals added a second time.
- `counter_status`: COUNTER_VERIFIED, COUNTER_UNAVAILABLE, or CAPTURE_DROPS_DETECTED.
- `counter_detail`: sanitized fixed code/errno; no raw error text or payload.

A missing/invalid interval permanently invalidates complete cumulative counts:
those totals remain None even if a later query succeeds. Observed drops remain
sticky across subsequent zero intervals. Invalid counter values fail closed.
Valid zero-packet intervals remain distinguishable from UNKNOWN.

Quality messages can report failure, but packet metadata is transmitted only
after that interval's counters pass. HEARTBEAT precedes its packet. This is a
validation ordering correction, not a throughput optimization. Initial READY
with bad counters is rejected by the controller before verified capture readiness.

The receiver checks consecutive sample numbers and exact cumulative arithmetic.
Duplicate, missing, or inconsistent intervals produce
`HELPER_CAPTURE_COUNTER_INTEGRITY_FAILED`. Old messages lacking v2 evidence are
not silently accepted. Its existing `statistics()` method returns each accepted
delta once, then zero new deltas while the heartbeat is still fresh. A stale
heartbeat or sticky counter fault raises; it does not return a current zero.

Authenticated counter failures are stored as private `counter-failure.json`,
separately from successful verified-ready/verified-closed receipts. The GUI's
Last Error receives the counter category. Native-source authorization rejects
sticky counter faults before research inference. Research-only, NOT_INFERABLE,
OPERATIONAL_INFERENCE_BLOCKED and WRITE_DENIED remain enforced.

The watchdog is disabled when entering cleanup, and the final counter query runs
while the socket is still open. Stop/watchdog/timeout cases close mock capture and
transport resources. A failure discovered only by the final sample causes a
non-success helper exit after sending the failed CLOSED record. No automatic retry.

## Changed files

Relative to the starting worktree, only:

- `src/soc_agent/security_ai/operational/network_capture/capture.py`
- `src/soc_agent/security_ai/operational/network_capture/live_helper.py`
- `src/soc_agent/security_ai/operational/network_capture/helper_transport.py`
- `src/soc_agent/security_ai/research/live_service.py`
- `tests/unit/live_network/test_counters.py` (new)
- `tests/unit/live_network/test_listener.py` (v2 READY fixture fields)
- This report.

Producer features, model artifacts, privilege checks/capability drop,
interface allowlist and 60-second/512-frame bounds were not changed.

## Test results

Each row is a separate invocation; counts are not combined across overlapping runs.

| Final invocation | Result |
| --- | --- |
| Live Network unit/integration + network capture unit | **169 passed**, 22.78 s |
| GUI unit/integration + Research Adapter unit/integration + Linux Runtime integration | **154 passed**, 67.46 s |
| Actual WSLg GUI prepare/stop/navigation/recovery, no capture | **1 passed**, 12.74 s |
| Dependency-inclusive independent export: Live/Network Capture suite | **169 passed**, 22.50 s |
| Ruff `check src tests` | PASS |
| Ruff `format --check .` | PASS, 942 files (final check) |
| `git diff --check` | PASS |

The new counter module contains 41 cases: layout/short buffers, OSError, closed
socket, zero packets, reset arithmetic, sticky UNKNOWN/drop, invalid values,
READY/HEARTBEAT/CLOSED failure classification, mock helper send ordering,
Stop/watchdog, send backpressure, missing/duplicate intervals, receiver accounting,
private failure receipt, stale heartbeat, and inference authorization denial.
All actual socket/capability/signal/resource-limit effects in helper-control-flow
tests are replaced with mocks. The positive helper flow is not a real helper run.
Existing artifact inference regressions use explicit fixture inputs, not live data.

All guarded final invocations reported **0 AF_PACKET/AF_INET/AF_INET6 socket
creation attempts**, with no actual capture or traffic. The wrapper is
`python -m tests.native_capture_verification_guard --import-mode=importlib -q ...`.
It invokes pytest and rejects these socket families; ordinary AF_UNIX fixtures
remain permitted.

Earlier test-development failures are not counted as passes: 7 new mock cases
initially used inconsistent microsecond/nanosecond timestamps and were corrected;
a later single failure expected the wrong existing authorization error string.
Final reruns above passed. No failed check was ignored.

## Independent export and Git

Strict **HEAD + only this task's changed files** failed collection because
`live_session.py` is absent from HEAD. Other uncommitted prerequisites include
`live_input.py`, Live GUI/controller/worker changes, and the previous listener fix.

A separate export of HEAD plus the previously recorded Live Network/listener
allowlists and this fix (30 overlay files before this report) passed 169 tests.
It excluded Reliability Replay and unrelated user changes. Trusted local research
artifacts/interpreter were explicitly referenced read-only, not copied or replaced.
This isolates the code from Replay but does not make a counter-only commit
independent of the missing Live feature baseline.

Accordingly **Stage/Commit/Push were not performed**. The initial index remains
unchanged. Required next Git step: separately review/commit the Live Network and
listener prerequisites, or explicitly authorize a combined reviewed scope, then
repeat strict export validation. No raw dataset, model binary, runtime DB, or
private diagnostic log was staged.

Final SHA comparison confirmed preservation of 143 pre-existing unrelated
worktree files and 25 retained session files; the index and HEAD were unchanged.

## Helper identities and required reapproval

Old approved helper SHA256:

```text
9699cd29f14851287d03e8883ddc765c95a89e9e8169281b4be0b949bff4d87d
```

**New Helper v2 SHA256**:

```text
a8a0cafe7494922a0296a250129ab5695b681dbbec6febf512509b023ef44856
```

Changed `capture.py` SHA256:

```text
c15ad82c1c8ca7dfc4433d81d2e6f4c6c5aebfe52e9cad395bd82f3b907c1245
```

The session manifest pins the helper/capture source bundle. Old sessions retain
their old identities and must not be reused with this code. Their original files
are preserved; historical verification requires their matching pinned source.
No real execution is authorized by the old helper SHA after this change.

Before real execution, obtain explicit approval for the new SHA/source bundle:
user execution only, `lo`, at most 60 seconds/512 frames, temporary CAP_NET_RAW in
the separate helper, same UID/GID, immediate capability drop, no persistent file
capabilities/configuration changes, no payload retention, no operational promotion.

After approval, the user should:

1. Verify the new helper SHA with `sha256sum` at its existing source path.
2. Restart the GUI with `.venv/bin/python -m soc_agent.gui` as the normal user.
3. Prepare a **new** Live Network session and confirm LISTENER READY. Copy the
   newly generated, reviewed command; never use a retained old-session command.
4. Authenticate and execute that command **personally in the terminal**, with
   the GUI kept open. The agent must not collect a password or execute it.
5. Stop with Ctrl+C or Stop live; preserve that session's READY/CLOSED or
   `counter-failure.json`, stderr category, and Runtime state for read-only review.

This report does not authorize an interface/time/frame scope expansion or
unbounded retries. No new actual capture command has been executed by Codex.

## Final assessment and remaining blocker

| State | Assessment |
| --- | --- |
| IMPLEMENTATION_DEFECT | Confirmed conflated errors/lost failure detail; v2 correction tested |
| COUNTER_VERIFIED | Mock/fixture normal/reset/zero cases pass; no new kernel validation |
| COUNTER_UNAVAILABLE | Mock failure path distinctly classified; blocks inference |
| CAPTURE_DROPS_DETECTED | Mock positive-drop path distinctly classified and sticky; blocks inference |
| ROOT_CAUSE_UNKNOWN | Historical live failure remains unresolved due missing interval evidence |

Live Helper v2 E2E is pending new user approval and user-executed capture. New
telemetry should distinguish unknown counters, measured drops, missing delivery,
and send timeout. It cannot retroactively recover the missing old interval or
establish that performance tuning is necessary. Operational model approval remains
outside this task and blocked.

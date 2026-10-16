# Live Network transport timeout and bounded reader stabilization

Validation date: 2026-10-16. SOC baseline:
`f305cf7ff8159671c9a0d161c96c0012edcc23c9`.
ML baseline: `e1a01260f0463a38d4d778859bc2a86f8e9cfbde`, unchanged.
Environment: WSL2, kernel `6.18.33.2-microsoft-standard-WSL2`, Python 3.12.14.

**PARTIAL — transport timeout confirmed; receiver starvation reproduced and
corrected in ordinary-user Unix IPC fixtures; LIVE_E2E_BLOCKED.**
No privileged helper, AF_PACKET capture or IP test traffic was executed.
The exact historical blocking call and its duration remain unmeasured.

## 1. Saved evidence, inspected read-only

The supplied directory was
`~/.local/share/autonomous-soc-agent/gui/live-network/session-0bc4afed88574fb0849141e41b6b45d1`.
Its independent internal session identity is
`0611c05e-cb8e-4de0-a1ba-8d352d82fe8a`.
The 14 existing session files were hashed for preservation. SQLite inspection
used read-only connections; no session was resumed or repaired.

| Evidence | Preserved observation |
| --- | --- |
| READY | Counter sequence 1; interval and cumulative packets/drops 0 |
| READY identity | UID/GID 1000; CapEff/Prm/Inh/Amb 0; CapBnd 8192; NoNewPrivs 1 |
| Last accepted HEARTBEAT projection | Sequence **54**, accepted cumulative kernel packets **50** |
| Last helper projection | Received frames **53**, sent metadata packets **26** |
| Failure record | Sequence **56**, interval packets **170**, reported cumulative packets **258** |
| Helper failure | `HELPER_TRANSPORT_TIMEOUT` |
| Receiver failure | `HELPER_CAPTURE_COUNTER_INTEGRITY_FAILED` / `COUNTER_SEQUENCE_MISMATCH` |
| Missing interval | Expected sequence **55** was not accepted |
| Reported failure drop fields | Interval 0, cumulative 0; **not accepted as verified totals** |
| Overall capture drops | **UNKNOWN** |
| Standalone HEARTBEAT history | **MISSING**; only the latest state projection survives |
| Verified CLOSED receipt | **MISSING** |
| Full capture duration / exact failed-send duration | **UNKNOWN** |
| Packet metadata persisted / flows / model invocations | **27 / 0 / 0** |
| Persistent queue | **16 DONE, 11 PENDING**, backlog 11 |
| Runtime | DEGRADED / NOT_READY, counter integrity error |
| Capture gaps | **2 lifecycle gaps**, not a measured kernel drop count |
| Latest helper CPU / peak RSS | 3.601442 s / 196,235,264 bytes |

The last helper metadata count is sampled before the final accepted packet and
is not an independently reconciled end-of-session count. Kernel counters,
received frames, parsed metadata and committed Source records are different
accounting domains. They must not be subtracted to invent packet loss.

The user's `sendall` traceback and the retained helper error establish a transport
timeout. The missing sequence establishes incomplete counter delivery. Although
the failure contains drop fields of zero, the missing reset interval and absent
verified CLOSED prevent a lossless-capture claim. The **87 drops from the previous
session belong to that previous session**, not this one.

All seven SQLite databases returned `integrity_check = ok`. The runtime state
digest, READY/session audit bindings and append audit chain were independently
verified. Audit event counts: INITIALIZED 1, NETWORK_CONFIGURED 1,
LIVE_HELPER_VERIFIED 1, NETWORK_CAPTURE_GAP 1, NETWORK_SOURCE_COMMITTED 16,
NETWORK_COLLECTION_BLOCKED 1, LIVE_HELPER_CLOSED 1. The CLOSED audit event has
terminal digest UNKNOWN; it is not a successful helper CLOSED receipt.

Audit head:
`6210542af618113eaeb0124232eb37f2b0467c79fd4e10758bdcbe9a7364d3eb`.

Selected preserved evidence identities:

| File | SHA256 |
| --- | --- |
| session.json | `0e6e802a77d12432e0b530b99db2415f2b2ae9e8f81489f29e2c3b5c72be523d` |
| verified-ready.json | `abf51ad049e7e218286e6a1f7041643ef6e36a9708e1bfff7e4eda9861c6c718` |
| counter-failure.json | `c25464d75198c85cafec1c1b333c4412bdff1abede7aadb2238e5f8ac1cbdfef` |

## 2. Transport contract and root-cause boundary

The helper uses an abstract Linux AF_UNIX **SOCK_SEQPACKET** channel. It sends
JSON HEARTBEAT and PACKET records, with a **0.5-second per-send socket timeout**.
No production SO_SNDBUF or SO_RCVBUF override is installed. A current ordinary
Unix socket reports both buffers as 212,992 bytes; the failed descriptor's actual
buffer size and occupancy were not recorded and remain UNKNOWN.

The existing receiver uses nonblocking `recvmsg(8192)` and validates record size,
session identity, packet sequence and reset-on-read kernel counter intervals.
Each heartbeat interval must advance the counter sequence exactly once and
reconcile cumulative totals. There is no reconnect or send retry after failure.

Before this change, the existing NetworkMonitor called receive, then performed
packet enqueue, Source/provenance persistence, queue claim/finish and state/audit
work synchronously on the same backend asyncio thread. SQLite uses FULL
synchronous commits and a bounded busy timeout. A monitor iteration can also
sleep 100 ms; the previous bounded control-record drain fix did not separate
reading from this processing. Runtime construction/recovery after READY also
performs synchronous work before the receive loop begins.

**No socket reads occur while that thread is occupied with synchronous work.**
A full Unix send queue can therefore outlast the helper's 0.5-second timeout.
The paused-processor fixture below reproduces exactly this failure mechanism.
Historical SQLite commit times, recv gaps and send queue occupancy were not
retained, so a particular database call cannot be named as the sole cause of
the user's execution. Native model invocations were **0** in this saved session;
model inference is not an evidenced cause of that execution's timeout.

Tk's main thread is separate from the backend event loop. Moving only a Tk
callback would not resolve backend receive starvation. Model workers are already
separate processes; their architecture is retained.

Python documents a total-operation timeout for
[socket.sendall](https://docs.python.org/3/library/socket.html#socket.socket.sendall).
For AF_UNIX, SO_SNDBUF is effective and SO_RCVBUF does not control buffering as
it does for other socket families; see
[unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html).
Kernel PACKET_STATISTICS reset-on-read semantics remain unchanged; see
[packet(7)](https://man7.org/linux/man-pages/man7/packet.7.html).
No timeout, socket buffer, sysctl or kernel counter policy was relaxed.

## 3. Minimal transport change

```text
Existing approved helper (unchanged, separate process)
  → existing authenticated AF_UNIX channel
  → one unprivileged metadata reader thread
  → bounded in-memory PacketObservation staging (session frame budget, ≤512)
  → existing NetworkMonitor / persistent queue / Source Store / audit
  → existing isolated research model workers, subject to existing gates
```

The reader starts immediately after validated READY, **before synchronous
Runtime/SQLite initialization**. It owns socket reads and existing protocol
validation. It uses a 50 ms select wait, the existing two-second heartbeat
deadline, and no busy polling or database/model work. Normal per-record parsing
and interface checks still consume reader CPU; this is not a promise of unlimited
receive throughput.

The staging capacity equals the approved session's `max_packets`, at most 512.
At 8,192 encoded bytes per record the encoded capacity is at most 4 MiB; Python
objects and interpreter memory are additional. No unlimited queue or second
persistent queue was introduced. The persistent queue remains the existing one.

- A full staging queue fails with `HELPER_TRANSPORT_BACKPRESSURE`, disconnects
  the helper, and records capacity, depth, high-water mark and unadmitted count.
  No overflow is silently dropped or admitted for inference.
- Counter UNKNOWN, sequence gaps, positive drops, packet duplication, malformed
  records, stale heartbeat and disconnect remain fail-closed. A transport timeout
  accompanying counter failure retains both causes; the GUI can show
  `HELPER_TRANSPORT_TIMEOUT_COUNTER_INTEGRITY_FAILED`.
- HEARTBEAT and CLOSED remain in wire order with PACKET validation; the reader
  removes processor-induced head-of-line blocking rather than reordering counters.
- A clean CLOSED marks collection non-live immediately, while accepted metadata
  can drain through the existing processor. It does not stop the monitor before
  the buffer is drained. Counter deltas are exposed once, without double-counting.
- Stop rejects further delivery, sends the existing STOP/disconnect, and joins
  the reader within two seconds. Missing final counters remain unavailable.
  Shutdown uncertainty is an error; model/consumer cleanup still runs.
- Reader failure/exit appears as ERROR with Last Error on the first state query.
  Metrics include reader running/error, depth/capacity/high-water, delivered count
  and whether a clean final counter record exists. Historical results are not LIVE.
- Unpersisted buffered metadata is recorded in private
  `transport-unprocessed.json`; failure details use `transport-failure.json`.
  Existing immutable files are not overwritten. These receipts are accounting,
  not an automatic replay facility or exactly-once guarantee.

A process crash can lose volatile staging metadata before a diagnostic can be
written. Existing session restart/gap rules remain required. No automatic replay
or re-inference of an interrupted request was added.

## 4. Bounded same-input performance comparison

Driver: `tests/live_transport_diagnostics.py`.
Measurements: [live-network-transport-benchmark.json](live-network-transport-benchmark.json).
These are **synthetic metadata over ordinary-user AF_UNIX socket pairs**, with
privilege/raw-socket attestation explicitly substituted by a fixture. No helper
or AF_PACKET socket is launched. Each case offers the same 48 packet values,
interleaved counter messages and CLOSED, with 8 ms simulated processing per
packet. Both variants use a 0.5-second sender timeout and the same fixture-only
SO_SNDBUF request of 4,096 bytes (Linux reports 8,192). This deliberately small
test buffer is not a production buffer setting or the historical failed buffer.

The baseline invokes the existing inline receive policy without starting a
reader; the candidate starts the new reader. Record validation is shared and
unchanged. Three trials per condition alternate order: **12 runs total**.
Each table cell is the median of its three trials.

| Condition / variant | Delivered / offered | Wall s | CPU s | Packets/s | Staging high-water |
| --- | ---: | ---: | ---: | ---: | ---: |
| Steady inline | 48 / 48 | 0.405 | 0.018 | 118.44 | 0 (no staging) |
| Steady reader | 48 / 48 | 0.394 | 0.012 | 121.92 | 47 |
| Processor paused 650 ms, inline | **1 / 48, SEND_TIMEOUT** | 0.659 | 0.001 | 1.52 (failed partial run) | 0 |
| Processor paused 650 ms, reader | **48 / 48**, clean CLOSED | 1.043 | 0.013 | 46.04 | 48 |

The inline failed send lasted 500.60, 501.48 and 500.57 ms in the three paused
trials. Unattempted/undelivered offered fixture messages are explicitly counted;
they are **not kernel packet drops**. Successful reader trials have zero duplicate
deliveries, preserved order and fixture counter totals 48 packets / 0 drops.

| Condition / variant | Delivery p50 ms | Delivery p95 ms | Successful send p95 ms |
| --- | ---: | ---: | ---: |
| Steady inline | 8.29 | 8.54 | 8.40 |
| Steady reader | 188.99 | 361.86 | 0.20 |
| Paused inline (one delivered item only) | 650.42 | 650.42 | 0.03 |
| Paused reader | 837.76 | 1010.85 | 0.18 |

Delivery latency is from each packet's send attempt to processor receipt.
Successful-send latency excludes failed sends, which are reported separately.
The reader allows a burst to be submitted quickly, so buffered items wait longer
for the processor. Inline backpressure delays future send attempts instead.
**The change stabilizes transport during bounded processing stalls; it does not
make SQLite faster or improve every end-to-end latency.** The failed partial
baseline is not a valid throughput improvement ratio.

Diagnostic-process peak RSS was **205,230,080 bytes** across this invocation.
This is a cumulative whole-process high-water mark, not isolated per-variant
memory consumption or a production memory budget proof.

Independent clean Export benchmark: the same 12 cases reproduced steady 48/48,
paused inline timeout with 1/48, paused reader 48/48, zero duplicates, clean
candidate counters and identical input fixture digest. Median steady throughput
was 119.62 / 122.75 packets/s; paused reader 46.12 packets/s. Timing/RSS vary with
scheduling and are not expected to have identical hashes.

A separate integration test uses the real SQLite queue, Source and audit
pipeline: it pauses the processor synchronously for 650 ms before Runtime
initialization, then processes eight synthetic packets with an additional 20 ms
per-packet delay. The reader retains all eight, the pipeline finishes with nine
DONE records (eight packets plus the shutdown flow), audit verifies, and model
invocations remain zero.

## 5. Tests and independent Export

Each row is a separate invocation. Overlapping suites are not summed.

| Invocation | Result |
| --- | --- |
| Initial existing Live Network unit/integration | 92 passed, 10.88 s |
| New reader/real-SQLite fixtures, including final stop/first-error checks | 16 passed, 3.76 s |
| Live Network unit/integration + Network Capture unit, final source | 193 passed, 29.20 s |
| GUI / Research Adapter unit/integration + Linux Runtime integration | 154 passed, 63.70 s |
| Actual WSLg GUI prepare/copy/stop/restart/navigation/close, no capture | 1 passed, 12.38 s |
| Clean SOC/ML Export: Live / Network Capture, final source | 193 passed, 29.11 s |
| Clean Export: GUI / Research / Runtime | 154 passed, 59.19 s |
| Clean Export: WSLg GUI | 1 passed, 9.87 s |
| Clean Export: same-input benchmark | 12 runs, matching functional outcomes |
| Ruff `check src tests`, `format --check .`, `git diff --check` | PASS |

The broader GUI/Research/Runtime and WSLg runs preceded the final narrow explicit
Stop/final-counter and first-error display assertions. The final Live suite
includes those checks. No earlier results are relabeled as new executions.
Tests cover paused/full send buffers, timeout, disconnect, queue overflow,
duplicate packets, missing counter interval 55, real-drop rejection, stale
heartbeat, reader startup/exit, clean CLOSED draining and Stop cleanup. Existing
regressions cover worker crash/timeout, listener lifecycle, research-only/source
validation, audit integrity and operational promotion denial.

All guarded test and benchmark invocations reported **0 attempted
AF_PACKET/AF_INET/AF_INET6 socket creations**. Ordinary AF_UNIX IPC is allowed.
Mocks do not establish real kernel counter quality or actual live inference.

The independent Export contains committed SOC HEAD plus only the seven files
listed below, and committed ML HEAD. Existing user modifications and Reliability
Replay are excluded. External model files are referenced read-only at their
existing paths with their pinned identities; they are not copied into the Export.

Safe reproduction (no privileged helper or IP traffic):

```bash
.venv/bin/python -m tests.native_capture_verification_guard --import-mode=importlib -q \
  tests/unit/live_network tests/integration/live_network tests/unit/network_capture
.venv/bin/python -m tests.native_capture_verification_guard --import-mode=importlib -q \
  tests/unit/gui tests/integration/gui tests/unit/research_adapter \
  tests/integration/research_adapter tests/integration/linux_runtime
.venv/bin/python - <<'PY'
import sys
import tests.native_capture_verification_guard as guard
from tests.live_transport_diagnostics import main
sys.argv = ['benchmark', '--output', '/tmp/soc-transport-benchmark-new.json']
main()  # Exclusive output creation; choose an unused path.
print({'network_socket_attempts': guard.blocked})
PY
```

## 6. Changed files and preservation

1. `src/soc_agent/security_ai/operational/network_capture/helper_transport.py`
2. `src/soc_agent/security_ai/research/live_service.py`
3. `tests/live_transport_diagnostics.py`
4. `tests/unit/live_network/test_transport_reader.py`
5. `tests/integration/live_network/test_transport_runtime.py`
6. `docs/linux-soc-v1/live-network-transport-benchmark.json`
7. `docs/linux-soc-v1/live-network-transport-timeout.md`

The helper, Producer v1.1.0, 14-feature contract, model artifacts, Raw Dataset,
existing user edits/Replay, failed session and Final Demo evidence are preserved.
No ML source or artifact changes are part of this task.

## 7. Security boundaries and remaining live blocker

Approved and current helper SHA256 are identical:
**`a8a0cafe7494922a0296a250129ab5695b681dbbec6febf512509b023ef44856`**.
The helper file was not modified, so this task creates no new helper SHA approval
request. Only its nonprivileged receiver/service and diagnostic tests changed.
No sudo, pkexec, setpriv, privilege escalation, raw capture, test IP traffic,
security WRITE, model training or operational promotion was performed.

Existing limits remain lo only, 60 seconds, 512 frames, temporary CAP_NET_RAW
restricted to the user-executed helper, capabilities dropped after socket open,
credential/payload non-retention and separate model worker processes.
Counter UNKNOWN/drop/integrity rejection remains enabled. Status remains
RESEARCH_ONLY / NOT_INFERABLE / OPERATIONAL_INFERENCE_BLOCKED / WRITE_DENIED.

**Actual live E2E remains unverified.** A user's next test requires restarting
the GUI to load the new receiver, preparing a **new** session, verifying Listener
READY, and using only that session's displayed manual helper command within its
approved bounds. Do not reuse the failed session command. Stop/close the session
if a timeout, integrity error or drop occurs; no automatic retry/reconnect is
added. Codex does not execute those capture/authentication commands.

The next live result must preserve READY, ordered counters, clean CLOSED, packet
and queue accounting, capability state and audit. Success requires no UNKNOWN or
drop interval; the fixture's success cannot substitute for that evidence.
OS scheduling, GIL-heavy work, storage stalls longer than the staging budget,
reader validation cost and kernel capture drops remain possible. The earlier
87-drop session has not been reclassified or fixed by inference from this test.

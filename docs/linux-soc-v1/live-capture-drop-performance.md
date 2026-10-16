# Live capture drop assessment and bounded metadata drain

Date: 2026-10-16. Source baseline SOC HEAD:
`df96d37d951e0fdf3ba047768aa024dbf353052a`.
ML HEAD: `e1a01260f0463a38d4d778859bc2a86f8e9cfbde` (unchanged).

**DROP_CONFIRMED · BOTTLENECK_IDENTIFIED (receiver fixture) · LIVE_E2E_BLOCKED.**
The receiver pacing defect is reproduced and minimally corrected. Its contribution
to the historical live loss remains **BOTTLENECK_UNVERIFIED**: no live sender
latency/queue occupancy trace exists, and no new capture was executed.

## 1. Saved evidence, inspected read-only

Source directory supplied by the user:
`~/.local/share/autonomous-soc-agent/gui/live-network/session-c6313ff0f0254c8e8382618941e44dfd`.
Its independent internal session identity is
`bd20ce89-2861-4917-a022-693306fbc994`; a directory suffix need not equal this UUID.
All session files were hashed before/after inspection and tests.

| Evidence | Observed value |
| --- | --- |
| READY | Sequence 1, packets 0, drops 0, COUNTER_VERIFIED |
| READY process | UID/GID 1000; CapEff/Prm/Inh/Amb 0; CapBnd 8192; NoNewPrivs 1 |
| Last HEARTBEAT projection | Sequence 30; accepted cumulative kernel packets 272 |
| Last helper projection | Received frames 29; sent metadata packets 14 |
| Failure record | Sequence 31; interval packets **96**, interval drops **87** |
| Failure cumulative values | Packets **368**, drops **87** |
| Counter status | `HELPER_CAPTURE_DROPS_DETECTED`, no UNKNOWN detail |
| Standalone HEARTBEAT log | **MISSING**; only the latest metrics projection survives |
| Verified CLOSED receipt | **MISSING** |
| Capture elapsed / failed-interval duration | **UNKNOWN** |
| Helper RSS | 196,055,040 bytes at READY and latest projection |
| Helper CPU | 3.471444 s at READY; 3.480703 s latest; delta 0.009259 s |
| Runtime | DEGRADED / NOT_READY, last error HELPER_CAPTURE_DROPS_DETECTED |
| Runtime packets / flows / inference | 15 metadata packets / 0 flows / 0 model calls |
| Queue | 14 DONE, 1 PENDING; backlog 1; no poison |
| Capture gap | 2; these are lifecycle gaps, not a kernel drop count |
| Aggregate `capture_drops` | UNKNOWN; observed interval loss remains explicitly 87 in `capture_counter_issue` |

`272 + 96 = 368`, sequence `30 + 1 = 31`, and the state's counter issue exactly
matches `counter-failure.json`. The state digest, READY/session audit bindings,
and monitor audit chain were independently checked with SQLite `mode=ro` reads.
All seven SQLite databases returned `integrity_check = ok`. There are 14 source
commit audit records. The LIVE_HELPER_CLOSED audit entry contains terminal digest
UNKNOWN; it is not a successful CLOSED receipt.

Audit head:
`7b2f7427acb232743a9f30641d44860ac908dfc5ca8130bf060d83e681379e17`.
This is local saved evidence, not independent remote attestation or a complete
reconstruction of all 31 intervals. **COUNTER_VERIFIED** here means the preserved
failure arithmetic/bindings pass; it does not mean lossless capture quality.

The second user execution reused this session. The listener accepts exactly one
helper and closes its listening endpoint after accept; failure closes the channel.
An old session command consequently gets ConnectionRefused before `capture.open()`.
A new manually prepared session is required; automatic reconnect is intentionally
not added. No second successful capture is inferred.

## 2. Cause separation

Drop occurrence is established. Its exact historical timing/cause is not.
The helper's latest CPU delta is small, but it ends before the failing interval;
there is no per-call parse/serialize/send trace or historical receive-queue size.
It cannot prove that JSON, WSL scheduling, IPC blocking, or a traffic burst was the
sole cause. The retained kernel and metadata counts also cover different domains:
loopback clones, incoming observations, parser filtering, unread backlog and the
outgoing-only policy prevent a simple subtraction from measuring drops.

`PACKET_STATISTICS` resets on read; cumulative totals must sum intervals, and a
later zero cannot erase the earlier 87 drops. See [packet(7)](https://man7.org/linux/man-pages/man7/packet.7.html).
Receive buffer accounting includes kernel overhead; buffer values are not raw
payload capacity. See [socket(7)](https://man7.org/linux/man-pages/man7/socket.7.html).

The code does not set AF_PACKET SO_RCVBUF. Current read-only sysctls were
rmem_default 212,992 and rmem_max 4,194,304 bytes; the failed descriptor's actual
buffer and occupancy are **UNKNOWN**. These current settings do not establish a
historical packet-capacity limit. No buffer/sysctl/NIC settings were changed.

## 3. Confirmed receiver bottleneck and minimal fix

Before the fix, `HelperCapture.receive()` returned None after processing a
HEARTBEAT, even with a PACKET already buffered behind it. `NetworkMonitor.run()`
treats None as the end of its receive batch, then publishes/persists state and
sleeps 100 ms. Thus control records unnecessarily introduced idle cycles into an
otherwise ready metadata stream.

The only product change in this task is `helper_transport.py`:

- Continue through at most **64 control records** per receive call, returning
  the first validated packet immediately.
- Return immediately on real EAGAIN/empty input, CLOSED or failure.
- Preserve every interval/packet identity, sequence, drop and cumulative check.
- Keep default monitor packet batch 16, persistence and sleep unchanged.

Validation moved into `_receive_record` without relaxing it. A positive drop or
bad interval aborts the drain before the following packet is returned. No list
of unbounded packets is buffered. A 64-control-record run yields even if more
records remain, preventing a busy loop. This improves already-buffered control
handling; a real empty queue between HEARTBEAT and PACKET can still yield.

The raw helper receive loop, kernel statistics frequency, CPU budget, packet
limit, buffer size, source/Producer/model contracts and approved helper were not
changed. This is not a claim that batching kernel receives is necessary.

## 4. Same-input offline benchmark

Reproducible driver: `tests/live_network_performance.py`.
Full final measurements: [live-capture-drop-benchmark.json](live-capture-drop-benchmark.json).
Inputs are synthetic 80-byte frames/AF_PACKET-shaped metadata, not captured
packets. Runtime trials feed prebuilt messages through the real NetworkMonitor,
persistent queue, Source Store and audit, with socket attestation explicitly
substituted by a fixture. No real helper is launched.

Each variant uses the same 16 packet values, packet batch 16, timeout/queue
budgets and persistence. Three trials alternate execution order. The baseline
reproduces the pre-fix single-record receive policy and shares unchanged record
validation with the candidate, isolating the drain policy difference. Startup
configuration is outside the timed monitor run; recovery, persistence and sleep
inside that run are included. No models execute.

| Final guarded worktree benchmark | Baseline | Candidate |
| --- | ---: | ---: |
| Median duration | 3.2301 s | 1.7931 s |
| Median-duration throughput | 4.95 packets/s | 8.92 packets/s |
| Relative improvement | — | **1.80×** |
| Logical packet input | 16 | 16 |
| Wire message reads | 33 | 33 |
| Durable records | 17 DONE | 17 DONE |
| Kernel fixture count / drops | 16 / 0 | 16 / 0 |
| Audit | verified | verified |

The extra durable record is a shutdown flow summary. No silent record deletion
or omitted counter validation explains the improvement. Independent Export
reproduction: baseline 2.9761 s, candidate 1.3807 s, **2.16×**. An initial
exploratory run was 2.45×. Wall times vary with WSL scheduling/system load; these
are per-invocation fixture measurements, not live NIC throughput or a guarantee
of drop-free capture. Diagnostic-process peak RSS was 206,049,280 bytes, a whole
process high-water mark rather than a per-helper/per-variant memory comparison.

### Stage measurements (final guarded run)

| Stage | Median |
| --- | ---: |
| Mock single recvmsg + timestamp decoding | 2.20 µs |
| Mock batch of 16 receives | 33.29 µs per batch |
| Packet parsing | 17.16 µs |
| Helper-style JSON serialization | 12.23 µs |
| Receiver JSON/schema validation | 14.48 µs |
| Read-only interface identity validation | 35.63 µs |
| AF_UNIX send + receive round trip | 1.72 µs |
| Mock statistics read | 0.157 µs |

These are three-round microbenchmarks. Mock receive/statistics timings do not
measure real AF_PACKET syscall/queue costs. The raw batch microbenchmark is a
bounded Python loop over the same mock receives, not recvmmsg or a deployed
helper optimization. Uncongested AF_UNIX timing is not the failed helper's send
latency. In a separate local AF_UNIX-only socketpair fixture, a stopped reader
caused EAGAIN after 93 records of 1,079 bytes with 212,992-byte socket buffers.
This demonstrates bounded backpressure without attributing that capacity to the
historical AF_PACKET descriptor.

A separate persistent queue fixture admitted two entries, rejected the third
at capacity 2, and retained exactly two PENDING records. No overflow was converted
to success. No IP test traffic or packet injection was generated.

## 5. Tests and independent Export

Each row is its own invocation; overlapping suites are not summed.

| Invocation | Result |
| --- | --- |
| New bounded-drain regression cases | 8 passed |
| Live Network unit/integration + Network Capture unit | **177 passed**, 25.74 s |
| GUI / Research Adapter unit/integration + Linux Runtime integration | **154 passed**, 66.12 s |
| Actual WSLg GUI prepare/copy/stop/restart/navigation/close, no capture | **1 passed**, 13.24 s |
| Clean SOC/ML Export: Live/Network Capture suite | **177 passed**, 24.67 s |
| Clean SOC/ML Export: GUI/Research/Runtime suite | **154 passed**, 60.12 s |
| Clean Export: actual WSLg check | **1 passed**, 9.19 s |
| Clean Export: offline benchmark | completed, matching packet/counter/queue outcomes |
| Ruff `check src tests`, `format --check .`, `git diff --check` | PASS |

Tests cover the actual saved 96/87 drop values as a failure fixture, counter
integrity/accounting, control-batch limit, empty socket behavior, duplicate
packets, bounded transport/queue pressure, timeout, worker crash, listener cleanup,
no operational promotion and no privilege escalation. All guarded tests and final
benchmarks reported **0 attempted AF_PACKET/AF_INET/AF_INET6 socket creations**.
Ordinary AF_UNIX fixture IPC is explicitly allowed; it is not network test traffic.

Reproduce without capture:

```bash
.venv/bin/python -m tests.native_capture_verification_guard \
  --import-mode=importlib -q \
  tests/unit/live_network tests/integration/live_network tests/unit/network_capture
.venv/bin/python -m tests.live_network_performance --output /tmp/soc-perf-new-result.json
```

The benchmark output path must not already exist. It uses a fresh temporary
private runtime and never the retained failed session.

## 6. File scope, preservation and Git

This task changes one product file and adds two diagnostic/test modules, the
benchmark JSON and this report. The currently requested dependency audit also
identifies the previously uncommitted Live Network implementation, Listener Fix
and Counter Fix as prerequisites. The reviewed integration allowlist is **35
files**: only that related stack and these diagnostics. Earlier reports preserve
their historical BLOCKED/pending-Git statements; this report records the later
combined integration verification.

Independent Export was built from clean SOC/ML Git HEADs plus this related SOC
allowlist. It excludes unrelated user changes and Reliability Replay, including
all uncommitted ML changes. Explicit trusted local model/interpreter references
are read-only. Raw packets, Zeek labels, models, operational DBs and private logs
are excluded from staging. Working/export source SHAs are compared before staging
and index blobs are compared before commit. The initial index was empty.

The remote was fetched and matched the baseline before staging. Commit/push is
conditional on final staged checks and a second unchanged-remote/fast-forward
check. The final commit and push identities are reported in the task completion
message rather than embedding this document's own commit hash.

## 7. Helper identity and remaining Live E2E blocker

Existing and current helper SHA256 are identical:

```text
a8a0cafe7494922a0296a250129ab5695b681dbbec6febf512509b023ef44856
```

The helper source bundle is unchanged; no new helper binary/source approval is
introduced by this receiver-only fix. This task does not execute another capture
or expand previous interface/time/frame authorization. A subsequent real test
must be user-executed in a **new** explicitly approved session, with normal-user
GUI, lo, maximum 60 seconds / 512 frames, temporary CAP_NET_RAW only in the helper,
capability drop, no payload retention, and no security WRITE. Do not reuse the
failed session command. Prepare, confirm LISTENER READY, review/copy the fresh
command, then perform authentication/execution personally in the terminal.

A live retry is needed to measure actual queue occupancy, send latency and loss
under controlled approved input; those values remain UNKNOWN here. No Drop/UNKNOWN
check was removed and no buffer or CPU budget was increased. Research models
remain RESEARCH_ONLY; operational inference NOT_INFERABLE/BLOCKED, finding
promotion blocked, WRITE_DENIED. **Live E2E success is not declared.**

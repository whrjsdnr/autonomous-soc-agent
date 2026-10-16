# Native Idle flow frame budget and isolation assessment

Date: 2026-10-16. SOC baseline `9477b054070e1a2f7658d10803c5749006c1dca4`;
ML baseline `e1a01260f0463a38d4d778859bc2a86f8e9cfbde`.

**Assessment: CAPTURE_VERIFIED / FRAME_BUDGET_INSUFFICIENT /
ISOLATION_BLOCKED under current authorization / NATIVE_IDLE_FLOW_PENDING /
LIVE_AI_INFERENCE_PENDING.** Namespace co-location is a plausible future design;
its WSLg/bootstrap/runtime feasibility remains untested. No production code,
Helper, Producer, timeout or model was changed. No privileged command, capture,
test traffic, namespace/veth creation or security WRITE was performed.

## 1. Read-only actual session evidence

Target: `session-f360a55750ab48f0ba52098c5b2d0d91`.
Internal capture identity: `7822a749-0094-4f95-b02e-ee7e09f80667`.
The existing `research.live_evidence.verify` contract was reused before metadata
analysis. The sanitized, self-digested evidence is
[native-idle-flow-budget-evidence.json](native-idle-flow-budget-evidence.json).

| Observation | Verified stored value |
|---|---|
| READY / CLOSED | Both present, matching session and capability state |
| Counter | COUNTER_VERIFIED, READY sequence 1, CLOSED sequence 542 |
| Kernel cumulative packets / drops | 512 / 0 |
| Received raw frames / sent metadata | 512 / 256 |
| Stored packets / Flow records | 256 / 4 |
| Queue / Source Store | 260 DONE / 260 ACCEPTED; no pending or poison |
| Finalization / transport | VERIFIED; delivered 256; queue depth 0; high-water 156 |
| Helper error / unprocessed file | null / MISSING |
| Elapsed capture | 9.275769664000109 seconds |
| Packet kernel timestamp span | 8.152108646 seconds |
| SQLite / database preservation | Seven databases integrity `ok`; hashes unchanged |
| Capture gap | 1 lifecycle gap, distinct from kernel drops |
| Timeout-eligible flows | 0 |
| Quality / Edge receipts / model-linked investigations | 0 / 0 / 0 |

Missing `transport-unprocessed.json` is not the persistence proof. Matching
sent/stored counts, source receipts, DONE records, finalization and audit provide
that proof. No replay, receipt insertion, recovery mutation or model execution
was performed against this retained session.

Counter interval history is not persisted in full: READY/CLOSED and verified
runtime audit are available, but intermediate 540 samples cannot independently
be replayed from saved files. The saved transport reports verified sequence and
cumulative accounting; raw per-second kernel arrival peaks remain UNKNOWN.
Kernel packet counters and userspace received counts are separate measurements,
even though both equal 512 here. PACKET_STATISTICS resets its counters on read;
existing cumulative accounting is retained. See [packet(7)](https://man7.org/linux/man-pages/man7/packet.7.html).

Helper exit 0 is **user reported**. There is no saved shell exit-status file;
CLOSED/error-null and counter/persistence verification are independently present.
The preserved audit head is
`13580c248791f3a70c0272c1f929727e2fda3273ca52f05523b2df8181dcfd40`.

## 2. Flow distribution and exclusion cause

All stored observations are IPv4 TCP. No UDP test Flow is present. The source
process, owner and purpose of these connections cannot be established from this
packet metadata; they are not attributed to a browser, IDE, malware or service.
Endpoints and raw payload are omitted from public evidence.

| Flow digest prefix | Packets | Forward / backward | Duration s | Maximum observed interpacket gap s | Closure |
|---|---:|---:|---:|---:|---|
| `d406d036ddad` | 74 | 36 / 38 | 8.152109 | 1.552160 | SHUTDOWN |
| `26fd0af6a5c0` | 44 | 22 / 22 | 7.766912 | 1.689548 | SHUTDOWN |
| `fa9c2adcdf04` | 68 | 41 / 27 | 7.813971 | 1.547127 | SHUTDOWN |
| `13678717c220` | 70 | 42 / 28 | 7.813910 | 1.479808 | SHUTDOWN |

All 256 packet references are uniquely accounted for across these four flows;
forward/backward counters and durations were independently recomputed from their
stored packet references. These are captured slices, not complete TCP
conversations. No packet-reference duplication or unaccounted packet was found.

One-second **outgoing metadata** bins, relative to the first packet timestamp:
`66, 4, 50, 14, 18, 63, 10, 26, 5` (last bin partial). Their sum is 256. These
are not raw-frame bins: only outgoing observations are retained after loopback
host clones consume the same receive budget. The aggregate ratio is exactly
2 received frames per stored metadata packet in this session; that ratio is not
asserted for every future interval or other interfaces.

The immediate blocker is frame-limit exhaustion before 30 seconds. Further,
none of the four observed flows was idle: its maximum gap is below 1.69 seconds.
Increasing capture duration or frame budget alone will not make continuously
active connections satisfy Idle. A distinct owned flow must actually become
silent, and a later delivered packet must advance the event-time watermark.
SHUTDOWN is still excluded. Active remains 120 seconds, beyond a 60-second run.

## 3. Frame budget calculation and uncertainty

Capture wall-clock raw receive rate:

```text
r = 512 / 9.275769664000109 = 55.197575893578595 frames/s
point estimate B(t) = ceil(r * t)
scenario estimate = B(t) + 16
planning margin = ceil(1.5 * r * t) + 16
```

The extra 16 assumes four owned UDP echo exchanges/eight datagrams and the
observed loopback clone pattern. It is a planning allowance, not a measured new
traffic result. The 1.5 multiplier is an explicit heuristic, not a statistical
confidence bound or validated burst maximum.

| Observation window | Constant-rate frames | Plus scenario allowance | 1.5× rate + allowance |
|---|---:|---:|---:|
| 31 s | 1,712 | 1,728 | 2,583 |
| 33 s | 1,822 | 1,838 | 2,749 |
| 40 s | 2,208 | 2,224 | 3,328 |
| 59 s | 3,257 | 3,273 | 4,901 |

Thus **1,712 is the minimum integer under the constant-mean model for 31 s**,
not a proven minimum for an unknown future trace. Approximately 1,728 includes
the proposed traffic; a practical 33-second scheduling window projects 1,838.
The actual future minimum/safe upper budget is UNKNOWN because arrival bursts
and load changes are unbounded by this one sample.

At the existing 512 cap, 31 seconds plus 16 scenario frames would require mean
background rate <= (512−16)/31 = 16 frames/s. A 33-second plan allows <=15.03/s;
keeping capacity through the helper's roughly 59-second normal window allows
<=8.41/s. These are necessary arithmetic budgets, not sufficiency guarantees.
The observed 55.20/s exceeds them. The stored Runtime rate 6.9387 metadata/s uses
a 36.8944-second monitoring/drain window; it must not replace raw receive rate.

A hypothetical 2,048 cap fits the 33-second mean estimate but not its 1.5 margin.
4,096 fits the 40-second margin but not the 59-second margin. Even 8,192 cannot
guarantee arbitrary future traffic. None of these larger values is approved or
implemented; altering a session JSON cannot enable them.

## 4. Isolation alternatives and implementation constraints

| Alternative | Privilege and compatibility | Security / resources / time | Current decision |
|---|---|---|---|
| Existing namespace, quiet lo, cap 512 | Existing manual temporary CAP_NET_RAW only; unchanged helper and controller | Least setup; all background loopback metadata remains observable; low frame demand only if environment is genuinely quiet; no timing guarantee | Conditional fallback; quiet condition not established |
| Existing lo, larger cap | New approval and coordinated bounded session/transport changes; not just a GUI setting | More metadata retention, serialization, SQLite work and memory; same background privacy and burst risks; duration still <=60 s | BLOCKED by unchanged-helper/current limits |
| Move only Helper to a new namespace | Requires setup privilege; controller/session remain in original namespace | Abstract socket inaccessible; interface identity changes; receiver cannot verify other namespace's packet inode through its own `/proc/net/packet` | BLOCKED with current architecture |
| Co-locate existing GUI/controller, Helper and test sockets in a disposable namespace; lo only | Separate reviewed bootstrap, normal UID/GID GUI, only temporary CAP_NET_RAW for helper | Removes original-namespace loopback interference by design; no veth needed; WSLg and lifecycle must first be validated; existing 60 s/512 capture limits retained | Recommended future isolated experiment; runtime UNKNOWN, not authorized now |
| Namespace + veth / host bridge | Additional CAP_NET_ADMIN setup, interface scope and routing review | More interfaces, cleanup and potential host/external traffic paths; direct veth capture violates Session's lo-only type | Not recommended for this Idle test |

Linux network namespaces isolate interfaces, stacks and the **abstract Unix
socket namespace**. This matters because this Helper uses abstract AF_UNIX,
not a filesystem socket. The repository additionally hashes network-namespace
inode into interface identity. A namespace cannot be treated as the old source.
These compatibility conclusions follow from code plus
[network_namespaces(7)](https://man7.org/linux/man-pages/man7/network_namespaces.7.html).

On this WSL kernel, the namespace handle exists and `ip`, `unshare`, `nsenter`
are installed. Namespace creation and WSLg inside another namespace were **not**
tested. Privileged network namespace creation/entry requires a reviewed
CAP_SYS_ADMIN path; loopback/veth interface configuration requires CAP_NET_ADMIN.
CAP_NET_RAW alone covers packet sockets, not that setup. The capture helper must
never receive the setup capabilities. See
[unshare(2)](https://man7.org/linux/man-pages/man2/unshare.2.html) and
[capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html).
No rootless user-namespace workaround is assumed to satisfy the existing UID,
capability and source contracts.

Current hard constraints include `Session.max_packets <=512`, Message
sequence/received/sent <=512, counter sequence <=2048, a session-sized bounded
transport queue, 128 packets per reconstructed flow, 128 live flow states,
Native request <=128 packet references, a 256-pending persistent queue and
10,000-source retention. A larger cap needs a reviewed end-to-end budget,
including counter messages and failure/stop paths. `live_session.py` is in the
Helper's pinned code bundle; even changing it while leaving `live_helper.py`
bytes unchanged changes the approved execution contract. No such edit was made.

## 5. CPU, memory and execution-time assessment

Saved Helper peak RSS is 196,161,536 bytes (187.07 MiB); CPU at READY is 3.469121 s
and at CLOSED 3.638013 s. The difference is 0.168892 s for this capture interval;
it excludes most interpreter/import startup. These are existing receipt metrics,
not a new performance benchmark. The current Helper limits remain 512 MiB
address space, 10 seconds process CPU, 60 seconds watchdog, 64 descriptors and
no core dumps. Address space is distinct from resident memory.

Saved Runtime process peak RSS is 289,730,560 bytes (276.31 MiB), process CPU
40.748973 s. Those are process-level values and do not isolate capture, GUI,
SQLite or other work. No bottleneck or linear scaling claim is made from them.
Transport high-water was 156 metadata records and drained to 0 without error.
The existing 512-record queue has at most 4 MiB encoded bodies at 8 KiB each;
Python objects/queues and temporary copies consume additional memory. An 8,192
record version would mean 64 MiB encoded bodies alone, before that overhead.
No larger queue or worker budget was allocated.

Quiet lo preserves current resource bounds. Raising the cap increases bounded
work and exposure, and could hit CPU/backpressure/source-retention constraints
before the deadline. A fresh lo-only namespace avoids the identified background
input by design, while adding a privileged setup/cleanup failure surface. No
measured CPU/RSS estimate for namespace setup or veth exists. Neither setup nor
model finalization should be confused with the Helper's capture watchdog. The
existing research worker separately limits address space to 3 GiB and CPU to
15 seconds, with adapter timeout at most 30 seconds per invocation. Those limits
are unchanged; no new worker RSS/latency measurement or inference occurred here.
A successful future two-model experiment adds real model work after capture;
namespace isolation does not remove those costs.

## 6. Recommended future manual scenario and approval scope

Prefer a **single disposable lo-only network namespace with co-located existing
components**, rather than enlarging the capture budget or adding veth. This is a
reviewable plan, not an executable bootstrap supplied or run in this task.
Before execution, review the fixed setup/entry/UID-drop/cleanup commands and
approve them separately. No runtime or Helper implementation is added here.

Proposed next approval scope:

1. Operator creates exactly one disposable network namespace, configures only
   its own lo as UP, and bounds the experiment lifetime to 180 seconds. Setup
   authority is short-lived and limited to creating/entering that namespace and
   changing its lo; no host NIC, firewall, DNS, route or persistent capability
   changes, no veth, NAT, bridge, external connection or dataset download.
2. Start the existing GUI/controller as the actual ordinary UID/GID (verify
   1000/1000 before use) **inside that namespace**, with zero effective/permitted/
   inheritable/ambient capabilities and a fresh private GUI data directory.
   Use existing `--data-directory` support; do not attach or modify historical
   operational databases. Root GUI is forbidden. WSLg filesystem display access
   must work without disabling access control or adding TCP forwarding; otherwise
   stop before capture. GUI startup must not start collection automatically.
3. Prepare a fresh session in the same namespace. Operator manually authenticates
   and starts the unchanged approved helper there, at most **one run**, lo only,
   <=60 seconds and <=512 received frames. Keep UID/GID, cleared supplementary
   groups, temporary CAP_NET_RAW only and socket-open capability drop checks.
4. After verified READY, use owned UDP sockets on 127.0.0.1 and ephemeral ports:
   three echo exchanges on 5-tuple A (six datagrams, <=64 non-sensitive bytes
   each); keep endpoints bound and silent for **31 seconds after A's last
   packet**; then one echo exchange on distinct 5-tuple B (two datagrams) to
   advance the watermark. Expected traffic allowance is about 16 raw loopback
   frames, not guaranteed. No DNS, scanning, arbitrary service traffic or injection.
5. Let normal helper CLOSED and bounded persistence/model drain finish. Do not
   click Stop to force eligibility. Any unexpected input, Drop, Counter UNKNOWN,
   source/audit failure or namespace/display mismatch aborts the experiment;
   inference remains blocked. Expect two model attempts for one eligible A flow,
   but verify receipts rather than assuming that outcome. Operational promotion
   stays forbidden; Research-only advisory and READ-only investigation only.
6. Close the owned GUI/helper/workers, retain metadata receipts/audit, and let the
   namespace holder exit. Operator verifies only owned processes/resources are
   gone. No unrelated process may be killed. If cleanup is uncertain, record it
   rather than removing unrelated host resources. Namespace lifetime depends on
   remaining processes/references, not just a named handle; see
   [ip-netns(8)](https://man7.org/linux/man-pages/man8/ip-netns.8.html).

This proposal requires new authorization because namespace/lo setup and new
traffic are expressly prohibited in the present task. Existing one-time capture
permission is not transferred. Capture isolation is not a security sandbox for
filesystem/credentials; the local trusted-user boundary remains. If privileged
namespace setup is declined, retain the original-namespace quiet-lo option and
first establish an acceptable background condition without stopping unrelated
processes. Do not simply repeat this saturated 512-frame run.

## 7. Integrity, tests and independent Export

Helper SHA256 remains
`a8a0cafe7494922a0296a250129ab5695b681dbbec6febf512509b023ef44856`.
Quality RF / Edge scaler-LR SHA256 remain respectively
`53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603` /
`661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882`.
Network14 v1.1.0 feature/configuration digests are recorded in the companion JSON;
no Producer or binary was modified or newly loaded for inference.

Final validation runs (not added together as unique coverage):

| Run | Command scope | Result |
|---|---|---|
| Final focused | `tests/unit/live_network/test_idle_budget.py` | 16 passed, 1.25 s |
| Final worktree regression | `tests/unit/live_network tests/unit/network_capture tests/unit/gui` | 298 passed, 25.34 s |
| Independent Export, final sources | Same regression scope | 298 passed, 20.56 s |

Each run used `--import-mode=importlib -q` under
`tests.native_capture_verification_guard`, with explicit `SOC_IDLE_BUDGET_SESSION`
pointing to this retained session. Each reports 0 prohibited packet/IPv4/IPv6
socket attempts, 0 failures, 0 errors and 0 skips. No model inference, actual
capture or traffic test was needed. Earlier development passes (16 focused and
298 regression) are not summed into these final results.

New tests cover independent integer/round-up arithmetic, missing/NaN/Inf/invalid
inputs, synthetic clone-frame exhaustion before Idle, packet-watermark behavior
and a later sentinel, refusal of >512 frames/>60 seconds/veth Session inputs,
Mock namespace identity mismatch, pinned Helper/artifact SHAs, sanitized manifest
integrity and complete retained-session file hash preservation. The namespace
identity change is a Mock; it does not create or enter a namespace. Existing
unit regressions retain counter/drop fail-closed, bounded transport, shutdown,
source integrity, eligibility, GUI state and operational-denial coverage.

Reproduce the focused read-only verification from repository root:

```bash
SOC_IDLE_BUDGET_SESSION="$HOME/.local/share/autonomous-soc-agent/gui/live-network/session-f360a55750ab48f0ba52098c5b2d0d91" \
.venv/bin/python -m tests.native_capture_verification_guard \
  --import-mode=importlib -q tests/unit/live_network/test_idle_budget.py
```

Ruff `check src tests`, `format --check .`, worktree/staged `git diff --check`:
PASS. The independent Export also passes Ruff and format checking. Its SOC and ML
source trees come from their baseline HEAD archives plus only the four task
files: this report, its sanitized JSON, `tests/native_idle_budget_support.py`,
and `tests/unit/live_network/test_idle_budget.py`. Existing trusted model paths
are referenced read-only for SHA verification; no model/DB/raw dataset binary is
copied into the Export. The final assessment exactly matches the digested JSON
in both worktree and Export. Test/source/Export/staged file SHA256 values are
compared before commit.

Preservation inventory: 120 original SOC dirty/untracked files, 10 ML files and
108 files in existing Native session directories retain their pre-task SHA256.
The original empty staging area was preserved until task-only staging. Helper,
model binaries, existing Native sessions, Raw Dataset and Final Demo evidence
are outside the change set. No ML change or ML commit is required.

## 8. Final decision

| Item | Result |
|---|---|
| CAPTURE_VERIFIED | PASS for retained actual kernel session only |
| FRAME_BUDGET_INSUFFICIENT | Confirmed: cap exhausted at 9.2758 s; future adequate budget UNKNOWN |
| ISOLATION | BLOCKED under current authorization; co-located design plausible, actual setup/WSLg UNKNOWN |
| NATIVE_IDLE_FLOW_PENDING | No timeout-eligible Native flow in this session |
| LIVE_AI_INFERENCE_PENDING | Quality/Edge Native receipts remain 0 |
| Operational AI | BLOCKED / NOT_INFERABLE / RESEARCH_ONLY / WRITE_DENIED preserved |

Capture and persistence success are not Live AI inference success. A new,
separately approved manual experiment and verified model/source/feature receipts
are still required. The future isolated result would validate controlled
namespace-local loopback research input, not physical NIC or production detection.

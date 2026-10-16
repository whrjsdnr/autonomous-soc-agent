# Native flow eligibility and Network research inference

Validation date: 2026-10-16. SOC baseline
`422a02efa8fb8867a3c7c202e183972317780655`; ML baseline
`e1a01260f0463a38d4d778859bc2a86f8e9cfbde`.

Overall: **PARTIAL — LIVE_INFERENCE_PENDING**. Timeout lifecycle, Network14
arithmetic parity, actual RF/LR inference on explicit synthetic FIXTURE input,
READ-only investigation, recovery and GUI presentation are verified below.
The retained Native session still has **zero model receipts**. This work ran no
privileged command, AF_PACKET capture, test network traffic, training or security
WRITE. Operational inference remains BLOCKED / NOT_INFERABLE.

## 1. Flow eligibility contract

The existing `FlowTable`, NetworkMonitor, queue/source stores, Producer v1.1.0,
isolated research workers and Orchestrator are reused. No timeout, feature,
model threshold, source authorization or producer contract is relaxed.

| Rule | Existing contract |
|---|---|
| Flow identity | Interface + protocol + bidirectional endpoint/port pair |
| Direction | First observed endpoint pair is forward; reversed endpoints are backward |
| Idle timeout | Next observed timestamp minus last flow packet >= 30 seconds |
| Active timeout | Next observed timestamp minus first flow packet >= 120 seconds |
| Timeout ordering | Expire before inserting boundary packet; ACTIVE has priority |
| Model lifecycle candidate | IDLE_TIMEOUT or ACTIVE_TIMEOUT only |
| Diagnostic exclusions | SHUTDOWN, PACKET_LIMIT, RESTART_GAP, unknown closure |
| Per-flow packet cap | 128; hitting it is diagnostic PACKET_LIMIT, not timeout eligibility |
| Request packet references | Unique committed references, 1–128; source/session/provenance verified |
| Producer span | Less than 120 seconds; adjacent gaps nonnegative and less than 30 seconds |
| Feature contract | Existing 14 names/order, float32, no imputation, finite values |

`FlowSummary` is explicitly diagnostic/incomplete in the existing schema. A
lifecycle candidate does not certify a complete physical conversation. The
Producer supports singleton/one-direction observed flows, including duration 0
and defined zero dispersion/IAT for a singleton. There is no existing minimum
duration or mandatory reverse-packet rule to invent. Missing committed packet
references, observed capture gaps, duplicate IDs and unordered timestamps remain
errors; absent observed reverse packets alone do not prove capture loss.

Native inference additionally requires authenticated READY/source binding,
verified zero-drop counter intervals, clean CLOSED, successful full persistence
finalization, audit integrity, source receipts, exact configuration and artifact
binding. An IDLE/ACTIVE label cannot bypass these gates. Producer experimental
capture quality `UNKNOWN` does **not** authorize an unavailable kernel counter:
kernel Counter UNKNOWN continues to block Native inference.

## 2. Retained actual Native session

Read-only target: `session-0f9e538dad3d4531bcc9e3e322cb3538`.
Internal capture session: `cf6000a7-3085-4948-b12c-bfb4a144e86b`.

READY/CLOSED and COUNTER_VERIFIED remain valid: kernel packets 516, received
frames 512, sent/stored metadata packets 256, drops 0, elapsed 5.032110403 s.
Finalization VERIFIED; 260 queue DONE (256 packet + 4 flow); 260 accepted source
records; SQLite checks passed. No unpersisted metadata packets were found.
The lifecycle gap count is 1; it is not a measured kernel packet drop.

| Flow digest prefix | Start UTC | End UTC | Duration s | Forward / backward | Closure / rejection |
|---|---|---|---:|---:|---|
| `2030577d6cbd` | 06:08:28.302621 | 06:08:33.292280 | 4.989659 | 37 / 45 | SHUTDOWN |
| `b00a20a1e248` | 06:08:28.302740 | 06:08:33.293594 | 4.990854 | 16 / 17 | SHUTDOWN |
| `accbf4301e9c` | 06:08:28.305721 | 06:08:33.301577 | 4.995856 | 35 / 34 | SHUTDOWN |
| `c4d561e8a89d` | 06:08:28.306051 | 06:08:33.301164 | 4.995113 | 36 / 36 | SHUTDOWN |

All timestamps above are on 2026-10-16. Total packets: 82 + 33 + 69 + 72 = 256.
Lifecycle eligible 0, excluded 4. No IDLE/ACTIVE boundary was reached before
capture completion. No historical flow was relabeled, no feature/model receipt
was inserted, and no historical investigation was invented.

Runtime audit digest:
`926664b1dba33e40689ce5ab300297df0317a6ac3507e84283204aac979826c1`.
Research audit/SQLite verification succeeds, but there are no model-linked
investigation checkpoints to restore in this Native session. The read-only
verifier reports database hashes unchanged. Worker shutdown/recovery and actual
inference are tested separately on FIXTURE sessions.

## 3. IDLE/ACTIVE fixture and independent reference

Synthetic packet bytes go through the SOC packet/flow path and the separate ML
offline PCAP parser/flow reconstruction path. Independent hand arithmetic provides
expected vectors; comparing two calls to the same Producer is not the reference.
A native-shaped timestamp declaration in a parity unit test is synthetic input,
not capture attestation. Actual model tests explicitly declare origin FIXTURE.

IDLE fixture: forward/reverse/forward at 0, 0.5, 1 s, IP lengths 40/60/80,
SYN/ACK/FIN; a packet at 31 s closes the old flow before entering the next one.
Expected fourteen values, rounded to float32:

```text
(1, 2, 1, 120, 60, 40, 80, 60, sqrt(800/3), 1, 1, 0, 0.5, 0.5)
```

ACTIVE fixture: alternating directions at 0/20/40/60/80/100 s; a boundary packet
at 120 s closes the old flow. Its feature duration is **100 s**, not 120 s, since
the boundary packet belongs to the next flow:

```text
(100, 3, 3, 180, 180, 40, 80, 60, sqrt(800/3), 1, 1, 0, 20, 20)
```

Both paths match all 14 hand-calculated float32 values. ACTIVE nanosecond
boundary −1/0/+1 and existing IDLE nanosecond tests protect segmentation. Origin
and source digests remain distinct even when arithmetic agrees. Native/offline
bytes are **IP length**, not Ethernet frame length: diagnostic flow frame-byte
counters must not replace Producer IP-byte inputs. TCP flags, endpoint direction,
event timestamps, ordering and configuration are preserved. This demonstrates
metadata/arithmetic parity for these fixtures, not physical NIC/offload parity.

Feature order (unchanged): `duration_seconds`, `forward_packet_count`,
`backward_packet_count`, `forward_ip_bytes`, `backward_ip_bytes`, `ip_length_min`,
`ip_length_max`, `ip_length_mean`, `ip_length_population_std`,
`tcp_syn_packet_count`, `tcp_fin_packet_count`, `tcp_rst_packet_count`,
`iat_mean_seconds`, `iat_max_seconds`.

Feature contract SHA256:
`84ba0916f0ce4e9e12bb70712db2cd1eaea84ba4173acd57b647faf38efb1c6e`.
Producer configuration SHA256:
`7999723911ce3d2e9cd3b3b6e0d45e11f44b1316cdf9c7f4883d7e2a69ca21a7`.
Producer version remains 1.1.0; ML source and feature contract are unchanged.

## 4. Actual research models, advisory and investigation

Trusted existing local artifacts are SHA-verified before isolated worker loading:

| Model | Artifact SHA256 | Threshold |
|---|---|---:|
| Quality RF | `53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603` | 0.35 |
| Edge scaler + LR | `661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882` | 0.8 |

Model IDs are `linux-network14-research-v1-quality_rf` and
`linux-network14-research-v1-edge_lr`. Artifact binaries remain outside Git.

| Explicit FIXTURE | Quality score / prediction | Edge score / prediction |
|---|---|---|
| IDLE_TIMEOUT | 0.140625 / CLASS_0 | 0.08766025304794312 / CLASS_0 |
| ACTIVE_TIMEOUT | 0.5859375 / CLASS_1 | 0.9785099029541016 / CLASS_1 |

These are actual model outputs, **uncalibrated scores**, not verified malicious
probabilities or actual Live findings. UUID/source/feature digests can differ
between independent fixture runs; fixed arithmetic and scores are compared.
Each integration case persists its own source/feature-bound receipts for both
models, Research Advisory, ASSESSED_READ_ONLY investigation, assessment and audit.
Checkpoint restoration succeeds with provider calls 0; the synthetic assessment
has no operational observations. Restarting the research service returns
CACHED_NO_NEW_INFERENCE for both replay keys, retains identical records, and
leaves no worker process. Tail SHUTDOWN flows generate no receipt.

## 5. GUI and lifecycle visibility

The existing backend now exposes committed per-session flow counts: timeout
candidates, excluded flows, pending flows and closure reasons. DONE timeout flows
count as candidates; PENDING/CLAIMED remain pending; POISON is excluded. Missing
session/data returns UNKNOWN, not zero. Source generation/interface/digest checks
reject mixed-session or malformed events. Counts are expressly lifecycle-only;
full capture/persistence/producer gates still decide inference authorization.

Live Network displays `Eligible (timeout only)`, `Excluded`, `Pending` and
`Finalization` from backend values. Actual WSLg tests show the retained Native
session as eligible 0 / excluded 4, models with no successful live inference.
A separate explicit FIXTURE GUI test renders actual RF/LR receipts (1 each),
retained/IDLE worker state, READ-only investigation and verified audit. It does
not label those results Live. The existing one-command GUI entrypoint is unchanged:

```bash
.venv/bin/python -m soc_agent.gui
```

## 6. Native scenario feasibility and next user approval

**ACTIVE_TIMEOUT is impossible within the existing 60-second capture limit**;
it needs at least 120 seconds from first packet. Only its fixture semantics are
verified here. No larger capture limit is implemented or authorized.

IDLE_TIMEOUT requires an observed packet after 30 seconds of silence for the
specific flow. The helper watermark follows delivered event timestamps, not the
processor wall clock. Waiting alone followed by SHUTDOWN is insufficient.

A bounded, user-executed candidate within lo / 60 s / 512 received frames is:

1. Prepare a fresh GUI session; verify actual listener and helper READY. Use the
   existing manually authenticated helper only after explicit user approval.
2. Use owned UDP sockets on 127.0.0.1 and ephemeral ports: one echo 5-tuple A and
   a distinct echo 5-tuple B. Keep ports bound; create no external/DNS traffic.
3. After READY, perform three echo exchanges on A (six datagrams), each payload
   at most 64 non-sensitive bytes. Then remain silent on A for 31 seconds after
   its last packet.
4. Perform one echo exchange on B (two datagrams). Its timestamps act as the
   sentinel that expires A. Total: four exchanges/eight datagrams. Allow helper
   normal CLOSED and queue/model finalization before stopping the GUI.
5. Keep the hard 60-second/512-frame limits. Explicit GUI Stop still cancels
   inference; drop, unknown counter or persistence/audit failure still blocks it.

This is a **design only**; no traffic script, helper or capture was executed by
Codex. It requires separate user approval for these new owned-loopback exchanges
and manual execution in a new session. The helper's existing SHA is unchanged:
`a8a0cafe7494922a0296a250129ab5695b681dbbec6febf512509b023ef44856`.
No prior one-time capture permission is assumed to cover another execution.

The current environment is a blocker to guaranteeing this scenario. Read-only
netdev counters over 10.001341506 s increased lo RX and TX by 1,972 packets each
(about 197.17/s); no traffic was generated for this measurement. Netdev counters
are **not AF_PACKET counters** and cannot certify capture drop or exact frame
multiplication. Typical loopback clones could consume about 16 frames for the
proposed traffic, but actual framing is not promised. Background traffic also
consumes the 512-frame budget. A conservative full-window budget would require
raw background rate below roughly (512−16)/59 ≈ 8.4 frames/s, with safety margin.
The current netdev observation does not establish that condition. User-owned
background traffic must be understood before a new manual run; this work stops
no user process and changes no NIC/firewall setting. A new failure may still be
safe but ineligible SHUTDOWN. Therefore NATIVE_SCENARIO_READY is conditional design
readiness, **not verified feasibility in the present busy environment**.

## 7. Regression, independent Export and preservation

Current worktree and clean Export were run independently, with packet/IPv4/IPv6
socket creation denied by `tests.native_capture_verification_guard`. All six
final runs report 0 attempted prohibited sockets, 0 failures, 0 errors and 0
skips. No inference is counted as Native. Prior long-regression results are not
reused as current results.

| Final run | Worktree | Independent Export |
|---|---|---|
| Live Network + Network Capture | 228 passed, 87.28 s | 228 passed, 91.14 s |
| GUI + Research Adapter + Linux Runtime | 154 passed, 65.69 s | 154 passed, 65.69 s |
| Actual WSLg GUI checks | 3 passed, 26.69 s | 3 passed, 26.05 s |

The first suite covers `tests/unit/live_network`, `tests/integration/live_network`
and `tests/unit/network_capture`. The second covers `tests/unit/gui`,
`tests/integration/gui`, `tests/unit/research_adapter`,
`tests/integration/research_adapter` and `tests/integration/linux_runtime`.
WSLg checks are `tests/gui_flow_eligibility_checks.py`,
`tests/gui_native_session_verification_checks.py` and
`tests/gui_live_network_checks.py`; the retained-session opt-in selects exactly
the Native session in section 2. All commands use `--import-mode=importlib -q`.

New coverage includes IDLE/ACTIVE segmentation and hand references, timeout
boundaries, SHUTDOWN/short-flow semantics, missing reverse references,
duplicate/unordered packets, capture gap/counter UNKNOWN/drop denial,
per-session DONE/PENDING/CLAIMED/POISON display, real RF/LR fixture workers,
advisory/checkpoint/replay recovery, and WSLg source/receipt/state accuracy.
Earlier focused development runs passed 19 and 18 cases respectively; they are
not added to final suite totals.

Worktree `ruff check src tests`: PASS; `ruff format --check .`: PASS;
`git diff --check`: PASS. Export Ruff/check-format: PASS (unrelated uncommitted
files are absent). No ML files were changed.

The Export consists of both repositories' baseline Git archives plus exactly
this task's 10 SOC files. No existing user edits or Reliability Replay are
included. Existing trusted external artifact/interpreter references are explicit;
no model binary or Native DB is copied into the Export. Clean ML source from its
HEAD is used for Producer loading. Both IDLE/ACTIVE actual-model fixture outputs
match the worktree's pinned model IDs, origins, thresholds, predictions and
scores. Source UUIDs/digests and latency can differ across runs. The actual Native
session is referenced read-only by both WSLg checks and remains receipt-free.

Changed files: `research/live_input.py` (shared unchanged timeout policy),
`research/live_service.py` (read-only lifecycle counts),
`research/live_evidence.py` (verification counts), `gui/live_view.py` (backend
metrics), `tests/live_flow_eligibility_support.py`, unit/integration
`live_network/test_flow_eligibility.py`, `tests/gui_flow_eligibility_checks.py`,
`tests/gui_native_session_verification_checks.py`, and this report.

Preservation check: all 120 pre-existing SOC dirty/untracked files, all 10 ML
files and all 94 files in existing Native session directories match their initial
SHA256 inventories. The original index was empty and remained unchanged until
selective task staging. Helper SHA and both model binary SHAs remain exactly as
listed above. Raw datasets, operational DBs and Final Demo evidence are outside
the change set. All task sources are compared byte-for-byte with the Export and
selectively staged blobs before commit; no ML commit is needed.

## 8. Verdict and remaining blockers

| Item | Result |
|---|---|
| FLOW_ELIGIBILITY_VERIFIED | PASS for unchanged lifecycle/source gates |
| IDLE_TIMEOUT_VERIFIED | PASS, fixture and boundary tests |
| ACTIVE_TIMEOUT_VERIFIED | PASS, fixture only; infeasible under 60 s Native scope |
| NETWORK14_PARITY_VERIFIED | PASS for synthetic packet metadata and hand references |
| QUALITY_FIXTURE_INFERENCE_VERIFIED | PASS, actual pinned RF artifact |
| EDGE_FIXTURE_INFERENCE_VERIFIED | PASS, actual pinned scaler/LR artifact |
| INVESTIGATION_VERIFIED | PASS, explicit FIXTURE READ-only advisory/checkpoint |
| NATIVE_SCENARIO_READY | Design prepared; current background-budget feasibility BLOCKED |
| LIVE_INFERENCE_PENDING | Native receipts remain 0; fresh approved manual run required |
| OPERATIONAL_GATE_BLOCKED | Preserved; RESEARCH_ONLY / NOT_INFERABLE / WRITE_DENIED |

Physical Linux NIC/offload/capture completeness, generalization, calibration and
operational promotion remain unverified. No retraining, DNS9 Producer promotion,
model artifact replacement or automatic security response is included.

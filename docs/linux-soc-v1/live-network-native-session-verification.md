# Native Live Network session verification

Validation date: 2026-10-16. SOC source HEAD:
`fcff821fdd8f1ac5cee76b4e53baa7ccfc938d7a` (matches the requested baseline).
ML HEAD: `e1a01260f0463a38d4d778859bc2a86f8e9cfbde`, unchanged.

**Overall E2E: PARTIAL.** Actual native capture, complete metadata delivery,
persistence and finalization are verified. Quality/Edge inference, advisory,
investigation and model-checkpoint recovery are **BLOCKED**: this session has
no eligible completed research flow and no model receipt. No product code change
or policy relaxation is needed to explain that outcome.

Machine-readable summary:
[live-network-native-session-evidence.json](live-network-native-session-evidence.json).
It includes the original database SHA256 values and a canonical manifest digest,
without packet values, endpoint identities, credentials or personal paths.

## 1. Session identity and preservation

Supplied directory:
`~/.local/share/autonomous-soc-agent/gui/live-network/session-0f9e538dad3d4531bcc9e3e322cb3538`.
Internal session UUID: `cf6000a7-3085-4948-b12c-bfb4a144e86b`.
All 14 files were hashed before inspection and remained unchanged after
verification, GUI checks, regressions and independent Export. No recovery writer,
queue replay, raw capture, test IP traffic or native-session inference was run.

Existing user edits and Reliability Replay were excluded from this work. Both
repositories' initial indexes were empty and preserved until selective staging.
No ML changes, model copies, installations or binary modifications were made.

## 2. Capture and counter integrity

| Item | Actual saved result |
| --- | --- |
| Source origin / interface | NATIVE_AF_PACKET / lo |
| Approved/current helper SHA256 | `a8a0cafe7494922a0296a250129ab5695b681dbbec6febf512509b023ef44856` |
| Session bounds | 60 seconds / 512 receive frames |
| READY / CLOSED | Present; session and receipt digests bound to runtime audit |
| READY / final accepted counter sequence | **1 / 524** |
| Counter status / recorded counter issue | COUNTER_VERIFIED / null |
| Cumulative kernel packets / capture drops | **516 / 0** |
| Received frames / sent parsed packet metadata | **512 / 256** |
| Elapsed | **5.032110403000843 seconds** |
| Helper error | null |
| Capability state at READY and CLOSED | UID/GID 1000; CapEff/Prm/Inh/Amb 0; CapBnd 8192; NoNewPrivs 1 |
| Original helper process, current read-only check | Not present |
| Session abstract Unix socket, current check | Not present |

The saved session, code bundle, interpreter identity, capability receipts,
runtime counter projection and helper audit bindings are consistent. This is
verification of retained **local-chain evidence**, not fresh process attestation
or a new privileged capture. No standalone heartbeat history exists, so the
sum of every individual reset interval cannot be independently replayed. The
receiver's retained accepted sequence/cumulative state and final receipt agree.

Kernel packet arrivals, frames actually received before the frame cap, and
filtered outgoing metadata are different accounting domains. **516 − 512 is
not a drop measurement**, and 512 − 256 is not lost metadata. The exact identity
of the four extra kernel-counted packets is not retained; no explanation beyond
the observed accounting domains is asserted. The verified drop counter is zero.

## 3. Transport, persistence and duplicate checks

| Item | Verified value |
| --- | ---: |
| Sent / delivered / stored packet metadata | **256 / 256 / 256** |
| Transport staging remaining / high-water / capacity | **0 / 208 / 512** |
| Reader running / reader error | false / null |
| Final counter verified | true |
| Packet event Source sequences | Contiguous **1–256** |
| Duplicate packet Source digests / observation keys | **0 / 0** |
| Stored Flow records | **4** |
| Durable Queue | **260 DONE** |
| PENDING / CLAIMED / POISON | **0 / 0 / 0** |
| Operational Source records | **260 ACCEPTED** |
| Queue backlog / runtime last error | **0 / null** |
| Finalization / runtime state | **VERIFIED / STOPPED** |
| Runtime lifecycle gap count | **1** |

The queue schema uses POISON for exhausted/rejected work, not a FAILED status.
The absence of `transport-unprocessed.json` is recorded but **not used as proof
of persistence**. The evidence is the exact sent/delivered/persisted count match,
decoded event identities, individual Source/provenance resolution, queue outcomes
and audit records. A duplicate observation key here means identical kernel
timestamp, frame digest and direction; identical bytes at different timestamps
are not automatically treated as invalid retransmissions.

Each of the four Flow summaries was rebuilt from its stored packet references
using the existing Flow validator and matched its stored statistics. References
cover all 256 packets exactly once, with zero duplicate Flow references. This
is storage/reconstruction validation, not a new independent training Golden Pair.

All seven SQLite databases returned `integrity_check = ok`:

- `runtime/network/sources.sqlite`: 260 accepted Sources.
- `runtime/network/queue.sqlite`: 256 packet and 4 Flow events, all DONE.
- `runtime/sources.sqlite`: 0 authentication Sources in this Network session.
- `runtime/queue.sqlite`: 0 authentication events.
- `runtime/monitor.sqlite`: valid state/audit and 0 operational Findings.
- `runtime/collection-audit.sqlite`: 0 authentication maintenance events.
- `network-research/soc/external-validation.sqlite`: valid initialized research
  ledger, with 0 model receipts, contexts, assessment runs and workflow checkpoints.

Every durable Network queue outcome remains
NOT_INFERABLE / DIAGNOSTIC_ONLY / WRITE_DENIED. One start/restart lifecycle gap
records the absence of kernel replay across sessions; it is not one dropped
packet or a failure of this session's persistence.

## 4. Flow completion and finalization

All four Flow close reasons are **SHUTDOWN**. Their packet totals are
**82, 33, 69 and 72**, summing to 256. Durations are respectively 4.989659,
4.990854, 4.995856 and 4.995113 seconds. There are **0 IDLE_TIMEOUT** and
**0 ACTIVE_TIMEOUT** flows eligible for research inference.

The helper reached its 512-frame budget after about five seconds. The receiver
drained all accepted metadata through the existing queue, committed Sources,
finalized the four open tails as diagnostic SHUTDOWN summaries, verified counts
and audit, then recorded NETWORK_CAPTURE_FINALIZED. The finalization audit entry
binds this session generation, 256 packets, 4 flows and
ELIGIBLE_TIMEOUT_FLOWS_ONLY. No collection-blocked event is present.

The Producer's existing 30-second idle / 120-second active policy was not reached
by the observed packet-time progress. Waiting for slow persistence or reading
these records later cannot turn five seconds of captured traffic into a complete
idle window. Capture termination and complete training-compatible Flow semantics
are separate. The finalization fix correctly preserved these tails as diagnostic
instead of manufacturing eligibility.

## 5. Producer and actual model status

Producer v1.1.0, Network14 feature names/order, float32 dtype, source/configuration
contracts and pinned package source identities passed read-only preflight.
Feature contract digest:
`84ba0916f0ce4e9e12bb70712db2cd1eaea84ba4173acd57b647faf38efb1c6e`.
Producer configuration digest:
`7999723911ce3d2e9cd3b3b6e0d45e11f44b1316cdf9c7f4883d7e2a69ca21a7`.
The preflight API's generic OFFLINE_PCAP description is not evidence of input
origin; actual packet, generation and Source records establish NATIVE_AF_PACKET.

| Model | Actual artifact verification | Native session receipt/result |
| --- | --- | --- |
| Quality RF, `linux-network14-research-v1-quality_rf` | SHA256 `53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603` | **0 / BLOCKED**, score and prediction UNKNOWN |
| Edge scaler + LR, `linux-network14-research-v1-edge_lr` | SHA256 `661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882` | **0 / BLOCKED**, score and prediction UNKNOWN |

Verification hashed trusted local artifacts/manifests without deserializing or
calling them for this native session. Artifact integrity does not prove execution.
There are no Producer Feature Vector receipts, model attempt/receipt files,
advisory contexts, investigations or native model checkpoints in this session.
READ-only Investigation is therefore **BLOCKED**, not a zero-risk assessment.
Existing Artifact and model IDs were preserved; operational model promotion
was not attempted.

## 6. GUI consistency

An opt-in actual WSLg test launched the existing Command Center in a private test
directory and explicitly selected a **read-only retained view of this exact
session** through test composition. It did not attach or control the operator's
existing GUI process, start collection, invoke a replay, or select another session
by modification time. The test ran at 1920×1080 and 1366×768.

Verified displayed text: Packets 256, Flows 4, Drops 0, Gaps 1, Queue 0;
Quality and Edge IDLE / confirmed 0 / unknown 0; Last error NONE_RECORDED;
Audit VERIFIED. Input origin and generation match the selected native session.
The page has no advisory rows or executable helper command and shows
RETAINED_SESSION_NOT_LIVE, no active helper/listener and operational inference
blocked. Retained rates become UNKNOWN rather than current live traffic rates.

Finalization VERIFIED is present in the backend snapshot but **does not currently
have a dedicated visible label** on the existing Live page. The page's Audit
label describes research-ledger integrity; the Network audit chain was checked
separately. These presentation limits are documented rather than expanded in
this verification task. No history from a different session or Fixture model
result was imported into the selected view.

## 7. Audit and retained-state recovery

Runtime audit head:
`926664b1dba33e40689ce5ab300297df0317a6ac3507e84283204aac979826c1`.
CLOSED receipt audit binding:
`fbd3eae6f25c738af2ba5d3178e8530ea993b312a58d89a8b0270d1860ef0021`.

There are 266 chained audit entries: 260 NETWORK_SOURCE_COMMITTED entries and
one each for initialization, configuration, helper verification, start gap,
finalization and helper closure. State digest, Source provenance and audit chain
verify. The persisted reader is stopped, queue/staging are empty, the original
helper process is absent and its abstract Unix socket is gone.

A freshly constructed retained-state owner returned the same session, Network
state and empty model record list, without creating a capture/task/worker or
changing any of the 14 files. This verifies read-only reopen/state restoration.
There is **no native model receipt/checkpoint to recover or replay**, so native
model checkpoint recovery and duplicate-inference replay remain unexercised.
The combined AUDIT_RECOVERY E2E criterion is consequently BLOCKED, even though
audit integrity and retained queue/state restoration pass. Fixture recovery
regressions are reported separately and cannot fill that evidence gap.

## 8. Tests, Export and reproducibility

Current executions, with no duplicated aggregation:

| Invocation | Result |
| --- | --- |
| Live Network unit/integration + Network Capture unit | **208 passed**, 84.92 s |
| GUI / Research Adapter unit/integration + Linux Runtime integration | **154 passed**, 72.11 s |
| WSLg selected native retained-state check + existing live-page lifecycle check | **2 passed**, 20.72 s |
| Independent clean Export: selected native retained-state GUI check | **1 passed**, 5.79 s |
| Independent Export: saved-session verifier | Same PARTIAL verdict, all counts, audit and DB SHA values exactly match |
| Ruff check src tests / format --check . / git diff --check | PASS |

Existing regressions use isolated Fixtures, including actual model binaries for
their separate Fixture inference tests. Their invocations are not native receipts
for this session. All guarded invocations reported **0 attempted AF_PACKET,
AF_INET or AF_INET6 socket creations**. Ordinary AF_UNIX fixture IPC is allowed.
No native capture, privilege command, IP test traffic, security WRITE or native
session re-inference occurred.

The Export consists of committed SOC/ML HEAD plus only this task's report,
sanitized manifest and opt-in verification test. It excludes user modifications,
Reliability Replay, raw datasets, operational databases and model binaries.
Existing session files/artifacts are explicitly referenced read-only. Since no
product code changed, the Export repeats the new retained-session verification
rather than the full long-running Fixture suites.

Reproduce read-only CLI verification (PARTIAL / exit 1 is the expected outcome):

```bash
.venv/bin/python -m soc_agent.security_ai.research.live_evidence \
  --directory "$HOME/.local/share/autonomous-soc-agent/gui/live-network/session-0f9e538dad3d4531bcc9e3e322cb3538"
```

Opt-in GUI evidence comparison, with no capture or replay:

```bash
SOC_NATIVE_SESSION_VERIFY_DIRECTORY="$HOME/.local/share/autonomous-soc-agent/gui/live-network/session-0f9e538dad3d4531bcc9e3e322cb3538" \
  .venv/bin/python -m tests.native_capture_verification_guard --import-mode=importlib -q \
  tests/gui_native_session_verification_checks.py
```

## 9. Final decision and remaining blocker

| Criterion | Verdict |
| --- | --- |
| Capture | **CAPTURE_VERIFIED** |
| Saved counter consistency | **COUNTER_VERIFIED** |
| Transport | **TRANSPORT_VERIFIED** |
| Persistence | **PERSISTENCE_VERIFIED** |
| Finalization | **FINALIZATION_VERIFIED** |
| Quality actual native inference | **BLOCKED** |
| Edge actual native inference | **BLOCKED** |
| Native advisory / investigation | **BLOCKED** |
| Native model audit/checkpoint recovery | **BLOCKED** |
| Overall actual native E2E | **PARTIAL** |

The remaining blocker is **zero eligible timeout-complete research Flows**, not
the missing-unprocessed-file heuristic or another persistence failure. The
session's SHUTDOWN tails are preserved and are not forcibly inferred. A future
user-authorized capture would need observed packet-time progress producing an
eligible complete Flow under the existing limits and Producer contract. No new
capture or parameter change is authorized or scheduled by this report.

RESEARCH_ONLY / NOT_INFERABLE / OPERATIONAL_INFERENCE_BLOCKED /
DIAGNOSTIC_ONLY / WRITE_DENIED remain in effect. Capture/persistence success does
not approve an operational model or establish detection performance.

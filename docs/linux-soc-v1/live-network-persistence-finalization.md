# Verified capture persistence and research finalization

Date: 2026-10-16. SOC baseline:
`820fa37471aa3504e78e7e9df87972354b6d2a93`.
ML HEAD: `e1a01260f0463a38d4d778859bc2a86f8e9cfbde`, unchanged.

**Overall: PARTIAL.** The user's saved capture is verified, but only 240 of
256 sent metadata packets were durably stored. The remaining 16 packet values
are absent from saved evidence. This task preserves the session read-only,
fixes future finalization, and verifies actual research binaries on explicit
FIXTURE input. It does not establish actual live model inference for this session.

## 1. Actual capture evidence

Directory: `~/.local/share/autonomous-soc-agent/gui/live-network/session-959024515d9f4c5ba99afd888b72a57e`.
Internal session UUID: `851f8675-595c-4865-a2d9-3dc24f766715`.
All 15 existing session files were hashed before inspection and preserved.

Approved and current helper SHA256:
`a8a0cafe7494922a0296a250129ab5695b681dbbec6febf512509b023ef44856`.
The helper and its approved source bundle were not modified.

| Saved evidence | Result |
| --- | --- |
| READY / CLOSED | Both present, session/READY/CLOSED digests bound to runtime audit |
| Counter sequence | READY 1; final accepted CLOSED **514**; no recorded counter issue |
| Final counter status | COUNTER_VERIFIED |
| Cumulative kernel packets / capture drops | **512 / 0** |
| Received frames / sent parsed metadata | **512 / 256** |
| Capture elapsed | **1.0797787780011276 s** |
| Helper error | null |
| Capability state at READY and CLOSED | UID/GID 1000; CapEff/Prm/Inh/Amb 0; CapBnd 8192; NoNewPrivs 1 |
| Reader error / final counter verification | null / true |
| Transport delivered / buffered / high-water | **240 / 16 / 240** |
| Unprocessed receipt reason | EXPLICIT_STOP_BEFORE_PERSISTENCE (historical generic cleanup label) |
| Runtime final state | DEGRADED / NOT_READY, **StorageError** |
| Source/queue packet records | **240 packets**, all DONE and source/provenance validated |
| Source/queue flow records | **5 flows**, all DONE and source/provenance validated |
| Queue backlog / poison | 0 / 0 |
| Operational Source records | **245 ACCEPTED** |
| Research model receipts / investigations | **0 / 0** |
| SQLite integrity | All **7** databases: ok |

Kernel packets, loopback receive frames, outgoing parsed metadata, and Source
records are different accounting domains. The helper filters the observed input
before sending metadata; 512 kernel frames and 256 sent metadata records do not
imply 256 drops. The verified CLOSED reports zero drops. The degraded monitor
conservatively stores `capture_drops = null` after a processing failure; this
does not overwrite or invalidate the separate saved kernel counter receipt.

The original 240 packet event identities and content digests were decoded and
their persisted Sources/provenance independently resolved by the read-only
saved-evidence verifier. Thus **240 committed** is established, rather than
inferred from the `delivered_packets` metric. Generally, dequeue/delivery can
precede enqueue or Source Commit; a failure after dequeue need not be persisted.

Audit head:
`74386769863759d1ce51e2d2a812cf19eb9422324253cf152505a8bafa4f7e36`.
There are 245 NETWORK_SOURCE_COMMITTED records, plus initialization,
configuration, verified helper binding, start gap, collection-blocked and
helper-closed entries. CLOSED's audit digest is
`538899559b73cb3a60dc63a2633dd7ca8df2c99fc8e31d1b6415dff44b1ba607`.
Runtime state digest and audit chain verify. These are local-chain bindings,
not independent remote attestation.

## 2. Actual interruption and lifecycle root cause

The last Source Commit is at 05:45:30.477490 UTC; the collection-blocked event
is at 05:45:35.929485 UTC with reason **StorageError**. It occurs before the
helper-closed audit event. The monitor had accepted the clean CLOSED already,
but still had 16 packet objects in the in-memory transport staging buffer.
The persistent EventQueue contained no PENDING packets: those 16 never reached
the durable queue or Source Store. No saved packet bodies or worker request
files contain them. A count-only unprocessed receipt cannot reconstruct them.

The old cleanup unconditionally labeled buffered data
EXPLICIT_STOP_BEFORE_PERSISTENCE even when cleanup followed a storage failure.
That label is **not evidence that the operator pressed GUI Stop**. No separate
GUI Stop audit record or underlying SQLite error code survives. No helper
timeout, frame limit error or unexpected reader exit is recorded here.

Two concrete processing defects were identified:

1. **Processor wall time was used as a flow expiration clock while older packet
   metadata remained queued.** The five retained flows have packet counts
   124, 55, 52, 4 and 5 (total 240), durations 0.006–0.963 s, yet all were closed
   as IDLE_TIMEOUT after slow persistence crossed the 30-second wall-time bound.
   The pending 16 packets can still belong to those connections. These historical
   flow slices cannot be promoted as complete Producer inputs.
2. **Native source authorization retained an outer queue read transaction while
   calling nested packet/provenance reads.** A concurrent writer cannot complete
   its commit while that read lock remains. An isolated real-SQLite test reproduces
   SQLITE_BUSY under that retained-read policy and verifies writer completion
   when the outer read is released first. Model/source validation also previously
   ran concurrently with continued packet persistence.

The saved approximately 5.45-second interval is consistent with a configured
five-second database busy timeout, but the original StorageError discarded its
cause. **The historical SQLite sub-error and exact failing operation remain
UNKNOWN.** The lock fixture establishes a defect/risk, not proof of which
database operation failed in the user's execution. Future storage error records
retain a sanitized SQLite error name, without paths or exception text.

## 3. Safe finalization contract

```text
Authenticated READY → existing bounded reader → existing metadata staging
  → clean CLOSED (collection no longer LIVE; no new helper/reconnect)
  → drain all accepted metadata through existing persistent queue
  → commit Sources/provenance and remaining diagnostic flows
  → verify terminal counts, queue completion and audit
  → NETWORK_CAPTURE_FINALIZED / finalization=VERIFIED
  → eligible timeout-flow Producer v1.1.0 → isolated research workers
  → advisory / READ-only investigation / research audit
```

The helper's frame/time bounds and protocol are unchanged. Finalization requires
the receiver's existing ordered counter validation, no drop/reader error, clean
CLOSED, sent metadata count matching received sequence and delivered count,
empty transport staging, bounded received frame/time fields, zero pending/claimed/
poison durable records, per-session persisted packet count reconciliation, and
verified audit. Missing counts or a count mismatch cannot approve inference.

Metadata processing uses the last delivered packet timestamp as its expiration
watermark, rather than advancing by storage-processing wall time. Packet-driven
idle/active expiration retains the existing 30/120-second policy. In an idle
capture with no newer packet, expiration may be deferred; wall-clock silence
after bounded capture ended is never invented as observed traffic continuity.
Feature meanings, direction, 14-feature order/dtype and Producer v1.1.0 contracts
are unchanged.

Open tails are still finalized as **SHUTDOWN diagnostic/incomplete** flows.
PACKET_LIMIT and RESTART_GAP flows remain diagnostic too. Only the existing
eligible IDLE_TIMEOUT/ACTIVE_TIMEOUT flows, closed using observed packet-time
progress, can reach the research Producer. A clean CLOSED does **not** make an
arbitrary capture-end slice complete. No zero padding or contract relaxation is
introduced to obtain a model result.

The existing pending research consumer now starts only after successful monitor
finalization; it does not run model/source checks during packet persistence.
Authorization releases its outer queue read transaction before nested validation
and additionally rejects cancellation, service errors or absent finalization.
The existing bounded pending references, worker budgets, circuit breaker and
duplicate-request ledger are reused. No second runtime or persistent queue exists.

Explicit GUI Stop still cancels, rejects further receive and does not drain the
unpersisted staging buffer for inference. Cleanup now distinguishes
PERSISTENCE_OR_FINALIZATION_FAILED from explicit cancellation and clean
CAPTURE_FINALIZED. Missing final counters, drops, corruption, incomplete durable
drain or failed persistence remain BLOCKED. Final durable drain has a queue-capacity
bound. There is no automatic retry/reconnect, lost-packet reconstruction, source
restamping or exactly-once guarantee across separate databases.

## 4. Fixture and actual-model validation

All new executions are isolated, ordinary-user tests. AF_UNIX synthetic metadata
tests explicitly substitute helper attestation and do not establish a real
capture. The completed synthetic frame-budget case sends 256 metadata packets
with a 512 received-frame terminal count: **256 delivered, zero staged remaining,
258 DONE** (256 packets + two PACKET_LIMIT diagnostic flows), verified audit and
no premature IDLE_TIMEOUT flow. No model is invoked for those incomplete slices.

A separate explicit **FIXTURE** flow has a genuine packet-time idle boundary
followed by an incomplete tail. It verifies four committed packets, one eligible
flow and one SHUTDOWN flow; only the eligible flow enters the actual model workers.

| Model | Artifact SHA256 | Fixture worker result |
| --- | --- | --- |
| Quality RandomForest | `53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603` | Actual receipt, RESEARCH_ONLY, CLASS_1; score 0.4375; threshold 0.35 |
| Edge scaler + LogisticRegression | `661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882` | Actual receipt, RESEARCH_ONLY, CLASS_0; score approximately 0.74248; threshold 0.8 |

These are uncalibrated research scores, not proven malicious probabilities.
The initial isolated integration invocation produced one receipt per profile,
both with 14 float32 Producer features, source/feature/provenance bindings and
ASSESSED_READ_ONLY investigation. Checkpoints restored successfully. Restarting
the research ledger returned CACHED_NO_NEW_INFERENCE for both profiles, keeping
the receipt count at two. Later regression/Export invocations use their own new
isolated directories; their model calls are not added to the actual user session.

A separate mock-model service fixture verifies the scheduling order: dispatch
occurs only with finalized persistence, empty staging and verified audit. Mock
dispatch is not included as actual model evidence. Worker crash/timeout and
duplicate replay rejection are covered by the existing adapter integration tests.

## 5. Tests and independent Export

Each row is a separate invocation; overlapping cases are not summed.

| Invocation | Result |
| --- | --- |
| Initial five new persistence/actual-model integration cases | 5 passed, 46.86 s |
| SQLite lock-policy cases | 2 passed, 5 deselected, 1.55 s |
| Lock-policy + service dispatch order | 3 passed, 5 deselected, 2.34 s |
| New completion/count/watermark unit cases | 7 passed, 0.54 s |
| Existing Live Network/Capture regression before final combined run | 193 passed, 24.36 s |
| Final Live Network unit/integration + Network Capture unit | **208 passed, 88.64 s** |
| GUI / Research Adapter unit/integration + Linux Runtime integration | **154 passed, 74.66 s** |
| WSLg GUI prepare/copy/stop/restart/navigation/close, no capture | **1 passed, 15.03 s** |
| Independent SOC/ML Export: Live/Capture | **208 passed, 84.91 s** |
| Independent Export: GUI/Research/Runtime | **154 passed, 60.13 s** |
| Independent Export: WSLg GUI | **1 passed, 10.00 s** |
| Ruff check src tests / format --check . / git diff --check | PASS |

The new cases exercise clean CLOSED, the 512-frame budget, explicit cancellation,
full drain, a dequeue followed by persistence failure, corrupted audit, missing/
mismatched terminal counts, event-time expiration, deferred research scheduling,
actual model receipts and duplicate recovery. Existing suites additionally cover
positive drops, counter sequence failure, duplicate packets, backpressure, worker
crash/timeout, listener cleanup and GUI/gate accuracy. All guarded invocations
report zero attempted AF_PACKET/AF_INET/AF_INET6 socket creations.

The independent Export uses committed SOC/ML HEAD plus only this task's seven
files. Uncommitted user edits, Reliability Replay and ML changes are excluded.
Existing pinned model binaries/interpreters are referenced read-only; no binaries,
operational databases or original packets are copied into the Export or Git.
Timestamps, source UUIDs and latency vary between fixture runs; verification
compares contracts, identities, counts, origin, classifications and recovery
behavior, without requiring time-dependent receipt hashes to match.

Safe read-only verification of the retained session:

```bash
.venv/bin/python -m soc_agent.security_ai.research.live_evidence \
  --directory "$HOME/.local/share/autonomous-soc-agent/gui/live-network/session-959024515d9f4c5ba99afd888b72a57e"
```

Expected: PARTIAL (CLI exit 1), CAPTURE_VERIFIED, TRANSPORT_PARTIAL, 240 packets,
5 flows, 245 DONE, 16 unpersisted metadata packets and zero model receipts.
The stronger verifier separately reports capture and persistence; successful
SQLite integrity alone cannot approve missing metadata or historical flow slices.

## 6. Changed files and preserved boundaries

- `src/soc_agent/linux_runtime/network_monitor.py`: packet-time flush, bounded
  final commit/count/audit verification, explicit finalization and error category.
- `src/soc_agent/security_ai/operational/network_capture/helper_transport.py`:
  completion/count guard, packet watermark and truthful cleanup reason.
- `src/soc_agent/security_ai/research/live_service.py`: deferred consumer,
  finalization authorization and release of outer SQLite read lock.
- `src/soc_agent/security_ai/research/live_evidence.py`: separate saved capture,
  transport and complete-persistence verdicts.
- `tests/unit/live_network/test_finalization.py`.
- `tests/integration/live_network/test_finalization.py`.
- This report.

No sudo, setpriv, pkexec, new AF_PACKET capture, IP test traffic or OS security
WRITE was executed. Helper SHA and approved code bundle, model artifacts,
Producer contracts, Raw Dataset, existing Final Demo evidence, user edits and
Reliability Replay are preserved. No ML commit is needed. Operational status
remains NOT_INFERABLE / OPERATIONAL_INFERENCE_BLOCKED / DIAGNOSTIC_ONLY /
RESEARCH_ONLY / WRITE_DENIED. Research results are not operational Findings.

## 7. Final verdict and remaining blockers

| Scope | Verdict |
| --- | --- |
| Actual saved helper capture | **CAPTURE_VERIFIED** |
| Actual complete transport-to-persistence delivery | **TRANSPORT_PARTIAL** |
| Actual 240-packet stored subset and provenance | **PERSISTENCE_VERIFIED for that subset** |
| Actual full 256-packet persistence/finalization | **BLOCKED**, 16 values unavailable |
| Actual user-session Quality/Edge inference | **LIVE_INFERENCE_BLOCKED**, no receipts |
| Actual retained audit/SQLite integrity | VERIFIED read-only |
| Actual complete capture recovery | **BLOCKED**, volatile metadata cannot be recreated |
| Isolated persistence / actual-model / audit-checkpoint-recovery fixtures | VERIFIED within FIXTURE scope |

The historical session is not repaired or resumed. Its five premature timeout
flow summaries are preserved as evidence and not authorized for new inference.
The code can safely finish a future qualifying capture and process eligible
research flows, but this cannot restore the missing 16 historical packet values.
One-second/frame-limited captures may contain no eligible timeout-complete flow;
that remains a legitimate no-inference result, not a reason to weaken Producer
boundaries. A future actual validation must be user-executed with a new session
and capture authorization; Codex did not execute or automatically schedule it.

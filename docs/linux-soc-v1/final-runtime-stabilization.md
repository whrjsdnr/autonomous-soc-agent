# Final unified Runtime stabilization

Validation date: 2026-10-15, WSL2 Ubuntu / actual WSLg. SOC baseline
`3c70170470aa6244f90e93fbdbdb64c8aa15ab5c`; ML baseline
`9c36c83f9d2a85d7fd91233552cef23f75fd6aa8`. Both main branches matched the
requested commits; both indexes were empty. Existing user/Replay changes were
inventoried by SHA256 before edits and excluded from this work.

This audit covers the existing research demonstration, retained Authentication
evidence and fixture failure/recovery boundaries. It does not certify always-on
production detection or physical Linux deployment.

## 1. Package integration matrix

Paths are relative to the existing sibling SOC/ML repositories. No installation,
environment rebuild, deployed artifact replacement or Producer change was needed.
Tamper tests use bounded private copies of existing files.

| Component | Current path / contract | Interpreter / boundary | Result |
|---|---|---|---|
| SOC Core | SOC `src/soc_agent`, existing Orchestrator/planner/guard/policy/approval/execution/assessment | SOC `.venv/bin/python`, 3.12.14; autonomous-soc-agent 0.1.0 metadata, imported source checkout | Existing interfaces reused |
| Quality | ML `models/network-research-v1-final/quality_rf/model.joblib`, RandomForest, threshold 0.35 | SOC `.security-ai-demo/inference/bin/python`, 3.12.14; one request per owned child | Actual research inference verified |
| Edge | ML `models/network-research-v1-final/edge_lr/model.joblib`, StandardScaler + LogisticRegression, threshold 0.8 | Same isolated interpreter; sklearn 1.9.1 / joblib 1.6.0 / numpy 2.5.3 | Actual research inference verified |
| Network Producer | ML `src/ml/verified_producers/network_v1_1.py`, 1.1.0 / Network14 / float32 | Explicit pinned ML source and raw offline replay | Contract unchanged |
| DNS | ML `packages/dns-security-ai/src/dns_security_ai`, 0.1.0; DNS9 / scaler / LiteRT 2.3.0 | Same isolated worker, existing SOC `.security-ai-demo/artifacts/dns` | Actual native fixture inference verified |
| Installed package adapters | Network/DNS/Security AI 0.1.0 in SOC `.venv/lib/python3.12/site-packages` | Existing external adapters/context/operational provenance | Regression verified |
| Authentication | Existing Linux Journal collector, persistent queue, sources, findings and audit | Existing Linux Runtime; retained WSL DBs read-only | Retained evidence and fixture lifecycle verified |
| GUI | Existing Tk Command Center, `gui/backend.py`, ApplicationService status and ResearchDemo | Tk thread + existing backend event-loop thread | Actual WSLg verified |
| Experience / feedback / self-improvement | Existing stores, candidates, offline evaluation, review and governed activation | Existing identity/policy/audit boundaries, isolated test DBs | See execution table |

SOC Python does not have LiteRT; the isolated interpreter does. ML Python has no
installed DNS/Security AI distribution metadata, but explicit pinned source imports
are used in the worker/package tests. Metadata presence is not inference validation.
The DNS historical manifest lists numpy 2.5.4 versus current 2.5.3: fixture success
does not prove training provenance. See ML `docs/final-package-compatibility.md`.

## 2. Reproduced defects and minimal fixes

**Parent death left an owned research worker running.** A bounded inference-block
fixture ran through the real Worker bootstrap and resource limits; after killing
its owned parent, the worker remained alive. The test cleaned up its own processes.
The existing Worker now sets Linux PR_SET_PDEATHSIG to SIGKILL and checks the exact
parent PID both before and after registration. The parent supplies its PID through
a fixed CLI argument. Failure occurs before native model imports. No privilege,
global OS configuration or independent Linux Runtime lifecycle is changed.

**Stop during asynchronous Start preflight was undone.** An event-controlled test
called Stop while READ-only preflight was pending. When preflight returned, the
old coordinator set `started=True` and created storage. The existing coordinator
now tracks pending Start and cancelled Start, rejects overlapping Start, and keeps
the demo STOPPED after Stop/close. STARTING is shown only for a non-cancelled
preflight. No replacement Runtime or new model capability is introduced.

The initial regression test demonstrated the Start/Stop assertion failure before
the fix; the final tests verify both defects, parent-registration failure/race,
duplicate Start/Stop, oversized memory refusal and actual GUI abrupt termination.

## 3. Runtime lifecycle and worker stability

Existing Linux Runtime tests exercise normal start, writer-lock exclusion, graceful
stop/SIGTERM, double-stop, cursor resume, backpressure and process recovery. A GUI
close detaches an explicitly started independent Linux Runtime. It stops only its
owned research work; a parent-death signal applies only to the model child.

Research preparation (`STARTED`) is distinct from actual worker `RUNNING`. Status
uses the owned process return code; completed/cached history does not make a model
ACTIVE. Reopen restores counts/receipts but leaves the demo STOPPED. An interrupted
dispatch remains UNKNOWN and is not automatically retried.

Existing limits are unchanged: 30 second maximum parent wall timeout, 15 CPU
seconds, 3 GiB address space, 128 KiB result file, core dumps disabled, one BLAS
thread and denied AF_PACKET/IPv4/IPv6 sockets in the model worker. Investigation
has a separate 20 second timeout. The memory test attempts an oversized virtual
mapping and observes refusal without allocating that physical memory. Limits are
ceilings, not measured peak RSS or a complete same-UID sandbox.

## 4. Artifact integrity and actual native execution

| Artifact | Verified SHA256 |
|---|---|
| Quality RF | `53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603` |
| Edge scaler/LR pipeline | `661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882` |
| DNS TFLite | `28e089af363dd565a4fb3d3f202de9e9f9804bd14a164de4fd7b61adb1201e33` |
| DNS scaler | `2735f7650a7d7888ee68f2df870b4e29d83666962931ae2aecb9aa339f40266a` |

All match the fixed reviewed identities. Seven legacy model/scaler/resource hashes
also match preserved evidence. Network14 ordering/float32 and Producer 1.1.0 are
unchanged. DNS9 ordered-name digest stays
`3276c1b595ec566677bce530f2839247b7fa1320dc5e3549f85c0c17c959edd0`.

Current actual WSLg run used two verified offline training flows, each through
Quality and Edge, plus two existing precomputed DNS9 fixtures:

| Profile | Actual scores | Measured package/prediction latency (ms) |
|---|---|---|
| Quality | 0; 1 | 17.11; 18.63 |
| Edge | 0.000242734; 0.999817193 | 6.82; 7.50 |
| DNS | 0.55859375; 0 | 20.18; 20.89 |

Quality/Edge timing covers prediction; DNS timing includes existing package lazy
loading/preprocessing/invoke. These scopes differ and are not a comparative
performance benchmark. Six real native calls produced six separate READ-only
investigations with restored checkpoints, distinct source/evidence identity and
zero provider calls. [Sanitized current evidence](final-runtime-evidence.json)
records artifact/input/receipt digests, timestamps, limits and audit heads.

## 5. Queue, source and provenance

Existing queue/source/provenance regressions cover claim/ack, duplicate packets and
events, poison/malformed input, source/feature digest tampering, backpressure,
interrupted SQL writes and crash/restart at persistence boundaries. Fixture packet
tests are not new kernel packet collection. Existing saved native evidence is read
only; no capture or external traffic is performed.

Retained WSL Authentication revalidation finds one authenticated source event,
one DONE_READ_ONLY finding and its provenance/evidence reference. Four SQLite
integrity checks return `ok`; Audit verification succeeds. Runtime has 560 retained
queue events, including unsupported logs, not 560 attacks. Queue backlog is zero.
Runtime is STOPPED / DEGRADED / NOT_READY with RESUMED_EXACT collector checkpoint.
Every retained SQLite file SHA remains unchanged across inspection and GUI review.

The research SQLite integrity check also returns `ok`; its security audit chain
and receipt/context/checkpoint bindings are verified on close/reopen. Files and
SQLite are not one globally atomic transaction. Exactly-once external effects
are not claimed.

## 6. Investigation and approval

Actual native replay reuses existing SOCRuntime/Orchestrator, governed READ tool,
planner, assessment and checkpoint code. Research scores stay untrusted advisory
context, separate from verified source metadata. They are not attack probabilities
or operational observations. DNS fixture and offline Network results are not joined
to retained Authentication as one real incident. No operational Finding is promoted.

Existing regression checks cover model fact-promotion rejection, forged Evidence,
tool permission, action binding, expiry, operator peer identity, policy/evidence
mismatch, replay, simulation and approved test-marker rollback. These tests use
isolated fixture stores and registered test resources; no host security settings
are changed. The existing Unix socket approval boundary is not bypassed.

## 7. Self-improvement regression

Existing Experience, authenticated feedback, failure feedback, candidate generation,
offline evaluation, holdout, review and promotion-denial suites run unchanged.
Governed activation/rollback tests use isolated DBs and test identity credentials;
they do not activate policy or models in the running environment. Unreviewed
candidates and measured score improvements do not grant promotion authority.
No Replay implementation or user edits are staged.

## 8. GUI state consistency

Launch remains `.venv/bin/python -m soc_agent.gui`. Actual WSLg tests exercise
mapped windows, native research replay, actual worker-running observation,
Dashboard updates, READ-only Authentication review, close/reopen, duplicate module
launch and graceful SIGTERM. The new abrupt-close test kills only its own GUI
child, confirms the owned model child exits, then restores the interrupted attempt
as UNKNOWN without a new invocation.

Current actual screenshots were inspected at both sizes:

- [Dashboard 1920×1080](stabilization-screenshots/unified-dashboard-1920.png).
- [Dashboard 1366×768](stabilization-screenshots/unified-dashboard-1366.png).
- [Network/DNS research result](stabilization-screenshots/unified-research-dns-1920.png).

Cards show Quality/Edge/DNS IDLE after completion, two successes each, separate
BLOCKED operational gate and retained NATIVE_OS Authentication. Charts use actual
receipt values/times; DNS score changes 0.55859375→0. Runtime STOPPED is not healthy
live monitoring. Missing/unavailable values remain UNKNOWN. No UI redesign or
invented graph data is added in this stabilization.

## 9. Failure injection and recovery evidence

| Failure | Executed coverage / safe result |
|---|---|
| Worker timeout / crash | Research and DNS integration tests; UNKNOWN, owned cleanup, no retry |
| Abrupt GUI/parent close | New process and actual WSLg tests; worker terminated, uncertain dispatch retained |
| Stop while Start pending | New event-controlled race test; no reactivation or storage creation |
| Memory budget | New oversized mapping test; refusal under existing RLIMIT_AS |
| Bad parent registration | New identity/race/prctl failure tests; fail before model load |
| Queue interruption / SQLite restart | Existing Linux Runtime and network pipeline crash matrix; no silent ack/loss |
| Audit/receipt/context corruption | Existing isolated tamper/commit-failure tests; UNKNOWN/BLOCKED, no success publication |
| Artifact/source/order tampering | Existing trusted-file/DNS contract tests; rejected before deserialization |
| Missing/untrusted environment | Existing GUI environment and adapter tests; unavailable/UNKNOWN without inference |
| Stale process/writer lock | Existing Runtime lock, stale capture and dispatch recovery tests; no stale READY |

Fault fixtures are explicitly distinguished from six successful native model calls.
Production DBs/artifacts were not corrupted. No unlimited retry, worker restart,
fresh capture, traffic generation or automatic privileged operation was used.

## 10. Security boundaries

NOT_INFERABLE, BLOCKED, RESEARCH_ONLY, DIAGNOSTIC_ONLY, WRITE_DENIED, artifact
integrity, source provenance, explicit human approval and no automatic promotion
remain enforced. No training, model replacement, threshold tuning, Producer change,
new Runtime/Agent/Collector/framework or real OS security WRITE occurred. Offline
regressions run with the existing network-socket-denying audit guard. One deliberate
unbound INET socket identity-rejection case runs separately without bind/connect/send.

## 11. Executed test results

Each row represents a separate execution; overlapping suites are not summed.

| Execution | Result |
|---|---|
| Working Linux Runtime / Network Monitor / operational features | 266 passed, 105.38 s |
| Working native/external adapter, context, storage, READ backend and Runtime | 381 passed, 351.86 s |
| Working policy/approval/execution/restricted/GUI/research/S01–S12 regression | 322 passed, 1 deselected, 192.90 s |
| Final working research + GUI unit/integration after all source fixes | 117 passed, 47.47 s |
| Final failure fixtures including actual WSLg abrupt GUI close | 8 passed, 6.96 s |
| Actual unified WSLg six native calls, crash/reopen, module duplicate/SIGTERM | 3 passed, 43.83 s |
| Working ML + three Security AI package test suites | 630 passed, 4.07 s |
| Deliberate unbound INET operator identity-rejection | 1 passed, 0.33 s |
| Working core/self-improvement/feedback/audit/response regression | 491 passed, 990.82 s |
| Working capture/parser/status/auth recovery/checkpoint/tool/planner/assessment/storage/evaluation boundaries | 697 passed, 23 skipped, 134.37 s |
| Export same boundary scope, short private Unix-socket test root | 697 passed, 23 skipped, 100.68 s |
| Export Linux Runtime / Network Monitor / operational features | 256 passed, 106.90 s |
| Export research + GUI unit/integration | 117 passed, 44.69 s |
| Export actual unified WSLg, crash/reopen, module duplicate/SIGTERM after readiness correction | 3 passed, 43.53 s |
| Working corrected module launch readiness / SIGTERM check | 1 passed, 9.48 s |
| Clean ML Export + three Security AI package suites | 623 passed, 5.02 s |
| Export core/self-improvement/feedback/audit/response regression | 491 passed, 916.16 s |
| Export native/external adapter/context/storage/READ backend/Runtime | 381 passed, 316.29 s |
| Export policy/approval/execution/restricted/GUI/research/S01–S12 | 325 passed, 1 deselected, 206.08 s |

The 322-case run preceded three additional lifecycle fault cases; the final
117-case focused run includes all seven new lifecycle cases. Earlier exploratory
runs are not counted as additional passes. No interrupted run is counted as passed.
SOC Ruff `check src tests`, full `format --check .` (915 working / 871 Export
Python files), and `git diff --check` pass.
ML Ruff check/diff pass using the existing SOC Ruff installation; ML full format
has 24 pre-existing working violations and 21 baseline Export violations, unchanged
by this documentation-only ML audit. The 23 skips require actual Windows/NTFS,
which is outside this WSL validation. Existing ML regression tests fit tiny synthetic
estimators to check preprocessing/serialization; these do not retrain the reviewed
research models or generate deployed artifacts.

## 12. Independent Git Export

Both baseline HEADs are exported with only this task's allowlisted source, tests
and report files. No user/Replay deltas are included. Existing pinned raw/model
files and isolated interpreter remain declared external dependencies; clean
exported ML source is explicitly supplied to test-only composition. The model
Worker checks actual imported Producer/package roots. This proves code reproduction
with declared local dependencies, not a self-contained distributable model bundle.
Artifact/contract pins, native receipts, audit/checkpoint restore and actual GUI
state are compared. Final execution outcomes follow below before commit.

## 13. Remaining issues and final readiness

Operational Network/DNS inference remains BLOCKED: Producer parity, new independent
operational evaluation and physical Linux validation are not established. DNS9
class mapping/scaler pairing/calibration remain unverified. The four selected
Network training flows and two DNS fixtures demonstrate wiring, not accuracy.
Authentication validation uses retained WSL evidence and fixture failure tests;
new continuous journald operation and live LLM APIs are not exercised here.

Linux parent-death handling is specific to the target environment and creating
thread lifetime; it is not a Windows support claim. CPU/address-space/network
guards do not sandbox hostile code sharing the same UID. Any timeout, lost commit
or corrupt state must remain UNKNOWN pending operator review.

Runtime capability expansion ends after this stabilization. Next work is GUI
design/UX, rehearsal and final reporting; no further AI/runtime feature is added.

## 14. Changed scope and final execution supplement

Implementation is limited to existing research `adapter.py`, `worker.py` and
`service.py`. New tests are `tests/integration/research_adapter/test_lifecycle.py`
and `tests/gui_stabilization_checks.py`; the existing module launch test in
`tests/gui_wslg_checks.py` now waits for the registered SIGTERM handler. Other
changes are this report, sanitized
evidence JSON, three actual screenshots, and the ML package compatibility report.
Existing user changes, raw files and model binaries are excluded.

The initial Export WSLg execution had 2 passed / 1 failed because the old module
launch test used a fixed one-second sleep and delivered SIGTERM before handler
installation under load. The test now observes kernel SigCgt registration with a
bounded deadline. No production handler or shutdown policy was weakened.
The initial expanded Export boundary execution had 694 passed / 3 failed / 23
skipped: an overlong basetemp path correctly triggered OPERATOR_SOCKET_PATH_TOO_LONG.
A shorter private test root resolved those failures with the same production
socket guard. A diagnostic subset separately passed 121 cases in 30.05 s. These
initial failures are not counted as successful executions or added to final counts.

**Final scoped Runtime readiness: VERIFIED.** Network Quality/Edge research,
DNS native fixture research, owned-worker lifecycle, queue/source/provenance,
READ-only investigation, governance, self-improvement guards, actual WSLg and
Audit/checkpoint recovery passed the executions above. Authentication is verified
for retained native WSL evidence plus fixture lifecycle/recovery regression; fresh
continuous live collection was deliberately not run. Operational Network/DNS
readiness remains BLOCKED / NOT_INFERABLE.

Both Export and working GUI runs performed six distinct actual native invocations.
The profile/input/artifact/score/prediction/assessment/checkpoint results match;
invocation IDs are disjoint. Timestamps, receipt digests and audit heads differ
because these are independent executions. No saved receipt was substituted for a
new native call. Ten extra working Runtime cases and seven extra working ML cases
are pre-existing user tests excluded from Export/commit. All new tests are exported.

Before selective staging, baseline SHA256s of 118 existing SOC files and 10 ML
files were unchanged; both initial empty indexes were preserved. The approved
Manual Capture source still hashes to
`1f52fcd13c3eabd025bb7a810db4b9709b6c85ea065fed103e9eabd055fc17ba`;
it was not executed. Source/test/report/image blobs are compared byte-for-byte
with the final Export and selected index. Commit and push IDs are recorded in the
completion response after Git verification. No failed or interrupted execution is
silently treated as passed. Runtime feature development ends here.

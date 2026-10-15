# Network Research Adapter & Advisory GUI Integration

Validation date: 2026-10-15. SOC baseline `f088c80814cca0e23c59f09b044a9c35cdb4de3e`;
ML baseline `fe884521f1b8138f3016ad7bc770243193a85bf8`.

Research demo verdict: **VERIFIED**. Operational inference: **BLOCKED / NOT_INFERABLE**.
This verifies offline model execution and presentation, not detection quality or deployment readiness.

## 1. Adapter architecture

```text
Existing Tk Desktop / GUI Worker event loop
  → Explicit ResearchDemo start / selected fixed offline flow
  → ResearchAdapter → owned bounded subprocess
  → Existing PCAP parser + Flows + IoT-23 binding recovery
  → Network Producer v1.1.0 → verified local RF or Scaler/LR
  → Receipt → ResearchAdvisoryContext
  → Existing compose_application / SOCRuntime / InvestigationOrchestrator
  → Governed READ tool / assessment / checkpoint / audit
  → GUI counts, scores, offline flow graph, investigation trace
```

The implementation is in `src/soc_agent/security_ai/research/`. GUI wiring adds one
Network Research page and methods to the existing `gui.backend.Backend`; it does not
create a Runtime, queue, model registry, GUI framework, or web server. Normal Linux
Runtime ownership and Unix-socket approval authentication remain unchanged.

The existing native adapter assumes legacy Top40/DNS9 model bindings. Reusing those
identities for Network14 would misrepresent the input contract. This adapter therefore
has separate research request/receipt/context contracts and reuses existing provenance
helpers, evidence storage, policy, executor guard, audit and checkpoints. Synthetic v2
and Operational Provenance v3 are unchanged.

## 2. Artifact verification and environment

| Model | Existing local research artifact | SHA256 | Threshold |
|---|---|---|---:|
| Quality | `ML/models/network-research-v1-final/quality_rf/model.joblib` | `53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603` | 0.35 |
| Edge | `ML/models/network-research-v1-final/edge_lr/model.joblib` | `661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882` | 0.8 |

Model IDs are `linux-network14-research-v1-quality_rf` and
`linux-network14-research-v1-edge_lr`. Pinned manifest digests:

- Quality: `80bb31b38c6e35dac1628f8c5c3ed1843ae81779ca3173a356f18473821b5f66`.
- Edge: `293e6046e2b46777c383ae0b5de5951596238d4f26e552263022b9b65357e2d9`.

Preflight checks hashes before loading, RESEARCH_ONLY identity, no operational promotion,
producer version, ordered features, threshold, Python 3.12.14 and sklearn 1.9.1.
The child also verifies the exact RF class or StandardScaler/LogisticRegression pipeline
and 14 input features after loading. Only these pinned trusted local joblibs are loaded.
Ownership, permissions, regular-file type, size and symlink checks precede reads.

The existing `.security-ai-demo/inference/bin/python` environment is reused. No packages
were installed, deployed artifacts replaced, or ML environment modified. Bounded temporary
copies are used only for integrity rejection tests. The fixed sibling
ML checkout provides code/raw files/artifacts. Missing or changed dependencies return
BLOCKED, not a mock result. Source hashes in `replay.json` pin the reviewed ML execution
path. Two existing local CTU parser/label changes have explicitly reviewed alternate
hashes: the PCAPNG multi-interface guard does not affect this Classic PCAP, and the CTU
binding change is outside the IoT binding path. Clean committed ML source was separately
tested in Git Export; these local changes are not dependencies of this feature.

## 3. Producer and source contract

The catalogue contains four fixed VERIFIED_MATCH flows from **training Capture 8-1**.
The Worker re-parses actual retained PCAP, validates the Zeek references with existing
independent wire-reference recovery, then calls `network_features` v1.1.0. It compares
source/feature digests, names/order and sample identity to the pinned catalogue.

Only `OFFLINE_PCAP` is accepted. `NATIVE_AF_PACKET`, `FIXTURE`, arbitrary model paths,
caller commands, unrecognized profiles and flow indices are rejected. The 14 float32
features and Producer v1.0.0/v1.1.0 contracts are unchanged. The replay catalogue does
not make AF_PACKET-to-training producer parity pass. Actual Linux flows remain diagnostic.
No new capture or traffic generation occurred; Test 34-1 was not opened or re-evaluated.

This offline source is the existing verified acquisition file, not a new live queue item.
The READ tool stores its bound source metadata in the existing Core Evidence store.
It does not forge a legacy native Source Store record or ingest flow bytes into a
legacy CIC event schema with different byte semantics. Live Persistent Queue / Source
Store and their operational gates remain unchanged.

## 4. Inference isolation, limits and failure handling

One request runs in one owned subprocess, with maximum concurrency one, no retry and
at most eight distinct model/flow pairs per demo directory. Limits precede scientific
imports: 3 GiB address-space ceiling, 15 CPU seconds, 128 KiB result-file ceiling,
core dumps disabled, parent wall-clock timeout at most 30 seconds. BLAS threads are
limited to one. An audit hook denies new IPv4/IPv6/AF_PACKET sockets. Credentials and
arbitrary parent environment variables are not forwarded. Standard output/error are
discarded; feedback contains static sanitized failure codes.

Timeout, crash, cancellation and unknown dispatch outcomes stay UNKNOWN. Stop terminates
only the owned Worker. There is no automatic retry, worker respawn or uncertain replay.
Address-space limit is a ceiling, not measured Peak RSS. Receipt latency measures only
`predict_proba`, not process startup, PCAP parsing or GUI end-to-end time.

This is process isolation for known trusted local code, not an OS sandbox against
malicious same-UID code. Local hashes provide integrity, not publisher signatures.
Joblib remains unsafe for untrusted content; pinned artifacts are an explicit dependency.

## 5. Advisory context and investigation

`soc-network-research-advisory:v1` binds receipt digest, incident ID, model/artifact,
producer, origin, source/feature digests, event/inference timestamps, score, threshold,
prediction, unknown uncertainty and RESEARCH_ONLY status. Scores are **uncalibrated model
scores**, not attack probabilities; Quality and Edge scores are never averaged.

The existing projection rules mark the separate prompt section UNTRUSTED ADVISORY,
NOT EVIDENCE. The governed Runtime uses the existing explicit scripted client; there
are zero external LLM calls. The only registered tool is incident-bound
`read_local_source_report` with READ permission. Evidence contains raw source metadata,
not scores or attack claims. Any nonempty observations/hypotheses or elevated draft
assessment from model output is rejected deterministically in this demo.

Execution stops at `ASSESSED_READ_ONLY`, before response planning/execution. No operational
Finding is generated and no approval is fabricated. This validates actual orchestrator,
policy/executor, evidence and checkpoint wiring with SCRIPTED reasoning, not live LLM quality.

## 6. Audit, duplicate prevention and restart

Start creates a private isolated existing `RuntimeGovernanceStore`, plus a replay lock
and bounded attempt/receipt files under GUI data directory `network-research/`.
The existing hash-chain audit anchors dispatch and completed-record digests. An attempt
is reserved before invocation; duplicate completed requests return CACHED_NO_NEW_INFERENCE.
Unfinished dispatches after restart remain UNKNOWN with no automatic re-execution.
Receipt/audit/checkpoint tampering fails closed; failed reads never reset counts to zero.

Snapshots validate records and restored investigation evidence/trace without inference
or writes. Tests compare DB/file hashes around read-only status. GUI restart restores
stored counts and audit as STOPPED; Start remains explicit. Files and SQLite commits
are not one atomic transaction: a failed completion audit can leave an unpublishable
receipt and UNKNOWN state. This deliberately blocks replay; exactly-once external effects
are not claimed. GUI shutdown does not stop an independently running Linux Runtime.

## 7. GUI screens and demo steps

Run the existing command:

```bash
.venv/bin/python -m soc_agent.gui
```

Choose **Network Research → Start Research Demo → both/quality/edge → Flow 1–4 →
Run Offline Replay**. There is no manual JSON edit or second terminal. Stop Demo cancels
owned work. Repeating a completed selection displays cached status and does not increment
counts. Missing dependencies are reported in the page/detail panel; no inference runs
as a side effect of status polling or opening the page.

The page displays model integrity/status, operating BLOCKED, actual Runtime/queue health
(UNKNOWN if offline), confirmed model counts, errors/UNKNOWN, source labels, observed
packet counts per replay flow, per-model score bins, latest advisory rows, timestamp,
evidence references and investigation trace. Details expand to receipts/digests/limits.
The flow chart is replay sequence, not live packets/second. At 1366×768 the existing
scroll container gives access to lower rows/details.

Actual WSLg screenshots, captured from running Tk windows and visually inspected:

- [Before inference, 1920×1080](network-research-screenshots/research-before-1920.png).
- [Actual two-model results, 1920×1080](network-research-screenshots/research-after-1920.png).
- [Actual resized window, 1366×768](network-research-screenshots/research-after-1366.png).

## 8. Actual E2E results

[Sanitized receipts and validation summary](network-research-demo-evidence.json) retain
digests and aggregate metadata, not packet payloads, addresses, credentials or original labels.

| Replay flow | Packets | Quality score / class | Edge score / class |
|---|---:|---|---|
| 1 | 2 | 0.000000 / CLASS_0 | 0.000242734 / CLASS_0 |
| 3 | 6 | 1.000000 / CLASS_1 | 0.999817193 / CLASS_1 |

Four actual model invocations completed; counts became Quality 2 / Edge 2, unique flows 2,
with no worker errors. Both score distributions and the observed-packet chart changed
from real receipts (2→6), not injected UI values. All four investigations reached
ASSESSED_READ_ONLY with one raw-source Evidence reference and successful checkpoint restore.
Audit verified after GUI close/reopen; restored state STOPPED with counts preserved.
Measured prediction-only CPU wall latencies in this run: Quality 11.24/12.66 ms;
Edge 9.11/11.70 ms. These four observations are not a performance benchmark.

The actual module launch, duplicate GUI instance handling and graceful SIGTERM test also
passed. An idle Stop display left STOPPING during development; it was corrected and the
final actual-window test confirms STOPPED and restart behavior.

## 9. Security regression and independent reproduction

Validation covers pinned artifacts/model/producer/schema, untrusted paths/symlinks,
source and feature tampering, advisory digest, model-fact promotion, timeout/crash/cancel,
duplicate invocation, concurrent work, interrupted dispatch/restart, audit failure,
receipt corruption and read-only status. Existing Linux Runtime, approval, restricted
response, operational gate and external context security suites are run separately.
Run counts below are separate executions; overlapping tests are not added together.

The Export consists of each repository's baseline Git archive plus only this task's
SOC files and ML report. The test harness explicitly supplies existing pinned local
raw/model/interpreter dependencies and the **clean exported ML source** to the child;
the child's producer import root is checked. Production GUI accepts no such environment
override. No binary/raw data or uncommitted Replay files are exported/committed.

## 10. Remaining limitations

- Research models remain RESEARCH_ONLY. Operating inference, automatic Finding promotion,
  live-source producer parity and actual Linux response are BLOCKED/NOT_INFERABLE.
- Four preselected training flows demonstrate wiring, not independent detection evaluation.
  Existing research evaluation limitations remain; no new holdout claim is made.
- The trusted sibling ML files and existing native environment must be provisioned locally.
  This change does not install packages, distribute research binaries or create deployments.
- Explicit failure/restart tests use synthetic failure injection; real successful RF/LR
  execution and WSLg screenshots are separately identified above.
- No new live LLM/provider validation, new capture, retraining, physical Linux server or
  privileged OS write was performed.

## 11. Reproduction commands and dependencies

From SOC, with the pre-existing trusted ML sibling and native environment:

```bash
.venv/bin/python -m pytest --import-mode=importlib -q \
  tests/unit/research_adapter tests/integration/research_adapter \
  tests/unit/gui tests/integration/gui
.venv/bin/python -m pytest --import-mode=importlib -q \
  tests/gui_research_checks.py \
  tests/gui_wslg_checks.py::test_actual_module_command_duplicate_and_graceful_sigterm
.venv/bin/python -m ruff check src tests
.venv/bin/python -m ruff format --check .
git diff --check
```

Existing native adapter regressions require explicit `SOC_EXTERNAL_ARTIFACT_ROOT` pointing
to the existing `.security-ai-demo/artifacts`, `SOC_EXTERNAL_INFERENCE_PYTHON` pointing to
the existing isolated interpreter, package source import paths for the ML packages, and
`RUN_LIVE_LLM_TESTS=0`. The existing `tests/native_capture_verification_guard.py` wraps the
offline suites to deny newly created network/capture sockets. The one test intentionally
creating an unbound INET socket to reject a forged operator socket was run separately;
it neither connects nor sends traffic.

Independent Export tests explicitly compose these same external resources using
`SOC_RESEARCH_VALIDATION_REPOSITORY` in the test helper. Only the test helper also accepts
`SOC_RESEARCH_VALIDATION_ML_SOURCE` to use committed ML source from the separate Export.
These names are not production GUI settings, and cannot select an arbitrary GUI executable.
Export reproduces code with declared pinned local dependencies; it is not a self-contained
artifact distribution.

## 12. Changed file inventory

SOC files owned by this change:

- `src/soc_agent/gui/app.py`
- `src/soc_agent/gui/backend.py`
- `src/soc_agent/gui/research_view.py`
- `src/soc_agent/security_ai/research/__init__.py`
- `src/soc_agent/security_ai/research/adapter.py`
- `src/soc_agent/security_ai/research/environment.py`
- `src/soc_agent/security_ai/research/investigation.py`
- `src/soc_agent/security_ai/research/models.py`
- `src/soc_agent/security_ai/research/replay.json`
- `src/soc_agent/security_ai/research/service.py`
- `src/soc_agent/security_ai/research/worker.py`
- `tests/research_adapter_support.py`
- `tests/gui_research_checks.py`
- `tests/unit/research_adapter/conftest.py`
- `tests/unit/research_adapter/receipt.json`
- `tests/unit/research_adapter/test_contracts.py`
- `tests/integration/research_adapter/conftest.py`
- `tests/integration/research_adapter/test_demo.py`
- This report, `network-research-demo-evidence.json`, and the three linked screenshots.

ML owns only `docs/network-research-adapter-contract.md`. Both original indexes were empty.
Baseline SHA comparison confirms all other pre-existing files, including Replay and user
changes, are unchanged. Seven legacy artifact/resource hashes and both research binary
hashes were rechecked. No raw dataset, binary, original label, credential or generated
large dataset is included in this change.

## 13. Final executed test results

Each row is a separate execution; overlapping counts are not summed.

| Execution | Result |
|---|---|
| Working SOC Research Adapter + GUI unit/integration | 83 passed, 31.68 s |
| Export same focused scope, clean exported ML producer code, actual RF/LR | 83 passed, 29.85 s |
| Working Runtime + Network Monitor + Operational Features | 266 passed, 102.87 s |
| Working Native Adapter + External Context/Storage/READ backend/Runtime | 381 passed, 318.38 s |
| Working Approval + Execution + Restricted Response + GUI + Research | 205 passed, 1 deselected, 164.20 s |
| Clean SOC Export full combined scope of those three groups | 842 passed, 1 deselected, 556.51 s |
| Deliberately unbound INET operator identity rejection, separate from socket-denying Guard | 1 passed, 0.33 s |
| Working Policy + Scenario S01–S12 | 86 passed, 35.65 s |
| Export Policy + Scenario S01–S12 | 86 passed, 35.58 s |
| Actual WSLg Research + actual module launch/duplicate/graceful-SIGTERM | 2 passed, 29.35 s |
| Export actual WSLg Research with explicit pinned local dependency composition | 1 passed, 16.63 s |
| ML tests + existing Network/DNS/Security AI package tests, working tree | 630 passed, 4.09 s |
| ML same scope, clean Git Export | 623 passed, 3.94 s |

The initial working full combined run ended with SIGTERM/143 before pytest summary.
It is **not** counted as passing; no assertion failure was printed and the signal's
origin was not established. The three shorter independent processes above re-executed
its entire scope successfully. The clean Export full combined run also passed. During
development, two focused test assertions and the idle Stop display failed; those were
corrected before the final runs listed here.

Working/export SOC counts differ by ten pre-existing untracked operational feature tests;
ML counts differ by seven pre-existing user CTU tests. These files are excluded from the
commit and are not prerequisites of the exported code. The offline Guard rejected one
network socket attempt in the Runtime group and in the full Export; no native capture or
test traffic was generated. The separately run operator-identity case uses only an
unbound socket and sends nothing. Successful model E2E uses actual binaries; explicit
crash/timeout/audit failure tests use isolated failure injection.

Final quality: SOC `ruff check src tests`, full `ruff format --check .` (904 working / 860
Export files) and `git diff --check` pass. ML `ruff check src tests`, this task's report
format and `git diff --check` pass using the existing SOC Ruff installation. ML full
format has 24 unchanged pre-existing violations (21 in clean Export); these were not
reformatted. ML pytest was supplied from the existing SOC test environment to the
existing ML interpreter without installing or rebuilding dependencies.

The 23 SOC files and one ML report are compared byte-for-byte with Export before Stage;
Stage blob SHA256 is then compared to the tested source. Existing user files, original
models and uncommitted Replay remain excluded. Commit IDs are reported by Git after
commit rather than embedded in a report whose own hash would change.

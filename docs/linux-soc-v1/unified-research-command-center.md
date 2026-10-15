# DNS Research Advisory & Unified SOC Command Center

Validated 2026-10-15 on WSL2 / WSLg. Baselines: SOC
`441c63e42fd7596b93416d13be0b4d4be6c715f0`, ML
`a82925dba04203beb85b61814fab703cab62c097`. Both matched the requested HEADs;
both indexes were initially empty. Existing dirty/untracked files remain excluded.

**Research integration: VERIFIED. Operational Network/DNS inference: BLOCKED / NOT_INFERABLE.**
Successful native fixture inference is not validation of operational DNS detection.

## 1. Architecture and reuse

```text
Existing Tk Desktop / Command Center / background event loop
  ├─ Existing Linux Runtime status + retained Authentication findings (READ-only)
  └─ Existing ResearchDemo / private governance store / audit / replay lock
       → existing isolated Worker, one explicit request
         ├─ OFFLINE_PCAP → Producer 1.1.0 → Quality RF / Edge Scaler+LR
         └─ FIXTURE → existing DNS9 contract → official DNSPredictor / LiteRT
       → typed research receipt / separate untrusted advisory projection
       → existing SOCRuntime / Orchestrator / governed READ tool / assessment
       → existing Evidence, Audit, Checkpoint → GUI projections
```

No new Runtime, Agent, queue, source store, GUI framework or model registry is introduced.
The existing `network-research/` store name and Network receipt contract are retained for
backward compatibility. DNS uses the same coordinator, process isolation and checkpoint
composition, with a DNS receipt and context contract. Authentication remains in its own
Runtime and source store; displaying these domains together does not join their incidents.
Synthetic v2, Operational Provenance v3, approval and response boundaries are unchanged.

## 2. DNS artifact identity and environment

| Property | Verified current value |
|---|---|
| Package | `dns-security-ai` 0.1.0, existing ML package source |
| Model ID | `dns_cicbell_dnn_int8` (unchanged) |
| Model version | `int8-sha256-28e089af363d` |
| Bundle | `dns-int8-reviewed-1` |
| Model | `model/dnn_int8.tflite`, 9,288 bytes |
| Model SHA256 | `28e089af363dd565a4fb3d3f202de9e9f9804bd14a164de4fd7b61adb1201e33` |
| Scaler | `preprocessor/scaler.joblib`, 1,135 bytes |
| Scaler SHA256 | `2735f7650a7d7888ee68f2df870b4e29d83666962931ae2aecb9aa339f40266a` |
| Feature schema | `cic-bell-dns-stateless9-v1` |
| Ordered-name contract digest | `3276c1b595ec566677bce530f2839247b7fa1320dc5e3549f85c0c17c959edd0` |
| Threshold | 0.5; supplied detector default, not validated/tuned |
| Runtime | Existing isolated Python 3.12.14, LiteRT 2.3.0, sklearn 1.9.1, joblib 1.6.0 |

Source is the existing ML DNS package and existing reviewed local deployed bundle under
`.security-ai-demo/artifacts/dns`. No model, scaler or environment was replaced or installed.
Read-only checks pin package Python/JSON bytes, the fixed interpreter, metadata and both
artifact bytes. The official predictor's bundle validation runs before scaler deserialization
and TFLite loading. Unknown joblib files and request-supplied paths are never accepted.

LiteRT is in the isolated environment, not the SOC Python. Preflight therefore reads its
fixed distribution metadata without importing/running a model; the Worker imports it.
The manifest's historical review lists numpy 2.5.4, while this existing environment uses
2.5.3. Actual inference passes here; this does not establish upstream training compatibility.
Training/scaler pairing, DNN class mapping and calibration remain UNVERIFIED.

## 3. DNS9 input and preprocessing contract

Order is exactly:

```text
FQDN_count, subdomain_length, numeric, entropy, special,
labels, labels_max, labels_average, len
```

The official contract rejects missing, extra, negative, nonnumeric, NaN/Inf and values
outside float32 range. It constructs named float32 features, applies the existing
StandardScaler, rounds/clips to INT8, invokes the model and dequantizes its scalar output.
Input tensor is `(1,9)` INT8 with quantization `(0.0387900173664093,-40)`;
output is `(1,1)` INT8 with `(0.00390625,-128)`.

`dns_replay.json` pins two existing feature fixtures: all-ones from `gui.probe`, and
`[14,0,0,2.78,2,2,10,6.5,11]` from the DNS package's fixture. The first had prior native
GUI validation; both were executed natively in this change. These are precomputed numeric
fixtures, not raw FQDNs, independent ground truth or evidence of training producer parity.
Input digest means canonical named fixture payload before float32/scaler/quantization;
it is not a raw query or a quantized tensor digest.

Requests require explicit research mode and `FIXTURE` origin for DNS (fixture index 0–1).
Network still requires OFFLINE_PCAP (flow index 0–3). Raw query/native-origin requests,
caller model paths and DNS7 compatibility assumptions are rejected. No FQDN extractor,
DNS7→DNS9 conversion, automatic operating event inference or Finding promotion is added.

## 4. Research adapter and advisory provenance

`soc-dns-research-receipt:v1` includes actual model/version, model/scaler/contract digests,
fixture ID, input digest, ordered names, native score/prediction, threshold, timestamp,
package-reported latency, applied limits and provenance digest. It requires RESEARCH_ONLY,
FIXTURE_NATIVE_ONLY, producer parity UNVERIFIED, FIXTURE_ONLY_NO_OPERATIONAL_SOURCE,
unknown uncertainty, uncalibrated score, operating BLOCKED and WRITE_DENIED.

`soc-dns-research-advisory:v1` binds the full receipt digest to a fresh research incident.
It cannot use the Network context contract or be interpreted as Authentication evidence.
Both reuse the existing untrusted projection rules and ResearchClient. Model scores are
not observed facts or calibrated malicious probabilities; package class predictions are
displayed as CLASS_0/CLASS_1. Quality, Edge and DNS scores are not averaged or fused.

The incident-bound READ tool returns only DNS fixture metadata. Its Core Evidence record
describes that fixture reference, not an observed DNS query or a model verdict. Network's
existing raw packet metadata report/schema is preserved. Observations/hypotheses remain
empty and scripted assessment remains info/zero-confidence; attempted model-fact promotion
is rejected. This is the existing real Orchestrator with SCRIPTED reasoning, not a second
investigation implementation. There are zero provider calls and no response planning or
execution after the READ-only assessment.

## 5. Bounds, audit and recovery

The existing Worker applies 3 GiB address-space, 15 CPU seconds, at most 30 seconds parent
timeout, 128 KiB output, no core dumps and one BLAS thread before native imports. Network
and AF_PACKET socket creation is denied in the Worker. Parent environment credentials
are not forwarded. Errors are static sanitized codes; original exception strings are
not feedback. Memory limit is a ceiling, not a measured RSS value. Known local packages
and joblibs remain trusted dependencies; this is not an OS sandbox against same-UID code.

Concurrency is one, with no automatic retry/restart. Existing locked attempt/receipt and
hash-chain audit handling now permits at most ten distinct replay keys (eight Network,
two DNS). A completed key is cached without a new inference count. Interrupted dispatch,
crash, timeout or uncertain result remains UNKNOWN and is not automatically re-executed.
Audit/receipt/context/checkpoint tampering fails closed. A confirmed model receipt can
coexist with an UNKNOWN investigation; model success and investigation completion are
different counters. Per-model UNKNOWN counts do not pretend an unobserved call was absent.

GUI close stops its owned research Worker, not an independent Linux Runtime. Reopen
restores receipts/counts, validates audit and checkpoints, and leaves the demo STOPPED.
Operating gates remain blocked. File and SQLite commits are not a globally atomic
transaction and exactly-once external effects are not claimed.

## 6. Unified GUI and demo steps

```bash
cd ~/kdt-linux/autonomous-soc-agent
.venv/bin/python -m soc_agent.gui
```

Dashboard shows the Runtime hero first, then Quality, Edge, DNS and Authentication cards,
actual inference success/UNKNOWN counts, timestamp/error, operating gates, recent advisory,
DNS score trend, actual inference sequence, investigation progress and input distribution.
Existing queue, network traffic and Runtime investigation charts remain below. No live
traffic metric is fabricated when no capture is running. Distribution counts are source
input units, not attacks: unique offline flows, unique DNS fixtures and retained auth
records. Missing Authentication measurements are excluded and explicitly UNKNOWN.

Use **Network / DNS Research Demo → Start Research Demo → both/quality/edge/dns →
Run Offline Replay**. DNS selection restricts input choices to fixtures 1–2. Start and
status do not infer. The progress monitor uses a cheap actual owned-process check; it
does not repeatedly scan DB/artifact state while investigating. IDLE/dispatch/waiting
are distinguished from an actually RUNNING Worker. Stop only cancels owned work.

Research detail rows expose origin, score, threshold, prediction, investigation and audit
references; expandable detail contains the typed advisory context/digests. **Review
Authentication** uses the existing Investigations page and configured Runtime. Existing
Connect/`--runtime` attaches a Runtime read-only; there is no automatic discovery of
arbitrary user DBs. With no Runtime configured, Authentication stays UNKNOWN/OFFLINE.

The existing route key `Network Research` is retained; its navigation label now names
Network / DNS. No extra terminal or manual JSON edit is needed for research replay.

## 7. Actual inference and Authentication evidence

[Sanitized validation summary](unified-research-evidence.json) records actual six native
receipts from the final WSLg run; no raw dataset, original labels, credentials or payloads.

| Source | Quality | Edge | DNS |
|---|---:|---:|---:|
| Offline 8-1 flow 1, 2 packets | 0 | 0.000242734 | N/A |
| Offline 8-1 flow 3, 6 packets | 1 | 0.999817193 | N/A |
| Existing DNS9 all-ones fixture | N/A | N/A | 0.55859375 |
| Existing DNS9 package example | N/A | N/A | 0 |

Quality 2 / Edge 2 / DNS 2 invocations, six separate ASSESSED_READ_ONLY incidents, one
source/fixture Evidence reference each, verified audit and successful checkpoint restore.
Packet graph changes 2→6 and DNS score graph 0.55859375→0 from actual receipts. Source
origin stays OFFLINE_PCAP versus FIXTURE. Thresholds are 0.35 / 0.8 / 0.5 respectively.

Measured latency in this run: Quality 10.42/13.90 ms and Edge 8.14/11.11 ms are prediction
only; DNS 22.21/24.24 ms is package latency including lazy loading/preprocessing/invoke.
These scopes differ and six samples are not a comparative performance benchmark.

Authentication review revalidated an existing previously collected WSL Runtime: one
verified authentication event, one provenance reference, one DONE_READ_ONLY finding,
audit verified. Actual source value is NATIVE_OS. Runtime is currently STOPPED / NOT_READY
and the UI labels it RETAINED, not a fresh live detection. All existing Runtime SQLite
file bytes were unchanged across GUI review and close/reopen. No new journald collection,
packet capture, traffic generation or security WRITE occurred in this task.

## 8. Actual WSLg screenshots and corrections

Screenshots are actual mapped Tk windows, not generated images:

- [Before inference](unified-research-screenshots/unified-before-1920.png).
- [Unified Dashboard 1920×1080](unified-research-screenshots/unified-dashboard-1920.png).
- [Unified Dashboard 1366×768](unified-research-screenshots/unified-dashboard-1366.png).
- [Network/DNS research replay](unified-research-screenshots/unified-research-dns-1920.png).
- [Retained actual Authentication review](unified-research-screenshots/unified-retained-authentication.png).

Visual review found narrow-card clipping and an old four-line Cairo surface assumption.
Cards now use shorter lines; text rendering uses a bounded 32-line surface and clamps
crop coordinates. The actual-window test checks multiline rendering and no Tk callback
exceptions. The existing scroll container exposes lower charts/detail at 1366×768.

The first GUI test also asserted an incorrect origin name (NATIVE_LINUX_AUTH); it was
corrected to the actual stored NATIVE_OS value without changing source evidence. One
development GUI run under concurrent validation completed model receipts but had an
UNKNOWN investigation; that run was not submitted as successful E2E. Its root cause was
not established. Heavy status polling was removed from in-flight monitoring; subsequent
final working and Export tests separately verify complete results and recovery. Bounded
timeouts still legitimately return UNKNOWN under failure/load and require operator review.

## 9. Tests and independent reproduction

New tests cover DNS artifact/scaler/schema/package/link tampering before deserialization,
origin spoofing/raw input rejection, receipt/context integrity, cross-domain incident and
Evidence isolation, actual DNS/RF/LR execution, timeout, owned crash, unknown dispatch,
duplicate replay, read-only status, restored audit/checkpoint, actual GUI process state,
source labels, chart points, resize, multiline text and restart. Existing suites cover
Network adapter, Authentication/Linux Runtime, operational gates, Orchestrator, policy,
approval, restricted response, GUI and scenarios. Live provider calls are disabled.

Independent Export uses baseline Git archives plus only this change's files. Tests supply
the existing pinned local raw/model/native-environment dependencies and clean exported ML
source explicitly. The Worker checks the actual producer/package import root; no uncommitted
Replay or user ML source edit is needed. This is code reproduction with declared external
dependencies, not a redistributable self-contained model package.

Run focused tests with:

```bash
.venv/bin/python -m pytest --import-mode=importlib -q \
  tests/unit/dns_research tests/integration/dns_research \
  tests/unit/research_adapter tests/integration/research_adapter \
  tests/unit/gui tests/integration/gui
```

Actual display tests are `tests/gui_unified_checks.py`, `tests/gui_research_checks.py`
and the existing module launch/SIGTERM WSLg check. Optional test-only
`SOC_UNIFIED_AUTH_RUNTIME` supplies a known retained Runtime; it is not a production
auto-discovery setting. Native regressions require the existing explicit artifact/interpreter
paths and ML package import paths. Offline suites use the existing socket-denying Guard;
the deliberately unbound INET operator identity test is run separately and sends nothing.

## 10. Remaining limitations and next stage

- DNS9 training Producer parity, class mapping, scaler pairing, calibration and operational
  efficacy remain unverified. DNS7 is not interchangeable with DNS9.
- Network uses four preselected training flows; this is wiring demonstration, not fresh
  independent performance evaluation. No locked holdout was reopened or threshold tuned.
- Authentication evidence is retained WSL data, not a new always-on collection validation.
  Current unconfigured/offline status must not be presented as healthy live monitoring.
- No live LLM API, new capture, model training, replacement, promotion, physical Linux
  server validation, or actual security response was performed.
- Native dependencies, known ML checkout and private model artifacts must already exist.
  No installer or arbitrary environment search is added.
- With this AI integration complete, work proceeds to stabilization, UI/UX, demonstration
  and final reporting. Further AI capability expansion is not part of this change.

## 11. Executed tests and quality results

Each row is one execution. Overlapping scopes are not added together.

| Execution | Result |
|---|---|
| Final working DNS + Network Research + GUI unit/integration | 110 passed, 42.70 s |
| Final working actual unified WSLg window | 1 passed, 40.55 s |
| Final clean Export focused tests + actual unified WSLg window | 111 passed, 62.03 s |
| Working Linux Runtime / Network Monitor / Operational Features | 266 passed, 101.73 s |
| Export same scope | 256 passed, 101.36 s |
| Working Native / External Context / storage / READ backend / Runtime | 381 passed, 324.00 s |
| Export same scope | 381 passed, 314.18 s |
| Working Approval / Execution / Policy / Restricted / GUI / Research / S01–S12 | 318 passed, 1 deselected, 194.75 s |
| Export same scope | 318 passed, 1 deselected, 198.57 s |
| Deliberately unbound INET operator-identity rejection, separate from Guard | 1 passed, 0.41 s |
| Actual unified + existing Network research + actual CLI launch/duplicate/SIGTERM WSLg checks | 3 passed, 72.98 s |
| ML tests + Network/DNS/Security AI package tests | 630 passed, 4.76 s |
| Clean ML Export same scope | 623 passed, 4.80 s |

Ten extra working Runtime-scope cases and seven extra working ML cases are pre-existing
user/untracked tests, excluded from the commits and Export. All new focused tests are
present in Export. The Guard rejected one attempted network socket in each Runtime
execution; no capture or test traffic was produced. Other guarded groups had zero attempts.
ML tests use the existing ML Python with pytest explicitly supplied from the existing SOC
test environment, and fixed existing package source paths; no dependency was installed.

SOC Ruff check, full format check (912 working files) and diff check pass. ML Ruff check,
new report format and diff check pass using the existing SOC Ruff installation. ML full
format has 24 unchanged pre-existing violations; these are outside this change and were
not reformatted. Model/scaler/resource hashes and baseline hashes of every other existing
file were rechecked before selective Stage. Stage blob SHA256 is compared with tested
source and Export, and only the allowlisted files are committed.

## 12. Changed file inventory

Existing SOC files extended:

- `src/soc_agent/gui/app.py`
- `src/soc_agent/gui/backend.py`
- `src/soc_agent/gui/research_view.py`
- `src/soc_agent/gui/typography.py`
- `src/soc_agent/security_ai/research/adapter.py`
- `src/soc_agent/security_ai/research/investigation.py`
- `src/soc_agent/security_ai/research/models.py`
- `src/soc_agent/security_ai/research/service.py`
- `src/soc_agent/security_ai/research/worker.py`

New SOC implementation/test files:

- `src/soc_agent/gui/unified.py`
- `src/soc_agent/security_ai/research/dns.py`
- `src/soc_agent/security_ai/research/dns_replay.json`
- `tests/gui_unified_checks.py`
- `tests/unit/dns_research/conftest.py`
- `tests/unit/dns_research/test_contract.py`
- `tests/integration/dns_research/conftest.py`
- `tests/integration/dns_research/test_unified.py`

Evidence/docs: this report, `unified-research-evidence.json`, and the five linked actual
screenshots (24 SOC files total). ML changes only `docs/dns-research-adapter-contract.md`.
No raw dataset, original label, research binary, uncommitted Replay or unrelated user
change is included. Commit IDs and remote equality are reported from Git after commit.

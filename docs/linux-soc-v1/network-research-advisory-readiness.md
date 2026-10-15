# Network research advisory integration readiness

2026-10-15, WSL2 Ubuntu. SOC baseline `23767a0394d5f74384463c3be33fdfcf7c4c8865`; ML baseline `8c6da5fa613e3053bf2cb4d73addfd248595c1d1`.

## Decision

ML outcome **RESEARCH_EVALUATED**. SOC operating readiness **BLOCKED**. This is the separately authorized retrospective research protocol, not a change to prior operational Admission.

## Dataset and provenance

Existing IoT-23 PCAP/Zeek sources, frozen exact binding-recovery policy and Network Producer1.1.0 (14float32, OFFLINE_PCAP) reused. Flow is the sample unit even when several concordant Zeek connection references bind it. Non-verified statuses excluded. Raw/label hashes checked, source/feature/config/row digests recorded. No new download/capture/OS response.

| Role | Session | Samples | Benign | Malicious |
|---|---|---:|---:|---:|
|train|8-1|4218|2162|2056|
|validation|3-1|76320|2927|73393|
|diagnostic|20-1|2304|2300|4|
|test|34-1|4295|981|3314|

## Leakage / generalization scope

No cross-session original Flow/label-reference/source-feature digest reuse observed. Identical numeric feature values and shared destination endpoint/address hashes exist and are reported. Devices/campaigns not proved independent. Validation3 predates Train8 and is scan-heavy. This is not future prediction or operating accuracy. Capture drop/gap UNKNOWN.34-1 was previously inspected for labels/binding and is not a blind holdout. It remains Test; no reassignment, threshold tuning or fitting on it.

## Models and evaluation

Train-only scaling for balanced LogisticRegression, balanced trees without scaling. Seed20261015, single CPU thread. Five fixed candidates evaluated on3-1; threshold selected on a fixed validation grid before test access. Quality selects RandomForest128/depth12; Edge selects StandardScaler+LogisticRegression C1.0 by predeclared validation eligibility/CPU latency rule.

| Model | Split | Precision | Recall | F1 | AP | FPR |
|---|---|---:|---:|---:|---:|---:|
|quality|validation|0.998748|0.999796|0.999271|0.999984|3.1431%|
|quality|locked Test34|0.951796|0.887749|0.918657|0.984635|15.1886%|
|edge|validation|0.999255|0.987478|0.993332|0.999437|1.8449%|
|edge|locked Test34|0.995458|0.727520|0.840656|0.912923|1.1213%|

Quality Test FPR15.19% and Edge Test FNR27.25% show deterioration. No retuning followed. Diagnostic20 has only4 malicious samples; no operational claim. Calibration/Brier, ROC-AUC, confusion matrix, novel-feature subset and measured fit/CPU/batch latency are in the ML evidence. Peak RSS includes the complete fit process/dataset, not model-only RAM. Benchmarks used one thread on a shared WSL2 i5-12400 (12 logical CPUs); no isolated physical-server measurement.

## Test Lock

Lock digest `1c2aedc3c3c5ccbb24fc09a6a7ac047acde379cc064c5c1734fcf9dd13c727b3`. Final result digest `a57a284cbf7e91d8cc4abfed2aad41774428bb0720e18bb10f03f4aadbcd4eec`.

Lock saved before opening Test; exclusive attempt receipt consumed first, one prediction pass per selected model; no retry after uncertain/crashed result. Test failures do not authorize reselection. Original lock binds evaluation source SHA, model binary/preprocessor, threshold, split manifests, versions and source SHA.

## Research artifacts

Local ML `models/network-research-v1-final/`, RESEARCH_ONLY, no binaries/raw dataset committed under existing ignored model policy. Digest-before-load for trusted owner-controlled local artifacts only; joblib is not safe for untrusted models.

| Model | Bytes | SHA256 |
|---|---:|---|
|linux-network14-research-v1-quality_rf|117241|`53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603`|
|linux-network14-research-v1-edge_lr|1773|`661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882`|

## SOC integration contract review

Existing `src/soc_agent/security_ai/external/models.py` restricts observation types to network_flow_top40/dns_stateless_feature_record and fixed bindings/packages. `inference.py`, native worker and `ExternalEvidenceAdapter` do not accept the research14/scaler artifacts as existing native models. No code was added to bypass those contracts. Future work needs a reviewed versioned Network14 observation/model binding and backend, explicit artifact trust and source/provenance/evidence validation, timeout/budget/UNKNOWN recovery, advisory projection and model-fact promotion protection. A new schema must coexist with existing Syntheticv2 and Operational Provenancev3 semantics.

No runtime integration, automatic inference, Finding creation or live advisory injection was performed. Context construction would still require actual incident/source association and deterministic validation, not just a model score. Scores are not observed facts, attack probabilities, approval grants or execution authority. Existing Policy/Human Approval/Restricted Executor boundaries remain unchanged.

## Operational boundary

NOT_INFERABLE; inference/Finding promotion BLOCKED; feature generation DIAGNOSTIC_ONLY; WRITE_DENIED. Seven legacy model/scaler/resource hashes unchanged. No root/capability/network setting changes, external model provider or live LLM call. No physical Linux validation.

## Export and regression

Independent baseline+owned-files Export reproduces all four Feature/label datasets, all five binary SHA and Validation predictions/metrics. Test model inference is not repeated; original result digests and count-derived metrics verified. Existing user PCAPNG-only guard creates an explicitly recorded source SHA difference from HEAD; all inputs are Classic PCAP and exact dataset equivalence verified. Original Lock stays unchanged and correctly fails a literal source-SHA check against the different parser source. This is scoped experiment reproducibility, not global parser equivalence.

Final executions (overlapping suites, do not sum):

| Execution | Result |
|---|---|
| Focused new research tests |35 passed|
| ML working broad |630 passed (3.17s)|
| ML independent Export broad |623 passed (4.77s)|
| SOC working configured broad |769 passed, 1 deselected in 603.48s (0:10:03)|
| SOC independent Export configured broad |759 passed, 1 deselected in 602.21s (0:10:02)|
| SOC AF_INET identity assertion, separate unbound socket only |1 passed (0.45s)|

The ML difference7 is pre-existing user CTU tests excluded from Export. The SOC difference10 is pre-existing untracked operational producer-parity tests excluded from Export. The AF_INET assertion is deselected only in the no-network guarded broad run and passed separately: open/unbound/close only, no bind/connect/send. The broad guard denied AF_PACKET/IPv4/IPv6 capture/traffic and records its prevented attempts. RUN_LIVE_LLM_TESTS=0; existing native regressions use verified legacy feature fixtures and the existing persistent `.security-ai-demo` backend, not operational raw inference or these research artifacts.

Initial failures were investigated and retained, not counted as passes:

- ML/SOC Python initially used for ML isolated-package import:511 passed,1 failed; corrected ML interpreter plus missing source paths:568 passed,1 failed; full explicit package paths produced the final630 passes. ML `.venv` lacks pytest/Ruff; existing SOC test/tool dependencies were reused without installation; model training and ML broad tests use ML Python.
- SOC first guarded invocation omitted repository root from spawned-child import path:734 passed,35 failed,1 skipped. Relative-root correction:760 passed,9 failed,1 skipped; independent Export:750 passed,9 failed,1 skipped. Remaining failures were8 obsolete `/tmp` native environment defaults and1 intentional AF_INET identity assertion blocked by the no-network guard.
- Absolute roots with AF_INET deselected: working760 passed,8 failed,1 skipped,1 deselected; Export750 passed,8 failed,1 skipped,1 deselected. Native paths then configured from READ-only verified persistent environment, producing the final passing executions above. No source/security control was changed to hide failures.

Ruff `check src tests`:PASS in both repositories, using the existing SOC Ruff executable from each respective repository cwd/config. SOC whole format:PASS. ML owned8 Python files format:PASS. ML whole format:24 pre-existing violations, preserved (not reported as a full-format pass). `git diff --check` and selected staged checks:PASS.

New tests cover manifest and feature tampering, source/label reference and group leakage, concordant/conflicting labels, float32/order/missing/NaN/Inf, train-only scaler, invalid output, trusted digest-before-deserialize, symlink/ownership, purpose/promotion denial, threshold/model source lock changes, duplicate final test and crash-after-reservation. All unit test data are synthetic; those test executions do not reopen actual34-1 model inference.


## Changed files and next stage

SOC change is this report only. ML adds7 source files,1 test file,3 JSON metadata files and1 report. No runtime, model gate, policy, package dependency or user/Replay file changed. Next stage requires an independent evaluation protocol/data, host/campaign/capture quality evidence, safer measured FP/FN, explicit native adapter and producer parity review, artifact licensing/distribution decision, and physical-server benchmarking. Research training success grants no operating model replacement authority.

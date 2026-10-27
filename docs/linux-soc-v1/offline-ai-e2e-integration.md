# Autonomous SOC Agent — Offline AI / Response Integration

Status: **OFFLINE_E2E_VERIFIED; NATIVE_AND_PRODUCTION_BLOCKED**. Baseline `a93045c`; development branch `feat/offline-ai-e2e`. This work adds no approval system, policy activation, privileged operation, network capture, actual DNS request, firewall change, service stop or paid API call.

## Architecture inventory and actual connections

| Capability | Existing implementation / integration | Evidence level and remaining boundary |
|---|---|---|
| TCX packets / per-CPU clock / window / flow | `ebpf_tc/supervisor.py`, `ebpf/window_evidence.py`, `ebpf/input_eligibility.py` | Existing actual Native events retained. P02/P03 INCOMPLETE. Stored actual nine candidates remain five UNKNOWN/four INCOMPLETE; zero model calls |
| DNS Sidecar / UDP+TCP transaction normalization | `collectors/analysis_feed.py`, `ebpf_tc` Sidecar and `research/total_dns.py` | Existing Native transactions are metadata evidence; they are not admitted DNS9 features |
| Authentication collection | `operational/native_authentication.py`, `authentication_pipeline.py`, `source_store.py` | Existing journal/SSH normalization and declared sources. PAM module-attempt failure is not a final denied authentication; no coercion to final outcome |
| PCAP replay / flow engineering | Existing pinned `research/worker.py` and ML `network_v1_1` producer | Actual retained IoT23 PCAP parsed into Network14, source/feature/label-reference digests validated, existing RF/LR inference run. This is a TRAIN research sample, not independent efficacy evaluation |
| Zeek | Existing pinned OfflineZeek and producer/consumer adapters | Implementation preserved; this task uses the existing pure offline PCAP path, not a new Docker/capture session |
| Network14 | Existing 14-feature producer, catalogue, RF/LR packages, receipts | Real raw-PCAP-to-feature-to-model integration verified offline. No conversion to the separate five-feature model contract |
| Network XGBoost / IsolationForest | Existing JSON packages, adapters, shared five-feature schema and numerical forest | Actual prediction from retained synthetically trained packages; input records synthetic. Not production models or Network14-trained XGBoost |
| Authentication IsolationForest | Existing epoch-aligned five-minute window extractor, five features, package/adapter | Actual numerical forest inference on synthetic event batches; source identifiers retained and windows separately correlated |
| DNS INT8 model | Existing pinned DNSPredictor/scaler/LiteRT worker and DNS9 fixture catalogue | Actual INT8 inference on precomputed Fixture features. Producer/training/calibration provenance remains limited/unverified; raw-query-to-DNS9 parity remains blocked |
| Fusion / risk | Existing `MultiModelFusionEngine`, model vocabulary and `ThreatAssessor` | Network/Auth fusion preserves independent source groups, missing coverage and UNKNOWN confidence. No averaged score, cross-domain actor inference or model-as-fact promotion |
| Policy / safe response | Existing `GovernedExecutor`, `PolicyEngine`, `ToolRegistry`, `ApprovalManager` | New composition registers only source-read and memory-revalidation tools under existing read-only policy. No authority inferred from model labels |
| LLM investigation | Existing `InvestigationPlanner`, `InvestigationOrchestrator`, `ThreatAssessor`, local `OfflineDesktopClient` | Actual planner/executor/assessment flow with explicitly SCRIPTED client. Local injected draft tests prove hypotheses remain separate; no generative model/provider was called |
| Known error / feedback | New bounded composition around existing read tools and audit | One source revalidation for caller-reported `FEATURE_EXTRACTION_INTERRUPTED`; no worker restart/host-repair claim. Unknown errors enter the planner; no automatic model retry |

Operational call path:

```text
soc-agent analyze-offline --input <JSON> --input-sha256 <SHA> --output <new directory>
  -> typed Job / retained original input / attempt audit
  -> existing Feature Extractors or pinned ResearchAdapter
  -> all package Feature/Source/Schema checks before predict
  -> original inference receipts + model/artifact/feature/source identities
  -> existing Fusion (supported packaged model kinds), advisory classification
  -> existing Policy + GovernedExecutor + read-only Tool
  -> unknown anomaly/error: existing Planner -> read-only investigation -> Assessor
  -> source postcondition + original receipt verification + hash-chained audit
```

## New operating code

- `security_ai/workflow_models.py`: discriminated input jobs; common source Envelope; inference record and outcome schemas. Unknown Session/Release/Namespace/interface remain null rather than invented. Eligibility is explicitly `OFFLINE_ONLY_NO_NATIVE_ADMISSION`.
- `security_ai/workflow_inputs.py`: existing Network/Auth extractors, package loader, adapters, native predictors and Fusion; existing pinned PCAP/DNS worker. No fitting, feature formula replacement or new model registry. All selected input compatibility checks precede inference.
- `security_ai/offline_workflow.py`: one-directory/one-attempt orchestration, original receipt persistence, safe response, bounded advisory projection, planning and auditable result restoration. A crash leaves intent and prevents adoption/reset of the same directory; automatic resumption/replay is deliberately absent.
- `security_ai/offline_analysis_cli.py` and a narrow `cli.py` dispatch: pinned offline jobs and read-only result verification. The CLI constructs only the scripted client. Trusted application code may inject an existing LLMClient; it does not enable provider configuration or purchase/call an API automatically.
- `tests/integration/test_offline_ai_workflow.py`: operating CLI and real packaged predictor tests plus failure injection.

Supported jobs are `network14_replay`, `dns_fixture`, `stored_records`, `stored_dns`, `native_checkpoint`, and `collector_error`. `stored_records` accepts existing normalized SecurityRecord schemas, not arbitrary feature arrays; existing ingestion adapters can supply these records. `stored_dns` retains existing DNSQuerySource records but returns INCOMPLETE until the real nine-feature producer contract is verified. It never substitutes a DNS Fixture. `native_checkpoint` reuses the existing input-evidence validator and unconditionally retains the Native inference policy gate.

`NORMAL`, `KNOWN_THREAT`, and `UNKNOWN_ANOMALY` are **advisory classifications of observed model outputs**, not confirmed incident/attack findings. `KNOWN_THREAT` denotes an existing supported classifier label such as BruteForce; it does not confer a blocking capability. Model/artifact failures and incomplete inputs cannot become NORMAL. All source/feature provenance and original scores remain in the saved result/receipts. Source Evidence, model advisory context, uncertain hypotheses and action outcomes are separate objects. The model-aware LLM adapter deterministically rejects generated observations, even when a draft cites an existing evidence ID; hypotheses still require existing reference validation.

## Executed end-to-end scenarios

These were executed through the actual CLI against the frozen export; detailed immutable receipts and hashes are in `.git/offline-ai-e2e-20261027-1/final-cli/`.

| Scenario | Data / actual predictor | Outcome |
|---|---|---|
| A — normal | Actual retained PCAP sample0 -> Network14 -> RF + LogisticRegression | Two actual inferences, NORMAL advisory, policy-governed source read, verified postcondition and audit |
| C — unknown anomaly | Actual retained PCAP sample3 -> Network14 -> RF + LogisticRegression | Two actual inferences, UNKNOWN_ANOMALY, SCRIPTED planner/read tool/assessment, no host response |
| DNS anomaly | Precomputed DNS9 Fixture -> real scaler + INT8 LiteRT model | One actual inference, UNKNOWN_ANOMALY, scripted read-only investigation. Not raw observed DNS or Native eligibility |
| B — known label | Synthetic flow record -> real XGBoost + numerical IF packages | BruteForce/anomaly model outputs, KNOWN_THREAT advisory, existing read-only policy, source continuity verification |
| C — anomaly without attribution | Synthetic flow -> XGBoost BENIGN + IF anomaly | Disagreement retained, UNKNOWN_ANOMALY, scripted investigation |
| Authentication | Synthetic final-outcome events -> five-minute features -> real IF | Anomaly, all42 source references retained, complete scripted investigation after context fix |
| D — interrupted extraction | Caller-reported synthetic error with a valid retained record | Exactly one existing-policy read-only revalidation; INPUT_REVALIDATED_NO_COLLECTOR_REPAIR. No collector restart claim |
| E — insufficient Native evidence | Actual stored Batch3 summary/transport -> unchanged input validator | Nine candidates remain UNKNOWN5/INCOMPLETE4, inference0; original evidence unchanged |

No scenario uses fabricated model predictions. Native/eBPF packets were not freshly collected. Model inference success on a Fixture is distinguished from Fixture/mock inference. LLM results are explicitly scripted/local test drafts; they are not presented as live generative reasoning.

## RCA / bounded failure handling

A first Authentication run preserved a successful actual IF receipt but reported investigation failure: the full feature/source provenance was duplicated into model context, exceeding the64,000-character LLM request limit. The fix projects model identity, artifact/feature/receipt digests, source count and at most eight explicitly marked reference samples. Full provenance remains in original receipts and the final output. A separate new offline attempt completed after the fix; the original failed investigation remains on disk. No Native retry occurred.

Initial broad regression had nine environment failures because the worktree lacked the separately provisioned inference environment. Existing `SOC_RESEARCH_VALIDATION_REPOSITORY` was bound to the real read-only repository environment; no files, dependencies, tests or assertions were weakened. Final independent tests use their own source export and that explicit existing backend.

Other failure injection verifies bad/overflow/14-vs5 features block every predictor, bad package SHA is MODEL_ERROR, Native policy gate blocks inference, DNS raw input is not substituted, partial successful model receipts survive later failure, hostile LLM tools/facts are rejected, input/result/original receipt tampering fails restoration, duplicate attempts fail, CLI pin mismatch creates no attempt, and nonprivileged analysis never requests Root or an Internet/packet socket. Cancellation/crash is not interpreted as successful analysis; a pending attempt is preserved and not adopted automatically.

## Verification and Artifact

- Final related Workspace **959 PASS**; independent frozen Export **959 PASS**.
- Focused integration **26 PASS**, including actual XGBoost/IF on synthetic records and operational CLI gates. Real research-worker executions are separately recorded above, not counted as mock tests.
- Repository Ruff PASS; Format **1,410 files** PASS; Diff PASS.
- Frozen code/test build inputs **1,752**, SHA256 `8b6f878309323f40e4e8e736b859500e6641499a14b5ed5f4fa44e78b606b08b`. Source/Export/Stage pins verified. Generated reports and preserved preexisting Native report drafts are outside this explicit build-input map; Git Tree supplies repository identity.
- Two offline Wheel builds are byte-identical: `autonomous_soc_agent-0.1.0-py3-none-any.whl`, SHA256 `347547be3dd64c208d5cfebce15e0a845fabd22687dd5048038d3c130c3e0897`; **674 entries**. No Root/Native image was generated or promoted by this task.
- The Wheel is unpacked in an isolated ordinary directory for CLI execution and persisted-result verification; it is not installed over an existing release.

Example retained replay input:

```json
{"kind":"network14_replay","flow_index":3,"profiles":["quality","edge"]}
```

```bash
soc-agent analyze-offline --input /absolute/job.json --input-sha256 <exact-file-SHA256> \
  --output /absolute/new-analysis-directory --research-ml-root /absolute/existing/ML
soc-agent analyze-offline --verify --output /absolute/new-analysis-directory
```

The optional research root uses the existing pinned project-local interpreter and verified producers/models. No download, training, arbitrary command, live collector or provider is selected by the job. API callers may use the typed record job with explicitly trusted package manifest pins. Job/feature size, source and model schemas, finite numerical ranges and output audit are checked. Choosing a new output directory is an explicit new offline attempt, not automatic retry/resumption of an uncertain attempt.

Final Commit/Tree, remote confirmation, exact source/wheel hashes, audit verification and preservation checks are recorded in `.git/offline-ai-e2e-20261027-1/git-and-integrity.json`. Only this task's code/tests and this report are committed; the existing Batch2/Batch3 report drafts remain untouched and unstaged.

## Native / production boundaries and remaining work

Campaign Root5/10 and Native4/10, Batch3 Root2/4 and Native1/2 are unchanged; no reservation or consumption. Existing Namespace `net:[4026532232]`, Host development environment, installation/Rollback, prior FAILED/false/UNKNOWN and original Ledger/Audit remain preserved.

The nonprivileged offline analysis/response/investigation core is connected. Full production completion still requires actual Native Capture Integrity and Flow completeness evidence, at least one genuinely eligible Native candidate, verified raw-DNS-to-DNS9 producer parity/golden pairs, appropriate production model/training/score validation and a separately configured/authorized generative LLM if desired. Existing five-feature XGBoost/IF synthetic selection cannot establish Network14 production efficacy. Separate domains do not establish a common actor. Host remediation remains governed by the original policies and exact human approval; this feature registers no such capability.

No old Artifact approval is inherited by this changed code. A later Native release needs a freshly frozen Artifact and existing R1/R2/Root/Native approval contracts. This work does not activate those policies. P02/P03 remain INCOMPLETE; P04 has zero new Native ELIGIBLE results; Native AI, DNS9 operational promotion and production remain BLOCKED.

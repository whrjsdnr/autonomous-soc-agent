# Final SOC Agent integration verification

## Latest bounded Native Continuous verification — 2026-10-29

The approved additional single trial at `608c03e` passed actual Kernel BPF load,
TCX attach, authenticated Producer READY, two fixed local TCP connections, 20 real
Native metadata events, two sealed windows (20/0 callbacks), attestation and cleanup.
One of two Flow candidates was ELIGIBLE; the other remains INCOMPLETE under the
unchanged observed-event timeout contract. A separate new human model Action then
authorized analysis of the retained real Native input through the existing CLI:
two actual RF/LR predictions, one UNKNOWN_ANOMALY Incident, SCRIPTED read-only
investigation/evaluation/response and verified Audit. This is normal test traffic,
not evidence that an attack occurred. No external API or DNS inference was called.

Actual Tk displayed the live Native collector and subsequently the verified retained
REAL_NATIVE model result. Root, ordinary Runtime and authenticated Collector cleanup
were VERIFIED; Kernel link/prog/map snapshots were unchanged. The legacy Ledger
remains81 rows. Historical UNKNOWN/UNVERIFIED/FAILED/false evidence remains intact.

**Bounded Native Continuous network E2E VERIFIED; DEMO_READY.** Unattended production
release, live DNS9/Auth, long-duration/high-load operation and REAL_API investigation
of this Native result are not claimed. Full error register, hashes and test evidence:
[Continuous runtime report](continuous-runtime-integration-report.md).

The report below records the earlier state and is preserved as history.

Final judgment: **DEMO_READY**. Real offline model analysis and verified historical
real API investigations are visible in the existing desktop. **Native AI E2E is
BLOCKED**, not VERIFIED; RELEASE_READY is not claimed.

## Implementation and architecture

The existing Tkinter desktop, background asyncio Worker, Backend application
service, `analyze-offline` CLI, feature/model adapters, Incident contracts, Policy,
Investigation tools, Audit database and `verify_result` are reused.

`Desktop → Worker → Backend → AnalysisService → analyze-offline → existing model /
investigation workflow → retained result + Audit → verify_result → Desktop`.

The AI Analysis page provides Run Offline Job, Stop Owned Analysis, Open Verified
Report, actual prediction rows, Incident classification, investigation plan and
assessment, response postconditions, evidence/provenance and Audit. Incident,
Investigation and Evidence/Audit are separate tabs. All results retain their
OFFLINE_PCAP/FIXTURE/REAL_NATIVE evidence origin and SCRIPTED/REAL_API investigation
mode. Imported reports are explicitly not live collection.

AnalysisService starts one fixed nonprivileged CLI in an owned process group,
keeps the UI event loop responsive, rejects duplicate starts and direct
native_checkpoint/tcx_analysis jobs, records the real child exit code, verifies
results before display and terminates only its owned group on Stop/desktop exit.
Timeout is bounded, failed runs are not retried, unverified cleanup prevents
restart and prevents desktop shutdown from being reported as successful. Imported reports are external evidence, never owned processes to stop.
No API authorization or Root command is exposed by this new page.

Modified production files: `gui/analysis_service.py`, `gui/analysis_view.py`,
`gui/backend.py`, `gui/production.py`, `gui/__main__.py`. New service lifecycle and
actual Tk tests cover process fault boundaries, duplicate start, Stop/close,
missing report rejection, Native entrypoint refusal and display state. README
contains launch and import instructions.

## Real data / AI / investigation results

| Input and execution | Actual outcome |
|---|---|
| Existing real PCAP Flow 0, new owned analysis run | OFFLINE_PCAP; real RF and LR; CLASS_0/CLASS_0; NORMAL Incident; verified Audit; child exit 0 and cleanup VERIFIED |
| Existing real PCAP Flow 1, new owned analysis run | OFFLINE_PCAP; real RF and LR; NORMAL; verified Audit; exit 0 and cleanup VERIFIED |
| Existing real PCAP Flow 3, new owned analysis run | OFFLINE_PCAP; real RF and LR; UNKNOWN_ANOMALY; SCRIPTED investigation through existing read-only tools; SOURCE_CONTINUITY_VERIFIED; Incident/Audit verified; exit 0 and cleanup VERIFIED |
| Preserved historical actual API E2E, reopened in actual WSLg desktop | Real RF/LR predictions and UNKNOWN_ANOMALY; REAL_API plan, read-only tool results, evaluation and Audit reverified; actual table displayed two model rows |
| This work's new external API requests | **0** |
| This work's Native capture / eligible candidates / model calls | **0 / 0 / 0**; no Native verification promoted |

Model identity is retained in each original inference receipt, including manifest,
artifact digest, input fingerprint, source references, latency and score semantics.
The real RF artifact SHA is
`53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603`;
LR artifact SHA is
`661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882`.
Scores remain uncalibrated research scores, not attack probabilities. Incident
classification remains advisory rather than a confirmed attack.

Known-error revalidation, quality rejection, raw DNS and TCX approval gates are
covered by the existing workflow regressions. SOURCE_CONTINUITY_VERIFIED proves
retained input continuity, not host/collector repair. No service/network response
was executed. DNS raw/transaction success is separate from DNS9; its missing
training extraction contract remains INCOMPLETE. Authentication status uses the
existing Backend and stays NOT_ATTACHED when no authenticated source is attached.

Private evidence and screenshot are in common Git directory
`final-soc-integration-20261028/`: analysis-{0,1,3}-result.json,
gui-real-report-validation.json and gui-release-actual-api-report.png. Historical API
result remains under `ai-pipeline-integration-20261027-1/actual-api-e2e`. Existing
`deadline-native-e2e-20261028T033152Z/demo-run-normal.sh` and `demo-verify.sh` remain
untouched. They do not constitute Native verification.

## Policy activation and frozen Native execution artifacts

The approved policies were recorded using existing contracts, preserving the
original 73 Ledger rows and adding only two policy events. Current Ledger: **75
rows**. Automatic integrity and exact development OBSERVE_ONLY policies are
active; they do not grant R1 or Root/Native execution authority.

- Automatic integrity / Native metering receipt:
  `b869d799728ec28c6e07c3ed4392194b56b51ed77d333e4d6d405b78d8ae2c53`
- Root/Native metering receipt:
  `a8768b73c20c7845100788cab06e1f27baeea8f18067e1b5b1d64b2acfe5ad75`
- Parent Namespace receipt:
  `881bb48352eaf10eb4a963494a7a23f81455d348021fa14dbfd499bc42af6ef4`
- Expiry: **2026-10-29T17:15:11+09:00**.

The frozen Native worktree remains at
`323c546f2d6c6f8abc6af97061994d59b2836cdc`, tree
`6bc204048d86412bf48f3ee5d0c32865588b7ca6`. GUI changes use the separate
`feat/final-soc-agent-integration` branch and do not change approved Native sources
or apply their receipts to this new GUI source.

| Frozen Native artifact | SHA256 |
|---|---|
| Source snapshot | b6040fe2465aa729f201d33eb3589b446c2c5f413766c1d33b3e2ddf950bb1e0 |
| Manifest | 349abb555ecb0c6877f11c76801c5676ad0470d8b24b89da3902f3d608cc056c |
| Bundle | 25a7814e5f864ae6415f1b70c006c022fd0891489262e9820649645a37028ce7 |
| Execution image | 88dfad10ef6e26794526386610b6555565dfcdaa8e723073213f81db06ff920a |
| Root manifest | e40ebd2408b5bf587f1b23ae0128c0b76da9498836b7b74218b43c8788d1711f |
| Final automatic Controller manifest | 6dc836483934b03cfe355f8ee1e78ce50c235cc1b18b7b653861702e5809276c |
| Final automatic Controller image | d1f1e0e4b934c4a46931eabda32b3e82f916e57bdc51e4837135888e051bebbc |

Supervisor 26 files and automatic Controller 2 files reproduce identically.
Final Controller is an execution approval target, not an execution authorization.
Host nonconsuming check correctly reports PHASE_D_COLLECTOR_SCOPE_MISMATCH and
Host automatic request pin reports AUTOMATION_EXECUTION_NAMESPACE. Neither is
bypassed. Actual target Namespace internal check is NOT_EXECUTED.

Target inode 4026532232 and Host net:[4026531833] are unchanged. Namespace
privileged entry, lo/route/socket observations and real TCX are not performed by
this integration. Existing positive DNS/45-second historical evidence and all
negative FAILED/false/UNKNOWN evidence remain unchanged.

## Native execution gate

The user's Root/Native/DNS execution intent and terminal availability are recorded.
A fresh independent R1 decision for Native Session
`a8da6bbd-5a6b-497c-86a6-57dfcdc34fb7` is still pending. Availability (“가능”) is not
recorded as risk acceptance. Exact Scope is in common Git directory
`approved-handoff-auto-metering-20261028T082633Z/current-execution-review.json/.md`.

AGENTS.md §33 and the existing R1 contract require explicit human acceptance of
Program 1145 cause UNKNOWN, past global Cleanup UNVERIFIED, FAILED and original
safe_for_next_attempt=false. Existing R1 receipts cannot be replayed for this new
Session/current Ledger. After the decision, Root Controller needs direct Scope /
sudo, actual settled Ledger and strict ACK, fresh official R1 preparation and
receipt, R2/install/Native validation, atomic request publication and READY, then
Namespace internal check PASS before install/Capture. Cleanup failure stops work;
there is no automatic retry. No new approval framework was implemented.

No Root/Native/DNS run, execution reservation or fresh R1 receipt was created in
this task. Campaign **Root11 / Native4**, Batch3 **Root8 / Native1** are unchanged.
OBSERVE_ONLY preserves counts and exact Scope restrictions; production Root cap
10 is not changed. Existing install/rollback, Namespace and user worktree are
preserved. Actual RF/LR on Native evidence still requires ELIGIBLE features and
existing action-specific approval. LLM API and DNS9 are outside Native execution
scope.

## Validation and release artifacts

Workspace focused regressions: **206 PASS**, followed by **81 PASS** GUI/lifecycle
regressions after final display/shutdown refinement. Independent frozen Export: **207 PASS** on the final source. Whole-tree Ruff and format checks pass;
Git diff check passes. Actual WSLg report display, table content and clean Worker
termination were exercised; the screenshot is an actual window capture.

Initial test runs recorded two environment/procedure failures and are preserved:
a worktree-relative absent model interpreter (fixed by the existing explicit
validation-root setting), and SourceGuard correctly rejecting a concurrently
updated Export (rerun on a frozen Export). No assertion or safety control was
weakened.

Final source pins: **630 files**, SHA
`dbe9f23b426e09b33a6aeb2bebdfb07bf89a46b785fdeb761f671ff4e0350ff5`.
Workspace and independent Export Wheels are byte-identical, **1,375,867 bytes**,
SHA `3122551781e21fee50e37df15a90d1d3ecffb69e7ea3c10d4c09310bcbf9da9e`.
They include the new GUI service/view but are **not** approved Root artifacts.
Exact private build evidence: `final-soc-integration-20261028/release-artifact-identity.json`.

GUI launch: `python -m soc_agent.gui --analysis-ml-root /path/to/existing/ML`.
Historical report display: `python -m soc_agent.gui --analysis-result /path/to/result`.
Use the existing project Python environment; no local LLM installation is needed.

Remaining release gates: independent R1 acceptance and actual approved Native
execution; actual Capture Integrity / Flow Completeness / Network14 ELIGIBLE;
real Native RF/LR Prediction/Incident/Audit; Collector/Controller/cleanup evidence.
Until those pass, the release supports the verified Offline demonstration and
must not be advertised as a verified Native SOC deployment.


The selective integration commit is published on
`origin/feat/final-soc-agent-integration`. Native execution source remains frozen
on its original branch; no merge into the approved Native source was performed.
The integration commit/tree are recorded in private
`final-soc-integration-20261028/release-artifact-identity.json` after publication.

## Continuous Replay service extension — 2026-10-28

별도 `feat/continuous-runtime`에서 GUI와 생명주기가 분리된 Replay 서비스, bounded streaming
Network14/실제 RF·LR/Incident·Audit를 추가했다. 기존 Native 진단·인증 감시·Offline 시연은 유지한다.
상시 Native TCX backend는 미구현이며 기존 진단 승인으로 실행하지 않는다.
검증과 제한은 [Continuous Runtime 통합 보고서](continuous-runtime-integration-report.md)를 참조한다.

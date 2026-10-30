# Native AI Orchestration E2E — approved limited trial and preserved recovery history

## Latest result: 2026-10-30 18:34–18:41 KST

**NATIVE_ORCHESTRATION_VERIFIED for this limited Native input → RF/LR → SOCRuntime →
read-only investigation → Assessment → Audit/GUI path, with SCRIPTED investigation.**
This is not real LLM validation, one-hour stability verification or production promotion.
The older failures and UNKNOWN/UNVERIFIED findings below remain unchanged.

Executed frozen implementation: `c542398fcd5820f86b56743f65db6ce279dabaed`, report HEAD
`7a1b6f3e71ac38fce6d3a6febf8b290f80979618`, Release `0.6.3`.
Runtime Session `bd5cd8aa-66b4-4e1d-b997-bc38f9bfb97b`, DNS Session
`0771bfdf-3f98-4181-b21e-3b15772e15c8`, Namespace `net:[4026532232]`, lo/Ingress.
The exact request and Artifact hashes in the candidate section below identify the executed
version. A subsequent four-line Worker status correction is separately tested; it was
not installed into or retrospectively attributed to this Native trial.

Evidence roots (repository shared Git directory):

- Execution: `.git/native-orchestration-final-fixes-20261030T085013Z/review-ready/execution/`
- Independent verification: `.git/native-orchestration-approved-attempt-20261030T093317Z/`
- Machine-readable result: `native-result-verified.json` in the verification directory.
- GUI verification: `gui-current-native-verification.json`, six actual Tk screenshots.
- Immutable execution evidence: `executed-evidence-pins.json` (178 file hashes).

The user confirmed the new Scope/R1 in the real terminal and authenticated directly with
sudo. Ten independent decision records reference the exact request. One Root/Collector
attempt ran; no automatic retry. Eight fixed Root paths were verified/applied, with three
changed configuration contents and existing backups preserved. Root first error is null,
actual child exit is 0; the terminal entry's installed unsupported `--new-process` option
failed before any Scope/Root admission and was corrected to Terminator's supported `-u`.

| Actual measurement | Result |
|---|---|
| Whole bounded execution, including cleanup | 404.593137288 seconds; limit 600 seconds |
| Sum of independently sealed capture intervals | 396.136964112 seconds; excludes detach/re-attach gaps |
| TCX callbacks delivered to Runtime | 54 (34 + 20 + 0 across three epochs) |
| Sealed Windows / Capture Attestation | 3 / all VERIFIED within owned-hook scope |
| Flow candidates | 7: ELIGIBLE 5, INCOMPLETE 2 |
| Actual local DNS | UDP2/TCP1; 3 query/response Transactions, RCODE0 |
| DNS metadata | 14 records: 6 DNS messages + 8 TCP control records; semantic parse errors0 |
| TCP source | Two helper starts / four connections; starts 180.61 seconds apart |
| RF/LR | 8 predictions, four eligible flows in one separately approved sealed job |
| Network workflow Incidents | 2: UNKNOWN_ANOMALY with8 predictions; DATA_QUALITY_FAILURE with0 |
| Investigation tasks | 5 immutable revisions, each claimed once and Queue DONE |
| Investigation result | Read-only source report completed, Assessment/checkpoint revision7, WAITING_HUMAN |
| Runtime security audit | 58 records; chain VERIFIED; model result receipts independently verified |
| Loss / errors | Queue drops0, source gaps0, model errors0, collector restarts0 |
| STOP / Cleanup | Bound TCX ACK, DNS CLOSED/counter/ACK, owned Root and Runtime VERIFIED |

The first sealed eligible job was `35480ca1733c9044da127d11e8aa36ea0dd145fcd78e6eef2afff05b49686937`.
A separate existing model-review terminal displayed that exact job and received user `yes`
at `2026-10-30T09:39:02.062479Z`. Its grant authorized exactly eight RF/LR invocations.
No future jobs, external API or DNS9 authority was generated. The second eligible window
was not approved: its retained Queue entry is POISON / INFERENCE_UNAVAILABLE after Stop,
with attempts1 and no model execution. This is intentional non-replayable cancellation,
not Collector failure; the original job and Queue record remain intact.

Network and DNS source links reach the existing SOCRuntime. The predicted Native Incident
has conflict=true from the actual model evidence; the scripted plan reads its retained
source and escalates for independent human review. No successful conflict resolution or
real LLM reasoning is claimed. DNS evidence revision changes produced distinct task IDs
for the same Incident; all five task revisions have a single claim. Authentication was
not attached. No synthetic events, external calls or new traffic were introduced.

### Independent cleanup and GUI findings

TCX STOP ACK binds generation694824034956530, the approved policy and target Namespace;
receiver joined and socket closed. DNS cleanup retains authenticated CLOSED, final counter,
STOP intent before CLOSED, joined reader/handshake and closed channel/listener. The transient
process observation was EXITED_ZOMBIE; the later service snapshot confirms inactive/MainPID0
and successful exit. All five owned services are inactive with MainPID0, owned Collector
socket absent, target TCX empty, BPF Link/Map arrays empty. The DNS probe child exited0 with
client FDs closed. Root audit preserves its previous prefix.

Global BPF program IDs changed between snapshots; this is not proof of global cleanup.
Global/past UNKNOWN and UNVERIFIED states are not promoted. Ledger remains81 rows with
SHA `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae` and a valid chain.
All4,792 previously pinned evidence files are unchanged.

The initial GUI was no longer running when inspected; its empty log does not establish
whether the operator closed it. Cause remains UNKNOWN. Reopening `soc-agent gui` kept the
same Runtime and did not restart Capture. Two real Tk attach/reconnect checks display
8 REAL_NATIVE prediction records, 5 tasks, DNS3 and VERIFIED cleanup without callback
errors or retained-file changes. Dashboard, Continuous, AI Analysis, Investigation and
System screenshots were captured from that actual stored Native session.

### Post-trial defect and nonprivileged verification

Confirmed defect: after exact model admission, `worker_state` retained
WAITING_EXACT_MODEL_ACTION_APPROVAL while `analysis.state` was RUNNING. In
`continuous/service.py`, successful `start_retained_tcx` now changes Worker state to
ANALYZING and refreshes its observation time. Permission validation still executes first.
A new asynchronous regression proves no state advance before the admission boundary returns.
No Root code, grant validation, resource limit or retention policy changed.

Workspace and independent Export: each77 related tests passed across the final regression
and isolated Unix transport recheck. Initial test invocation lacked the existing inference
environment root; the configured rerun passed that case. The first export/Workspace test
base path exceeded AF_UNIX's address limit; its one transport test passed with a short
isolated `/tmp` path. Failures and correction logs are retained, assertions unchanged.
Two current Native GUI attach/reconnect checks passed. Ruff all-repository check,
format1534 files and diff check passed. Two Workspace Wheel builds and independent Export
match SHA `f5542eb8aedf1cc55011c0bc739a5ae2b5b1a839959dff798a38cc40a9e50d34`.
Native/Root artifacts were not changed or unnecessarily rebuilt; their existing pinned
reproducibility evidence remains separate from this Python display correction.

The completed attempt is consumed. A new Native execution of changed Source requires a
fresh exact Binding and user Scope/sudo; this turn performed no second Native attempt.

## Preserved pre-retest report (historical status)

Date: 2026-10-30 (Asia/Seoul). **Native orchestration: PARTIALLY_VERIFIED; end-to-end NOT VERIFIED.**
Implementation/nonprivileged orchestration remains integrated. New candidate: not installed,
not started, no receipts or reservations issued. It requires fresh direct Scope/R1 confirmation
and user-entered sudo authentication. Model Action and external API permission are not granted.

## Actual attempts and first errors

Two distinct user-terminal-confirmed attempts were made on frozen code
`143c1e6524c8720c408d9240603f10b986a9436b`. Each had a new request, Runtime/DNS Session,
Scope confirmation and sudo authentication. Neither was an automatic retry.

| Attempt | First failure | Actual result |
|---|---|---|
| `.git/continuous-orchestration-integration-20261030T073539Z/native-review/execution` | INSTALLATION: dnsmasq service TimeoutStart contract asserted 15s instead of its reviewed 5s | Root trial 6.7795s; fixed installation completed; Collector/Runtime/DNS never started; actual child Exit2 |
| `.git/native-orchestration-launcher-recovery-20261030T083446Z/review/execution` | AUTHENTICATED_PRODUCER_READY_TIMEOUT, root-trial.py line741 | Kernel Collector and ordinary Runtime started; Root trial45.774s; actual child Exit2; DNS and TCP suppliers never started |

Second attempt: sealed empty capture interval **20.844402598s** (monotonic bounds),
not41.932s of collection: the latter timer includes shutdown/evidence collection after Collector start.
Native packet0, DNS transaction0, Flow0, ELIGIBLE0, RF/LR0, Incident0, investigation task0.
One empty capture-window assessment VERIFIED; no Native analysis job was generated.
Queue/drop0; no external API. An empty attested window is not Packet/AI E2E success.

The producer reported policy `528250b98e91a3b73c05af4fc73a9c2cb59ca6a72814a820742cc41d59d332e2`,
but Launcher READY retained prior policy `34c8d3cb29f8dda4fc67ced661c6fab284209ce328612398bfb30dd0f209a3f1`.
Therefore the new request could never satisfy READY. This is a Launcher binding defect;
it is not evidence of a TCX event-receive failure. The preflight missed that literal.

On owner shutdown, the waiting DNS Listener raised `HELPER_LISTENER_CLOSED`. Runtime
recorded that secondary error; Root retained the original READY failure separately.
Runtime journal lookup timed out after15s. The underlying journal delay cause remains UNKNOWN.

## Error list and repairs

| Finding | Minimum repair | Evidence / remaining limit |
|---|---|---|
| dnsmasq5s contract checked as15s | Reviewed Launcher checks per-unit5s/15s/90s values | Recorded effective contracts pass; wrong timeout/capability/UID/resource mutations rejected |
| READY compared prior policy SHA | Existing process_identity observation helper accepts the verified current request's policy and namespace; candidate Launcher embeds exactly the tested function | Correct current pin accepted; exact prior pin/tampering/scope/stale heartbeat rejected; no new authority |
| Owner Stop before Helper admission looked like transport failure | DNSProducer records owner intent, joins owned handshake and persists local-listener-only cleanup | No Helper CLOSED fabricated; helper cleanup NOT_OBSERVED, global UNKNOWN; unsolicited closure/peer failure still fail |
| STOP ACK could precede recorded request time | Record intent before send; retain send failure and prevent duplicate attempt | Immediate ACK / failed send regression; existing authenticated CLOSED checks retained |
| Journal timeout discarded partial evidence | Current-boot200-line tail, existing15s bound; preserve partial stdout/stderr, timeout and unknown child exit; continue other cleanup | Actual candidate cleanup statements tested; timeout still marks evidence incomplete and cannot produce overall success |
| New candidate inherited old Runtime/Python Source | Bind service PYTHONPATH to new frozen Export; prepare isolated DNS Python using existing dependencies plus exact new Wheel offline | Real `-I -B` imports confirm new package path, matching DNS bundle, Controller imports and no ML import; no Helper/capture execution |
| Candidate Source map included unsupported top-level build metadata | Keep CLI runtime map restricted to src/; retain pyproject/lock in full Git archive/build evidence | Official CLI rejected the draft with AGENT_NATIVE_SOURCE_PATH; corrected map671 files passes, validator unchanged |

Production changes: `continuous/dns_source.py`, `continuous/process_identity.py`.
Tests: `test_dns_lifecycle.py`, `test_dns_source.py`, `test_trial_observation.py`.
Launcher corrections are in the exact unconsumed candidate's `execution/root-trial.py`;
consumed launchers and their first-error records were not edited.
The existing pre-admission Stop regression now asserts normal iterator completion plus
narrow local cleanup, replacing its previous expectation of the confirmed bug. New negative
tests cover unexpected Listener closure, racing peer rejection and failed STOP transmission.
No permission, peer identity, SHA, resource or model-admission check was relaxed.

## Cleanup: independent findings

| Scope | Second attempt evidence |
|---|---|
| TCX Collector / receiver | VERIFIED bound STOP ACK, generation/namespace/policy match, joined receiver and closed socket |
| Empty Window seal | VERIFIED owned-hook counter reconciliation; no packet/flow eligible; global clock accuracy not claimed |
| DNS Helper | NOT_STARTED / no authenticated Helper observed; no CLOSED or process exit can be claimed |
| Local DNS transport / Runtime | Historical UNVERIFIED; secondary Listener error and final Runtime Exit2 preserved |
| Root-owned after-snapshot | Owned socket absent; Collector inactive/MainPID0; Runtime failed/MainPID0; target TCX arrays empty; kernel comparison preserved |
| Runtime journal | UNVERIFIED15s timeout; new collection code preserves partial evidence on any future timeout |
| Global Kernel / older trials | UNKNOWN/UNVERIFIED unchanged; no retrospective promotion |

Nonprivileged tests verify owner-stop local transport cleanup and final Runtime storage
state after a preserved primary error. These tests do not rewrite the real failed trial.

## Regression and builds

| Validation | Result |
|---|---|
| Workspace final related regression | 754 passed in 651.52s (0:10:51) |
| Independent Export final related regression | 754 passed in 658.69s (0:10:58) |
| Workspace Controller/READY/R1/R2/Namespace + recovery | 291 passed in 230.57s (0:03:50) |
| Export same boundaries | 291 passed in 202.82s (0:03:22) |
| Real Tk preserved Native / detach-reconnect / source separation | Workspace5PASS; Export5PASS |
| Candidate actual Launcher contract checks | 16PASS; final embedded functions/current request separately match |
| Official CLI | setup CONFIGURED_NOT_STARTED; doctor integrity/models PASS; start --preview requires direct Scope/R1/sudo; status STOPPED |
| Native Continuous | Six outputs identical across two builds and independent Export; userspace BTF parse, no Kernel load |
| Supervisor / TCX | Eight Supervisor outputs and one TCX object identical in two builds |
| Wheel | Two workspace builds and Export identical |
| Ruff / format / diff | PASS |

The first broad test runs exposed the old expected-error Stop assertion and lacked the
explicit retained-Native GUI input setting (one skip). Both issues were resolved; those
initial logs remain alongside the final reruns. GUI retained data is real previous Native
analysis with SCRIPTED investigation, not this failed attempt or a new external API call.
Replay/model tests use retained PCAP or explicitly labelled fixtures. They are not new
Native capture or model execution permission.

## New exact candidate (not approval authority)

- Code commit: `c542398fcd5820f86b56743f65db6ce279dabaed`; Tree `272fc40357dc8bb611cc7afc498793961a1da5e1`.
- Source canonical SHA: `d69db2b9c0ca524fc1197e8e9905ba74004e6e93b08ed93caaf62038d1d6c1c9`.
- Git archive SHA: `5f89bce597bee36fc08ce929cd468607a7c547fa0784518fa362c1b2e4f4828e`.
- Wheel SHA: `c950798ba40cac732451ba4e0c7d2a8dabb0f114d0b68181d28d9856256ae6c6`.
- Root Manifest SHA: `477dd70a23c5c673f11abe84fbde5acb7266629231f5ac13a394fda47d2ceac5`.
- Request SHA: `d00e7e22f89555a288dbc6d570cc5dee9892217d48c66d4daf697ef267e696ff` (automatic checks; no manual SHA entry).
- Runtime Session: `bd5cd8aa-66b4-4e1d-b997-bc38f9bfb97b`.
- DNS Session: `0771bfdf-3f98-4181-b21e-3b15772e15c8`; Release `0.6.3`.
- Namespace: `net:[4026532232]`, `lo / Ingress`.
- Review: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/native-orchestration-final-fixes-20261030T085013Z/review-ready/approval-package-final.md`.
- Identity: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/native-orchestration-final-fixes-20261030T085013Z/final-artifact-identity.json`.

Eight existing fixed Root paths, three changed policy/Runtime/DNS configurations;
Collector executable unchanged. Backups preserved, no service enable or new Root path.
Whole600s including cleanup; ownerSTOP400/Drain460, services420, RootTERM530/KILL560,
outerTERM590/KILL595. Collector128MiB/CPU25%; Runtime512MiB/CPU50%; Queue32.
Runtime storage256MiB and Root Audit64MiB are polled safety checks, not hard filesystem quotas.
Fixed loopback TCP<=4 connections, two helpers at least180s apart, per-helper35s gap;
127.0.0.1:18080, source18081/18082, existing fixed payload. DNS UDP2/TCP1 to local
127.0.0.53:53 dnsmasq with exact request bytes, only after authenticated readiness.

No old receipt is reused. The new Source/policy/Session needs direct exact Scope/R1
confirmation. Existing upper policy deadline remains2026-10-31T07:00:57.778156Z,
with at least65min remaining at entry; actual decision duration cannot exceed24h.
Historical FAILED/false, Program1145/Heartbeat UNKNOWN and cleanup uncertainty stay visible.
RF/LR requires separate action-specific approval of actual sealed ELIGIBLE jobs.
No DNS9, external API, host-auth collection, external network or automatic retry.

## Operator command

After reviewing the candidate, execute in the ordinary user's own terminal:

```bash
cd /home/geonug/kdt-linux/soc-one-command-runtime
.venv/bin/soc-agent start --home /home/geonug/kdt-linux/autonomous-soc-agent/.git/native-orchestration-final-fixes-20261030T085013Z/native-profile-ready --gui
```

The command displays exact Scope/R1, asks for `yes`, and invokes sudo directly on that
terminal. It never asks the user to copy a SHA or send a password in chat.
Use the same `--home` with `status`, `gui`, or `stop`. GUI closure does not stop the backend.
This command is not evidence of an executed/passed new test. A consumed or expired
review must fail closed, not be retried with the same receipt.

## Preservation and release judgment

4,792 pinned prior files unchanged. Ledger81 rows and verified chain unchanged:
`07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae`.
No later Root installation, namespace entry, traffic, model/API call, receipt or reservation
was performed during offline repairs. The earlier two installations and their backups remain
as actual trial history, separate from this statement.

**ORCHESTRATION_INTEGRATED** applies to nonprivileged implementation.
**Native Orchestration PARTIALLY_VERIFIED / new execution awaiting confirmation**:
empty-window/TCX closure was observed, but Packet/DNS→models→Incident→SOCRuntime
was not reached. RELEASE/OPERATIONS_VERIFIED is not asserted.
Evidence directory: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/native-orchestration-final-fixes-20261030T085013Z`. The root cause of historical heartbeat and journal latency
remains UNKNOWN; the next admitted single trial must independently validate Helper CLOSED,
final counters, STOP ACK, Window Seal, Root and Runtime Cleanup.

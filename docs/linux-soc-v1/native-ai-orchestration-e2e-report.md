# Native AI Orchestration E2E — failure recovery and exact retest preparation

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

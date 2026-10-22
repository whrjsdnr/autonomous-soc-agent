# NATIVE_SOC_PHASE_D Diagnostic E2E Report

## Overall Status

**BLOCKED awaiting exact-SHA diagnostic-only approval and privileged preflight.**
Offline diagnostic preparation is verified; actual Unified Native E2E is PENDING.
Production qualification remains FAILED because the full Export regression had
2 failures. Those results are not erased or called flaky. No Root installation,
OS authentication, Native capture, BPF load/attach or DNS traffic was executed.
Native AI, DNS9 and production promotion remain BLOCKED.

## Export Failure Assessment

| Failure | Diagnostic-only impact | Remaining concern |
|---|---|---|
| Operator response Timeout | NON_BLOCKING_FOR_DIAGNOSTIC_E2E for the direct headless Phase D entry | Not used by that entry; operational API timeout/outcome ambiguity still unresolved |
| Legacy Zeek READY/ACTIVE assertion | NON_BLOCKING_FOR_DIAGNOSTIC_E2E for this specific polling assertion | Preparation, cleanup, decoder and host resources remain shared; resource latency not proven harmless |
| Targeted SIGTERM negative-control child READY timeout | NON_BLOCKING_FOR_DIAGNOSTIC_E2E for failure before the unguarded baseline received a signal | Historical child startup delay UNKNOWN; actual protected branch passed |
| Existing Hook/resource ownership | Conditional privileged preflight required | UNKNOWN is not absence; Inspector failure/conflict blocks attach |

These classifications do not waive the required Native READY, START, STOP,
SIGTERM, Deadline, integrity or cleanup gates. They justify requesting one limited
diagnostic execution, not executing it without explicit approval.

### Operator evidence

Full test: `test_fixture_pipeline_peer_approval_simulation_and_restart[SCRIPTED]`.
`operator_request` timed out at `reader.readuntil`, asyncio TIMEOUT5s, not a kernel
errno. Original immutable read-only test Audit records execute request, STARTED,
SIMULATED with real_os_handler_calls0, and OPERATOR_RECEIPT. The pure operation
committed despite missing the client response deadline; automatic retry is unsafe.
Per-stage monotonic latency, original CPU/memory/thread/process residual state
and I/O contention were not recorded. Stored wall timestamps are not substituted
for those missing measurements. Exact latency cause remains UNKNOWN.

The direct Phase D path runs `phase_d.execute -> supervisor_startup.execute ->
SupervisedSession.command / offload_session.execute`. It does not start the
Operator API or call operator_request. The real startup regression now fails if
OperatorServer.start is reached. No Operator timeout, permission or audit policy
was changed to obtain this classification.

### Zeek READY evidence and shared boundary

Full test: `test_partial_append_drains_after_exit_and_recovers_no_inference`.
A complete sequence1 READY line exists in the original mock stream. Its immutable
Audit records ZEEK_STREAM_PROGRESS sequence1 and total_received1, proving the
record was consumed. COLLECTOR_STARTED/ACTIVE was not observed before the test's
fixed100ms assertion; this does not prove READY was absent. Exact historical
thread scheduling remains UNKNOWN. The existing legacy path offloads polling,
including empty network/DNS persistence and progress audit, through to_thread.

Phase D prepares that adapter and closes it, but does not call its `start()`;
DNS uses offload_session's separate analysis-worker READY Event. This branch
checks analysis_errors after wake-up, verifies START peer/session/release/scope/
sequence, then sends the one-shot START before capture. A new assertion in the
existing real startup test forbids the legacy start path and confirms both the
Phase D DNS worker and shared adapter stop execute, even after TCX processing
failure. Decoder, persistence and host resources are still shared risks: actual
DNS deadline and cleanup must be observed in the authorized Native run.

### Additional targeted startup observation

The first focused root-worktree run was173PASS/1FAIL: the unguarded SIGTERM
negative-control child did not print READY within its test's3s readiness bound.
No signal had yet been delivered. The guarded actual termination case passed.
The complete module subsequently passed7/7 in isolation. Current ordinary-user
import-to-READY measured1.304s, available memory7,339,504kB and loadavg0.37/0.67/1.03;
these current samples do not reconstruct the historical failure. No timeout was
increased. The final fresh independent Export focused run passed all174 tests.

## Approval / Existing Policy

No approval verifier was modified. AGENTS.md requires relevant pytest/security
validation; the existing NativeCampaign enforces exact Release/Scope, single-use
approval bytes/hash, budget and OS authority. It contains no all-pytest-pass gate.
Prior full-suite-only release qualification remains failed. The latest user
instruction permits preparing a limited diagnostic exception request while
preserving production constraints, not automatic Root/Native execution.

A diagnostic-purpose approval must explicitly acknowledge the unresolved full
regression and grant exactly one fixed-image installation and one Native attempt.
This report/request is REQUESTED, not APPROVED. The existing receipt and terminal
scope confirmation remain required. Unknown privileged resources are investigated
by the approved fixed Inspector before any TCX attach; no foreign resources may
be deleted. No policy code or Native Gate was weakened.

## Release — Diagnostic Candidate Only

| Identity | SHA256 |
|---|---|
| Version | `0.6.3`, LIMITED_DIAGNOSTIC_NOT_PRODUCTION |
| Phase D Manifest | `06a86ab9357803a586880d9a255a86fdf4509e154beb7688341b006602ec1fb2` |
| Source Bundle | `00cedc05322547f87798ef8f248b6edbaae68098b772af5691b707bfb4263ab9` |
| Execution Image | `7789cefc7c5215f093452fb2b3971d1927773fbf388f2644557a7bb7d5e83d8d` |
| Root Manifest | `162d2f949ebb923b7aa83410615cde8bcdbaa836705768c61364e1bf0c52bc01` |
| Frozen source snapshot,1,699 inputs | `66faec30073be62ac7395014c2b5ffe4b4ef9269272d9a57c128ec2825638860` |
| TCX object | `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06` |

The only new code edit in this task strengthens an existing branch-selection and
shared-cleanup regression; product sources and authority rules are unchanged.
A single formatting blank line was normalized with AST identity proven. Fresh
builds after that edit, not earlier build certificates, are the final diagnostic
build evidence. All26 artifacts match between independent build-A/build-B;
physical build directories differ while the reviewed immutable deployment path
is the explicit same input. Runtime artifact hashes also match the earlier
candidate; this does not transfer any previous approval to this purpose.

Baseline Git is9a12fe9e5b7a3569f9cfcf82cbdd92e55e8436b0. The existing release
branch is `release/native-soc-phase-d-0.6.3`; no shared-main push is allowed.
Final Commit/Tree and index-to-snapshot proof are recorded after commit in private
`diagnostic-e2e-review/post-commit.json` and `diagnostic-approval-request.md`.
The generated report is excluded from its own source digest; its final bytes
are bound by that Git tree. This avoids claiming a self-referential Commit SHA.

## Verification

- Final independent Export safety/core regression: **174PASS**,88.12s, exit0.
- Includes exact receipt/budget/single use, Inspector privilege isolation and
  owned-resource preservation, TTY/START peer/session/replay/timeouts, SIGTERM,
  first-error/partial failure cleanup, Clock194ms/10ms bound, Phase D Plan/Scope,
  flow eligibility, real capless file-only Zeek READY before START, and the two
  previously failing modules. All Root/authentication/capture entries are mocked
  or denied; real IPC and owned ordinary-user test-child signals are distinguished
  from actual Native capture. No new test count is treated as Native evidence.
- Final SourceGuard and start/end path-hash maps match in release view and fresh
  Export. The earlier user Workspace remains dirty; only the qualified source
  view, Export and index are compared, not unrelated user files.
- Fresh independent dual build:26/26 equal. BuildA 10.466s;
  BuildB 10.376s. These are build timings, not Capture metrics.
- Previous full Export remains5909PASS/2FAIL/30SKIP. **Not rerun** under the latest
  E2E-first priority; not called production qualified. Prior Workspace3286PASS
  supplementary result is historical; it is not a fresh whole-suite success.
- Earlier isolated modules33PASS and first diagnostic Export174PASS are separate
  evidence; the root173PASS/1FAIL is retained, not overwritten by later passes.
- Ruff/Format/Diff and actual staged-blob/Source Snapshot comparisons are required
  before the diagnostic-branch commit; final results are in the postcommit proof.

## Native E2E / Eligibility — NOT EXECUTED

TCX Capture, Network14 new candidates, DNS capture/analysis, Supervisor Native
lifecycle and whole Native Cleanup are PENDING. No new packet, feature, DNS,
loss, CPU/RSS, flow completion or cleanup measurements exist.
Historical Release0.6.2 remains FAILED:194.004499ms inversion root cause UNKNOWN;
10ms bound unchanged. Historical dispositions remain late reject1 + pending
abort1 + post-error policy discard2245 =2247. Existing four Network14 candidates
remain INCOMPLETE; unpreserved candidates UNKNOWN. No eligibility relaxation,
NaN/Inf replacement, timestamp rewrite or fixture-to-Native promotion occurred.

## cgroup Ownership and Minimum Native Conditions

Historical cgroup programs6332/6336 ownership stays UNKNOWN. Their absence,
ownership or leak status cannot be inferred from the ordinary-user diagnostics.
Before any approved attach the fixed privileged Inspector must successfully
snapshot Program/Map/Link, `/sys/fs/cgroup` attach targets and lo ingress/egress
filters, check TCX ownership/collision, and bind observations to this session.
After owned TCX FD release it repeats the inspection. Other-service programs are
never detached. Query failure is not absence; unknown unsafe Hook ownership blocks
capture. Historical zero owned Maps/Links/lo-filters does not upgrade global Cleanup.

## Budget / Requested Scope

Actual Ledger usage stays Native2/5 and Root2/5, three remaining each. No new
reservation or attempt was made. All8 protected user files and104 historical
records are unchanged; Ledger SHA remains
`a8c59d0468ad30bdd313b2d98538c6ae531371edb205fdf782efdf2cd4b2df60`.
Existing0.6.2 installation remains unchanged, Root Manifest
`56e1b7bc8a2a7a2ebd6902899f349b5fae7432f24d492ce8dab1a92b90e72dc4`.

Requested diagnostic exception, after explicit exact-SHA approval only:

- One fixed-image Root update of9 files in `/usr/libexec/soc-agent-ebpf`, root:root,
  executables0555, others0444. Atomically retain exact0.6.2 rollback at
  `/usr/libexec/.soc-agent-ebpf.rollback-56e1b7bc8a2a7a2ebd6902899f349b5fae7432f24d492ce8dab1a92b90e72dc4`;
  verify no backup collision and installed SHA before operation.
- One Unified Supervisor Native attempt. TCX net:[4026531833],lo/Ingress,
  max300s/4096 metadata/Queue32, each privileged role AS256MiB/CPU20s.
- DNS same namespace/lo,127.0.0.53:53, `native-0516.localhost.` A, UDP1/TCP1;
  shared10s/capture<=7s/packets32/snaplen512/Queue32. Existing loopback resolver
  listener is observed read-only; never replace an existing conflicting service.
  Zeek existing RAM512MiB/CPU1 profile. No external DNS or settings changes.
- Inspector SYS_ADMIN read-only; Broker BPF+NET_ADMIN; GUI/Network14 ordinary UID.
  Existing TTY scope confirmation and one fresh sudo/PAM password, entered directly
  by the user. Never store, collect or log the password.
- No automatic retry, new-SHA approval inheritance, pinning, external deletion,
  packet drop/modification or unapproved traffic. Preserve first failure and
  independent collector results; actual completeness/quality is evaluated anew.

## Next Required Action

Review the final exact Commit/Tree, SHA, known failed regression and bounded scope
in `diagnostic-approval-request.md`. Grant or reject the one-shot diagnostic
exception using the existing approval contract. Without that explicit approval,
installation/authentication/attach/capture remains blocked. A diagnostic success
still does not authorize Native AI, DNS9 or production promotion.

Private proof directory: `.git/native-soc-phase-d/worktree-063/diagnostic-e2e-review/`.
Includes failure-impact-assessment, environment snapshot, import-timing samples,
root safety failure/isolation logs, old/new source maps, final dual-build evidence,
final Export174 log, and append-only pending approval/commit proofs.

---

## Prior full-regression failure report retained unchanged

# NATIVE_SOC_PHASE_D Release 0.6.3 — Full Export Qualification

## Overall Status

**BLOCKED: mandatory full independent Export regression failed.**
This is not READY_FOR_APPROVAL. No installation, authentication, BPF load/attach,
Native capture or DNS traffic occurred. No APPROVED receipt, budget reservation,
Stage, Commit or Push was performed. Latest explicit user instruction withholds
Root and Native approval. Native AI, DNS9 and production promotion remain BLOCKED.

## Latest Validation

| Verification | Observed result |
|---|---|
| Workspace supplementary run | 3,286 passed / 30 skipped; 271.34s |
| Workspace current-node coverage | 6,029 nodes: those fresh passes/skips plus 2,713 exact-source unchanged complete-file passes reused; not a single full-command pass |
| Independent Export full fresh run | **5,909 passed / 2 failed / 30 skipped**, exit1, 3,240.02s |
| Isolated reproduction, both failed modules | 33 passed / 0 failed, 7.71s; does not override full-run failures |
| Source before/after | All 1,700 selected file hashes unchanged in release Worktree and physical Export |
| Existing dual build | 26/26 identical; candidate only, not final qualified Release |
| Protected user/evidence inputs | 8 user files + 104 historical evidence files unchanged |
| Installed Root release | Existing 0.6.2, all 9 file hashes/ownership/permissions unchanged |
| Ruff / Format / Diff | PASS in Workspace and release Worktree; 1,401 / 1,357 Python files formatted |
| Root / Native budgets | Both **2/5 used, 3 remain**; zero used in this task |

Export contains 5,941 selected tests. The larger Workspace has 88 additional
user/untracked cases outside the reviewed release. The Export run reused zero
prior passes. Thirty skips retain existing explicit environment/soak prerequisites;
no live LLM/API tests were enabled. Seven upstream fork-in-multithreaded-process
warnings are retained in the raw log. No test or assertion was removed to pass.

## Failure 1 — Operator response timeout

Test: `tests/integration/linux_runtime/test_final_integration_audit.py::test_fixture_pipeline_peer_approval_simulation_and_restart[SCRIPTED]`.
First API: `operator_request` awaiting `asyncio.wait_for(reader.readuntil(...),
timeout=TIMEOUT)` in `linux_runtime/operator.py`; original exception TimeoutError,
configured limit 5s. This is an asyncio deadline, not a kernel errno.

The original failed test database was opened with SQLite `mode=ro&immutable=1`.
Audit sequence20 records execute request; sequence21 STARTED; sequence22 SIMULATED
with real_os_handler_calls0; sequence23 OPERATOR_RECEIPT. Therefore the pure
simulation and Receipt were committed despite the client not receiving a response
within its deadline. No real OS response action occurred. A timeout must not be
replayed automatically as though no work happened.

Code inspection shows request validation, synchronous Audit operations and final
Receipt work outside the server dispatch-only `wait_for` interval, while the
client bounds the complete response wait. This identifies the timing boundary
and committed outcome, not the exact historical monotonic latency of each step.
The stored wall timestamps are not substituted for missing monotonic timings.
Exact scheduler/I/O/resource causality remains UNKNOWN. The same two-mode module
passes in isolation without changing production deadlines or source.

Necessary next evidence: per-step monotonic instrumentation for request validation,
dispatch, receipt commit and socket send, with a controlled slow-audit reproduction.
Only then choose a minimal protocol/performance correction. Do not simply increase
TIMEOUT or suppress the timeout. No unproven production change was made here.

## Failure 2 — asynchronous Zeek readiness assumption

Test: `tests/unit/zeek_live/test_contract.py::test_partial_append_drains_after_exit_and_recovers_no_inference`.
After appending the remaining READY line the test sleeps a fixed 100ms and expects
ACTIVE; actual state remained LAUNCHER_STARTING. The collector performs `_poll`
through `asyncio.to_thread`, so fixed elapsed sleep does not prove polling and
state transition have completed. A thread/loop completion signal is the correct
synchronization candidate; the original failed run retained no thread scheduling
trace. This test and its whole module pass in isolation, so no Stream parser,
TTY/START or Capture defect is confirmed by this failure alone.

A future minimal test correction must await actual poll/state completion under a
bounded test deadline and inject a slow reader to prove the race, while retaining
partial-line, ACTIVE, CLOSED, no-inference and Cleanup assertions. No production
state or eligibility check was weakened. No timing-based source patch is accepted
as a final release fix without its reproduction and full revalidation.

## Source and Artifact Identity — provisional, NOT executable approval

Baseline HEAD / origin/main observed:
`9a12fe9e5b7a3569f9cfcf82cbdd92e55e8436b0`.
Existing release branch: `release/native-soc-phase-d-0.6.3`.
No new Worktree was created after restart. Shared main/user changes are preserved;
the existing release Worktree remains the reviewed export/index view.

| Candidate identity | SHA256 |
|---|---|
| Phase D Manifest | `06a86ab9357803a586880d9a255a86fdf4509e154beb7688341b006602ec1fb2` |
| Source Bundle | `00cedc05322547f87798ef8f248b6edbaae68098b772af5691b707bfb4263ab9` |
| Execution Image | `7789cefc7c5215f093452fb2b3971d1927773fbf388f2644557a7bb7d5e83d8d` |
| Root Manifest | `162d2f949ebb923b7aa83410615cde8bcdbaa836705768c61364e1bf0c52bc01` |
| TCX Object | `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06` |
| Candidate source snapshot, 1,699 files | `49f114930db133b1c56c852e05bd4628ac3daebfdc5f696e233613de091608a6` |

The generated report is excluded from its own source digest; a future successful
Stage/Commit must bind its final bytes separately. No source/test change occurred
after the failing Export run. The 26 equal artifacts remain candidate evidence,
not proof that mandatory regression passed. Any future source/test fix requires a
new frozen snapshot, fresh dual build and appropriate regression; old results
must not be relabelled as results for the amended input.

The runner checked all SourceGuards before asserting pytest's nonzero exit. Its
failure was the failed tests, not SOURCE_CHANGED_DURING_BUILD. An explicit after-
failure map confirms original start hashes match all 1,700 paths in both views.
Earlier failed/interrupted logs are unchanged; aggregate rechecks do not erase
this full-run failure.

## Preservation / Git / Approval

The append-only Ledger remains SHA256
`a8c59d0468ad30bdd313b2d98538c6ae531371edb205fdf782efdf2cd4b2df60`;
its chain was verified before this run. Original creation-time budget JSON is not
rewritten; actual reservation history is Native2/5 and Root2/5. Existing Audit,
Native evidence, user files, models and raw datasets are not staged or altered.

**Commit/Push and final approval request are withheld** because the user requires
all mandatory validation to pass first. There is no newly confirmed Commit/Tree,
no final Stage equality proof, and no authorization to execute the provisional
Artifact. Prepared private finalization scripts were not executed after failure.
The request can be finalized only after the failed gate is resolved and the exact
amended source/export/index/artifact identities are checked.

Future requested scope remains one exact-SHA Root update preserving installed
0.6.2 and one Supervisor run: net:[4026531833], lo/Ingress, max300s, 4,096 metadata,
Queue32, each privileged task AS256MiB/CPU20s; DNS existing local-only one UDP and
one TCP query, 10s overall/7s capture/32 packets/snaplen512. No approval or budget
reservation for that scope is created here. Password, if later required, is entered
by the user directly in the real OS terminal and never stored/logged/transmitted
through application configuration.

## Historical Native blockers, unchanged

The actual 0.6.2 execution stays FAILED: 194.004499ms inversion cause UNKNOWN;
10ms reorder bound unchanged. Historical 2,247 dispositions remain late reject1,
pending abort1, post-error policy discard2,245. Four retained Network14 candidates
stay INCOMPLETE; unpreserved candidates UNKNOWN. Cgroup6332/6336 ownership UNKNOWN;
historical owned Map/Link/lo-filter zero does not prove global Cleanup. No offline
run upgrades these Native findings. Native AI, DNS9 and promotion stay BLOCKED.

## Evidence

Private `.git/native-soc-phase-d/worktree-063/` records:
`cycle-11/export-full.log`, `cycle-11/progress.json`,
`cycle-11/input-start.json`, `cycle-11/input-end-after-failure.json`,
`export-two-failures-reproduction.log`, `export-full-failure-analysis.json`,
`final-c9-build.json`, `final-c9-source.json`, `final-preservation-before.json`.
Both prior reports were copied unchanged to `blocked-export-full-report/`.

---

## Earlier report retained unchanged — historical identities, not this approval

# NATIVE_SOC_PHASE_D — Source Stabilization & Native Evidence Recovery

## Overall Status

| Independent verdict | Result |
|---|---|
| SOURCE_STABILIZED | VERIFIED for the observed frozen source/export |
| TIMESTAMP_DIAGNOSTICS_VERIFIED | VERIFIED offline; exact historical kernel delay UNKNOWN |
| TCX_DISCARD_ACCOUNTING_VERIFIED | VERIFIED for retained counters and reconstruction fixtures |
| NETWORK14_OFFLINE_VERIFIED | VERIFIED for saved vector/schema/digest and synthetic formula parity |
| NATIVE_LIVE_REVIEW_READY | READY; REQUESTED review is not execution approval |
| Actual Root / Native Live | BLOCKED awaiting a new explicit approval receipt |

Offline source stabilization is verified for a separately hashed export.
**Actual Root / Native verification remains BLOCKED pending a fresh exact-SHA
approval receipt.** The executed Release0.6.2 remains FAILED. No historical
result or Network14 candidate is upgraded. Native AI, DNS9 and production
promotion remain BLOCKED.

Project: `/home/geonug/kdt-linux/autonomous-soc-agent`.
HEAD and origin/main: `9a12fe9e5b7a3569f9cfcf82cbdd92e55e8436b0`, branch main.
The previous report was copied unchanged to the new evidence directory before
this update. Earlier failed/interrupted runs and stale review materials remain.

## Source changes and attribution

`build.py` was changed at14:48:24KST, and `source_guard.py` at14:52:49KST on
2026-10-22. The old task recorded two different source SHA values during its
candidate preparation. Git Diff, file timestamps and process snapshots do not
identify the writing PID or human/session author: **writer UNKNOWN**. Other
processes were neither stopped nor modified.

The existing build wrapper and SourceGuard were preserved byte-for-byte during
this task. SourceGuard uses bounded inotify plus file hashes, including transient
write/restore detection, and keeps a detected failure sticky. This is detection,
not an immutable lock against another process with the same UID.

The previously failed test was:
`test_phase_d_cli_to_real_tcx_plan_and_dns_preflight_before_auth`.
Expected: `SUPERVISOR_APPROVAL_DENIED`; actual: `SOURCE_CHANGED_DURING_BUILD`.
A fresh unchanged-source reproduction passed without changing its Assertion.
Instrumentation recorded six successful Guard checks over593 input files and
no hash changes. The old run did not retain sufficient event details to identify
the exact writer/path responsible for its failure; its historical cause cannot
be narrowed beyond the observed guard rejection and source-change evidence.

## Confirmed correction and stable execution source

The compiler guard covered an individual `compile_native` call but not the
subsequent package assembly / Python image hashing interval. `phase_d.prepare`
now reuses the same SourceGuard around the **whole prepare transaction**.
A mutation after compilation, including modification followed by restoring the
same bytes, prevents a candidate from being returned as successful. A real build
exception remains the first error, and observer FDs close on failure.

Changed runtime file:

- `src/soc_agent/security_ai/ebpf_tc/phase_d.py`
- Before: `954d5acc546a0145dd884ada634bd0c8b47add0324ee3496f98224c4f17ee7e2`
- After: `36f7c284d671d9988106e59ee1ad8236b245c3587cb6841ddc48f8db8d264133`

Added behavior tests:

- `tests/unit/ebpf_tc/test_source_stabilization.py`
- SHA-256: `7c67d72ec35d3252c097f5180ac1bc0a43b1166627a913ca2775d7387d9d286a`

No changes to `build.py`, `source_guard.py`, kernel event timestamps, reorder
thresholds, TCX attach/cleanup policy or Feature eligibility were needed.

Sources, tests and documentation were copied to a new private `source-export`
while the original inputs were watched. Original and exported hashes agreed.
Build/test execution uses that export with an explicit PYTHONPATH and ordinary
UID; compiled output, candidate/session data and test results are outside source
inputs. Guards check inputs around compilation, tests and final sealing.

Full593-file source SHA-256:
`20420e2a40f0eadc0ccbf7b98258d0e60f278cc9126513332d6e19953d8f7d49`.
This is an observed, revalidated snapshot. Future execution still must revalidate
it; a later modification cannot inherit this verification.

## Timestamp analysis

Historical fatal event: ordinal188, CPU1, CPU observation attempt28.
Timestamp `530711793501600ns`, previous maximum `530711987506099ns`:
**194004499ns =194.004499ms** inversion, exceeding the unchanged10ms policy.
Two earlier inversions (173ns and152ns) were within the window.

The source path is:

```text
bpf_ktime_get_ns -> parse -> shared BPF ring reservation/submit
 -> ABI integer ns decode -> EventOrdering -> bounded queue -> Flow Assembly
```

One shared BPF ring is used; CPU attempt counters are not per-CPU buffers or a
global generation sequence. Userspace delivery ordinal, per-CPU attempt sequence
and sorted Flow ordinal have distinct meanings. Original event ns are neither
clamped nor converted to wall time before validation.

The timestamp is sampled before ring reservation. A deterministic interleaving
fixture reproduces inversion without claiming that the ring reordered its
reservations. Kernel ring semantics are documented in the
[official ring-buffer documentation](https://docs.kernel.org/bpf/ringbuf.html).
The exact194ms kernel scheduling/producer/reservation delay is **UNKNOWN**:
there is no historical reservation/commit/receive timestamp pair or previous-max
CPU for that record. No global sequence or buffer identity is invented.

Current host observations: clocksource `tsc`; Python monotonic clock uses
`clock_gettime(CLOCK_MONOTONIC)`,1ns reported resolution. These current facts are
not retrospective proof of Native calibration or clock accuracy. Historical
ClockContract remains KERNEL_MONOTONIC_NS / DECLARED_ONLY / UNVERIFIED.

Retained aggregate metrics:

| Metric | Historical value |
|---|---:|
| Maximum processing queue wait | 8.069356ms |
| Maximum processing call | 6.423440ms |
| Maximum receive gap | 824.444671ms |
| Maximum checkpoint write | 365.700903ms |

These aggregates are not per-event correlation. In particular the checkpoint
maximum does not establish the194ms root cause, and a receiver pause alone does
not invert monotonically ordered event timestamps. Flow merge happens after the
observed rejection, so it is not the rejection stage. Current0.6.3 retains the
previous-max CPU/attempt/delivery provenance diagnostics for the next approved run.

## TCX discard and counter domains

Historical session: `fe6d42c5-c314-4075-91dd-bfe298d9b795`.
Generation: **9245281928320049646**, preserved as uint64 above2^63.

| Domain / stage | Count |
|---|---:|
| Owned hook observations | 2435 |
| Unsupported, not emitted | 2 |
| Emitted / delivered | 2433 /2433 |
| Decoded userspace received | 2433 |
| Applied to Flow Assembly | 186 |
| Userspace discarded | 2247 |
| Reorder reject, reconstructed | 1 |
| Pending-at-error abort, reconstructed | 1 |
| Persisted post-error discard subset | 2245 |
| Queue rejects / ring reservation failures | 0 /0 |
| Kernel-wide packet drops | UNKNOWN |

Before ordinal188:187 received,186 applied,1 pending. Fatal rejection contributes
one discard, pending abort contributes one, and2245 later decoded records are
counted under fail-closed discard. The1/1/2245 split is reconstructed from code,
recorded totals and a metadata fixture; it is not newly recovered historical
per-packet reason counters. Current reason totals are disjoint and bound to
Session/generation; first error is retained across later errors.

Counter/CLOSED and final2436 transport frames were observed. This does not turn
failed processing Drain into successful Feature Drain. Processing queue peak14,
reorder queue peak10, both within32; no recorded queue rejection/backpressure.

The two CPU attempt gaps occur at delivery297 (CPU1,41->43) and548 (CPU8,84->86),
**after** the fatal188th event. They cannot explain that first failure. Aggregate
unsupported2 is numerically consistent with two absent attempts, but no per-CPU
unsupported breakdown was retained, so exact reconciliation remains UNKNOWN.

## Network14 — four real retained candidates

Current eligibility was recomputed from the actual saved vectors and transport
receipt and exactly matched the historical candidate receipts.

| Flow ID prefix | Packets | Retained Feature fields | Eligibility |
|---|---:|---|---|
| fc7fe230ae84 | 46 | All14 finite float32, names/digest valid | INCOMPLETE |
| e6f1d3e3bc0b | 33 | All14 finite float32, names/digest valid | INCOMPLETE |
| 229fdda8d522 | 65 | All14 finite float32, names/digest valid | INCOMPLETE |
| 8d14c2d92a14 | 42 | All14 finite float32, names/digest valid | INCOMPLETE |

Total packet count186 matches applied metadata. No required field is absent in
those vectors; this is not proof of complete Capture/Flow windows. Source receipt
SHA, per-vector input digest, values digest and eligibility output digest are
recorded in `native-evidence-recovery-v2.json`.

Blocking categories remain capture integrity / processing discards, session CPU
attempt gaps, clock calibration, INCOMPLETE Flow closure, Golden Native parity
and model-artifact provenance. All raw packet metadata for those186 records is
not retained here, so full raw-packet statistical reconstruction is unavailable.
No value imputation, lifecycle relaxation or retrospective eligibility promotion.

Independent C-parser/ML Feature parity uses five **synthetic PCAP fixtures**
(IPv4/IPv6, TCP/UDP, idle/active windows). It verifies offline formulas and all14
features, not actual Native window completion or Native model inference.

## DNS / Supervisor reuse

Existing0.6.3 first-error, STATUS/STOP serialization, SIGTERM, CLI exit and Cleanup
regressions were retained. Historical DNS2 Queries/2 Responses/2 Transactions
and internal deadline success remain valid; its full sidecar completion failed
with SUPERVISOR_CLIENT_CLOSED. Successful analysis is not Unified success.

Current Phase D headless loop can continue TCX after DNS finishes; only the legacy
non-Phase-D branch breaks on DNS completion. No DNS deadline increase is needed
or made. Observed event time still governs30s idle/120s active Flow completion;
approved capture/event caps cannot guarantee a candidate completes.

## cgroup ownership — read-only only

Historical Program6332 and6336 were cgroup_device objects, tags
`461f9f5162fd8042` and `b8f4fb5f08605bc5`. Attach Target / Creator / Session
ownership remain UNKNOWN. Owned TCX6331/Link11 and final Map/Link/lo-filter cleanup
were separately recorded; global Cleanup remains CLEANUP_UNVERIFIED.

Current UID1000, CapEff/CapPrm0, namespace `net:[4026531833]`, cgroup `/init.scope`.
The generic bpftool launcher could not find a kernel-specific binary. The existing
pinned bpftool was then used for fixed read-only program-ID, link and cgroup-tree
queries; all failed with Operation not permitted. This is not proof that the
programs exist or are absent now. No capability escalation, detach, map change or
program deletion occurred. Root observations require the new explicit approval.

## Regression / quality

- Former failed preflight test: passed unchanged with Guard instrumentation.
- SourceGuard/assembly behavior fixtures:12 passed.
- Independent export related unit tests: **504 passed**.
- Integration initially could not import the existing independent ML Feature
  module from the export's default sibling path:5 failures. Existing explicit
  validation-root settings corrected the test environment; no package download,
  model inference or Assertion change. The5 affected tests passed on rerun.
- Initial integration:251 passed /5 failed solely on the missing validation-root
  input. Corrected rerun:all5 affected tests passed. Therefore all256 unique
  related integration tests are verified; the initial failures remain recorded.
- Source/test guards reported no changes throughout candidate preparation and
  the complete unit/integration runs. No existing assertion was changed.
- Ruff check, Ruff format --check (1399 files) and git diff --check passed.
  Exact commands, exit codes and timings are retained in evidence metadata.
- No test was removed, skipped to hide failure, or changed to accept a weaker
  boundary. The newly added tests check stage races and first-error preservation.
- Root / Native runs in this task: **0 /0**, no approval or reservation issued.

## New candidate and Native approval boundary

Prepared Release0.6.3 from the frozen export:

| Identity | SHA-256 |
|---|---|
| Manifest | `fb6be75d18736657693707d749624bad0e3eb8708d9e3a242483b935a55e9b0c` |
| Bundle | `8d90d78c67f5481f3198f4721d87efae5cb8947a7530f735c31a1cfbc460b332` |
| Native execution image | `9178f63ecaadf24ad989120f24620005ddfaa9703d8958c863cd0d23c1b2776f` |
| Root Manifest | `230d92ead48cf4e43b3d70078368f893f12fd2f3aeb58078daa6b576a6c88545` |
| TCX object, unchanged | `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06` |

Build Manifest and the new REQUESTED review bind these identities to the full
source snapshot, dependencies, namespace/lo INGRESS, isolated capabilities,
Zeek command/probe, resources, output paths, new execution ID and Cleanup policy.
The future command imports only the hashed source export through an explicit
PYTHONPATH; it does not silently use a changing Workspace or prior stale review.

Native and Root remain **2/5 used,3 remaining each**. Proposed future scope is one
installation/replacement and one Unified Supervisor Native run, no automatic
retry. Existing TCX300s/4096/Queue32/AS256MiB/CPU20s and DNS loopback-only
UDP1/TCP1/active10s/capture7s/32records/snaplen512 limits remain unchanged.
Root Inspector snapshots are read-only and cannot detach foreign resources.

No new review is an approval receipt. No install/load/attach/capture/DNS traffic
may occur until an explicit receipt matches the newly sealed exact identities.

Fresh review path:
`artifacts/native-soc-phase-d-source-stabilization-20261022/execution-approval-request.json`.

Review SHA-256:
`2b6c6f592e1937e6a6c1ea8d4c7440308956f97b06121466cb5580198548482e`.

Build Manifest SHA-256:
`a7e6de4df35218f0140cc2e9e6e9e2977f87c7ac6d9ff700d32232fbc9936207`.

Review planned execution ID: `25ffc87d-5848-4050-a139-e79e94da8a18`.
Review expiry:2026-10-23 06:24:21 UTC /15:24:21 KST.
The approval-user.json, Native session/result and DNS execution markers are absent.
These are future absence checks, not authority tokens or reserved budget.

## Preservation and remaining limits

Previous approval/receipt/audit/ledger/failure records, installation0.6.2,
rollbacks and user changes remain. All1609 protected files and47 historical
Native artifact hashes were checked. Four SQLite Audit chains (6/6/7/28 records)
were verified with mode=ro, immutable=1 and query_only=ON; their file hashes did
not change. The original five-row Ledger chain verifies, with no new reservation. Git Stage/Commit/Push were not performed.
The Git index is preserved; source identity is proved by the independently
hashed export rather than falsely equating an unchanged Stage with edited source.

UNKNOWN remains: historical source writer, exact194ms producer delay, complete
historical packet replay, cgroup ownership/current object presence, Native clock
calibration and actual0.6.3 Native results. These do not become success through
an offline pass. Native AI / DNS9 / production promotion remain BLOCKED.

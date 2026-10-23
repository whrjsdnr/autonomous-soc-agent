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


# NATIVE_SOC_PHASE_D 0.6.3 Diagnostic E2E — actual attempt 3

## Overall Status

**FAILED** for the approved integrated diagnostic attempt. DNS analysis and owned
kernel/process cleanup were verified separately. TCX processing failed closed;
this is not an end-to-end success or an operational qualification.
All earlier report sections remain historical records with their original identities.

## Release / SHA

Executed approved Commit `22777ce15be384c1a7ea0a8d98f85a5aeb60a0fc`,
Tree `22db2c5edaf5c3d2e6a6bae00ca78978479e6ff9`, Release0.6.3:

- Manifest: `06a86ab9357803a586880d9a255a86fdf4509e154beb7688341b006602ec1fb2`
- Bundle: `00cedc05322547f87798ef8f248b6edbaae68098b772af5691b707bfb4263ab9`
- Image: `7789cefc7c5215f093452fb2b3971d1927773fbf388f2644557a7bb7d5e83d8d`
- Root Manifest: `162d2f949ebb923b7aa83410615cde8bcdbaa836705768c61364e1bf0c52bc01`

## Approval Receipt

The explicit exact-image user approval was translated through the existing
receipt contract, SHA `51f9438ef414bcc2a72aa8a1356f04600e808e1d6f5b049c6260fa451778fa7a`.
Owner-only receipt and exact launch are under
`.git/native-soc-phase-d/live-063-diagnostic/`.
The Ledger records the two historical whole-Export failures as nonblocking only
for this direct headless diagnostic path. Full Export remains5909PASS/2FAIL/30SKIP;
those failures are not relabeled fixed or used for production qualification.

## Root Installation

One installation completed. All9 installed files match the approved Root package,
root:root with0555 executable/0444 data permissions. Previous0.6.2's9 hashes,
ownership and permissions match the preserved read-only preflight snapshot at
`/usr/libexec/.soc-agent-ebpf.rollback-56e1b7bc8a2a7a2ebd6902899f349b5fae7432f24d492ce8dab1a92b90e72dc4`.
One fresh sudo authentication invocation inherited the user's real TTY; password
input was not programmatically read, recorded or counted. Scope confirmation and
START were separate from password entry. No additional sudo invocation was used.

Inspector permitted/bounding sets contained only CAP_SYS_ADMIN; Broker only
CAP_BPF+CAP_NET_ADMIN. Both had zero effective/inheritable/ambient idle sets.
No Inspector SYS_ADMIN capability was passed to the Broker or user Runtime.

## Native Execution

One existing Unified Supervisor CLI invocation, exit1. First failure:
Stage `TCX_DATA_PROCESSING`, API `PacketChannel.error`, ValueError
`TCX_PROCESSING_QUEUE_OVERFLOW`, errno **None**, signal **None**.
This is a synthetic processing/admission policy error, not a kernel errno.
No later control error replaced it, and no automatic retry occurred.

## TCX Capture / Clock / Flow

Actual Kernel load/attach succeeded: Program969, tag`5d24af0965a164b7`, Link1,
net4026531833 / lo ifindex1 / Ingress attach_type46, no pinning.

| Counter domain | Actual result |
|---|---:|
| Owned map observed attempts |153|
| Owned map emitted / socket delivered packet records |151 /151|
| Owned map ring reservation failures |0|
| Owned map disabled attempts |2|
| Receiver shared-budget rejection |17|
| Adapter received |134|
| Network14 applied |53|
| Adapter discarded |81 =8 pending-abort +73 post-error policy discard|
| Total user-space unprocessed/discarded |98 =17 +81|

Conservation:151 =53 +98, with no pending records at final snapshot. Broker send
failures, EAGAIN and EPIPE were0. Kernel-wide packet drops remain UNKNOWN; an owned
ring reservation counter of0 does not prove global packet completeness.
CPU observation-attempt gaps17 are not treated as demonstrated Ring Buffer loss.
Clock inversions0, maximum0ns in this attempt;10ms limit unchanged. The historical
194ms inversion is not reproduced and its root cause remains UNKNOWN.

## Network14 Eligibility

Four **new** candidates below, all14-field vectors/digests valid, all flow closures
INCOMPLETE after processing failure. The historical four candidates remain unchanged.

| Candidate Identity | Packets | Feature fingerprint | Decision |
|---|---:|---|---|
| `2f0622af191589d645e8c8e1f1d0b29460caec298a03cc0df683fad8dbda5683` | 14 | `418c23824d36ba6d46bfb300f34fadcb146e70dc952433cd46d9d7d02b6f58c1` | INCOMPLETE / BLOCKED_CAPTURE_INTEGRITY |
| `1754211df708e50acd2e389e585c5a6e842074ee293ae2e0c53cf52440e21e4c` | 14 | `ccee68f923c13246637587e0f569509728f04b99bdabc91e897566d23f99e813` | INCOMPLETE / BLOCKED_CAPTURE_INTEGRITY |
| `620eefa4e4420e062888ca4a33e7ee20365b6a19c93ff7cde818f431a6520a09` | 13 | `dddf161ebae8971d376b6f356528f8aa2f15ea0bc394a4236a77715f2f0cb76f` | INCOMPLETE / BLOCKED_CAPTURE_INTEGRITY |
| `ee8455db26520903d2a087ab8454c7d9a480a1e151cb240847231e062a81024c` | 12 | `d98e96da252e8aa9eb9c6e452b44ace6731ecc1491ce5b7c2d1a5162acf83564` | INCOMPLETE / BLOCKED_CAPTURE_INTEGRITY |

These53 applied packets were partitioned14/14/13/12. No FIN/RST completion evidence
exists in their feature vectors. Admission loss, fail-closed termination, incomplete
flows and unverified capture calibration block eligibility. The adapter's own
summary still reports ring_loss UNKNOWN while the transport preserves a successful
final owned-map snapshot. These are separate evidence domains; neither missing
adapter provenance nor missing model/native-golden receipts is filled with defaults.
No candidate is promoted based only on finite values or valid digest.

## DNS / Zeek READY / Deadline

Controlled local test only:127.0.0.53:53, native-0516.localhost., A;
UDP1query/1response (transaction49665), TCP1query/1response (49666), valid question
match, RCODE0 and one answer each. Zeek accepted2 completed transactions:UDP1/TCP1,
response_records2; its completed-log model does not independently count query and
response packets or prove retransmission/duplicate-query absence.

Actual12 CHECKSUM_PARTIAL records received and corrected on analysis copies;
12 receipt pairs preserve distinct original/analysis digests. No captured packet
was rejected; Capture reports accepted12/rejected0/socket_drops0. Original bytes
are not retained for a fresh offline recomputation, so receipt/provenance verification
is distinguished from independent payload attestation.

Zeek stream19 records:12 Raw-IP UNSUPPORTED,2 network,2 DNS, plus protocol control;
Counter and CLOSED observed, invalid/duplicate/sequence-gap0. Raw-IP observations
were excluded from Network14. DNS Diagnostics stored2 records.
Visibility `DNS_VISIBLE_CONTROLLED_LOCAL_TEST`; integrity remains
`PARTIAL_PROVENANCE_NOT_END_TO_END_PAYLOAD_ATTESTATION`, not DNS9 eligibility.

Monotonic seconds:

| Stage | Time |
|---|---:|
| Authenticated |67438.365297820|
| Zeek process launched |67438.455474565|
| Zeek script initialization |67440.196561416|
| Zeek READY |67440.211646436|
| Capture started |67440.211960580|
| Capture ready |67440.214497626|
| Capture closed |67447.128221412|
| Analysis input closed |67447.133774501|
| Counter |67447.215545910|
| CLOSED |67447.215819812|
| Cleanup complete |67447.466898680|

Authenticated active elapsed9.105386808s, capture6.916260832s; both within scope.
Internal analysis deadline not expired, analysis/container exit0, container absent.
The launcher elapsed27.401s also includes human scope confirmation/authentication;
it is not substituted for the authenticated10s DNS deadline.

## Supervisor / Cleanup

Supervisor stateCLOSED, final component cleanupVERIFIED, control_errors empty,
first_errorNone in the privileged Supervisor. This does not override the earlier
user-space TCX processing failure. DNS evidence survived the TCX failure.

TCX Counter and CLOSED received; queue pending0, reader/processor/checkpoint writer
not alive, checkpoint submitted1/committed1/rejected0. Processing drain remains
FAILED because of the first processing error; aggregate CLEANUP_UNVERIFIED is
preserved even though all observed resources were released.

Link stateTCX_CLEANUP_VERIFIED. FD evidence checks3 map FDs and1 program FD after
libbpf close using F_GETFD/EBADF in the single-threaded owner:all closed, result0.
Raw individual close return values were not observed and are not invented.
Broker/Inspector/capture owned processes exited; Inspector authority revoked,
channel closed, exit0. Session authorization disposed. Zeek exit/container absence
comes from the Phase-D Sidecar evidence; the unused legacy Supervisor Zeek flag
is not mistaken for a retained Sidecar container. No GUI was opened; native
summary/Diagnostics/Audit projections are evidence, visual GUI validation is PENDING.

## cgroup Ownership

Privileged before/after snapshots are byte-identical by normalized inventory:
12 programs,0 maps,0 links,0 lo ingress and egress filters,7 cgroup paths.
Program969 is absent afterward. Existing cgroup/system programs, including948/965,
were present before this session and preserved. No new current-session cgroup
program is observed. Historical6332/6336 ownership remains UNKNOWN, not retroactively
resolved by this new inventory. No foreign resource was detached or deleted.

## Root Cause Analysis

Confirmed source policy: `_receive` consumed a complete authenticated packet, then
used `packet_slots.acquire(blocking=False)` against the shared32 budget. A single
instant with no slot raised fatal overflow, even without a processing exception,
socket send failure or Ring reservation failure. Native queue peak29 is ingress
only; the budget also includes in-flight and reorder slots. Per-overflow exact
occupancy and CPU scheduling were not recorded, so transient versus sustained
exhaustion and scheduler starvation remain UNKNOWN. The approximately9s maximum
receive gap spans waiting for final terminal traffic during DNS, not proof of a
9s packet-processing stall. Adapter processing max0.684ms, checkpoint max22.209ms;
there is no evidence here that synchronous Audit caused the rejection.

Minimum fix on branch `fix/native-phase-d-packet-admission`: peek16-byte fixed
header solely for scheduling, reserve a shared slot **before full recvmsg**, then
perform all existing credential/PID/session/sequence/schema validation unchanged.
If exhausted, wait once up to50ms, recording waits/resume/timeouts/total/max latency;
there is no busy loop, larger Queue, extra worker, timestamp fabrication or forced
reorder flush. Failure still increments rejection/discard and preserves first error.
Counter/END/CLOSED need no packet slot and remain drainable. Validation, receive or
enqueue failures release reservations; this also fixes a reservation leak on a
physical enqueueFull after successful acquire. A header peek never grants trust.
All32 reorder-held slots can still time out; the fix does not promise lossless
capture at arbitrary bursts or silently extend the10ms reorder contract.

## Regression Tests

Workspace Data Plane15PASS (139.15s), including five new admission/reservation
cases and existing slow receiver, processing failure, Counter/CLOSED/cleanup tests.
Clock/eligibility/Supervisor termination25PASS (77.15s). No full6000-test suite was
repeated or represented as fixed. Independent export and negative-control outcomes
are recorded below after completion. Changed-file Ruff/format and diff pass.

## Evidence Integrity

Append-only campaign reservation/FAILED finish retained,8-row Ledger chain verified.
Old ledger byte prefix unchanged. All112 protected hashes (user8 +historical104)
match.49 completed Native artifact/evidence hashes match their frozen index.
TCX journal hash-chain decoding succeeds using the journal's own TCX binding;
an earlier manual review incorrectly passed the separate DNS approval and failed
binding validation. That helper failure is retained in initial review; it is not
reported as Native journal corruption. The actual Handoff had already parsed its
bound journal and retained FD/send/counter evidence.
Private evidence: `.git/native-soc-phase-d/live-063-diagnostic/` and the immutable
approved build's `supervised-result.json`; no session/raw/model data is committed.

## Native / Root Budget

Native3/5 used,2 remaining; Root3/5 used,2 remaining. One reservation and failed
finish only. Nonprivileged remediation/builds consume neither budget.

## New unapproved remediation identity

Same Release version0.6.3, **different candidate**, not covered by executed approval:

- Source Snapshot: `761dabd21b5e1c38d7de2a93cbc804dc7ef5f8cc498998c084fa1bc70174fb04`
- Manifest: `630280263a93f3c5bcb1d56c7e7f3f0faca81c9d497af9b3674b8d77568e48ac`
- Bundle: `74978c1d513c11f9237d6484bbd9ada69eb18849f2353ecaff7fa1aba7cc572f`
- Image: `af619a24529423a33a70d73b15bd59c697d4ae926acff0b0c259b738d1a8da47`
- Root Manifest: `ed5800729801c40f849c59417c2d09e439b26c0b72e56e05b112ae4f502bcb17`
- Two builds:26/26 identical,1699 source file hashes unchanged across both builds.

Stored under `.git/native-soc-phase-d/receiver-remediation-063/`, produced from the
frozen independent export, no Root or Native execution. Build path is an explicit
identity input; BuildB uses BuildA's reviewed deployment path. Report excluded
from its own Source Snapshot and covered by the eventual Git Tree instead.

## Remaining Blockers / next approval

Actual admission recovery with this changed candidate is NOT Native-verified.
A separate exact-image receipt is needed for one installation and one Unified
Supervisor diagnostic run, same net4026531833 lo/Ingress300s/4096/Queue32/256MiB/CPU20s,
DNS local UDP1/TCP1 active10s/capture7s/32records/snaplen512 and existing container
limits. Preserve installed0.6.3 and its0.6.2 rollback, inspect before attach, stop
on failure, no automatic retry. Root Manifest review must be regenerated for the
new candidate before executing, not copied from the old receipt.

Native AI, DNS9 and production promotion remain **BLOCKED**. Historical194ms
inversion RCA, completed-flow/capture calibration and full Export's two failures
remain unresolved. Component cleanup success does not make overall E2E VERIFIED.

### Completed remediation verification

- Independent frozen Export:5 new admission tests PASS,10 unrelated tests deselected,
  40.36s. Workspace Data Plane15PASS and related Clock/eligibility/termination25PASS
  remain the complete focused regression results; counts are not summed as unique tests.
- Negative control:the new pre-consumption reservation test fails on the **unchanged
  approved old Export** at the expected recvmsg assertion (1FAIL,17.41s). This proves
  the regression detects the original consume-before-reserve behavior. It is not a
  failure of the corrected Export or a claim about Native recovery.
- No source edit occurred after the frozen build;1699 before/after hashes still match.
  The documentation report is excluded from its own Source Snapshot and covered by Git.


# NATIVE_SOC_PHASE_D Packet Admission E2E — actual attempt 4

## Overall Status

**FAILED** overall. Actual Packet Admission recovery and4096/4096 Network14 packet
application succeeded in this run, as did DNS/privileged resource cleanup. Final
Checkpoint serialization failed; final Audit/processing Drain remains unverified.
Do not promote this diagnostic to Native AI, DNS9 or production success.

## Release / SHA

Executed Commit `e50ca0b3b69bbff1115e7c41c4233b78c00254c0`,
Tree `32333f04a51059947b442217275c6884267ca764`,
branch `fix/native-phase-d-packet-admission`, Release0.6.3 receiver candidate:

- Manifest: `630280263a93f3c5bcb1d56c7e7f3f0faca81c9d497af9b3674b8d77568e48ac`
- Bundle: `74978c1d513c11f9237d6484bbd9ada69eb18849f2353ecaff7fa1aba7cc572f`
- Image: `af619a24529423a33a70d73b15bd59c697d4ae926acff0b0c259b738d1a8da47`
- Root Manifest: `ed5800729801c40f849c59417c2d09e439b26c0b72e56e05b112ae4f502bcb17`

## Approval / Budget

Exact user approval translated to a new owner-only receipt,
SHA `77d20a5cb275e3988875761255e836e39d560bd2ff2befa085c08d843906213f`.
The existing single-use CLI/Supervisor and real TTY were used; one fresh sudo
invocation, no programmatic password collection or terminal transcript. Root
installation completed and all9 hashes/ownership/permissions passed read-only
post-verification. Previous0.6.3 Root Manifest162d2f94... was retained in its
full-digest rollback directory; the older0.6.2 rollback is also unchanged.
The previous full Export5909PASS/2FAIL/30SKIP assessment remains unresolved and
was acknowledged only for the direct diagnostic path.

Exactly one reservation and FAILED finish appended. Native4/5 and Root4/5 used,
one remaining each. No automatic retry, new reservation or extra sudo occurred.

## Packet Admission

| Metric / domain | Native result |
|---|---:|
| Packet records received / processed / applied |4096 /4096 /4096|
| Delayed admission waits / resumed |3 /3|
| Admission timeouts |0|
| Immediate admissions, **derived**4096 minus3 successful waits |4093|
| Receiver shared-budget rejects |0|
| Error-pending / post-error policy discard |0 /0|
| Shared budget / ingress queue peak / reorder peak |32 /29 /20|
| Total / maximum admission wait |8.703483ms /4.244158ms|
| Maximum queue residence |3.776804ms|
| Maximum packet processing time |1.842893ms|
| Maximum recvmsg / validation |3.165393ms /7.177961ms|

Immediate admission is not a separately recorded counter; the arithmetic is valid
here because every received packet was processed, no rejection occurred and all3
waits resumed. Queue and reorder peaks are not simultaneous measurements and must
not be added. Packet budget remains32 across ingress/in-flight/reorder,50ms wait
bound unchanged; actual observed waits were shorter than50ms. Queue32 sufficed for
this sample, not proof for arbitrary workloads or sustained rates.

Prior151/53 sample had17 admission rejects; current4096/4096 has0 with3 measured
recoveries. Traffic conditions and duration differ, so no throughput improvement
percentage or universal overflow-free claim is made.

## TCX

Kernel load/attach:Program1000,tag`5d24af0965a164b7`,Link2,lo/Ingress,
net4026531833,ifindex1,attach_type46,no pinning. Actual owned-map final counters:
observed4126,emitted4124,ring reservation failure0,disabled2,other categories0,
delivered4096. Counter retrieval/map lookup/transmission succeeded; Ring Drain0.
**Kernel-wide drops remain UNKNOWN.**

Emitted minus delivered is28. `loader.c::emit` stops forwarding after the approved
4096 event cap while final ring polling consumes records. This is a source-backed
budget-exclusion path consistent with the difference, but no independent per-record
exclusion counter exists. The28 remain explicitly unreconciled capture/delivery
records, not silently counted as Queue rejection, proven kernel loss or lossless
capture. `EMITTED_DELIVERY_NOT_RECONCILED` remains in candidate RCA.

Counter generation1099162056965725441, no CPU observation-attempt gap observed.
CPU distributions:0:1000,1:950,2:1069,3:1077. Four cross-CPU inversions24/81/70/141ns
were reordered within the unchanged10ms bound, late events0, timestamps unmodified.
Historical194ms inversion remains UNKNOWN and was not reproduced or fixed.
Clock calibration/capture completeness are not inferred from successful reordering.

## Network14

12 new candidates, packet counts sum4096; all finite14-float32 contract/digest
checks passed and all12 are INCOMPLETE. Eight earlier vectors are represented by
validated retained RCA receipts; four tail vectors remain available. No missing
raw vector is invented. All closures are PACKET_LIMIT, not complete TCP/timeout
proof. Historical candidates remain unchanged.

| Candidate | Packets | Feature fingerprint | Decision |
|---|---:|---|---|
| `7c951a04f2cd4c761aa410fc355a4a68ea7005e3ccf93627e4432b2fd46a6bb5` | 1033 | `2b10ae7ca5fb6b2919acf309dbf1d864cd915ca6553a3f782b097e5bce671ce0` | INCOMPLETE |
| `d5421fec5a23af77570299f6a86e572ead0a40745fe31f04898b891443943705` | 1029 | `9a7bc8f6acdf946e85c0911fdc954268e9b99cb65668dd496381eda9fe33889d` | INCOMPLETE |
| `7d1eb2f1255ef247bc96f980c9358e33810ef0c1e669d972fb6d11201f2853ed` | 996 | `007532ad77ec0b8179203e0b4b7edf95dac7d773d4d529b85d88951e81867b11` | INCOMPLETE |
| `d633312ed808b7b2d5c23b62cb358502fc3c7b6d24727ada420853b9bd54b29b` | 1002 | `70bb69481ef91e83e06d8454fd0ddd44367cae15f20c34babe5ad9d7c8623fbe` | INCOMPLETE |
| `b183504924cc736590665882bdb3edc2cd19612ede096bac05178c4274b187ac` | 2 | `e55a87ea6e27eeb3fcaaed4c49aec9d2cb90eb34b51cb1f740d947a65e81231e` | INCOMPLETE |
| `650a4ccad028ad8c06396e2ff52d43760e4c2d1cc274c66200181d1674b4bb52` | 10 | `fdbc2e41ccf157afec3ce22c54b0c211e2c3b408d6a808ff0a9fd1888e5de665` | INCOMPLETE |
| `966946bb7611eb29c8f0bc67cfa679c5e9765b9c6125b1500863a77f4504d7dd` | 4 | `4bc5935bcdf4d7841717622e301dc105cee18df789cdb2abb6c3bd5e4772a1d9` | INCOMPLETE |
| `871e337ecbc1d6468464c9bc2017066dfef0c132ac08683588bb1a40c18ce65f` | 4 | `8d0b29ba1006b570f478cc8b7db16a4ee90aa36fd7055b2a2ef9cced9053fa2a` | INCOMPLETE |
| `4d88306e3c8563fa2e8edf161624312e8bafb7c3340bdfe767a16d1e4b1cebdc` | 4 | `0532b55d7c3b5a037d63a3b894e81f84a4fa14573873ad04c8a56989915f1163` | INCOMPLETE |
| `37ade919f0a403534fafc79848a51790a1d655e7c48ed26cfb3d35b8d0d85b08` | 4 | `ad39eaa784b9bdcd88d8ae3398a9d66f7f22ba468ce7d3fe769304b177ec49c7` | INCOMPLETE |
| `b11e40c6cf920a396f75bc865605cc9a10b6f67e81817284c70c2e0ae4b74bd1` | 4 | `169008a38ff672eb822f05e42c8b9d644cbc8667d9119569072380dfc12c8c66` | INCOMPLETE |
| `914324f6c5ffc25a8948ef376d908897a7cbe525aa85c1dd6b7cd377f896e844` | 4 | `7f81581183b11f9df5aa84f98b7ad225ca68eb0c980a80276a0be0cf5d798c75` | INCOMPLETE |

Common blockers:CaptureIntegrityUnverified,PACKET_LIMIT flow incompleteness,
ClockCalibrationUnverified,emitted/delivered mismatch,NativeGolden/Model receipts
UNKNOWN and policy BLOCKED. Four thousand ninety-six applied packets and zero
Queue rejection do not constitute AI input eligibility. Feature eligibility0/12.

## DNS

Controlled local UDP1query/1response +TCP1query/1response against127.0.0.53:53,
native-0516.localhost.,A. Probe transaction IDs49665/49666, question match true,
RCODE0,one answer each. Zeek accepted2 completed transactions,UDP1/TCP1,
response_records2. Query/response packet totals are independently demonstrated by
the probe, not invented from Zeek's completed-log model. Duplicate completed
transactions0; retransmission/query collision ambiguity remains UNKNOWN.

12 captured CHECKSUM_PARTIAL analysis copies,accepted12/rejected0/socket_drops0;
original/corrected digest receipt chain preserved. No network packet or offload
setting changed. Raw-IP UNSUPPORTED remains excluded from Network14.
Counter/CLOSED observed, sequence gaps/invalid records0; DNS Diagnostics2 records,
visibilityDNS_VISIBLE_CONTROLLED_LOCAL_TEST. Integrity remains limited analysis-copy
provenance, not end-to-end payload attestation or DNS9 approval.

Authenticated72653.035805454 →READY72654.281241805 →capture ready72654.282679185
→capture CLOSED received72661.200303536 →analysis/container cleanup72661.444820667
→final cleanup72661.477984748 (monotonic seconds).
Authenticated active elapsed8.447669303s, internal analysis deadline met, final
Sidecar stateCLOSED,exit0,container absent. This independently preserves DNS success.

## Supervisor / Cleanup

Controller CLI exit1, first failure StageTCX_DATA_PROCESSING,
API PacketChannel.error, ValueErrorEBPF_CHECKPOINT_SIZE, errnoNone,signalNone.
No follow-on errors replaced it. Supervisor privileged final stateCLOSED,
cleanupVERIFIED,first_errorNone,control_errors empty. No signal was injected in
this Native run; SIGTERM behavior is covered by regression, not falsely claimed
as an observed Native interrupt.

Counter and Data CLOSED received; reader/processor/checkpoint worker exited,
queue empty,pending0. Writer13 submitted/13 committed/0 rejected/0 outstanding,
writer failureNone. **Those13 commits do not include the rejected final summary**:
last durable row is4095 bytes,stateMETADATA_STREAM_ACTIVE,accepted4096,
finalized_count0. Final12 candidate receipts exist in the final result but did
not commit as a final Checkpoint. Processing/Audit Drain remains FAILED and
aggregate CLEANUP_UNVERIFIED is preserved.

TCX Link cleanupVERIFIED;3 map FDs +1 program FD verified closed after libbpf close
with F_GETFD/EBADF,all_observed_fds_closed true,result0. Raw individual close return
values were not recorded. Entry exited0,Inspector authority revoked/channel closed,
exit0;Supervisor/Inspector PIDs794828/794830 absent. Session authorization revoked.
Zeek container absent, separate from the unused legacy Zeek cleanup flag.

Before/after inventories identical:11 programs,0 maps,0 links,0 lo ingress/egress
filters,6 cgroup paths. Owned Program1000 absent afterward. Existing cgroup program
IDs/tags/attach targets were unchanged; no foreign deletion. Historical unknown
program ownership is not retroactively resolved. GUI was not opened; projections
and Diagnostics evidence do not imply visual GUI verification.

## Root Cause Analysis

Confirmed failure path:PacketChannel processing →end_metadata_stream(PACKET_LIMIT)
→finalize12 flows →request_checkpoint →_checkpoint_text →16384-byte bound.
Repeated candidate RCA contexts expanded the actual final summary to17209 UTF-8
bytes. This is a local synthetic storage-size error, not errno/SQLite EAGAIN and
not Packet Admission overflow. Ring/transport/processing paths already completed.

Minimum remediation in `checkpoint.py`/`collector.py`:a versioned durable encoding
factors identical RCA fields into shared context and retains every per-candidate
row. Original full-summary digest and Audit/Plan binding remain the authority;
Recovery restores the exact original summary before validating those bindings.
Small historical JSON checkpoints remain byte-format compatible and are not
rewritten.16KiB persisted snapshot bound,writer capacity2,FULL SQLite atomic commit,
Queue32 and all Capture/AI gates remain unchanged. Decode validates version,
row bounds/disjoint fields and bounded expansion (existing1024-flow/8MiB session
limits). Oversized non-factorable summaries still fail explicitly, never truncate.

Actual Native final summary reproduced **offline only**:17209 →9651 bytes,
all12 receipts and full semantic digest preserved. This is not a new Native success.
New tests cover24 receipts through writer/SQLite/Audit/Recovery, legacy JSON,
tampering shared fields,unsupported encoding,overlap,count/expansion bound and
oversize rejection. No new dependency/compression library was introduced.

## Evidence Integrity

The11-row append-only Ledger chain and old byte prefix validate.112 protected
hashes (user8 +historical104),previous Native evidence49 files,current Native49
files and retained0.6.3/0.6.2 rollback hashes/owner/perms unchanged. Native journal
18 records hash-chain verifies; recovered stateRECOVERY_REQUIRES_USER_REVIEW,
last link lifecycleTCX_CLEANUP_VERIFIED. No raw/session/model data is committed.
Private current evidence: `.git/native-soc-phase-d/live-063-packet-admission/`;
original approved artifacts/result: `receiver-remediation-063/build-A/`.

## Tests

Final formatted Workspace focused Checkpoint/Collector/Clock/eligibility:44PASS,
7.06s. Independent frozen Export Checkpoint suite:8PASS,0.50s.
Data Plane/Supervisor integration outcomes are appended after completion.
No whole6000-test suite repeated; historical2 Export failures remain unresolved.
Ruff/format/diff are checked on changed files, no assertion/gate weakening.

## New Artifact Identity — NOT approved

Same0.6.3 version,new Checkpoint remediation candidate:

- Source Snapshot: `b0bc3589c0000e8686c86a6ab23757d026c2f5698ea123baaf67ea4890c4bf12`
- Manifest: `b39ede93fc07852502965082745813bb6e62b3b443e82c3d60e154bc0546e8ae`
- Bundle: `c8f0c040b8d4f8f44aa704816624c514544b6ac03f420db0fbe2b9ed7a2fadd3`
- Image: `50efdf7cbbd5f2a683e8003d7dcabbe3d08b5afb7ee3a66b278eb0d01af99683`
- Root Manifest: `ce4d5648fe94344311e886d1bdc57afd84b4c00492afd93f5c3379cbbc541edf`

Two builds from frozen independent export:26/26 equal,1699 source hashes unchanged.
Artifacts under `.git/native-soc-phase-d/checkpoint-remediation-063/`.
Report excluded from its own Source Snapshot; eventual Git Tree covers this text.
No new Root/Native execution for these bytes. New explicit exact-SHA approval and
receipt are required for any further install or Native run.

## Native / Root Budget / Next Required Action

Native4/5 and Root4/5 used,one remaining each. Preserve old campaigns and all
failed outcomes. Next request can authorize only one installation preserving current
ed580072... and older rollbacks,one Supervisor run within existing scope; no retry.
Inspector before/after inspection and existing lo/Ingress/300s/4096/Queue32/
256MiB/CPU20s limits remain. DNS local UDP1/TCP1 active10s/capture7s/32/snaplen512,
existing Zeek resources unchanged. Native AI,DNS9,production remain BLOCKED.

Remaining:actual Native final-checkpoint/Recovery verification,flow completion,
capture-window/counter reconciliation,clock calibration,historical194ms RCA,
historical cgroup ownership,visual GUI verification,and2 whole-Export failures.


### Final verification and superseding candidate

- Data Plane/Supervisor:initial21PASS/1setupERROR (180.07s). SourceGuard rejected
  a fixture build while this session ran Ruff import cleanup in the same source
  tree. That build is invalid and is not relabeled passed. After source freeze,
  the affected cpu_reuse fixture/test passed unchanged (23.79s);all22 unique
  cases are now covered. No external editor is inferred from that event.
- Strengthened the large-summary regression to call Collector._checkpoint_text
  directly, not just its encoder. Final44 focused tests PASS in4.98s.
- This test-only strengthening caused a fresh source freeze and another independent
  double build;the intermediate candidate above is superseded,not overwritten.
- Final frozen Export:Checkpoint8 +approval/budget13 =21PASS in1.01s.
- Final source1699 files unchanged,26/26 build artifacts equal. Source snapshot
  `77d1c688e159b11a842dde2213ac158170d356d3cf1d201372837de9cc95f916`.

**Use only this final candidate for a future approval request**:

| Identity | Final SHA-256 |
|---|---|
| Manifest | `acfa1cd754691612626b7f7715c61c60cd2aa0ecdf2c3f7bd68d66fb010fac0c` |
| Bundle | `c8f0c040b8d4f8f44aa704816624c514544b6ac03f420db0fbe2b9ed7a2fadd3` |
| Execution Image | `50efdf7cbbd5f2a683e8003d7dcabbe3d08b5afb7ee3a66b278eb0d01af99683` |
| Root Manifest | `ce4d5648fe94344311e886d1bdc57afd84b4c00492afd93f5c3379cbbc541edf` |

Final artifact directory:
`.git/native-soc-phase-d/checkpoint-remediation-063-final/`.
No Root/Native run occurred for this candidate;current installed identity remains
ed5800729801c40f849c59417c2d09e439b26c0b72e56e05b112ae4f502bcb17.
New exact approval is required. Native/Root remain4/5;one remaining each.

Additional uint64 Journal/SQLite/Recovery regression:12PASS in0.86s.


# NATIVE_SOC_PHASE_D Final Preflight & Diagnostic Approval Request

## Overall Status

**READY_FOR_APPROVAL for limited diagnostic E2E only.** No Root installation,
authentication, Kernel query, attach/detach, capture or DNS traffic occurred.
The last actual Native run remains FAILED; final Native Audit Drain/Cleanup is
not reclassified by these ordinary-UID tests. Native AI/DNS9/production remain BLOCKED.

**Capacity limit:**1024 mutually different candidate receipts are not guaranteed
representable within16KiB. The tested unique-ID/digest maximum and low-repetition
case fail explicitly with EBPF_CHECKPOINT_SIZE and leave input/previous durable
state unchanged. This is a declared diagnostic limitation, not a successful
maximum-capacity qualification. The next run can still fail for unrepresentable
summaries. No receipt/digest is deleted, no size/Queue/deadline gate is raised.

## Baseline / Preservation

Started from Commit3a0ba617a2546b72bd22ac005382db96363e347f on the existing Release
worktree. Original shared main/origin/main9a12fe9 and user8 files remain untouched.
No new Worktree or competing writer was introduced. Other observed Codex processes
were in separate Adaptive-Agent-Harness repositories; source snapshots,not process
names alone, establish stability.1699 tracked source/test/config files excluding
this self-referential report form the frozen release input inventory.

112 protected hashes (user8 +historical104),both completed Native evidence indexes,
11-row Ledger chain and byte-for-byte ledger preservation verified. Eight known
Native SQLite monitor Audit chains verified through mode=ro,immutable=1,
query_only=ON,with record counts27/6/5/6 and27/6/16/6; all file hashes unchanged.
No migration or Recovery writes were applied to old Native databases.

Installed Root Manifest remains
`ed5800729801c40f849c59417c2d09e439b26c0b72e56e05b112ae4f502bcb17`.
All9 installed files and retained0.6.3(162d2f94...) /0.6.2(56e1b7bc...) rollback
hashes,root:root ownership and0555 executable/0444 data modes verify read-only.
Current Kernel state is not queried without authority; fresh Inspector inspection
is mandatory inside a separately approved session before Capture.

## Confirmed defects and minimum corrections

1. The prior codec accepted non-object summaries,1025 empty receipts and NaN in
   its small-summary fast path; duplicate JSON keys silently accepted the last
   value. Replay of reviewed3a0ba61 functions confirms these behaviors. Both
   persisted formats now enforce object/receipt shape and1024 bound,nonfinite
   values are rejected,ambiguous duplicate keys fail explicitly. Legacy valid
   JSON,including unsorted keys and uint64 values,remains readable without rewrite.
2. Dictionary insertion order could change stored SHA. New writes use canonical
   sorted object keys and actual UTF-8 encoding. Receipt list order and duplicates
   are preserved exactly; reversing a list changes its semantic digest as it should.
   Semantic summary digest and physical storage SHA are distinct for encoded forms.
3. Same ProgramID/Tag with a changed loaded_at falsely passed resource comparison.
   A new fixture reproduced58PASS/1FAIL before correction. The fixed comparison
   includes loaded_at alongside ID/type/tag/map IDs. Attach-target changes also
   remain explicit failures. No foreign program is adopted,detached or deleted.
   Identical or absent identity metadata still cannot prove an external creator;
   historical ownership remains UNKNOWN.

No privilege,capability,ABI,Network14 arithmetic,model or approval gate was relaxed.
No new background service,Queue,framework or dependency was introduced.

## Checkpoint worst-case results

- Actual failed final Summary:17209 default-JSON bytes,12 receipts. Final canonical
  JSON is16295 UTF-8 bytes and restores every field/ID/digest/provenance unchanged.
  Its semantic/storage SHA is
  `248357f1820b893133d62a59ea4d1b3e5135560dd9394fcc0199468dd10980b8`.
- Historical9651B factored result remains a result of the prior codec,not falsely
  reused as the new byte count. An explicitly synthetic200-byte extra context
  on the actual12-receipt Summary triggers shared-context encoding:9874B,all12
  receipts/digests restored exactly. No synthetic field is inserted into Native evidence.
- Empty0:28B,single1:225B,1024 identical duplicate rows:3340B. Duplicate storage
  preservation is not duplicate Feature eligibility.1024 unique receipts and
  a32-receipt low-repetition/long-provenance case are explicitly rejected unchanged.
- Exact16384 UTF-8 bytes succeeds;one byte over fails,for both ASCII and Unicode.
  Long strings have the existing byte budget,not an invented independent limit.
- Repeated input and permuted object-key construction yield identical stored text
  and SHA;candidate order changes remain observable. Nonfinite/non-object/malformed
  input,unknown encoding,shared-field overlap,excess count and expansion are rejected.
- Codec keeps16KiB stored bound,existing1024-flow/8MiB expansion bounds,writer Queue2,
  FULL SQLite commit and original decoded-summary Audit/Plan binding unchanged.

Private proofs:actual-summary-offline-proof.json,capacity-limits.json,
confirmed-defects.json under `.git/native-soc-phase-d/final-preflight-063/`.

## Audit Drain / Cleanup failure injection

Checkpoint encoding,writer,SQLite FULL commit and Recovery preserve24 complete
synthetic candidate receipts and original semantic digest. Tampering shared fields
fails Recovery binding. Injecting EIO during the Audit append after checkpoint
DELETE/INSERT rolls back the whole transaction:previous Checkpoint row/digest and
Audit chain stay identical,writer commit count0,flush/close report failure,and
Recovery exposes the old state rather than claiming final persistence.

Existing slow-Audit tests hold the writer while packet processing proceeds,
retain ordered bounded pending snapshots,and verify durable Drain only after
release. Queue-full,Audit error,Counter/CLOSED after packet processing failure,
CLOSED with pending work,FD closure,first-error and subsequent-cleanup-error
separation all pass. Startup tests now explicitly inject Checkpoint size/flush
errors while both Collector stop paths run;injected close errno5 remains a
separate FINAL_NATIVE_CLOSE error. Ordinary owned children exercise SIGTERM and
second-signal cleanup protection. STATUS/STOP race and CLI success/error exit
semantics remain covered. These are fixtures,not a new Native Cleanup verdict.

## Packet Admission / Clock regression

Queue32,one bounded50ms admission wait,three measured successful Native waits from
the prior run,Counter/CLOSED drain,10ms reorder bound and fail-closed overflow
semantics remain. The current task makes no new Native performance measurement.
Prior4096/4096 delivery,zero Queue reject/timeout/policy discard and141ns maximum
inversion remain historical observed results; they do not become another execution.
Historical194ms root cause and calibration remain UNKNOWN.

## Candidate-specific Network14 evidence

All12 old candidates keep INCOMPLETE. The private candidate-rca.json records each
original receipt plus explicit source/counter/clock/flow/missing-evidence fields.
The complete candidate list is below; no old eligibility is retroactively upgraded.

| Candidate | Packets | Available feature evidence | Decision |
|---|---:|---|---|
| `7c951a04f2cd4c761aa410fc355a4a68ea7005e3ccf93627e4432b2fd46a6bb5` | 1033 | CHECKPOINT_RECEIPT | INCOMPLETE |
| `d5421fec5a23af77570299f6a86e572ead0a40745fe31f04898b891443943705` | 1029 | CHECKPOINT_RECEIPT | INCOMPLETE |
| `7d1eb2f1255ef247bc96f980c9358e33810ef0c1e669d972fb6d11201f2853ed` | 996 | CHECKPOINT_RECEIPT | INCOMPLETE |
| `d633312ed808b7b2d5c23b62cb358502fc3c7b6d24727ada420853b9bd54b29b` | 1002 | CHECKPOINT_RECEIPT | INCOMPLETE |
| `b183504924cc736590665882bdb3edc2cd19612ede096bac05178c4274b187ac` | 2 | CHECKPOINT_RECEIPT | INCOMPLETE |
| `650a4ccad028ad8c06396e2ff52d43760e4c2d1cc274c66200181d1674b4bb52` | 10 | CHECKPOINT_RECEIPT | INCOMPLETE |
| `966946bb7611eb29c8f0bc67cfa679c5e9765b9c6125b1500863a77f4504d7dd` | 4 | CHECKPOINT_RECEIPT | INCOMPLETE |
| `871e337ecbc1d6468464c9bc2017066dfef0c132ac08683588bb1a40c18ce65f` | 4 | CHECKPOINT_RECEIPT | INCOMPLETE |
| `4d88306e3c8563fa2e8edf161624312e8bafb7c3340bdfe767a16d1e4b1cebdc` | 4 | VALUES | INCOMPLETE |
| `37ade919f0a403534fafc79848a51790a1d655e7c48ed26cfb3d35b8d0d85b08` | 4 | VALUES | INCOMPLETE |
| `b11e40c6cf920a396f75bc865605cc9a10b6f67e81817284c70c2e0ae4b74bd1` | 4 | VALUES | INCOMPLETE |
| `914324f6c5ffc25a8948ef376d908897a7cbe525aa85c1dd6b7cd377f896e844` | 4 | VALUES | INCOMPLETE |

Each candidate shares these capture-session limitations:
- Window terminated at PACKET_LIMIT,not a complete idle/active/normal Flow boundary.
- Owned counters emitted4124/delivered4096:28 unreconciled records at the cap;
  zero ring reservation failures is not proof of global zero packet loss.
- CPU attempt gaps0 observed,not complete Capture proof. Four inversions <=141ns
  reorder within10ms,late0;Clock calibration remains unverified.
- Feature14-float32/digest checks were recorded;four retained vectors were rehashed
  offline. Eight candidates have receipts only,no missing raw vectors fabricated.
- Source Session/generation,Program1000/Link2,event chain and release provenance
  remain preserved. Final durable Checkpoint receipt was absent due to the original
  size failure. Golden/model evidence and Native AI authorization remain absent.
The receipt-storage defect is fixed offline;flow/capture evidence gaps are genuine
observational limits and are not repaired by serialization or defaults.

## cgroup readiness

Fixed authenticated Inspector snapshots include programs/maps/links/lo hooks and
`bpftool -j cgroup tree /sys/fs/cgroup`. Tests verify same Inspector before/after,
Peer Credentials/Session binding,read-only allowlist,failed query !=absence,revocation,
changed Tag,loaded_at,AttachTarget and added foreign Program. Changes make Cleanup
UNVERIFIED without deletion. Native TCX owner identity remains separate from foreign
Program identity. Last actual before/after11 Programs/6 cgroup paths were unchanged;
no new privileged query or historical ownership claim is made here.

## Verification

- Workspace focused Checkpoint/Collector/Clock/eligibility/Supervisor/Inspector/
  approval-budget/uint64:142PASS in7.40s.
- Ordinary-UID C Data Plane +Supervisor termination/Checkpoint failures:24PASS
  in183.25s. No Root or capture involved. No SourceGuard rejection in this frozen run.
- Source mutation detection +CLI exit-code tests:14PASS in0.53s.
- Independent frozen Export core suite:142PASS in7.74s.
- Initial added determinism fixture was itself too large to be representable;
  it was corrected to repeated-context rows while retaining the same order/SHA
  assertions. The separate non-factorable-size rejection tests remain mandatory.
- Whole Export historical5909PASS/2FAIL/30SKIP remains unresolved,not reclassified.
  Operator Timeout/legacy READY100ms failures remain excluded only from the
  explicitly reviewed direct headless diagnostic path,not production qualification.
- Ruff/format/diff pass. Final source inventory is unchanged across verification,
  independent export and two new builds.26/26 artifact names and hashes agree.

## Final Artifact identity

Same version0.6.3,new final-preflight diagnostic candidate. Old approval requests
are superseded for execution but retained unchanged as history.

| Identity | SHA-256 |
|---|---|
| Source Snapshot | `b27f0e46e1fd157c13f1334f47245ddd25ce2c7cc63887372a64c487a89ba6af` |
| Manifest | `20c717e66b73d74ea414b8a6f17ce94227eb3261c3b320348acf8fcb46a8f5ba` |
| Bundle | `c98f2429f90674a34e37f5190e52630da58144898cf288faff5ce145b7792723` |
| Execution Image | `df6723099b498fc6c1fd29b117d9f13abab0dc738a47a06294eb153dc38679c4` |
| Root Manifest | `2eb95e82226d330e8ff80dcff57d143aae98f2d589d4ab361af21b5fa27c0471` |

Artifacts: `.git/native-soc-phase-d/final-preflight-063/release/`.
Workspace/Export/Stage are compared using the same1699-file normalized source
inventory;they are not mislabeled as Git Tree or executable SHA. This report is
excluded from its own Source Snapshot and covered by the final Commit/Tree.
Final Git/Stage binding and approval request are recorded after selective commit.

## Final Diagnostic E2E Approval Request

Requested Root operation:UPDATE_RETAIN_PREVIOUS of exactly9 fixed files in
`/usr/libexec/soc-agent-ebpf`,root:root,0555 executables/0444 data,one attempt.
Preserve currented580072... in its full-manifest rollback path and both older
rollback directories. Only the existing SHA-held image launcher is authorized:
`/usr/bin/sudo -k -u root -- /usr/bin/python3 -I -S -c <existing pinned loader>`.
No arbitrary shell,path,payload or extra Root command. User enters password on TTY;
START uses the existing independent authenticated control channel.

Requested Native:one existing Unified Supervisor diagnostic run;net4026531833,
lo/Ingress,max300s/4096 metadata/Queue32,privileged tasksAS256MiB/CPU20s;
Inspector read-only before/after;TCX load/attach/drain;Network14 receipts/eligibility;
DNS same namespace/lo,127.0.0.53:53,native-0516.localhost.,A,UDP1/TCP1,
active10s/capture7s/32records/snaplen512,existing ZeekRAM512MiB/CPU1 profile.
Observe Checkpoint/Audit Drain,Counter/CLOSED,Supervisor exit,FD/Link/Map/container
cleanup and cgroup identities. No foreign detach,offload/DNS/network policy change,
external traffic,scope expansion or automatic retry. Failures retain first and
subsequent errors and independent resource cleanup evidence.

Budget unchanged:Native4/5,Root4/5,one remaining each. No reservation or receipt
approval is created by this report. Exact new SHA approval plus the existing
Approval Receipt contract is mandatory before install/auth/attach/capture/traffic.

## Remaining limits

Arbitrary maximum unique receipts cannot be guaranteed within16KiB;oversize remains
fail-closed. The prior actual12 receipts round-trip offline only. Native final
Audit Drain,overall Cleanup,flow completeness/capture calibration and graphical
GUI verification remain unverified. Production whole-regression failures remain.
Native AI,DNS9 and production promotion remain **BLOCKED**.


# NATIVE_SOC_PHASE_D 0.6.3 Final Diagnostic E2E — attempt 5

## Overall Status

**PARTIALLY_VERIFIED** for the full campaign. The approved collection and
termination diagnostic completed **VERIFIED**: CLI/privileged entry exit0,
`first_failure=null`, `errors=[]`, `PROCESS_AND_AUDIT_VERIFIED`. This does not
qualify Network14 for AI, prove global lossless capture, or resolve historical
failures. This section adds a new result; earlier FAILED/UNKNOWN results remain.

## Release / SHA

Executed Git Commit `666f9cf0e423a72ffe808f810db5c5d6adae255f`,
Tree `c9ba143507a0931f2cd965a8fd7b9b61bd34d2cf`,
branch `fix/native-phase-d-checkpoint-preflight`, Release0.6.3.

| Artifact | SHA256 |
|---|---|
| Manifest | `20c717e66b73d74ea414b8a6f17ce94227eb3261c3b320348acf8fcb46a8f5ba` |
| Bundle | `c98f2429f90674a34e37f5190e52630da58144898cf288faff5ce145b7792723` |
| Execution Image | `df6723099b498fc6c1fd29b117d9f13abab0dc738a47a06294eb153dc38679c4` |
| Root Manifest | `2eb95e82226d330e8ff80dcff57d143aae98f2d589d4ab361af21b5fa27c0471` |
| Source inventory: Workspace/Export/Stage | `b27f0e46e1fd157c13f1334f47245ddd25ce2c7cc63887372a64c487a89ba6af` |
| TCX object | `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06` |

The source inventory covers1699 files, excluding this report. A subsequent
documentation commit is not the executed Commit/Tree or a newly approved binary.

## Approval Receipt / Root Installation

Explicit user approval is bound to `live-063-final/approval-user-063.json`, SHA256
`c3e9e25272b9652109045933676efa92f2219a12976ab4f3088ff00080f3194b`.
Attempt `75620bc36b0042ce8a1d9a77d217dce3`, application session
`77a6a62a-7e31-4aa8-a175-85fd6e4971cc`.
One fresh `sudo -k` authentication invocation on the user's real terminal used
the existing held-image loader. Password keystrokes/prompt retries were not
recorded and cannot be independently counted. No secret was collected by Codex.
No additional authentication or privileged post-run command was invoked.

Exactly9 Root Manifest files were verified after installation, root:root,
0555 executables/0444 data. The previous `ed580072...` installation survives in
its full-manifest rollback directory, together with older `162d2f94...` and
`56e1b7bc...` rollback sets; all9 files of each match their prior SHA/ownership/mode.

Scope remained net:[4026531833],lo/Ingress,300s/4096events/Queue32,
privileged AS256MiB/CPU20s. DNS used the existing same-namespace lo scope,
127.0.0.53:53,native-0516.localhost.,A,one UDP and one TCP query,
10s active deadline/7s capture/32packets/snaplen512,existing Zeek RAM512MiB/CPU1.
No policy/offload/resolver changes, external DNS, foreign detach or retry.

## TCX Capture / Packet Admission / Clock

Program1011,tag `5d24af0965a164b7`,Link3 attached successfully and were released.
4096 received /4096 applied /0 rejected /0 policy discarded /0 pending;
all discard-accounting categories balance. Queue admission waited4 times and
resumed4 times; timeout0,queue-full0. Immediate4092 is derived as4096−4.
Queue peak28 of32; max admission wait11.962421ms,total29.571643ms,
queue residence max13.044591ms,packet processing max11.790564ms.
The existing50ms admission bound and10ms clock bound were unchanged.

27 bounded inversions were reordered,max1391ns,late events0,CPU attempt gaps0.
CPU0/1/2/3 delivered1193/849/1066/988 events. Clock remains declared
KERNEL_MONOTONIC_NS with native calibration unverified. The historical194ms
inversion was not reproduced; its root cause remains UNKNOWN.

Final owned Map snapshot retrieval succeeded: observed4114,emitted4108,
disabled6,ring reservation failures0,unsupported/malformed/budget0,delivered4096.
The emitted-minus-delivered12 is consistent with the loader consuming events
without forwarding after its4096 packet cap, but no independent per-record
exclusion counter proves this attribution. It remains unreconciled metadata;
Kernel-wide drops remain UNKNOWN. No claim of global zero loss is made.

4100 frames arrived;final sequence4099. Socket failures0,EAGAIN0,EPIPE0,
POLLOUT waits0. The POLLOUT recovery branch was not exercised by this Native run.
Counter and CLOSED arrived;final ring drain result0 (8.175521ms),Map lookup0,
transmit0. Processing/receiver/Audit workers stopped with no pending work.

## Checkpoint / Audit / Recovery

Actual final Checkpoint: **14006 UTF-8 bytes <=16384**, canonical JSON,
8/8 candidate RCA receipts retained and the configured4-vector tail retained.
Semantic digest and serialized SHA:
`8ef5fc2410b6ad84aa0796946cc6aa413dca7fc86ad2050ef6c9a5e03e0468eb`.
Generation `15081108673287173545` (>2^63) survived Native IPC/SQLite/Recovery.

Audit writer23 submitted/23 committed/0 rejected/0 outstanding,no failure,
max commit71.039707ms. The SQLite Audit chain27 records includes25 Checkpoint
records (async23 plus initial/final synchronous checkpoints). Final Checkpoint
Audit digest and plan binding verified. Audit Drain VERIFIED.

Recovery ran without privilege on a separate owned SQLite copy only:
`RESTORED_NO_REATTACH`,all stored receipt/plan/event-chain/feature evidence equal,
original Native database hash unchanged. Native journal18 records verified;
last lifecycleTCX_CLEANUP_VERIFIED;authorization is not restored by recovery.

**Limit:** this8-candidate run fit canonical JSON. Shared-context compression was
not exercised in Native; its prior lossless/boundary tests remain offline proof.
Unique maximum-capacity receipts are not universally representable within16KiB;
oversize must continue to fail explicitly without truncation or raising the cap.

## Network14 Eligibility

8 new candidates,all **INCOMPLETE**,eligible0,all closed byPACKET_LIMIT.
Their packet counts sum4096. Schema and value digests validated at generation;
final receipts preserve all8 identities/digests/provenance,while raw vectors are
retained only for the4-vector tail. Earlier raw vectors cannot be revalidated
from their digests alone. Original receipt reason codes remain unchanged.

| Candidate flow identity prefix | Packets | Close | Final raw vector retained | State |
|---|---:|---|---|---|
| `7be4c9bb41c4200a` | 971 | PACKET_LIMIT | no; receipt only | INCOMPLETE |
| `4fabf63176053057` | 969 | PACKET_LIMIT | no; receipt only | INCOMPLETE |
| `0aad5f6e336b4e6d` | 1081 | PACKET_LIMIT | no; receipt only | INCOMPLETE |
| `0ef7783280958252` | 1055 | PACKET_LIMIT | no; receipt only | INCOMPLETE |
| `d45b8a6447a87ca9` | 2 | PACKET_LIMIT | yes | INCOMPLETE |
| `ae36ea303ea41982` | 10 | PACKET_LIMIT | yes | INCOMPLETE |
| `6d9f33cf7b9b254d` | 4 | PACKET_LIMIT | yes | INCOMPLETE |
| `397bc6a013c21dce` | 4 | PACKET_LIMIT | yes | INCOMPLETE |

Full identities,feature digests,original reason codes and separate review limits
are retained privately in `live-063-final/candidate-rca.json`.
Common barriers: capture integrity not proven,flow completion not proven,
clock calibration not proven,Native golden parity/model receipt unavailable,
Native AI policy blocked. Original RCA can retainRING_LOSS_UNKNOWN even though
a later final snapshot reports ring reservation failures0;do not retroactively
rewrite the earlier receipt. Final evidence still leaves emitted/delivered12
unreconciled. Previous historical candidates remain INCOMPLETE/UNKNOWN.

## DNS / Zeek READY / Deadline

Controlled local probe independently confirmsUDP1 query/1response andTCP1
query/1response,transaction IDs49665/49666,question match true,RCODE0.
Zeek/DNS Diagnostics accepted2 completed transactions (UDP1/TCP1),response
records2,duplicate completed records0,missing QTYPE/ID/TTL0.
Zeek completed-log records do not independently count individual query packets;
`query_packets` and `response_packets` remain null. Transaction-ID collision or
retransmission ambiguity remains UNKNOWN without individual packet identities.
Visibility: **DNS_VISIBLE_CONTROLLED_LOCAL_TEST**,not general/external DNS proof.

12 capture records accepted,0 rejected,0 socket drops;analysis-copy provenance
chain verified. CHECKSUM_PARTIAL analysis-copy corrections preserved the recorded
original/corrected digest contracts;raw payload was not retained for independent
post-run recomputation. Stream19 records:12Raw-IP UNSUPPORTED,2network,2DNS,
Counter and CLOSED;invalid/duplicate/sequence-gap0. Raw-IP records are excluded
from Network14. Capture integrity remains partial analysis-copy provenance,
not end-to-end payload attestation or DNS9 eligibility.

Monotonic timing (seconds,one clock domain):

| Stage | Start/marker | End/marker | Evidence |
|---|---:|---:|---|
| DNS authenticated-to-completion window | 75121.879376947 | completion | 9.391756595s;10s bound met |
| Zeek launch-to-READY | 75122.037493684 | 75124.707563111 | script-init75124.672392614 |
| Capture | 75124.708584527 | 75130.648155168 | 5.939570641s;7s bound met |
| Analysis input-closed-to-CLOSED | 75130.654090174 | 75130.748586575 | Counter75130.748330850 |
| Analysis cleanup complete | — | 75131.150537605 | deadline_expired=false |
| Final cleanup marker | — | 75131.259973607 | worker exited |

The terminal launcher elapsed36.625s includes human confirmation/authentication
and outer orchestration;it is not the DNS active window. These observations do
not establish a10s whole-application bound from an independently observed PAM
completion timestamp. DNS scope active deadline and300s Native limit were met.
Container exit0,CLOSED observed,container absence verified,no cleanup failures.

## Supervisor / Cleanup / cgroup Ownership

Supervisor CLOSED,first_error null,control_errors/failures empty,entry/CLI exit0,
no processing/I/O/cleanup error. Queue/Ring/Processing/Audit Drain VERIFIED.
OS authorization REVOKED;Inspector authority revoked,channel closed,exit0;
Supervisor/capture/Inspector PIDs863012/863013/863014 absent after exit.
The operator's terminal review window is not a Collector process.

Inspector retained onlyCAP_SYS_ADMIN in permitted/bounding sets (effective0 at
reported hello);Broker permitted/boundingCAP_BPF+CAP_NET_ADMIN,effective0 at
reported snapshot,inheritable/ambient0,noCAP_SYS_ADMIN. Snapshot values do not
constitute a syscall-by-syscall effective capability trace. GUI/AI were not
launched as privileged children;graphical GUI verification was NOT_RUN.

3Map FDs and1Program FD confirmed closed viaF_GETFD/EBADF after libbpf close,
result0;raw close() return values were not independently observed.
Authenticated before/after inventories are identical,including full raw identities:
Programs12->12,Maps0->0,Links0->0,lo ingress/egress filters0->0,cgroup rows7->7.
Owned Program1011/Link3 are absent at final inspection;current-session cleanup
is VERIFIED. Foreign system-service programs including948/1007 were already in
the before snapshot with matching tags/load timestamps/attach targets and were
preserved. Their original creator/session attribution and historical+2 Program
ownership remain UNKNOWN;this run does not retrospectively establish ownership.
Legacy Supervisor `zeek_container_removed=false` describes its unused legacy
collector branch;actual Sidecar `container_absent=true` is the relevant proof.

## Root Cause Analysis / Regression Tests

There is no first failure in this attempt:Stage/API/errno/signal are not
applicable,no new code defect confirmed,no implementation changed,no retry.
The prior EBPF_CHECKPOINT_SIZE failure did not recur,with the canonical-format
Native coverage limitation above. Queue waiting resumed without rejection;
no evidence supports changing Queue32,50ms or10ms limits.

Pre-run validation retained:Workspace core142PASS,DataPlane/Supervisor24PASS,
SourceGuard/CLI14PASS,independent Export core142PASS;dual builds26 artifacts
identical,Ruff/Format/Diff passed. No redundant full suite rerun after an
unchanged implementation. Historical whole Export5909PASS/2FAIL/30SKIP remains
unresolved;diagnostic approval does not qualify production.

## Evidence Integrity / Budget / Final Decisions

Private evidence root:`.git/native-soc-phase-d/live-063-final/`.
`preflight.json`,`native-evidence-sha256.json`,`evidence-review.json`,
`candidate-rca.json`,`checkpoint-recovery-proof.json`,
`journal-verified-review.json`,`post-run-preservation.json` and the appended
`ledger-review-event.json` connect receipt/result/recovery/preservation hashes.
The49 Native files in this run and49 files in each prior0.6.3 attempt match
frozen indexes. All112 protected baseline/user files match;all1699 release
source files unchanged before documentation;prior Ledger prefix preserved.
Ledger sequence14 appends evidence review to the unchanged pending-result event;
no historical event was rewritten. Final Ledger has15 valid chained records.

Root **5/5**,Native **5/5**,remaining **0/0**. One install and one Native attempt
were reserved,executed and reviewed;no automatic retry/new privileged inspection.
Budget baseline and historical campaigns were not reset.

| Area | Final decision |
|---|---|
| Unified Supervisor | VERIFIED within this diagnostic scope |
| TCX delivery / Packet Admission | VERIFIED for4096 received/applied;global capture integrity incomplete |
| Network14 AI input eligibility | INCOMPLETE,0/8 eligible |
| DNS Sidecar | VERIFIED controlled local transactions/Counter/CLOSED/deadline |
| Checkpoint | VERIFIED actual canonical checkpoint/storage/copy recovery |
| Audit Drain | VERIFIED |
| Current-session Kernel/container/FD cleanup | VERIFIED |
| cgroup ownership | Current before/after unchanged;historical ownership UNKNOWN |
| Native AI / DNS9 / production promotion | BLOCKED |

Remaining work:reconcile metadata beyond the packet cap,obtain capture/calibration
and genuine flow-completion evidence,retain necessary vector/model parity receipts,
resolve whole-Export failures and perform separately scoped GUI verification.
Any further privileged/Native execution needs a new budget and explicit exact-SHA
approval;this report requests no automatic new session.


# SOC Native Stabilization — Batch 1

## Overall Status

**INSTRUMENTED / NATIVE_VERIFICATION_REQUIRED**. No Root installation, BPF query,
attach/detach, capture, Docker capture session, or DNS traffic was executed.
No historical candidate, Ledger, Audit or Native failure was reclassified.
This batch establishes explicit accounting and lifecycle receipts;it does not
establish Native Capture Integrity or grant AI eligibility.

The original workspace remains main9a12fe9 with its prior user/development edits.
Implementation used the existing clean release worktree
`../native-soc-phase-d-release-063`,starting6d059d8,branch
`fix/native-stabilization-batch1`. No user edits were copied into this branch.
Historical approved binary666f9cf and its installed files remain unchanged.

## P01 Counter Reconciliation

**Root Cause:** CONFIRMED source-level population mismatch and missing exclusion
instrumentation. Kernel `observed` increments per hook/per CPU before enabled,
parser and reserve checks. `cpu_sequence` uses that attempt number. `emitted`
increments after successful Ring submit. Thus disabled/unsupported/malformed,
reserve failures and per-CPU budget exclusions are distinct attempt outcomes.
The Kernel4096 attempt budget is per CPU;the Loader4096 delivery cap is aggregate.
The old Loader silently consumed callbacks after this aggregate cap. Its variable
named`emitted` counted admitted send attempts before validation/send,not Kernel
submissions or confirmed sends. These populations cannot be equated.

Historical final totals:observed4114=emitted4108+disabled6;delivered/applied4096.
This is consistent with12 callbacks excluded at the aggregate cap. **The historical
12 events are not individually attributable**:there was no exclusion counter or
retained per-callback trace. No packet loss or exact12-event attribution is invented.

**Fix:** per-runtime/generation callback,successful delivery,budget-excluded,
invalid-scope/size and send-failed counters. Delivery is incremented only on
successful atomic192-byte send,not inherited from a previous session's cumulative
send counter. Source identity is checked even after the cap. A new terminal
ACCOUNTING kind6 has a fixed80-byte payload;the original80-byte packet ABI and
192-byte envelope are unchanged. Existing peer/session/program/approval/sequence
checks apply. Duplicate/cross-generation/invalid equations are rejected.

The same80-byte accounting is committed to the chained Journal **before** its
channel send,so a blocked/closed Data Channel does not erase the local claim.
Drain error and Map lookup/query diagnostics remain independent. Old streams
without ACCOUNTING remain readable withUNKNOWN reconciliation;old consumers
reject new kind6,so Producer/Consumer must be deployed with the same new SHA.
Journal decoding alone does not restore Native authority or prove process exit.

**Verification:** actual compiled Loader callback executed without libbpf/Kernel
calls,including cap exclusion,send EAGAIN,invalid epoch after cap and cumulative
session counter isolation. Python tests cover malformed/duplicate/epoch mismatch,
missing fields,Ring loss,receive mismatch andDrain-11. Equations:

```text
observed = emitted + ring_reservation_failures + unsupported + malformed + disabled + budget
emitted = callbacks                         (only after a successful final drain)
callbacks = delivered + budget_excluded + invalid + send_failed
delivered = authenticated receiver received (same generation)
```

Accounting balance is separate from quality:classified exclusions/failures never
become zero-loss capture. A failed send cannot be labeled budget exclusion merely
because the arithmetic balances. Counter values are never adjusted to force equality.

**Remaining Gap:** historical12 attributionUNKNOWN;new Native accounting has not
run. P01 isINSTRUMENTED,with the exclusion mechanism reproduced and fixed.

## P02 Capture Integrity

**Evidence/Fix:** terminal Counter/ACCOUNTING/processing projections are joined by
generation and scope. Source receipt includes application session,Plan digest,
program SHA,approval digest,namespace/interface/hook. Actual received CPU intervals
retain first/last attempt and Kernel event timestamp plus received count;these are
received-event intervals,not proof about silent CPUs or disabled observation.
Map snapshot,Socket loss,Queue rejection,CPU gaps,late events and final drain are
separate reasons. Missing evidence staysUNKNOWN. Kernel-wide drops remainnull.

`start_config_ns` is the configured start bound,not a measured first packet or an
atomic enable barrier. `final_drain_started_ns` is an after-detach userspace marker,
not a fabricated last-packet timestamp. The Map generation is scope-bound by the
owned map/runtime;its scalar counters do not themselves embed a generation field.

**Verification:** missing Counter/Epoch,unsuccessful drain,CLOSED absent,processing
failure,Ring loss andSource Provenance fixtures fail to establish integrity.
Even fully reconciled fixture accounting leaves capture statusINCOMPLETE.
**Remaining Gap:** no atomic whole-window attestation/initial per-CPU snapshot,
no independently verified Native clock calibration,and no Kernel-wide drop proof.
This code intentionally cannot promote Capture Integrity solely from final totals.
P02 remainsINSTRUMENTED,notVERIFIED.

## P03 Flow Completeness

**Lifecycle/Fix:** preserve per-flow first/last observed Kernel event timestamps,
bidirectional observation,FIN direction(s),RST observation and the actual later
event watermark witnessing an idle/active timeout. These fields follow the same
Flow identity,Feature digest and Checkpoint receipt. Timeout closure does not extend
feature duration to the witness;duration remains last-minus-first observed packet.
No end timestamp is synthesized from Wall Clock,STOP or an idle processing thread.

TCP FIN/RST remain observed evidence,not new completion authority. The current
metadata ABI lacks TCP sequence/ACK/handshake proof,so even two FIN directions do
not prove whole-session capture. UDP idle timeout remains30s;active timeout120s.
STOP,packet limit,overflow,clock failure,normal source exhaustion and leftover
flow drain preserve their existing incomplete/blocked semantics. Duplicate finish
is rejected. Counter/clock uncertainty cannot upgrade a timed-out flow for Native AI.

**Verification:** one/both FIN directions,RST,one-way flows,UDP idle timeout,
TCP active timeout,real timeout witness,last-event bounds,STOP drain,no duplicate
export,receipt/Checkpoint round-trip and independent14-feature math.
**Remaining Gap:** past8 candidates remainPACKET_LIMIT/INCOMPLETE;new lifecycle
metadata has no Native proof yet. P03 remainsINSTRUMENTED.

## Regression Tests

Final unchanged-source results:Workspace targeted273PASS (136.48s),independent
Export core224PASS (23.05s),ordinary-UID C/socket/data-plane/Drain integration15PASS
(228.75s). New Batch1 tests27PASS are included in those suites,not additional
Native attempts. Ruff passes for all10 changed Python files,Format check passes,
Git Diff check passes. No test/assertion was removed or weakened. The full
Workspace/Export suite was not rerun;historical2 failures remain unresolved.
All tests are ordinary UID fixtures;C callback/Unix socket/SQLite integration
is not a Kernel Native run.

The first invocation without importlib mode hit duplicate test basenames during
collection;the official isolated invocation uses`--import-mode=importlib`.
Source-pinning assertions initially rejected changed Producer/Collector hashes.
A new `native-stabilization-batch1-source-amendment.json` links the unchanged
historical amendment and current exact hashes;the assertions still validate both.
An overlapping earlier compile correctly rejected our then-in-progress edit via
SourceGuard. Its result was superseded by a complete unchanged-source rerun.
No historical certificate was rewritten or assertion removed.

Export initially lacked the independent ML reference source path (220PASS/1FAIL).
Re-run explicitly sets`SOC_RESEARCH_VALIDATION_REPOSITORY` to the existing trusted
repository parent;ML producer source hashes are recorded separately. No model,
Root or external network call is used. This is dependency setup,not a skipped test.

Synthetic capacity proof:4096 in-memory events/8 flows,8 receipts and4-vector tail,
15096 UTF-8 bytes,encode/decode equal,allINCOMPLETE. This is not Native evidence.
A separate dense1us fixture correctly hit the unchanged32-record/10ms reorder
fail-closed boundary;it was not bypassed. The successful capacity fixture uses
1ms event spacing. No universal worst-case capacity guarantee is claimed.
16KiB and maximum receipt guards remain;unique oversized input still fails.

## Source / Artifact Integrity

Frozen build input contains1703 files (source/tests/contracts/dependencies plus
existing documentation,excluding the Phase D report). The new problem tracker
and the appended report are post-build reporting only,covered by Git Tree rather
than falsely counted as compiled input. Workspace/frozen Export/Stage must match
this exact input set. A SourceGuard observes runtime inputs during each build.
All26 artifact files from independent buildsA/B match. No old/superseded build is
the final release. Qualification:`.git/native-stabilization-batch1/release-v2/`.

Release version remains0.6.3,**distinct Batch1 candidate with new SHA**,not the
historically approved0.6.3 image. Native/Root approval does not carry over.

| Identity | SHA256 |
|---|---|
| Frozen input inventory | `1a6911b824269a315010480d214a099f476360c63adb95981cb1464ab5f110b0` |
| Manifest | `76ed726c48808212ae629601239335ca37b1e24e09022cae081fb0068d964fc0` |
| Bundle | `7d770e1d383302c7e37883eb73428e5145edaa5570b64f453b0d43e8b9016fbb` |
| Execution Image | `108e5a26238ee5a0c90a3a522a805ee01cf54062a7cf87150ef36f141f067df0` |
| Root Manifest | `a1214d2c58bd21ca7a156e4f5c136dbbb63d796b649d26e2400cce89ebe00297` |

## Native Verification Required

Request scope for a future exact-SHA approval:one fixed9-file Root installation
preserving current2eb95e82... rollback,and one Unified Supervisor diagnostic run,
net:[4026531833],lo/Ingress,max300s/4096events/Queue32,privilegedAS256MiB/CPU20s.
DNS retains existing127.0.0.53:53,native-0516.localhost.,A,UDP1/TCP1,
active10s/capture7s/32packets/snaplen512,ZeekRAM512MiB/CPU1.
Root files:bootstrap,broker,entry,libnative-tc.so,manifest.bin,pam-policy.conf,
tc.bpf.o,release.json,release.trust. Verify actual Root Manifest commands,installed
SHA/ownership/rollback and privileged Inspector snapshots before any attach.
No foreign detach,no offload/resolver change,no external traffic,no automatic retry.

Expected evidence:new callbacks/exclusions/failures vs Kernel totals and receiver,
actual epoch/CPU intervals,flow lifecycle receipts,Checkpoint size/recovery,
DNS/CLOSED,Audit/FD/container/Kernel cleanup. This instrumented run is not expected
to establish missing atomic capture/clock/model proof or automatically enable AI.

User authorized new Native development budget10 total,max2 perBatch;Batch1 used0/2,
total0/10. Historical Phase D remains5/5Native and5/5Root. Root budget extension is
pending clarification;new exact-SHA approval and receipt are absent. The existing
Phase D executor remains bound to its exhausted5-run campaign. New10-run campaign
execution registration/enforcement is not implemented or bypassed in this data-path
batch;it must be explicitly connected and verified before execution. The new budget
record is not an executable receipt. No reservation or Native/Root use occurred.

## Git Commit / Push

Implementation and report changes only on`fix/native-stabilization-batch1`.
No original user files,Native raw evidence,model artifacts or Ledger/Audit files
are staged. Final commit/Tree and the private approval request are bound after
selective staging. No direct main push or force push.

## Next Batch Readiness

Data-path instrumentation is ready for review and exact-SHA diagnostic approval;
Native execution remainsBLOCKED by approval/Root-budget/new-campaign registration.
P01 historical12 remainsUNKNOWN;P02/P03 remainINSTRUMENTED. No historical candidate
isELIGIBLE. Native AI,DNS9 and production remainBLOCKED. Prior whole-Export
5909PASS/2FAIL/30SKIP is not requalified by these targeted tests.


## Batch 1 actual Native result — registered campaign, attempt 1

See [Batch 1 Final Report](native-stabilization-batch1-final-report.md).
Following explicit user execution/all-budget approval,the separate registered
SOC_NATIVE_STABILIZATION contract is now Native10/Root10,max2 each perBatch.
Authoritative Ledger is `.git/native-stabilization-batch1/execution-v1/`;
old Phase D5/5+5/5 and development-only records remain unchanged.

Current approved Artifact537a278/four SHAs unchanged;ordinary-UID bookkeeping
adapter8ba3b18 delegates to the same Supervisor/Root image. One actual run:
CLI0,no first error,4096received/applied,Queue reject/timeout0.
Kernel observed4140=emitted4138+unsupported1+disabled1;
callbacks4138=delivered4096+explicit after-cap exclusions42.
P01VERIFIED for this epoch,not retrospective proof about historical12.
P02INCOMPLETE:CPU attempt gaps2,missing atomic window/calibration evidence.
P03PARTIALLY_VERIFIED:one bidirectional FIN receipt;all7 candidatesINCOMPLETE.
DNSUDP1/TCP1 transactions,9.508s active,CLOSED/container cleanup verified.
Native shared-RCA checkpoint13213B,7receipts,copy recovery/Audit Drain verified.
Owned FD/Program/Link cleanup verified;Map/Link/lo filters0,cgroup inventory
unchanged11Programs/6targets. No foreign detach,policy change or second run.
New Native1/10,Root1/10;Batch1 Native1/2,Root1/2. OverallPARTIALLY_VERIFIED.
Native AI,DNS9,productionBLOCKED;prior full-Export failures remain unresolved.

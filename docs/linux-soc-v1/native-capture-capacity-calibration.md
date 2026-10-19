# Native capture capacity calibration — interrupted-work recovery

Status: **FIXTURE_CALIBRATED — Workspace 3/3 and Independent Export 3/3 PASS;
NATIVE_CALIBRATION_PENDING / SEPARATE_APPROVAL_REQUIRED.** Date: 2026-10-19.
SOC baseline `84406a6bd9cb7c400ed0ab1c8f0d385026cb51f9`; ML baseline
`e1a01260f0463a38d4d778859bc2a86f8e9cfbde`.

## Final completion — latest result

Run `capacity-final-completion-20261019-01` completed only the two previously
unexecuted Export cases, **serially, once each**. Existing Workspace 3/3,
Export Conservative, and the **277 passed / 3 deselected** related regression
were reused. Initial verification matched all 22 Workspace/Export file hashes;
the 19 runtime/policy/profiling source/manifest files did not change. Only this
report, its evidence JSON, and the evidence-integrity test were updated.

| Remaining Export case | Pytest | Command wall s | CPU s including workers | Peak sampled process-tree RSS MiB | Queue peak / final | Drain s / limit | Finalization |
|---|---|---:|---:|---:|---:|---:|---|
| Balanced v2 | 1 passed in 13.00s | 15.140 | 14.685 | 397.82 | 2 / 0 | 11.328 / 30 | VERIFIED |
| Performance v2 | 1 passed in 11.33s | 13.384 | 13.779 | 397.36 | 2 / 0 | 9.627 / 30 | VERIFIED |

Both exits were zero. Each case generated **four actual RF/LR receipts and four
READ-only investigations**, verified audit/recovery, no duplicate replay, 14
Producer features, zero capture gaps, and zero capacity exclusions. Input is
**FIXTURE**, never a Native capture success. Across all six Workspace/Export
cases, feature values, model identities, scores, and predictions agree; session,
receipt, and feature identity digests remain distinct as expected.

Model Artifact SHA256 remained:

* Quality RF: `53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603`
* Edge LR pipeline: `661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882`

Network14 Producer remains v1.1.0, contract
`84ba0916f0ce4e9e12bb70712db2cd1eaea84ba4173acd57b647faf38efb1c6e`,
with unchanged feature meaning, order, float32, eligibility, and event time.

Preflight used repeated samples: available memory stayed above **2 GiB**, CPU
affinity was 12, Memory PSI avg10=0.00, and avg60 declined from 0.06 toward 0.00.
An unrelated ~112 MiB pytest process was observed and left untouched. During the
two model cases minimum available memory was **2.029 / 2.104 GiB**; maximum PSI
avg10 was **0.00** for both. Swap remained approximately **1.35–1.40 GiB / 2 GiB**,
without sustained pressure or a large surge. No process was terminated to obtain
headroom. The earlier 0.12 PSI observation remains historical evidence below.

Drain duration was measured with a test-only monotonic observer that delegated
to the unchanged finalizer. The **30-second deadline was not increased**. No
Timeout, SIGILL, or OOM occurred in these two cases. The preceding timeout was
not reproduced across six serial cases; its original root cause and recurrence
risk remain UNKNOWN. No automatic retry, new helper execution, privilege command,
actual packet capture, or test traffic was performed.

Final evidence checks cover historical failures, successful completions, policy,
artifact/receipt/source integrity, queue/drain results, and research-only gates.
Workspace evidence checks: **7 passed in 0.37s**; Export evidence checks:
**7 passed in 0.39s**. Ruff, whole-workspace format (**1,046 files**), and diff
checks PASS. The final 22 files match the Export by SHA256. Original SOC 122 /
ML 10 user-file hashes, protected Native/model hashes, and Raw metadata remain
unchanged. No full regression was repeated after these metadata-only changes.
Final delivery is
restricted to the 22 owned files, with Stage/Export SHA comparison and normal
Fast-forward-only Git push. The delivery commit is the commit containing this
report; the validation baseline HEAD above is intentionally retained rather than
attempting to embed a self-referential commit hash. Model binaries, operating DBs,
Raw data, original user work, and Reliability Replay are excluded.

## Earlier validation resume — historical result

Run `capacity-final-validation-20261019-01` first matched all **22** owned files
against the previous independent Export. Both HEADs, empty indexes, 132 original
user-file hashes, and protected Native/model hashes matched. No Runtime code,
helper, manifest, policy, deadline, or resource limit changed in this resume.

The three Workspace RF/LR integration cases passed **once each**, serially.
Each produced four actual model receipts and four READ-only investigations,
with zero capture gaps/capacity exclusions, queue peak two/end zero, and VERIFIED
finalization. Separate pytest results: Conservative **1 passed in 13.12s**,
Balanced **1 passed in 10.86s**, Performance **1 passed in 10.97s**. Export
Conservative also passed: **1 passed in 11.98s**. Input was the same **263 synthetic
metadata packets / 526 simulated raw frames** per case, explicitly FIXTURE.
These are not Native throughput or capture results.

| Scope / policy | Exit | Command wall s | CPU s including workers | Peak sampled process-tree RSS MiB | Queue peak / end | Drain |
|---|---:|---:|---:|---:|---:|---|
| Workspace / Conservative | 0 | 16.399 | 14.022 | 397.70 | 2 / 0 | VERIFIED |
| Workspace / Balanced | 0 | 12.624 | 13.176 | 398.10 | 2 / 0 | VERIFIED |
| Workspace / Performance | 0 | 12.872 | 12.979 | 397.74 | 2 / 0 | VERIFIED |
| Export / Conservative | 0 | 14.136 | 14.085 | 399.27 | 2 / 0 | VERIFIED |
| Export / Balanced | Not started | N/A | N/A | N/A | N/A | RESOURCE_BLOCKED |
| Export / Performance | Not started | N/A | N/A | N/A | N/A | RESOURCE_BLOCKED |

Command wall time includes interpreter/import startup; process-tree RSS includes
the isolated worker. Preflight before every actual case satisfied **2 GiB
MemAvailable**, 12 affine CPUs, and PSI avg10=0.00. Conservative's running-process
minimum MemAvailable briefly reached **1.98 GiB** after starting; the next case
started only after fresh samples again exceeded 2 GiB. No new heavy test was
started below the threshold. Workspace cases recorded PSI avg10=0.00.

After Export Conservative, Memory PSI **some and full avg10 increased from 0.00
to 0.12**, with MemAvailable 2,569,916,416 bytes (about **2.39 GiB**) and swap
usage about **1.40 GiB / 2 GiB**. This observation is not an OOM or model failure
diagnosis. The user required stopping on renewed pressure; the remaining two
heavy Export cases were **not started**, retried, or marked passed. No unrelated
process was terminated.

The 30-second drain deadline stayed unchanged. Timeout was **not reproduced in
these four serial cases**; the old failure's root cause/recurrence risk remain
UNKNOWN. No automatic retry was used. Separate related Workspace contract, GUI,
DNS diagnostics, audit, and recovery regression: **277 passed, 3 deselected in
53.16s**. Actual-model cases were excluded from this separate regression because
they had already run individually. Counts overlap earlier runs; do not add them
into a unique total.

The fresh Export contains HEAD plus the 22 owned files, no original user/Replay
overlay or model binaries. Its first actual-model case passed; **full final
Export validation remains PARTIAL**. Reports/evidence integrity: Workspace **6 passed in 0.37s**, Export **6 passed
in 0.35s**; Ruff, whole-workspace format (1,046 files), and diff checks PASS.
Final preservation check: zero original-user/protected hash changes, unchanged
Raw metadata, and empty indexes in both repositories. All 22 final files match
the Export by SHA256. No stage, commit, fetch/push, privileged command, or Native
capture was performed in this resume.

## Initial interrupted-work recovery — historical result

The original recovery observations below retain their original scope and do not
supersede the latest result above. Numerical Fixture calibration,
an implemented approval boundary, successful historical inference, and successful
final integration are different claims. At initial recovery, expanded-policy
model integration had **not** passed: the preceding attempt had **23 passed, 3 failed** with
`STREAM_GRACEFUL_DEADLINE_UNKNOWN_NO_RETRY`. The 30-second drain deadline remains
unchanged. Resource pressure was observed; its causal relationship to those
timeouts, an OOM, or a native-library failure is not established by the logs.

Machine-readable measurements, policy limits, source hashes, and result scopes:
[calibration recovery evidence](native-capture-capacity-calibration-evidence.json).
Private raw logs and preservation snapshots remain in
`.git/capacity-calibration-audit/`; they are not publication artifacts.

## Baseline and preservation

Both HEADs still match their expected baselines. Both indexes were empty at
recovery start. SHA comparison preserved all **122 SOC / 10 ML** original user
files, including Reliability Replay. Protected Native evidence and model hashes
matched the pre-interruption snapshot. All **58** Raw files retained size, mtime,
and inode; their earlier completed SHA inventory is preserved. Recovery did not
rehash the entire multi-gigabyte corpus unnecessarily.

Only calibration-owned files are candidates for a later commit. No original
user/Replay changes are included in the independent export. Historical session
databases are not replay destinations. No model, dataset, checkpoint, or Native
session was replaced. No privileged command, capture, test traffic, or security
WRITE was executed.

## Initial recovery resource diagnosis (historical)

Read-only observations: 8,192,147,456 bytes total guest RAM, 12 logical CPUs and
12 CPUs in the process affinity mask. At recovery start available RAM was
about **1.24 GiB** in the first shell observation; the preservation snapshot
recorded 1,406,087,168 bytes (about **1.31 GiB**). Its 2 GiB swap device was full.
Memory PSI initially showed little current pressure, while subsequent IO PSI
showed significant stalls. A low instantaneous PSI value does not supply memory
headroom. Process RSS, swap, PSI, and affinity snapshots are retained privately.
Docker/containerd and other Python processes were observed and left untouched;
unclassified Python processes are not assumed to be this project's workers.
Cgroup resource ceilings are **UNKNOWN**. The preservation snapshot recorded four
unclassified long-running Python processes with RSS 185,696 / 182,472 / 151,976 /
143,860 KiB; Docker/containerd RSS was 27,244 / 21,556 KiB. These are observations
of shared resource use, not a diagnosis attributing the failure to those processes.

The new policy requires at least **2 GiB MemAvailable and two affine CPUs** both
before preparing a Native session and before entering the helper's privileged
capture engine. The initial recovery observations failed that gate with
`CALIBRATED_RESOURCE_HEADROOM_REQUIRED`. This is a conservative prerequisite, not
a guarantee against future pressure. Low-cost behavior tests explicitly mock
resources; they do not certify Native resource readiness. Actual model rechecks
were deferred then. No WSL setting was changed or unrelated process terminated.

## Native baseline and rate mathematics

The retained failure directory ends in `44bccafed5934b2e97e3d10a0dffd8cb`; its
capture UUID is `347c6117-3692-4f22-a83d-d834b8417f9e`. These are distinct identities.
Rejected CLOSED records 384 raw frames / 192 sent IP packets / 384 kernel packets,
zero drops, counter sequence 385, and 1.0236316919908859 seconds. All 192 transport
packets were delivered. Verified CLOSED is missing; source/model/investigation
completion must not be inferred from delivery or zero kernel drops.

Legacy token bucket: initial 256 tokens; refill `128 * monotonic_delta`, capped
at 256; one token per raw frame **before** loopback direction filtering. The
attempt counter increments before consumption, so it includes the rejected
attempt. The elapsed-time upper envelope is
`256 + 128 * 1.0236316919908859 = 387.0248565748334` tokens. Bucket initialization
also precedes the capture elapsed-clock origin. This loose envelope neither
proves nor disproves a local burst; unused refill can be lost at a full bucket.
Per-packet arrival times and the rejected token balance were not retained.
**ACTUAL_BURST_UNKNOWN; token-bucket defect unproven.** Aggregate average FPS is
not instantaneous burst evidence.

## Processing capacity — reused Fixture measurements

Each stage ran in a fresh unprivileged process. Packet stages used 100 warm-up
and 2,000 timed calls; Producer used 10 / 500; durable SQLite handoff used 3 / 30;
each actual model used 1 / 3; investigation 1 / 3; WSLg render 10 / 50. Model
timing includes isolated process startup and verification. The investigation
stage used a trusted actual RF receipt and the existing READ-only orchestrator.
Percentiles are nearest-rank observations, especially coarse for three samples.
The JSON includes p50/p95/p99, throughput, process CPU, sampled RSS, queue depth
where applicable, error counts, interpreter, and kernel. Nonapplicable queue
measurements are null, not fabricated zeros. Stage-source hashes at measurement
time were not recorded; current harness identity is listed separately.

| Stage | p99 ms | Notes |
|---|---:|---|
| Raw parsing | 0.0592 | Synthetic wire input |
| DNS extraction | 0.0076 | Metadata only; partially overlaps parse work |
| JSON serialization | 0.0518 | Packet envelope and metadata |
| Unix transfer | 0.0022 | Uncontended ordinary user socket pair |
| Transport validation | 0.0613 | Structured message decoding |
| Flow aggregation | 0.2119 | Bounded isolated flow state |
| Network14 | 0.3952 | Existing Producer |
| SQLite durable handoff | 256.9211 | Commit, claim, finish; not packet storage |
| Quality isolated adapter | 2,285.8397 | Actual RF; cold process per request |
| Edge isolated adapter | 2,122.2640 | Actual LR pipeline; cold process per request |
| READ-only investigation | 289.9524 | Existing orchestrator |
| WSLg render | 9.2582 | Actual empty STOPPED view |

These are pre-interruption measurements, not new recovery executions. Successful
stage files and failed harness attempts are retained separately. One initial
profiling harness had backend/path and sampler-cleanup errors; corrected stage
files exist. Failed attempts are not counted as passing measurements.

## Candidate policies and selection

The six packet-path p99 values sum to about 0.394084 ms. A planning allocation of
25% of one CPU gives approximately 634.38 raw frames/s; rounding down to a power
of two gives 512. A conservative quarter/half/full ladder produces the candidates
below. Burst is capped by the unchanged transport capacity. This sum is **not a
joint p99**, measured saturation point, or AF_PACKET throughput result. Kernel
receive/counter work, concurrent host load, and actual traffic distributions
remain unmeasured. CPU/RSS/IO must be checked in a separately approved Native run.

| Policy | Raw FPS | Burst | Duration s | Maximum raw frames | Qualification |
|---|---:|---:|---:|---:|---|
| Legacy (default, unchanged) | 128 | 256 | 300 | 38,656 | Existing approved scope |
| conservative-v2 | 128 | 256 | 300 | 38,656 | Separate approval required |
| balanced-v2 | 256 | 512 | 300 | 77,312 | Separate approval required |
| performance-v2 | 512 | 512 | 300 | 154,112 | Conditional Fixture recommendation |

All new totals are exactly `rate * 300 + burst`, not unbounded capture. No rate
is raised automatically. The default remains **legacy**. Exact policy validation
rejects arbitrary rate/burst/session/resource changes. Each candidate retains
transport capacity 512, inference capacity 8, 128 active flows, 1,024 flow records,
8 MiB packet-metadata state, 768 MiB controller RSS, 64 MiB session disk, 35 helper
CPU seconds, 160 controller CPU seconds, maximum 64 inferences, and 30-second
graceful drain. Helper AS and existing worker per-request limits are unchanged.

The common discrete-event trace contains an instantaneous synthetic 384-frame
burst, then 128 and 512 FPS segments. Conservative and balanced eventually reject
it; performance admits it. A paused/slow service overflows the bounded transport
explicitly. This artificial trace is not a reconstruction of missing Native
arrival times and is not proof of end-to-end sustained capacity.

Two serial model profiles plus investigation are much slower than packet
processing. The existing bounded inference queue therefore remains essential:
capacity exclusions are audited `NOT_INFERRED_NO_RETRY`, never inference success.
Capture-wide loss/counter/rate/auth failures still block both Network and DNS;
they are not downgraded to harmless inference overload.

## Revised helper and approval boundary

New entry: `network_capture/calibrated_helper.py`, session contract
`soc-total-calibrated-session:v2`. It reuses the unchanged capture engine and
requires exact session, code, policy, and approval digests before capture. The
15-file manifest includes new policy/session/helper files and relevant transport
and isolation code. Session permissions remain 0700 directory / 0600 files.
Authenticated Unix peer/executable/argv/capability checks remain in place.
The one-session reference/tombstone ceiling is explicitly opt-in for calibrated
policies and bounded at 154,112; the legacy 38,656 ceiling remains unchanged.
Quarantined keys never regain eligibility by eviction. A full-bound reference
test checks cleanup and bounded RSS without packet capture or model loading.

New Helper SHA256:
`375c06dbeb4e14c881fa496459182677b4efaa293845ecfac0dab0da663c4703`

New Bundle Digest:
`56ec48caac56a248fc0eeb5bb09c4fae4176482ed19ea8c48526f7638ae8bb31`

Old live Helper SHA remains
`a8a0cafe7494922a0296a250129ab5695b681dbbec6febf512509b023ef44856`.
Old total bundle remains
`e26057b77534b552701826dd1c4d6829e76d94fcfc0bb8c263fd661f2038ac0f`.
Old approvals do not authorize the new entry, session, or limits. Runtime source
changes invalidate the new bundle/session; do not reuse a prior command.

## Network, DNS, AI, GUI, and audit integration

Existing Network14 v1.1.0 order, float32, packet event timestamps, direction,
idle 30s / active 120s, and eligibility are unchanged. SHUTDOWN and packet-limit
flows are not forced into inference. No timestamp clamping or reordering hides
regression. Flow-local quarantine and common capture-wide failure remain separate.
DNS metadata query/response diagnostics share capture integrity; DNS9 inference
remains **PARITY_BLOCKED**. Raw payload and names are not retained.

Quality RF and Edge LR artifact hashes remain, respectively,
`53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603` and
`661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882`.
Earlier identical 263-packet prefix comparisons produced four actual receipts
and four READ-only investigations per candidate. They used the **earlier total
frame ceiling** and are retained as historical prefix evidence, not certification
of final expanded policies. Likewise, the earlier 20-second-per-policy Mock soak
had no actual model calls and predates final expanded-policy verification.

The Tkinter selector exposes each candidate explicitly. GUI status distinguishes
configured rate, policy approval, actual capture readiness, retained results,
and operational gate. Unapproved selection cannot launch a helper. Token balance
is UNKNOWN when not measured. Restart generates a new session identity; retained
approval is not current authorization. Authentication remains terminal-owned:
no root GUI, password input, password storage, `sudo -S`, or unrestricted command.
Model results remain uncalibrated research advisories with existing READ-only
investigation and audit, never automatic operational Findings or OS responses.

## Initial recovery verification (historical)

Recovery run `capacity-recovery-20261019-01`:

* Syntax/import: 18 owned Python files, new/old bundles verified.
* Ruff `check src tests`: PASS. Initial whole SOC format: 1,044 files already
  formatted; final workspace check: 1,046; independent export: 1,002. The export
  excludes original uncommitted user files.
* `git diff --check`: PASS.
* New low-cost policy/authentication/session/bundle/GUI tests: **23 passed,
  3 deselected in 77.77s**. The three actual-model cases were explicitly excluded
  for insufficient memory; they are not counted as passing or resolved.
* Additional streaming/capture/Network14 contract regression: **249 passed in
  100.58s**, without actual model inference.
* New recovery-evidence integrity tests: **5 passed in 0.81s**.
* Independent HEAD-plus-22-owned-files export: **277 passed, 3 deselected in
  167.82s**, Ruff/format PASS, zero guarded capture/Internet-socket attempts.
  Original user/Replay overlays and model binaries were excluded. Trusted model
  references were read-only; artifact hashes matched. The three actual-model
  cases remain excluded, so this is **LOW_COST_PASS / FULL_MODEL_BLOCKED**.

Each line above is a separate execution, with overlapping tests; do not sum the
counts into a unique regression total. The report/evidence were finalized after
the export run, then copied into that same export and rechecked for integrity
(**5 passed in 6.19s**, separate execution).

The low-cost test command used the existing socket-denying test guard and a
dedicated temporary directory:

```bash
.venv/bin/python -m tests.native_capture_verification_guard \
  --import-mode=importlib -q \
  --basetemp=/tmp/soc-capacity-recovery-low-cost \
  tests/unit/streaming_network/test_calibrated_policy.py \
  tests/integration/streaming_network/test_calibrated.py \
  tests/gui_calibrated_policy_checks.py \
  -k 'not identical_candidate_load_actual_artifacts'
```

No long regression or actual model benchmark was needlessly repeated. Earlier
test attempts are individually scoped in evidence; their counts are not added
together. OOM/SIGILL are not claimed reproduced or fixed. At initial recovery,
model drain failures and insufficient memory prevented final integration
acceptance and stage/commit/push. The latest section separately records subsequent
successes and the resource stop. ML source was not changed.

## Next Native validation and approval scope

All six required Fixture cases are complete. Do not repeat them or the passing
277-case regression without new changes or failure evidence. Before a separately
approved Native run, recheck MemAvailable, swap/PSI trend, affinity, dependencies,
and both model hashes. Investigate any new timeout explicitly; do not extend
deadlines or lower integrity gates merely to obtain a pass.

Request separate user approval for one fresh
**lo-only / 300s / 512 raw FPS / burst 512 / maximum 154,112 raw frames** session,
using the exact new SHA and Bundle Digest above, temporary CAP_NET_RAW, capability
drop after socket open, bounded queues/resources, no automatic capture restart,
metadata-only retention, and no OS security WRITE. Actual Native calibration,
kernel counters/drop quality, and end-to-end completion are **PENDING**.

The following preview exits before OS authentication when SHA approval is absent:

```bash
cd ~/kdt-linux/autonomous-soc-agent
.venv/bin/soc-agent start --gui --monitor total --rate-policy performance-v2
```

After explicit separate approval **and completed integration validation**, the
user—not this agent—can enter the reviewed terminal authentication flow:

```bash
.venv/bin/soc-agent start --gui --monitor total --rate-policy performance-v2 \
  --approve-calibrated-sha 375c06dbeb4e14c881fa496459182677b4efaa293845ecfac0dab0da663c4703
```

Review the printed policy/bundle, answer `yes`, and authenticate only to the OS
terminal prompt. GUI Stop drains within policy; helper deadline/disconnect also
ends capture. Never reuse a failed session. This document and implementation are
**not permission to execute** the new helper. Native calibration, DNS9 parity,
and operational promotion remain blocked/pending independently.

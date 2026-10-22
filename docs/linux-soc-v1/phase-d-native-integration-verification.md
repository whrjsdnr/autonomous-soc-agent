# NATIVE_SOC_PHASE_D Final Report

## Overall Status

**BLOCKED — exact-image installation/Native approval pending.**

The instruction to investigate/stabilize is not approval of a new SHA. The actual
campaign budget and creation ledger authorize development only. No sudo/PAM,
Root installation, privileged inventory, BPF load, TCX attach, Native capture or
DNS query was performed in this work. Native/Root usage remains **0/5, 0/5**.
The existing0.6.0 approval request was withdrawn after a termination defect was
identified. One combined installation/Native request was presented for the fixed
0.6.1 candidate below; no approval receipt has been manufactured.

## Git / Release

Baseline HEAD and origin/main: `754ea8dfbd2e96836249b024092d1e3beae022c5`.
Git commit identity and the following artifact identities are separate.

|0.6.1 identifier|SHA256|
|---|---|
|Integrated manifest|`6aed33cbf761adb2e391783b6746a7815a5ce7a054953bd7214350ff82d0c2d3`|
|Runtime bundle|`ef7e223759b3efbb36486b53a5076ed87aed1934bf2195af26abd39890add812`|
|Execution image|`c3857752a1ab8abdefd7c14516a66fb3740b01d14e9dd5ea9447d344db98e562`|
|Root release manifest|`1f205935cdb344178a848108b508d20a9f6e1028ad56f718b0a61cb4269478d3`|
|Unchanged TCX object|`9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06`|

Candidate: `.git/native-soc-phase-d/stabilization-061/candidate/`.
Existing0.6.0 artifacts and verification receipts remain intact.

Installed0.5.16 remains unchanged. Its Root manifest is
`2e5faaf4dac7381157adcc82b61465316946aa115c501073f25eb95ee9282289` and
bundle is `bddd454656af79a4fac26ce0d4f20cb1d00f3afc2012e7531ce3f7778c271916`.
Read-only installed-file ownership/mode/SHA/dependency verification passed.
The planned rollback path is `/usr/libexec/.soc-agent-ebpf.rollback-` followed by
that manifest. No conflict exists at the inspected time; recheck before install.
No rollback path was created or installation file replaced.

The DNS0.5.20 baseline remains:
manifest `414aea0feb53a5b1e424d4157a602687f3b8906f484d64e6bda6d1ca260087d5`,
bundle `de4208dc9c1439135baf2d05bed4a89b0249dfd59b72036fd723bfcee10f76d0`,
image `a2ad9ecccb569f185323f78d62a4cf7fc805a9670a84e4b0d4e35e34ab571e39`.
These identify baseline evidence; integrated execution uses the new image SHA.

## Unified Collector

- Supervisor / shared Session, Release, Approval: implemented; Native PENDING.
- TCX program, packet ABI, Loader, data plane and owned-Link contracts: unchanged.
- DNS TTY/START, checksum-copy, Analyzer and Counter/CLOSED paths: unchanged.
- New source fixes do not add authentication, Supervisor, Root shell or setuid.
- GUI, Network14 and model workers remain ordinary user processes.
- Inspector SYS_ADMIN and Broker BPF+NET_ADMIN profiles remain separate.
- Real concurrent delivery, capabilities and combined cleanup: PENDING.

### Termination and original-error defect

Previously the ordinary Controller had no SIGTERM handler. A real ordinary-child
reproduction confirmed that default SIGTERM exits without Python `finally`.
Thus parent audit finalization could be skipped even if child/Kernel FD lifetime
later released resources. These are different cleanup claims.

`supervisor_startup.execute()` now installs a main-thread termination boundary,
unwinds once through existing cleanup, ignores repeated stop signals during that
bounded cleanup, and restores previous handlers. The original signal number is
retained. SIGKILL remains uncatchable; its audit/cleanup outcome cannot be proven
by this handler or inferred from a fixture.

The execution wrapper now records safe first-failure Stage/API/class/errno/signal
separately from cleanup errors. A repeated final-close error is recorded without
preventing the result receipt or replacing the first failure. Tests inject a
read error errno5 and a separate close error errno9; these are **fixture errors,
not actual Kernel errno**. No raw error input or password is saved.

### Campaign launch contract

`native_campaign.py` supplies bookkeeping for the qualification CLI, not a new
privilege/authentication authority. Existing TTY confirmation and OS authentication
remain required. The CLI requires explicit campaign and exact approval receipt
arguments; an absent/changed receipt prevents execution.

The initial budget/baseline and old ledger prefix are never rewritten. Under an
exclusive file lock, the runner verifies the ledger anchor/hash chain, exact
release and approved scope, independent Native/Root limits, then appends and
fsyncs reservation **before** calling the existing executor. A failure consumes
the reserved attempt. A consumed approval cannot launch another session.
Concurrent requests cannot consume one approval twice. Final records preserve
failure metadata and never automatically pronounce Native VERIFIED.

`budget.json` remains the initial declaration. Effective usage is that declaration
plus append-only `NATIVE_ATTEMPT_RESERVED` records; do not reset the declaration
or infer remaining budget without reading the ledger. In the actual campaign
there are no such records yet, hence usage0/5 for both budgets. Approval receipts
are public decision metadata, not authentication tokens, and must only be created
after the user's exact-image decision. Preparation/tests do not create one.

## Network14

### Candidate Eligibility / Capture Integrity

The immutable [D-1 evidence](phase-d-feature-eligibility-evidence.json) was reused.
The four0.5.16 candidates retain their original vectors/digests and INCOMPLETE
termination. New annotations do not modify those records:

|Flow prefix|Packets|Input state|Native AI|
|---|---:|---|---|
|89751ff9e100|16|INCOMPLETE|BLOCKED|
|6e6e7bcce539|24|INCOMPLETE|BLOCKED|
|7254400bd0f1|22|INCOMPLETE|BLOCKED|
|6e8caf439886|28|INCOMPLETE|BLOCKED|

The earlier0.5.13 six-candidate run retained four detailed receipts and lost two
candidate details. The unretained two remain UNKNOWN. No Flow IDs or reasons
were invented for them.

### Counter

Historical0.5.16:179 received,90 accepted,89 discarded,0 queue rejected. Final
owned-map counters: observed432, emitted385, delivered181, disabled47, ring
reservation failure0. Difference204 is unreconciled delivery, not proof of204
Ring losses. Three CPU observation-attempt gaps are not necessarily lost emitted
records. There is no per-packet evidence attributing them to individual flows.
Current0.6.1 counters are NOT OBSERVED. Counter epoch/generation, replay, reset,
missing CLOSED and unknown-loss behavior are covered by nonprivileged tests.

### Clock

Historical0.5.16 inversions0/late0; calibration DECLARED_ONLY. Kernel monotonic,
userspace processing time, Zeek event time and wall/audit time are not compared
as one clock. Reordering preserves original ns timestamps, with bounded10ms/
32-event behavior. Neither reordering nor fixture calibration proves Native clock
accuracy. Session/domain mismatch and late-event rejection remain enforced.

### Flow Lifecycle / Feature Generation

Idle30s/active120s, direction, key, packet/byte counts, float32 order and digest
contracts are unchanged. FIN/RST are observed features; the trained window
contract does not treat them alone as new completion authority. No new TCP
completion policy or timeout threshold was introduced.

Unreconciled attempts conservatively quarantine outstanding flows. The retained
short0.5.16 candidates have no full timeout-window evidence. PACKET_LIMIT,
CAPTURE_STOP, QUEUE_OVERFLOW, CLOCK_INVALID, NORMAL_END and INCOMPLETE remain
separate; changing a label does not establish completeness. Event cap4096 can
end collection before a30s/120s observation window completes; no packet limit was
increased and stopped intervals were not filled using wall time.

### RCA implementation defects fixed

1. Final Supervisor RCA previously recomputed from only the last four vectors,
   losing already retained per-candidate RCA receipts. It now retains bounded
   full receipts while adding terminal counter context. Missing raw vectors are
   explicitly marked checkpoint-receipt-only, not claimed revalidated. The test
   uses eight receipts/four vectors and preserves all eight identities.
2. NaN/Inf/noncanonical values could raise during digest calculation, preventing
   an INVALID report. They now produce INVALID with no imputation or inference.
3. Input states distinguish INVALID, INCOMPLETE and UNKNOWN. A correctly shaped
   timeout candidate with unproven capture/parity/model evidence remains UNKNOWN.
   No candidate is granted ELIGIBLE without the missing Native evidence; Native
   AI policy remains BLOCKED independently.

Native Golden Parity, bound model artifact receipt and current complete capture
remain unproven. Existing offline model success does not supply those receipts.

## Performance

Baseline Native metrics are historical, not before/after0.6.1 measurements.
No0.6.1 Native rate, drop count, eligibility rate, processing latency, peak RSS,
CPU or cleanup duration was measured. No throughput improvement is claimed.
At a read-only development checkpoint MemAvailable was4609504KiB; memory PSI
avg10/avg60 were0.00. These are host observations, not collector benchmarks.
No GUI performance/full model benchmark or unrelated optimization was performed.

## Verification

Tests distinguish ordinary-process signals, mocked authority/approval paths,
real Unix metadata transport and actual Kernel capture. No test here loads BPF,
opens a capture interface, changes capabilities or generates DNS traffic.

- Real SIGTERM/default-vs-guard cleanup and original errno/cleanup separation.
- Exact SHA approval, scope, missing approval, duplicate/concurrent launch,
  independent budgets, no refund, invalid initial budget and append-only chain.
- Native input states, NaN/Inf/type/digest, retained receipts and historical UNKNOWN.
- Existing TCX startup, clock, frame/counter scope, loss, flow and Golden contracts.
- C fixture transport/Counter/CLOSED/drain regression; no Native equivalence claim.

Some older tests assumed immediate processing despite the existing10ms reorder
window, contiguous observation-attempt numbers, or an EOF mock without the real
transport-fatal flag. These fixtures now drive explicit observed-tail drain,
late-event violations beyond10ms and accurate terminal frames. Queue conservation
asserts33 received =33 discarded (32 queued plus1 rejected), rather than omitting
the rejected record. Production limits/validation were not weakened. An obsolete
EOF mock was interrupted as an owned test process after looping; no Native or
user process was signalled. All original behavior areas remain asserted.

Final test and source/Export/index results are recorded below after qualification.
The unchanged D-1 file-only DNS/GUI/model-related source results remain baseline
regressions; they are not reported as new Native tests.

## Evidence / Budgets / Approval

Historical104 receipt hashes, eight user-file hashes, existing install hashes,
old0.6.0 candidate and existing ledgers are preserved. Native sessions, raw/model
artifacts and datasets are excluded from source commits/exports. New preparation
artifacts live under `.git/native-soc-phase-d/stabilization-061/`.

Read-only environment: kernel6.18.33.2-microsoft-standard-WSL2,
namespace`net:[4026531833]`, lo ifindex1; UDP/TCP listeners for127.0.0.53:53 exist.
No local service was replaced or DNS query sent. Current privileged Program/Map/
Link/TC-filter inventory is UNKNOWN until the approved Inspector runs; past zero
counts do not establish present absence or retroactively verify old cleanup.

Requested combined approval: install0.6.1 preserving0.5.16 rollback, one OS
terminal authentication, Inspector preflight, then only if clear lo/Ingress
<=300s/4096 metadata/Queue32/256MiB/CPU20s per privileged role. DNS remains same
namespace/lo, active<=10s/capture<=7s/32 packets/snaplen512/Queue32, fixed local
127.0.0.53:53 native-0516.localhost. A UDP1/TCP1, no external DNS or settings
change. Zeek retains RAM512MiB/CPU1 and capless isolated analysis. No auto-retry,
no pinning, no packet modification/drop, no arbitrary foreign cleanup.

## Native Verdict / Remaining Blockers

|Area|Current verdict|
|---|---|
|Unified Supervisor Native|PENDING approval and actual execution|
|TCX Native Counter/Clock/Capture Integrity|PENDING; historical incomplete evidence retained|
|DNS Sidecar Native TTY/START/lifecycle|PENDING for integrated0.6.1|
|Network14 Native eligibility|BLOCKED; incomplete/unknown evidence|
|Current privileged resources / capabilities|UNKNOWN; not queried without approval|
|Native GUI / combined cleanup|PENDING|
|Nonprivileged regression / evidence preservation|Qualified separately below|
|Native AI / DNS9 / operational promotion|BLOCKED|

The work must resume with the exact0.6.1 decision, not assume that this task or
an old0.6.0 approval permits its new SHA. If approved, reserve before launch,
use the existing terminal path once, inspect before attach, preserve actual first
failure and all cleanup evidence, then review actual packet/DNS/feature outcomes.
A failed Native attempt does not start a new session automatically.

## Qualification Results

The frozen independent Export passed121 focused cases on its first run. One
feature-reference case failed because the Export intentionally contains no sibling
ML repository; it passed after supplying the existing explicit test-only source
roots (`SOC_RESEARCH_VALIDATION_REPOSITORY` / `SOC_RESEARCH_VALIDATION_ML_SOURCE`).
Both independent producer source SHAs match the reviewed catalogue. Thus **122
focused cases passed**, with no assertion removed or model binary copied/loaded.
This includes actual signals only for owned ordinary fixture children, never
Native collectors. Workspace focused runs also passed49 contract cases and73
flow/counter/qualification cases. Ruff/Format/Diff passed on changed files.
No entire-project regression, full model, GUI benchmark or Wheel run was added.

The new qualification CLI requires `--campaign`, `--approval-file` and
`--approval-sha` with the exact release `--manifest` / `--image`. The approval
file has not been created; it must represent a real explicit decision, not an
inferred instruction or an authentication token. Before Native launch, recheck
all file SHAs, previous install/rollback conflict, namespace, local listener and
Inspector resource/hook evidence.

### Installation payloads (prepared only;9 files)

|File|SHA256|Root mode after approved installation|
|---|---|---|
|bootstrap|`df183f29c4b73d5cd401e37d51ac4a95a13a756411df7ce21e1f6c5361372ee2`|0555|
|broker|`62b2019d09f606e0c59d8b47ca216c23240b725294f1f929b9fed9ae442725ee`|0555|
|entry|`8e4ef82c3fe45ae5a414509316a2922898148ed860bb7ebdde9f743509ce4455`|0555|
|libnative-tc.so|`138b6a4f7a30db599635a523c7abfbd912758ebee5624f00a7d5fc221c8f09e3`|0444|
|manifest.bin|`b247a42e124e28242c61ed31468bbd1125b4d5ac2e0442b4f351a7033722626a`|0444|
|pam-policy.conf|`93af76067bf513b4db8c5a9bd606e348ccde334b83e52f7dc71544c9c1f82696`|0444|
|release.json|`1f205935cdb344178a848108b508d20a9f6e1028ad56f718b0a61cb4269478d3`|0444|
|release.trust|`0cd588ea8c3eb01ebe6f6afcb32f8ed19dee549cbaea43494c509dc7a89b713c`|0444|
|tc.bpf.o|`9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06`|0444|

# SOC Native Stabilization — Batch 3 Preparation

## Overall Status

READY_FOR_POLICY_AND_BUDGET_REVIEW; Native execution remains BLOCKED.
Batch 3 development and nonprivileged qualification are complete. No policy
activation, human risk acceptance, budget allocation, authentication, Root
installation, Capture or diagnostic traffic was performed in this task.
P02/P03 remain INCOMPLETE and P04 has no verified Native ELIGIBLE candidate.
Native AI, DNS9 and production remain BLOCKED.

## Batch 2 Closure / Batch 3 Baseline

Development continues on `fix/native-stabilization-batch3`, based on pushed code
`7d73a97635a156c060f0da3e28a6e1ac387e58e0` / tree
`c4998db3ca8d8bd6ab829a719d1dd81def490c18` in the existing isolated worktree.
The original user workspace and pre-existing unstaged Batch 2 report edits were
preserved. No new worktree or campaign counter reset was made.

The shared SOC_NATIVE_STABILIZATION campaign retains 12 immutable Ledger rows:
11 original rows plus the previously approved settlement. Batch 2 remains
charged Native2/2 and Root2/2; Campaign totals remain Native3/10 and Root3/10.
The interrupted reservation remains EVIDENCE_INCOMPLETE, Root UNKNOWN, Native
UNKNOWN. Its consumed receipt remains consumed; accounting closure is not proof
of no execution, a refund, a positive safety decision or permission to retry.

The last actual Batch 2 Capture delivered/applied4,096/4,096, with no Packet
Admission rejection. Supervisor Exit1 / FAILED and global Cleanup UNVERIFIED
are preserved. Session-owned TCX/container Cleanup was VERIFIED. Program1145
removed from wsl-pro.service has cause UNKNOWN; no newly added Program was
observed in that historical comparison. No new privileged snapshot was taken.
Original safe_for_next_attempt=false remains intact.

The Batch 2 historical-context execution management grant was validly applied
for settlement. It is not a reusable grant for new source, Batch or Artifact.
Evidence sources and their SHA pins are preserved in the private Batch 3
`batch2-inherited-evidence.json`; past candidates were not reclassified.

## Runtime Policy Block RCA

The existing `native-recovery check` calls `phase_d.validate`, then
`validate_image_recovery(..., require_policy=True)`. The pending image embeds
RECOVERY_POLICY_BODY=None and has no Recovery policy SHA. This exact condition
raises RECOVERY_POLICY_APPROVAL_REQUIRED. It is not an expiry diagnostic and
not an ABI failure. Current Source and Runtime verification both pass.

The retained installation remains bound to its original dependency hashes.
The new isolated Runtime uses current zlib1g1:1.3.dfsg-3.1ubuntu2.3; no downgrade,
old-hash replacement, installation mutation or automatic mismatch allowance
occurred. The previous limited ABI report is reused as a pinned compatibility
input, not as a claim of production ABI qualification.

Changed source changes the Recovery implementation pin and Artifact Identity.
Batch 3 has a new Session and Binding. The latest Ledger includes the accounting
settlement. Those are additional reasons old grants cannot transfer; the
immediate check error is still the missing embedded Recovery approval.

## Minimal Operational Changes

The existing Binding accepts explicit BATCH3 in addition to BATCH2. The existing
reassessment CLI derives the batch from that validated, pinned packet. Admission
and per-batch counting use the amendment's Binding rather than hardcoded BATCH2.
The base campaign controller, budget file and global maximum10 remain unchanged.

Batch 3 requires a distinct BatchAllocation decision in the pinned admission
amendment: explicit approver/human reference, exact base budget/baseline hashes,
Native maximum2 / Root maximum2 and expiry. Missing, mismatched or expired
allocation fails closed, including expiry after the confirmation wait. No real
allocation receipt was issued or applied.

An optional accepted_settlements map in the existing human R1 review pins exact
accounting event hashes. The validator requires the approved
EVIDENCE_INCOMPLETE / UNKNOWN / UNKNOWN, KEEP_RESERVATION_CHARGE,
approval_reusable=false and authorizes_execution=false fields. Only a fresh,
explicit human review and separately approved admission amendment can use that
map. The original failure, charges and UNKNOWN outcomes are never rewritten.
Without that review, a settled uncertain attempt still blocks the next run.
Settled attempts also cannot be reused to claim old R2 traffic permission.

These are inactive extensions to existing models/validators, not a new executor
or approval CLI. AGENTS.md section33 requires Human Review -> Approved Update;
new implementation pins intentionally invalidate automatic use of old policy
receipts. No production grant or positive R1 decision was manufactured.

## Proposed Budget

Campaign reservation-inclusive usage: Native3/10, Root3/10; remaining7 each.
Batch 2 final charged usage: Native2/2, Root2/2.
Batch 3 has zero reservation events and no approved allocation yet. Proposal:
Native maximum2 and Root maximum2, within the existing global10 and batch2 caps.
This would leave campaign usage3/10 until an actual reservation; the first
approved one-installation run would project4/10 and Batch3 1/2. No previous
charge is refunded. Each future execution still needs its own exact approval;
two allocated slots do not authorize an automatic second run.

## P02 / P03 / P04 Diagnostic Conditions

Reuse existing R2Launcher and Supervisor lifecycle without changing traffic or
thresholds. Capture ATTACH/link evidence precedes R2.start, which precedes the
initial DNS Sidecar. The initial UDP/TCP probe records actual TCP socket-close
monotonic time. Sidecar analysis retains its internal10-second deadline and
finishes independently of the longer TCX observation period.

At TCP close+35seconds, one separately approved UDP witness to the same local
endpoint may be sent. At close+45seconds request existing normal STOP; the
existing60-second capture plan and300-second overall cap remain. Thus planned
STOP is approximately45seconds after TCP close, not an invented45-second
Capture Window. Actual timestamps, CLOSED and snapshots determine the result.

FlowAssembly uses the kernel event-time watermark. A captured late UDP event
can expire a prior idle Flow only if it is at least30seconds after that Flow's
last observed packet. Waiting in userspace after STOP cannot do this. FIN/RST
are preserved flags, not alternate eligibility authority. STOP-forced flows
remain incomplete. Per-CPU paired windows, same epochs, clock brackets,
reconciled counters and loss checks independently gate Capture Integrity.

Before a separately approved run, the user should close unnecessary VS Code
Remote sessions and background loopback activity. There is no approved rate
limiter/filter/drop mechanism. Prior4,096-event exhaustion at12.873seconds
implies about318events/second; surviving45seconds requires under about91events/
second on average, with additional headroom for initial traffic and close time.
These are planning calculations, not new traffic measurements or acceptance
thresholds. No synthetic result guarantees that the next host run will satisfy
that condition. Early cap, unsupported packets, missing CPU/window evidence or
new losses retain INCOMPLETE/INVALID as appropriate; no limits are relaxed.

The synthetic complete-window fixture can produce ELIGIBLE input receipts, with
stable schema/fingerprint/digest/provenance and no model execution. Historical
actual candidates remain seven with zero verified eligibility. Offline replay
has UNKNOWN for raw vectors that were not retained; that is not new Native
success and does not change original judgments. Full vectors/receipts and the
16KiB Checkpoint cap must still survive the next actual run.

## Nonprivileged Verification

- Related Workspace regression:501 PASS; independent frozen Export:501 PASS.
- Focused Batch 3 / window / R1/R2 run:89 PASS, including12 new transition tests.
- Tests cover real temporary hash-chain preview/append, no implicit UNKNOWN risk
  acceptance, missing/wrong/expired batch allocation, expiry after confirmation,
  actual reassess CLI BATCH3 dispatch, preserved charges/false and replay denial.
- Existing window/Flow/R2 cases cover late witness, early4,096-event stop,
  clock/epoch mismatch, missing windows, STOP watermark freeze, valid timeout
  input, Receipt integrity, DNS/Supervisor/Checkpoint and no-approval execution.
- Ruff check PASS; Ruff format check PASS (1,387files); git diff check PASS.
- SourceGuard watched workspace and frozen Export throughout verification/builds;
  1,729 selected inputs have identical start/end SHA maps. Symlink/replacement,
  addition/deletion and observed inotify mutations invalidate the cycle. This
  detects changes; it is not a filesystem lock against adversarial TOCTOU.
- Stage and independent BuildA/BuildB have exactly28 identical file/hash entries.
- Existing protected112 files, historical Native49 files, installed9 files and
  retained/Rollback234 files are preserved. Ledger stays12 rows with unchanged
  SHA and original FAILED/false/UNKNOWN evidence. No execution budget consumed.

This is related regression qualification, not a claim that the previous global
Export Operator timeout / Zeek READY failures or production qualification have
been resolved. All approval and integrity checks must repeat before execution.

## Source / Pending Artifact Identity

Source Snapshot SHA256:
`ff7ebc04cb759d64ca0e5dd0b7308aba3feae5f6b4620bc1346bbe620186c203`

Manifest SHA256:
`28cdeb0916ad1e61d421a15ec2269b3a092f02e7575a1a7389d15b7a5d18ea9a`

Bundle SHA256:
`0b0c636a1e8623b78693b93ab2fd03c456d450e04e11784df359e75e53fab90e`

Execution Image SHA256:
`1d9b732953b65291382e9c93252f8b6d4f035e89f8e383bb0318868c7b47af87`

Root Manifest SHA256:
`a715e1aab17d25ce89d87ce320a8b16997cb3072d83956734126baa470a501a6`

These identify actual non-executable-policy-pending0.6.3 artifacts, not an
approved Native Release. Policy receipt inclusion changes image/Manifest SHA;
the post-policy exact Identity must be requalified, never approved by inference.
Current nonconsuming check: SOURCE_VERIFIED and RUNTIME_VERIFIED, then BLOCKED /
RECOVERY_POLICY_APPROVAL_REQUIRED; reserved=false, executed=false.

## Git / Single Approval Package / Next Action

Only the three operational modules, new Batch 3 regression test and this report
are selected for the Batch 3 commit. Pre-existing Batch 2 report changes and all
private Ledger/receipts remain unstaged. Final Commit/Tree, remote verification
and source-to-commit checks are recorded after commit in `git-delivery.json`.

One review dossier, with independently validated decisions and no issued grants:
`.git/native-stabilization-batch3/release-preparation-20261027-1/approval-package.json`.

It contains the exact final Git identities, pending Artifact SHA, Runtime
Recovery binding, latest Ledger pin, Batch3 budget proposal, R1 procedure and
UNKNOWN settlement risk material, R2 traffic Scope, management/admission policy
pins, fixed9-file Root scope and one-run Native request. All decisions are PENDING.

The existing embedded-policy contract imposes a real ordering constraint:
first review policy and budget; then build with the approved policy receipt and
requalify new SHA; then bind independent R1/R2/Root/Native decisions to that final
Artifact. The single dossier can carry successive linked identities; a pending
image hash cannot preauthorize a different future image. No additional approval
system or speculative positive receipt was created to conceal this dependency.
No execute invocation is authorized by this preparation.

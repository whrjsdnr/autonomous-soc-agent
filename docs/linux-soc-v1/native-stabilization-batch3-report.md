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


# Batch 3 — Environment, Capture and Checkpoint Stabilization (2026-10-27)

## Overall Status

INSTRUMENTED; Native execution remains BLOCKED by the measured ambient load and
pending new exact-Artifact approvals. This task performed no Root operation,
authentication, Native Capture, attach, DNS query or other diagnostic traffic.
The last actual Native result remains PARTIALLY_VERIFIED, P02/P03 INCOMPLETE,
P04 ELIGIBLE0/9. Existing candidates were not reclassified. Native AI, DNS9 and
production remain BLOCKED. No new approval system or execution policy was added.

## Loopback Source — Current Evidence Versus Historical Attribution

Passive35.003173992s sampling of /sys/class/net/lo/statistics/rx_packets observed
12,063 packets, mean344.625890 packets/s (five-second intervals309.58–380.38/s),
with no increment in the interface RX dropped counter. ss -tinape snapshots
before/after correlate four established TCP connection pairs with actual /proc
FD socket inodes, PID/PPID, namespace and cgroup. All are net:[4026531833] and
cgroup0::/init.scope. Port34339 belongs to VS Code Remote server/extension hosts:

| Client port | Client PID | Server endpoint owner | Purpose verified by executable/arguments |
|---|---:|---:|---|
| 41702 | 82065 | 560 | VS Code node -e net.createConnection / server-main.js |
| 41714 | 82078 | 82115 | VS Code node tunnel / extensionHost |
| 53190 | 836 | 560 | VS Code node tunnel / server-main.js |
| 53192 | 854 | 925 | VS Code node tunnel / extensionHost |

Counting each pair once using server endpoint segs_in+segs_out deltas gives
2,935+2,825+3,126+3,163=12,049 TCP segments. Both endpoint counters agree.
Comparison with12,063 interface packets is approximate: snapshots are not atomic,
TCP segments and interface counters have different observation boundaries.
This is evidence that these VS Code Remote connections dominate *current*
loopback load, not attribution by process name alone. Some other listeners have
no readable owner and remain UNKNOWN. No process/service was stopped. Other
Codex processes were observed but not killed; no source mutation was detected
in the guarded export/build verification.

Historical Native evidence preserves flow hashes, counts, first/last event
watermarks and direction counts but not the necessary socket tuple/PID mapping
or every packet timestamp. Thus historical ownership/ports and a per-second
packet histogram cannot be reconstructed. The four historical dominant flows
are not retroactively assigned to the current sockets. Historical Native counts:
TCP4,082, UDP14, total4,096; top four TCP flows4,072 (99.414%); event-span rate
339.048119 events/s. Emitted4,132=delivered4,096+post-limit exclusions36 remains
reconciled in epoch5785906024313912557. Ring reserve failures0 and processing
rejects0 are scoped observations; kernel-wide drops remain UNKNOWN.

## Capture Window / R2 / Flow Timeout RCA

The existing4,096-event cap stops Capture immediately; subsequent STOP wall-clock
waiting cannot advance the FlowAssembly event watermark. Idle Timeout is30s
since the Flow's last observed packet in the same monotonic event domain;
active timeout remains120s. FIN/RST observations alone do not attest Capture
Window completeness. Per-CPU pre-attach/post-detach snapshots and same-epoch
clock evidence remain necessary and do not repair a truncated delivered prefix.

R2 already starts after Capture Ready, preserves TCP Close time, sends its single
additional approved UDP at TCP Close+35s and requests STOP at TCP Close+45s.
Startup time is additional to that45s interval; the300s total bound and10s DNS
Sidecar analysis deadline are unchanged. A later UDP event can supply an event
watermark only if Capture is still active and real evidence validates it. The
Sidecar may have already exited; its earlier DNS Deadline success is separate
from TCX's later timeout observation. No timer or eligibility condition changed.

Current ambient mean projects15,508 packets over45s (peak interval projects
17,117), before setup or controlled queries. At the measured mean4,096 packets
would take11.885s. These are passive interface-load projections, not synthetic
TCX event counts or guarantees. Current environment feasibility is NOT MET.
Even4,096/45=91.02 packets/s would leave no startup/scenario headroom. Actual
full-duration bounds must be assessed after environment preparation; low passive
rate still cannot prove a future Capture Window or candidate completeness.

Operational code capture_readiness.py exposes read-only loopback_snapshot and
assess_loopback_budget. It flags observed high ambient rate, resets, namespace/
clock/schema errors and short quiet observations. It never authorizes execution,
filters packets, changes counters or marks a Flow ELIGIBLE. There is no new
automatic admission gate or safety-policy activation.

Preparation for a separately approved attempt: save work; close unnecessary
VS Code Remote windows/extensions through the user's own UI, then use a standalone
Windows Terminal/WSL shell rather than an active Remote session to repeat passive
sampling for35s or longer. This can disconnect the current development session;
no agent-triggered termination is authorized or performed. Retain the actual
netns/lo scope and evidence of the newly quiet sockets. A separate network
namespace would change Scope and requires separate approval, so it was not
created. Full-scope filtering, event-cap increases, timeout reduction and packet
shedding are not alternatives used here. If ambient load remains high, do not
spend the last Batch3 attempt under the same conditions.

## Checkpoint Size Analysis and Lossless Change

Original persisted UTF-8 Summary15,766B /16,384B left618B. In its V1 envelope,
summary payload9,834B includes feature_tail4,641B and ordering2,069B; candidate
rows5,254B and shared context610B dominate the remaining payload. These component
sizes exclude enclosing JSON key punctuation and should not be added as a full
byte-accounting equality. Repeated feature-name arrays and nested lifecycle
Window/termination authority fields were confirmed across rows.

checkpoint.py now supports SHARED_CONTEXT_V2: deterministic shared top-level
fields and nested lifecycle fields are factored independently in candidates and
feature_tail. Row order, distinct timestamps/counters/identities, values, Digest,
Provenance and every receipt are retained. V2 is selected only when smaller than
the existing V1 fallback for an oversized plain summary. Plain JSON and V1
remain readable; no historical database or Summary is rewritten. Decoder schema,
shared/row overlap, duplicate JSON keys, UTF-8 bytes and bounded expansion remain
validated. The16KiB limit is unchanged and oversize remains an explicit failure.

A derived re-encoding of the exact previous Native Summary is12,525B, saving
3,241B and leaving3,859B. All nine candidate metadata receipts and four originally
retained raw vectors restore identically; semantic Digest remains
95fff67c57e55a5ba3692f170e7af2d31208d2f5e36c45ef9015e24c5c72c496.
The five missing historical raw vectors are not fabricated. This capacity change
does not change their UNKNOWN decisions. Original database SHA remains
5f287e8a94bad8b8928c65e133d559d6abf58946f5567bc212777ff30c1c4bf1.

The existing1,024-candidate bound, Unicode/long distinct contexts, differing
observations, deterministic encoding,16KiB boundary, malformed contexts, digest
binding, SQLite persistence/recovery and failed-save preservation were tested.
1,024 identical contexts fit, but1,024 distinct long identities/contexts do not
universally fit16KiB. That case still raises EBPF_CHECKPOINT_SIZE without deleting
or truncating evidence. No promise of arbitrary maximum-input compression is made.

## Verification and Failure Classification

New and related core regression: Workspace372 PASS and independent frozen Export
372 PASS, including actual persistence/recovery and synthetic STOP/Drain, R2,
clock, Flow, Network14, policy/approval and budget tests. Synthetic/fixture tests
are not a new Native success. Ruff, Format and Diff pass.

The wider ebpf/ebpf_tc/release integration selection was also run:781 PASS,
15 FAIL. All15 failed nodes reproduce in the unchanged pre-task frozen ddc1750
Export (15 FAIL). They comprise one historical Zeek Bundle pin for the earlier
CLI source, ten C fault-fixture cases producing inconsistent CPU Window/Counter
records, and four source-stabilization test doubles lacking the existing recovery
argument. They were not hidden or weakened. Those broader pre-existing regressions
remain unresolved; no full Workspace or production qualification is claimed.
Exact node lists, baseline reproduction and core selection are saved as evidence.

## Source / Artifact Integrity

Frozen selected source:1,732 files, including the three new module/test files.
The pending Batch2/Batch3 report edits remain outside the existing selected build
input set. Both source/export bytes and SourceGuard change detection were checked.
No source mutation was accepted during build. Existing installation and Rollback,
Native55-file evidence index, protected112 files and campaign Ledger are unchanged.

The current approved a715... installation now matches the current zlib dependency
SHA. The *existing normal* Builder independently validated that installed Runtime;
no old mismatching dependency was ignored and no Recovery policy was modified or
reused. It produced a review-only Stage and two independent builds with26/26
files identical (the earlier recovery-specific28-file set included two recovery
companion reports). Prepared bytes do not grant execution authority.

Review candidate Artifact Identity:

- Manifest SHA256: `fd9d2e61b53104f3b3d6b48e5ace8c3e394705a713be834207c62a909b1c4240`
- Bundle SHA256: `4cbe8ce11056cdaac4d11139b11e583fb9831564e61f81f560b52562b7975c77`
- Supervisor Execution Image SHA256: `2a93c1557196c2bc88530b547f16cf877f632b7c19c78af6d37c18ff7962abec`
- Root Manifest SHA256: `c56d1126e2d0dadb265375027243b9edaae8b721535c6c534689c72561656c5f`
- Previous installed Root Manifest: `a715e1aab17d25ce89d87ce320a8b16997cb3072d83956734126baa470a501a6`

In addition, the existing quarantined Runtime Builder produced23/23 identical
files with executable_admission=false and a fail-before-import image. Its separate
Manifest is `c31fd604a719296a848f66e769e3c8e0121e93063c37faf15ea92d46f79ca889` and image is `cf1188f49c47a57093d8800c749f290d81509d75bc67e4dee6d45f850b77dc1b`.
It is not the Supervisor image above. Both builds retain current zlib SHA
f61677c7bdb7c2aa2a243ea781bfd16afcb361cede7b4ef76127a9d8eb9a5242.

Existing native-recovery check against the new review candidate returned BLOCKED /
R1_AMENDMENT_REQUIRED, reserved=false, executed=false. SOURCE_VERIFIED and
RUNTIME_VERIFIED passed. POLICY_APPROVED is NOT_APPLICABLE for the unchanged
normal-dependency path, not a fabricated positive Recovery approval. All actual
R1, R2, Root and Native approval stages remain blocked. No execute command ran.
Final Git Commit/Tree, selected-source SHA and post-Push checks are recorded in
this task's final-verification.json and the consolidated pending approval package.

## Git / Evidence / Budget / Next Conditions

Only this task's five source/test changes and this appended report section are
selected for Commit/Push. Older pending documentation changes, including the
Batch2 report, are preserved outside this Commit. Original user workspace,
installed/retained files, Ledger/Audit and past FAILED/false/UNKNOWN evidence are
not staged or rewritten. No force push, consumed-receipt reuse or refund occurs.

Campaign Native4/10 and Root4/10; Batch3 Native1/2 and Root1/2 remain unchanged.
The one remaining allocation per operation is not permission to execute. The
next review dossier is environment-checkpoint-stabilization-20261027-1/
next-approval-package.json under .git/native-stabilization-batch3. Its decisions
are PENDING: quiet-environment evidence, fresh exact-Artifact/Session R1 admission,
R2 Traffic Scope, managed execution Binding, Root1 and Native1. It retains the
Program1145 UNKNOWN cause, past global Cleanup UNVERIFIED and uncertain settled
reservation. Do not reactivate old receipts or automatically retry. P02/P03/P04
require new Native evidence; Native AI, DNS9 and production remain BLOCKED.


# Batch 3 — Dedicated Network Namespace Preparation (2026-10-27)

## Overall Status / User Environment

IMPLEMENTED_DISABLED_PREVIEW; actual isolated Native qualification remains BLOCKED.
The user's latest constraint supersedes earlier Remote-close/quiet-host advice:
VS Code Remote, other projects, services and WSL must remain running. None was
stopped, killed, moved, restarted or shut down. No Root command, namespace creation,
setns/unshare, interface change, Native Capture or real DNS traffic was performed.
The previous passive terminal did not measure after Remote closure: its recorded
status was REMOTE_CONNECTIONS_STILL_ACTIVE_NOT_POST_CLOSE_MEASUREMENT. No post-close
success is claimed and that workflow has been abandoned.

Current host Scope remains net:[4026531833]. Read-only ip netns list was empty;
/run/netns/soc-native-b3 was absent and the kernel exposes NET namespaces through
/proc/self/ns/net. iproute2 and the namespace limit are present. This establishes
availability of interfaces/tools, not successful privileged creation in this WSL.
The existing time Namespace and user mappings were not changed.

## Isolation Design / Compatibility

Network namespaces isolate network devices, sockets and routing. A new namespace
with only its own lo and no veth/NAT/default route excludes the existing host's
VS Code loopback connections without filtering/dropping their packets or changing
those processes. This is the kernel design; actual separation is NOT yet observed.
See [Linux network_namespaces(7)](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
and [ip-netns(8)](https://man7.org/linux/man-pages/man8/ip-netns.8.html).

| Component | Compatibility and current boundary |
|---|---|
| TCX C plan/ownership | Namespace inode already crosses the authenticated ABI; lo ifindex alone is insufficient. No BPF/packet ABI change. |
| Ordinary controller / Root Supervisor | Both must start as new owned processes inside the dedicated Namespace; approved sudo inherits it. No existing user PID is moved. |
| Supervisor Image | New explicit Namespace preview binding; active legacy descriptors remain host-only. New scopes require a disabled preview descriptor. |
| Integrated DNS capture | Exact target Namespace comes from a SHA-held image constant, never environment/argv. Default historical host check remains. |
| Local DNS service | Host systemd-resolved is unreachable through the new lo. Use a dedicated no-forwarding responder at the same127.0.0.53:53. No host DNS configuration change. |
| Zeek analysis | Reuse existing stdin-PCAP/analysis-copy path with --network=none and no NET_RAW. It consumes copied bytes, not the host lo. |
| Legacy Zeek live / standalone checksum probe / R2 V1 | Remain host-bound; they are not approved isolated entry points. R2's old Namespace receipt is explicitly rejected for the new Scope. |
| cgroup / maps / filesystem | Not isolated by a network namespace; retain existing global/owned Cleanup distinctions and all ownership checks. |

Docker --network=host shares the Docker daemon host's namespace; entering a new
Namespace in the CLI does not move the daemon or its host-mode containers. Thus
that mode is not the isolation solution. See [Docker host networking](https://docs.docker.com/engine/network/drivers/host/)
and [Docker none networking](https://docs.docker.com/engine/network/drivers/none/).
The integrated Phase D copy feed avoids that problem; legacy live Zeek remains
unsupported for an isolated preview. No Docker container was launched for these
tests: the real-Docker offline integration test was intentionally not run because
it would itself create a namespace. Existing argv/transport fixtures were used.

## Operating Code Implemented, Without Activation

namespace_isolation.py provides a strict isolated Scope (distinct from the host),
read-only configuration inspection, fixed setup proposal, Namespace-specific DNS
Scope Digest, exact diagnostic DNS wire responses and single-scenario protocol
state. Only native-0516.localhost. A, transaction IDs C201/C202/C203 and ordered
UDP/TCP/UDP are accepted. No recursion, forwarding or arbitrary destination/name.
Duplicate queries and count/order expansion fail explicitly.

isolated_dns_worker.py supplies an ordinary-UID prebound-socket transport. It
never binds, connects, resolves, creates namespaces, elevates privilege or launches
processes. Before IO it checks current Namespace and zero-capability ordinary UID,
then checks exact listener endpoint/type and SO_NETNS_COOKIE against a fresh,
unbound socket in that Namespace. Host-created listener FDs cannot silently cross
this check. Socket cookies are not confused with namespace inodes. It serves only
three responses, enforces the additional UDP no earlier than35s after server TCP
close, and closes its own provided sockets on completion/failure. Application
receive/close timestamps are not Kernel Flow evidence.

A confirmed transport defect found during review was fixed before final build:
per-read timeout alone could permit a fragmented slow TCP request to exceed the
worker lifetime. Every exact-read iteration and reply write now recomputes the
same absolute60s responder deadline. Synthetic tests reproduce slow reads,
premature witnesses, timeout, foreign namespace cookies and owned-FD closure.
This responder lifetime is separate from the unchanged DNS Sidecar analysis
Deadline10s. Root prebinding, ordinary-worker spawning/resource limits and session
ownership must be covered by the new approved Namespace resource lifecycle.
There is currently no CLI/Supervisor call that starts this new worker.

phase_d.prepare_namespace_preview reuses the existing compiler, package Builder
and Supervisor image assembly. It emits a distinct SOC_PHASE_D_NAMESPACE_PREVIEW_V1
contract. The Supervisor image begins with an unconditional
ISOLATED_NAMESPACE_POLICY_NOT_ACTIVATED exit before imports. Descriptor validation,
startup and SupervisedSession independently reject activating the new Scope.
Existing operational manifest validation rejects this preview contract. There is
no argv/environment flag to activate it or automatically inherit an old receipt.
The existing R2 Scenario/TrafficReceipt still rejects the new Namespace. Formal
new Scope/R2/lifecycle activation requires the AGENTS.md33 approved-update process;
this preparation does not widen those active permission rules.

capture_readiness.assess_loopback_budget now accepts an explicit expected Namespace
for read-only analysis. The host default is unchanged. Host samples cannot be
used as isolated-namespace evidence; no result grants execution or eligibility.

## Capture / Flow / Checkpoint Conditions

Keep events4096, Queue32, admission50ms, clock reorder10ms, Checkpoint16KiB,
Native duration300s, memory256MiB, CPU20s, DNS analysis10s. No timeout, Feature
formula/schema, provenance or receipt criterion was weakened.

Planned sequence: dedicated responder READY; Capture READY; initial approved
local UDP1/TCP1; real client TCP close; additional local UDP at+35s; STOP at+45s;
Queue/Flow finalization, Checkpoint, Audit Drain and owned/global Cleanup. Existing
R2's time origin is TCP close, so startup is additional. The last UDP flow may
correctly remain incomplete at STOP; the earlier TCP/UDP flows need actual event
watermarks beyond30s and complete per-CPU/Clock evidence. TCP FIN alone is not
Flow completeness. No new time namespace is proposed.

The last Native controlled pair contributed UDP2 packets and TCP10 packets; a
similar additional UDP pair would give roughly14 diagnostic packets. This is a
historical-based estimate, not a guaranteed bound for a new responder/kernel run.
Retransmissions and all actual scope traffic still count toward4096. Actual35/45s
passive counts, CPU boundaries, counter epochs, clock brackets and timeout
receipts must be measured after approved Namespace creation. No actual isolated
Window, low packet rate, Capture Integrity or ELIGIBLE candidate is declared.

All prior Network14 candidates keep their decisions (Native ELIGIBLE0). The new
configuration and protocol Fixtures are synthetic. Checkpoint evidence is not
reduced to fit a Namespace scenario; the existing V2 lossless encoding, legacy
restore and16KiB fail-closed tests passed unchanged. The old unexplained12 events,
Program1145 cause UNKNOWN, historical FAILED/false and uncertain reservation stay
unchanged. Namespace isolation does not resolve global cgroup uncertainty.

## Verification / Frozen Inputs

Final focused Namespace tests27 PASS. Related Workspace479 PASS and independent
Export479 PASS; tests include existing Capture/Clock/Flow/Network14, Namespace
scope gates, responder synthetic IO, approval, budget, STOP/Drain, Checkpoint and
Supervisor paths. Ruff/Format/Diff PASS. Earlier attempt478 PASS /26-file build
was superseded after the absolute-TCP-deadline source correction; its artifacts
are not reused as final evidence. The previously documented15 broad historical
regression failures were not rerun or claimed resolved.

Final source1,735 selected files, Snapshot SHA256 `399a063dc23ba4d2da19a1e433c353cab86bda5010d87cbcc305538313513851`. Stage and two
independent builds have26 identical files. The preview uses net:[4999999999] as an
explicit SYNTHETIC test value, not an observed or approved Namespace. Preview
Manifest `a8a9aac57ba10c0b55591efe6179d0142f3779ca43ad858d8b2af32d175a8ea1`, Bundle `028d9025e74184ac5fa5a0a567fcfaba7ba47ee40b13a388004afce1ba12c66a`,
Image `27b19d9ff5a1c3053fecdd59cc0442edb7c89395c912bb1a33920b3bc6695e96`, Root Manifest `bde2ff5f3d8862f32d36e0e28d48486ac4253311cc987bb1e3f5d548e30dffbc`
are test/review identities only. None is a valid actual Native execution approval
request. Actual Namespace inode and real isolated Artifact SHA are PENDING.

Evidence directory: .git/native-stabilization-batch3/namespace-isolation-final-20261027-1/.
It contains test-selection.json, workspace-tests.log, export-tests.log,
build-verification.json, source-start/end.json, host-capability-review.json,
setup-proposal.json, setup-approval-request.json and final-verification.json.
The old55 Native files,112 protected user/historical files, installed/retained
files and18-row Ledger are rehashed/preserved. No ledger event or budget charge
is added by preparation.

## Required Human Decisions / Actual Environment Changes

The consolidated setup request is a request, not an approval receipt. It proposes
only a new soc-native-b3 Namespace and lo UP, no veth/NAT/firewall/host route or
system DNS changes. Existing name collision must stop without reuse/deletion;
any failed step stops. ip netns add may create a root-owned /run/netns mountpoint,
so it is outside the existing nine-file installation Root Manifest. No setup
command has run.

Separate approval is required for Namespace setup and its new Scope policy,
including exact lease/ownership, DNS listener prebinding and ordinary-worker
lifecycle, R2 Scope binding and resource limits. A name is not ownership. After
creation record actual Namespace dev/inode, boot/session/creation receipt and held
FD lease before generating the real new Scope Artifact. Never move/terminate
existing user processes. Cleanup may release only the verified own sockets,
processes, TCX objects and exact owned Namespace; unknown resources must not be
removed by name. Preserve current global Cleanup rules.

Root setup cost is NOT defined as a nine-file installation by the current campaign
contract. Its budget mapping needs an explicit human decision; no cost/refund or
extra Batch3 allowance is inferred. Current Campaign Native/Root remain4/10 each,
Batch3 remains1/2 each. Namespace setup is not permission to install or Capture.
Once actual Namespace Identity and approved activation bytes exist, issue fresh
exact-SHA R1/R2/management/Root/Native bindings, then nonconsuming check. Old host
Namespace grants, consumed receipts and synthetic preview SHA cannot be reused.

## Git

Only this task's operating code/tests and appended report section are selected.
Older pending Batch2/Batch3 documentation edits remain unstaged and preserved.
Final Commit/Tree, remote Push result and source-to-Commit checks are recorded in
final-verification.json. No Force Push or historical evidence rewrite is used.

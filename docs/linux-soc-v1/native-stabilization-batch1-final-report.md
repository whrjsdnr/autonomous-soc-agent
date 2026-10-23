# SOC Native Stabilization — Batch 1 Final Report

## Overall Status

**PARTIALLY_VERIFIED**. One explicitly authorized Native session completed with
CLI/privileged entry exit0,no first or follow-on failure,
`PROCESS_AND_AUDIT_VERIFIED`. P01 isVERIFIED for current-epoch metadata accounting;
P02 remainsINCOMPLETE;P03 isPARTIALLY_VERIFIED for observed termination evidence,
with all7 new Feature candidatesINCOMPLETE. No historical result was upgraded.
No automatic second execution was performed.

## Campaign / Approval

- Campaign:`SOC_NATIVE_STABILIZATION`,batch`BATCH1`.
- Authoritative registered ledger:`.git/native-stabilization-batch1/execution-v1/`.
- Native1/10,Root1/10;Batch1 Native1/2,Root1/2. Remaining9 overall and1 inBatch1 each.
- Prior Phase D remains5/5Native and5/5Root;its Ledger/budget were not rewritten.
- The earlier development-only budget/REQUEST remain preserved as history.
  Their pending Root field is superseded by the new registered execution contract,
  not silently edited into an approval.
- User's follow-up explicitly instructed execution and authorized the remaining
  budgets after the exact Artifact list. This authorizes the current SHA/session,
  not any future changed binary or automatic retry.
- Receipt:`execution-v1/attempt-1/approval.json`,SHA256
  `269b260e99307a60c7da4aa862cc0e2b4d89aad13a6ec6bed0e0ea20918e5cff`.
- Attempt:`8ed7672c684144ff96ead4be1daac20c`;session
  `e28fbd82-07a4-4066-9b7b-2ba3e9e38d61`;generation1749717119874752036.

### Artifact Identity and qualification adapter

Approved Artifact Git537a278f104e1cc86a1308fdcc7ad6f6887074e4,
Tree4b731896821e596b2f7989bcfa827c3ce558aaab.

| Artifact | SHA256 |
|---|---|
| Manifest | `76ed726c48808212ae629601239335ca37b1e24e09022cae081fb0068d964fc0` |
| Bundle | `7d770e1d383302c7e37883eb73428e5145edaa5570b64f453b0d43e8b9016fbb` |
| Execution Image | `108e5a26238ee5a0c90a3a522a805ee01cf54062a7cf87150ef36f141f067df0` |
| Root Manifest | `a1214d2c58bd21ca7a156e4f5c136dbbb63d796b649d26e2400cce89ebe00297` |
| Approved1703-file input inventory | `1a6911b824269a315010480d214a099f476360c63adb95981cb1464ab5f110b0` |
| Unchanged TCX object | `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06` |

The existing runner only admitted the old5-run campaign. The new ordinary-UID
`StabilizationCampaign` budget adapter reuses`NativeCampaign.reserve`,its locked
append/hash-chain/fsync,exact scope/Receipt/replay checks,and`finish`. It adds the
separate10/10 budgets,2/2 perBatch,controller/Batch/budget receipt binding,and
blocks another reservation until previous completion and safe evidence review.
The old constructor and old campaign are unchanged. Missing Root budget rejects.
Reserved attempts,including failure after reservation,remain consumed;pre-reserve
rejection consumes nothing. There was no cancellation in this session.

Adapter Commit8ba3b18f7e5d5c64897fcc2a339a9d6cb6056aaf,
Tree501a925c1348cf3f59eaa8806850291aace012a0,
source SHA256`5456671a37e2b56148e770ada0f96675a006c6ed207b8017a8f20fe803fe360d`.
It is qualification bookkeeping outside the Root execution image,recorded
separately from the approved Artifact inventory. It delegates to the same
`phase_d.validate` and`phase_d.execute`;no monkeypatch,Root shell,alternate
Supervisor,approval bypass or inherited privilege was introduced.
All26 approved artifact bytes and runtime bundle matched before execution.

One fresh sudo authentication invocation used real TTY stdin;the user entered
credentials directly. Passwords/keystrokes/retry counts were not recorded.
No additional privileged post-run inspection/authentication was invoked.

Scope:net:[4026531833],lo/Ingress,300s/4096events/Queue32,privilegedAS256MiB/CPU20s.
DNS:127.0.0.53:53,native-0516.localhost.,A,UDP1/TCP1,10s active/7s capture,
32packets/snaplen512,existing ZeekRAM512MiB/CPU1. The existing systemd-resolved
localhost responder was used without replacement/configuration change. No
external request,offload change,foreign detach or scope expansion occurred.

Root installation replaced exactly the9 fixed Manifest files. Root:root ownership,
0555 executable/0444 data modes and file hashes were verified after installation.
The previous2eb95e82... installation is preserved in its full-Manifest rollback
directory,together with all older rollback sets. No user/model/raw data was staged.

## P01 Counter

### Reconciliation — VERIFIED,current owned metadata epoch only

| Layer / outcome | Count | Domain / observation |
|---|---:|---|
| Kernel observed | 4140 | Owned per-hook/per-CPU Map,aggregate final snapshot |
| Kernel emitted | 4138 | Parsed metadata submitted to Ring |
| Kernel unsupported | 1 | Attempt without Ring event;subtype not retained |
| Kernel disabled | 1 | Attempt outside enabled config;not automatically packet loss |
| Ring reservation failures | 0 | Owned Map count,not Kernel-wide drops |
| Malformed / Kernel budget exclusions | 0 /0 | Owned Map count |
| Loader Ring callbacks | 4138 | New generation-scoped terminal accounting |
| Confirmed packet sends | 4096 | Successful atomic192-byte sends |
| After-cap metadata exclusions | 42 | Explicit Loader counter;no network packet drop implied |
| Invalid scope/size / send failures | 0 /0 | Loader classification |
| Userspace received / applied | 4096 /4096 | Authenticated Receiver / Packet Adapter |
| Queue reject / policy discard / pending | 0 /0 /0 | Processing accounting |
| Kernel-wide packet drops | UNKNOWN | Not observed;never filled with0 |

```text
4140 = 4138 emitted + 1 unsupported + 1 disabled
4138 callbacks = 4096 delivered + 42 budget_excluded + 0 invalid + 0 send_failed
4096 delivered = 4096 received = 4096 applied
```

Same generation1749717119874752036,final Map timestamp78331785971577ns,
configured start78319402854107ns,final-drain marker78331785853385ns.
The last two are configuration/after-detach bounds,not an atomic Capture Window.
Final drain0,Map lookup0,Counter transmit0. The19-row chained Native Journal
contains the identical ACCOUNTING payload as the authenticated Data Channel.
4101 frames,last envelope sequence4100,CLOSED received. Envelope sequence is
Userspace transport sequence,not an invented Kernel global packet sequence.
Socket send failures/EAGAIN/EPIPE/POLLOUT waits0. POLLOUT recovery was not exercised.

**Historical12 Events:** UNKNOWN. This session's42 exclusions confirm the source
mechanism and fix,not the exact attribution of events absent from an older trace.

### RCA / competing hypotheses

| Hypothesis | Evidence / falsification | Decision |
|---|---|---|
| Current emitted-delivered difference is cap exclusion | callbacks4138,explicit excluded42,send/invalid0,Map emitted4138;would fail if any equation/drain/epoch differed | CONFIRMED current epoch |
| Current difference is Ring reserve or Socket delivery loss | owned Ring failures0,send failures0,received=delivered;Kernel-wide drops not observed | Does not explain current42;no global zero-loss claim |
| Two CPU attempt gaps are lost delivered records | CPU3 starts atattempt2;CPU1 moves317->319;observed-emitted2 are unsupported1+disabled1 | Exact per-CPU attributionUNKNOWN;aggregate matching is insufficient |
| Reordering proves calibrated capture time | 18 bounded inversions,max2835ns,late0;no calibration samples | Reordering VERIFIED,Native calibrationUNKNOWN |

## P02 Capture Integrity

**Counter:** final same-epoch accounting reconciles,with explicit42 exclusions.
A single final aggregate cannot prove an initial baseline,periodic continuity or
silence on unobserved CPUs. Unsupported1 and disabled1 are not merged into Ring
loss or fabricated per-packet Drop records.

**Clock:** KERNEL_MONOTONIC_NS declared,no UTC conversion/timestamp rewrite.
18 inversions,reordered18,max2835ns,late0,10ms bound unchanged. Calibration remains
unattested. Historical194ms inversion cause remainsUNKNOWN.

**CPU Coverage:** actual received intervals:

| CPU | First/last attempt | Received | First event ns | Last event ns |
|---|---|---:|---:|---:|
| 0 | 1 /1372 | 1372 | 78319524558665 | 78331663962241 |
| 1 | 1 /958 | 957 | 78319553323090 | 78331615589191 |
| 2 | 1 /916 | 916 | 78319708274323 | 78331650247166 |
| 3 | 2 /852 | 851 | 78319519848288 | 78331638211713 |

These are received-event intervals,not proof about disabled/unsupported/silent
CPU intervals. Gap2 is retained asUNRECONCILED. Final totals are consistent with
unsupported/disabled outcomes,but no per-CPU map rows or individual excluded
metadata prove which gap belongs to which cause.

**Provenance:** Plan digest
`cb75441e2c34aba367f7a598229e91d66ed4bd97b8679a9e597accbbee814643`,
program SHA9a4d26cf...,approval/session/generation,namespace4026531833,
lo/Ingress and the received event/Feature chains match Checkpoint/Recovery.
Source isKERNEL_TCX_NATIVE. These receipts prove their scoped linkage,not absent
packet bytes or an atomic start/end boundary.

**Final Decision: INCOMPLETE / PARTIALLY_VERIFIED evidence.** Reasons remain
KERNEL_UNSUPPORTED,DELIVERY_BUDGET_EXCLUDED,CPU_ATTEMPT_GAPS_UNRECONCILED,
ATOMIC_CAPTURE_WINDOW_NOT_ATTESTED,INITIAL_PER_CPU_BASELINE_NOT_OBSERVED,
CLOCK_CALIBRATION_NOT_ATTESTED,KERNEL_WIDE_DROPS_UNKNOWN. No threshold was relaxed.

## P03 Flow Completeness

**TCP:** one7-candidate receipt containsBOTH_FIN_OBSERVED,bidirectional,10packets.
No receipt reportsRST. Two FIN directions establish termination observations,
not complete handshake/ACK coverage or a full Capture Window.

**UDP / Timeout:** the independent DNS path completed UDP and TCP transactions.
No TCX flow receipt has an idle/active timeout witness. The captured event span
is approximately12.144s;30s idle/120s active limits were not changed or satisfied
by an invented timer. A persisted protocol label is absent from these TCX RCA
receipts,so a no-FIN receipt is not automatically classified asUDP or joined to
an individual DNS transaction solely by packet count.

**STOP:** the aggregate delivery cap was reached. The current fail-closed
assembler finalizes withINCOMPLETE when CPU attempt gaps exist;that is why all
seven receipts recordINCOMPLETE rather than flow completion. No last-event time
was replaced with process STOP/wall time. The precise original end-control reason
is not a separate persisted field in the summary;do not invent one from the last
receipt. Queue/Flow/Audit drain success is a distinct shutdown fact.

The candidate source is the shared Plan/session/epoch above;each full Flow ID,
observed first/last window fields,lifecycle and Feature fingerprint is retained in
`attempt-1/evidence-review.json` and the Native Checkpoint. No separate atomic
Window Identity exists in this release;observed bounds are not mislabeled as one.

| Flow ID prefix | Packets | TCP termination observation | Candidate state |
|---|---:|---|---|
| `93a4377e8060a7f6` | 1005 | NOT_OBSERVED | INCOMPLETE |
| `53509369865b9376` | 1004 | NOT_OBSERVED | INCOMPLETE |
| `8aaf397df76559f0` | 1064 | NOT_OBSERVED | INCOMPLETE |
| `d87a4add52a584d7` | 1007 | NOT_OBSERVED | INCOMPLETE |
| `7652c849be919a7e` | 2 | NOT_OBSERVED | INCOMPLETE |
| `69fa597443c7d37d` | 10 | BOTH_FIN_OBSERVED | INCOMPLETE |
| `03b2fb255f0a87ec` | 4 | NOT_OBSERVED | INCOMPLETE |

All7 feature schemas/digests validated at generation. Raw vectors are retained
for the configured4-vector tail only;first3 RCA receipts preserve identities and
fingerprints but cannot independently reproduce missing raw vectors. All7 have
Capture Integrity/clock/parity/model-receipt barriers;eligible0. Earlier4/8/12
historical candidates and2 unpreserved candidates retain their prior verdicts.

**Final Decision: PARTIALLY_VERIFIED termination evidence;Flow completeness
INCOMPLETE,0/7 ELIGIBLE.** No normal closure is fabricated from STOP or FIN alone.

## Native E2E

- **Supervisor:** shared session/release/approval,real TTY plus separateSTART,
  CLOSED,first_error null,control_errors/failures empty,entry/CLI exit0.
- **TCX:** Program1021,Link4,tag5d24af0965a164b7,lo/Ingress,unpinned;
  4096received/applied;unchanged TCX object/TCX_NEXT behavior.
- **DNS:** one UDP and one TCP query/response probe completed with question match
  andRCODE0. Zeek/DNS Diagnostics accepted2 completed transaction records,UDP1/TCP1,
  response records2,duplicate records0. Query-packet/response-packet counters in
  completed-log evidence remainnull;probe counts are independent evidence.
  DNS visibility isDNS_VISIBLE_CONTROLLED_LOCAL_TEST,not general DNS visibility.
  Transaction collision/retransmission ambiguity remainsUNKNOWN.
- **Deadline:** active9.508413827s<10s,capture6.588006595s<7s,
  input-closed78328.689385615,Counter78328.880221558,CLOSED78328.882143835,
  analysis cleanup78329.322709507,final cleanup marker78329.418863305,
  analysis_deadline_expired=false. Launcher36.541s includes human/authentication
  and outer orchestration;it is not the DNS active interval.
- **DNS Stream:**19records,12Raw-IP UNSUPPORTED,2network,2DNS,Counter/CLOSED,
  invalid/duplicate/gap0. The12 analysis copies were accepted;capture reject0,
  socket drops0. Raw-IP observations stay excluded fromNetwork14. Offload-copy
  provenance remains partial;raw payload was not retained for fresh recomputation.
- **Network14:**7 candidates,4096packets total,0eligible,allINCOMPLETE.
- **Admission/performance:** waits18/resumed18,immediate4078 derived,timeouts0,
  rejects0,Queue peak31/32,max admission wait7.832845ms,total91.196117ms,
  max queue residence9.317233ms,processing4.914802ms,Audit commit48.897964ms.
  Different live traffic prevents a controlled before/after speedup claim.
  Peak RSS/actual CPU usage were not independently measured.
- **Checkpoint:**13213B<=16384,**SHARED_RCA_V1 actually exercised in Native**,
  all7 receipts plus4-vector tail retained. Digest
  `ea930c46b0c9704d531d3e6f5b8513666f942d049019b7eef617511ce3c209f3`.
  Copy-only RecoveryRESTORED_NO_REATTACH equals stored Native evidence;original DB
  SHA unchanged. Audit chain26 records/24Checkpoint records verified;
  async writer22submitted/22committed,no outstanding/reject/failure.
  This sample does not prove arbitrary1024 unique receipts fit16KiB.
- **Drain:** Ring0,Map lookup0,Counter transmit0,processing pending0;
  receiver/processor/Audit workers stopped. Counter/ACCOUNTING/CLOSED received.
- **Cleanup:**3MapFDs/1ProgramFD checkedF_GETFD/EBADF after libbpf close;
  raw close return values were not independently observed. Inspector exited0,
  authority revoked/channel closed;OS authorizationREVOKED. Owned Supervisor,
  capture,Inspector PIDs943018/943019/943020 absent. Sidecar container absent,
  exit0;no cleanup failures. No extra sudo was used for these post-run checks.
- **Kernel/cgroup:** authenticated before/after inventories identical:
  Programs11->11,Maps0->0,Links0->0,lo ingress/egress0->0,cgroup rows6->6.
  Owned Program1021/Link4 absent at final inspection. Current session cleanup
  VERIFIED;historical foreign Program ownership remainsUNKNOWN. No foreign
  Program was deleted. The legacy unused`zeek_container_removed=false` field is
  not the actual Sidecar cleanup proof;its`container_absent=true` is.

## Verification

- Prior unchanged Artifact:Workspace273PASS,independentExport224PASS,
  C/socket/Drain integration15PASS,dual builds26 identical.
- Fresh pre-execution review62PASS;new budget-adapter/legacy/exclusion/Flow
  regressions50PASS after final adapter source freeze. Ordinary-UID mocks and
  fixture C/socket tests are separate from the single actual Native session.
- Ruff/Format/Diff pass. No assertions weakened or Native Gate changed.
- Approved1703 runtime/build input hashes stayed equal;all26 approved artifacts
  stayed exact before/after execution. The separately hashed ordinary-UID
  adapter/test additions do not change Root Image/Manifest/Bundle contents;
  the existing`phase_d.validate` checked the same approved identity.
- Historical full Export5909PASS/2FAIL/30SKIP remains unresolved. GUI visual
  verification and Native AI/model inference were not performed.

## Evidence / Ledger

Private evidence:`.git/native-stabilization-batch1/execution-v1/attempt-1/`:
`approval.json`,`preflight.json`,`launch-claim.json`,`terminal-exit.json`,
`native-evidence-sha256.json`,`evidence-review.json`,`journal-review.json`,
`checkpoint-recovery-proof.json`,copy-only`recovery-copy/`.
All49 current Native files are indexed without editing originals;prior49-file
indexes remain unchanged. The112 protected baseline/user files,all historical
Phase D Ledger/budget bytes and earlier development Ledger/budget are preserved.

New Ledger5records:creation,contract approval,reservation,finished-pending-review,
evidence review. It reuses the existing append/lock/hash/fsync format. Root/Native
1/10 each,Batch1 1/2 each;no cancellation or automatic retry. A safe-resource
review allows a future separately approved attempt;it is not a new execution
approval and does not turnCapture Integrity intoVERIFIED.

## Git Commit / Push

The adapter and its tests were selectively committed as8ba3b18 on
`fix/native-stabilization-campaign-execution`;the approved Artifact remains537a278.
This report/problem register update is a subsequent documentation commit. No
original user changes,Native raw evidence,Ledger/Audit or model files are staged.
Push is to the isolated branch;main is not overwritten.

## Remaining Blockers / Batch 2 Readiness

P01 is ready to reuse:explicit metadata exclusion and failures reconcile.
Past12 remainsUNKNOWN. P02 needs initial/final per-CPU window evidence and
independent clock/calibration proof;unsupported/disabled subtype and CPU
attribution are not retained. P03 needs genuine start/termination/window evidence;
persisting protocol and original source-end cause would improve diagnostic
attribution,but no new values were backfilled into this session. No such code
change was made after this successful run.

Batch2 can reuse these immutable receipts,Counter/ACCOUNTING/Journal and lifecycle
observations. Further installation or capture still requires an exact-SHA receipt
and safe pre-run inspection. Batch1 retains one remaining slot,but it is not
executed automatically. Native AI,DNS9 and production promotion remainBLOCKED.

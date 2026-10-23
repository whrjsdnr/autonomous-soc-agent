# SOC Native Stabilization — Batch 2

## Overall Status

READY_FOR_NATIVE_VERIFICATION. This is nonprivileged preparation, not a Native E2E success or authorization. Historical Batch 1 candidates remain 7/7 INCOMPLETE. Native AI, DNS9 and production promotion remain BLOCKED.

Development continues in the existing release worktree `/home/geonug/kdt-linux/native-soc-phase-d-release-063`, branch `fix/native-stabilization-batch2`, from `f1b756ea3c06692efc767348e4825984435dbce7`. The original user worktree was not reset, staged, or modified. No additional worktree, Supervisor, approval controller, Root installation, authentication, BPF attachment, capture, DNS traffic, or offload change was performed.

## P02 Capture Integrity

The prior capture's CPU 3 initial attempt 0→2 and CPU 1 attempt 317→319 remain unexplained individually. Aggregate unsupported=1 and disabled=1 cannot establish their per-CPU attribution. Missing initial per-CPU snapshots and clock calibration were confirmed instrumentation limitations; a particular CPU's inactivity, packet loss or clock defect was not established.

The existing authenticated 192-byte data envelope now supports separate CPU-window and clock-sample records (kinds 7 and 8). The packet ABI remains 80 bytes and the TCX object is unchanged. These records pass the existing peer credentials, approval, application, program identity and sequence checks. They do not consume the packet Queue32 or become Network14 packets.

The loader queries its owned counter map before attachment and after detachment. Each phase preserves all seven uint64 counters for every possible CPU and the actual CLOCK_MONOTONIC lookup brackets. Possible CPUs above 128 fail explicitly, rather than truncating coverage; at most 256 CPU rows and six clock rows are retained. Existing journal bounds and send/backpressure limits remain unchanged. Rows are journaled before socket transmission. Missing, duplicate, reordered, out-of-range or incomplete records cannot prove a window. Final aggregate retrieval remains independent of snapshot or drain failure.

A zero-counter CPU with both boundary snapshots means NO_OWNED_HOOK_ATTEMPTS, not that the CPU was offline or globally inactive. An absent CPU snapshot means missing coverage. Event first/last times are never invented for an inactive CPU. Per-CPU emitted/delivered populations, aggregate totals, event containment, counter epoch, processing completion, final drain and CLOSED are reconciled separately.

The broker additionally reads only `/proc/self/timens_offsets` and rejects a nonzero/unreadable monotonic offset. An initial implementation compared `/proc/1/ns/time`; an ordinary-UID C test exposed the ptrace access restriction, so that dependency was removed without acquiring additional privileges. The existing `soc_now` implementation is in `os.c`; link detach is in `tcx.c`. Earlier `common.c` and `tcx_link.c` lookups referenced nonexistent filenames, not compiler failures.

Three real realtime/monotonic bracket samples are taken at each boundary, bound to the generation. The existing 1ms maximum individual calibration bracket is preserved. Disjoint offset intervals, epoch changes, non-monotonic samples, or samples not enclosing the events prevent verification. Kernel event timestamps are not rewritten or converted to UTC. The kernel helper's documented monotonic domain is recorded in the [libbpf helper definition](https://github.com/libbpf/libbpf/blob/master/src/bpf_helper_defs.h). These brackets do not establish independent external UTC accuracy.

**Verification scope is explicit:** an owned-hook, supported-metadata observation window. System-wide/pre-hook drops remain UNKNOWN, even when this scoped window verifies. Unsupported input, ring reservation failure, malformed input, budget truncation, missing clock/boundary evidence, receive mismatch, or processing failure prevents a verified complete delivered window. This does not silently promote a partial packet-limit capture to a complete one.

Native status: INSTRUMENTED, not yet VERIFIED. The historical observations are unchanged.

## P03 Flow Completeness

Lifecycle evidence now retains the actual transport protocol, forward/backward packet and IP byte counts, first/last event times, timeout witness, FIN/RST observations and original collector stop reason. The gap-induced INCOMPLETE classification is preserved; its original CAPTURE_STOP/PACKET_LIMIT cause is no longer lost. No Network14 formula was changed.

The input receipt binds the observed flow interval and timeout witness to the capture window digest, application/generation, plan, program and approval provenance. The existing 30s idle and 120s active event-time timeout authorities remain unchanged. STOP, packet limit, FIN/RST observation alone, a missing witness, duplicate export, or an incomplete capture window cannot become COMPLETE. A complete Network14 timeout window is not a claim of a complete TCP connection or final ACK handshake. The packet ABI does not provide TCP sequence/acknowledgement evidence, and none was invented.

Synthetic timeout fixtures verify this connection; real FIN/RST and historical Batch 1 receipts remain evidence of observations only. An observed bidirectional FIN does not repair the historical capture window. Native status: INSTRUMENTED; actual complete windows still require a new approved execution.

## P04 Network14 Eligibility

Supervisor exposes `network14_input_receipts` separately from the existing Native AI policy RCA. The ordered 14-column schema is taken from the existing packet producer contract and bound by an ordered-name digest inside the approved runtime module. A regression assertion compares that pinned digest with the digest-validated packaged research catalogue; snapshots perform no mutable catalogue lookup or model-file access. Finite exact float32 values, nonnegative/count units, duration/count consistency, vector fingerprint, flow identity, source provenance, window digest and observed timeout witness are required. No values or timestamps are imputed. Definite malformed/invalid evidence is INVALID, missing raw vectors UNKNOWN, and insufficient window/flow evidence INCOMPLETE. Duplicate exports are INVALID.

A synthetic fixture obtains ELIGIBLE for **input evidence only**; its source stays FIXTURE_NOT_NATIVE, model_executed=false, model_artifact_validation=NOT_PERFORMED, and Native AI/DNS9 remain BLOCKED. No model is loaded or run. The legacy policy RCA preserves golden-parity/model-artifact unknowns and never grants inference permission. It no longer reports an input capture as unverified when that same capture assessment is verified.

Raw vectors remain bounded to the existing checkpoint tail; retained historical RCA receipts are not treated as revalidated raw vectors. No historical candidate status changes. Native eligible candidates newly demonstrated by this work: NOT_RUN, not zero-packet Native success.

## Code Changes

- `ebpf_tc/loader.c`, `data.h`, `data.c`: bounded, journal-first CPU/clock evidence, using the existing owned map and socket.
- `ebpf_tc/data_plane.py`, `journal.py`, `window_evidence.py`, `capture_evidence.py`: strict decoding, persistence, coverage and epoch reconciliation.
- `collectors/packet_producer.py`, `ebpf/collector.py`: preserve lifecycle evidence without changing feature arithmetic or completion policy.
- `ebpf/input_eligibility.py`, `ebpf/eligibility.py`, `ebpf_tc/supervisor.py`: input receipts independent of inference authorization.
- `native-stabilization-batch2-source-amendment.json`: append-only successor to the historical source certificates; boundary assertions retain the full chain.

## Regression Tests / Independent Export

The final verification record is stored under `.git/native-stabilization-batch2/` in the original repository. Synthetic/unit, ordinary-UID compiled-C/socket, and Native evidence are kept distinct.

- Final independent Export: **263 PASS**, 28.51s, on the final frozen source.
- **Final Workspace/unit/contract + integration: 343 PASS**, 403.62s (328 related unit/contract tests + 15 ordinary-UID C/socket integration tests). This includes the new complete authenticated wire → window → flow → input receipt test and pinned-schema assertion. Earlier 322/341-pass runs remain intermediate evidence only.
- The first C snapshot test failure reproduced the inaccessible `/proc/1/ns/time` check; the corrected self-offset version passed.
- An exploratory integration run was interrupted after failures while the source was evolving. Its incomplete log is retained; its first failure is not reclassified as confirmed flaky or Native failure. A clean diagnostic rerun passed 15/15. All 15 were subsequently rerun as part of the final 343-pass selection.
- Whole-repository Ruff: PASS. Format: 1,368 files PASS. Diff check: PASS.
- Historical full Export regression failures (Operator Timeout and legacy Zeek READY) remain unresolved; no full production qualification is claimed and the thousands-test suite was not repeated.

Queue32, admission50ms, reorder10ms and checkpoint16KiB are unchanged. Counter reconciliation, queue/error drain, CLOSED preservation, timeout/FIN/RST, checkpoint restoration and size boundaries, DNS, Supervisor shutdown, source mutation, SHA and approval/budget tests are included in the related regression selection.

## Source / Artifact Integrity

Final candidate is **0.6.3 Batch 2, distinct artifact identity**, not the installed Batch 1 image. Build A and Build B use the same frozen export and fixed deployment path. All 26 artifact paths and SHA256 values match. Source start/end inventory: 1,711 files, unchanged.

| Identity | SHA256 |
|---|---|
| Source snapshot / Workspace / Export / Stage input inventory | `c480864b769ab94adeec539404e16eafec98dc77a726c36f8053481b95ac9587` |
| Manifest | `67f7714abedc03a87157e0cad024ac0058f96ffd567d21d22edb04f4921871fa` |
| Runtime Bundle | `b3f1211ea0422398fb49ea75edb880ecbd59bfa40d49eb7defb5226b599a389d` |
| Execution Image | `da4556bebe778cde648bb1cd9420f19bcb7e12f19b93a9d72b8377181c0554c7` |
| Root Manifest | `f5b54fbbac173e05ab6bfc246612d409d1dc966a9fcab5635daadea8c1117ab3` |

Build times: 29.16s / 28.04s, not Native performance measurements. Final artifacts are under `.git/native-stabilization-batch2/release-v4/`. Earlier `release-v1`/`v2`/`v3` artifacts are retained as SUPERSEDED_NOT_FOR_APPROVAL after the final guards, schema binding and Ruff import-blank-line correction. The last correction is also AST-equivalent; nevertheless the Export tests and both builds were rerun and their earlier SHA values were not reused.

The two result documents (this report and the Phase D integration report) are excluded from the input inventory to avoid a self-referential release hash. They do not enter the executable runtime bundle. Inventory membership as well as each file's SHA is compared. Build-time SourceGuard watches the exported runtime source; the workspace/export and index bytes are rechecked before committing. This detects accidental mutation, not an adversarial filesystem lock.

Protected user8 + historical104 hashes (112), original Native49 files, historical campaign/Ledger/Audit, and installed9 hashes/owner/mode are unchanged. Current installed Root Manifest remains `a1214d2c58bd21ca7a156e4f5c136dbbb63d796b649d26e2400cce89ebe00297`. No foreign cgroup program was queried or removed in this work.

## Git Commit / Push

Implementation commit: `ef32cabe99d9adf041be60dbc476dc693f8e022d`; implementation tree: `0003ed849ed42105ee98e90d6996d2b413ab757f`. The 18 explicitly selected source/test/report files were committed and pushed to `origin/fix/native-stabilization-batch2`; main was not modified. The following report-only metadata commit does not change frozen inputs or artifacts. The exact final approval commit/tree is recorded in the machine-readable request after this report is committed. Source and Artifact identities were revalidated after commit.

## Campaign Budget / Native Approval Request

Authoritative registered campaign: `SOC_NATIVE_STABILIZATION`, execution contract in `.git/native-stabilization-batch1/execution-v1/`. Its immutable starting budget file is combined with append-only reservations/review; its zero initial counters are not the current consumption.

- Campaign Native **1/10 used**, Root **1/10 used**.
- Batch 1 Native/Root **1/2 used** each.
- Batch 2 Native/Root **0/2 used** each, as already defined by the registered per-batch contract.
- No reservation or execution consumed in this task.

Requested after explicit exact-SHA approval and a new valid Approval Receipt: **Root installation 1 + Unified Supervisor diagnostic E2E 1**, batch BATCH2, with no automatic retry. Preserve the installed a1214d2c… release and its rollback materials. Install only the existing Root Manifest's nine files under `/usr/libexec/soc-agent-ebpf`: bootstrap, broker, entry, libnative-tc.so, manifest.bin, pam-policy.conf, tc.bpf.o, release.json, release.trust. Use the existing TTY authentication and registered campaign adapter; the user enters any sudo password directly in their terminal. No password handling by this agent.

Scope: `net:[4026531833]`, `lo/Ingress`, at most300s, 4,096 metadata events, Queue32, 256MiB address space and20s CPU per privileged task. Zeek retains512MiB/CPU1. DNS sidecar retains its10s total/7s capture/32packets/512byte/Queue32 profile, same namespace/lo, endpoint127.0.0.53:53, QNAME`native-0516.localhost.`, A, one UDP and one TCP local query. No external DNS or network/offload configuration changes.

Expected evidence: both CPU boundary sets, generation-bound clock brackets, per-CPU/aggregate accounting and excluded populations, per-flow actual timeout witness, vector/schema/provenance receipt, Counter/CLOSED, checkpoint/audit drain, owned FD/map/link and container cleanup and read-only cgroup ownership comparison. Stop on first failure, preserve subsequent cleanup errors independently, and do not automatically reinstall/retry or remove unowned programs. A new SHA requires a new receipt.

Exact final Git commit/tree and the machine-readable approval request are recorded after selective commit in `.git/native-stabilization-batch2/approval-request.json`. Creating that request does not grant approval. The current task does not execute it.

## Remaining Blockers

P02/P03/P04 require new actual Native evidence; the synthetic pass is not a substitute. Packet-limit exclusions, unsupported input, absent/invalid clock samples, short captures without a real timeout, and STOP-only flows can still make every new candidate INCOMPLETE or INVALID. This release does not promise an eligible candidate regardless of input. In particular the bounded timeout authority needs an actual30s/120s event-time window, not an arbitrary stop time. Partial-prefix eligibility, full TCP handshake completion and external clock accuracy are not invented by this implementation.

Historical194ms inversion RCA, historical12-event attribution and historical foreign cgroup ownership remain UNKNOWN. Existing Native AI, DNS9 and production gates remain BLOCKED. The next required action is approval of the exact final SHA and one bounded BATCH2 attempt, followed by independent evidence review of Capture, Flow and input eligibility.


## Batch 2 approved Native execution — final evidence review (2026-10-23)

**Actual Native outcome: FAILED (Supervisor exit1); collection/owned cleanup partially verified.** This section supersedes the earlier preflight readiness and budget statements, without rewriting the actual failed run or historical candidates. No new Native execution, authentication, installation or capture was performed during post-run remediation.

### Approval, installation and immutable evidence

Executed Git `ca5b7cb43a2c87d6402c30590549ee958720c34d`, tree `094949f572148388092e4bc0e53a805e1c6c9672`, branch `fix/native-stabilization-batch2`.

- Manifest `67f7714abedc03a87157e0cad024ac0058f96ffd567d21d22edb04f4921871fa`
- Bundle `b3f1211ea0422398fb49ea75edb880ecbd59bfa40d49eb7defb5226b599a389d`
- Image `da4556bebe778cde648bb1cd9420f19bcb7e12f19b93a9d72b8377181c0554c7`
- Root Manifest `f5b54fbbac173e05ab6bfc246612d409d1dc966a9fcab5635daadea8c1117ab3`

All26 approved build artifacts and source1711 were checked before launch. Existing TTY scope confirmation and user-entered sudo authentication were used; the password was not collected by this agent. Session `75e98238-99ab-40d8-862c-5f1b93cb03f7`. Approval Receipt SHA `4afcf5e2099760f9d0aea93bed1e4b3ba895ef1a0c4abcf799e2ed6e9ae1b752`. Actual attempt `0648d6b41f204377854e58fb76c3aa36`.

Private evidence: `.git/native-stabilization-batch2/live-attempt-1/` contains preflight, terminal-exit,49-file Native evidence hash index, resource-diff, copy-only recovery proof and evidence review. Executed artifacts/result remain in `release-v4/build-A`. Original49 evidence hashes, protected104 historical records +8 user files, and previous installation/rollback bytes/ownership/mode were checked unchanged. The approved9 installed files match their Root Manifest SHA, root ownership and prescribed modes. The campaign ledger preserves the exact prior byte prefix and appends approval/reservation/finish/review only. Historical Phase D5/5 records remain unchanged.

### P01 counter continuity / Packet Admission

`observed4119 = emitted4113 + unsupported1 + disabled5`; ring reservation failures, malformed and kernel budget counts0. `callbacks4113 = delivered4096 + post-limit excluded17 + invalid0 + send_failed0`. Applied4096/received4096; queue rejection, timeout and policy discard0. These populations are explicitly distinct. Historic12-event attribution remains UNKNOWN.

Queue capacity32, peak31, final depth0;7 waits,7 resumed; maximum admission wait8.302ms, below50ms. Maximum processing7.608ms; maximum queue wait12.247ms. Receive-gap maximum905.988ms also includes quiet/control intervals and is not proof of processing stall. Ring, processing and audit drain VERIFIED. No queue, clock reorder or checkpoint limits changed.

### P02 Capture Integrity — INCOMPLETE

PRE_ATTACH and POST_DETACH snapshots cover all4 possible CPUs (8rows). Six authenticated generation-bound clock brackets establish same-host monotonic offset interval `[1792658424081458610,1792658424081458668]`ns; this is not external UTC accuracy. Generation `15224515642550003925`. Window bounds `84654434483997..84667481958499`ns.

Clock evidence VERIFIED; maximum inversion606,487ns,19 bounded reordered events,0 late events, below unchanged10ms. CPU emitted `[1130,828,1159,996]` and delivered `[1128,821,1155,992]` differ by17 in total, consistent with the known excluded population. Exact per-CPU excluded packet identities were not retained. CPU3 has2 unrepresented attempts (0→2 and784→786); exact attribution remains UNKNOWN. Unsupported1 plus truncated delivered window prevent full integrity, independently of successful clock validation. Kernel-wide drops remain UNKNOWN, owned ring reserve failures0.

**Confirmed diagnostic defect:** capture and candidate RCA previously labelled baseline/clock missing whenever any other window gate failed. Corrected diagnostics preserve independently observed zero baseline and VERIFIED clock while retaining overall INCOMPLETE, truncation, unsupported and unresolved-gap reasons. No integrity gate was removed.

### P03 Flow Completeness — INCOMPLETE; P04 Native eligible0/7

| Candidate prefix | Packets | Transport / termination evidence | Finalization | Actual candidate |
|---|---:|---|---|---|
| 1 `2c2e85eafb69` | 1022 | tcp / NOT_OBSERVED | INCOMPLETE | INCOMPLETE |
| 2 `bc15badf915c` | 965 | tcp / NOT_OBSERVED | INCOMPLETE | INCOMPLETE |
| 3 `95747c265140` | 1043 | tcp / NOT_OBSERVED | INCOMPLETE | INCOMPLETE |
| 4 `7458bea030fc` | 1050 | tcp / NOT_OBSERVED | INCOMPLETE | INCOMPLETE |
| 5 `e6926a906935` | 2 | udp / NOT_OBSERVED | INCOMPLETE | INCOMPLETE |
| 6 `772fcbd9028f` | 10 | tcp / BOTH_FIN_OBSERVED | INCOMPLETE | INCOMPLETE |
| 7 `10688c1c6896` | 4 | udp / NOT_OBSERVED | INCOMPLETE | INCOMPLETE |

Counts sum4096. All7 are bidirectional; TCP candidate6 has BOTH_FIN. FIN is termination evidence, not proof of a complete capture/model window. Each flow retains source stop PACKET_LIMIT, no observed timeout witness; neither30s idle nor120s active timeout is established in the roughly13s window. Actual candidate evidence remains INCOMPLETE for all7; no historical candidate was promoted. Feature schema/float32/fingerprints passed, independently of capture/flow completeness. Model inference was not executed.

**Confirmed receipt omission:** `input_receipts` iterated the raw4-vector tail despite retained RCA for all7. It now retains one input receipt for every candidate. Raw vectors remain bounded to4, no values/digests are invented. Offline corrected replay yields3 UNKNOWN (raw vector not retained) +4 INCOMPLETE,0 eligible. These derived input states do not rewrite the seven original Native RCA states. Original result SHA `e845b1493de6256fc868783932f5d41b6b2580842577e537b9bb79c323fa16b8` remains intact. Checkpoint16KiB fail-closed behavior and existing overflow tests remain required.

### DNS Sidecar — actual local analysis verified, timing caveat retained

One approved UDP query and one TCP query to127.0.0.53:53 each received a matching RCODE0 response; Zeek produced2 completed transactions (UDP1/TCP1), response_records2. Completed transaction logs alone do not independently count query/response packets or establish duplicate/retransmission identity. Capture accepted12/rejected0/socket drops0; Raw-IP12 UNSUPPORTED remain excluded from Network14. Stream invalid/duplicate/sequence-gap0, Counter and CLOSED received; container absence VERIFIED.

Monotonic phases: authenticated84654.979821168; process launched84655.187259546; script init84658.134028838; READY84658.177449155; capture84658.178347034..84663.744364624 (5.566s); input closed84663.831383492; Counter84663.984706087; CLOSED84663.984898018; analysis/cleanup84664.632327729; cleanup complete84664.737970349. Total authenticated active9.765661s <10s. Terminal elapsed includes human confirmation/password wait and is not active capture duration.

`zeek_exit.analysis_deadline_expired=true` was recomputed after cleanup, while the actual validation deadline guard passed earlier and no deadline exception was raised. CLOSED preceded the internal analysis deadline. The precise guard timestamp was not retained: UNKNOWN. This diagnostic ambiguity remains explicit; no timeout extension, fabricated timestamp or errno classification is used, and existing DNS timing implementation is unchanged in this narrow remediation.

### Checkpoint / Audit / Recovery

Actual UTF-8 checkpoint14,818B <=16,384B;7 retained candidate receipts,4 raw vectors. Digest `1835aadb2e75ea0bec5650cd5070af25a1f190c058f65c995f4d67c77164384f`. Audit23 records hash-chain verified; final digest `2aa1fa7fc25f20dacc4b7fa503fd40563b33eb6b421953fdaa8c36eec6b8bf52`. SQLite copied and recovered `RESTORED_NO_REATTACH`, no authentication/reattach; original database SHA unchanged. Generation above2^63 round-trips as original uint64. Journal33 records and FD evidence reviewed. Audit writer submitted19/committed19, outstanding0, no failure.

### Supervisor / cgroup / Cleanup — independent decisions

First failed guard: final resource inventory equality, symbolic `SUPERVISOR_RESOURCE_SET_CHANGED:programs` and `:cgroup_tree`; wrapper `SUPERVISOR_CLEANUP_UNVERIFIED`, no observed syscall errno or signal. Before12 programs/7 cgroup targets; after11/6. Only removed pre-existing Program1145 `sd_devices`, tag`4b13b8318fb7df93`, cgroup_device target `/sys/fs/cgroup/system.slice/wsl-pro.service`, loaded before this Session. No added Program. Attach-target attribution is observed; exact creator process and precise external removal mechanism remain UNKNOWN. No external service/program was stopped, detached or removed by remediation.

Owned TCX cleanup VERIFIED:3 map FDs +1 program FD verified EBADF, maps/links/ingress/egress filters0→0, drain complete and workers stopped; DNS container absent. Raw close returnvalues were not observed. **Global Cleanup remains UNVERIFIED and Native exit remains1.** External attribution does not bypass the strict resource equality guard; any future owned-resource-specific acceptance policy requires a separate reviewed contract. No guard/controller/Root cleanup policy was changed.

**Confirmed propagation defect:** `close()` recorded final cleanup failure in its snapshot without raising; startup wrote top-level `first_failure=null, errors=[]`. The new final-result composer records returned failure as a symbolic FINAL_NATIVE_STATE error if no earlier primary exists, preserves any earlier primary and independently retains cleanup errors. It neither manufactures errno nor changes CLI failure/cleanup state.

### Post-run scope / budget / decisions

Only deterministic Python diagnostics/receipt composition and focused tests changed. No C/BPF, Root install, authentication, capture, traffic, approval enforcement, campaign controller or resource guard was modified or executed again.

Campaign Native2/10, Root2/10; Batch2 Native1/2, Root1/2 (Batch1 remains1/2 each). Reservations, actual install/run and FAILED finish are recorded; evidence review is appended with `safe_for_next_attempt=false` pending the existing approval/safety contract. No automatic reservation/retry was made.

P02 INCOMPLETE; P03 INCOMPLETE; P04 INCOMPLETE (Native eligible0). Owned collection and teardown are verified independently; Unified overall FAILED due global cleanup mismatch. Native AI, DNS9, production promotion BLOCKED. Changed artifacts are UNAPPROVED and cannot reuse the executed receipt. The remaining diagnostic timing ambiguity, per-CPU excluded identities, timeout/window evidence and global ownership acceptance remain explicit next-work requirements.


### Post-run nonprivileged qualification — changed identity, not approved

Focused window/termination reproduction46 PASS (125.68s); related Workspace325 PASS (39.68s); independent frozen Export277 PASS (153.33s). These sets overlap and are not summed as distinct tests. The Export includes checkpoint overflow/recovery, provenance, queue/clock/counter, campaign/approval and supervisor first-error tests. Full historical Workspace/Export qualification was not repeated; the earlier Operator Timeout and legacy Zeek READY full-suite failures remain unresolved for production. Ruff PASS; format1368 files PASS; diff PASS.

Frozen source1711 start/end hashes match, Workspace/Export snapshot `8bdedfc6c3f9853ba3b0caa0c7b5c6753e2d2811939890dad5fbe64f8bf66cdc`. Two independent nonprivileged builds produced the same26 files and SHA map (31.602s and32.317s); no Native or Root execution during qualification. Stage equality is rechecked before commit. Build location `.git/native-stabilization-batch2/release-v5-postnative/`; executed v4 artifacts are preserved separately.

Changed candidate identities (not covered by the executed approval):

- Manifest `38375eea0f2b120bbdf1722c42959aca477be7c1a115e96d08b464b63adebf16`
- Bundle `c566375a8f12168cb7ae207970c1854cedb304e542a22c33d8506229797f5b54`
- Execution Image `1677d1b23dba9ce7fe8c3d7d20c08b41d2ef2ce24f842b157bca7bf51910a4f9`
- Root Manifest `58f9db57c65082edb5a7c00c26957a32d7c9a0b64d2a07020ad780939196dbc3`

No new approval receipt, budget reservation or Native launch is created. Before any next attempt, the registered controller requires a safe evidence review of the prior global cleanup mismatch and a new explicit exact-SHA approval/receipt; current review leaves safe_for_next_attempt=false. Owned-only acceptance must not be substituted for the existing strict global guard without separate authorization. Remaining Campaign8 Native/8 Root, Batch2 1 Native/1 Root are budget headroom, not execution permission.


Final ordinary-UID C/socket integration:15 PASS in278.36s. No kernel attach, container launch or DNS traffic in these tests. Final stage blobs match all1711 frozen source inputs (reports excluded by the declared source inventory rule); Workspace/Export/Stage SHA is the same8bdedfc6… snapshot. The preservation checker validates ledger record hashes over the exact newline-terminated JSONL bytes, as the campaign controller does; an initial ad-hoc check omitted those newlines and was corrected without changing any ledger bytes.

Post-run implementation/report Git operation is limited to these9 files on `fix/native-stabilization-batch2`, with no shared main update or force push. Final full commit/tree and remote equality are recorded after commit in private `postnative-release.json`; the executed ca5b7cb identity remains the Native evidence reference. Post-run qualification is nonprivileged only and does not change the actual FAILED / INCOMPLETE decisions above.


# SOC Native Stabilization Batch 2 — Final Native Qualification Preparation

## Overall Status

**BLOCKED_FOR_NATIVE_APPROVAL_AND_SAFE_REVIEW; nonprivileged preparation complete.** This task does not authorize a new install, authentication, attachment, capture or traffic. No new run was attempted or reserved. Actual prior Native result remains FAILED; this preparation is not a Native pass. The d56f45e runtime code is unchanged, with no new implementation defect confirmed requiring another patch.

## P02 Capture Integrity

All four possible CPUs have pre-attach/post-detach boundaries (eight records), with six generation-bound clock samples. Same-host clock brackets are VERIFIED; external UTC calibration remains UNKNOWN. Epoch15224515642550003925, KERNEL_MONOTONIC_NS. Corrected baseline/clock reason codes were verified without changing any integrity gate.

Original window identity `d5c0c2162901067afe1a906c96e9d15e844ab12746c8f20648d4ff859086febf`. All seven candidates bind this Session/window. Per-CPU emitted/delivered deficits sum17, matching the known post-limit exclusion total, but excluded packet CPU/attempt identities are not retained. Two CPU3 attempt gaps remain unattributed; they are not proof that CPUs were not observed. Unsupported1 and delivered-prefix truncation prevent full-window proof. Owned ring reservation failures0; system-wide loss UNKNOWN. Decision: INCOMPLETE, not a clock-calibration failure.

Next run must retain both CPU boundary sets, six paired clock samples, same generation, all branch populations, delivery counters and exclusions, event intervals, Counter/CLOSED/drain and window digest. Missing or nonzero/truncated evidence must still fail the existing gate. No zero-traffic timestamps or guessed offset may substitute for records.

## P03 Flow Completeness / P04 Network14

| Full candidate identity | Protocol | TCP termination evidence | Raw vector retained | Historical candidate state |
|---|---|---|---|---|
| 1 `2c2e85eafb6943d1006b79a00a45deb530e1961b0699254b7739a25f7f4c19d3` | tcp | NOT_OBSERVED | no | INCOMPLETE |
| 2 `bc15badf915c84f6b89de24b9d1d618764ed38ea32e4183a73bfe85e00043e30` | tcp | NOT_OBSERVED | no | INCOMPLETE |
| 3 `95747c2651407f52d0413f21680e75d959c4853273fa1fd33c09149c049d19b4` | tcp | NOT_OBSERVED | no | INCOMPLETE |
| 4 `7458bea030fcd93bc0f78ecb54f82a927c4c1ef4298c727b7365a262c00b6f88` | tcp | NOT_OBSERVED | yes | INCOMPLETE |
| 5 `e6926a9069358ccf6ed4eba71d19ef8fb338069dde59eb39edf1a010ec47e117` | udp | NOT_OBSERVED | yes | INCOMPLETE |
| 6 `772fcbd9028f18eceedf1c0a6d261ba02f37d78660305c7c41c75d007b94e131` | tcp | BOTH_FIN_OBSERVED | yes | INCOMPLETE |
| 7 `10688c1c68967d0a8e2ba37ba617a6fc3fe6928b02114bc7e8544f02fd1cd84f` | udp | NOT_OBSERVED | yes | INCOMPLETE |

All seven flows are bidirectional (none is disqualified as unidirectional). Candidate6 has BOTH_FIN_OBSERVED; the others have no TCP termination proof or are UDP. All seven retain PACKET_LIMIT source finalization, no timeout witness and no complete capture window. Feature validation/fingerprints passed when captured; no feature calculation defect was identified. Source provenance and retained RCA receipts exist for all seven. Three raw vectors are absent, so independent raw-value revalidation is UNKNOWN for those; this does not rewrite their historical INCOMPLETE states. The d56f45e input-receipt correction preserves all seven with missing vectors explicitly UNKNOWN, rather than silently omitting them.

**Native candidates7; ELIGIBLE0; historical INCOMPLETE7; no confirmed INVALID feature.** P03 INCOMPLETE, P04 INCOMPLETE. Full per-candidate Session/generation/window/clock/flow/provenance/schema/fingerprint/reason metadata is stored separately in private `final-qualification-preparation-1/candidate-rca.json`; original Native output is untouched.

The current model-window contract requires an observed event-time30s IDLE_TIMEOUT or120s ACTIVE_TIMEOUT witness. FIN/RST alone and STOP do not satisfy it. Prior capture occupied approximately13s before the4096 limit: it could not supply a30s idle witness. Arrival timing is not replaceable by waiting on a wall clock. Idle completion may be witnessed by a later actual event on another flow, as already tested by the synthetic pipeline. Synthetic ELIGIBLE remains FIXTURE_NOT_NATIVE with model_executed=false.

### Minimal TCP diagnostic scenario, within existing traffic approval scope

Reuse the **existing one TCP DNS query** to127.0.0.53:53 (`native-0516.localhost.`, A) as the single local TCP bidirectional exchange/FIN scenario; the prior run already observed both FIN directions. Keep the existing one UDP DNS query. No additional listener, TCP client, UDP witness, DNS query or external traffic is proposed for automatic execution with this artifact. Zeek retains its10s deadline; TCX may independently continue up to300s.

To prove timeout without new traffic, TCX must observe a later natural packet at least30s after that flow's last event, before the4096 metadata limit, with all integrity gates satisfied. If no natural witness arrives, no flow is eligible on that basis. Even a witnessed timeout needs its raw vector retained in the bounded four-vector evidence set; no extra raw vectors or receipt truncation bypass is proposed. An early timeout vector can still be displaced by later exports, so an eligible candidate cannot be promised.

Read-only aggregate `/sys/class/net/lo/statistics` observation, not packet capture:1380 packets over5.002386506s, approximately275.87 packets/s; rx_dropped/rx_errors did not increase during those two aggregate samples. This is not a TCX supported-event rate or capture-loss proof. It corroborates the risk of reaching4096 before the required30s window; no future rate is guaranteed. The operator should not consume the last Batch2 attempt expecting a guaranteed eligible candidate under sustained background traffic. No unrelated application/service was stopped or reconfigured. Narrowed filtering, an isolated namespace or an extra timed local witness would change the scope/artifact/tooling and require separate preparation and approval; none was implemented or silently authorized.

## Cleanup

Owned TCX FD/map/link/filter cleanup and DNS container absence are independently VERIFIED for the prior run. Global equality failed because pre-existing wsl-pro.service cgroup_device Program1145/tag4b13b8318fb7df93 was removed; no added Program was observed. The attach target is known, exact external removal mechanism UNKNOWN. It is not a newly leaked SOC-owned Program, and it is not grounds to override the strict global guard. Global Cleanup UNVERIFIED and prior exit1 remain unchanged.

The registered execution controller currently rejects a new reservation because the prior evidence review has safe_for_next_attempt=false. This is an additional real blocker beyond missing exact-SHA approval. Controller/Root guard/Receipt enforcement were not modified. A reviewed, append-only safe-to-attempt decision must be completed before reservation; that decision must distinguish permission to attempt again from changing the prior failed outcome. If an operator wishes to accept the identified external removal for *future admission only*, that must be explicitly reviewed, while fresh authenticated kernel/hook/FD/cgroup preflight and the existing strict post-run equality guard remain required. No record was changed to true by this task. An owned-only cleanup acceptance policy would be a separate policy change, not part of the request below.

## Native E2E evidence retained

Prior TCX4096/4096, DNS UDP1/TCP1 matched transaction, Counter/CLOSED, Checkpoint14818B, Audit hash-chain and copy-only recovery verified. Actual Supervisor exit1 with global cleanup mismatch; the old top-level first_failure omission is retained in raw evidence and reproduced/corrected offline. The DNS exit diagnostic recomputes analysis_deadline_expired after cleanup; exact earlier guard instant remains UNKNOWN although no deadline exception was raised and authenticated total9.765661s met10s. That measurement caveat is not recast as errno or silently resolved.

## RCA / Fixes / Regression Tests

No functional source change in this preparation: d56f45e already fixes returned cleanup failure propagation, independent clock/baseline diagnostics and all-candidate input receipts. The exact runtime source was rechecked against its frozen Export.

Fresh related Workspace325 PASS (24.90s); fresh frozen Export core117 PASS (4.05s), including Window/Clock, flow, checkpoint, campaign-budget and Zeek finalization contracts. These overlap prior tests and are not summed as distinct coverage. Unchanged-source qualification retains focused46 PASS, broader Export277 PASS, ordinary-UID C/socket integration15 PASS, Ruff/format/diff PASS from the post-run verification. No synthetic/ordinary-UID test is a Native execution. Full historical regression failures (Operator timeout / legacy Zeek READY) remain explicitly unresolved for production.

## Source / Artifact SHA

Implementation Git `d56f45e5c85527866a186dd96a5f33d09176b406`, implementation tree `1e762a0bee01a243b75773bf0fd4c70413c84c90`. Final report-only commit/tree is recorded in the private approval request after commit. The two report documents are excluded by the already declared frozen-source inventory; no runtime source or build input was changed.

Workspace/Export/Stage source snapshot `8bdedfc6c3f9853ba3b0caa0c7b5c6753e2d2811939890dad5fbe64f8bf66cdc`,1711 files. Existing independent BuildA/BuildB26-file sets and every artifact SHA were rechecked against qualification; they remain identical. New compilation was unnecessary because inputs/toolchain/deployment identity and artifacts are unchanged; no earlier result is attributed to changed source.

## Exact-SHA approval request — NOT APPROVED / NOT EXECUTED

- Manifest `38375eea0f2b120bbdf1722c42959aca477be7c1a115e96d08b464b63adebf16`
- Bundle `c566375a8f12168cb7ae207970c1854cedb304e542a22c33d8506229797f5b54`
- Execution Image `1677d1b23dba9ce7fe8c3d7d20c08b41d2ef2ce24f842b157bca7bf51910a4f9`
- Root Manifest `58f9db57c65082edb5a7c00c26957a32d7c9a0b64d2a07020ad780939196dbc3`

Request existing9-file installation1 under `/usr/libexec/soc-agent-ebpf`: bootstrap, broker, entry, libnative-tc.so, manifest.bin, pam-policy.conf, tc.bpf.o, release.json, release.trust. Preserve currently installed Root Manifest f5b54fbbac173e05ab6bfc246612d409d1dc966a9fcab5635daadea8c1117ab3 and all existing rollback directories; expected new rollback path `/usr/libexec/.soc-agent-ebpf.rollback-f5b54fbbac173e05ab6bfc246612d409d1dc966a9fcab5635daadea8c1117ab3`. Use the existing SHA-bound installation image/CLI/TTY flow, not arbitrary Root commands. User enters any password directly into the OS terminal.

Request Unified Supervisor diagnostic Native1, net:[4026531833], lo/Ingress, <=300s/4096metadata/Queue32; each privileged task256MiB address space/20s CPU; Zeek same namespace/lo512MiB/CPU1. DNS <=10s total/7s capture/32packets/512B/Queue32, UDP1 and TCP1 to127.0.0.53:53, native-0516.localhost., A. Queue admission50ms, reorder10ms, checkpoint16384B unchanged. No added generic TCP/UDP traffic, extra DNS, offload/settings changes, foreign detach, external scans or AI inference.

Required before execution: explicit approval of these exact SHAs and final Git binding; prior-attempt safe-review prerequisite; new session/release/scope-bound Approval Receipt; fresh authenticated Inspector/hook/FD/cgroup preflight; source/artifact/installed/rollback checks. Do not generate a reservation or authenticate from this document. On failure preserve first/cleanup errors and stop; no reinstall/retry or SHA approval inheritance. Record actual P02/P03/P04 independently even if eligibility stays0.

## Campaign / Batch Budget / Evidence

Ledger-derived Campaign Native2/10, Root2/10; Batch2 Native1/2, Root1/2. At most one further Batch2 attempt/install remains, conditional on approval and review; no new cost incurred. Existing failed outcome and safe-review flag remain unchanged. Protected112 files (104 historical evidence +8 user changes), original Native49 hashes, historical ledgers and the current registered ledger prefix/hash chain are preserved. Private preparation proof and candidate RCA are new files; old execution artifacts were not rewritten.

## Remaining Blockers / Next Batch Readiness

Exact-SHA approval and safe review are pending. Under current background traffic, full-window/timeout/raw-vector evidence is not guaranteed by another identical run. P02/P03/P04 are not VERIFIED. If no qualified long observation window can be obtained in approved scope, request a separately bound capture/traffic design rather than weakening gates or consuming the last attempt blindly. Native AI, DNS9 and production promotion remain BLOCKED.

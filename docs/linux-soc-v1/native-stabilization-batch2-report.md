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


# Batch 2 — Safe reattempt review and capture observation budget

## Overall Status

**BLOCKED** for Native execution; the new duration diagnostic is **INSTRUMENTED**. No Root installation, authentication, attachment, capture or traffic was performed. No ledger flag was changed or reservation made. P02/P03/P04 retain their original Native INCOMPLETE states and Native eligible0/7. A longer valid Flow window is not manufactured by the new diagnostic.

## Why safe_for_next_attempt is false

The authoritative record is sequence8, DIAGNOSTIC_E2E_EVIDENCE_REVIEW_COMPLETED, attempt0648d6b41f204377854e58fb76c3aa36, record SHA16c4cf5d3b891a0dfa005e03fd7d3ac97f2108ed35473a3e27136a304f4b258f. It explicitly records current_session_cleanup_verified=true, global_cleanup_verified=false, overall_status=FAILED and safe_for_next_attempt=false. The last flag was an ordinary-UID evidence-review decision, not an Inspector-generated owned-resource leak counter. The previous review conservatively left admission blocked after global resource equality failed. There is no implemented automatic rule that converts an external resource removal into a positive safety review.

The controller's `_locked` contract requires every prior reservation to be finished and to have an append-only review with safe_for_next_attempt exactly true before another reservation; otherwise STABILIZATION_PREVIOUS_ATTEMPT_UNREVIEWED. This gating code and the stored record remain unchanged. A new Artifact approval alone does not remove that prerequisite. No true review event was appended and no old event was edited.

### Independent cleanup facts

- Owned TCX:3 map FDs +1 program FD observed closed by F_GETFD/EBADF after libbpf close; map/link/lo ingress/egress inventories0 after cleanup; ring/processing/audit drained, workers stopped. Raw close returnvalues were not observed.
- DNS: Counter/CLOSED, container absence and cleanup receipt verified.
- Global programs12→11/cgroup targets7→6: only the pre-existing cgroup_device Program1145, sd_devices, tag4b13b8318fb7df93, attach target `/sys/fs/cgroup/system.slice/wsl-pro.service` disappeared. No new Program remained. Session-owned TCX cleanup and this foreign attach target are distinct evidence domains.
- The exact external removal trigger/creator process was not observed and remains UNKNOWN. Foreign target attribution does not prove full global stability or authorize ignoring the mismatch. Global cleanup remains UNVERIFIED and original Native FAILED.

Private `window-safety-review-1/safety-review-draft.json` links the original review, FD/drain proof, foreign attach target and global diff. It is a read-only draft for the existing governed reassessment procedure, not a replacement decision. To clear admission, that procedure must review the owned cleanup receipts, Program ID/tag/attach-target identities, lack of newly added resources, residual uncertainty, and the new session's required authenticated preflight. If policy acceptance of external drift is needed, request that explicitly; do not alter the Root equality guard. Past snapshots cannot retroactively establish the exact missing external removal event.

## Capture limit / STOP / timeout findings

The delivered event cap is exactly4096. In loader.emit, reaching it sets packet_budget_reached; additional callbacks are counted as budget_excluded rather than admitted. At the next bounded Broker loop, packet_budget_reached or300s expiry invokes TCX cleanup and terminal data finalization. This is not a mechanism for keeping a complete sampled capture alive. The terminal drain/counter/CLOSED paths still run.

The metadata adapter drains accepted work, calls FlowAssembly.finish and closes the assembly. Its observed-event watermark cannot advance after STOP. A subsequent event is rejected; merely waiting30s after STOP creates neither an event nor an idle witness. Timeout is measured in **kernel event nanoseconds**, with generation-bound same-host clock evidence; it is not userspace receive time or wall-clock elapsed time. IDLE_TIMEOUT requires an actual later event at least30s after that flow's last observed packet; ACTIVE_TIMEOUT requires an actual event at least120s after its first. A later event on another flow may witness an idle timeout while capture is still active. FIN/RST remain transport evidence; there is no existing FIN-only Native input eligibility branch.

The full Capture Window and an individual Flow timeout window are related but not identical: the model Flow window/witness must lie inside the verified owned Capture Window; the Flow need not occupy its entirety. Neither a complete finalization/FIN nor a long global capture alone proves a qualified Flow. STOP-only candidates remain incomplete.

### Can a valid window fit within existing scope?

Yes **conditionally**, within300s, if the actual population stays below4096 long enough to retain an observed30s/120s witness, no integrity gate fails, and the candidate's raw vector/provenance receipt survives retention. The existing one TCP DNS query already supplies a local bidirectional TCP exchange/FIN and is reused; no extra TCP server or traffic is necessary for that fact. The existing UDP query remains one. DNS Sidecar's10s deadline is independent of a potentially longer TCX capture; DNS need not stay open30s to support TCX event-time processing.

There is no approved packet-generation/rate/sample/filter parameter in the full-scope Plan. Broker command-rate slots rate-limit control requests, not captured packet events. Slowing receive/poll increases buffer pressure and cannot be used as a capture completeness solution. Pausing capture, silently excluding packets, increasing4096 or shortening30s would change the evidence contract and is not implemented. Waiting after detachment is not an alternative. Before spending the last Batch2 attempt, the operator needs a sufficiently quiet existing lo observation interval; the previous aggregate275.87 packets/s sample is not a supported-TCX rate or a promise of future conditions.

If the current host cannot supply that condition, a narrower explicitly described capture population or separately bounded diagnostic traffic/witness would require separate scope/artifact/tooling approval. An attested end-of-window heartbeat as new idle authority would also require a reviewed evidence contract; the present post-detach timestamp is not automatically proof of uninterrupted capture until that instant. None of these extensions was implemented or approved here. Existing four-vector retention may still leave a correctly timed earlier flow without independently revalidatable raw values; no receipt/vector is invented to overcome this limitation.

## Minimal diagnostic improvement

`SupervisedSession.snapshot.capture_observation_budget` composes a pure observation-budget explanation from existing processing CPU intervals, generation and delivery accounting. It reports actual observed event span, whether4096 was reached, counter epoch agreement, existing clock domain and30s/120s event-time contract, and explicitly says post-STOP wall time does not complete a flow. It returns UNKNOWN for missing/invalid count/epoch/interval evidence. A sufficient duration is labelled DURATION_ONLY and never treated as capture, completion or AI eligibility proof.

The actual saved run replays to observed_event_span_ns=12873273541, event_limit_reached=true, same_counter_epoch=true, state=CAP_REACHED_BEFORE_MINIMUM_IDLE_SPAN. This is a new **offline derived diagnostic**, not a new Native result or original timestamp. Original result SHA e845b1493de6256fc868783932f5d41b6b2580842577e537b9bb79c323fa16b8 is unchanged. Private `window-safety-review-1/observation-budget-replay.json` retains this distinction.

Only window_evidence.py, supervisor.py and the existing window test file changed functionally. No C/BPF, Capture/Flow/eligibility gate, rate, queue, timeout, checkpoint, authentication or campaign controller policy changed. The new Snapshot field is outside the checkpoint summary; raw vector retention and16KiB failure handling remain intact. No new queue, thread, dependency, network operation or model inference was added.

## Nonprivileged verification

Fresh Workspace331 PASS (31.74s); independent frozen Export283 PASS (145.67s), including supervisor first-error preservation, checkpoint boundaries/recovery, flow/window/clock, campaign-budget and DNS finalization contracts. Window tests cover a4096-event13s stop,30s boundary,120s duration, missing/mismatched epoch, non-mutating diagnostic output and rejected post-STOP events despite both FINs; the existing synthetic complete-window/event-witness fixture remains eligible only as FIXTURE_NOT_NATIVE with no model execution. No prior Native candidate is promoted by fixtures.

Two fresh independent builds from frozen source1711 produced26 identical file SHA values. BuildA27.857s, BuildB28.019s. Source start/end unchanged; snapshot `846e871eb7bb3a2a0d5c4ee6f236787eff6fba622c8e92947c566fe664247e6c`. Workspace/Export and stage/index equality are checked before selective commit. Ruff/format/diff pass. Data-channel integration and final preservation results are recorded below when completed; no test is represented as Native success. Historical full-suite Operator Timeout/legacy READY failures remain unresolved production qualification items.

## New artifact and approval request

Release0.6.3_BATCH2_OBSERVATION_BUDGET_DIAGNOSTIC, branch fix/native-stabilization-batch2. The implementation/report commit and Git tree are recorded after selective commit in private `window-safety-review-1/approval-request.json`.

- Manifest `3761b57f58a8632f942af6c18abcee47f6b4e5beea6e0f1c882dff8afa9bee05`
- Bundle `119f189c061775b737391eb97e123ae2af7ee98a8a1139477e5e3d9079bb04ec`
- Execution Image `d5980ab96da947c9d6bd0657da2c9c52e9484d4e6b30a853af308fe7432d61f9`
- Root Manifest `da894f80a427cee4d2d5991f9c736acbbed31e89d689ff141ba8035919a181f6`

Requested operations, **not approved or executed**: existing SHA-bound installation1 of fixed9 files under `/usr/libexec/soc-agent-ebpf`, preserving currently installed f5b54fbbac173e05ab6bfc246612d409d1dc966a9fcab5635daadea8c1117ab3 and all rollback material; Unified Supervisor diagnostic1 after positive governed safety reassessment and new exact-SHA/Session/Release/Scope Approval Receipt. The current stored false review remains unchanged. User directly enters any OS password in the trusted TTY; no agent secret collection.

Unchanged scope: net:[4026531833], lo/Ingress, <=300s,4096 metadata, Queue32,256MiB address space/20s CPU per privileged task; Zeek512MiB/CPU1 same namespace/lo; DNS10s total/7s capture/32packets/512B, local127.0.0.53:53 native-0516.localhost. A UDP1/TCP1. Admission50ms, reorder10ms and checkpoint16384B unchanged. Fixed9: bootstrap, broker, entry, libnative-tc.so, manifest.bin, pam-policy.conf, tc.bpf.o, release.json, release.trust. Root files and modes are explicitly listed in the request. No extra traffic, interfaces, unknown-program removal or global cleanup policy exception is requested with this artifact.

Before any actual run, recheck source/artifacts/installed/rollback, budget, prior safe review and new receipt; authenticated Inspector must obtain new FD/kernel/cgroup/hook inventories before attach. Preserve first error separately from cleanup; stop on failure and never retry automatically. If scope, source or SHA changes, request a new approval. A fresh execution could still legitimately produce0 eligible candidates; the diagnostic exposes that condition, it does not remove it.

## Budget / final decisions

Campaign Native2/10, Root2/10; Batch2 Native1/2, Root1/2. No reservation, install or Native cost incurred by this task. Current Ledger bytes and false flag are preserved; historical failures and104 evidence records +8 user changes remain protected. P02 INCOMPLETE, P03 INCOMPLETE, P04 Native eligible0/7; owned cleanup VERIFIED independently, global cleanup UNVERIFIED. Final readiness is BLOCKED by safety review and execution approval, with duration feasibility conditional on actual in-scope traffic. Native AI, DNS9 and production promotion remain BLOCKED.


Final verification for this revision: ordinary-UID data-channel/Drain integration15 PASS (275.61s); Ruff PASS, format1368 PASS, diff PASS. Workspace331 and Export283 are the newly executed results above; overlapping test sets are not summed as independent tests. Source1711/stage equality, immutable old Native49/protected112/current ledger and installed/rollback checks are recorded in private `window-safety-review-1/final-preservation.json` and `window-safety-review-1/installed-rollback-check.json`. Only the two diagnostic source files, one existing test file and this report are selected for commit; main and user changes are excluded. Final Git commit/tree/remote equality and the new exact-SHA request are recorded after commit in `window-safety-review-1/approval-request.json`.


# Batch 2 — Operator decision package: reassessment and a bounded long-window scenario

## Result: BLOCKED; two concrete decisions, no new execution

This revision performs no test rerun, feature implementation, installation, authentication, capture or traffic generation. Runtime implementation remains17241f76510b9d1e60562eca9d1803bf6b2d20ba. It clarifies the missing review procedure and presents a scoped alternative to another identical short capture. P02/P03/P04 remain INCOMPLETE; Native AI/DNS9/production BLOCKED.

## 1. Safety reassessment: verified evidence and procedural gap

Owned cleanup and global stability are independent. The original Session's3map/1program FD release receipts, zero remaining maps/links/lo filters, drained workers/audit and absent DNS container support owned cleanup VERIFIED. The global diff instead removes pre-existing Program1145/tag4b13b8318fb7df93, cgroup_device target `/sys/fs/cgroup/system.slice/wsl-pro.service`; no added Program was observed. Exact external removal cause/creator remains UNKNOWN. The old global UNVERIFIED, exit1 and FAILED result stay unchanged.

**Correction to earlier wording:** the repository does not provide a completed formal reassessment service/CLI or a dedicated review-approval receipt validator. It provides a hash-chained, locked, fsynced append primitive and an execution gate consuming DIAGNOSTIC_E2E_EVIDENCE_REVIEW_COMPLETED. The tests synthesize such a record through the private `_locked` method; that is not evidence of an authorized operator review workflow. The gate checks for a matching positive review event, not an authenticated latest reviewer decision with evidence/Release binding. Existing exact-SHA execution receipt checks do not by themselves validate a safety-review decision.

The sequence8 false decision (record SHA16c4cf5d3b891a0dfa005e03fd7d3ac97f2108ed35473a3e27136a304f4b258f) was an explicit conservative ordinary-UID review after global equality failed. It was not an owned leak detector. Removing the gate or adding a bare private-API true event would bypass the requested governance. Neither was done.

### R1 — request approval of a formal reassessment/conditional-admission procedure

Private `decision-package-1/safety-reassessment-request.json` pins original attempt0648d6b41f204377854e58fb76c3aa36, negative review, original result/recovery/resource-diff/Ledger hashes and the exact residual risk. Proposed procedure, for human review before any implementation or recording:

1. Operator reviews owned FD/map/link/container proof separately from external Program ID/tag/attach target and unknown removal cause. Reject or defer if any owned resource/binding is uncertain or an added unknown resource remains.
2. A dedicated review receipt must bind reviewer identity, attempt, latest review record, evidence hashes, decision/risk scope and the next Release/execution contract. The only requested positive decision would authorize **future single-attempt admission**, never certify old global cleanup or Native success.
3. A reviewed validator/recording path must validate that receipt and current review history, preserve the false record, append a new traceable decision through the canonical writer, and reject stale/unbound/revoked decisions. Direct flag replacement or a private lambda setting true is not the authorized procedure.
4. Fresh exact-SHA execution approval/receipt, budget check and authenticated Inspector/kernel/hook/FD/cgroup preflight still precede attach. The strict final global equality guard remains unchanged and can legitimately fail the next run if foreign resources change again.

This is a **proposed governance change**, not a currently available tool or an automatically satisfied condition. AGENTS.md §15/§33 require human review of approval/authorization-rule changes. Request approval of this procedure/implementation and a human decision on the documented residual risk; do not infer either from the current analysis instruction. The existing immutable campaign budget/controller pins must be preserved under any versioned amendment; no silent controller hash update, budget rewrite or campaign reset is permitted. No positive review was recorded here.

## 2. Read-only workload finding: a practical source to quiet

Current socket diagnostics show4 established loopback connections (8 endpoint rows), all readable owners being UID1000 VS Code Remote Node processes under `.vscode-server/bin/.../node`. Two read-only TCP_INFO/sysfs samples over5.010s show1678 aggregate lo RX packets and roughly1672 summed client-side TCP in/out segment increments on those connections. These metrics have different units/read brackets, so this is not an exact TCX reconciliation or a99% attribution claim. It is direct evidence of substantial **current** VS Code loopback activity. Attribution of historical candidate IDs to these sockets remains UNKNOWN because endpoint evidence was not retained for that comparison.

Private `decision-package-1/current-loopback-owner-observation.json` records PID/executable/start-tick ownership and counter samples, without packet payloads, command-line secrets or process signals. No process/service was stopped. This gives a concrete operator preparation: save work and disconnect the operator's own VS Code Remote WSL windows, use an independent OS terminal for Native authentication/launch, and avoid tests/tool-shell polling during Live. The agent must not kill these PIDs or alter networking. Socket ownership/rate must be rechecked read-only after the user makes that choice; an idle forecast cannot replace final Native counter/integrity proof.

## 3. Executable choices and limits

### A — existing artifact/scope, opportunistic only

The existing initial UDP1/TCP1 DNS probe may run in a quiet lo interval, followed by passive TCX observation up to300s. The later natural packet must witness30s of idle before4096; final counter/CPU/clock/window and retained raw-vector gates must all pass. This needs no extra traffic scope, but if disconnecting VS Code removes the last periodic traffic source, there may be **no later packet at all**. Waiting after STOP does not help. Therefore A is technically possible but not a reproducible guarantee; do not spend the last Batch2 slot assuming eligibility.

### B — preferred bounded controlled scenario, requires R2 approval and new tooling

R2 is a **scope-change/development request**, not an execution approval and not implemented by the current Artifact:

- Retain net:[4026531833], lo/Ingress, full unsampled capture, <=4096 events/300s, Queue32, Admission50ms, reorder10ms and checkpoint16KiB. Retain all CPU snapshots/clock/counter/loss requirements. No interface/filter/offload/DNS-setting changes.
- First perform the existing UDP1/TCP1 local DNS exchange inside unchanged Sidecar10s total/7s capture/32packets/512B. The TCP exchange supplies bidirectional data/FIN evidence. Sidecar Counter/CLOSED/container cleanup complete normally within its own10s; no deadline extension.
- **35s after the initial TCP probe closes**, make exactly **one additional UDP A query** to127.0.0.53:53 for native-0516.localhost. This is a TCX kernel-event witness. One send, <=512B response,1s response deadline, no retry/TCP fallback/system resolver/external DNS. It runs as an ordinary UID with no capabilities, at most one socket, proposed64MiB/CPU2s/wall40s after authenticated initial probe completion; close its FD on every exit, spawn with close_fds and no inherited Broker/Inspector/authority FDs, and accept no arbitrary command/environment input. Scheduling intent uses userspace monotonic time, but only actual captured kernel timestamps can prove the30s gap.
- Scenario total: **UDP2/TCP1**, versus current UDP1/TCP1. The late UDP witness is outside the already closed Zeek Sidecar; expected Zeek completed transactions remain the initial2, not3. Do not call its absence a Zeek capture failure or claim it was analysed by a closed collector.
- Target the existing Supervisor's normal scoped TCX STOP at initial TCP-close+45s; planned capture-stop upper bound60s after attach, within the unchanged300s contract. If startup/witness timing cannot fit, stop normally with INCOMPLETE evidence; no retry. Use existing STOP/Counter/CLOSED/drain/FD paths, not SIGTERM as a normal completion and not a second Supervisor/authentication.
- Under genuinely quiet traffic, the later UDP packet can cause existing event-watermark logic to finalize the original DNS UDP/TCP windows as IDLE_TIMEOUT. Approximately3 controlled flows fit the current four-vector tail. Raw-vector retention and capture integrity must nevertheless be checked; background noise, unsupported input, late events or other exports may still prevent eligibility. FIN, the35s scheduler or a clean response is never a substitute for those gates.

The extra query and bounded timing/STOP adapter need a separately pinned helper/launcher SHA, explicit traffic approval and a reviewed execution-contract amendment. `NativeCampaign.reserve` currently compares the Sidecar DNS counters to the immutable budget, so simply changing UDP1 to2 in an old receipt fails NATIVE_CAMPAIGN_APPROVED_SCOPE_CHANGED. Do not smuggle the late probe through the old receipt or execute an unbound helper. A versioned explicit TCX-witness scope must preserve the original Sidecar limits, historical budget/Ledger and their2/10 usage, followed by a newly built Artifact and exact-SHA execution approval. Current scenarioB helper/image SHA is **NOT BUILT**; none is invented or authorized here.

### Risk/stop conditions

Operator workload quiescence may be inconvenient and cannot guarantee future packet rate. The late helper adds a local UDP request and FD outside the current Sidecar lifecycle; it must be independently bounded/audited and included in cleanup evidence. Full-scope unexpected traffic may still exhaust4096 or make integrity incomplete. wsl-pro.service can still change global resources; no service stop/foreign detach or global-guard relaxation is requested. Any such drift still yields the actual strict cleanup result. No test traffic goes to an external endpoint, and there is no active scan. Any exceeded bound, conflicting service/identity, missing receipt or uncertain cleanup stops the attempt without automatic reexecution.

## 4. Current Git/artifacts/budget, not an approval for B

Current implementation Git17241f76510b9d1e60562eca9d1803bf6b2d20ba, tree a95c7fd5ebc97b2bb6bb75f913b244c135b0d180. Only this report changes in the present task; final report-only Git identity is recorded in the decision-package index after commit. The existing frozen1711 source inputs and26 artifact SHA values were rechecked; no recompilation/test repetition is attributed to this documentation task.

- Existing Manifest `3761b57f58a8632f942af6c18abcee47f6b4e5beea6e0f1c882dff8afa9bee05`
- Existing Bundle `119f189c061775b737391eb97e123ae2af7ee98a8a1139477e5e3d9079bb04ec`
- Existing Image `d5980ab96da947c9d6bd0657da2c9c52e9484d4e6b30a853af308fe7432d61f9`
- Existing Root Manifest `da894f80a427cee4d2d5991f9c736acbbed31e89d689ff141ba8035919a181f6`
- Existing source snapshot `846e871eb7bb3a2a0d5c4ee6f236787eff6fba622c8e92947c566fe664247e6c`

These identify the existing diagnostic implementation and possible A; they **do not include the R1 procedure or scenario B**. Their old approval requests remain unapproved. Current installed Root Manifest remains f5b54fbbac173e05ab6bfc246612d409d1dc966a9fcab5635daadea8c1117ab3 with rollback preservation required. A B execution request cannot truthfully bind current hashes; issue new full identities only after an approved implementation is built/qualified.

Ledger-derived Campaign Native2/10 and Root2/10; Batch2 Native1/2 and Root1/2. No new reservation or cost. Original49 Native files, protected104 historical records +8 user files and registered ledger bytes are preserved. No true review event or other Ledger update was made.

## Decisions requested / remaining blockers

1. **R1:** approve the formal evidence-bound reassessment procedure/implementation and review the documented prior-attempt residual risk, for future admission only. This does not itself install, run, certify old cleanup or authorize a raw flag write.
2. **R2:** approve preparation of the described quiet-workload + one late local UDP witness + bounded normal STOP scenario and its versioned scope/contract amendment. This is not Native/Root execution approval; current hashes do not cover that work.
3. After those decisions, prepare/qualify the bound tooling and ask separately for exact-SHA installation1/Native1 within the remaining Batch2 budget. If changes are rejected, A remains a conditional diagnostic with no eligibility guarantee; do not silently substitute it for B.

Safety admission remains BLOCKED, B remains DESIGNED_NOT_IMPLEMENTED, A remains CONDITIONAL_EXISTING_SCOPE. No new Native evidence exists. P02/P03/P04 remain INCOMPLETE; Native AI/DNS9/production remain BLOCKED. This package makes the actual missing procedure and specific scope delta reviewable instead of repeatedly asking to rerun the same13s capture.


# R1/R2 unapproved contract specification and inactive fixtures

## Status / activation boundary

**DRAFT_VALIDATED_NOT_APPROVED; operational admission remains BLOCKED.** This instruction does not approve R1/R2. The only code added is `tests/r1r2_draft_spec.py` and `tests/unit/ebpf_tc/test_r1r2_draft_contract.py`. No src module, policy, campaign controller, registered budget, live Ledger, authentication path or executable collector changed. There is no new CLI, socket helper, Root command or activation flag. Tests cannot install/attach/capture or write a real review.

The simulator requires explicit synthetic approval in each positive fixture; its default is unapproved. Its receipt contract is DRAFT_SPEC_NOT_A_PRODUCTION_RECEIPT_V1; its records are SPEC_ONLY_REASSESSMENT with no safe_for_next_attempt field. Production imports neither test module. These names deliberately cannot satisfy the existing real review gate. All positive tests are conditional specification examples, not human approvals or Native evidence.

## R1 proposed formal contract

### Review subject and immutable history

Keep the original attempt, Session, generation, previous Release and all four artifact hashes, original FAILED result and sequence8 safe_for_next_attempt=false untouched. Reassessment is a separate, single-next-attempt admission decision. It does not authorize Root/Native execution or certify global cleanup. Bind the proposed next application Session/Release/artifacts and execution-scope digest as well as the previous execution; a next kernel generation must be attested when actually minted, never fabricated in advance.

Actual evidence remains: owned FD/map/link/drain/container cleanup VERIFIED, global snapshot UNVERIFIED, external attach target wsl-pro.service/Program1145 attributed but exact removal cause UNKNOWN. Unknown foreign attach ownership is different from unknown removal cause. A human may be asked to accept the latter residual uncertainty for admission only; unknown ownership, unverified owned FDs/remaining resources, missing drain/container proof or added unknown Programs must defer/deny rather than be overridden by a generic confirmation.

### Receipt and trusted approval binding

Proposed required fields: contract/version; bounded receipt ID; authenticated reviewer identity and explicit human approval reference; whole canonical receipt SHA pinned by that trusted approval source; issued/expiry time; previous attempt/Session/generation/Release; next application Session/Release; Manifest/Bundle/Image/Root hashes; evidence-manifest hash; original negative-review hash; expected current Ledger tip; approved procedure/controller/scope digests; one-attempt scope; decision ALLOW_NEXT_ADMISSION_ONLY, DENY or DEFER; explicit acceptance of the documented unknown external removal cause. No field may grant execution, override global cleanup or relabel the failed run.

The trusted whole-receipt SHA is essential: a human reference string/digest alone does not bind changes to decision/risk fields. The production validator must resolve the trusted approval through the approved authority, not accept a caller's self-asserted Context. Canonical SHA detects byte/content mismatch; it is not proof that boolean cleanup claims are true or that a person approved them. Validate original authenticated Journal/Inspector/FD/container evidence, Session/Release/generation bindings and hash-chain integrity independently. Fixture cleanup booleans stand for these prevalidated observations; the test model does not implement a Root forensic verifier.

Use strict field types, fixed scopes, finite integers, uint64 generation range and full lowercase SHA256. The fixture specifically rejects True as numeric Literal[1] and numeric0 as a false authorization flag; strict Pydantic mode alone does not enforce those Literal type distinctions. Reject unknown fields and expiry/future receipts. Review receipt expiry uses a validated approval-clock domain; capture event-time uses kernel monotonic generation, never a wall-clock expiry comparison.

### Recording, replay and fail-closed behavior

After separately approved procedure implementation, a canonical review writer must take the existing trusted file lock, validate current chain/tip and latest review/authority while locked, and append a new evidence-bound, versioned decision. Never rewrite sequence8 or insert a bare private lambda setting true. A possible future record kind is NATIVE_REASSESSMENT_DECISION_V1; it is a proposed schema only, not a record written in this task. Preserve reviewer/receipt/evidence hashes and the predecessor review; subsequent DENY/DEFER/revocation must supersede earlier allow decisions.

Reject duplicate receipt IDs, duplicate receipt body digests, reused human approval references, stale tips and Session/Release/scope mismatches. Consumption for the next reservation must be atomic with that reservation under the approved versioned contract: review alone consumes no Native/Root budget, and the review cannot be used for another Session or a second attempt. Existing real code only checks whether any matching positive review exists; it does not enforce this proposed latest authenticated decision contract. Do not bridge the gap by synthesizing its legacy true event.

Missing grant/receipt/evidence, mismatch, expiry, replay, stale state, storage error or uncertain commit must fail closed before execution. No automatic retry after a write of uncertain outcome. The fixture models immutable in-memory history, tip comparison and latest decision semantics; it does not prove interprocess lock/fsync/crash recovery. Actual writer crash/concurrency tests are required on the approved implementation before activation.

### Governance and compatibility

AGENTS.md §33 requires proposal → policy validation → human review → approved update for approval/authorization rules. No production rule is changed here. A future reviewed execution-contract revision must bind the new controller/validator hashes, preserve the immutable original budget and historical records, and carry forward actual reservations (Campaign2/10, Batch2 1/2 each); no budget reset or silent controller pin rewrite. Old review/schema versions remain readable evidence and cannot silently activate the new procedure. A new exact-SHA Root/Native execution receipt remains separately necessary after valid reassessment.

## R2 proposed diagnostic contract

### Scope

Existing namespace net:[4026531833], lo/Ingress, <=300s/4096 metadata, Queue32, Admission50ms, reorder10ms, checkpoint16384B, privileged-task256MiB/CPU20s; Zeek512MiB/CPU1. No sampling/filtering, offload or DNS/network setting changes.

Initial Sidecar scope stays UDP1/TCP1 to127.0.0.53:53, native-0516.localhost., A, <=10s total/7s capture/32packets/512B. Separate proposed late TCX witness: UDP1 to the same fixed endpoint/name/type, no retry/fallback/external resolution. Scenario total UDP2/TCP1; the late query is outside the closed Sidecar and must be separately approved/bound/audited, not smuggled into the old UDP1 receipt. Current contract does not authorize it.

Operator first saves/disconnects their own VS Code Remote connections and uses an independent OS terminal; no agent process killing or service changes. Passive workload forecasts are planning information, not Capture Integrity evidence. No tests/tool-shell polling during approved Live collection. Background traffic can still exhaust the cap or make Window evidence incomplete; do not discard it to preserve duration.

### Separate lifecycles and clocks

After authenticated initial TCP DNS close, plan one witness request at close+35s and normal scoped TCX STOP near close+45s. Planned capture-stop upper bound60s after attach, below unchanged300s. If startup/witness/stop cannot fit, stop normally with incomplete evidence, not a late resend/deadline extension. The unprivileged helper is proposed as one no-capability child, one socket,64MiB/CPU2s/wall40s after initial probe completion; close_fds, no inherited Broker/Inspector/authority FDs, no arbitrary commands/environment. It is not implemented here.

The Sidecar must complete Counter/CLOSED/container cleanup within its own10s; it is not kept open for the35s wait. The existing Phase D Supervisor can continue TCX after the DNS future completes, within its300s loop, so the lifetimes are compatible in principle. Keep its heartbeat/status handling alive while a bounded child waits; do not block that control loop on sleep/recv. Use existing scoped STOP/sequence/lock/counter/drain paths, not SIGTERM as normal completion or a second authentication/Supervisor.

Scheduling uses host monotonic time as intent only. A received kernel packet timestamp, generation and verified per-CPU Window must prove the actual >=30s gap from the candidate's last event. Store the scheduled time, probe timestamps and actual observed witness separately. FIN or the timer firing is not completion evidence. A lost/missing probe cannot be manufactured into a watermark; a request at35s whose captured event time is still below30s must not make the flow eligible.

### Flow, counters and receipts

Bind candidate identity, source reference, capture-window digest, first/last event, directions, FIN/RST flags, timeout witness and reason, Feature fingerprint/schema and receipt digest. Require initial/final per-CPU snapshots, Clock Domain/epoch binding, reconciled branch populations, no ignored reserve/send/queue failures/excluded prefix and real drain. Fixed4 raw vectors remain bounded; raw missing is UNKNOWN rather than invented. Unknown ownership/window/clock cannot be promoted because the proposed timer ran.

In a quiet synthetic example the first bidirectional TCP FIN flow is finalized IDLE_TIMEOUT only when a later35s packet enters the real FlowAssembly; the later witness flow itself is incomplete at STOP. Waiting without a packet or an event below30s leaves the TCP candidate INCOMPLETE even with FIN and a verified synthetic capture Window. New Native candidates must be evaluated independently; the historical7 candidates remain INCOMPLETE and Native eligible0.

If4096 arrives early, stop with incomplete evidence without sending a late probe. Normal STOP means controlled teardown, not successful eligibility. Preserve first collector/helper failure, then separate stop/drain/checkpoint/cleanup failures; no retries or errno fabrication. Keep Counter/CLOSED, bounded Queue drain,16KiB checkpoint failure handling, audit drain and final global resource guard. Foreign wsl-pro.service churn may still fail global cleanup; the proposal does not exempt it.

## Validation performed / limits

53 new specification cases plus relevant unchanged capture/budget/checkpoint regressions: **142 PASS** in Workspace (2.89s) and **142 PASS** in independent Export (3.29s). These sets overlap and are not added as unique coverage. Cases cover missing/unapproved/tampered receipts; malformed/wrong SHA; previous/next Session and Release; scope; human identity/reference; expiry; duplicate/replay/reused approval; stale tip/latest denial; insufficient cleanup/unknown owner; unknown removal-cause risk acceptance; strict literal types; separate R1/R2 grants;35s/45s schedule and missed/capped/late plans; Sidecar closed requirement; unapproved/expanded namespace/interface/traffic/cap/deadline; real synthetic flow timeout and checkpoint round-trip.

The specification modules perform no filesystem, subprocess, network or production Ledger operation. Their SHA/event labels are intentionally unaccepted by the real controller, and production imports neither. Tests use isolated memory and the existing real pure Flow/Window/Eligibility/checkpoint code; no Kernel program, Docker, PAM, Root or DNS traffic. The ledger and Native evidence are not test fixtures. IO/crash/concurrent reservation, authenticated issuer transport, real-helper timing/process limits and Native performance remain **NOT IMPLEMENTED/NOT VERIFIED** until approved code exists. A standalone ad-hoc test initially used the original checkout's editable import path; it was corrected to the explicit release-worktree PYTHONPATH. The recorded final pytest/Export results use the correct sources.

The frozen Draft source set has1713 files (previous1711 plus2 inert test files); its start/end bytes match between Workspace and independent Export. This is a **Draft/test snapshot**, not a new Native release qualification. Production src bytes and existing26 Native artifacts remain unchanged. Old846e871e… qualification belongs to the previous1711-file Native build source; it is not relabelled as the new whole-Workspace snapshot. No new build or Native SHA was invented for unimplemented R1/R2.

## Necessary implementation changes after approval

| Area | Proposed work, currently inactive |
|---|---|
| Review receipt/authority | Trusted whole-body SHA, reviewer/Session/Release/scope/evidence binding, expiry and explicit risk scope |
| Versioned campaign adapter | Latest validated review, atomic one-use consumption/reservation, canonical append-only writer; preserve budget/history |
| Supervisor/Phase D | Opt-in approved scenario, initial probe-close reference, bounded helper and timed normal STOP using existing control session |
| Late witness helper | Pinned ordinary-UID fixed-endpoint single UDP action, no inherited authority FD, bounded response/cleanup/audit |
| DNS Sidecar | Keep10s deadline, original UDP1/TCP1 and CLOSED contract; do not reclassify late traffic as Sidecar observations |
| Evidence/receipts | Separate scheduling from captured event-time proof; link window/flow/fingerprint/provenance and actual cleanup |

No implementation is activated by importing this fixture or by a bare CLI/environment toggle. Existing approval gate remains effective. Before production implementation, human approval must cover the final R1 procedure, R2 scope and the execution-contract revision; this document and prior R1/R2 requests are not approvals.

## Approval / implementation / execution sequence

1. Review this proposal with its exact draft file hashes and explicit risks under AGENTS §33. Human approves/rejects R1 procedure and R2 expanded local-traffic contract separately; current status is REQUESTED_ONLY.
2. After approval, implement the reviewed validator/versioned adapter/helper/scenario with inactive-by-default execution. Validate issuer/evidence/atomic storage, failure injection, old/new version compatibility and helper limits. No original ledger/budget rewrite.
3. Build/qualify the resulting code. Recompute source/export/stage, helper/controller/contract and release identities; bind all of them to approval. A proposal SHA is not a Native image SHA.
4. Through the approved review handler, obtain the evidence-bound next-admission decision without changing original FAILED/false/global-UNVERIFIED facts. A positive fixture result is not usable for this step.
5. Obtain a separate exact new Manifest/Bundle/Image/Root/Session/Scope approval for installation1/Native1 if required. Validate remaining campaign/batch budget, rollback, OS TTY authentication and current Inspector/kernel/hook/FD/cgroup preflight. Only then run once, without automatic retry.
6. Independently decide P02/P03/P04, Sidecar, checkpoint/audit and owned/global cleanup from new evidence. Do not turn model input eligibility into Native AI inference permission.

## Artifact identities that require new SHA after approved implementation

Approved review contract/schema and authority/controller/adapter; execution-contract amendment binding old baseline and current usage; late helper/scenario launcher; integrated runtime bundle; source/export/stage snapshots; Manifest/Bundle/Execution Image/Root Manifest and trust material; new review and execution receipts. C/BPF/TCX ABI changes are not proposed, but any unchanged binary SHA must still be checked in the actual build. Current installed release/rollback is preserved. Exact new Native identities are **PENDING_IMPLEMENTATION**, not copied from17241f7.

Current runtime identity remains17241f76510b9d1e60562eca9d1803bf6b2d20ba / Manifest3761b57f58a8632f942af6c18abcee47f6b4e5beea6e0f1c882dff8afa9bee05; Bundle119f189c061775b737391eb97e123ae2af7ee98a8a1139477e5e3d9079bb04ec; Imaged5980ab96da947c9d6bd0657da2c9c52e9484d4e6b30a853af308fe7432d61f9; Rootda894f80a427cee4d2d5991f9c736acbbed31e89d689ff141ba8035919a181f6. These do not implement R1/R2.

Campaign Native/Root2/10, Batch2 Native/Root1/2 unchanged. Original Ledger, negative review, audit, Native49 hashes and protected112 files are preserved. No policy activation or new operational approval exists. Final state: **UNAPPROVED_DRAFT_CONTRACT_VALIDATED / NATIVE_BLOCKED**; P02/P03/P04 INCOMPLETE, Native AI/DNS9/production BLOCKED.

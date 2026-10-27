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

## R1/R2 operational implementation — separate authority grants still required

Status: **NONPRIVILEGED_IMPLEMENTATION_VERIFIED; NATIVE_BLOCKED_PENDING_APPROVAL**.
The implementation approval does not issue a procedure/reassessment/admission/
traffic/execution receipt. No actual campaign record, safe flag, installation,
PAM authentication, capture or DNS traffic was created during this work.

### R1 implementation and activation boundary

`ebpf_tc/reassessment.py` validates held owner/mode/length-checked receipt bytes
against separately supplied SHA256 trust anchors. Strict, immutable models bind
previous/next Git commit/tree, Release identities, sessions, scope, original
negative review, evidence catalog, reviewer, procedure approval and expiry.
It verifies the previous reservation's Artifact/Git/session and FAILED finish,
source evidence file digests and the latest negative review. Under the existing
flock/hash-chain/fsync writer it checks the current ledger tip again, rejects
replay/duplicate human references and appends only `SAFETY_REASSESSMENT_RECORDED_V1`.
It never emits a legacy positive review or changes the original false/FAILED.

Cleanup fields are explicit reviewer-attested interpretations, not an automatic
parser proving Kernel ownership. Their raw source digests must be supplied and
verified. ALLOW requires owned cleanup, no new unknown programs, an attributed
external owner and explicit acceptance of the UNKNOWN removal cause. Historical
Program 1145 removal cause and historical global cleanup remain UNKNOWN/UNVERIFIED.

`ebpf_tc/reassessment_admission.py` supplies a separate opt-in versioned adapter.
It is disabled without an exact, independently human-approved
`SOC_REASSESSMENT_ADMISSION_AMENDMENT_V1` with
`activate_versioned_admission=true`. This is a policy-change authorization and
is **not granted by implementation approval**. AGENTS.md §33 and the current
user instruction require separate human review before it can be activated.
The pinned legacy controller and budget were not edited. Legacy admission still
rejects the original false review, even after a new reassessment event exists.

The versioned adapter requires the latest unexpired positive reassessment,
unchanged original negative review, current ledger tip, exact next session /
Artifact / base scope and a separate execution approval. It delegates base scope,
Root/global budget and approval consumption checks to the existing campaign;
Batch 2 remains at most two Root and Native reservations. A reassessment may
support only one reservation. No prior result is relabeled successful. The R2
Supervisor branch verifies this reservation under the same ledger lock before
OS authentication and refuses missing/completed reservations.

There is no receipt issuer, bypass flag, Root shell or alternative authentication
implementation. SHA pins are operator-provided approval trust anchors, not digital
signatures or independently discovered reviewer identities.

### R2 implementation and limits

`ebpf_tc/r2_diagnostic.py` and the opt-in existing Supervisor path require a
separately pinned `SOC_R2_TRAFFIC_APPROVAL_V1` binding session, Artifact, exact
scenario, implementation SHA, expiry and exclusive claim path. The claim is
consumed before authentication; crash/send failure cannot trigger an automatic
retry. Claim-path substitution and already-created claims are rejected. The
ordinary-UID/capability-free helper can send only the single fixed C203 UDP query
at 127.0.0.53:53, `native-0516.localhost.` A, with a one-second response bound
and 512-byte maximum. It records response identity, monotonic timestamps and
digest, and closes its socket. No resolver API or fallback server is used.

The initial Sidecar keeps UDP1/TCP1 and its unchanged ten-second internal bound.
The initial probe now records the actual **local socket close** monotonic time;
this is not inferred peer FIN evidence. Its exact pinned PROBE_SHA was updated,
not removed. The additional UDP witness is requested at TCP local-close +35s,
after initial Sidecar completion; the existing Supervisor requests normal STOP
at +45s. The planned capture cap is 60s after ATTACH and the original hard cap
remains 300s. Queue32 / admission50ms / reorder10ms / checkpoint16384B and the
4,096-event / 256MiB / CPU20s limits remain unchanged.

This is total UDP2/TCP1. The late witness is **TCX observation**, not a third
Sidecar/Zeek transaction. Existing Source Provenance, actual Kernel timestamps,
CPU/Clock window validation, Flow termination and eligibility evaluators retain
authority. Waiting, a successful DNS response or PLANNED_STOP never asserts
ELIGIBLE. Early capture close, event limit or absent late witness stays INCOMPLETE.
The user must manually disconnect noisy VS Code Remote sessions; no process is
killed, event discarded, counter corrected, timeout shortened or limit expanded.
Quiet loopback and at least one eligible flow are not guaranteed by this launcher.

### Regression finding and minimal correction

The initial broad run had 409 PASS / 1 FAIL before any final builds: a signal
fixture exceeded its unchanged three-second READY wait **before sending SIGTERM**.
Supervisor import pulls scipy/sklearn (a measured import trace was about 1.918s;
exact scheduling contribution to the failed run is UNKNOWN). An isolated run
passed. To remove this irrelevant coupling from the signal fixture, the same
signal-only implementation was moved unchanged to `ebpf_tc/termination.py`.
Supervisor public aliases remain; an added identity assertion verifies it uses
those exact functions/classes. All signal and cleanup assertions and deadlines
remain unchanged. Earlier development failures, including the expected stale
probe pin and signal readiness failures, remain in qualification logs and are
not final-source verification results.

### Final qualification and preservation

- Related Workspace: **411 PASS**, `r1r2-operational-3/workspace-tests.log`;
  the exact final source snapshot matches that run. No Workspace source mutation
  was detected. This is not a claim that the historical full-suite failures are fixed.
- Final independent Export: **411 PASS**, `r1r2-operational-5/export-tests.log`.
- Operational R1/R2 cases: **37 PASS**, including real temporary hash-chain writes
  and one-shot dispatch to a mocked existing Supervisor; no real authority granted.
- Prior draft cases: **53 PASS**, still explicitly synthetic/inactive.
- Ruff / Format / Diff: PASS; 1,375 Python files format-checked.
- Source snapshot SHA256: `22dd59c8feb04dc50fa4ddc662259109da667a4ef5690367545dfce31692133a`; **1,718 files**,
  Workspace/Export start/end equal. Final change guards passed.
- Build A/B: **26/26 byte digests identical**, 21.962s /
  21.531s. Stage file hashes are in `qualification.json`;
  the build contract does not define a separate aggregate Stage identity.
- Manifest: `b82681b295ce458a6bf08be1b48b4e05c992c0c552af3a0ddef70b6b3a36fb33`
- Bundle: `fd4693384b6eb0d94e370b4cd3b2c14439e7d91d5207cb940ddd0b43bbffc576`
- Execution Image: `5d555ba00c9ff9f59d09fcfaab9358b58035b49d53c2d992b28d9433996c9cda`
- Root Manifest: `9983f2c3b90c82382466c3d83f84ab082b0ac2381851cab74525456e4ba46e76`
- Existing protected files: **112/112**, including the original eight user files
  and 104 evidence entries. Prior Native evidence **49/49** unchanged.
- Actual execution ledger SHA256 remains
  `f6a18f079ab88b4fa3f55daea7d3ccad004d47dd3d82567f59a3d125b3b6761a`.
- The first guarded Export attempt was rejected: a fresh pytest cache atomically
  creates `pytest-cache-files-*` in the source root before renaming to `.pytest_cache`.
  An instrumented diagnostic reproduced those exact non-input directory events;
  its observer-induced teardown errors are not qualification results. Installed
  `_pytest/cacheprovider.py::_make_cachedir` confirms this behavior. Input byte hashes
  and file sets were unchanged. The final runner relocates pytest's cache outside
  the source tree (`-o cache_dir=...`), with the strict SourceGuard unchanged.
  Final Export and both new builds passed their guards. Rejected cycles remain
  preserved; their Artifact identities are not approved or reused.
- Current installed Root Manifest remains
  `f5b54fbbac173e05ab6bfc246612d409d1dc966a9fcab5635daadea8c1117ab3`.
  Old full Workspace/Export failures are not reclassified by these related tests.


The final commit/tree are recorded after commit in the private
`r1r2-operational-5/approval-request.json`; embedding this document's own commit
hash in its contents would be self-referential. Only the two historical report
Markdown files are excluded from the build-source snapshot. They are not runtime
build inputs; post-commit code/input hashes must still match the frozen snapshot.

Campaign Native / Root remain **2/10 each**, Batch 2 **1/2 each**. Old Phase D
budgets remain exhausted and separate. No real reassessment/admission event was
appended; `safe_for_next_attempt=false` and the previous Native FAILED are intact.
P02/P03 remain INCOMPLETE, P04 remains 0/7 historical eligible, and Native AI,
DNS9 and production remain BLOCKED.

### Required human decisions before any future Native execution

1. Review/approve the R1 procedure and the separately scoped versioned admission
   amendment under AGENTS.md §33. The approved implementation itself grants neither.
2. A named human reviewer must approve the exact source evidence catalog, UNKNOWN
   external-removal risk, previous failed session and proposed next session / SHA.
   Append a separately pinned review receipt only after that authorization.
3. Pin the new R2 traffic receipt (UDP2/TCP1), next-session UUID and exclusive
   claim path, plus the reassessment record and admission amendment hashes.
4. Separately approve the exact Root Manifest nine-file installation once,
   preserving installed release and rollback, and one Native diagnostic reservation.
   Maintain net:[4026531833], lo/INGRESS, 300s, 4096 events, Queue32,
   privileged-operation AS256MiB/CPU20s, original container resource limits.
   The user enters any password directly into the existing trusted terminal path.
5. Recheck current ledger tip, remaining Batch 2 allowance, owned/global resource
   baseline, source and artifact hashes, and STOP/SIGTERM/cleanup contract. Stop on
   a mismatch; no automatic reinstall, replay, Native retry or unknown-program detach.

The exact pending Artifact identities and operation request are in the private
approval request. No approval can be inherited from the ca5b7cb or older images.


## 2026-10-27 — R1/R2 conditional execution preflight

### Overall status: BLOCKED — no Root or Native attempt started

The user authorized the R1 activation workflow and the exact R2 scope, and made
Root installation and Native execution conditional on a positive HUMAN safety
reassessment and valid receipts. The same instruction explicitly did **not** grant
that positive reassessment. A model evidence assessment cannot replace it. No
reviewer identity, positive human decision or valid reassessment receipt was found.
No procedure/admission activation, positive review event or execution reservation
was synthesized. Original FAILED and `safe_for_next_attempt=false` remain intact.

The approved Release worktree is
`/home/geonug/kdt-linux/native-soc-phase-d-release-063`, branch
`fix/native-stabilization-batch2`, HEAD
`bed73a983e93efba6079920619ad32e446a20e77`, tree
`824687ed158b3a6a068797cd722d247ce5d8739e`. The separate original worktree remains
on main with existing user/development changes; those were not overwritten.
Only this report is updated without committing, retaining the approved HEAD.
This report was already excluded from runtime build inputs; all 1,718 approved
source input hashes still match.

### Artifact checks and first preflight failure

All 26 files in each approved build still match their recorded hashes. The exact
submitted identities match the request and file contents:

| Identity | SHA256 |
| --- | --- |
| Manifest | `b82681b295ce458a6bf08be1b48b4e05c992c0c552af3a0ddef70b6b3a36fb33` |
| Bundle | `fd4693384b6eb0d94e370b4cd3b2c14439e7d91d5207cb940ddd0b43bbffc576` |
| Execution Image | `5d555ba00c9ff9f59d09fcfaab9358b58035b49d53c2d992b28d9433996c9cda` |
| Root Manifest | `9983f2c3b90c82382466c3d83f84ab082b0ac2381851cab74525456e4ba46e76` |

However, file-identity matching is insufficient for execution. The actual current
release validator rejects a host dependency before authentication:

- Stage: RELEASE_PREFLIGHT.
- API: `phase_d.validate -> verify_package -> verify_dependencies`.
- Original exception: `ValueError("DEPENDENCY_HASH_MISMATCH")`.
- errno / signal: not applicable; this is a deterministic validation failure.
- Library: `/usr/lib/x86_64-linux-gnu/libz.so.1.3` (both versions 113,000 bytes).
- Expected SHA: `86200da370f20476a2507e9097a789b5ef97269b4ca8d5e164ad82dab9d99892`.
- Observed SHA: `f61677c7bdb7c2aa2a243ea781bfd16afcb361cede7b4ef76127a9d8eb9a5242`.

`/var/log/dpkg.log` records the zlib1g:amd64 upgrade on 2026-10-24 06:07:39,
from `1:1.3.dfsg-3.1ubuntu2.2` to `1:1.3.dfsg-3.1ubuntu2.3`; dpkg-query reports
the latter as installed. The recorded old library hash is no longer present at
the pinned path. No code defect or errno-based system error was inferred from
this correct fail-closed behavior. The exact Actor responsible for the package
upgrade was not independently established.

### Nonprivileged reproduction and bounded preparation

Without changing source, dependency checks, the OS library or Root installation:

1. Reproduced the installed-release validation failure through
   `installed_release -> validate_root_release -> verify_dependencies`.
2. Compiled a nine-file package candidate from the unchanged source. Its current
   dependency validation passed. Partial Root Manifest:
   `864555640003971f0ffb8251945b9aee671827dbb3e001224e323706eedd2fe7`.
3. Attempted normal Supervisor-image preparation; it failed at
   `prepare_supervisor_image -> prepare_unified_image -> installed_release`
   with the same original error, because the previous installed runtime pins
   the old library. No full new Manifest/Bundle/Execution Image was finalized.
4. SourceGuard passed and all 1,718 source hashes, installed manifest and actual
   execution Ledger remained unchanged. No candidate was installed or executed.

The partial package is NOT a qualified Release or an approved replacement. A
new full image cannot be claimed from only its Root Manifest. The old SHA grant
is not transferred. No library downgrade, in-place manifest edit, hash-check
removal or installer-policy exception was performed. A proposal for a narrowly
bound forward-update recovery contract was written for human review; any such
policy change needs separate approval under AGENTS.md section 33.

### Human safety review evidence and remaining uncertainty

Historical evidence still supports Session-owned TCX FD/Map/Link and container
cleanup. Historical resource snapshots show no added programs and zero remaining
Map/Link/lo filters. The global change was removal of Program 1145, `sd_devices`,
tag `4b13b8318fb7df93`, attached as cgroup_device at
`/sys/fs/cgroup/system.slice/wsl-pro.service`. Ownership attribution is supported
by the recorded attach target; the removal cause remains UNKNOWN. The previous
global Cleanup remains UNVERIFIED. These are historical observations, not a fresh
privileged system snapshot. No new Root snapshot was collected before the human
approval gate. No positive safety conclusion was manufactured from these facts.

The original evidence digest is
`1a64123416cfbc63133f52cc4896394470f3bff43eb9b9d0533cf8591f776e42`.
A named reviewer must explicitly decide whether to accept the UNKNOWN removal
cause and authorize at most one next admission. Actual receipt issuance must bind
the final compatible next Artifact/session/scope and latest ledger tip; a new
Artifact needs separate exact-SHA approval.

### Execution, decisions and budget

- Root authentication / installation / Native reservation / Native execution:
  **NOT_STARTED**; no traffic generated, no automatic retry.
- R2 authorized scenario: initial UDP1/TCP1, then the same local UDP at TCP local
  socket close +35s; normal STOP at +45s, capture plan at most 60s after ATTACH,
  overall cap 300s. Sidecar 10s remains separate. UDP2/TCP1, Queue32, admission50ms,
  reorder10ms, checkpoint16KiB, events4096, AS256MiB/CPU20s are unchanged.
- Actual R2 timestamps / TCX / DNS / Supervisor Exit / current Checkpoint /
  Audit Drain / owned/global Cleanup: **NOT_RUN / NOT_OBSERVED this turn**.
- P02 and P03: historical INCOMPLETE; P04: historical 0/7 eligible. No candidate
  was reclassified. No real Native success or failure occurred this turn.
- Old execution Ledger: 9 rows, hash-chain verified read-only. SHA remains
  `f6a18f079ab88b4fa3f55daea7d3ccad004d47dd3d82567f59a3d125b3b6761a`.
- Campaign Native/Root **2/10 each**, Batch 2 Native/Root **1/2 each**. No new
  reservation, cancellation, consumption or reassessment event was appended.
- Preservation checks: protected files **112/112**, Native evidence **49/49**,
  existing installation and rollback inventory **234 files** matched. Installed
  Root Manifest remains
  `f5b54fbbac173e05ab6bfc246612d409d1dc966a9fcab5635daadea8c1117ab3`.
  Its file integrity is preserved; its runtime dependency validation is blocked.
- The previous 411/411 tests and double-build result are historical qualifications,
  not newly rerun or represented as current-environment qualification. No code
  changed, so no broad regression loop or new functionality was introduced.
- Native AI / DNS9 / production remain BLOCKED. Next Batch readiness: BLOCKED.

Evidence and concrete pending review requests:

- `.git/native-stabilization-batch2/r1r2-human-review-20261027-1/preflight.json`
- `.git/native-stabilization-batch2/r1r2-human-review-20261027-1/human-review-request.json`
- `.git/native-stabilization-batch2/r1r2-human-review-20261027-1/recovery-contract-proposal.json`
- `.git/native-stabilization-batch2/dependency-requalification-20261027-1/result.json`

Before any installation or capture, resolve both independent blockers: an explicit
human safety decision/valid receipt, and a reviewed compatible deployment path
with a complete requalified Artifact and fresh exact-SHA approval. The conditional
execution approval was not interpreted as permission to bypass either gate.


## 2026-10-27 — zlib recovery and R1 human-review readiness

Status: **BLOCKED for Root/Native; nonprivileged recovery study completed**.
This section adds evidence; it does not revise the previous FAILED result,
`safe_for_next_attempt=false`, or any historical candidate eligibility.
No production code, approval policy, dependency pin, installation or execution
ledger was changed. The original user working tree was preserved; this report is
in the existing release worktree `../native-soc-phase-d-release-063`.

### Confirmed dependency change

Git remains `bed73a983e93efba6079920619ad32e446a20e77`, tree
`824687ed158b3a6a068797cd722d247ce5d8739e`.
The approved image pins `/usr/lib/x86_64-linux-gnu/libz.so.1.3`:

| Identity | Approved dependency | Current host dependency |
| --- | --- | --- |
| Debian package | `1:1.3.dfsg-3.1ubuntu2.2` | `1:1.3.dfsg-3.1ubuntu2.3` |
| SHA256 | `86200da370f20476a2507e9097a789b5ef97269b4ca8d5e164ad82dab9d99892` | `f61677c7bdb7c2aa2a243ea781bfd16afcb361cede7b4ef76127a9d8eb9a5242` |
| Bytes | 113,000 | 113,000 |
| SONAME / runtime version | `libz.so.1` / `1.3` | `libz.so.1` / `1.3` |

`/var/log/dpkg.log` records the runtime/development package upgrade at
`2026-10-24 06:07:39` (log timezone not encoded). The upgrading actor is UNKNOWN.
Package file modification time is not evidence of the installation actor or time.
The approved execution image
`5d555ba00c9ff9f59d09fcfaab9358b58035b49d53c2d992b28d9433996c9cda`
binds Root manifest
`9983f2c3b90c82382466c3d83f84ab082b0ac2381851cab74525456e4ba46e76`,
which pins the old zlib bytes. The installed Root manifest
`f5b54fbbac173e05ab6bfc246612d409d1dc966a9fcab5635daadea8c1117ab3`
also requires its original dependencies. Runtime hash rejection is therefore
correct even though the library path and SONAME stayed the same.

### ABI and bounded compatibility evidence

Cached old `.deb` files were extracted only into a private evidence directory;
no system package was installed or downgraded. Recovered old library bytes match
the approved SHA. Static `readelf` comparisons found identical SONAME, 102 public
symbol contracts and byte-identical public headers. All observed zlib imports
and symbol versions required by current libbpf/libelf are satisfied.

The same newly built, compression-only test executable passed eight API groups
against each library: roundtrip compression, invalid-input rejection, CRC32,
Adler32, CRC combination, gzip file roundtrip, deflate initialization and inflate
initialization. Actual mapped-library paths were recorded. The harness ran as an
ordinary UID with 64MiB address-space, two CPU seconds and five wall seconds;
it performs no PAM, BPF, capture or network operations.

Conclusion: no ABI break found in the observed consumer contracts and selected
smoke tests. This is not proof of all zlib behavior or Native E2E compatibility,
and it does not replace cryptographic dependency admission.

### Recovery alternatives

| Approach | Evidence / reproducibility | Root and security updates | Identity / rollback / risk |
| --- | --- | --- | --- |
| A: isolated old environment | Exact old bytes recovered; full old runtime closure not proven | Private extraction needs no Root; global downgrade prohibited | Old hash alone cannot qualify a different namespace/path/PAM closure. Full isolated Native setup needs separate review. |
| B: current-zlib artifact | Exact new dependency pin; partial package double-build reproducible | Nonprivileged build; eventual fixed-file replacement needs separate Root approval. Keeps current update. | Preferred. New Root/trust identity and complete integrated image approval required; old runtime rollback remains blocked by stale dependencies. |
| C: separate compatibility study | Completed static/selected API evidence while preserving installation | No Root or package changes | Supports B; cannot clear runtime mismatch or replace a new artifact/R1 approval. |

Recommendation: **B plus C**, without system-wide downgrade or hash exceptions.

### Why a complete replacement artifact is not yet finalized

Normal preparation creates a valid current-dependency Root package, then calls
`installed_release` and correctly rejects the old installed dependency pin.
Actual replacement engines also check the previous installation/rollback via the
same runtime validation. Changing only image preparation would not solve this.
No alternate first-install, force flag, temporary library swap or skipped check
was used.

Two independent nonprivileged package builds produced **21/21 identical outputs**,
including the nine fixed Root files. Current-dependency package verification
passes. Its Root manifest SHA is
`864555640003971f0ffb8251945b9aee671827dbb3e001224e323706eedd2fe7`.
Relative to the approved proposed Root package, only `release.json` and
`release.trust` changed; the seven other fixed files are byte-identical.
This is a **partial package identity, not an approved complete release**.
New integrated Manifest and Execution Image SHA remain unset. The unchanged
runtime-source bundle remains
`fd4693384b6eb0d94e370b4cd3b2c14439e7d91d5207cb940ddd0b43bbffc576`;
future implementation changes require recalculation rather than approval transfer.
The historical 26-output full build is not counted as a new full build here.

### Recovery contract proposal — not activated

Keep normal runtime dependency validation unchanged. Propose a separately typed,
reviewed inspection for retaining/replacing an old installation: verify every
old fixed file, digest, trust record, canonical path, owner, mode and link count;
record its runtime dependency mismatch explicitly. Such a retained-file result
must never authorize executing the old release. Require the replacement runtime
to satisfy all current dependency, configuration and approval checks.

Any implementation/activation affecting installation admission requires Policy
Validation and explicit Human Review under `AGENTS.md §33`. The proposal contains
no active bypass and grants no Root authority. Bind a future replacement to the
exact old/new Root manifests, current dependency hashes, complete new image,
session, latest ledger and reviewed fixed-file commands. Reject additional drift,
stale/replayed grants, ambiguous ownership and invalid rollback runtime. Preserve
old files even when their execution is no longer admissible. No arbitrary Root
command or external-service program removal is proposed.

Requested next approval is limited to review of that recovery contract and its
nonprivileged implementation/tests. Installation/Native approval must wait for
complete future artifact hashes and a valid positive human R1 decision.

### R1 readiness and remaining human decisions

Original attempt `0648d6b41f204377854e58fb76c3aa36` remains FAILED/false.
Historical Session is `75e98238-99ab-40d8-862c-5f1b93cb03f7`.
Owned TCX FD/Map/Link and container cleanup remains VERIFIED; global cleanup remains
UNVERIFIED. Snapshot evidence records disappearance of Program 1145,
`sd_devices`, tag `4b13b8318fb7df93`, at
`/sys/fs/cgroup/system.slice/wsl-pro.service`, with no newly added program in that
historical comparison. Its disappearance cause remains UNKNOWN. That earlier
snapshot is not a fresh current resource observation. The later zlib upgrade is
not evidence of the cause of the program disappearance.

The review packet preserves these facts and the changed environment. Reviewer
Identity, human decision, risk acceptance and approval reference remain null.
No positive safety decision, production receipt, reassessment event or reservation
was generated. The future receipt must bind an explicit human Identity/risk
acceptance, exact Session/Release/Scope and complete new SHA set, evidence digests,
latest ledger tip, expiry and replay protection. The original negative event
must remain immutable. A fresh authorized resource preflight will still be needed.

### Current nonprivileged verification

- Workspace core regression: **206 PASS**; fresh independent Export: **206 PASS**.
  Approval/replay/stale-ledger, dependency/Root package and ordinary-UID adversarial
  C/Python execution-schema tests included. These are not privileged Native tests.
- SourceGuard: Workspace and Export PASS; **1,718 source inputs unchanged**.
- Two package builds: **21/21 outputs identical**, nine fixed Root files included.
- ABI harness: old/current library both PASS within the stated coverage.
- Ruff check PASS; format check PASS (1,375 files); final diff check recorded with
  final preservation evidence. Full historical 411-test/26-output qualification
  was not rerun or relabeled as current-host Native qualification.
- No Root authentication/install, Native execution, capture, DNS query, policy
  activation or positive human reassessment occurred.

Campaign Native **2/10**, Root **2/10**; Batch 2 Native **1/2**, Root **1/2**.
No budget consumed. P02/P03 historical INCOMPLETE and P04 historical 0/7 remain
unchanged; new Native qualification, Native AI, DNS9 and production remain BLOCKED.

Evidence is retained under
`.git/native-stabilization-batch2/zlib-recovery-study-20261027-1/` in the original
repository: `dependency-rca.json`, `abi-assessment.json`, `qualification.json`,
`package-file-delta.json`, `recovery-contract-proposal.json`,
`r1-human-review-readiness.json` and `final-preservation.json`.
The proposal and readiness packet are not approval receipts.


## 2026-10-27 — Conditional recovery contract review and fresh package rebuild

Status: **BLOCKED at integrated image preparation; permitted nonprivileged
verification completed**. This request permits review/build preparation but
explicitly does not substitute for the separate human approval required by
AGENTS §33. No admission-policy implementation was activated or modified.

### Exact contract boundary

`prepare_unified_image()` first verifies the new package, then requires
`installed_release() -> validate_root_release() -> verify_dependencies()` for
the previous installation. Current old-installation SHA validation fails with
`DEPENDENCY_HASH_MISMATCH`, not an errno-based system failure.
The actual unified replacement engine similarly calls
`root_main(previous, "check")` before archival and installation.

Correction/clarification to earlier broad references to check/rollback:
`install_engine.root_main()` already skips dependency validation for exact
`rollback`/unpublish, while retaining its approval/quiescence/file checks. The
preceding `check` in unified replacement is the relevant runtime dependency gate.
No rollback or check behavior was changed in this work.

The proposed change therefore needs explicit approval to distinguish **retained
file inspection** from **executable runtime qualification** in preparation and
replacement admission. It cannot be activated by declaring the ABI compatible or
using a first-install image for an occupied installation. The existing dependency
pins and original installed manifests remain unchanged.

Requested human policy decision, not a generated decision: approve a narrowly
scoped replacement contract that cryptographically inspects/retains all nine old
files even when the old runtime is no longer qualified, independently qualifies
all current dependencies of the new runtime, and requires exact SHA/Session/Scope
approval for the eventual replacement. No generic ignore-dependency flag, global
library change, arbitrary Root path/command, automatic incompatible rollback or
R1-positive decision is part of this request. Unknown additional drift must fail
closed. Reviewer Identity/decision/approval reference remain unset.

AGENTS §33 requires `Improvement Proposal -> Policy Validation -> Human Review ->
Approved Update` for authorization/security-boundary changes. A recovery approval
must explicitly cover the above distinction and implementation/admission scope;
ordinary build permission is insufficient. Approval for Root installation and
Native execution remains separate and requires complete future image hashes.

### Fresh verification from unchanged source

- Workspace selected regression: **206 PASS (13.33s)**.
- Independent Export same selected regression: **206 PASS (11.42s)**.
- Tests include R1/R2 missing/invalid approval, replay and stale ledger cases,
  campaign contracts, dependency/Root package verification and ordinary-UID
  execution-schema fixtures. No privileged E2E or fresh ownership snapshot.
- SourceGuard PASS in Workspace/Export, **1,718 inputs unchanged**. No new
  production functions or test bypasses. Existing dirty user/report files retained.
- Independent builds A/B: **21/21 outputs byte-identical**, nine Root files.
  Build times 11.401s and 11.455s; not a throughput benchmark or full 26-file release.
- Current package `verify_package` PASS, dependency inventory includes new zlib
  SHA `f61677c7bdb7c2aa2a243ea781bfd16afcb361cede7b4ef76127a9d8eb9a5242`.
- Old approved dependency remains
  `86200da370f20476a2507e9097a789b5ef97269b4ca8d5e164ad82dab9d99892`.
- Bounded compression-only harness rerun: eight API groups PASS for each exact
  old/current library; mapped paths checked. Earlier static symbol/header evidence
  remains limited to its stated ABI coverage. No all-runtime compatibility claim.
- `installed_release()` and `prepare_supervisor_image(..., dns_sidecar=True)`
  both still reject with `DEPENDENCY_HASH_MISMATCH`; no execution image file is
  emitted. This is expected retained protection, not a successful integrated build.
- Ruff check PASS; format PASS (1,375 files); Diff PASS.

### Identity and remaining approvals

| Item | Current verified value |
| --- | --- |
| Git Commit | `bed73a983e93efba6079920619ad32e446a20e77` |
| Git Tree | `824687ed158b3a6a068797cd722d247ce5d8739e` |
| Source snapshot | `22dd59c8feb04dc50fa4ddc662259109da667a4ef5690367545dfce31692133a` |
| Partial new Root Manifest | `864555640003971f0ffb8251945b9aee671827dbb3e001224e323706eedd2fe7` |
| Runtime source Bundle, unchanged | `fd4693384b6eb0d94e370b4cd3b2c14439e7d91d5207cb940ddd0b43bbffc576` |
| New integrated Manifest | NOT GENERATED — existing-installation dependency gate |
| New Execution Image | NOT GENERATED — same gate |

Candidate version label remains 0.6.3; neither label nor unchanged bundle grants
approval. New trust/Root identity requires a distinct complete artifact identity;
future implementation changes require new Git/Bundle/image hashes and fresh
approval, regardless of any later semantic version selection. No commit/push was
requested or performed; approved code Commit/Tree remain unchanged.

R1 is independent: the original FAILED/false and global Cleanup UNVERIFIED remain
unchanged; historical owned cleanup remains VERIFIED and Program 1145 removal
cause remains UNKNOWN. A new review packet must bind the complete future artifact
rather than reusing old R1 binding. Human Identity, risk acceptance and positive
decision were not inferred or issued. P02/P03 remain INCOMPLETE and P04 remains
historically 0/7 ELIGIBLE; Native AI/DNS9/production remain BLOCKED.

No Root authentication, installation, Native run, Capture, DNS traffic, policy
activation, reservation or real reassessment event occurred. Campaign Native/Root
remain **2/10 each**, Batch 2 Native/Root **1/2 each**.

New evidence directory in the original repository:
`.git/native-stabilization-batch2/zlib-recovery-contract-review-20261027-1/`.
See `qualification.json`, `admission-check.json`, `abi-recheck.json`,
`policy-review-request.json`, and `final-preservation.json`. The review request is
unsigned/pending and cannot authorize Root/Native execution. Required next action:
explicit human review of the narrowly described recovery-admission contract,
followed by reviewed implementation, new complete artifact qualification, an
independent R1 human decision, and separate exact-SHA execution approval.


## 2026-10-27 — Inactive retention/runtime contract separation specification

Overall status: **BLOCKED for production policy activation and integrated image;
permitted inactive implementation/fixture verification completed**.

### Before / proposed contract / active behavior

| Concern | Existing active contract | Inactive proposal |
| --- | --- | --- |
| Previous installation | Exact old file/trust/metadata validation plus old runtime dependency validation | Separately typed retained-file result verifying every old pin/path/owner/mode/link/file/trust fact; old runtime mismatch still recorded |
| New runtime | Own package, dependency inventory, dynamic trust, configuration and hash validation | Keep every active check; new runtime has its own pins and cannot consume retained-file success as runtime authority |
| Replacement preparation | Reject if old installation runtime dependency no longer matches | After explicit policy approval only, permit reviewed retained-file evidence for archival/replacement admission; never for executing old runtime |
| Rollback | Exact unpublish already has distinct checks; unified replacement first calls old `check` | Preserve old files; retained bytes alone never authorize execution or automatic runtime rollback |
| Approval | Existing exact-artifact/session/scope, R1, replay/latest-ledger and budget gates | Unchanged requirements; no valid review was issued by the fixture |

No change in the rightmost column is active. `installed_release`,
`validate_root_release`, dependency checks, unified preparation and Root engines
are unchanged. The recovery proposal still needs the separate human policy
approval required by AGENTS §33; this implementation instruction explicitly does
not supply that approval.

### Files actually added

- `tests/dependency_recovery_spec.py`: pure, strict/frozen fixture evidence models
  and separate comparison functions for retained inventories and new Runtime pins.
  Inventory comparison covers the complete fixed nine-file set, exact file hashes,
  expected directory, directory trust, UID/GID, modes, regular-file/single-link and
  trust-binding observations. Runtime comparison separately checks the new
  Root/Bundle/dependency pins (including package version), package/dynamic-closure
  observations and limited ABI outcome. Neither result authorizes a runtime.
- `tests/unit/ebpf_tc/test_dependency_recovery_spec.py`: 37 synthetic cases covering
  old file SHA/metadata/set/path/trust failures, rollback pin/path/completeness,
  new dependency/version/Root/Bundle mismatch, ABI incompatible/unknown,
  duplicate dependency paths, missing/expired/replayed/stale/misbound draft receipt,
  independent stage failures and the always-blocked policy gate.

The model consumes supplied synthetic observations. It does **not** read the
filesystem, authenticate receipts, implement a privileged inspector, or claim
that a caller-provided `trust_binding_verified=True` is real evidence. All
successful outcomes are named `VERIFIED_FIXTURE_ONLY`, with
`authorizes_runtime=False`. Admission always includes
`UNAPPROVED_DRAFT_NOT_ACTIVE`, including a fully matching synthetic receipt.
No production source imports this fixture module. No installer switch or runtime
bypass was introduced. Existing original FAILED/false/Ledger records were not
changed. P02/P03/P04 eligibility was not revised.

### Fresh verification and identities

- New concentrated draft tests: **37 PASS**.
- Workspace related regression including draft: **243 PASS**.
- Fresh independent Export with identical tests: **243 PASS**.
- SourceGuard Workspace/Export PASS, **1,720 input files unchanged** across
  testing/builds. Includes the two new fixture files; historical 1,718-source
  snapshot remains preserved and is not relabeled as this new snapshot.
- Two current-dependency package builds: **21/21 outputs identical**, including
  nine fixed Root package files; no complete integrated image is claimed.
- Current package verification PASS. Rechecked normal `installed_release()` and
  `prepare_supervisor_image()` both still reject `DEPENDENCY_HASH_MISMATCH` and
  emit no image. Failure has no system errno.
- Ruff/Format/Diff: PASS; no previous tests deleted/assertions weakened.

| Identity | Value |
| --- | --- |
| Git Commit (unchanged) | `bed73a983e93efba6079920619ad32e446a20e77` |
| Git Tree (unchanged committed tree) | `824687ed158b3a6a068797cd722d247ce5d8739e` |
| Uncommitted draft source snapshot | `50614dcd272d7cf74d7fc75d3f5bfe81859b890f0a95099985ec89904008b3a1` |
| Individual Root package Manifest | `864555640003971f0ffb8251945b9aee671827dbb3e001224e323706eedd2fe7` |
| Runtime Bundle (production sources unchanged) | `fd4693384b6eb0d94e370b4cd3b2c14439e7d91d5207cb940ddd0b43bbffc576` |
| New integrated Manifest / Image | NOT GENERATED / BLOCKED pending policy approval |

The committed tree does not include the two new fixture files; their exact
content hashes and source snapshot are recorded separately. No commit/push was
performed; active approved production source remains unchanged. The test-only
source snapshot is not an execution approval identity.

The unchanged old zlib pin is
`86200da370f20476a2507e9097a789b5ef97269b4ca8d5e164ad82dab9d99892`
(`ubuntu2.2`); the independently verified new package pin is
`f61677c7bdb7c2aa2a243ea781bfd16afcb361cede7b4ef76127a9d8eb9a5242`
(`ubuntu2.3`). Earlier 102-symbol/header/consumer and bounded API evidence remains
limited ABI evidence, not proof of production compatibility or a hash exception.

### Required human decisions / current limits

A human policy owner must explicitly review the proposed separation and its
replacement-admission scope, with Identity and approval reference. The unsigned
request remains pending; no such Identity/approval is inferred from the OS user,
Git author or this fixture. Production implementation/activation and a complete
new artifact require that approval, then review/testing and fresh artifact hashes.
R1 human risk acceptance is independent and remains absent. Its future receipt
must bind the complete future Session/Release/SHA/Scope and latest ledger.

Original FAILED/false and global Cleanup UNVERIFIED remain. Historical owned
cleanup VERIFIED and Program 1145 disappearance cause UNKNOWN remain. No new
resource observation, Root authentication/install, Native run, Capture, DNS
traffic, reservation, reassessment event or approval receipt occurred.
Campaign Native/Root **2/10 each**, Batch 2 Native/Root **1/2 each** unchanged.
P02/P03 remain historical INCOMPLETE; P04 remains 0/7. New Native qualification,
Native AI, DNS9 and production remain BLOCKED.

Evidence directory:
`.git/native-stabilization-batch2/dependency-contract-separation-draft-20261027-1/`.
See `approval-request.json` (pending, not a receipt), `qualification.json`,
`production-gate-recheck.json`, `source-start.json`, `source-end.json` and
`final-preservation.json`. Original installed/rollback files and historical audit,
Ledger and user changes remain preserved.


## 2026-10-27 — Production dependency recovery preparation and R1 integration

Status: **nonprivileged operational implementation and integration VERIFIED;
policy activation / positive human R1 / Root / Native remain BLOCKED**.
This supersedes the earlier fixture-only implementation status, not any Native
FAILED/false history, ownership uncertainty or candidate eligibility.

### Operational code and call graph

`runtime_recovery.inspect_retained(exact_manifest)` traverses only the fixed
Root-owned installation path (or its exact manifest-named rollback path), with
O_NOFOLLOW directory traversal and held-FD file checks. It validates all nine
files, exact manifest/trust/payload SHA, UID/GID/mode/single-link metadata, complete
file set and path-vs-held inode. The result is `RetainedInstallation`, explicitly
not runtime-qualified and not usable as ReleaseManifest/UnifiedImage authority.
It preserves original dependency records and never substitutes current zlib SHA.
This is a point-in-time read-only observation; actual replacement must repeat
ownership/quiescence checks under its separately approved execution contract.

`runtime_recovery.prepare_runtime(source, output, abi_file, abi_sha)` reuses
`prepare_candidate -> compile_program/compile_loader/compile_native ->
create_package -> installation_payload -> verify_package`. It does not consult
old executable qualification. A SourceGuard binds the actually loaded source
and detects input mutations; outputs must be outside that source. It records
current dependency SHA/ELF identities, zlib/libbpf/libelf package versions, limited
ABI evidence, toolchain SHA and source snapshot. ABI report SHA is independently
pinned; current libraries and consumer hashes must match the new release. ABI
incompatible/unknown/malformed evidence fails explicitly.

Build metadata distinguishes fixed Root system Python from the actual ordinary
build interpreter. Compiler/system-interpreter identities remain root-trusted;
the user-owned build interpreter is recorded as build provenance, not Root runtime
trust. No global library downgrade, system package change or dynamic library load
was used for recovery preparation.

`validate_runtime` verifies the recovery manifest, exact image SHA/mode and
unconditional quarantine prefix, package/trust/current dependencies, host identity
and current Runtime Bundle. The image aborts *before every installer import* with
`RECOVERY_POLICY_NOT_ACTIVATED`; no argument, environment flag or receipt can
turn these bytes into an activated image. It is a separate quarantined Runtime
contract, **not a deployable Phase-D Supervisor execution release**. Activation
requires an approved connection to the existing install/Supervisor path and a new
image SHA; no previous execution approval is transferred.

`execution_readiness` composes independent installed preservation and new Runtime
checks and can invoke `reassessment_admission.preview_reservation`. The preview
reuses actual `ReassessedCampaign.reserve` / `NativeCampaign.reserve` validators:
policy amendment binding, real receipt schema, exact Artifact/Session/Scope,
latest ledger chain, replay, original negative review and budget checks. It
aborts before the locked writer appends, so it issues no reservation or grant.
The actual reservation path still repeats validation atomically before execution.
No parallel approval implementation was introduced. Existing ProcedureApproval,
ReviewReceipt and AdmissionAmendment schemas are reused; draft/mock contracts
cannot satisfy them. Their expected implementation hashes change with this code,
so previous amendment approvals cannot silently carry forward.

### Verification and fixes during this work

- Final related Workspace: **368 PASS (70.06s)**.
- Final independent Export: **368 PASS (69.90s)**.
- Includes the new real-file/real-validator/temporary-ledger tests, earlier draft
  tests, R1 cleanup/risk/replay/stale checks, source-mutation guards, Batch 2 Window,
  Supervisor failure/termination, approval budgets and C/Python schema fixtures.
- Two isolated real Runtime builds: **23/23 identical outputs**;
  includes nine Root files, quarantined image and Runtime manifest. Both validate
  against current dependencies. The earlier 21-output partial build is not reused
  as this result; neither is the historical 26-output Native-capable image build.
- SourceGuard Workspace/Export PASS; **1722 input files unchanged**.
- Real installed-file inspection: nine files VERIFIED_READ_ONLY, runtime_qualified
  remains false. New current-host Runtime verification passes independently.
- Actual readiness: both read-only checks pass; policy NOT_ACTIVATED and human
  grants missing. Original `installed_release()` still rejects old dependency SHA.
- Ordinary-UID actual quarantined-image rejection test: exit 1 with the exact
  guard diagnostic, before installer code. No Root/Native/traffic.
- Ruff/Format/Diff PASS. Full unrelated Workspace/Export suites were not rerun;
  prior full-suite Operator/Zeek failures are not declared resolved.

Initial failures were retained in evidence directories -1 through -3 and focused
logs. Two implementation/setup issues were corrected: strict Contract JSON-array
normalization for dependency tuples (roundtrip regression added), and separating
fixed Root Python identity from the user-owned build interpreter. Existing
termination tests also depended on the real host installed version. Their
first-install fixture now uses an absent temporary installation path, and their
explicit post-preflight fault injections mock environment preflight. All existing
failure/cleanup/signal assertions remain. The real host mismatch is independently
rechecked and still blocked; production preflight/Root gates are unchanged.

### Exact new identities (quarantined preparation only)

| Item | SHA256 |
| --- | --- |
| Source Snapshot | `eccf7ad1ef6d890c165550cde1b74e0be87b78d7724a761b1c7e08c44b289ab5` |
| Recovery Runtime Manifest | `a96f84ac2644e9446ac53669e5e8e53f6c503e4ec38c9df6b8970815ad10ca40` |
| Runtime Bundle | `a76bfe6b152ceab18490135aaedea87c5bb64ea182b42838065c5ec9faa9c7fe` |
| Quarantined Image | `00a6e346136d0ed8d303be5a78261791bc70bb51fec7a30200691e5de8f7afbd` |
| New Root Manifest | `73230abe317ecdb9fe359bb0dfe7c1fbf74b14d2011ea11c783845c97c1c9f4d` |

The label remains 0.6.3 but the identity is the distinct
`SOC_QUARANTINED_RUNTIME_CANDIDATE_V1`; it cannot be passed off as an approved
`SOC_PHASE_D_UNIFIED_V1` execution artifact. The source build began from bed73a9
plus the explicit reviewed diff. Final Commit/Tree/remote confirmation is recorded
in `git-delivery.json` after the commit; artifacts contain no self-referential Git
commit field. Source inputs and artifact hashes are rechecked after commit.

### Remaining approvals, evidence and budget

No policy activation or positive R1 decision was created. Human policy approval
must cover using independently verified retained-file evidence for replacement
admission while keeping all new runtime/authentication checks. A future activated
Supervisor image must receive a new exact-SHA approval. R1 independently requires
named reviewer Identity, explicit risk acceptance, exact new Session/Release/SHA/
Scope, evidence pins, latest-ledger/expiry/replay validation. The original FAILED
and false remain; owned historical cleanup VERIFIED, global cleanup UNVERIFIED,
Program 1145 removal cause UNKNOWN. No unknown program was removed.

Campaign Native/Root **2/10 each**, Batch 2 Native/Root **1/2 each**, unchanged.
No real Root authentication/install, Native run, capture, DNS traffic, real R1
receipt issuance or ledger append occurred. P02/P03 remain INCOMPLETE; P04 remains
historically 0/7 ELIGIBLE. Native AI/DNS9/production remain BLOCKED.

Changed operational files: `runtime_recovery.py`, `reassessment_admission.py`.
Tests: new runtime recovery tests, retained draft specification/tests, isolated
Supervisor termination fixture. Existing user edits and installed/rollback files
are excluded from staging. Only this work's explicit seven-file change is committed
on `fix/native-stabilization-batch2`; no main/force push.

Evidence: `.git/native-stabilization-batch2/runtime-recovery-integration-20261027-4/`
in the original repository, including qualification/source snapshots, both build
logs/artifacts, retained-installation.json, actual-readiness.json, final-preservation
and Git delivery records. Approval preparation in this directory remains unsigned
and is not a production receipt.


# SOC Native Stabilization Batch 2 — Operational Integration (2026-10-27)

## Overall Status

**Operational integration implemented; nonprivileged verification PASS.
POLICY_APPROVAL_REQUIRED; actual execution BLOCKED.** No real policy activation,
human reassessment, installation, Capture or R2 traffic occurred. This section
supersedes the earlier need for additional Supervisor integration code. It does
not revise any previous Native FAILED/false/INCOMPLETE or UNKNOWN evidence.

## Runtime Recovery Integration

- Actual entry: `soc-agent native-recovery prepare|reassess|check|execute`, routed
  through existing `soc_agent.cli`. Worktree: `../native-soc-phase-d-release-063`,
  branch `fix/native-stabilization-batch2`.
- `prepare` reuses `phase_d.prepare -> prepare_candidate ->
  prepare_supervisor_image -> prepare_unified_image`. `RecoveryBuild` selects the
  separate prepare-only path; it never declares the old runtime compatible.
- Installed preservation uses the actual fixed-path/held-FD nine-file inspector.
  Old Root Manifest remains
  `f5b54fbbac173e05ab6bfc246612d409d1dc966a9fcab5635daadea8c1117ab3`.
  The original strict `installed_release` still returns DEPENDENCY_HASH_MISMATCH.
- New recovery binding pins old/new Root identity, full retained-file observation,
  new dependency inventory, implementation, TCX/R2 Scope, ABI report and current
  host/toolchain metadata. ABI/host files are independently SHA-bound. Current
  zlib remains `ubuntu2.3`, SHA
  `f61677c7bdb7c2aa2a243ea781bfd16afcb361cede7b4ef76127a9d8eb9a5242`.
  Old zlib SHA remains
  `86200da370f20476a2507e9097a789b5ef97269b4ca8d5e164ad82dab9d99892`.
- Actual Supervisor image/sidecar/Phase D contracts now carry the recovery binding.
  Unlike the earlier unconditional-quarantine SDK image, these are complete
  **policy-pending Supervisor templates**. Without a policy receipt, Controller
  and embedded Root continuation both deny execution. They are not promoted to
  executable approval candidates merely because they build and hash correctly.
- A separately SHA-pinned `SOC_RETAINED_REPLACEMENT_POLICY_V1` human approval must
  name an approver/reference, exact binding and validity period. It authorizes the
  retention-verification rule only, explicitly not Root or Native execution.
  An operator-supplied receipt SHA is the existing trust anchor, not a signature
  or automatic reviewer discovery. No ignore-dependencies/force flag was added.
- Normal install/authentication paths are unchanged. Only an approved recovery
  image can use Root `_apply(previous, check)` to revalidate exact old files
  before the existing quiescent archival operation. New dependencies, OS policy,
  new installation and post-installation checks remain mandatory. Unknown drift
  fails closed, and incompatible old bytes are never executed for verification.

## R1 Approval Integration

- `reassess` accepts separately pinned procedure/review/evidence files and calls
  the existing `reassessment.reassess` under its locked append-only writer.
  It does not synthesize reviewer Identity, risk acceptance or an ALLOW decision.
- `check` projects existing validators into SOURCE_VERIFIED, RUNTIME_VERIFIED,
  POLICY_APPROVED, R1_REASSESSMENT_VERIFIED, R2_SCOPE_APPROVED,
  ROOT_INSTALL_APPROVED and NATIVE_EXECUTION_APPROVED. It is not a new persistent
  state machine and cannot start work from a state transition.
- Non-consuming `preview_reservation` checks exact new Artifact/Scope, previous
  Root identity, loaded-source Git Commit/Tree, current amendment/ledger/review,
  expiry/replay and both budgets. Mock/draft contracts cannot satisfy the real
  schemas; successful synthetic tests use temporary ledgers and explicit mocks
  for OS/artifact observations, never real execution authority.
- `execute` requires EXECUTION_READY, repeats checks, then uses the existing
  `ReassessedCampaign.reserve -> phase_d.execute -> Supervisor` path. Reservation
  is atomic and conservative; post-reservation failures follow the existing
  finish/failed accounting and never retry. Preflight/check itself consumes none.
- A recovery image cannot use direct Supervisor execution without an approved
  R2/Campaign reservation. R2 reservation and review expiry are checked again
  before its claim/authentication boundary. Existing FAILED/false and Program
  1145 removal cause UNKNOWN remain, independently of a new human decision.

## R2 Launcher Integration

- Capture Ready: ATTACH acknowledgment must include link evidence before starting
  the existing launcher. Scheduling timestamps are user monotonic observations,
  not invented Kernel packet or per-CPU coverage evidence.
- TCP Close: existing authenticated DNS probe result supplies
  `socket_closed_monotonic_ns`; missing/changed/reversed observations fail or
  remain explicitly INCOMPLETE.
- 35s observation: elapsed time uses monotonic nanoseconds relative to TCP close.
  Additional UDP requires Sidecar CLOSED and actual send/receive timestamps that
  satisfy the 35s bound and ordering; a failed attempt is never retried.
- 45s STOP: existing Supervisor normal STOP/Drain/Cleanup is requested relative
  to TCP close. Event/capture limit reached early or no witness stays INCOMPLETE.
- Fixed scenario: net:[4026531833], lo/Ingress, local 127.0.0.53:53,
  native-0516.localhost. A; total UDP 2/TCP 1, events 4096, Queue32, admission50ms,
  reorder10ms, Checkpoint16KiB, address space256MiB, CPU20s, execution300s.
  Initial Sidecar capture7s/32 packets/512-byte snaplen and analysis10s are
  unchanged. The late UDP is a TCX observation; no second DNS Sidecar is started.
- Launcher never declares Flow completeness/ELIGIBLE. Actual TCX packet/window/
  counter/clock/termination evidence still determines Network14 eligibility.
  Existing failure propagation, SIGTERM handling and independent cleanup remain.

## Integration Verification

- Related Workspace: **454 PASS (145.10s)**.
- Independent Export: **454 PASS (115.61s)**.
- Actual CLI/image pipeline concentrated tests plus R1/R2: **64 PASS**.
- Includes existing 368-test baseline scope plus operational entry tests,
  Installer/Runtime/Unified handoff and existing terminal-CLI tests. Full unrelated
  repository pytest was not rerun; prior full-suite failures are not relabeled.
- Failure injection covers missing policy/receipt, invalid issuer/schema/expiry,
  bound SHA/Session/Scope/Git mismatch, root/native grant omissions, stale/replay,
  old file tamper, image tamper, R2 missing close/witness, timestamp invalidity,
  early capture end and existing DNS/STOP/Cleanup failure contracts. No assertion
  or limit was weakened. A copied-image tamper fixture was corrected to point
  its descriptor at the modified copy rather than the untouched original.
- Added a confirmed CLI exit-code fix: returned first failure, last_error or
  unverified Cleanup now yields exit1, not a misleading success exit0.
- SourceGuard: **1725 frozen inputs unchanged** in Workspace/Export.
- Reproducibility: common unprivileged Stage plus independent A/B builds,
  **28/28 files identical**, including full Supervisor image, Root files,
  recovery ABI/host evidence, sidecar and Phase D manifests. Common Stage is an
  existing supported deployment-path input, never the Root install destination.
- Actual pending-artifact CLI check returned exit2, SOURCE/RUNTIME VERIFIED,
  POLICY BLOCKED, no reservation or execution. Ruff/Format/Diff PASS.

## Artifact Identity

These identities are policy-pending templates, not Root/Native grants:

| Item | SHA256 |
| --- | --- |
| Source Snapshot | `d855dcf4402b211062d1ebf590dc178f369541d73c48a8d127e24eaef3801fc6` |
| Manifest | `d28e3b9f349c8b378373c9e241c667ea26c69304c6871357af5a9d6b92e8c2d4` |
| Bundle | `f51a016e2cef5e509d283f5e7fdeacba170215b2d2c4e20f035f3cc3035c6dd4` |
| Supervisor Execution Image template | `e8dd87772351b3e02cbe9a2faebf2f36b15eb0f6e36a4177306c42fa255e6822` |
| Root Manifest | `eee9d6372060fa3114fee449836d8a727a9fdb45c3078bf24ab8a4179ba5d87f` |

The source began at b12d62c plus this explicit change. Final Git Commit/Tree and
remote match are recorded after commit in `git-delivery.json`; post-commit source
and artifact hashes are rechecked. Git metadata is not embedded as a circular
self-hash in generated artifacts. The complete dependency inventory and host/
compiler/interpreter identities are in the manifests and `recovery-host.json`.

## Git

Only this work's explicit files are staged on the existing fix branch. No main
or force push; original user working tree and its eight edits are preserved.
Final commit/push confirmation is included in the response and evidence record.

## Campaign Budget

Native **2/10**, Root **2/10**; Batch 2 Native/Root **1/2 each**, unchanged.
No actual Root authentication, installation, Native run, Capture, DNS traffic,
real R1 review issuance or actual ledger append occurred.

## Remaining Approval Requirements

1. Human policy owner reviews the exact retention/runtime binding and issues a
   valid pinned RecoveryApproval under AGENTS §33. Current policy SHA is null.
2. Re-run the **same** prepare CLI into a new output directory with
   `--policy-file` and `--policy-sha`. No further code changes are needed. This
   creates a new image/manifest SHA containing the human grant; current pending
   hashes must not be silently promoted or inherit old execution approval.
3. Human R1 review binds that final Artifact, Session/Scope, evidence and explicit
   UNKNOWN-risk acceptance; use the existing procedure and the new `reassess`
   CLI to append the separate decision. Supply the separately approved R1
   AdmissionAmendment. Original false remains.
4. Supply R2 TrafficReceipt (including unique claim path) and exact Root/Native
   execution receipt. `check` is non-consuming; `execute` is explicit and still
   requires one user-entered OS TTY password. Passwords never pass through code,
   files, environment variables or captured stdin.

All receipt examples in tests are synthetic. The evidence-directory pending
policy-review template is not a valid approval receipt and cannot enable work.

## Remaining Blockers

P02/P03 actual Capture/Flow evidence remains INCOMPLETE; P04 actual eligible count
remains historical 0/7. Native AI, DNS9 and production remain BLOCKED. Historical
owned cleanup VERIFIED/global cleanup UNVERIFIED and external Program1145 removal
cause UNKNOWN are preserved. No fresh privileged snapshot was claimed.

Evidence: `.git/native-stabilization-batch2/operational-supervisor-integration-20261027-1/`
in the original repository: qualification/source maps, both builds/Stage, actual
CLI readiness, pending policy template, preservation and Git delivery records.


# SOC Native Execution Management — Pre-execution Cancellation & Reservation Recovery

## Overall Status

IMPLEMENTED_AND_NONPRIVILEGED_VERIFIED; policy activation and actual historical
reservation disposition remain pending. No Root, Native, Capture, traffic,
refund, consumed-approval reuse or historical settlement occurred.

## Root Cause / Existing Path

Legacy execute consumes approval and counts a reservation before Supervisor
preparation, exact-Scope human confirmation and OS authentication. Terminal
SIGHUP previously had its default action, bypassing Python cleanup and the
reservation finish path. The past attempt's actual termination cause remains
UNKNOWN; the missing SIGHUP boundary is an independently reproduced structural
failure path, not a claim about the historical signal.

The unfinished attempt is 0c74eddb14764d399d5a9d1d57ab5cdd, Session
710c9d9a-7d87-466d-9566-ea55253d834d. New actual read-only CLI inspection reports
EVIDENCE_INCOMPLETE with Root/Native UNKNOWN. Missing Session files and unchanged
installation do not manufacture a cancellation receipt. The original consumed
approval, false and FAILED records remain immutable.

## Operational Code

- `execution_management.py`: existing private GovernanceDatabase transactions
  persist a bounded hash-chained lifecycle, process start-ticks/boot identity and
  one-shot launcher lock. Restart inspection distinguishes a live owner from a
  dead/reused PID or changed boot. Corrupt/missing/truncated evidence fails closed.
- Existing `reassessment_admission.execute` and `phase_d.execute` thread an
  opt-in control object through the **same** Supervisor. A valid pinned
  ManagementApproval is mandatory; absent approval retains the old strict path.
- With that policy active, existing exact-Scope confirmation happens before
  reservation. Atomic reservation reuses all current SHA/Scope/R1/R2/Ledger/
  budget/replay validators. User absence or refusal before confirmation makes
  no reservation and invokes no authentication or traffic.
- Write-ahead AUTHENTICATING is committed before the OS call. Root files verified,
  Native start intent and actual Attach acknowledgement are separate markers.
  Auth cancellation or crash during an external-operation gap remains UNKNOWN,
  rather than being relabeled no-use. Only confirmed observations say STARTED.
- SIGHUP joins SIGINT/SIGTERM in the existing cleanup boundary. SIGKILL/WSL crash
  cannot run handlers; durable observations support later review without replay.
- `settle` requires **both** valid policy activation and separate human
  SettlementApproval, exact implementation/attempt/evidence/ledger-tip pins,
  and no prior closure. CANCELLED_BEFORE_EXECUTION needs a matching validated
  write-ahead journal with no auth; absence of evidence cannot satisfy it.
  Human-approved settlement appends EXECUTION_RESERVATION_SETTLED_V1 only.
  Reservation charges and consumed receipts remain held. UNKNOWN settlement
  does not bypass existing Native safety gates or prove Cleanup.
- `execution_request.py` is a strict pinned packet of existing CLI arguments,
  not another executor or approval authority. Unknown fields, changed directory,
  relative paths, argument overrides and missing policy pins are rejected.

## States / UX

APPROVED → AWAITING_USER_CONFIRMATION → USER_CONFIRMED → RESERVED →
AUTHENTICATING → ROOT_INSTALLATION_VERIFIED → NATIVE_START_INTENT →
NATIVE_CAPTURE_STARTED → COMPLETED/FAILED. Pre-auth termination is separately
CANCELLED_BEFORE_EXECUTION; external-operation uncertainty remains UNKNOWN.
The lifecycle is ordinary-user evidence, not a privileged atomicity claim.

Existing CLI modes remain prepare/reassess/check/execute. A launch packet lets
the operator invoke existing execute with `--request-file` and its generated
pin instead of manually copying every grant/SHA. All validators still run.
The user retains the existing one exact-Scope yes/cancel interaction and direct
OS-TTY password; no extra Enter wrapper is required by the new path.
`check --campaign ... --attempt-id ...` is read-only restart inspection.
`reassess --settlement-file ... --settlement-sha ...` additionally requires pinned
management policy and evidence; check never performs settlement.

## Verification

- Final related Workspace: **489 PASS**.
- Final independent frozen Export: **489 PASS**.
- New focused lifecycle/settlement/CLI tests: **29 PASS**.
- Stage / independent Build A / Build B: **28/28 identical**, full file sets match.
- SourceGuard and start/end maps: **1,728 inputs unchanged**.
- Ruff / Format / Diff: PASS (1,385 Python files format-checked).
- Failure injection covers pre-confirmation close/refusal, auth uncertainty,
  Root-before-Attach failure, Native failure, duplicate launcher, expiry while
  waiting, actual SIGHUP in an ordinary process, simulated changed boot/dead
  owner, evidence corruption/missing data, replay, unavailable policy, separate
  Root/Native classification and interrupted settlement append.
- A partial append to a temporary campaign ledger is left untouched and rejected
  by the existing framing guard; it is not silently repaired or refunded.
- Mock/Synthetic dispatch and bounded builds are not Native Capture evidence.
  Existing Native/Flow/Counter/Checkpoint/Approval/Supervisor suites are preserved;
  no assertions were weakened. Unrelated full-suite historical issues are not
  claimed resolved.
- Earlier 488-test/build qualification is preserved but superseded by final
  execution-management-20261027-2 after the settlement activation gate tightened.

## Source / Artifact Identity

| Item | SHA256 |
| --- | --- |
| Source Snapshot | `57ce65a9c0809a60c30755c1e9f90f345b998d46e2ebebc886a3f0f11e9af1cf` |
| Manifest | `e7ff3f037d6959611ea1f752288b68bad8994f7690745ce1d69faeca87e12742` |
| Bundle | `3923c8dd5e6d9bb9a6378828575a5285545195c5d36ede7a0202642bd2cd80e7` |
| Execution Image | `cee5c34f0b30774749a32221bc7ef73b9781eab4e6c263584a24bbe98d3180da` |
| Root Manifest | `a75c302b8938529f16c978311d86662c04b79d0b2c6b51a0dd9ad0c32cdb293e` |
| Management implementation | `995b7862a00a1ef0c88894f2d60b6d57ca6531c539084d08e864ea5dd6dceea0` |

These are **policy-pending** nonprivileged artifacts. Actual check returns
RECOVERY_POLICY_APPROVAL_REQUIRED; they inherit no prior policy/R1/Root/Native
approval. Current zlib security update is retained; installed files and rollback
identities are unchanged. Final Git commit/tree and push are recorded after
commit in git-delivery.json; Git metadata is not a circular artifact self-hash.

## Preservation / Budget / Remaining Approval

Actual execution Ledger remains 11 rows, SHA256 `b1d0f7d6d2d4c2d9d5521cc44dbb1d7505f8340d50888a2120e20583a5ba01ac`.
Protected user/historical112, Native evidence49, current installation9 and
historical installation/Rollback234 files match. The campaign reservations
remain Native/Root3/10 each and Batch2 Native/Root2/2 each, including one
unfinished reservation. Previous completed usage remains two each; no new
execution or settlement is asserted.

Required decisions are explicit policy activation for the new path and a
separate evidence-based disposition of the old reservation. Refund/reallocation
is not implemented as an automatic consequence of cancellation and requires its
own authorized campaign change. Current Batch2 budget remains fully reserved;
UNKNOWN/EVIDENCE_INCOMPLETE cannot be passed as a safe-to-run decision.
Fresh artifact-bound Recovery/R1/R2/Root/Native approvals remain required before
actual P02/P03/P04 verification. New source hashes invalidate old grants.
P02/P03 remain INCOMPLETE, P04 historical Native eligible0/7, NativeAI/DNS9/
production BLOCKED. No further collector/feature redesign is needed for this
management change; actual Native qualification awaits those human decisions.

## Git / Evidence

Only this task's eight code/test files and this report section are selected for
commit on the existing fix branch. All pre-existing uncommitted report text is
preserved in the working tree and captured as a patch; it is not silently added
to this commit. Original user worktree's eight edits remain untouched. No main
or force push.
Evidence: `.git/native-stabilization-batch2/execution-management-20261027-2/`:
qualification, source maps, Workspace/Export logs, Stage/A/B, actual read-only
historical inspection, pending-runtime check, policy/settlement proposal,
preservation proof and post-commit delivery identity.

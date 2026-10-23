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

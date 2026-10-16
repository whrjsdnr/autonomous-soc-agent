# Streaming clock, checkpoint stability and Native readiness

## 1. Baseline and scope

Validation date: 2026-10-16. SOC baseline:
`872ec3ade420426f6ed24a8ce793830f1b50ccb2`; ML baseline:
`e1a01260f0463a38d4d778859bc2a86f8e9cfbde`. Both were on main,
aligned with the recorded origin/main, with an empty index. Initial private
inventories recorded 122 pre-existing SOC files, 10 ML files and 124 retained
native-evidence/model files, including hashes and the exact index. They are
preservation inputs, not changes in this commit. No existing session, DB,
dataset, model or Replay file was edited. No dependency was installed.

Machine-readable, sanitized observations and source bindings:
[streaming-clock-checkpoint-evidence.json](streaming-clock-checkpoint-evidence.json).
Private diagnostics retain system logs locally; host names and log payloads are
not published. This work performed no privileged execution, capture, generated
traffic, clock adjustment, NTP configuration or WSL restart.

## 2. Read-only WSL clock observation

Python 3.12.14; kernel `6.18.33.2-microsoft-standard-WSL2`; clocksource `tsc`.
The read-only timedatectl observation reported NTP=yes and NTPSynchronized=yes.
Boot epoch from /proc/stat was 1792114351. Journal entries recorded boot-time
clock initialization and initial time synchronization. These are observations,
not evidence that synchronization caused the earlier rollback.

The current 30.000850-second probe collected 14,309 paired realtime/monotonic
samples and observed **zero backward UTC steps: NOT_REPRODUCED**. Python reports
CLOCK_REALTIME adjustable/nonmonotonic and CLOCK_MONOTONIC nonadjustable/monotonic.
Sampling cannot exclude adjustments between observations or later recurrence.

The previous task's separate 10-second probe recorded 9,181 samples and one
0.470687-second backward UTC step. It remains historical evidence, not a new
reproduction. Host/guest synchronization, wall-clock adjustment and conversion
causes remain **UNKNOWN**. No root cause is attributed to WSL2 itself.

## 3. Clock contracts

| Path | Clock / ordering | Result and limits |
|---|---|---|
| Helper duration, rate tokens | monotonic elapsed; independent finite real interval watchdog | UTC is not a duration source; backwards monotonic input is rejected |
| Native handshake, authentication, shutdown | asyncio wait_for / loop.time | Finite waits, bounded cleanup; no unlimited retry |
| Transport heartbeat | time.monotonic | Two-second freshness; socket timeout remains finite |
| Streaming session / CPU budget | monotonic / process_time | UTC rollback does not extend these deadlines |
| Packet timestamps | kernel timestamp ns with UTC representation | Preserved; never replaced with ingestion UTC |
| Flow IDLE / ACTIVE | packet event time: 30s / 120s | No wall-clock expiration or invented watermark |
| Producer duration / IAT | first/last observed packet ns | Network14 order, float32, configuration and meanings unchanged |
| Model worker / investigation timeout | asyncio wait_for | Worker 0.1–30s; research investigation 20s; no replay on UNKNOWN |
| Streaming queue | durable token + exclusive writer recovery | No expiring UTC lease or lease stealing; interrupted inference is not recalled |
| Checkpoint | UTC created/updated, revision CAS, trace sequence | New explicit rollback rejection; existing validators remain |
| Audit | UTC event time plus append sequence/digest chain | UTC is retained even if adjusted; sequence provides ordering, not timestamp sorting |
| Receipt | worker UTC inferred_at | Event metadata, not latency; latency is measured separately |
| GUI | monotonic observation-start ordering; UTC display label | Slow older polls cannot replace newer state; uptime is monotonic |

An event-time rollback is distinct from an ingestion UTC adjustment. If actual
packet timestamps go backwards, aggregation remains fail-closed. With no later
packet, active flows do not become IDLE by wall time; shutdown remains diagnostic.
This preserves the training Producer's time meaning and can limit Native inference.

Legacy Authentication finding retry scheduling (`RuntimeStore.claim` next_attempt)
still uses persisted UTC across restarts. Clock rollback can defer that schedule;
it is not a streaming lease or an authority-expiry bypass. This limitation is not
reported as monotonic-stable or silently rewritten, particularly because unrelated
Authentication service changes are user-owned. Governance/approval UTC validation
was not relaxed. Physical-server clock behavior remains unqualified.

## 4. Checkpoint root cause and minimal fix

The original WorkflowCheckpoint validator raises the same
`Invalid checkpoint progress metadata` for updated_at < created_at **or**
rounds > round_limit. Fixture tests reproduce both. Earlier failing checkpoints'
field values were not captured; their actual causal attribution remains UNKNOWN.
Increasing monotonic time cannot make invalid persisted UTC metadata valid.

A separate implementation defect was reproduced before the fix: CheckpointStore
accepted a successor updated_at earlier than the previous updated_at, provided it
was still after created_at. The new regression initially returned **1 failed,
3 passed**. This is a verified successor-validation defect, not proof of the old
intermittent exception's root cause.

Changes are limited to:

- Typed `CheckpointClockRollback` with code CHECKPOINT_CLOCK_ROLLBACK.
- Runtime UTC comparison against the committed updated_at before claiming a step
  and again when building its successor. No clamping, sleeping for time to catch
  up, synthetic timestamp, changed schema or new time abstraction.
- Independent successor-time comparison inside the existing store transaction,
  after CAS/claim validation. Existing digest, revision, references, round limits
  and atomic trace publication remain mandatory.
- Research outcomes classify this exception as
  RESEARCH_CHECKPOINT_CLOCK_ROLLBACK_NO_RETRY. A valid model receipt can remain
  available while the investigation outcome stays UNKNOWN. The completed audit
  entry binds the digest of that classified outcome; no error is hidden.

Before-claim rollback executes no step and leaves the durable checkpoint/trace
unchanged. The current runtime is blocked; a fresh explicit runtime may restore
the unchanged checkpoint. Rollback during a step keeps the durable claim, refuses
automatic restart/resume, and requires existing operator reconciliation. No claim
is cleared merely because time advanced. No existing checkpoint was restamped.

## 5. Fixture, model, GUI and recovery verification

Checkpoint tests cover increasing/equal UTC, before-claim and during-step rollback,
rollback above creation time, explicit restart and unchanged durable progress.
The existing checkpoint suite also exercises competing writers, duplicate/CAS
conflicts, partial publication rollback, commit-response loss, corrupt metadata,
trace/digest binding and interrupted-claim refusal. Equal UTC remains valid:
revisions and sequence, rather than artificial time increments, order steps.

An actual pinned RF inference followed by injected application-only UTC rollback
produced a retained receipt, UNKNOWN investigation, the specific NO_RETRY code,
valid audit, and cached replay with no second inference. This was OFFLINE_PCAP
research evidence, not a new Native session. The streaming tests separately
verify increasing uptime despite backwards store UTC, unchanged active event-time
flows, and GUI monotonic observation ordering.

Actual WSLg Tk start/stop/resize/close/new-interpreter reopen passed with synthetic
streaming input and actual RF/LR workers. Restored receipts are retained history,
current inference count is zero, and collector LIVE remains false without a helper.
No native authentication was launched. GUI product code did not require changes.

## 6. Bounded stability observation

The prior 1,800.978905-second fixture run is reused and explicitly remains from
the previous task: 3,679 synthetic packets, 50 eligible flows, queue DONE=50,
one mock UNKNOWN/circuit-open call, **zero actual model inferences**, and no new
network socket attempts. It is not evidence that the new checkpoint fix ran for
30 minutes. Its original result file was present and read again.

Additional current real-time fixture probe: `python -m tests.streaming_clock_stability`
with --seconds 60 and a fresh private output directory. It completed in
**61.302438 monotonic seconds**: 122 synthetic packets, 3 completed flow records,
1 eligible / 2 shutdown exclusions, queue DONE=1, 2 actual model receipts and
2 READ-only investigations, zero worker failures. Finalization VERIFIED applies
to this fixture only. No kernel capture existed; capture_drops remains UNKNOWN.

Parent CPU 2.212410s; process peak RSS 204,570,624 bytes; final sampled runtime RSS
179,761,152 bytes; peak retained encoded metadata 69,490 bytes; backlog 0 at end;
active metadata 0. Worker resources are separately bounded and excluded from
parent CPU measurements. One-second UTC samples saw no rollback; this does not
rule out subsecond adjustments. Audit digest:
`d33efca337017c7baae281127d4917f7b2066d351a9a2b6cfc065ec1a93e00ce`.

## 7. Helper static security readiness

stream_helper.py unchanged SHA256:
`1cc1c1f39007d1e8f53207dcd5f79f2128b12ea8077d5d09fcb6a72c5d037c84`.
Legacy live_helper.py also unchanged:
`a8a0cafe7494922a0296a250129ab5695b681dbbec6febf512509b023ef44856`.

Static review plus mock tests verify lo-only schema, session/code/interpreter
digest binding, authenticated Unix peer, ordinary UID/GID, empty supplementary
groups, initial CAP_NET_RAW only, immediate capability removal after opening the
socket, NoNewPrivs, finite watchdog/CPU/AS/fd limits, stop/disconnect, sequenced
cumulative counters, UNKNOWN/drop/integrity failure blocking, and no raw payload,
credentials or DNS name retention. Bounding CAP_NET_RAW may remain 8192 while
effective/permitted/inheritable/ambient become zero; bounding alone is not active
capture privilege. No real capability-drop observation was made in this task.

**300 seconds is the default proposed qualification, not the schema's global
maximum**: seconds currently accepts up to 1800. Approval must bind an actual
300-second policy/session digest. At 300s the frame budget is 38,656, token refill
128 raw frames/s plus burst 256, helper CPU cap 35s, helper AS 512 MiB, transport
512 records, inference queue 8, parent RSS policy 768 MiB, disk 64 MiB, graceful
drain 30s. These remain fixture-qualified policies, not measured Native capacity.

util-linux setpriv 2.39.3 help supports the generated flags. pkexec is absent in
this WSL environment; display variables alone do not establish a polkit agent.
The terminal fallback is required. No root GUI or privileged command was run.

## 8. Tests, quality and independent export

Runs overlap and must not be summed as distinct coverage:

| Current run | Actual result |
|---|---|
| Pre-fix new checkpoint regression | 1 failed / 3 passed; demonstrated defect |
| Post-fix full checkpoint suite | 34 passed, 11.00s |
| Initial new targeted clock tests | 2 passed / 1 failed; test fixture used wrong view attribute; corrected |
| Streaming / actual adapter / checkpoint regression | 134 passed, 56.53s |
| Investigation runtime / policy / approval / Linux runtime | 149 passed, 43.47s |
| Actual WSLg streaming GUI | 1 passed, 20.08s |
| Clean independent export, including new integrity test and WSLg | 247 passed, 80.49s |

All guarded current runs above reported zero blocked network-socket attempts.
No privileged helper ran. Existing earlier task pass counts are not claimed as
new executions. SOC Ruff src/tests, whole-tree format and diff checks pass.
ML Ruff passes; **24 existing whole-tree format violations** remain, unchanged.
No ML source or artifact change or commit is needed.

Independent export uses git archive of both baseline HEADs and only this task's
files. Replay and all user changes are excluded. Tests import SOC code from that
export, ML Producer code from the clean ML export, and explicitly reference the
existing trusted interpreter/models without copying binaries. Artifact hashes
are rechecked; export tests do not require capture or privileged authentication.
Final export result: **247 passed in 80.49s**, zero blocked network-socket
attempts. This combines checkpoint, streaming, real research adapter,
investigation runtime, policy, approval and actual WSLg tests. The report/evidence
were then synchronized into the export and their references/hashes checked.

## 9. Verdict and remaining blockers

Overall **PARTIAL**. Current clock probe: NOT_REPRODUCED. Checkpoint rejection,
successor integrity, no-retry recovery and streaming timeout behavior are verified
under fixtures. Historical checkpoint incident root cause remains UNKNOWN;
recurrence of host/guest UTC adjustments is not excluded. Helper security is
STATIC/MOCK READY for a separately approved bounded qualification, not Native E2E
verified. GUI state and audit/recovery pass the scoped tests. Legacy UTC retry
scheduling and physical-server qualification remain limitations.

NATIVE_CONTINUOUS_CAPTURE_PENDING; OPERATIONAL_PROMOTION_BLOCKED. Existing
NOT_INFERABLE / RESEARCH_ONLY / WRITE_DENIED boundaries remain. No model,
Producer contract, native packet event timestamp or approval policy was changed.

## 10. User-only five-minute Native qualification — approval required

This procedure is prepared for a **new separate approval**, not execution under
the old helper approval. Proposed scope: one fresh lo-only session, at most
300 seconds / 38,656 raw frames, 128/s refill plus 256 burst, temporary CAP_NET_RAW
only on the dedicated helper, normal user UID/GID, immediate capability drop,
metadata-only retention, no external traffic or OS security WRITE, no operational
model promotion. No new traffic generator is included in this scope.

1. After approving that scope and the current helper SHA, launch the normal-user
   GUI using the existing entry point:

   ```bash
   cd ~/kdt-linux/autonomous-soc-agent
   .venv/bin/python -m soc_agent.gui
   ```

2. Open Streaming Network, select Quality/Edge, Start Monitoring. Inspect the new
   session's policy (seconds=300 and frame_budget=38656), helper SHA and session
   digest. READY listener / authentication-required is preparation, not capture.
   Copy the current GUI-generated helper command; never reuse an old session.
3. In the user's own terminal authenticate with `sudo -v`, then paste the exact
   generated command. It uses sudo -n, /usr/bin/setpriv, the current numeric
   UID/GID, --clear-groups, --bounding-set=-all,+net_raw,
   --inh-caps=-all,+net_raw, --ambient-caps=-all,+net_raw, --no-new-privs,
   the pinned Python with -I -m stream_helper's full module, --directory and
   --session-digest. The GUI neither collects a password nor runs sudo itself.
   Only the freshly generated command contains the real session values.
4. Observe READY and zero active capabilities, counters, packet/flow/queue rates,
   drops/gaps and worker state. Stop (drain), Ctrl+C, disconnect or the finite
   watchdog ends collection. Do not retry failed sessions or UNKNOWN inference.
5. Preserve READY/HEARTBEAT/CLOSED, final counter sequences, persistence/flow
   exclusions, receipts, investigation, audit and checkpoint outcomes for
   read-only verification. Capture success alone is not AI inference success.
   IDLE eligibility still requires a later event after >=30s; without a qualifying
   flow, inference remains pending. Any controlled owned-loopback traffic scenario
   requires its own explicit approval and must not be silently added here.

Codex has not executed steps 2–5 for a Native session. Do not copy a command from
this documentation with guessed paths/digests; the prepared listener and generated
command are tied to one reviewed session.

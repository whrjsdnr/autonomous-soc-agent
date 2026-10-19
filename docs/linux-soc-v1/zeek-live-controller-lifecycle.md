# Zeek Live controller lifecycle and terminal handoff

Scope: implementation, non-privileged tests and independent Git export. Native Zeek
capture, sudo authentication, test traffic and security WRITE were not executed.
Native AI, DNS9 parity and operational promotion remain BLOCKED.

## 1. Historical failure and cause classification

Historical session: `session-2a98f1b45f674ff8a7c63dd6f140f232`.
Its six files were read only and hashed before changes. SQLite integrity is `ok`;
the three-record existing audit chain verifies. Records stop at INITIALIZED,
COLLECTOR_PREPARED and ZEEK_LIVE_PLAN_PREPARED. Controller identity was PID 2810358,
start ticks 28471151; that process is no longer running. process.json,
launch-failure.json, stream.jsonl and Native capture success evidence are MISSING.
The existing empty stop.request is preserved exactly.

**Actual Controller exit cause: UNKNOWN.** No exit signal, Stop actor or Stop reason
was retained. File modification timestamps put Stop roughly 80.30 wall-clock seconds
after preparation, and launcher.lock roughly 1.84 seconds after Stop. Those filesystem
times are observations, not a monotonic execution trace. They cannot establish when
the process died or whether the user closed a terminal/window, stopped the collector,
or encountered a crash. User Stop is not assumed.

In the old code a pre-existing stop.request rejects the launch at the reuse guard,
before `_controller()` is called. That rejection occurs outside the failure-sidecar
handler and the terminal prints only ZEEK_MANUAL_LAUNCH_FAILED_CHECK_SESSION. This
explains why the observed file state can occur without process.json or failure JSON;
the exact historical exception remains unrecorded.

Separately, code/fixture investigation verified three implementation defects:

- Approval waiting used `watch_started + capture duration + 20 seconds`; even an alive
  idle GUI would eventually create an automatic Stop. The observed historical file
  timing is shorter than that limit, so this is **not proven as this session's cause**.
- Empty Stop files did not identify reason/actor/session generation, and the old
  preparation path had no actual control listener to prove terminal handoff readiness.
- Terminal-close SIGHUP did not have the GUI's graceful close handler. This is a
  plausible exit path, not a retrospective diagnosis of the historical PID.

## 2. Controller identity and approval contract

New plans use `soc-zeek-native-plan:v2`; old v1 plans are not upgraded or reused.
A fresh UUID generation is part of the plan digest. controller.json binds PID,
/proc start ticks, Session ID, plan digest, generation and a generation-specific Linux
abstract Unix socket address. Zombie processes, PID reuse, mismatched generations,
wrong identities, wrong approval digests and Stop files reject launch before capture.
The new listener is an ordinary-user **control** socket, not the legacy privileged
capture-helper listener and not a new capture source. `handoff_listener_ready` is
separate from the legacy `listener_ready` flag.

The server checks SO_PEERCRED UID and PID, process-start identity, exact controller
identity and operation. Messages are at most 4 KiB, timeout 2 s, backlog 4 and at most
4 active clients. Kernel peer identity is checked on the client too. No password,
raw payload, arbitrary command or privilege operation travels over this channel.

```mermaid
sequenceDiagram
  participant GUI as Unprivileged GUI / Controller
  participant T as User terminal launcher
  participant Z as Bounded Zeek process
  GUI->>GUI: Prepare new plan, bind/listen, audit handoff READY
  GUI->>GUI: Copy: recheck identity, listener probe, current generation
  T->>GUI: claim (session, digest, generation, peer identity)
  GUI->>GUI: audit LAUNCHER_ACCEPTED; consume command once
  GUI-->>T: ACK
  T->>T: terminal OS authentication (user execution only)
  T->>GUI: validate same accepted launcher and live controller
  T->>Z: explicit scoped start (not executed in this task)
  Z-->>GUI: bounded metadata / READY / CLOSED
  GUI->>GUI: drain, verify, audit CLOSED, close control listener
```

## 3. Terminal handoff and deadlines

Prepare does not authenticate, invoke a helper or capture. A serving listener is
established before the command becomes valid. Copy performs a real Unix probe and
rechecks session/digest/generation before modifying the clipboard. Acceptance consumes
the command; a second claim is denied, even if the first client disappears before ACK.
The accepted launcher revalidates after terminal authentication and during execution.
A missing controller/listener after startup requests bounded collector cleanup.

**Waiting for user approval has no Capture Deadline.** It consumes no capture
privilege and is cancelled by explicit Stop, GUI close or verified failure. After a
launcher is accepted, incomplete authentication/start has a 90 s watchdog; terminal
sudo authentication retains its existing 60 s bound. Actual process observation
starts a separate monotonic runtime deadline. The inner Zeek runtime/resource limits
are unchanged. Capture does not automatically restart.

## 4. Stop request semantics

New Stop files contain reason, Session ID, plan digest, generation, actor identity and
monotonic observation time. They are created exclusively, never deleted to reactivate
a session, and never overwritten by later cleanup. Repeated Stop preserves the first
reason and creates no duplicate Stop audit record.

| Reason | Trigger |
|---|---|
| USER_STOP | Operator Stop |
| GUI_CLOSE | Closing the GUI window |
| CONTROLLER_EXIT | Gracefully handled SIGINT/SIGTERM/SIGHUP; dead-controller rejection sidecar |
| PREPARATION_CANCELLED | Failed new preparation after its own store was created |
| LAUNCH_FAILED | Authentication, identity, listener, startup or integrity failure |
| COLLECTOR_EXIT | Verified normal collector completion and finalization |
| TIMEOUT | Accepted-launch/process watchdog |

Stop invalidates the command and closes the listener before cleanup. SQL/Audit write
failure cannot prevent the Stop signal. An uncertain audit append is not retried as a
successful operation; ERROR and unverified audit status persist. New-session preparation
failure does not append into or rewrite a previous session's evidence.

SIGHUP now follows the production GUI's close path with CONTROLLER_EXIT. SIGKILL cannot
run GUI cleanup; the launcher detects loss of its controller and records a bounded
sidecar. If both controller and launcher are killed, the existing inner container
watchdog still bounds capture; immediate Native cleanup in that case is unverified.

## 5. Reviewed error codes

The terminal and GUI display a reviewed code, never a Pydantic dump, exception text,
credential, approval argument or private path.

| Code | Meaning |
|---|---|
| ZEEK_CONTROLLER_NOT_RUNNING | Controller exited or is a zombie |
| ZEEK_CONTROLLER_IDENTITY_MISMATCH | PID ticks/session/generation/plan/peer mismatch |
| ZEEK_SESSION_STOP_REQUESTED | Existing Stop invalidates launch |
| ZEEK_SESSION_REUSE_DENIED | Already consumed/attempted session |
| ZEEK_APPROVAL_DIGEST_MISMATCH | Approval does not match the new session plan |
| ZEEK_DOCKER_START_FAILED | Local process spawn failed |
| ZEEK_CONTAINER_EXIT_UNVERIFIED | Bad process exit or missing verified CLOSED |
| ZEEK_LISTENER_UNAVAILABLE | Control listener missing, closed or nonresponsive |
| ZEEK_PROCESS_DEADLINE_EXCEEDED | Accepted launch or process exceeded its bound |

Authentication failure, bundle mismatch, stream/counter/integrity and persistence
errors remain separately classified. Native pcap-statistics validity and Native
producer admission are still unverified; their gates are not bypassed.

## 6. GUI

The four pages, charts, cards and timelines remain. System shows authentication/
launcher phase, controller alive, control listener, COMMAND_VALID, generation, Stop
reason and Last Error. Copy is disabled for stopped, failed, accepted or stale
commands. A new generation invalidates the prior command. Existing monotonic snapshot
guards reject stale responses. If the backend thread exits, the GUI clears the
command and reports ERROR instead of waiting forever for its future.

The screenshots in `zeek-live-lifecycle-screenshots/` are actual WSLg preparation
screens at 1920×1080 and 1366×768. Environment checks are mocked; authentication,
Native capture and model inference are absent. They are UI evidence only.

## 7. Audit and recovery

Existing audit hashing/transactions are reused; no chain is rewritten. New events
include TERMINAL_HANDOFF_READY, LAUNCHER_ACCEPTED, LAUNCHER_REJECTED,
COLLECTOR_STARTED, COLLECTOR_STOP_REQUESTED, COLLECTOR_CLOSED and CONTROLLER_EXITED.
Each controller event binds session/digest/generation. The handoff verifies the
existing audit before authorizing a claim; corruption rejects authentication/start. CONTROLLER_EXITED describes
session-controller release, with `os_process_exit_observed=false`; it does not pretend
the OS process had already exited when it emitted that event.

When the controller cannot append, the launcher writes bounded, exclusive rejection
sidecars (at most 8). Existing Audit files remain unchanged. A Stop tombstone rejects
future launch. Recovery of a cancelled pre-launch v2 session verifies the committed
Stop-file digest and restores a stopped, non-launchable view. Incomplete launch remains
blocked. Old v1 sessions are read-only and non-launchable. Completed fixture receipts
restore without replay. No unfinished inference or Native capture is restarted.

## 8. Tests and independent export

Exact test runs, resource preflights, artifact identities, source SHA maps and export
results are recorded in `zeek-live-controller-evidence.json`. Verification denies
sudo/pkexec/setpriv, Native Docker capability/network options and AF_PACKET/IPv4/IPv6
socket creation. Unix sockets and owned test children are allowed.

Tests cover live control handshake, delayed approval beyond the old deadline, PID
reuse/start ticks, wrong digest/generation, repeated Prepare, new-session reset,
Stop/copy races, authentication cancellation, spawn failure, bounded idle clients,
GUI close, real SIGHUP of a WSLg fixture GUI, SIGKILL of an owned fixture controller,
Audit preservation, cancellation recovery, stream drain and no automatic replay.
All child fixtures explicitly report NO_CAPTURE. Actual Native execution is absent.
The existing streamed offline PCAP/RF/LR/read-only-investigation test is reused to
check completion and receipt recovery under the new controller lifecycle.

Initial development failures were retained: old function re-export/test expectations,
recovery without an active handoff object and repeated cleanup after an audit failure.
They were corrected with regression coverage. They are not counted as passes or
hidden by unmodified retries. Historical SIGILL root cause remains UNKNOWN.

| Independent Export run | Result | Scope |
|---|---|---|
| Main unit matrix | 443 passed | Collector, producer, streaming, GUI, research adapter |
| Stream/controller | 13 passed | Owned child signals, streaming and offline packet parity |
| Actual model integration | 1 passed | RF/LR receipts 2, READ-only investigations 2 |
| WSLg GUI | 9 passed | Four pages, charts, controller and existing GUIs |
| Audit/governance | 125 passed | Policy, approval, checkpoint, audit, transport |
| Final affected lifecycle matrix | 63 passed | Final audit authorization guard, lifecycle, GUI, streaming |
| Final actual model integration | 1 passed | Final source, RF/LR 2, investigations 2, no restored inference |
| Final public evidence / contracts | 57 passed | Source hashes, screenshots, receipts and lifecycle |

These runs overlap and are **not summed**. The main matrix preceded the final audit
claim guard; the affected lifecycle and model runs then verified the final source.
Model integration used actual Zeek offline processing with a synthetic golden PCAP;
its origin is ZEEK_OFFLINE_PCAP. Final queue peak/final: 7/0; inference queue: 2/0;
finalization PCAP_REFERENCE_FINALIZED. Audit digest after recovery equals the original;
restored new inferences: 0. Each model run is a separate session in the evidence JSON.
No skip, OOM, SIGILL or timeout was treated as a pass. Before the final model run,
MemAvailable was 4.28 GiB and memory PSI avg10 was 0.00. Models ran serially.

Workspace Ruff (`src tests`), format (`.`) and diff checks pass. Clean export Ruff,
format and offline wheel build pass; the wheel contains byte-identical final handoff,
launcher and Zeek policy files. The final public evidence checks are rerun after
document/evidence finalization; unchanged model tests are not needlessly repeated.

## 9. Performance

Before/after profiling uses the same interpreter, WSLg host, clean baseline export,
three fresh GUI processes per side and the existing 3 s idle profiler. It measures
startup, RSS, CPU, callback latency, worker/owner counts and SQL calls. Exact numbers
and their scope are in the evidence JSON. No Native CPU/RSS/throughput is inferred
from GUI or fixture measurements. No research views or visualizations were removed.
| Median of 3 fresh idle processes | Before | After |
|---|---:|---:|
| Startup | 2.466 s | 2.152 s |
| Idle RSS | 175.043 MiB | 174.859 MiB |
| Idle CPU (% of one core) | 0.272% | 0.243% |
| Callback p95 | 0.084 ms | 0.046 ms |
| Threads / idle children | 2 / 0 | 2 / 0 |
| Background async tasks / controller SQL statements | 0 / 0 | 0 / 0 |

Short samples and host scheduling noise apply; this does not establish a causal
speedup. The user's earlier 2.296 s / 174.98 MiB reference was a separate run. Active
Native performance is UNKNOWN. The handoff creates a server only after explicit preparation; default idle startup
still does not create a collector, model loader or capture process.

## 10. Remaining blockers and Native approval

Controller/handoff fixture verification does not verify Native capture. Native AI,
DNS9 and operational promotion remain BLOCKED; the historical Controller exit reason
remains UNKNOWN. Existing helper v2/v3, their manifests, rate/resource policies,
models, datasets and session evidence are unchanged.

Changed product files: `collectors/handoff.py`, `live.py`, `live_contract.py`,
`live_process.py`; GUI `__main__.py`, `backend.py`, `production.py`, `operator_view.py`.
New lifecycle/unit/owned-child/WSLg tests and immutable public evidence checks accompany
them. Existing contract tests were updated for v2; historical public evidence retains
its original v1 bundle identity.

New review identities:

- Launcher SHA256: `576309afd409f14b8fd6002710bdd59fe375e82ad895e163b25b4727ce7fa66c`
- Bundle digest: `bbd017c2ba8f3a7903270ec67c1e06a63ba53ae6aa04c1aa1ba2f6fc413e46bb`
- Image: `zeek/zeek@sha256:3fac39de707be96cb1a8163cab98a11bb2a1aa9e3535247db0f17b9c4670a019`
- Contract: `soc-zeek-native-plan:v2`; Session ID, generation and approval digest are
  generated afresh. The source hash map is in the evidence JSON.

Preservation checks matched all 132 original dirty SOC/ML files and 220 protected
artifact/evidence files. The 58 raw dataset files retained size/mtime/inode; they
were not rehashed or opened for processing. Original stages were empty and preserved.
Only this task's files enter the independent export and selective commit.

The revised launcher and v2 approval contract require **new SHA/bundle review and
separate user approval**. Old Zeek commands and old session directories must not be
reused. Do not remove stop.request.

Preparation only (ordinary user; keep this GUI process/terminal alive):

```bash
.venv/bin/soc-agent start --gui --monitor total --collector zeek-live
```

In System select Zeek Live, Prepare, confirm CONTROLLER_ALIVE/listener/COMMAND_VALID,
then Copy collector command. After reviewing and separately approving the new scope,
run that exact fresh command in a second interactive terminal:

```bash
.venv/bin/python -m soc_agent.security_ai.collectors.live_process \
  --session '<fresh v2 session directory>' --approve '<new plan digest>'
```

Only the user executes authentication/capture. The unchanged proposal remains lo/IP
only, 300 s, CPU quota 1, memory 512 MiB, temporary disk 16 MiB, metadata spool 8 MiB,
4,096 packet records, NET_RAW-only container and the pinned Zeek 9.0.0 image. Container
NET_RAW is retained for its bounded lifetime; post-open capability removal and Native
permission/namespace behavior have not been verified. There is no root GUI or password
storage. GUI Stop/close cancels the current command; fresh preparation is required
after rejection, completion or Stop.

After a separately approved run, inspect reviewed terminal/GUI codes, session and
generation binding, launcher acceptance, process exit, CLOSED, queue drain and audit.
Exit=0 or zero reported drops alone does not authorize Native AI. No Native success
is declared in this report.

## 11. Verdict

CONTROLLER_LIFECYCLE_VERIFIED, TERMINAL_HANDOFF_VERIFIED, SESSION_IDENTITY_VERIFIED,
STOP_REQUEST_SEMANTICS_VERIFIED, ERROR_PROPAGATION_VERIFIED, GUI_STATE_VERIFIED and
AUDIT_RECOVERY_VERIFIED apply to non-privileged fixtures and offline model recovery.
NATIVE_ZEEK_CAPTURE_PENDING; NATIVE_AI_BLOCKED; DNS9_PARITY_BLOCKED;
OPERATIONAL_PROMOTION_BLOCKED. Overall Native E2E remains PARTIAL.

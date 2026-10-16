# Live Network research advisory: implementation and operator validation

Status: **IMPLEMENTED_BUT_NOT_LIVE_VERIFIED / PARTIAL**. Actual privileged
capture and live-source inference have not been executed by Codex. The new
helper requires a separate user review and execution; earlier Manual Capture
v2 approval does not authorize it. Commit/push is pending operator evidence.

Base SOC HEAD: `df96d37d951e0fdf3ba047768aa024dbf353052a`.
ML HEAD: `e1a01260f0463a38d4d778859bc2a86f8e9cfbde` (unchanged).
Measured fixture results and source hashes are in
[live-network-advisory-evidence.json](live-network-advisory-evidence.json).
Existing Final Demo evidence, raw datasets and model artifacts are preserved.

## 1. Architecture

```text
User executes reviewed setpriv command in their terminal
    → bounded lo AF_PACKET helper, UID/GID unchanged
    → socket opened, capabilities dropped, verifiable READY
    → bounded authenticated AF_UNIX metadata channel
    → existing NetworkMonitor / NetworkPipeline
    → existing EventQueue / OperationalSourceStore / provenance
    → committed eligible Flow + referenced packet metadata
    → existing Network Producer 1.1.0 / Network14
    → existing isolated ResearchAdapter worker / pinned Quality or Edge
    → research advisory / existing READ-only Orchestrator / checkpoint
    → existing research audit ledger / Tkinter GUI
```

The new code composes the existing monitor and research service. It does not
introduce a second persistent queue, collector engine, policy engine or agent.
The in-memory inference handoff holds at most eight durable flow references.
Source writes run under the existing runtime writer lock. Research dispatch
uses the existing replay lock, attempt/receipt records and governance store.
It does not write an attached Authentication runtime or operational model registry.

## 2. Permission model and audited environment

Current account UID/GID is 1000/1000. The unprivileged controller's capability
snapshot is recorded in the evidence JSON. Both existing Python interpreters
have no `security.capability` xattr. No capabilities, sudoers, firewall, NIC,
DNS, routing or installed environment were changed.

`pkexec` is not installed in this WSL environment. No usable graphical Polkit
authentication path was established; no authentication UI was invoked. The
supported path is user-terminal authentication. Installed `setpriv` is
util-linux 2.39.3; its actual help lists the UID/GID, cleared groups, bounding,
inheritable, ambient and no-new-privileges options used below. Codex did not
execute sudo, pkexec, a capability-bearing setpriv command or a capture probe.

The command requests **only CAP_NET_RAW**, with UID/GID retained, supplementary
groups cleared and NoNewPrivs=1. Bounding-only configuration is insufficient:
the command also explicitly provisions inheritable and ambient NET_RAW for
exec, and the helper rejects missing/extra Effective/Permitted/Inheritable/
Ambient/Bounding sets. Actual delivery remains pending user execution.

The helper opens one non-promiscuous socket, then capset clears Effective,
Permitted and Inheritable sets and verifies Ambient is also zero. Bounding
remains 8192; NoNewPrivs remains 1. No Python file capability is installed.
The controller independently verifies SO_PEERCRED, process start identity,
interpreter SHA, exact module/arguments, all four UID/GID values, cleared
groups, capability sets and the raw socket inode/lo ifindex in `/proc` before
accepting metadata. This is a trusted local-user boundary, not remote attestation.

## 3. Capture helper and scope for review

New executable module:
`soc_agent.security_ai.operational.network_capture.live_helper`.

Reviewed helper SHA256:
`9699cd29f14851287d03e8883ddc765c95a89e9e8169281b4be0b949bff4d87d`.
Related source digests are pinned in each private session and in the evidence
JSON. A code/session/interpreter/interface change is rejected before opening
the capture socket. If this helper SHA changes, stop and review a new approval.
The original `native_probe.py` and `manual_capture.py` remain unchanged.

Initial supported interface: **lo only**. Eth0, other NICs and physical Linux
are not authorized or validated by this implementation. Capture uses a
60-second watchdog, a normal receive target of 59 seconds to leave cleanup
time, and at most 512 received raw frames. It stops earlier at the frame
limit, Ctrl+C, GUI Stop, peer disconnect or an error. There is no retry or
automatic helper restart. The observer's authentication wait is 120 seconds.

Loopback outgoing observations are retained once; host/incoming clones are
excluded. First-observed flow endpoint direction remains distinct from host
packet direction. Kernel SO_TIMESTAMPNS, interface identity, IP total length,
ports and flags are preserved. IPv4/IPv6 TCP/UDP parsing reuses the existing
parser; unsupported/truncated input fails closed. Payload bytes are transient
parser inputs only, never persisted or sent to the model. DNS metadata/names
are stripped before transport; DNS inference is not connected.

The helper has a 512 MiB address-space cap, 10 CPU seconds, no core dumps
and 64 file descriptors. It reports measured CPU/RSS and kernel counters.
Its code only receives from the raw socket. An already open AF_PACKET socket
is not made kernel receive-only by dropping capabilities: this Python helper
is not a kernel sandbox against compromised trusted code. No packet injection
is implemented or performed.

## 4. Producer parity and flow eligibility

Network Producer 1.1.0 and its 14 features are unchanged. Feature contract:
`84ba0916f0ce4e9e12bb70712db2cd1eaea84ba4173acd57b647faf38efb1c6e`.
Configuration digest:
`7999723911ce3d2e9cd3b3b6e0d45e11f44b1316cdf9c7f4883d7e2a69ca21a7`.

The diagnostic summary uses Ethernet frame lengths and cannot substitute for
Network14. The bridge reloads referenced, committed packet records and their
source/provenance chain, then supplies IP total bytes and integer nanosecond
timestamps to the actual producer inside the existing worker. No missing
feature is zero-filled. Source origin remains NATIVE_AF_PACKET or explicit
FIXTURE; it is never relabeled OFFLINE_PCAP.

Synthetic Ethernet packets pass both the SOC packet parser and the separately
implemented ML PCAP parser, covering IPv4/IPv6 and TCP/UDP. Their metadata and
14 float32 results are compared with a hand-calculated reference. For IP
lengths 40/60/80, forward/reverse/forward at 1/1.5/2 seconds, the independent
reference is duration 1, counts 2/1, bytes 120/60, min/max/mean 40/80/60,
population std sqrt(800/3), SYN/FIN/RST 1/1/0 and IAT mean/max 0.5/0.5.
Origin-bound source/feature digests intentionally differ; feature values,
names, order, dtype and configuration must agree.

Native timeout comparisons now use kernel nanoseconds rather than truncated
datetime microseconds. Boundary tests cover 30 seconds ±1 ns, and the Native
and ML flow implementations are compared on the same timeout sequence.
Idle=30 s / active=120 s remains fixed for inference. Only IDLE_TIMEOUT and
ACTIVE_TIMEOUT flows are eligible. SHUTDOWN, RESTART_GAP and native 128-packet
resource slices remain DIAGNOSTIC_ONLY; they are not treated as the training
producer's larger flow window. Existing diagnostic contracts are preserved.

This verifies **synthetic wire/metadata parity**, not physical NIC/offload
behavior or complete capture. Even zero observed kernel drops does not prove
no unobserved traffic, and bounded capture has a startup gap. Capture quality
therefore remains UNKNOWN and operational approval remains BLOCKED.

## 5. Live research inference

Reviewed artifacts are reused in place:

- Quality RandomForest: `53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603`
- Edge Scaler + LogisticRegression: `661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882`

Live mode is explicit and separate from the fixed offline replay request.
Native requests require the authenticated receiver and durable source binding;
a standalone Native request without that authority is rejected before a worker
starts. The worker verifies the reviewed producer code, feature/configuration
contract, model manifest, SHA, model type and backend versions before inference.
It uses the same bounded process launcher, parent-death handling, timeout,
CPU/address-space/output limits and network denial as the existing adapter.

Each bounded session allows at most 16 dispatch attempts with concurrency one,
no retry of unknown outcomes and a circuit breaker after two unknown failures.
Model dispatch is triggered only by a newly committed eligible flow. Status
polling never runs inference. Session/flow/profile keys prevent duplicate
calls; a cached request with changed source metadata is rejected. Interrupted
attempts remain unknown and are not automatically resumed. Post-capture model
draining is bounded at 90 seconds and is not displayed as live collection.

The referenced passing fixture run used actual artifacts on one persisted synthetic
flow: Quality score 0.140625, Edge 0.08766025304794312, both CLASS_0 at the
existing thresholds 0.35/0.8. Recorded latency was 11.262505 / 6.179628 ms and
worker peak RSS 233779200 / 233000960 bytes. These are FIXTURE integration
measurements, not live traffic, detection accuracy or a controlled benchmark.
The receipt JSON records CPU, source/feature/artifact digests and timestamps.

## 6. SOC investigation, audit and recovery

Research receipts extend the existing advisory context with capture session,
flow identity, source/feature/provenance digests, artifact, output and validation
level. Scores are uncalibrated. A successful result enters the existing guarded
READ-only Orchestrator and checkpoint path; provider calls are zero in the
SCRIPTED research investigation. Tool evidence contains bound metadata only;
model output is not promoted to observation or attack fact. No operational
Security Finding, response approval or security WRITE is generated.

The existing attempt/receipt audit ledger is reused; source audits bind the
verified READY and terminal receipt digests. A new GUI/backend instance restores
retained receipts as history with no active helper. Current LIVE status requires
the authenticated process, matching start identity, fresh heartbeat and active
controller task. No saved RUNNING bit can make a restarted GUI LIVE. Closing
this GUI stops its own live companion and worker, and disconnect tells the
bounded helper to stop. Existing separately owned SOC Runtime remains untouched.

Audit tampering, source deletion, replay conflicts, timeout, worker crash and
backpressure have focused rejection tests. Actual privileged-helper crash and
capability delivery are still pending operator execution, not claimed verified.

## 7. GUI

Keep the existing one-command launch:

```bash
cd ~/kdt-linux/autonomous-soc-agent
.venv/bin/python -m soc_agent.gui
```

Dashboard links to **Live Network**, separately from Offline Research. The Live
page shows permission, collector/input state, Quality/Edge worker state,
confirmed/unknown counts, packet/flow rate, drops/gap, queue, results and
Investigation/Audit details. Empty or unavailable measurements remain NO_DATA /
UNKNOWN. The traffic plot uses actual measured metadata rates only.

States are distinct: LIVE_COLLECTION, LIVE_RESEARCH_INFERENCE and
OPERATIONAL_INFERENCE_BLOCKED. This implementation never emits
OPERATIONAL_INFERENCE_APPROVED. Neither preparing a session nor running a
research model grants operational readiness. Model counters are per session;
retained receipts are explicitly not fresh live inference.

## 8. User execution: required next step

**Codex stops before this step. The user executes authentication and capture.**

1. Check the helper source hash in your own terminal:

   ```bash
   cd ~/kdt-linux/autonomous-soc-agent
   sha256sum src/soc_agent/security_ai/operational/network_capture/live_helper.py
   ```

   It must exactly equal the reviewed SHA above. If it differs, do not run.

2. Launch the GUI, open **Live Network**, choose both / quality / edge and
   click **Prepare live session** once. This starts only an unprivileged
   observer. Review lo / 60 seconds / 512 frames and the displayed SHA.

3. In your terminal authenticate directly with `sudo -v`. The application
   must never ask for or store that password. Then paste the exact command
   from **Copy helper command**. Its form is:

   ```text
   sudo -n /usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all,+net_raw --inh-caps=-all,+net_raw --ambient-caps=-all,+net_raw --no-new-privs <verified SOC Python> -I -m soc_agent.security_ai.operational.network_capture.live_helper --directory <GUI-created private session>
   ```

   Use the GUI's complete quoted command, not literal placeholders. The GUI
   generates the exact interpreter/path/UID/GID for that session; no JSON edits
   are needed. If `sudo -n` or READY verification fails, stop and report it;
   there is no automatic authentication retry or alternate elevation path.

4. Confirm LIVE_COLLECTION / verified dropped capabilities in the GUI. Only
   traffic from your own loopback applications is in scope. Codex does not
   generate traffic. To yield an idle-timeout flow, finish a small owned local
   exchange early in the window, then allow 30 seconds idle before the helper
   ends. No traffic means zero inference; shutdown-only slices are excluded.

5. Stop with Ctrl+C in that terminal, **Stop live**, or the automatic bound.
   Wait for worker shutdown and stored results. Review source NATIVE_AF_PACKET,
   RESEARCH_ONLY, uncalibrated output, Investigation and Audit. Keep the session
   directory shown as the helper command's `--directory` argument.

6. After the helper and workers finish, verify saved evidence as your ordinary
   user (no sudo, no capture or model execution):

   ```text
   .venv/bin/python -m soc_agent.security_ai.research.live_evidence --directory <the exact GUI-created session directory>
   ```

   Send the resulting JSON and session directory to Codex. This reader verifies
   queue/source/provenance, receipt binding, audit/checkpoint, capabilities,
   bounds and SQLite hashes without replay or queue recovery. Missing/invalid
   primary evidence returns BLOCKED; absent eligible model results cannot be
   counted as live inference success. Keep raw/private stores out of Git.

Actual E2E verification, final evidence update and commit/push resume only after
these user-produced results. The previous Manual Capture SHA/approval is not
reused. No actual privilege execution was performed to prepare these steps.

## 9. Tests and remaining limitations

Current runs (separate executions, not summed): new unit/integration **35 passed**;
actual WSLg prepare/Stop/layout **1 passed**; Capture/Adapter/DNS/GUI/evidence
regression **292 passed**; Runtime/Governance/Self-Improvement subset **183 passed,
1 failed** because an old test defaulted to a deleted `/tmp` environment.
That failed test alone then **1 passed** using the existing verified persistent
artifact/interpreter paths, with no installation or file modification.
One earlier new integration run failed in its negative-test setup (changed IP
length violated packet schema before the intended cache check); the fixture
was corrected and the complete focused set subsequently passed.

Network socket guards blocked the one intentional permission-denial test;
all new live tests made zero packet/INET socket attempts. Actual model runs
were on explicit FIXTURE metadata; crash/peer rejection tests use mocks.
The final nanosecond/Capture/live-unit run passed 150 tests; the final independent
export passed all 36 new tests. Results are separate executions, not additive.
Ruff check, repository format check and git diff check passed. The evidence JSON
records these results.

Remaining live blockers: user execution of this new helper, actual capability
delivery/drop and READY inspection, real packet/flow source binding, actual
Native-input Quality/Edge calls and real helper-stop/crash evidence. No eth0,
external traffic, physical Linux, DNS9 operational producer, model promotion,
new training or real security response has been authorized or validated.

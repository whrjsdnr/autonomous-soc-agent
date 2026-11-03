# Authentication lifecycle final integration

## Scope and implementation

This change reuses `LinuxAuthenticationCollector`, the reviewed Journal parser,
`EventQueue`, `OperationalSourceStore`, `LinuxMonitor`, `RuntimeStore` and the
existing GUI. It does not implement another Host collector or model. The baseline
is release `ceaeb1c`; changes live on `release/research-demo-mvp` in
`releases/research-mvp`, a worktree of the main repository. The main worktree's
original modifications remain untouched.

`Agent CLI start --gui → existing application/native admission → ContinuousRuntime.run
→ AuthenticationLifecycle → existing linux_runtime start → LinuxMonitor.tick →
Collector/Parser → Queue → Source Store/Authentication Window → Runtime Store →
Continuous observed_snapshot → GUI project` is the managed collection path.
The existing TCX receiver, DNS producer, Network14 workers, SOCRuntime and exact
RF/LR/API GUI decisions remain separate.

`ContinuousConfig.managed_authentication` is explicit opt-in and defaults to null.
An `authentication_runtime` by itself continues to mean attach/read status only.
Managed collection requires a session-owned `runtime/authentication` directory,
the same parent incident/session identity, a pinned code identity, READ_ONLY mode,
no API env-file, no configured network collector, and an exact unexpired human
approval. Approval input binds both configuration digests, UID, Namespace, duration,
fixed selector and executable identity. Existing `ApprovalManager`, `PolicyEngine`
and `GovernedExecutor` enforce that decision. No receipt is issued or approved by
start, doctor or preview.

Before spawn a private, exclusive durable start intent prevents replay, including
failed attempts. The fixed Python child argv invokes the existing Linux Runtime.
There is no shell, configurable command, elevation or new system service. The child
inherits the parent's cgroup/Namespace and uses one numerical-library thread.
Only a freshly matching PID/start/UID/boot identity plus successful initial journal
poll permits READY. Process exit, changed identity, failed state or a monotonic
heartbeat age of five seconds fails supervision. Existing TCX/DNS 2/5-second
contracts are unchanged. Authentication blocking Journal/SQLite work runs in the
owned child, not the TCX receive loop.

On STOP the parent signals only its owned same-identity child, waits a bounded five
seconds, and, if needed, kills/reaps that same child. Forced termination is never
clean STOP ACK. Exit zero alone is insufficient: matching identity, STOPPED state,
no runtime error, verified audit chain and STOPPING/STOPPED records are also
required. A new private `authentication-cleanup.json` retains the result. This is
owned Authentication process/store evidence, not global Kernel cleanup. Existing
pending work/checkpoints are retained; process cleanup does not mean every
investigation completed. Authentication failures participate in the parent's
existing first-error and subsequent-cleanup-error handling. No auto restart occurs.

## Proposed Host collection policy — NOT activated

- Source: existing bounded `journalctl --no-pager --quiet --output=json` reader.
- Exact selector: `SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 + _COMM=sshd`.
  This is the existing auth/authpriv-or-sshd selector, **not an exact systemd Unit
  allowlist**. If approval requires exact Units instead, this selector cannot be
  represented as equivalent and collection must remain blocked.
- Access: ordinary user's existing read permission only; no sudo, group change,
  authentication attempt, synthetic Host login, or Journal configuration change.
- Duration: explicitly reviewed integer 1–600 seconds; the approval must cover it
  plus the five-second cleanup allowance. Parent Launcher total deadline and
  existing Runtime CPU/memory/PID/storage limits still apply.
- Session: parent UUID, code/config digests, UID and Namespace bound automatically.
- Minimization: trusted OpenSSH/PAM parser emits normalized pseudonymous account/IP
  identifiers; raw MESSAGE and original account/address are not GUI evidence.
  Cursor and source provenance remain retained. Source assurance remains declared
  Host Journal input; TCX capture attestation is not applied to it.
- Retention: session-local existing queue/source/audit databases; no automatic
  deletion, policy promotion, old Session adoption or reprocessing of old PENDING/
  POISON entries. Parent storage accounting includes the nested directory. Existing
  queue capacity, retry, deduplication and retention contracts remain in force.
- Rule thresholds are operator supplied and explicitly unvalidated; attaching a
  previously initialized store does not approve its thresholds or Host collection.

Actual Host collection and IF execution remain unapproved in this task.

## IF artifact and admission

The existing fixture package `tests/fixtures/security_ai_packages/authentication_anomaly`
is validated without calling inference. Its numeric model JSON SHA256 is
`a1e42f399d3ddaaf876753e0a2e1f3a2a9ad1956e1ed82ce99e5abdb02becc7a`.
Package inventory SHA, frozen selection, preprocessing profile, ordered features and
numeric forest structure are checked by the existing package loader.

Feature order is `failed_login_count`, `successful_login_count`, `total_login_count`,
`failure_rate`, `login_attempt_rate`, with witnessed 300-second windows. The profile
configuration threshold is 0.95; the manifest's **raw operating-point** threshold is
0.5604416052073505. These are different score spaces and are not interchangeable.
A later retained event, not passage of wall time, witnesses a complete window.
The last partial window stays incomplete.

The package is a fixture/training reference, not an approved Host deployment. Its
internal training/package parity does not establish Native Host distribution,
threshold validity or inference authorization. Current aligned profile has no
approved IF package. GUI/Runtime expose NO_APPROVED_PACKAGE or insufficient-window/
exact-action-and-Native-training-contract blockers with zero predictions. This
change does not manufacture an IF action grant or claim actual IF Prediction/
Incident E2E success. Existing read-only rule incidents/audit are retained separately.

## GUI and operational boundary

Authentication has its own collector/runtime state, event/window totals, IF admission
reason, prediction count and managed cleanup state. GUI reconnect projection keeps
these fields even when a separately attached store supplies a status snapshot.
A stopped/crashed owned process is not presented as RUNNING merely because an old
store snapshot says so. Native Host and fixture evidence must be labelled by the
actual source; the tests below use fixtures and do not verify Host collection.

The prior alignment script and its frozen `ceaeb1c` review remain preserved. Its
attach-only profile is not silently converted into Host collection authority.
Likewise the installed management Wheel remains a separate frozen artifact until
an explicit validated release update. Source changes require a new exact
Source/Artifact/Session binding; old Root/Native/model/API receipts cannot be reused.
The earlier proposed Root installation scope remains three changes and five
verification-only paths. This task does not install any of them. A new manifest
must compute the final diff rather than assuming those counts are approval.

After the new release/profile and independent permissions have been reviewed, the
existing entry points remain:

```bash
soc-agent doctor
soc-agent start --preview
soc-agent start --gui
soc-agent status
soc-agent stop
```

Until then use doctor/preview only. `setup --native-review` and
`--authentication-runtime` are existing supported options; attaching a directory
is not authorization to start it. Users do not type SHA or Session UUID values:
existing reviewed profile and internal binding checks supply them. Native launch
still requires direct Scope/R1 confirmation and sudo authentication. Host read,
IF model action, Network RF/LR action and external API authorization are independent.

## Verification record

Results, exact commands, preserved initial failures and reproducible build hashes
are recorded in the task evidence directory listed in the accompanying final
verification section. No real Host Journal, Root installation, Native capture,
DNS traffic, inference or external API request is part of this verification.

## Existing frozen profile CLI check

The actual `.venv/bin/soc-agent doctor` and `start --preview` were executed against
`release-session-alignment-20261103T083037Z/operator-home`, without starting anything.
Preview verifies the **old frozen** review and returns
`PREVIEW_ONLY_REQUIRES_DIRECT_SCOPE_R1_AND_SUDO`, Root8 three proposed writes/five
verification-only paths, Ledger81 and no reservations/capture/Root execution.
Doctor correctly keeps the Namespace-internal check BLOCKED outside the target and
reports `AUTHENTICATION_ATTACH_ONLY_NO_HOST_COLLECTION_AUTHORITY`. This is not a
preview of newly managed Authentication: the reviewed old runtime remains frozen
at `ceaeb1c`. Updating just the management CLI cannot upgrade its runtime, scope or
permissions. A newly reviewed runtime/config binding is still required to use the
managed integration in Live mode.

The first ordinary-disk full regression run retained an existing missing-TCX-ACK
elapsed-time assertion failure (7.624 seconds versus <6.5). Its unchanged isolated
case passed. A second ordinary-disk run retained a different existing Root Audit
`fsync` release-to-seal two-second timeout. Both logs are preserved; neither
assertion nor production timeout was increased. A tmpfs fixture-storage comparison
is recorded separately below. These observations do not identify the past Native
TCX stall's root cause, and do not verify real-disk latency under the Live cgroup.

## Runtime proposal details

For a later 600-second total / 360-second capture trial, collection duration must
cover Authentication's earlier start and the parent's stop phase. It must not be
set to the capture target and then assumed to remain alive through startup/drain.
A bounded duration such as 420 seconds is a proposal to review, not an activated
default or an extension of existing approval. Runtime CPU 50% / memory 512MiB /
TasksMax32 remain shared with the child; adding the child does not grant another
independent CPU/memory allocation. Verify actual journal readability under that
ordinary UID and service sandbox during a separately approved Live trial. No group
membership, service sandbox or Root path change is performed here.

Fixture command substitution cannot authenticate an OS event. Integration fixtures
exercise the production parser and source identity but are labelled VERIFIED_OFFLINE
in this report; their native-shaped fields are not evidence of actual Host access.
In particular a declared Host Journal source is not cryptographic Native assurance.

## Durable cleanup failure injection

Review found a failure path in the new lifecycle: an ACK could be collected before
writing `authentication-cleanup.json`, so a failed durable write could leave the
in-memory child cleanup field at VERIFIED. It now downgrades to UNVERIFIED, keeps
STOP ACK as an independent fact, marks the lifecycle FAILED and exposes
`durable_cleanup=false`. An injected disk-full error after clean child exit tests
this directly. No Native run was used to find or fix it. Parent cleanup audit is
published only after successful child cleanup evidence storage.

An intermediate ordinary-disk supplemental run retained a pre-existing 1.5-second fixture
completion assertion: one read-only job completed and one remained PENDING at
STOP. The new managed lifecycle tests passed in that run. The pending job was
preserved, not labelled complete. This timing-sensitive fixture result is retained
alongside the two earlier full-suite timing failures; root cause remains UNKNOWN.
Final tmpfs and isolated disk checks are listed below without conflating them.

## GUI display verification

The existing System page now renders the Authentication backend projection, including
windows, IF prediction/admission state, rule-job counts, audit health, STOP ACK and
durable cleanup, in addition to the Dashboard card. A real Tk test opens this page,
checks those fields, closes/reconnects twice and verifies the backend state is
unchanged. Its screenshots are actual GUI renders of explicitly labelled retained
**fixture state**, not screenshots of Host collection or IF execution. The earlier
projection-only reconnect tests remain intact.

The preparer must bind both fields in the **new** reviewed Runtime config (paths
below are placeholders for internally generated paths, not UUID/SHA user inputs):

```json
{
  "authentication_runtime": "<new-session-runtime>/authentication",
  "managed_authentication": {
    "approval_file": "<new-review>/authentication-collection-approval.json",
    "duration_seconds": 420
  }
}
```

The companion store is initialized through the existing initializer using the
parent Store UUID and explicitly reviewed rule thresholds. Its exact `action()` is
reviewed through the existing human approval contract. Config registration alone
creates no decision, Native token, IF action or API authorization. No such live
approval file was generated by this task.

## Final verification and disposition

Code commit: `dd81305ee4754cfbb1b2f66682d642ec4b12abdd`. The final source is identical in Workspace
and independent Export (`958f1ba8d1907d26ec513d69920bf5f55bd2d31435f26169dba838933a49a776`).

| Run | Passed | Pytest elapsed | Storage |
|---|---:|---:|---|
| workspace | 899 | 175.39s | tmpfs fixture databases |
| supplement-workspace | 97 | 42.0s | tmpfs fixture databases |
| export | 899 | 177.3s | tmpfs fixture databases |
| supplement-export | 97 | 44.54s | tmpfs fixture databases |

These suites overlap and must not be added together. Actual model-execution test
files were excluded under the no-inference instruction; their absence is recorded
in the raw commands. The new managed Authentication suite has 11 cases, including
real owned-child ingestion/stop with only the Host journal boundary mocked,
permission rejection, changed code/identity, crash, stale heartbeat, one-shot replay
block, existing IF package validation, GUI projection and durable-write failure.
The full suite also includes real Tk Authentication display/reconnection.

Ruff check, Ruff format check (1,609 Python files), and git diff --check pass.
Native six-artifact, legacy TCX, Supervisor and Wheel builds are identical across
A/B/independent Export. They compile/package only; no BPF is loaded. Wheel SHA256:
`2640b8772f44a7766773cc013f594afe9429eea69bd03cedbf605126c94b1f58`.

The batch validation driver ended with SIGTERM (143) after both complete successful
pytest result/guard files were saved, before starting builds. Its cause is UNKNOWN.
Builds were then run separately and all three matched. This was a development
validation-driver interruption, not evidence of a Native Root Trial failure.

All guards recorded zero violations. Ledger81, installed Root8 SHA/inode/mtime,
797 original failed-evidence files and 164 original user files remain unchanged.
Rollback/installation was not updated. Existing old draft documents were not staged.
No live approval was issued/consumed and no Host Journal/Root/Native/DNS/model/API
operation was executed.

[Portable verification evidence](evidence/authentication-lifecycle-final-20261103/verification.json)
and [actual Tk fixture screenshot](evidence/authentication-lifecycle-final-20261103/fixture-authentication-system-gui.png)
are committed with this report. Full raw logs/initial failures remain under
`.git/authentication-lifecycle-final-20261103T090936Z` in the shared main Git directory.

Disposition: **Authentication lifecycle / CLI / Runtime / GUI integrated and
VERIFIED_OFFLINE.** Ordinary-disk timing-boundary variability remains unresolved;
tmpfs success does not establish production disk/cgroup behavior. **Actual Host
collection, IF inference/training parity and full Live E2E remain UNVERIFIED.**
The existing installed management Wheel and old frozen review were not silently
updated to this candidate. Activate a newly validated release/profile only after
exact Host-read scope approval, refreshed Root/Native/R1 binding and independent
IF/Network-model/API conditions. No claim of FULL_E2E_OPERATIONS_VERIFIED is made.

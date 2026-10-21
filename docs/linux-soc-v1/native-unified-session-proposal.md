# One approval and one terminal authentication per application session

Status: historical architecture proposal, superseded by the implemented
[unified session](native-unified-session.md). Its single approved Native attempt
verified installation/authentication/handoff, then stopped at LOAD_REQUESTED.
The stable updater described below was not introduced: the implementation reuses
a reviewed SHA-pinned standalone installation image and Root-owned sealed handoff.
Prepared after the actual Release 0.4.5 authentication and cleanup qualification.

## Recommended operator flow

The operator runs one ordinary-user CLI, reviews one complete execution plan,
confirms with `yes`, and enters the OS terminal password once. The same application
then performs installation/version checks, Broker qualification, and the explicitly
approved bounded capture. There are no separate A/B/C approval prompts or separate
auth-only and live application restarts in this normal flow.

Command now implemented (see execution limits in the linked implementation record):

```text
soc-agent start --gui --monitor total --collector ebpf-tcx
```

Existing Zeek startup is preserved. Selecting TCX does not silently start Zeek or
combine the collectors' counters. AI, DNS9 and operational promotion stay blocked.

```text
Ordinary-user CLI: version/SHA/resource/namespace preflight
  -> display one immutable installation + authentication + capture plan
  -> human yes (one session-bound approval)
  -> OS terminal password (once, through fixed sudo entry)
  -> trusted installation verification / exactly approved update if needed
  -> Broker identity, IPC, capability and Kernel compatibility checks
  -> one explicitly approved bounded Native run
  -> ordinary-user GUI / Network14 / append-only Audit
  -> Stop, drain, owned-Link release, Broker exit, authorization disposal
```

Each internal check remains mandatory. Failure stops progression, records its first
stage and performs only verified owned-resource cleanup. No automatic retry,
fallback collector, foreign-Link removal or Gate override is introduced.

## Why the current flow asks repeatedly

Current A installs an exact pinned release in a separate sudo invocation. Current B
creates an authentication-only process, drops ALL capability sets to zero and ends
that application. C starts another application with another fresh authentication.
New source fixes have also required new release-specific installation approvals.
Repeated approval is therefore partly a lifecycle/entry-point design issue.

An all-zero, expired B process cannot regain capture capabilities. Persisting its
authentication result, reusing sudo timestamps, or adding a background root service
would not satisfy the existing session policy. The normal unified path must use
one appropriately restricted Broker from its initial authentication to final stop.
The existing auth-only diagnostic can remain as an optional explicit test command.

## One immutable authorization object

Introduce a closed `UnifiedSessionPlan` with a digest covering:

- New application ID/nonce, controller UID/GID/PID/start ticks and expiry.
- Observed installed version, exact target release/Manifest/Bundle and payload SHA.
- Exact installation action or VERIFIED_SKIP, updater/entry SHA and recovery action.
- Namespace, interface/index, hook, program SHA, no pinning/payload/drop policy.
- Duration/event/queue/memory/CPU budgets, explicit run count and no retry.
- Allowed commands, capability profile and startup-password-once policy.
- Native AI, DNS9 and operational Gates fixed at BLOCKED.

The first qualification plan should authorize ONE run: lo/Ingress/current verified
namespace, at most 300 seconds, 4096 metadata events, queue 32, address space
256 MiB and 20 CPU seconds. Per-app restart permissions and total budgets must be
displayed explicitly before later enabling multiple user-requested runs.

Approval binds exactly this frozen plan. It does not authorize unknown future
releases, another interface/hook, extra privileges or another app. A scope change
creates a new plan and requires approval once for that changed plan. Normal phases
within the unchanged plan do not ask again. A password authenticates the operator;
it does not authorize arbitrary root commands.

## Trusted entry and installation

Use OS-controlled sudo with a fixed root-owned entry, fixed argument schema and a
sanitized execution boundary. Retain the proven fresh-password policy, real TTY
identity checks, nonempty local password/account policy and rejection of NOPASSWD
or authentication exemptions. Do not globally invalidate other projects' sudo state.
No GUI password, sudo -S, askpass, stored token or custom setuid binary is introduced.

Installed-matching-release case: verify all versions, Manifest, payload/dependency
SHA, ownership and modes, then skip filesystem mutation and qualify the Broker.
This is the smallest first implementation and handles ordinary repeated startup.

Missing/outdated-release case: show the exact installation/update and rollback
actions in the SAME plan before approval. A stable root-owned session updater,
outside the versioned release being replaced, should execute only the fixed pinned
installer and then hand off to the verified Broker. This avoids updating a running
Bootstrap which the current quiescence guard correctly rejects. No arbitrary
user-supplied executable path, shell, DSO or Python import is accepted as root.

The very first trusted-updater enrollment still needs an explicit exact-SHA trust
decision. It can be packaged with a release installation plan, but must not be
presented as already supported. Current entry.c explicitly denies Native execution;
it cannot simply be renamed or treated as this future updater. Parent-sudo identity,
fresh-command proof, root-created sealed handoff evidence and the closed release
Manifest schema need a reviewed extension for the new fixed entry. Existing root
installation APIs must not be bypassed by launching mutable repository code.

The updater retains old releases atomically without deletion or overwrite. If
installation fails, no capture starts. If installation succeeds but capture fails,
retain the verified installation and report the capture failure; do not automatically
roll back a release while Hook ownership or quiescence is uncertain.

## Broker and privilege lifetime

After installation/verification, immediately leave the root installation role. The
single Broker uses the ordinary application UID with only CAP_BPF/CAP_NET_ADMIN
Permitted/Bounding as currently qualified; Effective is zero when idle and
Inheritable/Ambient remain zero. Activate only required capabilities for validated
Kernel operations, then return Effective to zero. Actual sufficiency for Kernel
load/attach remains a Native qualification item, not a design assertion.

The internal preflight mode has NO Load/Attach authority until every required
check passes under the same approved plan. This differs from the old auth-only
diagnostic, which permanently drops all capabilities and cannot later capture.
The session-purpose digest must distinguish these roles; an old auth-only approval
must never be upgraded into capture authority.

Keep the GUI, Controller, model workers and investigation in the original ordinary
user process tree. They are not spawned by the privileged entry and inherit no
capabilities or privileged Link FD. Broker commands remain closed/schema validated.
Verify peer UID/GID, PID/start ticks, session/approval/Manifest and scope at every
boundary. Broker restart or application exit invalidates authorization; recovery
cannot restore it from a file or trigger automatic auth/attach/inference.

## Lifecycle and control sequencing

```text
PREPARING -> APPROVAL_REQUIRED -> AUTHENTICATING -> INSTALLATION_VERIFIED
  -> BROKER_READY -> PREFLIGHT_VERIFIED -> CAPTURE_STARTING -> ACTIVE
  -> STOPPING -> DRAINING -> CLOSED
```

Failure states include ERROR, CLEANUP_UNVERIFIED and ORPHANED, with no automatic
restart. Installed-release success, OS-authentication success, actual capture and
Feature/AI eligibility remain separate measurements. UNKNOWN is never shown as 0.

Use one owner for the control command queue. STATUS, heartbeat, ATTACH and STOP share
one monotonically increasing verified request sequence across all phases. Do not
restart numbering when moving from preflight to capture. Start the capture deadline
when ATTACH is actually accepted, not while waiting for human input/authentication.

Retain TCX_NEXT(-1), Broker-owned unpinned Link FDs, atomic empty-hook/revision
validation and foreign-filter preservation. Stop requires queue/ring drain, exact
owned-Link cleanup, Broker exit and in-memory authorization disposal. Counter
evidence and Feature quality remain independent of successful process cleanup.

## One approval does not hide failures

The single plan includes all internal stages, so no extra C approval is needed after
a successful internal B/preflight. An unexpected change or failed attempt stops the
transaction. A later retry uses a fresh complete plan; no approval/password is
persisted or silently reused. New code/Manifest requires a new exact plan, once,
rather than three separate A/B/C approvals for that new release.

Audit the one approval and every subsequent phase separately, all linked to the
same session/plan digest. Record Root installation mutations, authentication,
capability observations, actual Kernel IDs/counters, Feature digests and cleanup.
No password/PAM secret/raw payload is logged. Preserve historical Audit unchanged.

## Minimal implementation and verification plan

1. Start with installed-matching-release unified CLI/session orchestration and a
   new explicitly scoped purpose. Keep one Broker alive through qualification and
   capture. Expose no new arbitrary command or privilege path.
2. Add the reviewed stable updater/enrollment boundary for the missing/outdated
   case, preserving exact-SHA atomic install and quiescence/rollback constraints.
3. Verify only core accept/deny, scope mutation, stale version/Manifest, failure
   before attach, shared command sequence, Broker restart and cleanup cases
   (approximately 6-8 focused tests), then the explicitly approved Native run.

Acceptance: one user scope confirmation and one terminal password for one complete
unchanged app plan; GUI stays unprivileged; failed preflight cannot attach; live
events reach the existing adapter; stop verifies only owned resources; Gates remain
blocked. Native verification is still required. This document does not implement
or authorize any root updater, service, Kernel action or automatic release promotion.

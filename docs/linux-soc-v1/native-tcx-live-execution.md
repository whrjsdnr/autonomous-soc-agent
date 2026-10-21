# Phase C-2 Native Live Execution

## Latest unified qualification

Installed 0.5.0 is VERIFIED by exact Root file checks. The single approved unified
invocation completed installation and OS authentication/Broker handoff, then failed
inside native load after LOAD_REQUESTED. No TCX attach/packet/Network14/GUI success
is established; cleanup is CLEANUP_UNVERIFIED. No automatic retry occurred.
See [the unified execution record](native-unified-session.md) for exact scope,
identities, evidence and remaining diagnostics.

## Previous 0.4.5 qualification status

At that qualification the installed release was 0.4.5; exact payload/Manifest/version checks passed.
Actual B authentication, auth-only Broker handoff, all-zero capabilities, STOP
acknowledgment, exit 0 and authorization disposal are VERIFIED for session
bd4bd3e8-a9be-4a7b-a140-9f8e3a827140. C session
4044126a-4f2c-442b-919c-6598958eb2d5 also authenticated/bound its capture Broker:
Permitted/Bounding were exactly CAP_BPF+CAP_NET_ADMIN and Effective/Inheritable/
Ambient were zero. Actual Kernel capability sufficiency remains untested.

C failed in the Controller sequence check before sending ATTACH: initial STATUS
had used sequence 1, but start_live_run hardcoded another 1. No Kernel load,
TCX attach, packet metadata, Network14 Feature or Native GUI occurred. Two data
frames are not two packet observations. Broker exit was 2 and cleanup remains
CLEANUP_UNVERIFIED; no owned Kernel Link was created. No automatic retry occurred.
The source fix uses last verified sequence + 1; four orchestration cases passed.
It is not deployed in the installed source Bundle, so no further Native run may
claim the modified source matches 0.4.5. Native AI/DNS9/operational Gates stay blocked.

The user requested one approval workflow; see [the unified session proposal](native-unified-session-proposal.md).
This is design only, preserving mandatory internal checks and exact new-release
approval. No new updater, service, privilege boundary or Kernel action was applied.
Historical attempts below remain preserved as evidence of their individual stages.

## Initial 0.4.2 attempt outcome

Release 0.4.2 was installed successfully at `/usr/libexec/soc-agent-ebpf` on
2026-10-21 KST. The authentication-only application then failed during ordinary-user
ELF preparation, before requesting OS authentication. No Broker handoff, BPF load,
TCX attach, packet collection, Network14 processing or Native GUI run occurred.
Approval C was not attempted. No automatic Native retry occurred.

## Release identity and Approval A

- Source HEAD: `14c240655cd5c306b191da25f4abf6bc37ad0835`.
- Manifest: `17f85c891df7f5b04026fcf180b6c175fece64752ceb2f2793dd36917e0c910d`.
- Installer: `67d4ebda1ba82a563a623f72f541b7e840b861cba5735b7c6958c553617847da`.
- Source bundle: `464811d02a0f30a3f06069654fe157c1f447bff1b68d0ecc99d26f734e039316`.
- Namespace observed: `net:[4026531833]`; interface lo, intended hook Ingress.

The approved SHA-pinned standalone installer ran through sudo in an ordinary-user
WSLg OS terminal. Its exit code was 0. Password entry remained with the OS terminal;
no password or authentication token was recorded. This installation sudo invocation
is not evidence of successful application-session authentication (Approval B).

The destination was absent before installation. All nine files were independently
verified afterward: exact file set, SHA256, single regular files, root:root,
executables 0555 and other files 0444. Destination directory is 0755. Package,
source bundle and dependency/configuration hashes matched before execution.
`validate_root_release` returned `VERIFIED_READ_ONLY` for installation files.

| File | Mode | SHA256 |
| --- | --- | --- |
| bootstrap | 0555 | `96d0df57066e3f1004a4343d22acbe6c0ca20aef7d6919181e8ca2010dcbbd7d` |
| broker | 0555 | `b872565bcd0abc67c2a5b9c7f96b21d9acb46df582870e303e067c42376254ff` |
| entry | 0555 | `8e4ef82c3fe45ae5a414509316a2922898148ed860bb7ebdde9f743509ce4455` |
| libnative-tc.so | 0444 | `7905693372d14e93162ff7fbeea4068a0094a737663b2403c337630901706536` |
| manifest.bin | 0444 | `8221efca1fb4d81089200e20d79d73a99aacc1cb47772bf7de848babde28ebb1` |
| pam-policy.conf | 0444 | `93af76067bf513b4db8c5a9bd606e348ccde334b83e52f7dc71544c9c1f82696` |
| release.json | 0444 | `17f85c891df7f5b04026fcf180b6c175fece64752ceb2f2793dd36917e0c910d` |
| release.trust | 0444 | `8ec2424921e017a228fd111368f0821bc6bf4e152e6ebd20399f3865f841f52e` |
| tc.bpf.o | 0444 | `928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a` |

Only these nine files were installed. No system PAM/sudoers/NSS configuration,
setuid bits, file capabilities, service, qdisc, filter or BPF resource was installed
or changed by the installer. The reference `pam-policy.conf` stays inside the release.
The installed release remains available; it was not automatically rolled back.
Rollback is the reviewed exact-manifest, quiescent atomic unpublish operation,
retaining files under the manifest-named rollback directory. No rollback was run.

## Approval B: first failure and root cause

Failure: `EBPF_LOADER_PREPARATION_REJECTED`, application
`c4678738-73d9-4941-ad90-a5ba90577253`, exit code 1.

The execution command supplied `artifacts-0.4.2/tcx.bpf.o` to the CLI's `--program`
argument. This was an operator command-selection error. `Application.prepare()`
first invokes the existing Phase-A Inspector, which accepts only `tc/ingress` and
`tc/egress`. The supplied object contains `tcx/ingress` and `tcx/egress`.
The separate `Preparation.os_auth_handoff()` subsequently binds the approved TCX
object hash in the actual privileged scope; the CLI preparation argument is not
that final Native object selection.

Counterevidence to a release integrity or Kernel failure: installation verification
passed; no authentication request was audited; no Kernel operation was reached.
A current-source Legacy preparation object was compiled without privilege, then
passed the same read-only Inspector with two programs/three maps and explicit
`kernel_load=false`, `tc_attach=false`. Its SHA256 is
`69de609ea8ee90ecf90d091ec361e46e61ed0638b3175390c77305145e19d5f4`.
An older retained Legacy fixture did not pass inspection and was not reused or modified.
No production source or installed release was changed to bypass this failure.

Corrected next command, prepared but NOT executed, requires fresh user approval
because the previous application attempt failed:

```bash
PYTHONPATH=/home/geonug/kdt-linux/autonomous-soc-agent/src /home/geonug/kdt-linux/autonomous-soc-agent/.venv/bin/python -m soc_agent.security_ai.ebpf_tc auth-qualify --program /home/geonug/kdt-linux/autonomous-soc-agent/.git/tcx-c2-execution/preparation-only-legacy/tc.bpf.o --inspector /home/geonug/kdt-linux/autonomous-soc-agent/.git/ebpf-loader-audit/export-build/phase-a-loader --artifacts /home/geonug/kdt-linux/autonomous-soc-agent/.git/tcx-c2-unified/artifacts-0.4.2 --data-directory /home/geonug/kdt-linux/autonomous-soc-agent/.git/tcx-c2-execution/auth-session-reapproval-required --package /home/geonug/kdt-linux/autonomous-soc-agent/.git/tcx-c2-unified/release-0.4.2 --manifest-sha 17f85c891df7f5b04026fcf180b6c175fece64752ceb2f2793dd36917e0c910d
```

This changes only the ordinary-user preparation object. The privileged TCX program,
Release 0.4.2, Manifest and intended B auth-only purpose remain unchanged. The new
application must display its fresh purpose/session digest and obtain terminal
approval/password. No BPF action is allowed in B. C remains conditional on successful
B shutdown and a separately validated scoped execution.

## Audit, process cleanup and preservation

The failed application's five-event audit chain was verified read-only:
INITIALIZED → SESSION_PREPARED → PHASE_A_ERROR → STOP_REQUESTED → CLEANUP_VERIFIED.
This last event describes ordinary-user preparation cleanup, not Native TCX cleanup.
Final chain digest: `49b49f2cc21f6640d19be149606f5fae00133a3ac4b3945b8e447f270a291f74`.
There was no OS_AUTH_REQUESTED event, no privileged Broker or owned Link from this
attempt, and no authentication authority to revoke. Native Link cleanup is untested.

Read-only TC inspection afterward showed the lo noqueue qdisc and empty Legacy
ingress/egress filters. This does not establish global TCX Link absence or support.
TCX capability, verifier, attach, live counters and existing TCX state remain unverified.
No test traffic was generated. No packet/Feature/queue/loss/Native GUI measurements
exist for this attempt; unknown values are not reported as zero observations.

All 132 pre-existing SOC/ML user-file hashes and the prior qualification document
were preserved. Existing Native sessions, model artifacts, datasets, Audit and Replay
were not reused, altered or committed. Private execution receipts and the new
application database remain under `.git/tcx-c2-execution/`.

## Verdict and remaining approval

- TRUSTED_INSTALL_NATIVE_VERIFIED (file installation/integrity only).
- OS_AUTH_NATIVE_PENDING; BROKER_HANDOFF_NATIVE_PENDING.
- CAPABILITY_SCOPE_UNKNOWN; Kernel TCX support UNKNOWN.
- TCX_VERIFIER_NATIVE_PENDING; TCX_ATTACH_NATIVE_PENDING.
- TCX_DATA_PLANE_NATIVE_PENDING; NETWORK14_NATIVE_BLOCKED.
- TCX_CLEANUP_NATIVE_PENDING; GUI_NATIVE_PENDING; AUDIT_NATIVE_E2E_PENDING.
- Failed preparation audit chain VERIFIED; Native collector audit not observed.
- NATIVE_AI_BLOCKED; DNS9_BLOCKED; OPERATIONAL_PROMOTION_BLOCKED.

Resume requires approval for one corrected B authentication-only attempt. Do not
reinstall A, automatically retry authentication or execute C after a B failure.
The requested C limits remain lo/Ingress/current verified namespace, 300 seconds,
4096 metadata events, queue 32, address space 256 MiB, CPU time 20 seconds,
no drop/payload retention/pinning/retry or foreign filter modification. Kernel support
and existing Hook state must be safely checked before attach. Native AI is excluded.

## Git and validation scope

Production source, binaries, source bundle and installed release were unchanged.
HEAD and origin/main remain `14c240655cd5c306b191da25f4abf6bc37ad0835`;
index remained empty. No Commit/Push was made for this interrupted execution.
This execution report is a new unstaged documentation file. Broad pytest/model/GUI
performance/wheel runs were intentionally not repeated: no source change occurred.
Validation covered exact package/dependencies/installed files, one ordinary-user
Inspector correction, failed-session audit chain, preservation and documentation diff.

## Approved corrected B attempt — 2026-10-21 KST

The user authorized one corrected B attempt and conditional progression to C.
The installed Release, Manifest, source bundle and empty Git index were rechecked.
The new application `1b30e4f6-4772-45e7-ab19-efcb7c7f9294` passed ordinary-user
Legacy ELF preparation and prepared the separate approved TCX handoff scope.

It displayed the purpose-bound approval digest, then exited with code 1 at the
approval-input comparison. In the executed CLI, this return occurs when the input
is not equal to `handoff.approval`. The input itself was intentionally not logged;
its contents and the reason for the mismatch are unknown. This is not an OS
password or Kernel failure. No OS_AUTH_REQUESTED/APPROVAL_ACCEPTED event exists,
so sudo authentication, privileged Broker startup, BPF load and C were not reached.
No automatic retry or Native Gate modification occurred.

The eleven-event Audit chain was verified read-only; final digest:
`ff22275d3e2c1da6b3e3ff15e9037a152a9c391450ddc32f46a35bc283fc496f`.
The auth wrapper reports CLEANUP_UNVERIFIED because no sudo child exists to supply
a verified exit code; this is distinct from a Native link cleanup failure. The
ordinary application's final CLEANUP_VERIFIED event is present. No privileged
Broker or Link was created by this attempt. The trusted installation remains.

The next B attempt requires renewed authorization, a fresh application/session and
fresh displayed purpose digest. The terminal expects the 64-character value labelled
`OS handoff approval digest`; the earlier preparation digest is a different value.
Only after that approval does the OS request the password. A successful B still
must stop and verify its Broker exit before conditional C. All prior Native verdicts
remain PENDING/BLOCKED; Kernel events have not reached Network14.

No production code was changed or committed. Private receipts and the new Audit
remain under `.git/tcx-c2-execution/`. No broad regression or model runs were repeated.

## Short explicit confirmation remediation

The next previously authorized B application
`74124ca5-0484-492f-8a72-4cbe35391a7d` also exited at the digest-input comparison
(return 1 at 2026-10-20T23:39:00 UTC). The user reported inability to paste and
suspected time delay. Observed evidence shows no OS_AUTH_REQUESTED event and no
AUTH_QUALIFICATION_TIMEOUT exception; a timeout cause is not established. The
manual 64-character confirmation creates unnecessary input errors.

An ordinary-user entry `python -m soc_agent.security_ai.native_terminal` now
reuses the existing preparation/handoff/authentication implementations and displays
the complete scope. The operator types `yes` instead of copying a digest. The
entry binds the exact displayed scope and current session digest internally,
rejects changes during confirmation, and denies blank/no/digest text/cancellation.
It requests no password: the existing fixed sudo entry retains direct OS TTY input.
It has no retry loop, stored authorization, native FD exposure or Kernel gate override.
Successful exit additionally requires verified handoff cleanup. B and C remain
separate app sessions; conditional C may proceed only after B succeeds and closes.

This entry is outside the installed native source bundle. The root-owned release,
Manifest, Bootstrap, Broker, Loader, TCX object, authenticated IPC and privilege
validation are unchanged. No root reinstall or Native execution was performed for
the UX change. Six focused confirmation cases cover accept, denial/default/wrong
input, scope mutation and cancellation. Source file SHA256 at preparation:
`c6893ee9195f3d537cbf3c44b5968d8978be525b6a36d09dce0b03a0be805a89`.

The corrected short-confirmation B command is prepared privately in
`.git/tcx-c2-execution/auth-short-command-awaiting-approval.json`, with a new
application directory. It has not been executed. A fresh explicit authorization
is needed after the prior failed attempt; the operator then needs only `yes` and
OS password, followed by Enter to stop a successful B session. No new capture or
Native success is claimed. Existing release and Native AI/DNS9/operational gates
remain unchanged.

## Short-confirmation attempt: controlling TTY failure

Application `114b197e-54f9-4545-8171-cefee3849574` accepted yes, then failed with
AUTH_QUALIFICATION_TTY_REQUIRED before requesting OS authentication. The exact
cause was checking the root-owned /dev/tty alias rather than the actual owned PTY.
The actual terminal identity fix and complete Release 0.4.3 update scope are recorded
in [the TTY fix approval](native-tcx-tty-fix-approval.md). No privileged Broker,
BPF load or TCX attach occurred. No retry was made automatically.

The user requested a fix and immediate retry. The correction passed 12 focused cases
and an ordinary-UID install/check/rollback simulation. Because the source Bundle
changes, the new release/update SHA is presented for the specific approval required
by the user's existing exact-release boundary. Release 0.4.2 remains installed;
0.4.3 is prepared but not installed. No Native result has been promoted.

## Actual Release 0.4.3 update and B entry rejection

Following explicit approval, the pinned Root update returned 0 at
2026-10-20T23:48:24 UTC. Exact 0.4.2 was retained in its manifest-named archive.
All nine installed 0.4.3 file hashes, UID/GID and modes and dependency trust passed.
B session `68574dd4-35f5-4f4e-82eb-cb7bde0bd87e` then accepted yes, passed actual
TTY validation and audited OS_AUTH_REQUESTED. It ended with
AUTH_QUALIFICATION_ENTRY_REJECTED before IPC/Broker readiness; C was not executed.
The sudo auth log records the fixed Bootstrap command and PAM session open/close.
This is evidence of OS invocation, not full fresh-auth/Capability/Broker qualification.

A deterministic policy blocker was found: generic soc_trusted requires GID 0 but
the normal /etc/shadow is root:shadow (GID 42), 0640. The old generic error cannot
identify whether an earlier policy branch rejected first. The file-specific fix,
secret-free diagnostic stages and precise 0.4.4 replacement/conditional retry are
in [the shadow fix approval](native-tcx-shadow-fix-approval.md). Ten focused tests,
reference compilation and ordinary-user install/check/rollback simulation passed.
No actual Root update or Native retry of 0.4.4 occurred pending exact-release approval.
Native AI, DNS9 and operational promotion remain BLOCKED; no actual Kernel packet
has yet reached Network14. Installed 0.4.3 and the preserved 0.4.2 archive remain.

## Actual 0.4.4 authentication and STOP failure

The 0.4.4 root update completed and was verified. A command artifact-version mistake
was denied during ordinary-user preparation, corrected without modifying the release,
and all artifact/package/installed/source SHA values were revalidated before the
next explicitly approved B attempt. Session 13e82898-4ead-4bba-9cf1-940f67f8e094
verified real OS authentication, root-to-ordinary-UID Broker handoff, peer/session/
Manifest identity and all-zero auth-only capability sets. Its STATUS reply passed.

STOP then failed because Python sends operation 5 while the C auth-only allowlist
incorrectly accepted 3/6. Entry exit was 0, but cleanup stays UNVERIFIED, and C was
not attempted. The exact fix, real ordinary-UID C socket verification and proposed
0.4.5 replacement/conditional retry are in [the STOP fix approval](native-tcx-stop-fix-approval.md).
Six relevant cases passed, with no real OS authentication or Kernel operations in
the tests. No installed release, previous audit or Native evidence was modified
for these tests. A new exact release approval is required for the changed Bootstrap.

## Actual 0.4.5 qualification and unified-workflow preparation

The approved Root update returned 0 at 2026-10-21T00:12:30 UTC. Version, Manifest,
all nine installed file SHA/UID/GID/modes and old 0.4.4 archive were verified. Auth
and live command paths were directly constructed for artifacts-0.4.5/release-0.4.5.
B session bd4bd3e8-a9be-4a7b-a140-9f8e3a827140 completed actual authentication,
Broker status, STOP response, process exit 0, CLOSED state and REVOKED authority.
Its cleanup is AUTH_ONLY_PROCESS_EXIT_VERIFIED. The app Audit chain was verified;
final digest 7583ae3e3f91094cdd4368a1607fa2cfd107eeb39883d8851656623e85df675e.
This is Native OS authentication/cleanup evidence, not a Kernel capture result.

C session 4044126a-4f2c-442b-919c-6598958eb2d5 verified actual authentication,
release/peer/session binding and P/B capability mask 549755817984 (CAP_BPF plus
CAP_NET_ADMIN); E/I/A were zero. It failed before any ATTACH wire send with
HANDOFF_COMMAND_REPLAY_OR_SCOPE because STATUS had already consumed sequence 1.
The Controller now derives the next sequence from the last verified command.
Tests cover initial sequence 0/1/7 and denied attach closing once without retry.
They are orchestration fixtures with no Kernel calls, not Native capture proof.

The user then requested a single approval instead of A/B/C operator prompts.
The proposed same-app Broker lifetime, immutable combined plan, optional exact
update, one terminal authentication and unchanged internal safety gates are in
[native-unified-session-proposal.md](native-unified-session-proposal.md).
The proposal is not implemented. No additional installation/Native retry was run.
Existing installed 0.4.5, prior archives, model/raw/user files and Native evidence
are preserved; no source Bundle mismatch is bypassed for the client-side fix.

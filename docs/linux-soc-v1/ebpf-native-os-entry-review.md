# Phase B-2I additional review — OS entry first, custom SUID removed

This decision supersedes the selected architecture in the original B-2I report. Review baseline: `3f34006bce39269e3149ceb6277a77ca353eba52`. The earlier evidence remains historical evidence, not proof of the replacement architecture. **Native release and the OS authentication handoff remain BLOCKED.** No root installation, sudo/PAM invocation, credential change, BPF/TCX operation, capture or generated traffic was performed.

## Root cause and actual privilege impact

The reproduced LD_AUDIT callback runs in an ordinary-user dynamic process before its main function. Its audit namespace explains why base-namespace enumeration missed it. That is evidence against the old verifier, not evidence of a root compromise. Clearing that process's environment cannot undo its executed code. The earlier static Entry fixture demonstrated a fresh clean exec, but introducing a project-specific setuid program created a new privilege-acquisition TCB, including raw syscall startup, descriptor/proof handling and a custom PAM conversation. Preserving it solely because sudo needs policy qualification was not a sufficient architecture decision.

The actual privileged-entry question must be answered before dynamic mapping snapshots can have security meaning. An untrusted GUI/CLI may prepare metadata; neither its own SHA observations nor its stdout can certify that a password challenge happened. A compromised ordinary-user parent also remains able to falsify its own UI or observe its user's input. No new process erases that account compromise.

## Revised alternatives and decision

| Alternative | Benefit | Cost / unresolved condition | Decision |
| --- | --- | --- | --- |
| Custom setuid Entry + custom PAM Helper | Application controls its terminal conversation and challenge count | Project owns another setuid entry, proof minting and password/account-policy implementation; more custom pre-authentication code | Remove privilege-acquisition path and setuid installation contract |
| OS sudo entry + fixed restricted session Broker | Reuses OS authentication, policy plugins and secure execution; application has no independent elevation primitive | Effective command policy, password mechanism, terminal/FD handoff, privileged identity and dependencies need qualification | Preferred target; **not connected or qualified for execution in this change** |
| Root-owned persistent service | Independent startup environment and stable Link ownership | Persistent privileged service plus session/password protocol and service-manager lifecycle; unjustified for current bounded sessions | Deferred; no service installed |

This is a deliberate reduction of the proposed application's privileged surface, not a claim that the future sudo integration is complete. The source now removes the production Entry's privileged helper exec/proof-minting implementation rather than merely adding a verifier or flipping its gate. The separately compiled ordinary-UID clean-exec fixture remains for historical boundary testing; it cannot run as root and is not a release Entry.

## Concrete changes and attack paths

| Before | After | Evidence / limit |
| --- | --- | --- |
| Release contract permits Entry `04755` | Every project payload has no setuid/setgid/sticky bits; Entry and retained Helper are `0555` | Strict Python release validation and C execution-manifest parsing reject old `04755` records, even if supplied hashes agree |
| Production static Entry contains a dormant helper exec and root proof-creation path | Production Entry supports ordinary-user inspection and unconditional denial only | Source deletion, deterministic compiled artifact, hostile LD_AUDIT/LD_PRELOAD fixtures; no privileged execution performed |
| Custom PAM Helper could eventually be reached through the proposed SUID Entry after qualification | No Entry can mint the prerequisite proof or enter that Helper; Helper's independent Native gate also stays closed | Old Helper retained as migration reference, not an authentication fallback; do not chmod it or invoke it through sudo |
| All missing configured NSS services could appear as authentication blockers | Required-role absence and all configured missing services are displayed separately; OS role remains unqualified | No db/nis evidence removed; no system policy changed; no Native trust promoted |
| Gate state could be mistaken for an implemented auth integration | Release and System/Audit metadata explicitly record `BLOCKED_OS_POLICY_AND_IPC_MIGRATION_REQUIRED` | Manifest cannot set handoff to VERIFIED; actual one-password startup is **not verified for this replacement path** |

Both before and after builds already blocked Native execution. No previously running installation was modified and no real root exploit was demonstrated or claimed fixed. Risk reduction is removal of the candidate's custom elevation mechanism and its proposed SUID install surface. It is not demonstrated mitigation of a running privileged deployment.

## Why a sudo prefix is insufficient

The official sudo command manual states that command execution normally closes descriptors >=3 and that sudo uses the invoking real UID for policy evaluation. The current Helper instead requires a nonzero real UID, its controller as its direct parent, and plan/IPC/audit descriptors 3/4/6. A sudo monitor/child changes those assumptions. Do not relax identity checks or enable `closefrom_override` globally just to make it launch.

A future fixed OS entry must recover and verify the original application's kernel peer credentials, PID/start ticks, generation and approved scope through a deliberately designed handshake. `SUDO_UID`, `SUDO_USER`, successful exit status, caller-supplied flags or a mock challenge result are not sufficient evidence. No broad sudo rule, shell, user-selected executable or custom policy plugin is added here.

The sudo manual's command-local `-k` ignores cached credentials; it does not guarantee a password under NOPASSWD, exempt_group, disabled authentication or a non-password PAM mechanism. A future command-scoped PASSWD policy with zero timestamp timeout and a qualified terminal password/account stack is a candidate, not an installed policy or a guarantee based on one fragment. All effective rules, includes, remote policies/plugins and exemptions must be considered. Do not run `sudo -K` to destroy unrelated project credentials. Do not add a second custom PAM challenge after sudo: that would violate the once-per-application policy.

Within a qualified application instance, only its memory-bound Broker authorization would cover explicit same-scope Start/Stop/Restart. A restarted Broker or application cannot restore that authority from journal/manifest/cache. GUI and model workers remain ordinary-user siblings outside the privileged process tree; no authenticated Broker command may spawn them. That topology and actual credential transfer still require Native qualification.

## NSS scope, without policy bypass

Read-only `/etc/nsswitch.conf` evidence places `db` under protocols/services/ethers/rpc and `nis` under netgroup. They are absent on this host. This does not prove they are called during password authentication. The retained Helper's explicit calls are passwd lookups and its fixed PAM account stack; Broker authorization uses numeric UID/GID and kernel peer credentials, with no direct NSS name imports. These source-derived roles do not close transitive PAM/OS-sudo NSS behavior.

The future OS entry delegates authentication/account and group policy to the OS. Its actual effective sudo/PAM/NSS scope must be observed/qualified; this change does not copy the custom Helper's role list to sudo and declare it complete. Missing required identity lookups must fail closed. No package installation, automatic exclusion of db/nis, nsswitch edit or group-policy bypass occurs.

## Capabilities, TCX and recovery

No capability implementation or TCX code changes. Candidate BPF Load/Attach rights remain CAP_BPF + CAP_NET_ADMIN; CAP_PERFMON and patched WSL2/LSM behavior remain unqualified. Effective rights only around approved Load/Attach is the existing design; retaining Permitted rights still gives a compromised Broker potential authority and is not described as powerless. GUI/AI do not receive those capabilities. Actual transfer/drop testing remains PENDING.

TCX_NEXT(-1), private Link FD, no pinning, no foreign Link removal and no automatic reattach are preserved. Trust failure must not prevent safe release of already-owned Link FDs. SIGKILL/external duplication and ambiguous cleanup remain Native questions; uncertainty remains ORPHANED/CLEANUP_UNVERIFIED. Recovery restores evidence, never authentication or inference authority.

## Qualification boundary and approval plan

Nonprivileged evidence can establish removed code paths, strict release-mode rejection, ordinary-user clean exec, manifest compatibility, fixture IPC/TCX ownership and existing offline regression. It cannot establish an effective OS password policy, actual PAM account behavior, privileged loader mappings, kernel credential transfer or WSL2 TCX behavior. Repeating mock authentication does not close those gaps.

Next work requires implementing/reviewing the fixed OS-entry IPC/identity protocol before requesting execution approval. Separate deployment approval must identify root-owned binaries and digests, command-scoped OS authentication policy, dependency/update policy and rollback. Only after that may a separate bounded Native validation request cover terminal authentication, minimal credentials, verifier and TCX lifecycle. No executable Native instruction is supplied for the current blocked candidate. Existing approvals do not authorize the replacement entry or any wider interface/hook scope.

## Official evidence

- [sudo 1.9.15p5 command manual](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/docs/sudo.man.in): privilege/real-UID policy, command-local cache invalidation and default descriptor closure.
- [sudo 1.9.15p5 policy manual](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/docs/sudoers.man.in): PASSWD/NOPASSWD, exempt_group, authenticate, timestamp_timeout, environment and FD execution policy. Version pin is source evidence, not confirmation of the installed effective policy.
- [glibc dynamic-loader manual](https://man7.org/linux/man-pages/man8/ld.so.8.html): secure execution and audit namespace semantics. Post-main observation cannot undo a constructor.

The accompanying evidence JSON records current source identities, actual checks, preservation, export and release blockers. Historical test totals are not added to the current totals or used to certify changed artifacts.

Compiled-code comparison (same build toolchain) confirms the removed `native_entry` function: previous Entry SHA `cb55b17610b1d93d7d80f959532972c3f29684f347879c4af7248609fa4f2ef9`, 9,752 bytes; revised Entry SHA `8e4ef82c3fe45ae5a414509316a2922898148ed860bb7ebdde9f743509ce4455`, 9,352 bytes. Manual disassembly review of the revised production image finds only UID reads, write and exit syscalls. The harmless exec fixture is a distinct compilation, never the packaged executable. Code size or instruction counts alone are not a security verdict.

Package `0.2.10` is a blocked migration inventory, not an OS-authenticated executable release. Its retained `pam_service=soc-agent-ebpf` and Helper dependency snapshots describe the quarantined custom reference, not sudo's real service or policy. They cannot qualify the replacement OS boundary. A future executable OS-entry release must use a separately reviewed schema/policy identity and must not reinterpret this inventory as authentication evidence.


Read-only OS observations for this review: installed sudo package is `1.9.15p5-3ubuntu5.24.04.4`; `/usr/bin/sudo` is root-owned `04755`. Its ELF was inspected without executing it. `/etc/sudoers` is root-owned `0440` and reading it returned permission denied; no bypass was attempted. Thus effective command rules, overrides, exemptions and group/netgroup requirements are not qualified. Readable `/etc/pam.d/sudo` includes common-auth/account/session; common-auth has `pam_unix.so nullok` and optional `pam_cap.so`; session includes pam_env/limits/umask/unix. This is **not** evidence that the current user has an empty password or that capabilities were changed. It means password-challenge and resulting credential/environment guarantees need actual OS policy review, not an assumed one-challenge success. The custom Helper's minimal PAM snapshot does not describe this OS stack.


Current independent Export validation: structural: **220 PASS**; native_contract: **147 PASS**; broker: **63 PASS**; regression: **695 PASS**; integration: **58 PASS**; model: **1 PASS**; gui: **17 PASS**; audit: **125 PASS**. Cohorts overlap and are not summed. Actual RF/LR evidence is offline Zeek/PCAP only. Ruff/Format, Wheel source-byte equality and Diff pass. Package validation median 103.326ms (3 offline samples; no Native or before/after performance claim). GUI functional checks pass; GUI performance was not remeasured. Source and artifact identities are in the companion evidence JSON. The replacement OS authentication handoff remains unimplemented and BLOCKED despite these passes.

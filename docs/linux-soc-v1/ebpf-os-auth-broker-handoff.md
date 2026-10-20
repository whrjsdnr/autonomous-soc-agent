# Phase B-2J — OS authentication and trusted Broker handoff

Baseline: `3974fa2d38c937d7ac5efed41977f537a9a23fe2`. This implements the missing handoff, not Native qualification. No sudo/PAM invocation, root installation, capability change, BPF load, TCX/TC operation, capture or generated network traffic is performed. Native release, Native AI, DNS9 and operational promotion remain BLOCKED.

## 1. Root cause

The retired SUID entry cannot authenticate or start a Broker. Prefixing the old PAM Helper with sudo would change real UID/parent identity and close its expected inherited descriptors. Restoring SUID or trusting `sudo` exit success would not fix this. The replacement must connect after OS authentication and authenticate both ends of the connection, independently of the sudo monitor PID.

## 2. Selected execution architecture

```text
ordinary CLI: prepare -> inspect release/scope -> explicit approval
  -> fixed /usr/bin/sudo -k -u root -- /usr/libexec/soc-agent-ebpf/bootstrap
     --os-handoff UID GID SESSION_HEX APPROVAL_DIGEST MANIFEST_DIGEST
  -> OS authentication/account policy [Native qualification pending]
  -> root-owned os_bootstrap.c executable, mode 0555, no custom PAM
  -> new Unix seqpacket connection + kernel Controller credential validation
  -> sealed approval/audit FD receipt + installed release validation
  -> root-created sealed authority/object, fixed held Broker executable FD
  -> existing capability reduction + fexecve, same PID/start ticks
  -> ordinary-UID scoped Broker, I/A cleared and idle E=0
  -> Broker Ready / existing six-command protocol / private TCX Link FD
```

`authenticate_native()` contains the terminal-only fixed invocation and handoff path, but the strictly validated release schema can only represent BLOCKED, so it rejects before TTY access or Popen. The compiled OS admission function independently returns false, as do existing Native/TCX gates. No environment, message, manifest or mock result opens these gates. Actual OS policy qualification is a deliberate unresolved prerequisite, not a client-supplied success boolean.

The new `bootstrap` build uses `os_bootstrap.c` and does not link libpam or call the retired custom conversation. Old `bootstrap.c`, policy reference and proof validators remain historical/compatibility source, not an executable fallback. Entry remains inspection/denial-only. All project install modes remain without SUID/SGID; previous setuid manifests are rejected. The old custom PAM reference is no longer a mandatory installed execution-trust record and the installation plan does not propose installing a custom PAM service. The release explicitly names sudo as the OS authentication service and marks its old PAM payload reference-only. That reference does not qualify sudo's PAM stack.

## 3. OS sudo policy and fresh application authentication

Use command-local `-k`, with the fixed command, to ignore cached credentials without a global `-K` purge. The official manual says this does not update the user's cached credentials. A password is only prompted if policy requires it; NOPASSWD, exempt groups, `!authenticate`, empty-password/non-password mechanisms and effective plugin/account policies still require separate review. No sudo policy fragment is silently installed, and no successful return code is accepted as proof of a password challenge.

The actual authentication policy is not qualified on this host. Root ownership and sudo parent inode, SUDO_UID/GID consistency, terminal presence, kernel peer identity and release verification are necessary but are not sufficient to establish a fresh password. Hence `soc_os_auth_admitted()` is an independent closed gate. Future admission requires separately reviewed effective policy and OS execution evidence. No password, PAM buffer, sudo timestamp or bearer credential is handled/stored by the application.

Fixture authentication is a separate `MOCK_OS_POLICY_NOT_NATIVE` model. Missing TTY, cached-only authority, NOPASSWD, denied account, cancellation, failure and timeout all reject before spawning its ordinary-user peer. A successful mock never creates a root-owned authority FD or authorizes the Native Broker.

## 4. Rendezvous and fixed schema

The running WSL environment has no `/run/user/1000`; no privileged runtime directory is created to work around that. Use Linux abstract AF_UNIX SOCK_SEQPACKET name `soc-ebpf.UID.SESSION_HEX`. This has no filesystem mode/owner; authentication is entirely kernel credentials, not path secrecy. A collision or foreign first connector aborts the session rather than retrying indefinitely. Namespace and interface are independently revalidated.

| Message | Bound | Validation |
| --- | --- | --- |
| Approval | 352 bytes + exactly two SCM_RIGHTS descriptors | Existing release envelope; argument-pinned approval/manifest digest; seals; byte-for-byte held FD; UID/GID; Session; Controller PID/start ticks; namespace/interface; fixed budgets |
| Root handoff / Broker Ready | 96 bytes each | Magic, stage, source, PID/start ticks, UID/GID, whole-envelope digest, Broker SHA |
| Commands | Existing 112-byte ABI | PREPARE/ATTACH/STATUS/DETACH/STOP/CLEANUP; fixed arguments; next sequence; scope; lifetime; rate |
| Reply | Existing 72-byte ABI | Sequence, state, error, reserved bits, Broker-owned metadata |
| Journal notifications | Existing 192/240-byte records | Allowed kinds, plan digest, record checksum; bounded notifications; full chain checked during recovery |

Approval and manifest digests are pinned in the fixed executable's argument schema as well as the received envelope. Recomputing an envelope checksum cannot substitute a different approved scope in transit. These digests and Session ID are public metadata, not authentication tokens. No caller-supplied executable, object path, shell command, link ID or privileged Link FD is accepted.

The Controller enables SO_PASSCRED and verifies SO_PEERCRED at connection admission. Every received packet must also have kernel SCM_CREDENTIALS matching the pinned PID/start ticks and expected stage UID/GID. This matters because SO_PEERCRED retains connection-time credentials while the root entry execs the ordinary-UID Broker. The Native Root-to-user transition is implemented but not exercised here. Unsolicited descriptors are closed and rejected. C rejects truncated messages, extra rights, unsealed/substituted plans, non-append/nonempty audit files and mismatched scope, closing all installed received FDs on rejection.

## 5. Trusted release and IPC boundary

The root entry requires numeric real/effective root identities, a foreground terminal contract, SUDO_UID/GID matching arguments, the trusted `/usr/bin/sudo` parent inode and the independently qualified OS admission gate. It then clears the environment to fixed PATH/LANG, resets signal mask/termination dispositions, sets cwd/umask and bounded startup resources, and establishes a new connection. It does not require the Controller to be its direct parent and does not depend on inherited FD 3/4/6 or sudo `-C` privileges.

Kernel peer credentials plus Controller PID/start ticks bind the received approval to the actual application. Existing root-owned fixed-directory/file/dependency/SHA enforcement is reused at entry, Broker and Loader. An ordinary user's matching files/manifest hashes are not root installation proof. The verified Broker is executed through a held FD; its source object is copied into a root-owned sealed memfd. Only that Broker receives root-created authority/object FDs. The Controller/GUI receives metadata, never those FDs or TCX Link FDs.

The ordinary transport fixture is a separately compiled, ordinary-UID-only C executable. Python verifies its bytes against the current reference and executes a sealed user-owned memfd, eliminating pathname/SUID/file-capability substitution at fixture execution. It embeds only its reviewed helpers/system dependencies, not a mutable `$ORIGIN` DSO. Source marker 2 is mandatory for fixtures; a fake Native marker is not accepted. The privileged Broker requires root-owned sealed authority and the closed Native gate; fixture success cannot start it.

## 6. Session lifetime and supervision

Prepare and approval do not start Capture time. Successful Broker Ready starts the application authority deadline (3,600 seconds); the actual existing Broker starts its 300-second Capture deadline only on an explicit ATTACH. The handoff waits at most 60 seconds for Native authentication, then uses five-second bounded protocol I/O. Native startup is separately bounded; Broker heartbeat is 15 seconds, commands <=2,048 at <=32/s, queue 32, address space 256MiB, CPU 20 seconds and <=16 explicit runs. These are existing Native ABI budgets, distinct from lower-layer fixture inspector/producer limits. The CLI displays the Native ABI approval scope explicitly.

One authentication attempt is permitted per application handoff. STOP/PREPARE/STATUS within the same scope reuse the bound session; no new password or process is requested. Scope changes, replay, expiration, stale PID/start ticks, EOF or Broker replacement revoke authority. A replay-denial audit marker prevents recreating the same application handoff after close; it contains no restorable grant. Broker crash has no automatic restart. Polling uses STATUS; requests are single-flight through the existing GUI worker.

The transport fixture never simulates Kernel ACTIVE or fabricates Link ownership. ATTACH/DETACH are denied there; actual TCX dispatcher/ownership regression remains in the existing compiled fixtures. In the Native code, the existing Broker performs the real six-command dispatch. Native operation remains gated. Graceful application close sends CLEANUP, drains bounded protocol metadata, closes the channel, waits and checks the existing journal chain/process exit. Forced signals are used only for the owned ordinary fixture child. An unverified privileged process is never killed by guessed PID; uncertain exit/cleanup is reported for review, without restart.

## 7. Privilege separation and TCX ownership

Only the fixed OS entry transitions to the fixed scoped Broker. GUI/AI workers are not its children. Numeric kernel identity authorization replaces custom PAM/NSS work in this entry; OS authentication/account and group/NSS policy remain OS responsibilities requiring qualification. Missing NSS db/nis evidence is not discarded or automatically bypassed.

Existing reduction retains candidate CAP_BPF + CAP_NET_ADMIN only; after Broker exec, Inheritable/Ambient are cleared, Effective is zero except Load/Attach, and bounded Permitted authority remains for explicit approved restarts. A compromised Broker is not described as powerless. Actual credential transfer, CAP_PERFMON need and WSL2/LSM behavior remain UNKNOWN.

No TCX program or Link ownership implementation changes: TCX_NEXT(-1), observation only, no pinning, no foreign Link removal and no automatic reattach. New trust failures abort new commands but disconnect through the existing held-FD cleanup path. Namespace/interface loss, external FD duplication, SIGKILL and ambiguous ownership still require Native evidence; uncertainty remains ORPHANED/CLEANUP_UNVERIFIED. Root process success alone is not capture integrity or AI eligibility.

## 8. GUI

Dashboard, Security Events, Investigation and System plus their existing charts/timelines remain. System adds OS Authentication, Handoff, Broker Session, Release Integrity, Capability, Native Gate and Cleanup with explicit source. The handoff state is separate from a live collector or inference result. Start does not silently fall back to the old fixture collector when an OS handoff exists. Stop keeps the approved Broker session; GUI/app close revokes it. There is no GUI password field, fabricated Native traffic or UNKNOWN-to-zero conversion.

## 9. Audit and recovery

Existing RuntimeStore append-only application audit and existing C journal/recovery are reused. Events include APP_SESSION_PREPARED, OS_AUTH_REQUESTED, OS_AUTH_HANDOFF_VERIFIED, BROKER_SESSION_BOUND, BROKER_READY, BROKER_SESSION_EXPIRED, HANDOFF_REJECTED, CLEANUP_VERIFIED/UNVERIFIED and BROKER_STOPPED. Fixture origin is explicit; base application audit also records no Native authentication in this phase. No password, PAM secret, authority FD or persisted credential is logged. A journal checksum is integrity evidence, not proof of OS authentication or Kernel cleanup.

Recovery verifies evidence and refuses to restore authentication, attach or inference. Existing session/Native evidence is never edited/reused. Failed/disconnected sessions cannot be reactivated by deleting stop evidence or replaying a hash.

## 10. Verification

Tests run ordinary C/Python processes and actual Linux Unix socket/SCM credentials/seals. They cover fresh app/replay denial, cached/NOPASSWD/TTY/account failure, cancellation/timeout, sequence/digest/identity/namespace/interface/hook/resource substitution, PID ticks, forged kernel credentials, unsealed/extra/substituted FDs, rejected-FD leak accounting, Broker crash, expiration, scope refusal, same-session stop/prepare, audit/recovery, GUI and closed Native gates. Existing TCX link fixtures cover foreign preservation, FD duplication, cleanup faults and crash scenarios. Existing Zeek/Network14/DNS/RF/LR regressions are separately run; offline Artifact success is not Native inference.

An initial exploratory run was deliberately interrupted to pin approval/manifest arguments before final verification; its pytest interruption/teardown transcript is retained, not reported as a current pass. A subsequent 27-test development run and eight FD protocol tests passed. Final evidence is generated only against the frozen independent Export, not these earlier code states.

## 11. Remaining blockers

Actual OS password/account policy, full sudo/PAM/NSS/environment dependencies, root installation, same-PID root-to-user transition, capability transfer/drop, supervisor behavior under real privileged failure, Kernel verifier, TCX support/coexistence and cleanup remain unverified. Effective sudoers policy was not read with elevation, no system configuration was changed, and no missing NSS package was installed. `soc_os_auth_admitted()` must not be changed merely because transport tests pass. SIGILL root cause remains UNKNOWN absent new evidence. No performance improvement is claimed from Fixture timings.

## 12. Native approval scope

Before execution: separately approve root-owned installation/update/rollback and effective OS authentication policy qualification for the pinned release and fixed command; retain no custom SUID program or broad sudo rule. Then separately approve bounded terminal authentication/credential and verifier/TCX validation: explicit lo/current namespace, one approved ingress or egress hook, 300 seconds, 4,096 metadata records, queue 32, address space 256MiB, CPU 20 seconds, app <=3,600 seconds and <=16 explicit runs. No generated traffic, pinning, auto restart, Native AI, DNS9 or operational promotion. Current builds cannot execute that scope; do not treat the displayed sudo argv as an admitted Native instruction.

## 13. Official API basis

- [sudo 1.9.15p5 command manual](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/docs/sudo.man.in): command-local -k, policy-conditional authentication, descriptor closure and monitor/child signal behavior.
- [Linux Unix socket manual](https://man7.org/linux/man-pages/man7/unix.7.html): abstract namespace, SO_PEERCRED, SCM_CREDENTIALS and descriptor passing. Actual ordinary-user socket tests supplement this contract, not Native authentication proof.

The companion evidence JSON records final source/artifact digests, independent Export checks, regressions, preservation and qualification verdicts.


Final independent Export verification: native_contract: **147 PASS**; broker: **63 PASS**; regression: **695 PASS**; integration: **58 PASS**; model: **1 PASS**; gui: **18 PASS**; audit: **125 PASS**; structural: **258 PASS**. Cohorts overlap and are not summed. Final structural/security cohort includes three audit/cleanup failure cases. C/BPF source and executable identities match the successful C regression. Changed handoff code was rerun; GUI interpreter started after the final source overlay. Ruff, Format, Wheel source-byte equality, artifact/package rebuild and Diff pass. RF/LR success is offline Zeek/PCAP only. Package validation median 101.432ms (3 offline samples, PSI recorded); no Native performance or GUI improvement claim. Full identities and blockers are in the evidence JSON.

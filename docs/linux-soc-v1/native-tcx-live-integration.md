# Phase C-2 unified Native live integration

## Current status

Implementation and nonprivileged preparation completed; **waiting for Approval A**.
Baseline `0ed99facbbf6150e912471d0b6029adb1fe22c4e`.
No Root installation, sudo/PAM invocation, capability mutation, BPF load, TCX attach,
network change or capture has occurred. Native events/features/loss are NOT_OBSERVED,
not zero. Native AI, DNS9 and operational promotion remain BLOCKED.

## Installer implementation

`install_engine.py` is a standalone standard-library engine. `install_image.py` embeds
all reviewed release bytes into a SHA-pinned image. Root execution uses the trusted
system Python with `-I -S` in a clean new environment and a held-file SHA check;
it does not import Python or load binaries from this development repository as Root.
The generated installation image is the explicitly reviewed first-install exception,
not an arbitrary root script/path interface. No site packages, user imports or shell
are loaded. No sudoers, PAM, NSS, service, setuid or file-capability changes are made.

Root-owned non-writable parent directories are walked with O_NOFOLLOW directory FDs.
Root files require exact modes, single links and SHA, with held-FD identity checks.
Payload bytes are immutable in the approved image. Dependencies and OS configuration
hashes are revalidated. Files are created exclusively in a new private sibling staging
folder, fsynced, verified and atomically published with RENAME_NOREPLACE. Existing
installations, symlinks or staging conflicts are not overwritten or merged. Failed
staging is preserved as bounded evidence, never recursively erased or auto-retried.

The legacy in-process `native_install()` API remains denied; the implemented privileged
entry is the isolated, pinned image `root_main()`. In-process Root execution/import
from a user-mutable SOC checkout is intentionally not the installer.

## Approval A — exact reviewed install scope

Release version **0.4.2**. Current fixed destination
`/usr/libexec/soc-agent-ebpf` does not exist. `/usr/libexec` is Root:Root mode0755;
recheck both immediately before execution. Final release directory mode0755,
all files UID/GID0:0, and the following exact payloads only:

| File | Mode | SHA256 |
|---|---|---|
| `bootstrap` | `0555` | `96d0df57066e3f1004a4343d22acbe6c0ca20aef7d6919181e8ca2010dcbbd7d` |
| `broker` | `0555` | `b872565bcd0abc67c2a5b9c7f96b21d9acb46df582870e303e067c42376254ff` |
| `entry` | `0555` | `8e4ef82c3fe45ae5a414509316a2922898148ed860bb7ebdde9f743509ce4455` |
| `libnative-tc.so` | `0444` | `7905693372d14e93162ff7fbeea4068a0094a737663b2403c337630901706536` |
| `manifest.bin` | `0444` | `8221efca1fb4d81089200e20d79d73a99aacc1cb47772bf7de848babde28ebb1` |
| `pam-policy.conf` | `0444` | `93af76067bf513b4db8c5a9bd606e348ccde334b83e52f7dc71544c9c1f82696` |
| `tc.bpf.o` | `0444` | `928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a` |
| `release.json` | `0444` | `17f85c891df7f5b04026fcf180b6c175fece64752ceb2f2793dd36917e0c910d` |
| `release.trust` | `0444` | `8ec2424921e017a228fd111368f0821bc6bf4e152e6ebd20399f3865f841f52e` |

Manifest Digest: `17f85c891df7f5b04026fcf180b6c175fece64752ceb2f2793dd36917e0c910d`.
Source Bundle: `464811d02a0f30a3f06069654fe157c1f447bff1b68d0ecc99d26f734e039316`.
Installer Image SHA256: `67d4ebda1ba82a563a623f72f541b7e840b861cba5735b7c6958c553617847da`.

Approved-image path: `/home/geonug/kdt-linux/autonomous-soc-agent/.git/tcx-c2-unified/approved-installer-v042.py`.
Exact command is retained in `.git/tcx-c2-unified/approval-a-command.txt` and the
shell-free argv equivalent in `approval-a-command.json`. Neither has been executed.
The Root command may write only the fixed release and its hash-named sibling staging
folder, plus fsync its parent. Risk: privileged filesystem writes and executable
publication. No process/service/collector is activated by installation.

`pam-policy.conf` remains a reference inside this directory and is **not** installed
under `/etc/pam.d`. Fixture binaries and model/raw/session files are excluded.

Rollback requires its own explicit manifest-bound approval and quiescence. The engine
verifies the entire exact installed file set/SHA/modes, rejects active bootstrap/Broker
executables, and atomically moves only this release to
`.soc-agent-ebpf.rollback-17f85c891df7f5b04026fcf180b6c175fece64752ceb2f2793dd36917e0c910d` in the same parent.
It never deletes files or touches any Kernel link/filter. OS dependency updates do
not prevent exact unpublication. Unknown contents/ownership or a rollback-name collision
stop the operation. No automatic rollback, Hook removal or restart is implemented.
Retained external Link FDs are not proven absent by a process scan; after a Native run,
quiescence and link cleanup must also be reviewed before any rollback approval.

## Authentication-only qualification — Approval B

After installed Root ownership, modes, payload/manifest/dependency SHA are verified,
a new ordinary-user app runs `auth-qualify`. It displays a new application/purpose
approval, then uses the OS terminal via fixed `/usr/bin/sudo -k -u root --` and the
Root-owned bootstrap. It does not use sudo -S, askpass, password pipes or GUI dialogs.

The C entry checks numeric SUDO UID/GID against the session, Root credentials,
trusted sudo parent inode, and actual parent argv requiring `-k` for this fixed command.
A narrow local sudoers parser rejects NOPASSWD, authentication exemptions, aliases,
unknown Defaults/plugins/NSS sudo policy and unreviewed includes. PAM password/account
stack shape is qualified at build time and public configuration hashes are pinned.
A nonempty local shadow password hash is mandatory; it is never logged or persisted.
Unsupported OS policy is a failure, not password proof. No system policy is edited.
The OS, not the app, performs PAM authentication/account evaluation.

The controller authenticates Root SO_PEERCRED, per-message credentials, PID/start ticks,
sealed approval FD and release/session scope. Purpose-bound digest
`SHA256(SOC_AUTH_ONLY_V1\0 || envelope)` differs from the live digest. The auth-only
status process drops UID/GID and **all** E/P/I/A/Bounding capabilities before the second
hello (separate source3, bootstrap SHA identity), then accepts only STATUS/STOP.
The controller reads actual capability sets from /proc. No BPF APIs, map creation,
load, attach, ring consumer or packet data plane is invoked in this mode. It expires
and cannot restore authorization or attach in recovery. Early sudo/entry rejection
is detected by process exit, without waiting the full authentication deadline.

This is an authentication-only qualification app session and ends after B. C starts
a new live qualification app session with its required new one-time password. Within
one app no per-command reauthentication is performed. No cached approval/credential
is persisted or transferred between these two apps. sudo's own password failure
handling remains OS-controlled; the app never retries a failed authentication.
Actual PAM/TTY/parent-monitor behavior is PENDING; no mock is Native proof.

## Live qualification — separate Approval C

The candidate contains `live-qualify`, but it must not be invoked until A and B pass
and explicit Approval C is recorded. It binds a fresh purpose digest
`SHA256(SOC_TCX_LIVE_V1\0 || envelope)`, exact installed program/bundle/manifest,
Controller PID/start ticks, current namespace and interface. Proposed scope:

- namespace `net:[4026531833]` and `lo`/ifindex1, both rechecked at runtime;
- exactly INGRESS, no EGRESS authorization;
- 300s maximum;4096 delivered metadata events;queue32;ring262144 bytes;
- address space256MiB, CPU20s;bounded one-hour app/16 explicit runs;
- TCX_NEXT(-1), no packet mutation/drop, no pinning, traffic generation or automatic retry.

`core.c` now uses a process-local qualification admission, initially false, rather than
an unconditional constant enable. The Root entry must validate OS policy, purpose,
trusted installed self/dependencies and scope before admission; after exec the Broker
independently requires a **Root-created sealed authority FD**, exact bytes, installed
self/manifest, UID/GID/capabilities and live Controller identity. User-owned memfds,
CLI flags, JSON/manifest edits or an ordinary-UID library call cannot admit execution.
Legacy unrestricted entry and Legacy TC attach/detach stay denied. Operational release
remains BLOCKED; qualification is scoped research capture, not promotion.

Only CAP_BPF and CAP_NET_ADMIN are retained in the Broker's permitted/bounding sets;
E/I/A become0 at idle, with E raised only for load/attach. Actual sets are observed
again by the controller. Actual WSL transfer, verifier and TCX capability requirements
remain PENDING and failures are not bypassed. GUI and model workers stay ordinary UID.

Before link creation, TCX programs must be absent and the kernel must report a valid
hook revision. BPF_LINK_CREATE carries expected_revision to reject a concurrent insert;
no replace/order/pin flags are used. Legacy filters are read and must be absent in this
initial scope. No qdisc is created. Cleanup compares the saved Legacy state and detaches
only the Broker-owned Link FD. Native query/support has not been probed. The non-root
preflight bpftool query returned EPERM, so no empty TCX-hook assertion is made.

## Packet delivery and Network14

The unchanged 80-byte Kernel event travels through the dedicated192-byte data envelope;
control remains separate. New type5 is a typed80-byte **counter** payload, not a packet.
After observation disable and owned Link detach, bounded ring drain precedes a per-CPU
owned-map snapshot and map release. Retrieval failure/overflow is explicitly UNVERIFIED
with missing totals, never fabricated zeros. Counter provenance is hook/map/generation,
not kernel packet drops or Zeek's capture handle. Duplicate snapshots are rejected.
At metadata budget, delivery stops at4096 and finalizes PACKET_LIMIT; Kernel-emitted
versus delivered counts can reveal budget discard. No incomplete flow is promoted.

Clock domain remains Kernel monotonic ns with no guessed UTC conversion. Existing
Idle30s/Active120s/order/float32/digest contracts and bounded first/last/statistics state
are reused. Source/counter/clock/flow completeness remain separate; Native AI is always
BLOCKED in this candidate. Models, Zeek/DNS and historical evidence were not modified.

## GUI, Audit and Cleanup

Four screens and existing graphs are retained. System shows the actual handoff source,
collector response state, journal Link/program identity/tag, packet processing/queue,
map-counter evidence and cleanup. GUI Start cannot invoke sudo or a fixture fallback.
Terminal approval precedes start; Stop/close acts on the current session only. The
independent reader and model gates are preserved. No GUI performance improvement or
Native GUI success is claimed; no screenshot/performance/model regression was repeated.

Native C journal records retain the append-only chain. Application evidence includes
actual /proc capability observations, data finalization and release/purpose binding.
A Native run writes a bounded `native-live-result.json` in its own private session;
it is not committed. Cleanup disables observation, releases only its Link FD, drains
queued metadata, snapshots counters, releases maps, stops Broker and revokes authority.
Any uncertain ownership/exit/cleanup remains CLEANUP_UNVERIFIED/ORPHANED; no restart.

## Nonprivileged verification and preservation

12 focused security cases passed (two justified additions above the3–10 target cover
counter semantics and actual compiled sudo-policy rejection). Existing ordinary-UID
C→socket→adapter→Golden Network14 idle test passed; the unrelated active case was
not rerun. These are offline/fixture results, never sudo or Kernel evidence.
The **exact generated final installer image** passed install/check/rollback using
ordinary-UID temporary directories. No Root ownership success is claimed from that
simulation. Native C/TCX compilation succeeded, but verifier/attach remain PENDING.
Changed-file Ruff/Format and diff checks pass. Full regression, models, Wheel, GUI
profiling and screenshots were not repeated. No new dependencies were added.

132 existing user files and the earlier C-2 qualification report remain unchanged.
ML models, Native sessions, audit/archive/replay and raw datasets are excluded from
this release and selective staging. The installer/payload binaries are private artifacts.
SHA ledger and test transcripts are in `.git/tcx-c2-unified/`.

## Pre-approval integration correction

Review found that a new purpose-specific displayed approval must not replace the
sealed envelope digest expected by the C packet producer. PacketChannel now binds
the envelope digest while Root entry independently validates the purpose digest.
The constructor test checks their difference. This was fixed before any installation
or Native attempt. Unapproved internal candidates0.4.0/0.4.1 are superseded by0.4.2.

## First-failure handling and remaining risks

Installation/authentication/Kernel execution are separate. Unknown sudo policy, sudo
monitor argv layout, capability transfer, kernel revision/query support, verifier/map
limits, cross-CPU timestamp order, loss accounting and FD cleanup require actual
approved system verification. This code does not pretend to settle them with mocks.
A failed approved run is not automatically retried; any code/binary change requires
new hashes and new execution approval. Trust failure does not authorize deleting an
external Link, qdisc or filter. SIGILL root cause remains UNKNOWN.

## Native verdict before approvals

| Item | Verdict |
|---|---|
| TRUSTED_INSTALL_NATIVE | PENDING A |
| OS_AUTH_NATIVE | PENDING B |
| BROKER_HANDOFF_NATIVE | PENDING B |
| TCX_VERIFIER_NATIVE | PENDING C |
| TCX_ATTACH_NATIVE | PENDING C |
| TCX_DATA_PLANE_NATIVE | PENDING C |
| NETWORK14_NATIVE | BLOCKED pending real input/integrity evidence |
| TCX_CLEANUP_NATIVE | PENDING C |
| GUI_NATIVE | PENDING C |
| AUDIT_NATIVE | PENDING real session |
| NATIVE_AI | BLOCKED |
| DNS9 | BLOCKED |
| OPERATIONAL_PROMOTION | BLOCKED |

## Source references

Linux6.18 `bpf_mprog_attach` rejects a mismatched nonzero expected revision with ESTALE:
[official kernel source](https://github.com/torvalds/linux/blob/v6.18/kernel/bpf/mprog.c).
This source/API contract is not WSL runtime proof. sudo `-k` with a command ignores
cached credentials, while policy controls whether authentication is required:
[official sudo source manual](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/docs/sudo.man.in).

## Git

Only this implementation/tests/integration report are eligible for selective commit.
The enclosing source commit and private staging receipt identify the exact review;
no Native sessions, models, installer image or binaries are committed. System work
remains paused at the user's explicit Approval A boundary.

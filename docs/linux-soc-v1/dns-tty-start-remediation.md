# DNS Sidecar 0.5.20 — independent TTY authentication and START channel

## Baseline and root cause

Baseline commit: `942e1fe`. In the approved 0.5.19 attempt the entry command
exited 1 before an authenticated message, Zeek, capture or DNS probe. The
controller reported `DNS_COPY_TERMINAL_MISMATCH`. Its original Root stderr and
errno remain UNKNOWN; the old evidence is not rewritten.

A deterministic source defect was independently confirmed: `stdin=PIPE` was
introduced for START while `_candidate_policy` forks the fixed bootstrap whose
`soc_os_password_policy_only` requires `isatty(0)`. This cannot satisfy the
existing TTY policy if the policy-check branch is reached. No inferred EPERM is
substituted for the missing original errno.

The campaign `DNS_PARALLEL_STARTUP_0519` remains **1/3 used, 2 remaining**.
This work is nonprivileged development/qualification only: no sudo/PAM, Root
installation, packet socket capture, DNS traffic or Native budget reservation.
Existing images, Native evidence and campaign ledgers are preserved unchanged.

## Authentication and control separation

The launcher retains the existing `isatty(0)` and `isatty(2)` preflight, exact
Manifest/source/image checks and fixed SHA-held sudo command. It launches with
`stdin=None`: the real OS terminal is inherited, not replaced by a pipe. stderr
also remains the OS terminal. The application does not read, copy, forward or
persist password input. Existing fresh-authentication and NOPASSWD/cache policy
checks are retained; no setuid or privileged shell is introduced.

START uses a separate AF_UNIX SOCK_SEQPACKET connection. The ordinary controller
creates an abstract listener derived only from numeric UID and the fresh
application-session UUID in the validated release envelope. It exists before
authentication. There is no caller-selected filesystem/executable path, socket
file, symlink or cleanup unlink. Backlog is one, requested send/receive buffers
are 4 KiB (Linux may double the effective sizes), and messages are at most 1 KiB.

After the existing Root credential, sudo-parent, envelope, installation,
dependency and password-policy checks succeed, the SHA-held image connects to
that listener. It verifies SO_PEERCRED against the exact controller UID/GID/PID
already bound by the validated envelope and process-start-ticks/namespace checks.
It emits authenticated readiness with the binding and its own PID. The controller
accepts and verifies SO_PEERCRED UID/GID 0 and that exact Root PID. Thus a user
message asserting successful authentication cannot confer authority.

Only after existing Zeek READY validation does the controller send a canonical
START record. It must match **all fields and exact canonical bytes**:

- type START, sequence 1;
- application session UUID;
- approved execution-image SHA and installed Root Release Manifest SHA;
- approval digest and scope digest (namespace/lo/packet/resource contract).

The sidecar Manifest/source Bundle are verified before authentication; they are
not self-referential fields embedded into their own image. The Root approval
binds the exact image, validated release envelope and installed Root manifest.
The new V4 scope digest explicitly identifies TTY/separate-seqpacket semantics.

Wrong fields, duplicate keys, unknown fields, oversized/truncated messages,
wrong peer identity, timeout, sequence reuse and an already queued second command
fail closed. Both peers close the one-shot connection before capture. No later
command is consumed. New app sessions have fresh identities and cannot reuse an
old binding. On authentication/READY failure no START is sent and no capture is
prepared. Listener/connection cleanup is independent of collector cleanup.

## Root diagnostic evidence

The image records fixed stage/API boundaries for entry credentials, envelope,
sudo entry, dependencies, installed release, password policy, resource limits
and capture preparation. A diagnostic dispatcher emits `DNS_COPY_ROOT_ERROR`
with stage, API, exception class, original fixed error code, actual OSError errno
(or null), and entry exit code 1. The controller persists `root-error.json` before
raising the first error; `capture-process-exit.json` independently records the
observed entry-process exit status.

Only literal error strings raised in the reviewed embedded source are admitted
as original codes. Arbitrary exception text, even uppercase strings, is replaced
by its exception class. There is no raw stderr/terminal-input recorder. This
preserves safe diagnostics without collecting password, PAM conversation or
session secrets. Capture-specific error evidence remains separate and earlier
errors are not erased by cleanup failures.

If sudo authentication or the SHA-verification prelude exits before the reviewed
image can emit a diagnostic, `entry-error.json` explicitly records
OS_AUTH_OR_IMAGE_ENTRY, the exit code and UNKNOWN_NO_ROOT_DIAGNOSTIC, with errno
null/unknown. It does not invent a Root stage or silently claim original stderr
was retained. Broken stdout can also prevent structured evidence delivery.
Per-syscall successful FD closes are not newly instrumented by this change.

## Preserved contracts and time budget

CHECKSUM_PARTIAL handling, independently verified original/copy digests, actual
corrupt-checksum and missing-metadata rejection, DNS Analyzer logic, Queue32,
Counter/CLOSED, bounded streaming worker, Raw-IP UNSUPPORTED classification and
TCX/Network14 are unchanged. GUI and analysis remain ordinary-user processes.

The active deadline remains ten seconds from the trusted Root entry after OS
password authentication, including post-authentication checks, control/Zeek
preparation, capture, analysis and cleanup. START is bounded by the same absolute
deadline; it cannot extend it. Capture remains at most seven seconds with the
existing close/finalization reserve and at most 32 records/512 bytes. Slow startup
reduces available capture time. Cleanup can continue for safety after timeout,
but any overrun fails qualification. No Native timing success is claimed here.

## Focused verification

- Actual ordinary-user PTY parent/child test proves inherited stdin remains a TTY
  while protocol stdout is separate. There is no sudo or password test input.
- Real ordinary-user Unix sockets verify SO_PEERCRED, peer mismatch rejection,
  canonical Session/Image/Manifest/Approval/Scope/type/sequence mismatch rejection,
  timeout, oversize and duplicate START rejection, and abstract-listener release.
- The full launcher integration mocks only Root/traffic and explicitly substitutes
  an ordinary-user test peer. Real capless, network-disabled Zeek must reach READY
  before START. Authentication rejection and missing-Root-diagnostic cases cannot
  start Zeek/probe; their listener is released and original evidence is retained.
- Embedded image compilation/wiring and fault-injected diagnostic dispatch verify
  stage/API/errno/exit-code preservation and secret-text exclusion without calling
  the actual Root function.
- Real Zeek analyzes synthetic UDP/TCP memory input with unchanged DNS transactions,
  Counter/CLOSED and owned-container cleanup. These are file/memory tests, not
  Native capture, DNS traffic or proof of actual PAM acceptance.

Ruff, format and diff checks are limited to changed files. No broad GUI/model or
TCX regression suite is repeated. Source-only export excludes existing user
changes, Native evidence, models and raw datasets; Workspace/Export/Stage hashes
are compared before selective commit.

## Candidate and next approval

DNS Sidecar **0.5.20**, prepared but not Native executed:

- Manifest: `414aea0feb53a5b1e424d4157a602687f3b8906f484d64e6bda6d1ca260087d5`
- Bundle: `de4208dc9c1439135baf2d05bed4a89b0249dfd59b72036fd723bfcee10f76d0`
- Execution image: `a2ad9ecccb569f185323f78d62a4cf7fc805a9670a84e4b0d4e35e34ab571e39`
- Candidate: `.git/dns-tty-start-remediation-0520/release-final/`.

No Root installation/replacement is required. Installed TCX 0.5.16 and previous
0.5.19 candidate bytes remain unchanged. Rollback is stopping candidate selection
and leaving the prior images intact; failed 0.5.19 is not automatically rerun.

Separate approval is required for this exact new image and one diagnostic run:
net:[4026531833], lo, whole active deadline 10 seconds, capture at most 7 seconds,
32 packets, 512 bytes, Queue32; existing 127.0.0.53:53, native-0516.localhost.,
A, exactly one UDP and one TCP query. No external DNS, system DNS/offload change,
Root install, TCX operation or automatic retry. Recheck the existing service and
release identity immediately before any future approved Native execution.

Native TTY/policy/Root-peer acceptance, actual DNS E2E and deadline compliance
remain PENDING. Campaign usage stays **1/3**, two remaining. Native AI, DNS9 and
operational promotion remain **BLOCKED**.

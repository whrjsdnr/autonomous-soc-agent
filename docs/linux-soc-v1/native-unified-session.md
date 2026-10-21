# Unified native application session

The normal entry is now implemented:

```bash
soc-agent start --gui --monitor total --collector ebpf-tcx
```

The ordinary-user CLI first verifies the installed release, builds an exact source
candidate, displays the complete installation/authentication/capture scope and
requires `yes` once. It never asks the operator to type a Digest. One fixed sudo
invocation with `-k` requests the OS terminal password. Installation, Broker
qualification and one bounded capture use that same authenticated process tree.
No separate A/B/C application restart or auth-only qualification is required.

## Execution and authority

The installed release remains `/usr/libexec/soc-agent-ebpf`, root:root, executable
files 0555 and other files 0444. All nine file hashes, previous and target Manifest,
image SHA, namespace, lo/Ingress, duration 300s, metadata budget 4096, queue 32,
256MiB address space and 20 CPU seconds are displayed together. AI, DNS9 and
operational promotion remain BLOCKED. This qualification entry authorizes one run;
it does not enable the GUI restart button or silently authorize additional runs.

The previous standalone installation engine is reused, with no permanent Root
service or new setuid entry. The fixed OS entry is:

```text
/usr/bin/sudo -k -u root -- /usr/bin/python3 -I -S -c <reviewed SHA-pinned loader>
```

The approved image is user-owned 0400, not falsely classified as a Root-owned
executable. The isolated system-Python loader opens it without following a symlink,
checks owner/mode/single link/size/SHA and compiles exactly the held byte snapshot.
Its source embeds the exact reviewed files and installation engine, imports only
system standard-library modules and never imports the development repository as
Root. Its SHA is part of the combined session approval. System Python/sudo hashes
and fixed dependency/configuration snapshots are rechecked; this does not prove
complete dynamic runtime closure or make the operational Release gate ready.

Before installation writes, a sealed candidate Bootstrap performs the existing
strict password-policy check: actual Root/TTY/numeric sudo identity, supported
sudoers/PAM policy, no NOPASSWD/exemption and nonempty local password policy. This
is a policy check, not a second authentication. Actual sudo alone requests the
password. It does not use sudo -S, askpass, a GUI password, a cached grant or -K.

Matching installations are verified and skipped. An exact outdated installation
must be quiescent; it is atomically unpublished to the digest-named rollback
archive, never recursively deleted or overwritten. Unknown installation state is
rejected. Failed publication stops without capture; the retained exact previous
release remains available for separately reviewed restoration. This update uses
a brief unpublished interval rather than claiming an atomic two-directory swap.

After installation verification, Root creates a sealed 512-byte in-memory FD binding
the entire 352-byte session envelope, image SHA, previous Manifest, original sudo
command SHA, own PID/start ticks and monotonic issue time. It execs the held,
SHA-verified installed Bootstrap without changing PID. Bootstrap verifies this
Root-owned proof, exact sudo parent/argv, age, scope, policy and the Controller's
separately supplied sealed envelope. It closes the proof and reuses the existing
Broker handoff, root release checks and privilege reduction. The proof is never
stored or sent to the GUI. The original Controller, GUI and model process tree
remain ordinary-user processes. No arbitrary path, shell command or Link ID is
introduced into the Broker interface.

The same Broker handles STATUS then ATTACH with increasing request sequences.
Failure stops progression and closes the session once. No authentication, capture
retry, foreign-Link removal, pinning or persistent grant is introduced. Existing
TCX_NEXT(-1), object ABI, data plane, Network14 and Zeek contracts are unchanged.

## Actual qualification on 2026-10-21

One user-confirmed unified application ran, session
`9f004895-eff5-41b2-93a7-a80d2752ab04`.

- Exact installed 0.4.5 was checked before building/approving 0.5.0.
- Root installation 0.5.0 and all nine ownership/mode/SHA checks succeeded.
  The exact previous release was retained.
- Fresh OS authentication and Root Bootstrap → ordinary-UID Broker IPC succeeded
  in the same invocation. There was no second authentication application.
- Observed Broker Permitted/Bounding were exactly CAP_BPF + CAP_NET_ADMIN;
  Effective/Inheritable/Ambient were zero at handoff. This is not evidence that
  those capabilities sufficed for the subsequent Kernel load.
- STATUS used sequence 1; ATTACH passed the previous Controller replay barrier and
  reached the native `LOAD_REQUESTED` checkpoint.
- ATTACH was rejected by the Broker. No `LOAD_VERIFIED`, TCX attach request or
  verified Link identity was recorded. The exact failing substep inside load is
  UNKNOWN: the existing loader suppresses libbpf diagnostics and collapses several
  failures into generic return codes. No verifier-success claim is justified.
- Delivered metadata, normalized packets, Network14 finalized flows/features: 0.
  Three data frames were protocol/control evidence, not three packet observations.
  Queue overflow was 0; Kernel counters and ring loss remain UNKNOWN, not zero.
- GUI launch was not reached. No model or Native AI inference ran.
- Broker PID 725214 exited, entry exit code 2, application exit 1, authorization
  REVOKED. Native cleanup remains CLEANUP_UNVERIFIED. No automatic retry occurred.
  An application-preparation cleanup event does not supersede the Native result.
- The six-record Native Journal chain verified. Its final claim is
  CLEANUP_UNVERIFIED and recovery requires user review. Existing noqueue and empty
  Legacy ingress/egress filter views were preserved; these views alone do not
  constitute a complete privileged TCX inventory.

Read-only libbpf object inspection reproduced `SCHED_CLS` type 3 and expected TCX
attach types 46/47 for both sections under installed libbpf 1.3.0. This rules out
an unrecognized section/type as the immediate explanation, but neither proves
Kernel TCX support nor identifies the failing Kernel/libbpf substep. Do not upgrade
libraries, broaden capabilities or retry based on speculation.

## Verification and remaining work

Eight focused new cases cover immutable-byte exec/replacement, hook/budget/release
rejection, policy failure before writes, one CLI route, same-Broker control sequence
and ordinary-UID authority-FD forgery rejection using real C. Related STOP/sequence,
installation preservation, confirmation and authentication boundary tests were run.
No broad model, GUI performance or screenshot rerun was needed. An independent
HEAD-plus-20-file export reproduced the executed source Bundle and passed the
17-case focused/STOP/sequence run. Changed-file Ruff/Format/Diff and the Wheel
passed. The Python package version remains 0.1.0; the separate Native release is
0.5.0. Existing user files (132 baseline entries), older evidence and model/data
artifacts were preserved.

The implementation addresses repeated approval/authentication lifecycle boundaries.
The actual packet path remains BLOCKED at native load. Next work must retain the
first load substage and raw errno safely, distinguish pre-load trust checks from
actual BPF syscalls/verifier rejection, and test that small change before preparing
another exact release. Any further Native attempt requires fresh session approval;
there is no automatic retry. Full dynamic closure, Kernel TCX qualification,
verified Link cleanup, Native Network14 and GUI/Audit E2E remain unproven.

Exact executed identities and counters are recorded in
[native-unified-session-evidence.json](native-unified-session-evidence.json).
Private session databases, executable images, binaries, Native journal and original
results remain under `.git/tcx-c2-execution/`, outside Git staging.

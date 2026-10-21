# Native BPF inspection privilege separation — Release 0.5.8 candidate

Implementation and unprivileged qualification only. No sudo/PAM authentication,
Root installation, capability transition, BPF resource enumeration, load, attach,
detach, capture or traffic occurred. Native and Root-install budgets remain2/3;
this work consumes neither remaining attempt. Installed0.5.7 is preserved.

## Verified source cause, distinct from historical errno

The running-kernel tag is `linux-msft-wsl-6.18.33.2`. In its
[kernel/bpf/syscall.c](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.18.33.2/kernel/bpf/syscall.c),
`bpf_obj_get_next_id()` checks CAP_SYS_ADMIN. The PROG/MAP/LINK GET_NEXT_ID cases
all call it; their GET_FD_BY_ID handlers also check CAP_SYS_ADMIN. In
[include/linux/capability.h](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.18.33.2/include/linux/capability.h),
`bpf_capable()` accepts CAP_BPF or CAP_SYS_ADMIN; that broader common check does
not remove the explicit SYS_ADMIN checks on global enumeration.

| Fixed command | bpftool7.4 API | Kernel handler/check |
|---|---|---|
| prog show | bpf_prog_get_next_id; bpf_prog_get_fd_by_id | bpf_obj_get_next_id / bpf_prog_get_fd_by_id: SYS_ADMIN |
| map show | bpf_map_get_next_id; bpf_map_get_fd_by_id | bpf_obj_get_next_id / bpf_map_get_fd_by_id: SYS_ADMIN |
| link show | bpf_link_get_next_id; bpf_link_get_fd_by_id | bpf_obj_get_next_id / bpf_link_get_fd_by_id: SYS_ADMIN |

The exact tagged [prog.c](https://github.com/libbpf/bpftool/blob/v7.4.0/src/prog.c),
[map.c](https://github.com/libbpf/bpftool/blob/v7.4.0/src/map.c) and
[link.c](https://github.com/libbpf/bpftool/blob/v7.4.0/src/link.c) establish these
calls. The previous SUP_MASK contained BPF+NET_ADMIN, so its global query cannot
satisfy that check. This explains the structural mismatch at
RESOURCE_INSPECTION_PROGRAMS; it does not manufacture an observed Native errno.
The historical diagnostic still has errno UNKNOWN.

The fixed `tc filter show` uses RTM_GETTFILTER. The tagged
[rtnetlink GET handling](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.18.33.2/net/core/rtnetlink.c)
and [tc_dump_tfilter](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.18.33.2/net/sched/cls_api.c)
do not impose the non-GET NET_ADMIN requirement for this dump. Its helper gets
zero capabilities; failure in the actual environment still blocks admission.

## Read-only includes tool build behavior

bpftool can build PID references by loading a BPF iterator, even during show.
[pids.c](https://github.com/libbpf/bpftool/blob/v7.4.0/src/pids.c) compiles that path
out under BPFTOOL_WITHOUT_SKELETONS; main.c reports the corresponding feature.
The actual pinned7.4.0 tool reports skeletons:false. Candidate preparation checks
`-j version` through a held SHA-verified executable FD with clean environment;
this is a version probe, not BPF inventory. The Root contract requires this known
build, and every execution rechecks the approved tool SHA/path/mode. A skeletons
build, unknown build, changed tool, mutable/setuid/setgid file or file capability
is rejected. No tool upgrade or unsupported-feature fallback is automatic.

## Selected separation and authority lifetime

A helper with extra privileges only at startup would still leave the final
inspection broken: once the Supervisor bounding set is reduced, it cannot regain
SYS_ADMIN without another authority boundary. Giving SYS_ADMIN to the TCX Broker
or Supervisor's general operation path was rejected.

The existing authenticated Supervisor therefore forks one private, session-limited
Inspector **before** reducing its own capabilities and before any object/Link or
Bootstrap authority FD exists. It is not an installed service and does not start
on boot. The original sudo child still execs the original Bootstrap directly;
the existing OS-parent and authority proof contract is unchanged.

| Role | Authority |
|---|---|
| Inspector worker | Root UID, permitted/bounding SYS_ADMIN only, idle effective/inheritable/ambient zero |
| BPF query helper | Fixed held bpftool FD, effective/permitted/inheritable/ambient SYS_ADMIN while executing |
| TC GET helper | Fixed held tc FD, effective/permitted/inheritable/ambient zero |
| Supervisor proper | Existing BPF+NET_ADMIN permitted/bounding, E/I/A zero |
| TCX Broker | Existing numeric UID and BPF+NET_ADMIN contract, unchanged C binary |
| GUI, Network14, DNS adapter, model workers | Ordinary-user existing runtime, no Inspector or privileged Link FD |

Helpers inherit the Inspector's bounding ceiling but cannot regain removed
permitted capabilities: secure NOROOT, no-new-privileges, clean environment,
no privileged executable modes or file capabilities. Each fixed tool call has
<=5s wall time and bounded16KiB output. Inspector has AS256MiB, CPU20s,64FDs,
<=330s life; these are per-process ceilings, not an aggregate application memory
claim. Preparation counts within the <=300s active window; <=30s is reserved for
final inspection/exit. The readiness bound30s is derived from five <=5s queries
plus IPC overhead, replacing queries previously performed outside the ready wait.
It is not a retry or a query timeout increase.

Only the per-session Inspector retains the authority needed for the two snapshots.
Fixed query helpers are short-lived. Both worker and helpers set parent-death
SIGKILL before use; privileged files that could clear that contract on exec are
rejected. Normal shutdown requests STOP, closes the private socket, waits/reaps
that exact child and records its PID/start-ticks/exit receipt. A crash, expiry or
missing exit receipt remains CLEANUP_UNVERIFIED. Actual signal/capability/FD
behavior still requires Native qualification; no fixture proves it.

## Private IPC and admission

The socketpair is created inside the Supervisor child and has CLOEXEC. Inspector
closes inherited descriptors except stdio and its private IPC. It cannot inherit
object/Link/authority FDs that do not yet exist. Root C Broker is the original
parent branch, so it never receives this descendant-only socket. GUI receives
JSON evidence only, through the existing supervised channel.

Every message checks Kernel SCM_CREDENTIALS UID/GID/PID, owning PID/start ticks,
sequence and a binding derived from the existing session/Manifest/approval
Envelope. Schema admits only SNAPSHOT and STOP, no argv/path/namespace/interface.
Exactly two snapshots are allowed; failure consumes the phase, no query retry.
Namespace and lo ifindex are rechecked on each snapshot. Global BPF IDs are
system-wide observations; they are not falsely labeled namespace-local objects.
Every request/reply is bounded and SCM_RIGHTS/truncation is rejected/closed.

The Supervisor independently verifies Inspector hello against its actual /proc
capability sets. Hello and final exit evidence enter the existing append-only
Supervisor Audit events. Release Manifest carries a closed InspectorProfile;
legacy manifests omit that optional field when serialized, preserving their
original hashes. A Manifest change does not grant Native authorization.

Start: same Inspector snapshot -> admission rejects any existing Link or lo
filter/uncertain ownership -> only then Broker readiness/Attach may proceed.
End: existing owned-FD Broker cleanup -> same Inspector snapshot -> compare
Program/Map/Link/filter identities -> stop/reap Inspector. Inspector is an observer,
never a resource owner by global ID. It does not pin/unpin/detach/delete foreign
objects. After-snapshot residual Link IDs are retained in evidence and force
CLEANUP_UNVERIFIED; they are not discarded as a generic query error.

## Failure and cleanup

Query failure is not an empty list. Inspector errors retain actual OSError errno
when available and propagate the resource stage. Collector stop/quiescence
failures do not skip independent inspection or Inspector disposal. Inspection
uses IPC, so no Python preexec/fork runs in a Supervisor with an active streaming
thread. Both stream and inspector errors remain recorded. Public Supervisor close
still calls the existing TCX-owned cleanup even when companion STOP fails.

The earlier0.5.7 recvmsg correction is preserved: MSG_CMSG_CLOEXEC is a valid return
bit; only truncation/error conditions reject a message. Rejection codes remain
private diagnostics and never authorize a session.

## Tests and limits

58 focused tests passed in27.15s: Inspector capability/command contracts, two-phase
snapshots, session/replay/scope rejection, real ordinary-UID SCM credentials,
forged Root peer rejection, denied queries, foreign/residual Link preservation,
post-inspection failure/disposal, owned-TCX cleanup callback, PID reuse, socket
close/exit receipts, privilege-changing tool rejection, parent-death setup order,
autoload build rejection, existing Supervisor/Zeek transport and pre-auth startup
boundaries. Capability/signal transitions are mocked; no actual Root worker or
Kernel query was launched. The compiled Bootstrap/Broker/Loader/TCX hashes match
the installed0.5.7 binaries. GUI/model/Zeek contracts were not changed, so no broad
model/GUI regression or performance claim is made.

Read-only enforcement here is the fixed reviewed code/command contract plus the
pinned non-autoload tool build. CAP_SYS_ADMIN remains a broad kernel capability;
this is not a claimed seccomp syscall sandbox. That residual risk and actual
runtime capability/lifetime behavior require explicit Native approval and review.

## Qualified candidate and installation

- Release:0.5.8
- Manifest:`a87e355d82eea4b9c5fe319ce98f6ff2417f3c441900ef1615397dc62f6c660d`
- Bundle:`23afc66ee561d047dc2ee20be3c1aa5cafdcb76f97a149f4541006c8cd8b63e7`
- Execution image:`84338aa2904e28b3eb35f4a6a988ae6da145ee26cb79b81d2713ee2b5c50107a`
- Previous installed Manifest:`e2720acc03d8ed9a77e7e5b69db3cd564c1b1b4607fb6556d9164400ddc0b458`

See [all nine hashes and profiles](native-bpf-inspection-privilege-separation-evidence.json).
The qualified private package is `.git/native-inspector-separation/qualified-release/`;
earlier private builds are superseded and unapproved. Installed0.5.7 was verified
read-only and remains unchanged. Future installation must retain it at
`/usr/libexec/.soc-agent-ebpf.rollback-e2720acc03d8ed9a77e7e5b69db3cd564c1b1b4607fb6556d9164400ddc0b458` (currently absent) without disturbing earlier rollback archives.
Executables remain root:root0555 and other files0444, no setuid/file capabilities.
No actual installation or rollback was performed.

The remaining Native budget is untouched (used2/3, install2/3). Running the new
Inspector SYS_ADMIN scope, its330s bounded lifetime and per-process budgets, and
the exact0.5.8 SHA requires separate approval. Existing lo/Ingress/net:[4026531833]
Capture scope and passive Zeek limits do not expand. Actual resource inventory,
capability sets, Kernel verifier/Attach, Live events and cleanup remain PENDING.
Historical Cleanup UNVERIFIED is not retroactively changed. Native AI, DNS9 and
operational promotion remain BLOCKED.

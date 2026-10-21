# Unified Native Supervisor — single authentication candidate

Implementation candidate, not Native E2E qualification. No Root installation,
sudo/PAM authentication, capability change, BPF load/attach, capture or traffic
was performed for this change. The installed release remains 0.5.3. Existing
TCX Link state remains UNKNOWN following the earlier unprivileged EPERM; tests
do not replace a privileged inventory. Native AI, DNS9 and promotion remain BLOCKED.

## Root causes and selected boundary

The previous TCX image authenticates through `sudo -k <fixed command>`, which
ignores and does not populate a reusable timestamp. The independent Zeek launcher
and inspection commands used `sudo -v`/`sudo -n`. They were not one authenticated
application session. Removing `-k`, trusting a persisted approval, or adding another
password request does not meet the session contract.

The new entry uses the existing Root-owned sudo/system-Python entry and SHA-pinned
held-image execution. No setuid path, authentication daemon, PAM implementation,
Root GUI or arbitrary command tool is introduced. The application prompts for one
scope approval and one fresh OS terminal password. Existing C password-policy and
OS-parent checks still reject unsupported/NOPASSWD policy; their real execution is
not certified by fixtures.

After installation/manifest checks, the authenticated image performs bounded
read-only BPF Program/Map/Link and lo ingress/egress inspection. Any query failure,
malformed output, existing Link, or existing Legacy filter stops before Bootstrap
and BPF load. The initial policy conservatively blocks any existing Link, including
unrelated Link types; it does not infer ownership from a name or delete resources.
Kernel queries use fixed verified executable FDs and minimal inspection capability
scope. Each output is <=16KiB and <=128 entries. Foreign identity sets are compared
after teardown; mutable runtime counters are not mistaken for identity changes.

Before any BPF object, Link or authority FD exists, the approved image forks a
bounded privileged Supervisor sidecar. The original process continues, with the
same PID and sudo parent, through the existing Bootstrap proof and numeric-UID
TCX Broker privilege drop. **The C proof, TCX ownership implementation, parser and
BPF object are unchanged.** This avoids a new authority proof ABI or weaker parent
validation. A permanent Root service was unnecessary.

The sidecar owns only inspection and the fixed Zeek container lifecycle. The
ordinary-user `SupervisedSession` coordinates that sidecar and the existing TCX
Broker IPC. New TCX work requires the companion session; STOP/DETACH/CLEANUP keep
the original held-Link-FD path even after companion trust/session failure.

## Permission and data separation

| Component | Intended runtime boundary |
|---|---|
| Initial installation/authenticated image | Short existing Root installation and policy boundary; no GUI/import of project code |
| TCX Broker | Existing numeric caller UID; permitted/bounding CAP_BPF + CAP_NET_ADMIN, idle effective/inheritable/ambient zero |
| Supervisor | Root UID for the local daemon socket; permitted/bounding CAP_BPF + CAP_NET_ADMIN, idle E/I/A zero; no-new-privileges, non-dumpable, cleared supplementary groups |
| Inspection helper | Fixed held executable FD; only CAP_BPF + CAP_NET_ADMIN during fixed read-only queries |
| Zeek container | Existing pinned image, NET_RAW only, cap-drop ALL, no-new-privileges, read-only root filesystem, host network with explicit namespace check and lo filter |
| Network14, DNS adapter, GUI, AI | Original ordinary-user Controller; no privileged Kernel/authority FDs |

Capability transitions exist as code but have not been executed in this task.
Kernel/tool compatibility and actual permitted/effective/bounding/ambient sets
remain Native qualification requirements. No CAP_PERFMON or CAP_SYS_ADMIN fallback
is added if inspection/load fails.

TCX still returns TCX_NEXT(-1), never drops/modifies packets, owns its Link FD,
forbids pinning and never removes a foreign Link by global ID. TCX timestamps,
counters, sequence/loss, Network14 quality and Zeek event clocks, DNS diagnostics
and capture counters stay separate. No counter sum becomes capture attestation.
No feature, preprocessing/model contract or model artifact changes.

## Supervisor IPC and lifetime

The abstract Unix SEQPACKET endpoint derives from UID/application session. Both
sides verify SO_PEERCRED; each message has Kernel SCM_CREDENTIALS, an exact
session/approval/envelope binding and sequence. PID/start ticks, Root sidecar
parent Broker identity and observed capability sets are checked. Messages are
<=16KiB, <=32 requests/second and bounded by the application lifetime. Unexpected
SCM_RIGHTS on command requests is closed and rejected. Replies may transfer one
**read-only FIFO** for Zeek metadata; Link/object/authority/regular-file FDs fail
validation and are never delivered to GUI/AI workers.

The sidecar allowlist is STATUS, START_ZEEK, STOP_ZEEK and STOP. TCX retains its
existing PREPARE/ATTACH/STATUS/DETACH/STOP/CLEANUP allowlist on its separate control
channel. No argv, executable path, BPF path, shell fragment or Link ID is a command
parameter. Scope-changing plans fail validation. Reply sequences/digests are
checked while connected; important commands, the verified pre-inventory and final
cleanup are appended to the existing application Audit. No password, sudo token
or reusable authorization is persisted. Recovery cannot recreate this session.

The research candidate admits one explicit Zeek start and one TCX run. A failed
start consumes the attempt; there is no automatic retry/restart. Manual repeated
runs are not exposed by this qualification entry. A future manual restart policy
must retain one authentication and enforce aggregate session budgets rather than
silently resetting them.

The Supervisor active lifetime is <=300s, followed by bounded cleanup; address space256MiB, CPU20s, descriptors64.
The TCX scope remains lo ingress, net:[4026531833], <=300s/4096 records, queue32,
256MiB/CPU20s. Zeek retains its existing separate limits: <=300s, packet4096,
events8192, output8MiB, queue32, container RAM512MiB, CPU1, tmpfs16MiB, fixed image.
Those container limits are not a new expansion of the TCX memory budget.

## Docker transport root cause and fixed API

An ordinary-user, non-capturing `docker --version` probe under RLIMIT_AS256MiB
failed with exit2: `fatal error: failed to reserve page summary memory`. Thus
spawning the Go Docker CLI below the bounded Supervisor would fail before capture.
The fix does not increase the address-space limit or use cached sudo.

The Supervisor instead uses the standard-library HTTP client on the fixed
Root-owned `/run/docker.sock`, verifies the Root daemon peer PID/start ticks and
namespace, checks support for pinned Engine API v1.51, and exposes only the fixed
owned-container create/attach/start/inspect/stop/remove operations internally.
No DOCKER_HOST, user Docker config/context, credential helper, network endpoint,
client executable or user-selected API URL is accepted.

The pinned image and existing scripts/command are reused. Only reviewed scripts
are materialized in a newly created Root-owned private `/run/soc-agent-ebpf/<id>`
directory; names/contents are embedded in the approved image. No user-writable
host policy directory is mounted. HTTP JSON bodies are bounded16KiB; attach headers
have a5s deadline, the lifetime bounds idle stream reads, multiplex frames are
<=64KiB and output<=8MiB. Stream backpressure/short frames/errors are explicit,
not silent drops. Existing `StreamProcess` validates privacy/schema and persists
metadata in the ordinary-user session before the existing DNS/Network14 adapters.
See the [Docker Engine API reference](https://docs.docker.com/reference/api/engine/version/v1.51/)
for attach multiplexing and fixed container operations.

AutoRemove is disabled so the exact created container's exit code can be verified
without a race against automatic deletion. Cleanup checks its returned full ID,
image, session digest and generation labels, and stopped state, then removes only
that ID with force=false and volume deletion disabled. An ambiguous create result
or ownership mismatch is CLEANUP_UNVERIFIED, never a name-only adoption/deletion.
Failed/blocked stream teardown prevents forking a query helper from a multithreaded process and records post-inspection as unverified. Forced death may leave a bounded container or policy directory; it is not silently
removed on recovery. Existing external containers are never cleaned up.

## Lifecycle, failures, GUI and Audit

Preparation and authentication precede RESOURCE_VERIFIED and TCX_READY. The
ordinary-user Zeek watcher must observe actual live stream readiness before the
entry requests TCX ATTACH. ZEEK_READY at the sidecar means process preparation;
aggregate ACTIVE requires both actual Zeek live state and verified TCX Link state.
There is no Native ACTIVE claim from a mock.

Stop first requests container teardown, then runs existing TCX held-FD cleanup.
Partial failure still reaches the other cleanup, post-inventory and descriptor
release. Failed stop is recorded and not retried automatically. EOF, peer loss,
controller/Broker crash, deadline and signals revoke new work. The sidecar waits
boundedly for the TCX parent to exit before post-inspection; unexpected identity
changes or unverified cleanup remain ERROR/CLEANUP_UNVERIFIED. SIGKILL cleanup is
not proved by a fixture or FD-lifetime assumption.

The four existing GUI screens/graphs remain. System status includes the separate
Supervisor lifecycle/final evidence and Zeek summary alongside TCX processing;
UNKNOWN remains unknown. No GUI or AI process is spawned by the privileged image.
Live rendering and Native cleanup are PENDING. The existing Zeek standalone launcher
is preserved for compatibility; **its separate legacy cache path is not the unified
entry**. Only the new supervised entry eliminates downstream sudo/cache dependence.

## Verification and candidate

Focused tests cover replay/schema/scope, query failure and foreign resources,
partial start/cleanup failure, no cleanup retry, actual ordinary-UID SEQPACKET
credentials and FD transfer, forged Root response rejection, no secondary Zeek
authentication, container capability/resource contract, foreign container protection,
real HTTP parsing over a socketpair, and separate held-FD cleanup after trust loss.
The existing authentication/image tests and pinned real Zeek offline DNS paths are
also checked. These are fixtures/offline PCAPs, not Native Root/Kernel tests. No
whole model suite or hundreds of regressions are repeated. Exact logs and candidate
identities are in the accompanying evidence JSON.

Preparation only:

```bash
PYTHONPATH=src .venv/bin/python -m soc_agent.security_ai.ebpf_tc.supervisor_startup NEW_DIRECTORY
```

After a separate approval of the exact new Manifest, Bundle and Supervisor image
SHA, the ordinary-user entry accepts the same directory with `--execute --manifest
EXPECTED_SHA --image-sha EXPECTED_SHA` and optional `--gui`. It displays scope,
requires explicit confirmation and then asks sudo for the OS password once. The
SHA values are public integrity identities, not saved authentication credentials.
Do not run the old TCX-only launcher for this combined qualification.

The new candidate is0.5.5, based on0.5.4 code; installed0.5.3 is retained until a
new installation is approved. Previous directories are preserved for an explicitly
reviewed rollback. Old0.5.4 approval does not authorize this new execution image.
Remaining Native checks: Root install/rollback, actual fresh-password policy,
capability transition and leakage, privileged pre/post inventory, Docker daemon
API/namespace, TCX load/attach, actual TCX+DNS delivery, clock/loss, GUI, drain and
independent cleanup evidence. Native Release, Native AI, DNS9 and operational
promotion stay BLOCKED until their separate evidence and approvals exist.

## Frozen candidate identities

- Manifest: `4bba3952647a2655d877548aecc79c2821d17b708bd7d42bec5ca536b04414dd`
- Source Bundle: `902eb82eb43c05ad9962c1af00d20ccee9f9e9ce965f3619c799f01555770f7b`
- Supervisor image: `d5bfe01c749036e3ba2499d2ea3658f8b4cf51b8a730364063ce90037a905242`
- Zeek source bundle: `8a422950144a7070610fc5d5e8b703efc19fcbd26f95d5c239b2374c233e257d`
- bootstrap: `80b1e23e0213cfcdb0543be5094c118b91c4c343575d8956a855326d6359ea9a`
- broker: `9919d3c5d9e02aa88be31360c9e29a2b4c0fd6953fae03e8835c033d71809b76`
- libnative-tc.so: `943f0b2e42350d661b5d20c6879ec8ce0119fbd070889e12c29ac55cd7213ae9`
- tc.bpf.o: `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06`

Private candidate: `.git/native-supervisor-candidate/release-candidate/`. No installation or Native execution is included in these results.

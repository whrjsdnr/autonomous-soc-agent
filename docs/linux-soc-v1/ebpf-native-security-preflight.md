# eBPF Native security preflight and release qualification

Baseline SOC `e699db6972619c09da14d1e27cad2fbb84fb5f67`, ML
`e1a01260f0463a38d4d778859bc2a86f8e9cfbde`. Implementation, compilation, ordinary-UID
filesystem/Unix IPC, adversarial fixtures and offline regression scope only. No PAM/sudo,
Kernel BPF load, TC attach/detach/qdisc change, AF_PACKET capture or test traffic was executed.
The Native admission gate remains closed. **Native release: BLOCKED.**

## Threat model and preservation

Untrusted callers may alter development artifacts, substitute links/parents, inject dynamic
loader/Python environment, replay approval/messages, delegate a socket FD or crash a controller.
A separate privileged TC administrator may replace a filter after our last ownership query.
Root/kernel compromise is outside the trust model; a manifest/hash is identity, not proof that
its contents deserve installation. Existing Zeek, v2/v3, Network14/DNS/model contracts and
four-screen production GUI are preserved. No old audit/session is edited. Initial Stage empty.
Existing user changes are SHA-inventoried separately and excluded from the Export/commit.
The previous B-2A report/evidence remain historical, including their superseded artifact SHA.

## TC ownership race and safe failure

[libbpf 1.3 TC implementation](https://github.com/libbpf/libbpf/blob/v1.3.0/src/netlink.c)
rejects nonzero prog_fd/prog_id on detach and sends RTM_DELTFILTER with interface, parent,
priority/handle and kind; it does not include an expected Program ID/tag. Therefore querying
again immediately before deleting does not establish compare-and-delete. The old real detach
callback had exactly this race. It is removed: real Attach **and** Detach now independently
return EOPNOTSUPP without querying/mutating TC, even if someone later changes only the global
gate. Native linking no longer imports bpf_tc_attach or bpf_tc_detach. The compiled verifier/
map/query paths remain behind the separate admission gate. No incomplete cleanable lease is
created by this preflight release.

Adversarial C scenario 15 changes the fake filter to Program 999 at DETACH_REQUESTED, after
all core queries/snapshots. Calling the actual blocked detach callback preserves that filter,
performs zero deletes and produces CLEANUP_UNVERIFIED. This proves safe refusal, not atomic
Native detach. Owner generation, session, namespace, interface and hook mismatch scenarios
also refuse deletion. Existing program ID/tag, collisions/partial failure/foreign preservation
fixtures remain. No qdisc deletion/creation or external-filter overwrite is introduced.

Alternatives: a private chain or reserved priority is collision isolation, not exclusion of
another CAP_NET_ADMIN writer. A private hook requires an independently enforceable exclusivity
contract. Kernel-owned BPF link/TCX attachment lifetime is a promising separate design but
[libbpf 1.3 public header](https://github.com/libbpf/libbpf/blob/v1.3.0/src/libbpf.h) has no
TCX attach API; compatibility, ABI/ownership and kernel behavior need review. No new attachment
mechanism or dependency upgrade is silently substituted. **TC_QUERY_DETACH_RACE: BLOCKED.**

## Trusted installation and dependencies

`soc_trusted` now rejects dot/dot-dot/repeated-separator/noncanonical paths and hardlinked
regular files. All directory components, including root, are checked for root ownership and
non-writability by group/other using directory FDs plus O_NOFOLLOW. Hash consumers retain the
verified descriptor, avoiding pathname reopen after validation. The existing sealed object
and authority FDs remain session-bound; normal-user sealed data is not authentication proof.

The new read-only `release.py` generates a fixed installation plan and validates a root-owned
installation by held directory/file descriptors, regular-file/single-link/exact mode/UID/GID,
size/SHA and stable metadata. Private ordinary-UID filesystem fixtures use their own owner
explicitly and never report a Root installation. Public qualification always requires UID 0.
Required destination `/usr/libexec/soc-agent-ebpf`; modes bootstrap 04755, broker 0555,
loader/object/manifest 0444; root:root. These are future deployment instructions, **not actions
performed or permission granted**. The 160-byte manifest order remains Bootstrap/Broker/Loader/
Program/Bundle. Only plan JSON is generated; there is no root installer or install side effect.

Both Bootstrap and Broker now embed this project's C implementation and link only system
libraries; neither resolves libnative-tc.so nor has RPATH/RUNPATH. The ordinary-UID fake driver
alone uses $ORIGIN. This removes custom-DSO lookup after privilege transfer; it does not prove
system ELF interpreter, PAM/NSS modules or full dependency closure trustworthy on a target host.
Those remain explicit release blockers. The loader DSO is retained for inspection/fixtures;
its reviewed source is also compiled into Broker and bound by the Broker/source-bundle SHA.

Inspection/fixture launch passes a minimal environment, not LD_PRELOAD/LD_LIBRARY_PATH or
PYTHONPATH. An actual constructor-injection fixture verifies the inspection path does not run
an injected DSO. Direct unprivileged ELF execution is not simulated setuid/AT_SECURE behavior.
The future pathname-based Python privileged handoff has been removed; native_handoff always
refuses until a reviewed secure execution design is admitted. No development checkout binary
is executed as Root. Actual installation/dependency/PAM trust remains unverified.

## Startup authentication and capabilities

Preserve one explicit scope approval and terminal password per fresh application session.
Same approved app permits bounded manual fixture Start/Stop/Restart without reauthentication.
Restarting the application/Broker cannot restore authentication from disk. Scope change needs
fresh approval. Existing exact root-owned PAM policy and a single terminal ECHO_OFF challenge
are required; cached-only/NOPASSWD/no-TTY/cancel/timeout fixtures fail. The design uses the
fixed PAM bootstrap rather than treating sudo's timestamp as app authority. No real PAM
challenge, password, token, sudo invocation or installed setuid binary is used here.

The [Linux 6.18 capability definitions](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/capability.h)
describe CAP_BPF plus CAP_NET_ADMIN for networking programs and CAP_PERFMON for tracing.
This program is SCHED_CLS with ring buffers, not a tracing/perf program: keep the candidate
set CAP_BPF/CAP_NET_ADMIN, not CAP_PERFMON/CAP_SYS_ADMIN/NET_RAW. Bootstrap's temporary root
identity is only for reviewed PAM/capability transition; GUI/SOC remain ordinary UID. No extra
capability is added to satisfy a failure. Exact WSL LSM, program-ID lookup, ambient capability
transfer, memlock/cgroup limits and actual kernel behavior remain PENDING; the candidate set
is not claimed to be validated Native minimum privilege.

## Broker IPC hardening

Native ABI remains 272-byte plan / 112-byte fixed request, no path or shell argument.
At admission the existing SO_PEERCRED PID/UID/GID/start-ticks/namespace/type checks apply.
Broker now requires SO_PASSCRED and a matching kernel-supplied SCM_CREDENTIALS on **every**
message, so a child receiving the controller socket cannot impersonate the original PID.
Any SCM_RIGHTS is closed and rejected, including truncated ancillary data. Exact record size,
MSG_TRUNC/MSG_CTRUNC, allowlist, reserved fields, app approval and strictly increasing sequence
are validated in the shared C request decoder before dispatch. No message-supplied FD is used
as authority/object. A sliding 32-command/second budget complements 2048 commands/app and
32KiB socket buffers; overflow stops without waiting/retrying. AF_UNIX socketpair has no
filesystem socket pathname; no world-writable listener is introduced.

Real ordinary-UID IPC fixtures cover credentials, delegation/PID mismatch, extra FD, truncation,
missing credentials, replay and malformed commands. These do not prove privileged Broker
confinement. C validators are tested directly without invoking PAM, capability changes or BPF.

## Crash, journal and recovery

Existing ownership journal and supervisor bounds remain. Journal recovery now opens a held
O_NOFOLLOW/nonblocking FD, requires a regular single-link bounded file, caps rows while reading
and rejects metadata changes during recovery. Corruption never restores authority. An observed
attach without claimed cleanup is explicitly ORPHANED; process exit remains UNKNOWN. Recovery
never auto-authenticates, reattaches, infers, or blindly deletes a hook. A corrupt/missing log
is not evidence of clean shutdown. SIGKILL may leave legacy TC hooks; it is not treated as a
successful cleanup. Existing fixture crash/timeout/ownership tests exercise those contracts;
no real Native process is killed and no real orphan is removed. Bounded cooperative shutdown
cannot guarantee completion under SIGKILL or an uninterruptible kernel operation.

## Release gate and GUI

`ReleaseEvidence` always returns BLOCKED with BLOCKED_NO_ATOMIC_OWNERSHIP and B2A_CLOSED,
even if a caller supplies other VERIFIED labels. Fixture results cannot enable admission.
Trusted installation, fresh authentication, identities, IPC, capability scope, TC ownership,
safe detach, cleanup recovery, kernel compatibility and explicit approval all require separate
Native evidence/review; unresolved dependencies alone also prevent release. Native AI/DNS9/
operational promotion remain BLOCKED independently.

The existing four screens, cards/charts/timelines and backend are preserved. System adds
Native release state, safe-detach reason and kernel compatibility without fabricated metrics.
Authentication/Broker/ownership/cleanup indicators remain source-specific; NOT_OBSERVED and
NATIVE_PENDING are not presented as VERIFIED. Preparation/audit still use existing append-only
RuntimeStore; compiled identities and plan digest bind the new source without rewriting history.

## Nonprivileged commands and Native approval

```bash
.venv/bin/python -m soc_agent.security_ai.ebpf_tc compile --output /tmp/soc-ebpf-security-build
.venv/bin/python -m soc_agent.security_ai.ebpf_tc qualify \
  --artifacts /tmp/soc-ebpf-security-build --program /path/to/reviewed/tc.bpf.o
```

`qualify` verifies development artifacts against a source reference and emits an uninstalled
plan and BLOCKED verdict. It does not authenticate, install or attach. There is no admitted
Native launch command in this release. Before user-driven Native work: review safe link-based
or equivalent atomic ownership, resolve system dependencies/root installation/PAM/capability/
kernel preflight and orphan handling, issue a separately hashed admission release and approve
a fresh app's exact interface/namespace/hook/hash/resource scope. Existing lo-only, 300s,
4096 events, queue 32, 256MiB/20 CPU-seconds per Broker limits are not broadened. No automatic
capture restart, kernel filter change, Native AI or operational promotion is authorized.

## Verification results and source provenance

Final independent Export: **95 passed in 54.72s**, covering closed Native gates,
replacement after the last query, ownership mismatch, installation/link/path/environment
attacks, per-message kernel credentials/FD denial, rate/sequence checks, corrupted/orphan
journal, app auth/recovery, qualification CLI and GUI. Earlier workspace 88 and Export 93
runs are retained, not added to the final count. The last audit/typed evidence/CLI additions
are included in final 95. No pytest failure or SIGILL occurred; SIGILL root cause remains
UNKNOWN. Initial lint diagnostics were corrected without a security-control exception.

Separate fresh Export regressions (not summed as unique tests): B-1 63 passed; existing
unit 693 passed; integration 58 passed; actual offline Zeek/RF/LR/SOC 1 passed (two real
artifact receipts); GUI 17 passed; Audit/Recovery 125 passed. The broad run used the first
Export; 509 package source files outside ebpf_tc byte-match the final Export. Final 95
covers the final changed product source. No passed old result is relabelled a Native result.
RF/LR ran serially after three headroom samples of 4.29–4.35GiB available, PSI avg10
0.03→0.02 and avg60 0.36→0.33. Final queues zero, recovered audit digest equal, zero restored
new inferences; all advisory/investigation WRITE_DENIED and OFFLINE_RESEARCH only.

## Performance and limits

Five serial samples per group, same fixture and toolchain, baseline HEAD versus final Export:

| Median (fixture only) | Before | After |
| --- | ---: | ---: |
| Artifact/scope validation | 4.433ms | 4.454ms |
| Prepare including reference builds | 2.642s | 3.739s |
| Mock auth + B-1 child startup | 1.110s | 1.162s |
| B-1 STATUS IPC | 2.023ms | 1.828ms |
| C ownership transaction, fake operations | 15.48ms | 18.29ms |
| Fixture cleanup/exit | 306.2ms | 309.8ms |
| Fixture supervisor RSS | 144.30MiB | 144.27MiB |

Preparation increased about 1.10s because Broker now compiles the loader/core directly instead
of resolving a custom DSO. Reference compilation is part of this measurement. No claim of
Native startup/attach/authentication speed is made; real Root Bootstrap validation, capability
transfer, Native IPC/cleanup and Kernel performance are UNKNOWN. Resource samples accompany
each benchmark. No other user's process was terminated and no resource configuration changed.

Production GUI: three serial WSLg runs per group with no capture/inference. Startup median
2.4728s→2.5308s; idle RSS 174.75MiB→174.85MiB; idle CPU 0.255%→0.258%
of one core. Both retain two threads, zero idle children/background tasks/controller SQL
queries, no model service and clean shutdown. Variation is descriptive, not evidence of a
speedup. Small source/reference-build overhead is accepted to avoid privileged DSO search.

## New compiled identities (not installed or approved for Native execution)

| Component | SHA256 |
| --- | --- |
| Bootstrap | `f2bc7b066e136c54a34d2c11c14c204bc6689859ff746626247b97cd10c6569a` |
| Broker | `2bf7de6452f6839a5bb9495ddeff27387234c01d3342a4ce6068aada8ba35ba3` |
| Loader DSO | `505cac1ea671fab205d8948e68400e58a53dd7977ac04e7a0213ef6832524935` |
| BPF object (unchanged) | `69de609ea8ee90ecf90d091ec361e46e61ed0638b3175390c77305145e19d5f4` |
| Source Bundle | `bb78ad7a937633b2d61174a8487845e16f5e268519dafccdc5f604ef6f537b52` |

Full source/binary digests, source-bound tests, environment, models and measurements are in
[the companion evidence](ebpf-native-security-preflight-evidence.json). Existing B-2A
SHA/approval is not reused for these changed artifacts. The preflight verdict stays BLOCKED:
atomic TC ownership, trusted dependency closure/installation and actual authentication/
capabilities/kernel/cleanup evidence are still missing. GUI and Audit/Recovery are fixture
verified; Native auth/verifier/TC pending; Native AI, DNS9 and operational promotion blocked.

## Final Export quality and verdict

Ruff check src/tests PASS; Format PASS (1,217 files in clean Export); Diff PASS; offline
Wheel build PASS. Every packaged Python/C/header/Zeek/JSON/conf file was byte-compared
against Export. Native artifacts rebuilt from Export match the listed SHA and source bundle.
Only this report/evidence changed afterward; final product/test SHA still match the final
95-test Export. Workspace/Export/index/commit manifests are compared before selective commit.
Existing 132 user files and 388 protected files remain SHA-identical; 58 raw-dataset records
remain size/mtime/inode-identical. No Native artifact/model/session binary is staged.

| Requested verdict | Result |
| --- | --- |
| TC_QUERY_DETACH_RACE | BLOCKED; unsafe Native mutations removed |
| TRUSTED_INSTALLATION_CONTRACT | BLOCKED; file/plan fixtures pass, system dependency closure and installation unverified |
| AUTHENTICATION_CONTRACT | VERIFIED, Mock/static only |
| BROKER_IPC_SECURITY | VERIFIED, ordinary-UID IPC/adversarial fixture scope |
| CAPABILITY_SCOPE | UNKNOWN; candidate defined, Native transition pending |
| CRASH_CLEANUP_FIXTURE | VERIFIED; Native SIGKILL cleanup unproved |
| NATIVE_RELEASE | BLOCKED |
| GUI | PRESERVED |
| AUDIT_RECOVERY | VERIFIED, fixture/structural scope |
| NATIVE_AUTH / NATIVE_VERIFIER / NATIVE_TC_ATTACH | PENDING |
| NATIVE_AI / DNS9 / OPERATIONAL_PROMOTION | BLOCKED |

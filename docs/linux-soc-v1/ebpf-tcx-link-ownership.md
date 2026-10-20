# TCX/BPF Link feasibility and safe ownership migration — Phase B-2C

Baseline SOC `2a75c4b3fd95deb413f30b980ce8266fd5d342fa`, ML
`e1a01260f0463a38d4d778859bc2a86f8e9cfbde`. Compile, header/symbol checks, ordinary-UID
fixtures and offline regression scope only. No BPF syscall, TCX/TC attach/detach, qdisc change,
PAM/sudo, AF_PACKET capture or test network traffic. Native release, Native AI, DNS9 and
operational promotion remain BLOCKED. Legacy TC Native mutations remain independently blocked.

## API research and correction

The preceding Preflight report's claim that libbpf 1.3 has no TCX API was incorrect. It is
superseded here; historical evidence is preserved. Installed libbpf-dev/libbpf1
`1:1.3.0-2build2`, dynamic `libbpf.so.1.3.0`, headers and the official
[libbpf v1.3 source](https://github.com/libbpf/libbpf/blob/v1.3.0/src/libbpf.c) include
bpf_program__attach_tcx. Header compilation, address-based symbol linking and an ordinary-UID
probe resolve attach_tcx, link_create/update/detach/get_info and link destroy/pin/unpin without
calling any mutating function. Installed UAPI has BPF_TCX_INGRESS/EGRESS (46/47), TCX link type,
LINK_CREATE/UPDATE/DETACH, BEFORE/AFTER and REPLACE. Version labels alone were insufficient.

The installed libc UAPI is 6.8.0-147, not running-kernel build headers; matching build headers
for WSL 6.18.33.2 are absent. Kernel version and successful user-space linkage do not prove
CONFIG_NET_XGRESS, capabilities, Verifier acceptance or TCX attach on this host. Running-kernel
TCX support is **UNKNOWN_NOT_PROBED**. No bpftool feature/load or attempted link creation was
used as a probe. Exact environment/header/library digests accompany machine evidence.

## Kernel lifetime and Legacy TC risk

Legacy RTM_DELTFILTER identifies a slot, not an expected program. It stays BLOCKED; no re-query,
user-space lock, shared qdisc deletion or positional fallback is introduced.

[Linux 6.18 TCX implementation](https://github.com/torvalds/linux/blob/v6.18/kernel/bpf/tcx.c)
uses a specific link object under RTNL when detaching. A retained Link FD refers to that
object, not to whichever filter now occupies an interface/priority/handle. Link ID is evidence,
not removal authority. No get-by-Link-ID or foreign object deletion exists in the new provider.
An authorized administrator can still update/detach a link after obtaining a reference; this
is not protection against privileged interference or proof of complete capture.

Closing the last unpinned reference releases a link; duplicated FDs, pins or other references
can extend its lifetime. libbpf link destroy normally closes the FD, while explicit link detach
invokes BPF_LINK_DETACH. Pin/unpin manipulate persistent references, not our app's approval.
Thus explicit owned-FD detach, verification of inactive ifindex, and FD close are separate steps.
A process exiting without an audit completion is never reported as verified cleanup. Interface
removal invalidates target identity and requires review rather than attaching to a reused index.

## Existing program compatibility: structural yes, semantics blocked

The unchanged object SHA is
`69de609ea8ee90ecf90d091ec361e46e61ed0638b3175390c77305145e19d5f4`.
SCHED_CLS, __sk_buff, tc/ingress and tc/egress, bounded maps/ring ABI and header-only metadata
are structurally relevant to TCX. A future loader must set/validate the TCX expected attach
type before load, rather than reusing a Legacy load/approval implicitly. Existing section
names do not themselves prove TCX load compatibility. No program/map/return-value change is
made in this task and no Verifier success is claimed.

Critical behavior: TC_ACT_OK is 0, which is TCX_PASS; TCX_NEXT is -1. The official
[kernel execution path](https://github.com/torvalds/linux/blob/v6.18/net/core/dev.c) stops
subsequent TCX execution on a non-NEXT verdict and bypasses Legacy TC evaluation for PASS.
An unchanged observer returning OK could therefore bypass another security filter. It must
not be admitted merely because the program does not issue DROP/REDIRECT/MODIFY. This task
preserves the requested TC_ACT_OK behavior by **not migrating it into Native TCX**. A separately
reviewed program/scope decision (for example a distinct NEXT observer) and new SHA/approval
would be needed; this is not silently implemented. Existing Network14/DNS contracts, 30s idle/
120s active, float32, Golden parity and research gates are unchanged.

## Ownership and lifecycle implementation

New tcx.h/tcx.c implements a bounded transaction core plus a separately closed real provider.
It reuses the existing soc_state/session, program FD produced by the loader, object SHA/seals,
namespace/controller checks and approval framework. The real provider is compiled into the
existing Broker/loader, not a new root service. It implements low-level libbpf link_create,
get_info_by_fd and link_detach on the **retained private FD**; attach flags are zero, no relative
ordering, replacement, update or pin API is exposed. Expected attach type, ifindex, generation,
program ID/tag/SHA, app identity, namespace and Broker PID/start ticks are validated.

Ownership includes generation, app/session, program SHA/ID/tag, Link ID, attach type/interface,
namespace and Broker identity. FD is a private in-memory resource, never GUI/IPC/Audit data.
The source's pinned field is our no-pinning policy, not proof of global pin absence. External
pin/reference count cannot be established from the queried link-info fields and stays UNKNOWN.

Lifecycle: NOT_ATTACHED → ATTACH_PENDING → LINK_ACTIVE → DETACH_PENDING → DETACHED. Failed
identity/mutation/audit/close goes CLEANUP_UNVERIFIED; retained external reference after crash
is modelled ORPHANED. Errors propagate via negative return codes and the existing Supervisor's
ERROR state. Partial creation retains any owned FD and does not retry. Close is attempted once;
a possibly consumed FD is never reused for a second close. Repeated attach on a state is denied.
Explicit detach is verified inactive before close; missing completion evidence is not fabricated.

Two independent gates remain: global B2A admission and an immutable TCX program-semantics gate.
Even opening only the global gate in another release cannot activate this provider. Native
TCX intent recording also returns unsupported: existing fixed Native journal/approval ABI has
no admitted Link ownership record. A Native dispatcher/ownership-journal migration needs its
own review. Compiled provider paths are therefore not an operational Native Broker integration.

## Broker, authentication and audit integration

The **fixture** integration reuses Preparation, the authenticated B-1 ordinary-UID supervisor,
PID/peer/sequence-validated STATUS, fixed command allowlist and existing append-only RuntimeStore.
Explicit TCX_FIXTURE approval is distinct from the Legacy plan digest; it is consumed on error
and cannot be replayed. The C fake resource table executes as a bounded unprivileged child,
not as a Collector and not with real Link FDs. Start/Stop/Restart authorization still belongs
to the one authenticated application session. No OS password, auth token or privileged FD is
stored/passed to GUI. No automatic retry or collector restart is added.

TCX_LINK_LIFECYCLE_FIXTURE Audit contains actual application context, Native-plan digest,
program SHA, separate fixture approval, bounded trace/result and native_execution=false.
Synthetic owner values in the C table are explicitly fixture values, not kernel evidence.
Success is published only after append succeeds; failure consumes approval without promoting
state. Recovery uses the unchanged app/Audit hash chain, restores no authentication, performs
no link reopen-by-ID, no automatic attach/detach and no inference replay. Initial integration
failures from duplicated Audit context fields were fixed by reusing the common event envelope;
logs are retained, and a separate audit-failure test prevents false success.

## Pinning, duplication, crash and interference

No pin/unpin/update/get-by-ID operations are exposed. Owned pin attempts are rejected before
create; no pin path exists. The fake table distinguishes close of a last reference from close
with a duplicated or externally pinned reference. Explicit owned-link detach stops attachment
even when an object reference persists. Foreign link/filter replacement after the last info
check does not change our held object; it is preserved by cleanup. Modification of our link's
program or a Link ID/namespace/session/generation mismatch fails identity checks and is not
relabelled as normal completion.

GUI/controller loss, SIGINT/SIGTERM, timeout and SIGKILL contracts reuse the supervised fixture
regressions. A real Broker dying with its last unpinned reference is expected to release the
link per kernel source, but actual WSL behavior, external references and exit evidence remain
Native PENDING. A mock crash with no other references is not Kernel cleanup attestation.
No source code here discovers/deletes another process's link or existing TC configuration.

## GUI and future Native requirements

Four production screens/cards/graphs/timelines remain. System adds attach mode, Link ID/state,
ownership, no-pin policy and UNKNOWN external pins. Before any observation Link ID is None,
not 0; fixture state is TCX_FIXTURE/FIXTURE_ONLY. Native link IDs or Live traffic are not made up.
The release gate stays BLOCKED regardless of fixture success. Actual Zeek collection is unchanged.

Before any Native TCX run: review return semantics and approved coexistence; load/expected-attach
contract; Link ownership approval/journal/dispatcher ABI; root installation/system dependencies;
fresh startup PAM boundary and minimum capability transfer; actual kernel compatibility and
exit/reference cleanup. Candidate capability set remains CAP_BPF/CAP_NET_ADMIN, with no new
CAP_PERFMON/SYS_ADMIN/NET_RAW grant. Native permissions remain unverified. A fresh app/session
must bind all binary/object/Bundle SHA, lo-only approved ingress or egress, namespace, generation,
300s/4096 events/queue 32/256MiB/20 CPU-seconds and no pin/export/update. Scope or artifact changes
require new approval. This release provides no Native TCX execution command.

## Tests and retained failures

Final source-bound independent Export: **125 passed in 74.81s**. Covers compiled/symbol API
probe, link object/FD identity, replay, program/hash/tag scope, foreign replacement, duplicates,
no-pin rejection, simulated external pin, last-reference crash, interface loss, partial attach/
detach/close/audit, closed Native gate, app approval/authentication, GUI and recovery.
No actual Kernel load/link/verifier or Native cleanup was executed.

Initial new integration run: 1 failed/119 passed (Audit plan_digest duplicated). Focused run:
1 failed/28 passed (application_session duplicated). Both fields belonged to the existing
common Audit envelope; remove duplicate context, retain separate Native-plan digest and publish
fixture success only after append. A new audit-failure test rejects success/retry. Focused
fix tests: 2 passed; final complete 125 passed. Old logs are retained rather than overwritten.

Separate regressions: B-1 63 passed. Initial existing units: **4 failed, 689 passed** while
Memory PSI increased; two inventory tests and two worker-failure mocks were preempted by
unchanged headroom guards. Only those 4 were rechecked after PSI declined: 4 passed. This
resource-sensitive test isolation was not fixed, and the initial run is not claimed green.
Remaining fresh integration 58 passed, GUI 17 passed, Audit 125 passed, actual offline Zeek/
RF/LR/SOC 1 passed (two receipts). No double-counted aggregate is presented. All 509 package
sources outside ebpf_tc match between the first regression Export and final Export. Final
125 covers the final changed source/typed owner evidence.

RF/LR ran serially only after three headroom/PSI checks (2GiB minimum, avg10 below 0.1,
avg60 below 0.2). Final source/inference queues zero, original/recovered audit digest equal,
no restored new inference. Receipts are ZEEK_OFFLINE_PCAP/RESEARCH_ONLY/WRITE_DENIED, not TCX
or Native AI success. SIGILL root cause remains UNKNOWN; no new SIGILL was observed.

## Performance

Same fixture/toolchain, five serial samples per group (before baseline HEAD / after Export):
preparation including reference builds 3.469s→4.094s; artifact/scope validation 4.877ms→5.874ms;
Mock authentication plus B-1 supervisor start 1.112s→1.135s; STATUS IPC 1.950ms→1.980ms;
fixture cleanup 313.1ms→299.4ms; fixture supervisor RSS 144.18MiB→144.37MiB. Extra compiled
TCX source increases preparation/build cost. These are not Native Broker or PAM measurements.

The exact C fake resource table (100 warmups, five samples) measured medians: attach
preparation 47ns, info/identity comparison 32ns, detach 59ns. These tiny in-memory operations
are timer-dominated and include no syscall/Kernel work. They must not be used to estimate
Native throughput/latency. Profile process-image peak (including exec ancestry) is 40,588KiB;
it is not Native Broker RSS. Native attach/identity/detach/RSS remain UNKNOWN.

Three fresh WSLg idle runs per group, no capture/inference: startup median 2.4380s→2.2965s;
RSS 175.43MiB→175.20MiB; idle CPU 0.256%→0.253% of one core; response p95 (median per run)
0.0570ms→0.0353ms. Two threads, zero idle children/background tasks/controller SQL and no model
service remain. Small samples/environment variation do not establish a speedup. Per-sample
resource/PSI data and all raw GUI values are retained in companion evidence.

## Identities and release verdict

Compiled identities below are not installed privileged artifacts or Native approval.

| Component | SHA256 |
| --- | --- |
| Bootstrap | `f2bc7b066e136c54a34d2c11c14c204bc6689859ff746626247b97cd10c6569a` |
| Broker | `2af83d320d88d50359eb8927bc78ca122dc167a244e78c1f08808b00daffd1ed` |
| Loader | `e686ac2df4de4420c31b326d0670e83f66e894a24198b3c0ab2cf04fc544ba4d` |
| Fixture driver | `0bf805518e44a261899e460168029518634172eb1b2b29c958fd14d18c1b798a` |
| BPF object (unchanged) | `69de609ea8ee90ecf90d091ec361e46e61ed0638b3175390c77305145e19d5f4` |
| Bundle | `69c20ebf593ff7f6782bae484e8cc0ad1140975d7f1450f4e4189c3e814ab472` |

[Machine evidence](ebpf-tcx-link-ownership-evidence.json) binds the source manifest, compiled
identities, failed/passed runs and scopes. Existing SHA/approval cannot admit this changed
Broker/Bundle. TCX API compatibility is VERIFIED for installed headers/linker, UNKNOWN for
running kernel. TCX_LINK_OWNERSHIP_FIXTURE_VERIFIED and LINK_CLEANUP_FIXTURE_VERIFIED apply
to the fake table only. Broker integration is fixture-verified, **Native dispatcher/journal
integration BLOCKED**. LEGACY_TC_NATIVE_BLOCKED, TCX_NATIVE_ATTACH_PENDING, GUI_PRESERVED,
AUDIT_RECOVERY_VERIFIED (fixture), NATIVE_AUTH_PENDING, NATIVE_VERIFIER_PENDING,
NATIVE_AI_BLOCKED, DNS9_BLOCKED and OPERATIONAL_PROMOTION_BLOCKED remain in effect.

## Final independent Export quality

Ruff check src/tests PASS; Format PASS (1,221 clean-Export files); Diff PASS; offline Wheel
build PASS. All 532 packaged Python/C/header/JSON/Zeek/conf files match Export bytes. Rebuilt
Bootstrap/Broker/Loader/fixture artifacts and bundle match measured identities. Only final
report/evidence metadata changed after quality; implementation/tests still match the final
125-test Export. Final workspace/Export/index/commit SHA are compared before selective commit.
132 pre-existing user files and 392 protected files (including four historical B-2A/Preflight
reports) retain SHA; 58 raw files retain size/mtime/inode. No model, Native DB/session/archive,
Replay or compiled artifact is committed. Existing user changes and original empty Stage are
preserved. Native release remains BLOCKED independent of software test/build success.

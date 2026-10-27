# Root-only Namespace accounting and launcher review

The Root-only reservation API is `RootOperations.check_root`, `reserve_root`, and
`record_root` in `security_ai/ebpf_tc/root_operations.py`. It never invokes sudo,
setns, a package installer, a worker, or a network client. Policy and exact action
receipts are independent, externally pinned inputs. No receipt is activated by
this development change. Existing Native and integrated execution keep the
existing NativeCampaign / reassessment / R2 / Supervisor validators.

| Operation | Native charge | Root charge | Admission |
|---|---:|---:|---|
| ROOT_SETUP | 0 | 1 | New exact policy + fixed setup Scope |
| ROOT_INSTALL | 0 | 1 | New exact policy + package and retained-installation checks |
| NATIVE_DIAGNOSTIC | 1 | 0 | Existing Native admission, with installation identity unchanged |
| ROOT_AND_NATIVE | 1 | 1 | Existing integrated admission |

The existing locked hash-chain writer validates and appends each event. The
shared accounting guard counts legacy reservations plus Root-only reservations
at campaign and batch level. It also runs in the nonconsuming reassessment check;
no old execution path may ignore a new Root charge. Historical records, charges,
controller pin and budget anchor remain unchanged. Cancellation, failure and
UNKNOWN retain charges. They never reactivate an approval. A Root-only request
cannot call the Native admission API by changing an operation label.

Root states are RESERVED_NOT_STARTED, START_INTENT, STARTED, then SUCCEEDED,
FAILED or UNKNOWN. CANCELLED_BEFORE_EXECUTION is allowed only from
RESERVED_NOT_STARTED. START_INTENT is a write-ahead observation, not proof of a
privileged start; interruption at that boundary remains ambiguous. Repeated
approval pins, repeated Session/operation reservations and repeated terminal
settlements are rejected. An unfinished, failed or UNKNOWN Root reservation
blocks subsequent reservations. Releasing that safety block is not implemented
as an automatic refund or positive safety decision.

The new request uses the existing ApplicationPlan constructor's session factory
and its ordinary-user controller identity. The serialized plan is retained as
provenance. The version and Root Manifest come from the compile-only package,
not an invented new release number. Source, exact candidate Artifact hashes,
installed and rollback pins, Scope, batch, policy implementation, budget,
baseline and latest Ledger tip are bound independently. Actual Namespace inode
is unknown until separately approved setup. A synthetic disabled preview is
build evidence only and cannot authorize actual Native execution.

## Proposed Root launcher boundary

`launcher_scope()` provides structured review data, not an arbitrary-command
executor. Root authentication and the following lifecycle remain separately
approved work; this document does not authorize them.

| Step | Execution user / capability | Changed resource |
|---|---|---|
| `/usr/sbin/ip netns add soc-native-b3` | Root; CAP_SYS_ADMIN for network namespace creation and named mount | New `/run/netns/soc-native-b3` mount; required `/run/netns` infrastructure if absent |
| `/usr/sbin/ip -n soc-native-b3 link set dev lo up` | Root; CAP_SYS_ADMIN to enter, CAP_NET_ADMIN to configure | New Namespace lo flags only |
| Enter using held FD in newly created child | Root; CAP_SYS_ADMIN in relevant user namespaces | Child network namespace only |
| Bind UDP/TCP `127.0.0.53:53` | Root prebind; CAP_NET_BIND_SERVICE if port is privileged there | Two dedicated listener FDs |
| Drop supplementary groups, GID, UID, permitted/effective/inheritable/ambient/bounding capabilities; set no_new_privs | Root child; CAP_SETGID, CAP_SETUID, CAP_SETPCAP where required | Child credentials only |
| Serve / stop | Original ordinary UID, zero capabilities | Only verified dedicated listener and accepted-stream FDs |

The low-port threshold is per network namespace; its actual value must be read
inside the new Namespace. Do not infer privilege requirements from the host or
modify a sysctl to make binding succeed. The proposed upper privilege envelope
allows prebinding before an ordinary UID runs the existing worker. See the
[Linux kernel IP sysctl documentation](https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html),
[setns contract](https://man7.org/linux/man-pages/man2/setns.2.html) and
[capability definitions](https://man7.org/linux/man-pages/man7/capabilities.7.html).

The launcher must reject an existing name, bind a held namespace FD to boot ID,
creation Session/receipt and post-creation inode, and verify both listener cookies
against a fresh socket there. It must never accept arbitrary argv or move an
existing user process. No veth, default route, NAT, forwarding, host resolver
change, service stop or host socket handoff is permitted.

Worker upper bounds remain 60 seconds for the transport lifecycle, 256 MiB and
20 CPU seconds. DNS Sidecar analysis remains independently limited to 10 seconds.
UDP2/TCP1 ordering and the 35-second application witness are diagnostic only;
they do not establish Kernel Capture Integrity, Flow Completeness or ELIGIBLE.
Native 300s/4096/Queue32/50ms/10ms/16KiB bounds stay unchanged.

Cleanup closes owned FDs and waits for the worker identified by PID/start ticks.
A child crash or authentication interruption must preserve evidence and report
UNKNOWN when the actual start cannot be proved. Parent-death handling and exact
resource limits belong in the reviewed launcher, not in an unbounded shell.
Namespace deletion by name remains forbidden. Retain the Namespace for identity
binding; deletion requires a separate held-identity/ownership-bound Scope and
proof of no owned live processes/TCX resources. No Root launcher or actual
cleanup command was introduced by this accounting implementation.

Without the separately approved B allocation, one setup changes campaign Root
from4/10 to5/10 and Batch3 Root1/2 to2/2, with no installation allowance left.

The versioned B allocation is recorded by `native-recovery reassess` using an
exact `--root-governance-file` and SHA. Separate policy and budget receipts are
verified independently, using the existing locked campaign writer. The original
budget/anchor remains root_per_batch_max2. A single valid
ROOT_BATCH_ALLOCATION_RECORDED_V1 event raises only Batch3's effective total Root
cap to3, within Campaign Root10; Native cap2 remains unchanged. Setup sub-allowance1
and installation sub-allowance2 prevent repurposing the extra slot. All reservation
paths and nonconsuming checks use the same effective-limit guard.

Duplicate/replayed grants, wrong Binding or stale Ledger are rejected. An expired
grant permits no new admission under cap3 and never refunds a charge. No automated
renewal or overwrite exists. The two approval records do not consume execution
budget or approve any Root command. On the current charged baseline, applying B
alone gives Batch3 Root1/3; a subsequent approved setup would produce2/3 and retain
one installation slot. Campaign stays4/10 until actual reservation.

A policy activation record applies only to the exact reviewed Binding. Recording
approval of an original source version does not transfer that approval to changed
source, Artifact hashes, or a new Root action. Rebuilt candidates need their own
exact policy/action pins. No live DNS lifecycle or Namespace is created by this
administrative CLI path.

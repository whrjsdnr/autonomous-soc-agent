# Continuous producer / authentication / recovery operations

This extension adds operational code without installing or activating privileges.
DIAGNOSTIC and its 4,096-event / 300-second contracts remain unchanged.

## Producer and authority boundaries

`continuous/native/continuous.bpf.c` reuses the existing packet parser and 80-byte
TCX ABI. It is a separate passive ingress program returning TCX_NEXT, with a 256KiB
ring, per-CPU cumulative counters, 4,096 admissions per CPU per minute and a renewable
five-second observation lease. A stalled/dead service cannot renew indefinitely.
These are proposed Continuous limits, not permission to bypass Diagnostic limits.

`provider.c` uses libbpf, requires Root, checks namespace/lo, admits only an empty
TCX ingress hook by expected revision, verifies the held link/program on each poll,
and disables observation/detaches/releases only owned resources on Stop. It never
replaces another program or invokes shell commands.

The standalone stdlib-only `service.py` requires its exact installed path, Python -I,
Root-owned nonwritable installed files, fresh installation contract, executable and
system Python/libbpf/libelf/libz/libc SHA pins, target namespace, no external interface
or route, exact capabilities and the service cgroup limits. It refuses checkout
execution before loading BPF. Root-side audit is bounded and hash chained; restart
validates it incrementally rather than loading the whole audit into memory.

The uninstalled service unit proposes:

- Target network namespace: `/run/netns/soc-native-b3`; actual inode checked in service.
- Capabilities: CAP_BPF / CAP_NET_ADMIN / CAP_CHOWN (only socket ownership setup).
- NoNewPrivileges, restricted filesystem/address families, 128MiB memory, 25% CPU,
  TasksMax4, no automatic Root restart, ten-second Stop timeout.
- No namespace creation/entry in the program, no generated DNS traffic, no package changes.

The system manager would enter the approved namespace at future activation. This task
neither installs the unit nor invokes it. `NetworkNamespacePath` itself requires a
separately approved privileged installation/start operation.

The read-only installation contract is `/etc/soc-agent/continuous-installation.json`.
It is an **administrator's approved-update attestation**, not a receipt issued by the
agent. No CLI here issues it. Existing §33 review/install authorization must precede
its installation. Root ownership is part of the trust boundary; a user JSON/old
Diagnostic receipt cannot activate this mode. The contract specifies:

- contract `soc-continuous-installation:v1`, purpose `CONTINUOUS_COLLECTOR_SERVICE`;
- namespace, lo, UID, expiry (maximum proposed 24 hours), PASSIVE_INGRESS_ONLY;
- exact human/risk review references, installed file SHA map and runtime SHA map;
- `native_model_inference=false`.

No synthetic approval references are supplied in this guide. Source/build output
provides the actual hashes for future review. Policy and execution remain unapproved.

```bash
# Compile only, ordinary user; destination must be new.
python -m soc_agent.continuous.native.build /absolute/new/build-directory
```

Outputs: BPF object, provider library, two standalone Python files, proposed service
unit, runtime identity. No setcap/setuid, loader invocation or system installation.

`TCXProducer` verifies installed policy and Root SO_PEERCRED, namespace, program,
generation, bounded frames, clock sample and cumulative counters. It has no Root
launch/authentication function. Worker or GUI loss does not terminate the independent
Root collector. An explicit ordinary `continuous stop` in Native mode sends only the
owner-bound STOP_CAPTURE command and requires the matching cleanup acknowledgement;
connection loss alone does not invent verified remote cleanup. The protocol cannot
execute arbitrary commands or start/replace privileged binaries.

## Native feature status

`NativeWindows` reuses the existing incremental Network14 Window and event ordering
arithmetic directly on Kernel monotonic ns, with bounded per-flow references and
30s/120s event-time completion. It never relabels monotonic ns as UTC. Candidates go
through the incident/audit workflow as UNKNOWN/INCOMPLETE, without a model call.

**The Continuous capture attestation/model-action admission bridge is still not
implemented.** Root streaming counters alone are not Phase D P02/P03 proof. The
policy currently rejects Native model inference. Activation plus a Live producer
check therefore does not by itself complete Native AI E2E; capture-window proof
and separately governed model-action integration remain required. Do not weaken
that gate or reuse Diagnostic R1/R2/model receipts to enable it.

## Authentication and DNS

The primary stream accepts saved normalized authentication/journal records and
explicit source watermarks. Existing project_journal, AuthenticationWindowExtractor,
package compatibility validation and IsolationForest are reused. Account/address
fields from journal parsing are pseudonymous. EOF/Stop produces an INCOMPLETE window;
only a later source event/watermark witnessing a closed five-minute window permits
inference. Unknown status, ordering regression or incompatible package blocks it.

A concurrent saved Journal producer can be configured alongside packet/DNS input:

```json
{
  "journal_replay_file": "/absolute/saved-journal.jsonl",
  "journal_replay_sha256": "<actual file hash>",
  "authentication_packages": [
    {"directory": "/absolute/verified/authentication-package", "manifest_sha256": "<actual hash>"}
  ]
}
```

Use these fields in a fresh normal Continuous config. The files are bounded and SHA
pinned. No journalctl command or Host collector is constructed by this configuration.
`JournalTransport` also implements the existing collector poll/cursor interface for
an explicitly authorized service composition. This development task used saved/mock
readers only. Supplying a real Host collector requires its collection permission;
there is no GUI option that silently upgrades saved replay into Host collection.

Packet EOF does not stop the concurrent journal task. Its own durable EventQueue
commits cursor after retention; normalized auxiliary input is committed before ACK.
DNS uses existing raw/stored transaction jobs, provenance and audit. DNS9 remains
INCOMPLETE; the TCX metadata ABI does not contain DNS payload. A real DNS sidecar
transport/operating scope remains a separate Live integration requirement.

## Durable recovery and retention

New service directories include version-2 streaming storage tables. Old directories
remain readable; starting the new engine on a missing schema fails explicitly rather
than modifying old evidence. Use a fresh directory or a verified version-2 backup.

Raw replay input and cursor are committed in one transaction before projection.
On restart, retained inputs rebuild open windows with stable identity. Replayed source
records deduplicate. Same completed jobs reuse queue admission, including existing
DONE/POISON decisions; partial/unknown inference is not automatically retried.
A crashed AI claim becomes POISON; resetting the worker resumes future pending work.

Native raw records compact into atomic compressed segments after verified file
publication and index/audit commit. Active copies are removed only after that commit;
per-CPU generation/sequence cursors remain. Segment corruption fails verification.
Storage quotas fail closed. Historical audit and campaign ledgers are never deleted.
Automatic age-based destructive expiration is **not activated**. Long-term off-host
archival/expiry policy and sustained throughput still need deployment validation.

```bash
python -m soc_agent.cli continuous archive /absolute/stopped-runtime
python -m soc_agent.cli continuous restore /absolute/new-runtime --from-archive /absolute/archive
```

Archive requires STOPPED, verified cleanup and no pending/claimed AI jobs. It uses
SQLite backup for the main, inference and journal cursor databases; includes inputs,
analysis, segments and code pin; rejects symlinks and preserves incomplete unpublished
stages. Restore verifies all hashes, preserves code pin/cursor/tombstones, requires a
new directory and never starts a process. Native restoration is blocked pending a
separate review. Original evidence is retained; archival is not silent data deletion.

## GUI and validation labels

Continuous screen shows domain, classification, eligibility and audit per incident.
Inspect Selected Incident verifies the stored result before opening the existing
Analysis detail view with investigation plan, tool results, evaluation and response.
GUI close detaches from the independent service. Replay, Scripted planning and live
Root data are labelled separately. See the integration report for actual verification
and remaining Native release blockers.

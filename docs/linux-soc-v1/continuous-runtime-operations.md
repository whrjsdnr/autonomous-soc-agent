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

## Sealed Native windows and model admission

The inactive Root service now rotates fresh owned maps after 180 seconds or 4,000
callbacks. Every capture window retains the actual PRE_ATTACH snapshot, three
pre-capture clock brackets, detach → final ring consume → POST_DETACH counters,
three final clock brackets, callback/drop totals and a canonical seal SHA. More than
4,096 delivered events or 128 possible CPUs is rejected. The per-minute BPF quota
remains independent. Only its period/admission state is carried into fresh maps;
rotation cannot reset the admission allowance within the same minute. No Phase D limits or validators were modified.

A new window starts only after the prior seal was delivered. There are explicit
unobserved gaps between detach and the next attach, and flows are **never joined
across them**. This is bounded owned-hook metadata assurance, not lossless Host
coverage. Clock drift, unsupported traffic, disabled attempts, drops or incomplete
per-CPU delivery prevent eligibility. TCP FIN/RST and wall-clock waiting cannot
replace the existing observed-event 30s/120s timeout witness.

`continuous.capture` recomputes features from retained events, then calls the unchanged
Phase D `assess_capture` and Network14 input validators. Long process lifetime is not
one capture window. Seal/session/epoch/namespace/program/policy/install-release digest
are bound independently. The release identity is the canonical digest of the installed
file SHA map, not a fabricated Root Release manifest or a Diagnostic receipt.

The retained transcript is durable before analysis handoff. Restart rebuilds the same
window and queue identity; missing prefixes remain incomplete through counter
reconciliation. A new epoch abandons partial old evidence without promoting it.
Duplicate sealed epochs and altered seals fail closed. Retained records remain
DECLARED_UNATTESTED outside their authenticated Root transport; recomputation alone
does not authenticate a user-authored Native transcript.

`native_model_inference=false` continues to prohibit the Root collector from running
models. The ordinary analysis worker uses the **existing exact retained TCX action
approval**, not collector authority. Eligible Native jobs wait for that approval without
starting a model subprocess. Incomplete jobs never call a model. The operator can
prepare the existing `analysis_action(job, output_directory)` approval for the immutable
job in `inputs/`; the wait audit records the exact action. No approval issuer or new
approval framework was added.

Optional configuration `native_model_approvals` is an absolute directory of existing
approved action JSON files named `<job-digest>.json`. The output binding is
`<runtime>/analysis/run-<job-digest>`. The existing CLI verifies approval SHA, action,
implementation, expiry and scope before RF/LR execution. An invalid approval fails;
it does not automatically retry or grant scope to later windows. Repeated unattended
model authorization beyond that existing contract is not activated by this change.

Source/installation hashes changed: old installation or model action approvals must
not be reused. **No service installation, policy activation, Kernel operation or Live
verification has occurred.** Next Live validation requires a fresh human-approved
service installation/namespace scope and the independent model-action permission.
DNS traffic requires its separate exact R2 scope; this passive service generates none.

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

# Native Loader failure RCA — Release 0.5.0

Baseline: `85ce055f4cf64ace6de6db7b1c1c2d90f7274d84`. Historical session:
`9f004895-eff5-41b2-93a7-a80d2752ab04`, recorded under
`.git/tcx-c2-execution/unified-app/application-83febd1ea83040bb90c5c001dfcb6ee0/session`.
Original session files, Audit and earlier reports were read-only. No authentication,
installation, capability change, BPF load, TCX attach/detach or traffic was run.

## Historical facts and limits

The six-record Native Journal chain verifies, ending with LOAD_REQUESTED then
CLEANUP_UNVERIFIED, without LOAD_VERIFIED or a TCX Link record. Broker PID 725214
exited (entry status 2); application status was 1. The accepted data-channel Counter
frame reports retrieval UNVERIFIED and delivered 0, followed by CLOSED. This is not
successful counter collection or packet evidence. The original return value,
errno, verifier text and FD inventory were not saved.

A useful code/evidence inference is possible: that Counter frame has only one
Native emitter, `soc_final_drain_counters()`. It requires the loader runtime
context; the original Broker starts with NULL context and only `load()` allocates
it. Thus the original LOAD_PREPARE checks/read/allocation completed and OBJECT_OPEN
was reached. This is a bounded inference from the accepted historical frame and
exact installed source, not a new syscall trace. It does not prove an ELF object,
BPF Map, Program or Ring Buffer was successfully created.

The first failure remains somewhere after runtime allocation and before successful
LOAD_VERIFIED publication. Even a LOAD_VERIFIED journal/notification failure after
a successful load cannot be excluded. A persisted LOAD_REQUESTED row alone would
not establish loader entry: its notification send can fail before `load()` runs.
The separate Counter evidence is what narrows the former boundary here.

| Stage | Release 0.5.0 evidence |
|---|---|
| LOAD_PREPARE | Completion inferred from the allocated runtime/Counter path |
| OBJECT_OPEN | Reached; original API result/errno unknown |
| OBJECT_VERIFY | Original completion unknown |
| BPF_OBJECT_LOAD | API invocation, bpf subcommand, result, errno and log unknown |
| MAP_INIT | Original Map/Program FD creation and validation unknown |
| RING_BUFFER_INIT | Original readiness unknown; UNVERIFIED counter cannot distinguish missing ring from failed lookup |
| TCX_ATTACH | Not reached under the ordered LOAD_VERIFIED-before-attach contract |

Read-only inspection of the unchanged installed Object reproduces libbpf v1.3,
SCHED_CLS sections and expected TCX ingress/egress types 46/47. Map schema matches:
events/RINGBUF 262144, config/ARRAY key4/value32/max1, counters/PERCPU_ARRAY
key4/value56/max2. These checks do not retrospectively establish successful Native
load. There is no evidence to prescribe a library upgrade or extra capability.

## Where the original error disappears

1. `load()` combines several trust checks into `-EPERM`, converts many libbpf,
   schema, load and info failures to `-EINVAL`, and disables libbpf print output.
2. The Dispatcher short-circuits validate/LOAD_REQUESTED/load and returns synthetic
   `-EUCLEAN` (-117), also using that value for later failures.
3. Broker reply contains only that outer code. The Controller combines protocol
   mismatches and nonzero errors into HANDOFF_BROKER_REQUEST_DENIED, then records
   HANDOFF_COMMAND_FAILED. It does not retain the reply's number in 0.5.0.

Consequently neither EINVAL (22) nor EUCLEAN (117) can be described as the observed
Kernel errno. The actual errno and primary cause are UNKNOWN. The installed
libbpf API distinguishes negative results from pointer/errno errors; the original
wrappers erased that distinction. See the [libbpf 1.3 header](https://github.com/libbpf/libbpf/blob/v1.3.0/src/libbpf.h).

A bounded, unprivileged Kernel-journal query for the UTC interval obtained from the
application Audit (00:50:01–00:50:05 on 2026-10-21) yielded no available records.
This is not proof that a complete privileged Kernel log contains no error. No
original verifier log has been recovered.

## Why Cleanup was UNVERIFIED

Three independent mechanisms must not be conflated with residual resources:

- The Dispatcher sets `s.failed=1` on load failure. Original cleanup derives
  `cleanup_verified=!s.failed`, returning EUCLEAN even if object release succeeded.
- Cleanup queries/compares a Snapshot even when no pre-attach Snapshot was captured,
  and attempts final drain even when the ring is not ready. Snapshot/drain failure
  returns before `release()`; the original evidence cannot identify which branch
  ran. Comparing a zero-initialized `before` structure is not a valid baseline.
- Controller close requires both a positive cleanup Journal claim and process exit
  0. This session has neither. Application-preparation CLEANUP_VERIFIED events do
  not override the Native result.

No Link attach was reached. Map/Program creation and intermediate FDs remain
unknown, and PID absence does not itself prove the entire Kernel inventory clean.
Read-only, unprivileged bpftool map/prog/link enumeration returned EPERM for all
three. There was no privilege escalation for inspection. The Kernel normally
releases process-held map references at exit, subject to other references; that
lifetime rule is not an independent inventory measurement. See [Kernel map lifetime documentation](https://docs.kernel.org/bpf/maps.html).
No foreign Link was searched by ID for removal or removed.

## Minimal implemented remediation — not installed or run Native

- Add explicit LOAD_PREPARE, OBJECT_OPEN, OBJECT_VERIFY, BPF_OBJECT_LOAD, MAP_INIT,
  RING_BUFFER_INIT, TCX_ATTACH and CLEANUP checkpoints. Save the first failing API,
  raw result and immediately captured errno separately. Contract helpers that do
  not expose an errno decode to `null`, never a fabricated 0/Kernel errno.
- Preserve the Dispatcher load result and Controller Broker reply value. Also
  distinguish LOAD_REQUESTED/LOAD_VERIFIED journal publication failures.
- Append a bounded, checksummed 216-byte LOADER_DIAGNOSTIC Journal row. Main failure
  and cleanup failure have separate immutable first records. Record observed FD
  counts only when an inventory was actually sampled; otherwise use UNKNOWN.
  These rows never become packet/control IPC responses or privileged GUI FDs.
- Request a bounded 64KiB shared BTF/program Kernel log from the first libbpf API
  attempt. Persist only length, SHA and at-bound status, not raw Kernel text. No
  extra load invocation is made to retrieve a log. Log ENOSPC must remain a distinct
  diagnostic error; buffer growth/retry is not automatic. A shared log may contain
  BTF or program output and cannot by itself identify the internal bpf subcommand.
- Mark whether the pre-attach Snapshot was captured and drain only a ready ring.
  Once no owned Link remains, attempt release of the owned, unattached object even
  if Snapshot/drain evidence fails. Preserve the first cleanup error. Capture
  failure still leaves the overall result UNVERIFIED; a separate release fact is
  not a promotion to Native cleanup success.

No Native Gate/admission, capability set, TCX ownership, pinning, packet program,
Network14/model/GUI contract or original evidence was changed. Installed 0.5.0 is
unchanged; these source changes cannot be represented as its qualified Bundle.

## Focused verification and next conditions

Nine new ordinary-UID tests exercise seven injected C failure paths, diagnostic
schema rejection and Controller return-value preservation. C tests inject libbpf
and policy results, parse a real Object and never forward a Kernel load/info/ring
operation. All seven scenarios were traced: zero bpf and capset syscalls. Their
EACCES/ENOEXEC/etc values are **fixture values**, not the historical session errno.
Object SHA remains `928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a`.

Related Journal/Dispatcher tests yielded 23 PASS and one existing failure. The
failing test expects an independently permanently closed TCX gate after mocking
the process gate. The installed baseline already delegates TCX admission to the
process-local scoped gate: the same fixture exits 1 against the unchanged installed
0.5.0 library and baseline headers, with zero bpf/capset syscalls. No production
gate or assertion was weakened. A focused run excluding that proven pre-existing
case yielded 23 PASS. Changed-file Ruff/Format/Diff and C -Werror checks passed.
No broad regressions, GUI/model benchmarks, Wheel or new installation were run.

Historical root cause/errno remain UNKNOWN. Do not retry based on a guessed cause.
A later separately authorized diagnostic execution would first require a reviewed
new release/version, Manifest/Bundle/binary SHAs, trusted installation and exact
session/interface/hook/budget approval. It must not reuse the failed session or
rewrite its Audit. Such authorization has not been requested or executed here.
Native Release, Native AI, DNS9 and operational promotion remain BLOCKED.

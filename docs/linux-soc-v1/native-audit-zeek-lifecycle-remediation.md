# Native Audit backpressure and Zeek lifecycle remediation

Baseline: `ec968ec`. Installed Release remains **0.5.12**. This work starts no
Native session, BPF operation, capture, authentication, capability change or
Root installation. Campaign usage remains **4/5**, with one Native attempt left.
Private evidence is under
`.git/native-e2e-remediation-campaign-059/audit-zeek-remediation-0513/`.

## Observations and causality

Original attempt-4 evidence is preserved unchanged.

| Boundary | Actual 0.5.12 result | Meaning |
| --- | --- | --- |
| Kernel Ring reservation | 0 failures | Does not prove complete userspace delivery or final Ring drain |
| Broker data socket | 2 failed PACKET sends, EAGAIN(11) | Actual nonblocking socket failure; distinct from Ring loss |
| Validated Controller packets | 255 | Reception, not completed Network14 processing |
| Shared processing budget | 35 rejections; peak ingress 27/32 | Budget also covers in-flight and reorder records |
| Packet Adapter | 220 received, 192 accepted, 28 discarded | Includes 27 post-error discards and pending processing discard |
| Feature candidates | 4, all incomplete/ineligible | No AI invocation |
| Checkpoint transaction | maximum 782,689,031ns | Processing worker waited for synchronous persistence |
| Receive-call interval | maximum 5,229,047,710ns | Includes idle/startup; not a measured active scheduling stall |
| Final Ring poll | -11 | Propagated packet callback send failure, not proof of Kernel Ring loss |
| Counter / CLOSED | both received | Independent evidence survived failure; not proof of successful drain |
| Resource inspection | Maps/Links/lo filters 0 | Existing foreign programs preserved; separate from protocol cleanup |
| Zeek stream | 321 packet records; no CLOSED | Adapter snapshot had 191 metadata records; integrity incomplete |

The source and timing identify a **processing dependency**: checkpoint completion
blocked the same worker that drained packet-processing credits. Moving reception
alone could not remove this bottleneck. They do not establish that Audit was the
direct or sole cause of the first socket EAGAIN. That causal attribution remains
UNKNOWN. The first-to-failed socket-sample interval also includes synchronous
Broker diagnostic journal writes, not just the 50ms POLLOUT wait; those existing
durable journal semantics are not relaxed here.

The precise slow component inside the FULL SQLite transaction (validation,
locking, filesystem or commit) was not separately measured in the old run. No
unsupported claim about WSL disk or scheduler behavior is made.

## Packet processing and durable checkpoint boundaries

The fast receiver still performs credential/session/program/ABI/sequence checks,
then hands packets to the existing worker using the shared **32 packet credits**
across ingress, in-flight and event-time reordering. No second packet budget is
added. Full-budget rejection is explicit, stops feature processing and remains
separate from Kernel reservation failures, send failures and adapter discards.

One ordinary-user checkpoint writer now accepts **immutable serialized summary
snapshots**, not packet records. It has two waiting slots, one in-flight snapshot,
and a 16KiB limit per snapshot. Accepted snapshots are written in submission
order without coalescing. The same database transaction commits the checkpoint
and its append-only Audit hash-chain entry with `synchronous=FULL`. No schema,
sync setting, hash validation or recovery policy is weakened.

`request_checkpoint()` explicitly returns PENDING when scheduled. It is not a
durable receipt. The original `checkpoint()` API remains synchronous: it flushes
previous submissions and returns only after its own FULL commit. Initial
preparation remains synchronous before collection. The existing every-64-accepted
packet checkpoint cadence is retained. FULL queue, writer failure or uncertain
commit is visible and fail-closed. A later Audit failure cannot replace the first
packet error. A failed/uncertain write is not retried automatically.

Pending snapshots can be lost on process death; they are never reported as
committed. Recovery uses the last committed checkpoint and verifies its binding
to the Audit chain, without reauthentication, reattach or inference. Async
progress must not be mistaken for durable packet history. No guarantee of durable
per-packet storage is introduced.

End-of-stream and application close require bounded queue processing, Audit
Flush and writer shutdown. CLOSED with pending packets, a live worker or pending
Audit writes remains PENDING/FAILED rather than successful Drain. Handoff cleanup
cannot be promoted solely from a Broker journal when data-plane completion or
Audit finalization is unverified. CPU ordering, event timestamps, Clock calibration
and Feature Eligibility contracts remain intact.

Receive snapshots additionally measure pump lock wait and credential/schema
validation duration. Those timings and the existing receive interval/processing/
checkpoint timings remain separate; an inter-receive interval alone is not a
measurement of an active receive stall.

## Zeek termination and ownership

`RootOperations.stop()` previously formed one exception-sensitive sequence:
stop, inspect, close capture, remove. A stop-response or stream-close exception
skipped removal, even when the exact owned container had already exited.
`AutoRemove=False` is intentional: removal requires ownership verification.
The old run's first timed-out API is not known; the new lifecycle records its
stage, exception category, errno when present and duration.

Cleanup now independently records:

1. Exact container ownership.
2. One stop request if running, followed by stopped-state inspection even if its
   response failed.
3. Bounded attach-stream drain; forced closure/error remains UNVERIFIED.
4. Revalidation of the exact created container ID, pinned image and immutable
   plan/generation labels, plus stopped state.
5. Non-force removal with no volume deletion, then an explicit absence query.

Stream failure does not skip removal of a proven-stopped owned container. It
still causes overall cleanup failure. Unknown ownership or running state never
authorizes removal. Stop has a ten-second total budget, per-request timeouts
remain at most five seconds, and the existing SIGINT/2s container stop contract
is unchanged. No automatic Collector restart is introduced. Inspector final
resource queries and closure remain independent of Collector failure.

The ordinary-user `StreamProcess` had a second evidence-loss path: status RPC
exceptions from `poll()` in error/finally handling could abort `exit.json`
publication and mask the original error. Status/stop/absence failures are now
captured independently and cannot skip the terminal sidecar. Adapter callback
failure requests stop but continues bounded, validated stream/Counter/CLOSED
accounting without passing later records back to the failed adapter. Missing
CLOSED is never fabricated. Cleanup success and capture integrity stay separate.

The prior 0.5.12 exited container was independently inspected against its saved
plan, image, generation, exact ID and stopped PID0 state. Only that container was
removed, without force/volume deletion; a successful exact-ID query verified
absence. The stream and original Audit/Native evidence were preserved. This
authorized residual cleanup used no Native slot and does not retroactively change
the failed 0.5.12 drain/cleanup verdict. Other containers and retained policy/Audit
files were not deleted.

## DNS visibility

Zero completed DNS transactions in the incomplete old stream cannot distinguish
no DNS traffic, loopback visibility limits, lost terminal output or parser/adapter
failure. Query/response packet counts remain UNKNOWN. Existing Zeek DNS parsing,
matching and encrypted-DNS limitations are unchanged. Missing CLOSED prevents
DNS visibility qualification. TCX and Zeek clocks, loss counters and capture
identities remain separate. No test traffic or interface change is performed.

## Qualification and remaining work

Focused tests exercise a deliberately blocked Audit writer while real shared
Network14 processing continues, bounded snapshot rejection, write failure,
ordered FULL commits and Audit verification, first-error preservation, actual
ordinary-user C/socket/Packet Adapter golden paths, pending Queue plus CLOSED,
EAGAIN/EPIPE and -11 drain evidence, owned-container cleanup after stop/stream
failure, foreign-container protection, adapter failure with terminal drain, status
RPC failure with exit-sidecar publication, and existing DNS/stream fail-closed
contracts. Fixture publication uses the same atomic publisher as production.

An initial processing-error test assumed peer exit0; immediate revocation can
instead produce exit2 on control EOF/send failure. Its corrected assertions
require the original error, authenticated CLOSED, stopped workers, committed
Audit and CLEANUP_UNVERIFIED, regardless of that control-close race. No security
gate was relaxed to obtain a successful test verdict.

These are nonprivileged checks, not Native shutdown success. Source-only export,
selected Stage/Commit hashes, package file SHA/modes, preauthentication startup
verification, preserved-file hashes and final test logs are kept in the private
qualification directory. Broad GUI/model regressions and screenshots are not
repeated because those components are unchanged.

Final component checks (separate executions, not duplicate totals):

| Check | Result |
| --- | --- |
| Checkpoint writer, clock and first-error preservation | 11 passed |
| Supervisor ownership/lifecycle and Zeek stream finalization | 64 passed |
| Authenticated C/socket → adapter/Network14/Audit path | 10 passed |
| Existing DNS/AI fail-closed gates | 2 passed |
| Changed Python Ruff / format / selected diff | passed |

Unchanged C sender/Loader fault checks also passed in the initial focused run;
they are retained as component evidence, not represented as a new Native run.
Intermediate failing/superseded test reports are retained with the final logs.

Release **0.5.13** is a candidate only. Installation must retain the complete
installed 0.5.12 tree for rollback and recheck trusted dependencies. New Root
installation and the last Native attempt require explicit approval of the final
Manifest/Bundle/execution-image SHA. Scope remains net:[4026531833], lo/Ingress,
300s, 4,096 metadata events, shared Queue32, 256MiB and CPU20s per privileged task;
Zeek remains passive on the same lo using its unchanged resource profile.

Final candidate directory:
`.git/native-e2e-remediation-campaign-059/candidate-0513-release/`.
Earlier preparation images are superseded and are not approved for execution.

| Identity | SHA256 |
| --- | --- |
| Manifest | `612f2080485d5f2f0f857ec71afd8db8f8461ad873859b5a4a5658c70da9bc05` |
| Source Bundle | `8ce8d81b57552ff1c73dd1f75e96c93ebd00b38e7d544fe1d0d1aba3c0c9575d` |
| Supervisor execution image | `510993cd41584db359913eb25056de28723ba6be5c426da77c0dbedcade4076f` |
| Bootstrap | `df183f29c4b73d5cd401e37d51ac4a95a13a756411df7ce21e1f6c5361372ee2` |
| Broker | `62b2019d09f606e0c59d8b47ca216c23240b725294f1f929b9fed9ae442725ee` |
| Loader | `138b6a4f7a30db599635a523c7abfbd912758ebee5624f00a7d5fc221c8f09e3` |
| TCX object | `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06` |

Package verification and the real startup path reached the approval boundary with
authentication explicitly forbidden in the check. No sudo or Collector start
was invoked. The retained-release identity for the planned rollback is
`867457934b7e7415eeaa7d6a85c8d0ca670f4c38a831b476bc8adb821916d09e`.

Before that run, inspect current Hook ownership in the authenticated Inspector.
The run must separately prove packet processing, pending/committed Audit status,
Counter/CLOSED, queue/worker flush, Zeek terminal evidence and removal, and final
kernel resource state. Native AI, DNS9 and operational promotion remain BLOCKED.

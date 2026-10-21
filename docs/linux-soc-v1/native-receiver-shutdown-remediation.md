# Native receiver backpressure and shutdown remediation

## Baseline and evidence

Baseline: `5f8e068`, installed Release 0.5.11. Private original evidence remains
under `.git/native-e2e-remediation-campaign-059/attempt-3/`; it is not rewritten
or included in the source export. The campaign remains at 3/5 Native attempts
and installations. No privileged action is performed during this remediation.

The last Native session received 2,355 TCX packets, accepted 2,354 into
Network14, and produced five candidates with zero eligible features. Packet
2356 failed `send()` with EAGAIN(11) after its 50ms readiness wait; CLOSED
subsequently failed with EPIPE(32). The two-second cumulative wait allowance
was not exhausted. No Counter snapshot was received; Ring loss is UNKNOWN.
Final inspection observed no session Map/Link/lo filter, independently of the
failed drain protocol. Zeek observed no qualified DNS transactions and lacked
its terminal stream record; this does not establish DNS traffic absence.

## Root causes and limits

1. The old receive owner performed Packet Adapter, event-time reordering, flow
   reconstruction and SQLite checkpoints under the same lock used by GUI and
   control reads. These operations could prevent `recvmsg()` from servicing the
   socket. The historical session did not measure receive gaps or processing
   latency, so the particular operation responsible for the 50ms stall remains
   UNKNOWN. A slow receiver and a stopped receiver cannot be distinguished
   retrospectively from these records alone.
2. The old receiver treated any authenticated nonzero sender-loss counter as a
   transport failure and shut down the socket. This explains a code path from
   the observed `TCX_DATA_SOCKET_DELIVERY_LOSS` to the later EPIPE: losing one
   packet also prevented reception of Counter/CLOSED evidence.
3. `soc_final_drain_counters()` returned immediately on a negative
   `ring_buffer__poll()` result. Thus a failed packet send during final drain
   skipped the owned Counter Map lookup and its append-only journal record.

The changes remove these couplings. They do not prove Native throughput or
eliminate scheduler, disk or consumer stalls.

## Receive and processing ownership

The existing authenticated reader now validates credentials, PID start ticks,
source/session/program identity, envelope size, sequence and loss, then enqueues
packet metadata. One ordinary-user processing worker owns the adapter, flow
assembler and checkpoint writes. GUI/control reads receive cached projections
and do not execute packet processing under the receive lock.

A shared 32-credit budget covers ingress records, the in-flight record and the
existing event-time reorder deque together. It is not two independent queues
of 32. Full capacity produces an explicit `TCX_PROCESSING_QUEUE_OVERFLOW`,
counts rejected metadata and stops feature processing. Remaining authenticated
frames can still carry counters and terminal evidence. Subsequent validated
packets are counted as discarded after error, rather than inferred upon.
No packet payload, timestamp or CPU sequence is fabricated.

Sender-declared forward transport gaps are accepted only when the envelope
sequence gap exactly equals the increase in its cumulative send-failure
counter. They remain integrity failures for features. Replays, regressions,
unexplained gaps and credential/schema changes still fail closed. This does
not weaken per-CPU sequence or clock checks.

## Counters, terminal evidence and cleanup

Final drain retains its first error but independently attempts the owned Map
lookup, counter aggregation and journal snapshot. A separate bounded
`DATA_COUNTER_QUERY` record preserves drain result, CPU/map lookup results,
whether the map syscall was attempted, raw lookup return/errno, aggregation
overflow, socket-transmission result, generation and elapsed time. Unknown
totals remain null. Allocation, lookup and transmission failures do not erase
the original drain failure. The journal distinguishes fixture and Native
sources and uses the existing hash chain and 1,024-record bound.

Counter and terminal messages bypass the processing queue. A validated CLOSED
is recorded independently of processing completion. EOF without CLOSED stays
an error. Close uses bounded waits; a live worker, missing terminal message or
checkpoint failure remains UNVERIFIED. Audit I/O failures retain their own
errno/SQLite code without replacing the first processing failure. They do not
stop the authenticated reader or privileged cleanup path.

The local journal remains available when the data socket cannot transmit.
Existing link release, owned-object FD checks, Broker exit and Inspector final
inspection remain separate evidence. A journal entry or empty final inventory
does not turn a failed drain into a successful drain. Existing foreign links
are never removed, and no automatic reattach is introduced.

## Instrumentation

Receiver snapshots include maximum receive-call gap/duration, processing and
queue-wait duration, queue-full counts, queue peak/rejections, receiver-stop,
close-request and CLOSED-receipt times. Adapter summaries include calls,
cumulative and maximum duration for clock ordering, flow reconstruction and
checkpoint/audit work. Timings use userspace monotonic performance time, not
packet event time. Cached projections are periodic and can lag active work;
final snapshots follow the bounded worker join.

`DATA_SOCKET_SAMPLE` journals the owned socket's actual SIOCOUTQ and SO_SNDBUF,
query return/errno, data sequence and cumulative sender wait at first pressure,
failed sends and final close. Missing measurements stay null. Existing
50ms/message, 40 waits and two-second cumulative send limits remain unchanged;
there is no suffix retransmission for SOCK_SEQPACKET short sends.

## Qualification

Focused tests cover real ordinary-UID Unix socket EAGAIN recovery, blocked
socket, EPIPE, short send, final Counter/CLOSED and journal recovery; fault-
injected drain failure with successful/failed map lookup and FD release; real
C producer through the authenticated channel into Network14 golden fixtures;
clock/CPU ordering; bounded full queue with Counter/CLOSED reception after loss;
and audit write failure during processing cleanup.

These are unprivileged tests, not Native verifier, capture or cleanup proof.
An intermediate test run was invalidated by changing C sources after building
its session Fixture; source/reference identity checks correctly rejected it.
The subsequent frozen-source run passed all 39 selected tests in 111.02 seconds.
Changed-file Ruff, format and diff checks passed. GUI, model and
Zeek source are unchanged; broad regressions, screenshots and model benchmarks
are not repeated.

## Release and approval

The candidate identity, file manifest, source hashes, test report, installed
release check and export manifest are recorded in
`.git/native-e2e-remediation-campaign-059/receiver-shutdown-qualification/`.
Candidate packages are private and are not installed by preparation.

Final candidate: **0.5.12**, directory
`.git/native-e2e-remediation-campaign-059/candidate-0512-qualified/`.

| Component | SHA256 |
| --- | --- |
| Manifest | `867457934b7e7415eeaa7d6a85c8d0ca670f4c38a831b476bc8adb821916d09e` |
| Source bundle | `0db4a5dfb493c95c6a511e41be6862925bb71c7978ea1cb81dd00ce60b0d352d` |
| Supervisor execution image | `9c00523f404d09ebdee6b48a4627bcc88f281b62161485e2eaac8b49dfe20983` |
| Bootstrap | `df183f29c4b73d5cd401e37d51ac4a95a13a756411df7ce21e1f6c5361372ee2` |
| Broker | `62b2019d09f606e0c59d8b47ca216c23240b725294f1f929b9fed9ae442725ee` |
| Loader | `138b6a4f7a30db599635a523c7abfbd912758ebee5624f00a7d5fc221c8f09e3` |
| TCX object (unchanged) | `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06` |

Installation must retain the complete current 0.5.11 tree, using its exact
manifest digest as the rollback identity, and reject unknown/conflicting
installation state. No system setting, capability, Hook or installed file is
changed here. Prior unapproved preparation images are superseded; only the
final documented SHA may be approved for execution.

New Root installation and one Native execution require explicit approval of
the final Manifest/Bundle/execution-image SHA. Proposed scope remains
`net:[4026531833]`, `lo/Ingress`, 300 seconds, 4,096 metadata events, shared
Queue32, 256MiB and CPU20s per privileged task, passive Zeek on the same lo.
There is no generated traffic or automatic retry. Pre/post Inspector queries,
Hook ownership and rollback must be rechecked at execution time.

Native revalidation must establish packet/Network14 delivery, receive and
processing latency, socket pressure, independent Counter/journal evidence,
actual CLOSED, drain result, individual FD release, Broker/Zeek exit and final
kernel inventory. DNS remains independently qualified; its previous missing
CLOSED is an unresolved blocker. Native AI, DNS9 and operational promotion
remain BLOCKED. Live shutdown success is PENDING, not declared fixed by tests.

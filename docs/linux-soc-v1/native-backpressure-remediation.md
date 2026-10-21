# Native CPU sequence, drain and backpressure remediation

## Native evidence and limits

The campaign ledger is `.git/native-e2e-remediation-campaign-059/budget.json`.
Two of five Native/install slots have been consumed. The historical exhausted
ledger remains unchanged. No third Native execution is authorized by this report.
Native AI, DNS9 and operational promotion remain BLOCKED.

| Release | Actual result |
|---|---|
| 0.5.9 | Kernel load and TCX attach succeeded: Program5194/Link2. CPU sequence validation stopped feature processing after two records. Its original failing CPU/sequence values were not retained, so forward gap versus reuse remains UNKNOWN. |
| 0.5.10 | Program5203/Link3; 124 packet records, 120 Network14 accepted, four Feature candidates, zero eligible Native AI inputs. Four initial per-CPU forward attempt gaps were recorded. One 30ns inversion was reordered; zero late events observed in this short window. Broker send failed with EAGAIN11; no Counter/CLOSED received. |

The exact 0.5.10 failed message kind/sequence was not recorded in the old
diagnostic. PACKET/125 is an inference from the active producer path and last
delivered Sequence124, not retained raw syscall context. The new diagnostic
records those values directly. Do not rewrite the old evidence with this inference.

The 0.5.10 AFTER Inspector inventory had Map0, Link0, lo ingress/egress Filter0
and the original 11 foreign cgroup Programs. The TCX journal recorded owned Link
release and post-close F_GETFD/EBADF checks for three Map FDs and one Program FD.
Overall drain/cleanup remained UNVERIFIED because the data protocol did not
finish. Root Supervisor/Inspector cleanup was separately VERIFIED.

Zeek's final process receipt reported container absent and process cleanup true,
but no CLOSED record and failed stream integrity. The stream ended with packet
Sequence309, not a DNS or CLOSED record; the outer adapter snapshot had accepted
191 metadata records. These counters cover different stages. DNS Query/Response
were not observed and DNS visibility is unqualified. No traffic was generated.

Private source evidence remains in `attempt-1/`, `attempt-2/`, `candidate/` and
`candidate-0510-final/` under the campaign directory. Existing sessions, journals,
Audit databases and raw stream files have not been edited or recovered in place.

## CPU sequence contract

The unchanged TCX BPF program increments its per-CPU `observed` counter before
configuration admission and supported-packet parsing. The 80-byte event's
`cpu_sequence` therefore counts observation attempts, including attempts which
never produce a ring record. Requiring contiguous emitted CPU sequences was a
contract error. The global authenticated data-frame Sequence remains contiguous
and independently checked.

The adapter preserves original CPU sequence/timestamp, records forward gaps as
unrepresented attempts, and quarantines the whole affected observation window.
Forward gaps are not equated with Ring Buffer loss. All affected Feature
candidates are ineligible, including timeout-finalized flows. Duplicate/regressing
CPU sequence still stops feature processing and retains CPU/previous/actual values.
Evidence examples are bounded to eight; per-CPU state remains bounded to128.
The existing Legacy fixture contiguous-sequence contract is preserved.

After feature processing has stopped, authenticated metadata may be decoded and
counted as discarded for bounded terminal drain. It cannot resume feature
generation or inference. Source/ABI/session/transport validation remains enforced.

## Socket failure root cause and structural correction

`data.c` uses a separate SOCK_SEQPACKET channel with SO_SNDBUF32768 (the OS may
account/double that requested value). `MSG_DONTWAIT|MSG_NOSIGNAL` makes each send
nonblocking regardless of SO_SNDTIMEO. The libbpf callback can drain a burst faster
than the ordinary Python adapter can consume/reorder/compute/checkpoint it.
Previously the first full socket queue immediately incremented delivery loss and
failed the producer. Thus terminal Counter/CLOSED could fail through the same
congested channel. The Controller then observed EOF_WITHOUT_CLOSED. This is
userspace socket backpressure; Ring Buffer loss remained UNKNOWN, not zero.

The fix keeps the socket buffer and application Queue32 unchanged:

1. Retain the same complete 192-byte message and original Sequence on EAGAIN.
2. Wait for POLLOUT once, requesting at most50ms, then resume that same atomic
   send once if writable. No busy loop or additional packet buffer is introduced.
3. Limit the Broker session to40 readiness waits and2s cumulative elapsed wait;
   also clip active waits to the approved observation deadline. Measured scheduler
   delay is recorded; these are bounded requested waits, not hard real-time claims.
4. A further EAGAIN, failed wait, absent receiver or exhausted budget remains an
   explicit failure with original errno. Failed attempts increment loss; recovered
   transient pressure does not fabricate packet loss. No Native session is retried.
5. A short positive send on SOCK_SEQPACKET is an error. Never transmit a suffix as
   a second message. The partial-result test is fault injection, not an observed
   Linux partial seqpacket send.

The cumulative40-wait/2s ceiling includes teardown, so cleanup has no unbounded
retry path. It does not enlarge the approved AS256MiB/CPU20s worker budgets,
Interface/Hook scope or privileges. A permanently slow/unavailable consumer still
stops capture rather than silently deleting metadata or opening an AI gate.

## Independent terminal evidence

New bounded80-byte payloads in the existing append-only216-byte journal format
record DATA_SEND_STATUS and DATA_COUNTER_STATUS. They are not injected into the
control reply or packet channel, and do not change the 80-byte packet ABI.

DATA_SEND_STATUS distinguishes transient pressure, failed send/poll and final
close. It records message kind, attempted/final delivered Sequence, raw result,
actual errno, requested bytes, total send calls, packets sent, wait time, readiness
wait count and resumed-send count. Only the first pressure witness is appended;
failure/final records remain bounded. No secret, payload or privileged FD is stored.

The owned-map Counter snapshot is journaled before attempting its socket send.
It can therefore survive a blocked/broken data channel. Fixture counter records
have a distinct label. A journal Counter is an observation claim, not proof of
socket delivery or Zeek capture integrity. Failed delivery prevents a clean
overall recovery claim even if resource-close events are present.

The original first processing error is preserved separately from recvmsg errno
and teardown errors. Missing CLOSED remains a protocol failure. A journal final
Sequence, process exit or clear inventory does not turn EOF into normal completion.

## Qualification

- CPU/Clock tests cover normal advance, first/forward gaps, duplicate, regression,
  multiple CPUs, inversion, late events, bounded evidence and Feature quarantine.
  Seven targeted tests passed on the current collector source.
- Four ordinary-UID C socket tests cover EPIPE, a genuinely full socket with a
  delayed reader, a permanently blocked receiver and injected partial send. The
  slow-reader case receives packet/Counter/CLOSED without loss; the blocked case
  fails within the bounded wait and retains the exact failing message/errno.
- Six related C/Python data-plane tests cover Golden Network14 parity, control/data
  separation, processing-error drain, Counter/CLOSED receipt and recvmsg errno
  preservation. Together with the four sender tests:10 passed.
- Current C Bootstrap/Broker/Loader and TCX Object compile successfully. Changed-file
  Ruff/Format and Diff checks pass. The exact candidate startup is separately
  exercised to the approval boundary with OS authentication forbidden.

These are ordinary-user socket/fixture and compilation results. They do not prove
that Live backpressure, DNS, GUI or normal drain is fixed on the kernel path.
No broad GUI/model regression or performance remeasurement was performed.

## Release 0.5.11 candidate

| Identity | SHA256 |
|---|---|
| Manifest | `ccb4bf7cf18d231e6d5f56911b05144049baaddf437e99b821a836080a506b2f` |
| Bundle | `e47f7b0962b6fb787264f8c18c0a6fe52cc04c74bf41ee79585a1848a18ed5f8` |
| Execution image | `2ac831aa787c17932cc5fe48b125364f9bd4c58318428169763b7ef3e471d20a` |
| Bootstrap | `df183f29c4b73d5cd401e37d51ac4a95a13a756411df7ce21e1f6c5361372ee2` |
| Broker | `f54503bc7f1e274acbc85eb54f9a098338907f5bea8a57be08163147c5430fb2` |
| Loader | `38cccbebba767d765ca3c3d67fd4dc119a28f588d982049f3f93b118ea31ab66` |
| TCX Object (unchanged) | `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06` |

The candidate is `.git/native-e2e-remediation-campaign-059/candidate-0511/`.
The earlier uninstalled0.5.10 preview candidates remain preserved and must not
be confused with this approved-for-review artifact. Candidate preparation does
not grant execution approval.

The installed0.5.10 is preserved. Proposed Root update is the same fixed nine-file
layout in `/usr/libexec/soc-agent-ebpf`, root:root, executable0555/other0444.
The reviewed atomic updater retains0.5.10 at
`/usr/libexec/.soc-agent-ebpf.rollback-7cc8ac8d2445a96669eb93b2588bc80911ae99e0561154c33e481d08bae33149`.
That destination was absent at qualification. Existing earlier backups stay intact.
Recheck Root installation/dependencies and rollback collision immediately before
execution. Never overwrite an unknown installation or roll back active Collectors.

## Next Native approval and stop conditions

Exact candidate installation and one Native attempt require explicit new SHA
approval. Reserve slot3/5 before launch and append the authorization/identity to
the campaign Audit; failures consume that slot. No automatic retry is permitted.

Scope remains net:[4026531833], lo/Ingress, <=300s, TCX4096 metadata, Queue32,
AS256MiB/CPU20s per privileged worker. Zeek remains passive lo in the same namespace
with its existing separate RAM512MiB/CPU1 container profile. Inspector alone keeps
SYS_ADMIN for fixed pre/post queries; Broker keeps BPF+NET_ADMIN. No generated
traffic, foreign Link deletion, pinning, packet blocking or privilege inheritance
to GUI/AI is permitted.

Fresh BEFORE inspection must succeed without Link/filter conflicts. Confirm
actual Packet/Network14 counts, per-CPU gaps/reuse, clock inversion, separate ring
and socket loss, bounded send waits, Counter+CLOSED, Zeek terminal receipt and
DNS visibility. Retain original errors and individual FD-release evidence.
AFTER inspection and owned-resource release must still run after data failure.
If resource ownership, installation integrity or cleanup is uncertain, stop new
Native execution and continue only unprivileged investigation.

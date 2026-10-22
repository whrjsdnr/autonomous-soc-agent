# DNS Sidecar 0.5.19: prewarm and bounded streaming qualification

## Scope and preserved evidence

The new campaign is `DNS_PARALLEL_STARTUP_0519`: **Native DNS diagnostics 0/3**,
three remaining. Budget creation authorizes development only. Root installation,
Native capture and local DNS traffic are not executed or approved by this work.
The prior 0.5.18 aggregate 3/3 ledger and all 0.5.17/0.5.18 private evidence are
preserved byte-for-byte; the new campaign references their hashes rather than
rewriting historical counts. Private preparation is under
`.git/dns-parallel-startup-campaign-0519/`.

The installed root/TCX release remains 0.5.16. No install or rollback operation
is required: this candidate is a separate SHA-held diagnostic image. Earlier
candidate images remain available unchanged. Reverting this candidate selection
does not alter installed files, TCX state or historical evidence.

## Root cause and limits of the previous evidence

In the approved 0.5.18 attempt, the local UDP and TCP clients each received one
matching DNS response. All 12 captured packets had kernel CHECKSUM_PARTIAL;
12 checksum-normalized memory copies and their receipt chain passed independent
controller verification. The capture supplied Counter/CLOSED with zero socket
drops. Zeek produced zero bytes and no Counter/CLOSED before
`ZEEK_ANALYSIS_SESSION_DEADLINE`, subsequently generalized to
`ZEEK_LIVE_INTEGRITY_FAILED`. This was an application deadline exception, not a
kernel errno or another demonstrated transport checksum rejection.

Capture CLOSED arrived 7.025548234 seconds after readiness. The full active
execution including cleanup returned after 10.779482978 seconds. Docker was
created only after capture, so its startup, initialization and analysis all
competed for the last approximately 2.5 seconds before the analysis deadline.
The container started and was later stopped/destroyed. The old stderr sink and
lack of fine startup spans prevent attributing its zero output to a particular
internal initializer or to cold filesystem caches. Both cold-start cost and
serial scheduling must be measured; the latter is directly established by code.
Postflight socket/container absence does not retroactively verify protocol drain.

## Structural change

1. The existing SHA-pinned sudo entry authenticates once and verifies the existing
   installation, controller, scope and dependencies. Its monotonic entry timestamp
   starts a **ten-second active deadline**, including these post-authentication
   checks. Human password wait and unprivileged preflight remain outside it.
2. Before opening any packet socket, the image emits a scope-bound authenticated
   state and accepts only the fixed `START\n` token through its inherited pipe.
   There is no executable path, command or deadline supplied by that token. The
   gate is bounded by the original deadline and rejects expired sessions.
3. The ordinary-user controller launches the existing fixed Zeek image, capless,
   network-disabled, read-only, with the existing 512 MiB/CPU1 profile. It feeds
   only a 24-byte Raw-IP PCAP header and waits for the existing READY envelope.
   A high-priority initialization marker on stderr and an explicit READY flush
   make startup observable before packets or EOF. The marker is an initialization
   phase boundary, not proof of every internal Analyzer's readiness.
4. Only validated READY permits START. The existing AF_PACKET/filter/AUXDATA path
   binds lo, drops UID/GID and all effective/permitted/inheritable/ambient caps,
   and emits capture READY. The approved probe runs once only in a separately
   approved Native execution. No test in this work sends these DNS requests.
5. The controller independently verifies each analysis copy and digest chain,
   filters to the exact probe ports, and feeds an ordinary-user analysis worker.
   One bounded memory queue retains at most 32 packets over the entire session,
   each at most 512 bytes. Consumer progress does not reset that total budget.
   Queue/limit failures are explicit. No PCAP or payload is persisted.
6. Capture and Zeek analysis now overlap. Capture is capped below seven seconds
   (6.9 seconds leaves socket-close scheduling headroom), and is shortened further
   if startup consumed more time, reserving 0.75 seconds inside the same deadline.
   This does not increase the approved maximum or fabricate timestamps.
7. Capture Counter/CLOSED closes the feed; EOF follows all queued input. The
   existing Zeek stream validates Sequence, Counter/CLOSED, DNS and cleanup.
   Worker, capture process and container cleanup finish before final time
   qualification. Missing CLOSED, pending work, budget overruns and cleanup
   failures remain failures. Cleanup may continue after a deadline for safety;
   any overrun is recorded and cannot qualify as ten-second success.

The transient privileged start gate is bounded, not a new privileged service or
setuid path. It permits no arbitrary shell or inspection command. Existing sudo
and fixed-entry verification are reused. The new scope digest explicitly binds
prewarm/shared-deadline semantics as well as namespace/interface/packet bounds.

## Timing evidence

The candidate records:

- Docker creation/start/die/destroy from a fixed, exact-plan-label read-only events
  query; query failure is recorded separately and is not resource-absence proof.
- Controller process launch, script-init marker, READY, Counter and CLOSED receipt
  times. These are controller observations, not exact internal instruction times.
- Capture start before socket creation and end after socket context close, using
  monotonic time supplied by the same WSL kernel as the controller.
- Input EOF, analysis cleanup, finalization and final elapsed/deadline result on
  success and failure. Metadata query overhead also counts toward final elapsed.

Docker event wall times are compared to controller wall receipt times only;
packet timestamps and TCX monotonic clocks are not compared to them. Monotonic
spans govern deadlines. Wall-clock adjustments may invalidate wall-span analysis.

Actual **nonprivileged file/memory-only** runs with synthetic UDP/TCP input and
fresh containers measured:

| Phase | UDP file input | TCP file input |
|---|---:|---:|
| Container create -> start | 142.6 ms | 133.1 ms |
| Start -> script-init marker received | 308.0 ms | 673.6 ms |
| Script-init -> READY received | 9.2 ms | 26.2 ms |
| Docker client launch -> READY | 708.3 ms | 918.3 ms |
| READY -> CLOSED received | 3.7 ms | 106.7 ms |
| Runner including cleanup | 907.2 ms | 1,266.2 ms |

No live capture is represented by this table. Containers were new but OS/image
cache state was neither changed nor controlled; these measurements do not prove
cold-cache behavior or a Native ten-second guarantee. The serial dependency is
removed independently of cache state: tests require READY before the first
packet/EOF, then verify actual Zeek DNS transactions and normal closure.

## Tests and preserved contracts

Focused tests cover queue32 total limits/closure, stale/wrong START rejection
before socket creation, exact embedded image wiring, digest/corruption rejection,
shared deadline restrictions, real pinned Zeek UDP/TCP on generated memory input,
pre-packet READY, timing phases, Counter/CLOSED and owned-container absence.
A full controller-path integration test mocks Root and the DNS probe while using
real capless Zeek; it proves READY -> START -> probe ordering, worker shutdown and
an INCOMPLETE verdict when no DNS packets were supplied. It is not Native success.
Ruff, formatting and diff checks cover only changed files. No GUI/model/performance
suite or broad regression was repeated.

CHECKSUM_PARTIAL remains provenance, not end-to-end payload authentication.
Original checksum/digests and verified receipt chain remain intact. Actual
completed-checksum corruption and missing AUXDATA stay rejected. TCX ABI,
Network14, model artifacts and DNS Analyzer logic are unchanged. Raw-IP metadata
that fails the existing L2 contract remains UNSUPPORTED, excluded from Network14.
Audit writes remain ordered and fsynced; failed stream and cleanup evidence are
not overwritten. GUI and AI workers retain ordinary-user privileges.

## Release candidate and next approval

- Version: **0.5.19**, not Native executed.
- Manifest: `a5477af2a0bbeb03cc86135c3cd18550fa6f930902adca815821b26a156351ab`
- Bundle: `d01916df744bb8b86797149f88cc3d20245c75cfe70bd2dbc5cf2274b66630d7`
- Execution image: `b81c6d9becf6d03a58210fa5bcf505d51d045c2332f21ef5e5a5e1fc91c5bb69`
- Candidate: `.git/dns-parallel-startup-campaign-0519/qualified-candidate/`.

Separate explicit approval is required for this exact image and one Native run:
`net:[4026531833]`, lo, whole active deadline ten seconds, capture at most seven
seconds/32 packets/512 bytes each, Queue32; `127.0.0.53:53`,
`native-0516.localhost.`, A, one UDP and one TCP query, no external DNS. Recheck
existing service identity before sending; do not replace any service. No Root
installation, TCX operation, offload change or automatic retry is authorized.

Native results remain PENDING. The new campaign remains **0/3 used**, three
remaining. Native AI, DNS9 and operational promotion remain **BLOCKED**.

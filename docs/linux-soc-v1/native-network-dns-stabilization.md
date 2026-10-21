# Phase C-3 — Native Network & DNS stabilization

Status: implementation and focused non-privileged verification; **new Native execution pending approval**. Native AI, DNS9 and operational promotion remain BLOCKED. Historical Native evidence is unchanged.

## Clock root cause

Release 0.5.3 actually loaded Program 4861 (tag `5d24af0965a164b7`) and Link 1. It delivered 129 packet records, accepted 126 into Network14 and produced four incomplete candidates, zero eligible features. It stopped at `EBPF_CLOCK_INVALID`.

The parser samples Kernel monotonic time before ring reservation. Ring buffer consumption follows reservation order; it does not sort timestamps sampled before reservation. The Controller previously imposed a global timestamp watermark before per-flow processing. That is a structural mismatch. Cross-CPU execution is a plausible mechanism, but the failed run retained neither the offending timestamp pair nor CPU distribution. Its exact inversion delta and scheduling cause remain UNKNOWN. This is not evidence of a faulty Kernel clock. See [Linux ring buffer design](https://docs.kernel.org/bpf/ringbuf.html).

The metadata adapter now holds at most 32 events and sorts by original Kernel event time, with a fixed 10ms lateness allowance. Receive sequence, per-CPU sequence and timestamps remain unchanged; a separate contiguous flow ordinal is passed to the shared flow assembler. Earlier watermark rejection is avoided only inside this explicitly bounded policy. Events beyond the bound or already-emitted event time fail closed as `EBPF_REORDER_LATE_CAPTURE_GAP`; a full queue fails closed and accounts for the rejected event. No silent drop, timestamp clamp, UTC conversion or AI eligibility override is introduced.

Snapshots retain inversion count, maximum delta, first eight inversion examples, CPU distribution, reordered/late/discarded counts and sequence checks. CPU state is bounded to 128 CPUs. The 10ms allowance is a candidate policy, **not calibrated from the old run**. More than 32 packets within the holdback window can still stop capture; Native measurements must determine whether this budget is practical. This is intentionally not hidden by enlarging buffers or releasing uncertain order.

Network14 retains idle 30s, active 120s, original feature order/float32/digest and completeness rules. Final bounded flush preserves packet times; capture stop, packet budget, late clock and overflow remain incomplete reasons. Kernel monotonic time and Zeek event time remain separate. Reordering establishes no wall-clock calibration or cross-collector correlation.

## Drain and cleanup root cause

The historical `soc_final_drain_counters()` result `-105` came from a path that translated any failed nonblocking data send into `-ENOBUFS`. The original send errno was lost, so it cannot now be called an observed Kernel ENOBUFS. The Python reader also closed its data socket on a processing error, preventing terminal counter/drain delivery. The exact historical syscall failure remains UNKNOWN.

Processing failures now close/finalize feature processing but keep the authenticated bounded data reader alive for final packet accounting, counters, RunEnd and CLOSED. Subsequent packets are validated and explicitly counted as discarded; they cannot re-enter inference. Identity, sequence, protocol or I/O failure still terminates transport. No retry of a failed send is added.

The C data path records the first `send()` API result and actual errno in the private journal. Final drain cannot replace the first processing failure, and cleanup continues after drain errors. Map/Program FDs observed before `bpf_object__close()` are checked immediately with `F_GETFD` for `EBADF`, without intervening FD allocation in the single-threaded Broker. Journal evidence records the checked counts and failures. These are post-close absence checks, **not raw close return values**. Ring buffer and object teardown remain libbpf-owned; numeric FDs are not closed twice. Existing Link FD ownership, no pinning and foreign-Link protection remain unchanged.

The old run's journal records Link release and cleanup, and post-run privileged inventory found Map/Link/sched_cls/lo filters all zero, with the same eleven foreign cgroup programs. This establishes no then-observed residue, not individual FD-close proof or retrospective overall cleanup VERIFIED. New individual close evidence requires the next approved Native run.

## DNS path and visibility

Existing Zeek 9.0.0 analyzer callbacks and DNS adapter are reused. No DNS parser or DNS9 contract is replaced. The pinned image is `zeek/zeek@sha256:3fac39de707be96cb1a8163cab98a11bb2a1aa9e3535247db0f17b9c4670a019`.

A bounded in-memory table (4096 connection/transaction keys, 65536 diagnostic callbacks) compares normalized question/QTYPE/QCLASS fingerprints. The table emits only aggregate counters; no QNAME, fingerprint or raw payload is persisted. Existing `dns_request`, `dns_message`, `dns_query_reply` and `dns_rejected` callbacks cover queries, positive replies and error replies. Zeek remains the transaction matcher. See [Zeek DNS event contracts](https://docs.zeek.org/en/current/scripts/base/bif/plugins/Zeek_DNS.events.bif.zeek.html).

Counters distinguish duplicate pending queries, pending-ID collisions, multiple responses, replies without observed queries and reply-question mismatches. NXDOMAIN/SERVFAIL and truncated records are counted separately. Completed `dns.log` metadata alone cannot reliably identify every wire retransmission or prove every transaction; this limitation is exposed as UNKNOWN rather than guessed. Transaction-start timestamps in completed logs can arrive out of order without a Kernel clock fault.

Visibility is independently classified as DNS_VISIBLE, NO_DNS_OBSERVED, CAPTURE_GAP, PARSE_FAILURE, DNS_TRANSACTION_INCOMPLETE or DNS_VISIBILITY_UNKNOWN. ENCRYPTED_DNS_UNOBSERVABLE requires explicit encrypted-only evidence; port 443 alone never proves DoH. DoH/DoT question contents cannot be reconstructed from ordinary packet metadata. A zero DNS count establishes neither normality nor parser failure.

Historical Native Zeek evidence remains: packet metadata 4096, Network events 117, UDP53 metadata 68, DNS events 0. Its zero-DNS cause remains UNKNOWN. Current resolver routing is a read-only observation, not proof of packet visibility and not permission to change capture interface. TCX counters never attest a Zeek capture handle.

## Verification and GUI/Audit

Focused tests exercise bounded inversion/late events and sequence/queue failure, actual ordinary-user socket send errno, diagnostic FD teardown faults, Control/Data delivery and recovery, and DNS visibility/duplicate/negative outcomes. Pinned real Zeek reads generated PCAPs with no network and no capture privilege; TCP DNS, duplicate query, ID collision, multiple responses, NXDOMAIN and SERVFAIL are covered. A separate same-PCAP comparison checks privacy-filtered `dns.log` against SOC stream transaction ID, QTYPE, RCODE, RTT, TTLs, endpoints, protocol and timestamp. UID is process-specific and deliberately excluded. Query text is absent from both stored forms.

Existing Audit chain verification is exercised in the stream/adapter tests. No old Audit is edited. Recovery does not authenticate, attach or infer. The GUI's four screens/graphs are preserved; the Native window title now identifies Native metadata rather than mock authentication, and final collector/Link labels use shutdown evidence rather than stale ACTIVE state. New ordering/processing/visibility evidence is available through existing diagnostic snapshots. **Live GUI behavior and actual Native DNS remain unverified for this candidate.** No screenshot, whole-model suite or GUI benchmark is repeated.

See the accompanying evidence JSON for exact test logs, source identities and performance scope. A 1000-sample ordinary-user ordering-observe/snapshot microbenchmark is reported without a before/after or Native throughput claim. Memory PSI and process RSS are recorded separately from Broker/GUI Native measurements.

## Release and Native approval requirements

Release 0.5.4 is prepared in `.git/tcx-c3-stabilization/candidate-final/`. The accompanying evidence JSON fixes Bootstrap/Broker/Loader/BPF/Manifest/Bundle and unified install image SHA values. The TCX object is unchanged from 0.5.3: `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06` (`TCX_NEXT(-1)`, 80-byte ABI, no drop/modify).

No Root installation, authentication, capability change, BPF load, TCX attachment, live Zeek capture or generated traffic was executed in C-3 preparation. Root-owned installed 0.5.3 was checked read-only. The prepared update retains the exact old directory; rollback requires explicit approval, quiescence and previous-manifest verification. Unknown files/installations are not overwritten. Existing user/model/raw dataset and Native evidence are excluded from the commit.

Required new approval scopes:

1. **TCX:** exact 0.5.4 Manifest and install-image SHA; atomic update at `/usr/libexec/soc-agent-ebpf` retaining 0.5.3; app startup terminal password once; one attempt on verified current namespace, `lo` ingress, <=300s, <=4096 events, queue32, address space256MiB, CPU20s. No raw payload, drop, pinning, automatic retry or AI. Read-only pre/post Kernel inventory; preserve all external filters/links. Stop on first failure and preserve raw errno/evidence. Safe cleanup remains required on failure.
2. **Zeek:** separate exact source bundle/pinned image, explicitly approved interface and namespace; <=300s, packet4096/event8192/output8MiB, Docker512MiB/CPU1 and only the existing approved capture capability contract. Do not silently switch interfaces. Passive capture does not authorize synthetic DNS traffic. If no plaintext DNS is observed, report visibility UNKNOWN/NO_DNS_OBSERVED and request a separately scoped DNS query/response stimulus if needed.

Native clock behavior, drain result, individual FD teardown, live DNS question/response counts, loss, GUI and final Kernel inventory are PENDING. Native AI, DNS9 and operational promotion remain BLOCKED regardless of fixture success.

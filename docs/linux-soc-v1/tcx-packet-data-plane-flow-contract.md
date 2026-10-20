# TCX packet data plane and Native flow contract — Phase C-1

## 1. Architecture and scope

Baseline: `d94602af9b2accc409b26de235340fe81fcf74e1`. Native Release stays BLOCKED.
No installation, authentication, capability change, BPF syscall/load, TCX mutation,
network capture or test traffic was executed. Existing dirty workspace files are
excluded from the independently archived candidate and preserved separately.

```text
TCX observer (unchanged, Native not executed)
  → existing libbpf ring callback
  → soc_data_emit / separate bounded SOCK_SEQPACKET
  → authenticated metadata receiver / one ordinary-UID reader thread
  → existing eBPF ring decoder and bounded collector
  → shared Network14 arithmetic with observed watermark + compact statistics
  → feature candidate / Capture+Clock+Native AI gates BLOCKED
```

The ordinary-UID C fixture exercises the same data emitter and real Unix transport.
It does not fabricate Kernel ACTIVE, Link IDs, capture attestation or model receipts.
Actual RF/LR/SOC verification uses the existing offline Zeek PCAP path separately.

## 2. Root cause analysis

### Packet route

`tcx.bpf.c` emits the unchanged80-byte `soc_event`. The existing `loader.c` ring
callback previously sent those bytes to `s.ipc_fd`. Handoff control replies are72
bytes; its only asynchronous records were journal messages. A valid ring record
therefore produced `HANDOFF_REPLY_SCHEMA`. Increasing a receive buffer would not
supply a packet contract, source validation, clock semantics or loss accounting.
The callback now invokes `soc_data_emit()` and never sends packet bytes to control.
The prior control-rejection regression remains as a negative test.

### Native Zeek PACKET_LIMIT

Session `session-b9fe165ac83046edb2b6f82f14fc4e10` is read-only, not reused. Its stream
SHA256 remains `cb484bfaa45a6e81df9f2fea94e92e2e0ccabbce061487c08aab7b52fc440787`.
Current reconstruction under the preserved legacy policy yields4096 metadata records,
117 connection events,0 DNS events and51 PACKET_LIMIT windows. **29 windows hit the
per-flow128-record retention cap;22 were still open when the session4096-record budget
ended.** The observed event interval is125.437133s, longest old window65.309362s,
and timestamp regressions0. This is not a timestamp unit error or model failure.
A same-key-only timeout also cannot expire a quiet flow when another key advances.
Exit0/CLOSED/cleanup evidence proves process finalization, not complete traffic.

A separate new-policy shadow projection of those same ordered metadata records produces
14 IDLE_TIMEOUT +4 ACTIVE_TIMEOUT candidates and8 PACKET_LIMIT windows, accounting
for all4096 records, with at most20 active first/last metadata references. This is
**not a reclassification of the old51 windows, Native feature parity, or AI eligibility**.
Capture counters/clock accuracy remain unverified; Native eligible inputs remain0.

## 3. Control/data separation

Control remains PREPARE/ATTACH/STATUS/DETACH/STOP/CLEANUP,112-byte requests and72-byte
replies, plus existing journal records. Sealed object/approval FD handoff is unchanged.
A second abstract Unix address, `soc-ebpf-data.UID.APPLICATION_UUID`, carries data.
The Broker connects after its privilege transition and owns its endpoint. The Controller
owns the receiving endpoint; no BPF/map/Link FD is sent on this channel.

One bounded ordinary-UID reader consumes data independently of control requests.
A lock serializes decoding, adapter setup, final drain and snapshots. It polls the
socket with a50ms bounded wait, stops on protocol/loss failure, and joins at shutdown.
It never authenticates, starts a collector, retries or reattaches. Control waits check
data failure and preserve control schema; they do not parse packet events as replies.

## 4. Packet and envelope ABI

The80-byte little-endian packet ABI is unchanged: generation, monotonic_ns,
per-CPU observed-attempt sequence, interface index/CPU, frame/IP lengths, ports,
family/protocol/TCP flags/hook and endpoint metadata. Compile assertions enforce80B
and little endian. Ingress/Egress hook identity is not first-seen flow direction.

The separate192-byte envelope consists of112-byte header +80-byte body:
magic/version/kind/source, application-wide sequence, socket-send-failure count,
application UUID, **outer release approval digest**, program SHA, then body.
READY/PACKET/RUN_END/CLOSED are distinct; marker bodies are validated separately.
CLOSED is a transport marker, not proof of flow completion. RUN_END is idempotent
per generation. No CLOSED or Native attestation is synthesized by Python.

Wire sequence includes markers; adapter packet sequence and per-CPU observed counter
are separate. Per-CPU gaps may represent unsupported/disabled/undelivered observation;
they cannot be labelled kernel packet drops or uniquely ring reservation loss.

## 5. Data channel security and resources

SO_PEERCRED binds UID/GID/PID at connection. SCM_CREDENTIALS and process start ticks
are checked on every message. After exit, only already-queued kernel-credentialled
records on the bound connection may drain; a reused live PID/start-tick mismatch is
rejected. This does not create new authentication. Application UUID, release approval,
source discriminator, program SHA, generation, namespace-bound plan, ifindex and hook
are independently checked. All SCM_RIGHTS on data are rejected and received FDs closed.
Malformed, oversized, truncated, replayed or wrong-source messages fail closed.

Bounds: queue32 events; receiver batch32; sender socket buffer32768 bytes; ring262144
bytes;4096 packets/run;16 explicit runs/app;65568 data frames/app including markers;
128 active flow states;1024 finalized windows; per-session collector checkpoint/storage
bounds inherited from the existing collector. Native duration300s, AS256MiB and CPU20s
remain unchanged. No unlimited event history or spool is added.

Socket EAGAIN/short send increments the sender's delivery-loss counter and fails the
producer; sequence gaps and missing CLOSED invalidate delivery. Queue rejection and
already-queued records discarded on failure are counted separately. Backpressure high
watermark24 and overflow32 are observable. Kernel drops and ring loss remain UNKNOWN
unless their own evidence exists; a socket-send count0 is not either of those counters.
Channel/protocol failure shuts down delivery, revokes the Handoff on observation, and
allows only existing owned-Link cleanup. No automatic retry occurs.

Linux [Unix socket documentation](https://man7.org/linux/man-pages/man7/unix.7.html)
defines message-preserving seqpacket and credential semantics. Abstract socket names
provide no filesystem access control; peer/session checks are mandatory. SO_SNDBUF
bounds producer buffering; SO_RCVBUF is not claimed to bound Unix sockets.

## 6. Packet adapter

The existing `ebpf.ring.decode`, Event model and EBPFCollector validate80-byte records
and reuse Network14 arithmetic. Collector identity is explicitly EBPF_TCX. Fixture
origin is TCX_STREAM_FIXTURE and is never Native authentication/capture evidence.
IPv4/IPv6, TCP/UDP, lengths, flags, generation, source/hook and sequence are validated.
The unchanged shared C parser handles supported Ethernet/VLAN and rejects unsupported
fragment/extension/truncated formats. Metadata alone cannot reconstruct omitted raw
headers or infer unsupported packets; CPU gaps remain conservative failures.

Addresses/ports exist only in bounded working state. Checkpoints retain plan/context,
counts, feature digests and a bounded feature tail, not packets, payload or FQDN.
A first/last metadata pair is explicitly not a reconstructable full packet proof for
model authorization. No offline-source label is forged to admit Native metadata.

## 7. Clock contract

Kernel CLOCK_MONOTONIC ns, userspace processing monotonic deadlines, Zeek decimal
UTC event time, wall clock, and replay event time remain distinct. Features use exact
integer event-time differences. Kernel ns are not converted to seconds/microseconds
or UTC; processing deadlines never expire a flow using an unrelated clock.
[Kernel timekeeping documentation](https://docs.kernel.org/core-api/timekeeping.html)
distinguishes monotonic from realtime and suspend behavior.

ClockContract binds domain and session. Optional fixture calibration requires3–8
ordered before/wall/after brackets, each no wider than1ms, with a nonempty common
offset interval `[wall-after, wall-before]`. Inconsistent source, session, sequence or
drift is rejected. These are fixture error bounds, not measured Native calibration.
Native accuracy is always UNVERIFIED and eligibility BLOCKED. No unsupported Nano-PCAP
admission or absolute UTC event timestamp is invented. Cross-CPU timestamp regression
under the new ordered watermark quarantines the stream instead of sorting/clamping it.

## 8. Flow reconstruction and termination

Shared Window arithmetic now optionally retains only first/last metadata plus count,
IP length sums/squares/min/max, directional bytes/counts, TCP flag counts and IAT
sum/max. This removes the artificial128-record split **only for the new metadata
stream policy** without increasing the4096-record capture budget or storing payload.
Legacy/default Zeek/offline behavior stays same-key and128-reference bounded.

The C-1 policy advances a global watermark only from validated, ordered observed event
timestamps. It finalizes ACTIVE_TIMEOUT at120s or IDLE_TIMEOUT at30s before inserting
the new packet. No wall-clock idle timer or TCP FIN/RST boundary is invented. Direction
remains first-observed endpoint pair. Flow identity binds application, generation,
source plan, hook/interface/namespace, clock/policy and first sequence. Generation
reuse is denied. Repeated starts cannot alias prior flow/feature identities.

Timeout completion is a *candidate* boundary. NORMAL_END does not create eligibility
without separate training/capture evidence. PACKET_LIMIT, CAPTURE_STOP, QUEUE_OVERFLOW,
CLOCK_INVALID and INCOMPLETE are never promoted. End of observation, process exit and
queue drain do not establish the remaining flows are complete. Graceful Stop drains
accepted data; missing end evidence fails closed. Historical budget windows stay blocked.

## 9. Feature eligibility

Feature names/order, formulas, units and float32 conversion remain unchanged. The
new producer context is TCX_METADATA_NETWORK14_C1. Tests compare all14 values and
numeric digests against the independent ML v1.1.0 producer, including a300-packet
variable-length/flag window that previously hit the128-record cap.

Capture integrity, source/sequence, clock, completeness, parity and artifact validation
are separate from feature generation. New metadata produces candidate features, no
receipts or model calls. Native capture/clock/artifact eligibility is insufficient;
Native AI remains BLOCKED even for a timeout candidate or valid fixture calibration.
Existing actual offline Zeek RF/LR inference and READ-only SOC investigation remain
the only model integration exercised here. DNS9/operational gates remain BLOCKED.

## 10. Zeek/TCX, ownership and GUI preservation

Zeek retains connection/DNS protocol analysis; TCX retains packet/hook diagnostics.
Counts are not added together; TCX counters never attest a Zeek capture handle.
Existing DNS0 cause stays UNKNOWN. No new DNS analyzer/model is introduced.

TCX observer source/object, TCX_NEXT(-1), no pinning, private Link FD ownership,
foreign-link preservation and Legacy TC Native blocking remain unchanged. Root entry,
authentication policy gates and capability qualification are not opened.
The GUI retains all four screens/cards/charts and adds data state/sequence/socket loss,
unknown ring loss, queue overflow and error rows to System. Fixture activity is not
plotted as Native live traffic. Reader/worker shutdown is verified in GUI fixtures.

Shared producer source changed through a backward-compatible extension, so the Zeek
bundle digest changes even though its launcher/image/default flow behavior is preserved.
Do not reuse prior Zeek or TCX session approval. New compiled Broker/Loader/Bootstrap
and C-1 bundle/package identities require a separate reviewed Native approval.

## 11. Verification and audit/recovery

Nonprivileged verification covers fixed packet/envelope ABI, C sender → separate
Unix data channel → existing decoder/adapter, independent control replies, sequence,
replay, UID/PID/start ticks, session/program mismatch, SCM_RIGHTS cleanup, size bounds,
queue overflow/discard accounting, backpressure, EOF, crashes, idempotent termination,
clock/bracket/session mismatch, IPv4/v6 TCP/UDP, timeout/budget semantics, dense-window
all14 parity, actual offline RF/LR/SOC, GUI and audit/recovery.

Application audit adds TCX_DATA_CHANNEL_BOUND and TCX_DATA_FINALIZED with bounded
sanitized evidence. The reused metadata RuntimeStore checkpoints feature/source/clock
context and digests into its append-only audit chain. Recovery verifies that chain and
returns RESTORED_NO_REATTACH with no authentication, capture or inference replay.
Existing Native/archive/audit files are never rewritten.

## 12. Performance

Measurements below use ordinary-UID C/socket/parser and offline/GUI fixtures only.
Data delivery timing includes control round trip, decoding, statistics and checkpoint;
it is not pure wire or Kernel throughput. Decode is measured separately. Native rates,
Native clock precision, ring drain/counter coverage and actual capability costs remain
UNKNOWN. No comparable prior data-plane throughput exists; no improvement is claimed.

## 13. Remaining blockers

Actual trusted installation, effective sudo/PAM password policy, capability transfer,
Kernel verifier/TCX coexistence, Native clock calibration/cross-CPU ordering, ring/map
counter coverage and final Kernel ring drain require separate system validation.
The C-1 socket/adapter queue drain is not proof of Kernel ring drain. Source counter
attestation and whole-capture Native parity remain unverified. A data fixture or shadow
timeout cannot promote Capture Integrity or Native AI. SIGILL root cause stays UNKNOWN.

## 14. Native approval requirements

This candidate cannot run Native merely by granting consent: release/OS/TCX admission
gates remain closed. Installation/authentication qualification must be completed in
separate reviewed work, without restoring setuid or reusing cached approval.

A future scoped run must bind exact release manifest/Bootstrap/Broker/Loader/bundle,
unchanged TCX object SHA, a new app/session approval, current namespace, lo ifindex,
one explicit INGRESS or EGRESS hook,300s,4096 records,queue32,ring262144 bytes, AS256MiB
and CPU20s. Review the new data-channel schema, first/last metadata storage and bounded
reader lifetime. No pinning, foreign filter changes, generated traffic, Native AI,
DNS9 or operational promotion is authorized. Recheck identity and cleanup before any
new run. Actual Native authentication/load/attach remain PENDING.

## Final qualification results

| Cohort | Result (not summed) |
|---|---|
| native_contract | 147 passed in 222.99s (0:03:42) |
| broker | 63 passed in 30.15s |
| regression | 695 passed in 77.67s (0:01:17) |
| integration | 58 passed in 74.87s (0:01:14) |
| model | 1 passed in 9.63s |
| gui | 19 passed in 123.26s (0:02:03) |
| audit | 125 passed in 13.49s |
| data_handoff | 75 passed in 373.05s (0:06:13) |
| gui_handoff | 2 passed in 56.84s |

Development structural292 PASS is retained as an earlier-source result; final affected75-case Data/Handoff cohort and2-case GUI cohort supersede its Data/Handoff execution. These overlapping counts are not added. Historical692+3 failures are not relabelled as PASS: the source-evidence assertions were amended and the complete695-case cohort rerun. Initial approval-envelope mismatch and interrupted development runs remain in private transcripts.

GUI n=3 startup median 2.9121s, idle RSS 174.84MiB. Decode n=3×1000 median 20245ns/event;24-record C/socket/feature/checkpoint delivery median 120.954ms. Shared WSL PSI and per-run values are recorded; no Native throughput or causal before/after performance claim.

| Verdict | Scope |
|---|---|
| TCX_DATA_PLANE_FIXTURE | VERIFIED |
| CONTROL_DATA_SEPARATION | VERIFIED |
| PACKET_ABI | VERIFIED |
| CLOCK_CONTRACT | VERIFIED_FIXTURE_NATIVE_ACCURACY_UNVERIFIED |
| FLOW_TERMINATION | VERIFIED_CANDIDATE_VS_INCOMPLETE |
| NETWORK14_PARITY | VERIFIED_OFFLINE_GOLDEN_AND_DENSE_ML_REFERENCE |
| NATIVE_FEATURE_ELIGIBILITY | BLOCKED |
| ZEEK_COLLECTOR | PRESERVED_DEFAULT_SEMANTICS_NEW_BUNDLE_REQUIRES_APPROVAL |
| TCX_LINK_OWNERSHIP | PRESERVED |
| GUI | PRESERVED |
| AUDIT_RECOVERY | VERIFIED_FIXTURE |
| NATIVE_AUTH | PENDING |
| NATIVE_TCX_ATTACH | PENDING |
| NATIVE_AI | BLOCKED |
| DNS9 | BLOCKED |
| OPERATIONAL_PROMOTION | BLOCKED |

| Candidate identity | SHA256 / digest |
|---|---|
| entry | `8e4ef82c3fe45ae5a414509316a2922898148ed860bb7ebdde9f743509ce4455` |
| bootstrap | `2dc6e2d00a80a37f052aa3a664f593e3c5db7a8307b00c504e1df2457b4ee171` |
| broker | `2e1fa1463947eb4df38d131fbdc020c8058560382af0d124b7c0818f71b0f01c` |
| libnative-tc.so | `c2e6841f0986246f5cb76b046ab002cd6be62c359d3d39c62596dee33cf588d1` |
| tc-fixture | `2b938cff0aa28831d283f3db2b66c9ea654a3101d7c16db514aecf5d48811aa6` |
| tcx-dispatch-fixture | `d43a397d678dbceb89faf85a5198924f9a95782f5384a0bd2abfbbda188feaca` |
| tcx.bpf.o | `928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a` |
| source_bundle_digest | `a258bbd24915ad2048a0b37148ad5d4d95f9925b18eb059f101f8b4483ee64a9` |
| Release manifest | `ba51746b3e80bb3c23872de14bcd3880b397c7705d4ab495beaa982c9bbe9e54` |
| Bundle | `a258bbd24915ad2048a0b37148ad5d4d95f9925b18eb059f101f8b4483ee64a9` |
| New Zeek bundle | `0307ad0632696635246442ef65436c50d7df85fe0b2a047e954c84adda40ed84` |

Candidate version 0.3.1, Native Release BLOCKED. Source/BPF compile is not verifier/TCX evidence. All preserved132 user files,400 protected hashes and58 raw stat entries match baseline;4 intentional source amendments retain their original SHA-matched snapshots. Old Native session files and model artifacts are unchanged. Workspace/Export/Stage/Commit comparison is recorded separately to avoid self-referential evidence hashes.

# Total Monitoring Native Timestamp / DNS Diagnosis

Validation date: 2026-10-19. SOC baseline `777914d42829a4adb3331d3c30e3f2534f6b82e5`;
ML baseline `e1a01260f0463a38d4d778859bc2a86f8e9cfbde`.
Verdict: **PARTIAL diagnosis; Native Total E2E BLOCKED**.
This investigation opened no packet socket, generated no DNS test traffic and ran
no authentication/privilege command. No runtime, helper, Producer or model was changed.

## Native identity and integrity

The latest Total session at inspection was
`session-efe2ca83d4f543b9befca9abdbfd687a`. Its manifest identity is
`e344f991-aac8-4c11-aa92-f0dfcb232c72`; the directory suffix is not the manifest UUID.
Session digest: `a5f7e5a9071a28d505bdb154c8c4eeed8eef867fcac470d9b231624f4699add6`.
The same digest occurs in STREAM_STARTED and authentication/READY audit entries.
All nine session code hashes and the interpreter hash match the local files.
READY has matching identity, UID/GID 1000, E/P/I/A capabilities zero and NoNewPrivs=1.

All seven SQLite databases passed `PRAGMA integrity_check` through
`mode=ro&immutable=1` connections, after confirming no WAL/journal files existed.
The monitor state digest and all eight consecutive hash-linked audit entries were
verified. Audit head:
`857b6004a04079af447325c2391d8580cf2c9439f009185f61ef6cd358cce43c`.
The sanitized [evidence record](total-native-timestamp-dns-evidence.json) binds
these observations, source file SHA256s, database counts and comparison operands.
It contains no raw packets, DNS names, credentials or personal paths.

| Stored evidence | Result / scope |
| --- | --- |
| STREAM_STARTED UTC | 2026-10-18T23:44:17.193526+00:00 |
| READY audit UTC | 2026-10-18T23:44:18.730614+00:00 |
| STREAM_ABORTED UTC | 2026-10-18T23:44:19.629811+00:00 |
| OS-auth exit audit | HELPER_EXITED, exit code 0 |
| Raw frames / helper IP packets / transport delivered | 36 / 18 / 18 |
| Controller accepted packets | 17; packet 18 rejected |
| Last observed kernel packets / drops / counter sequence | 36 / 0 / 40 |
| Comparison-bound counter sequence | 38 |
| Last observed queue / high-water | 0 / 9 |
| Verified CLOSED / rejected CLOSED | MISSING / MISSING |
| Final counters / finalization | UNKNOWN / BLOCKED |
| Helper DNS query / response / parse failure | 0 / 0 / 0, observed prefix only |
| Controller DNS events | 0 |
| Durable Network Source / Queue | 0 / 0 |
| Other source / queue records | 0 / 0 |
| Model receipts / findings / investigation checkpoints | 0 / 0 / 0 |

Counter VERIFIED and zero drops apply to the observed prefix, not a verified
whole-session termination. Helper exit zero does not prove CLOSED delivery or
final persistence. Packet observations are transient active-flow metadata; no
eligible finalized flow was committed. Zero source rows therefore do not prove
that no packets were received. No saved session was resumed or rewritten.
Counter sequence identifies a statistics sample, not an IP packet: sampling can
advance it for filtered frames and no-packet heartbeats. The comparison's sealed
sample 38 and later observed sample 40 are distinct, not a proved packet reorder.

## Exact timestamp failure and comparison scope

The persisted STREAM_ABORTED context agrees with the monitor state:

| Field | Value |
| --- | --- |
| Packet / helper packet sequence | 18 / 18 |
| Previous event ns | 1792367059623629397 |
| Rejected event ns | 1792367059623629386 |
| Previous UTC representation | 2026-10-18T23:44:19.623629397Z |
| Rejected UTC representation | 2026-10-18T23:44:19.623629386Z |
| Previous minus rejected | **11 ns** |
| Ordering scope | GLOBAL |
| Rejected flow-key digest | 1ab5551e41602bfc0d9d756442eafd4663643b4b833c13a8a010dbaecb60f3a4 |
| Direction / timestamp origin | OUTBOUND / KERNEL_SO_TIMESTAMPNS |
| Input origin | NATIVE_AF_PACKET |

`StreamingFlows.add()` compares the incoming integer ns with the **last globally
accepted packet**, before per-flow aggregation and event-time expiry. It does not
compare against controller UTC, inference time or a wall-clock deadline.
GLOBAL does not establish that both operands belong to the same flow: the previous
flow identity was not retained. A fixture with two distinct flow keys demonstrates
this exact limitation. Per-flow `Statistics.add()` also rejects regressions.

`PacketCapture.receive()` unpacks the native timespec (`@ll`) into integer seconds
and nanoseconds, validates the ns range and forms `seconds * 10**9 + nanos`.
The UTC datetime is truncated to microseconds, but the original integer ns is
serialized as an integer, validated against that datetime and used by the Flow
and Producer adapter. Both native operands fall in the same microsecond;
datetime-only comparison would hide this regression. Mock recvmsg plus JSON
round-trip tests preserve both exact values. No float conversion, timestamp
clamping, sorting, fabricated packet time or ordering tolerance was introduced.

Linux documents SO_TIMESTAMPNS as the nanosecond form of a system-time mechanism
that is not necessarily monotonic. Thus monotonically increasing transport sequence
does not by itself guarantee monotonically increasing event timestamps.
[Linux timestamping documentation](https://docs.kernel.org/networking/timestamping.html).

The immediate failure trigger is **verified**. The underlying cause remains
**UNKNOWN**: raw ancillary bytes, receive-time monotonic samples, previous flow key
and a contemporaneous clock-adjustment trace were not retained. The records do not
distinguish kernel timestamp generation/order from UTC adjustment. There is no
evidence proving a WSL kernel defect, timestamp conversion defect, duplicate
loopback packet, or transport/reader reorder. Sequence 18 agrees across helper
and controller at the comparison. The single-reader bounded FIFO and seal checks
reject wire/queue sequence corruption in fixture regressions. No reorder buffer
is justified by this native evidence.

## Network / DNS split integrity

The Total helper parses an OUTBOUND packet once, including DNS metadata where
supported, and updates DNS counters before the next heartbeat/PACKET send.
Raw INBOUND loopback clones consume frame/rate budget but are not forwarded.
OUTBOUND here is the AF_PACKET packet type, not the Flow's forward direction;
Flow direction still uses the first-seen endpoint tuple. A local DNS server's
response can also have an OUTBOUND loopback observation.
One authenticated Unix SOCK_SEQPACKET channel carries both domains.
`TotalCapture` removes the DNS field only for the existing network transport
validator, returning the original packet after validation. Names are prohibited.

Controller order in `StreamingMonitoring.observe()` is:

```text
origin/interface validation -> increment controller sequence
  -> copy without DNS for Network aggregator
  -> GLOBAL / FLOW event-time validation and Flow aggregation
  -> accepted-packet count
  -> DNSDiagnostics.observe(original packet)
  -> eligible Network flow persistence / inference queue
```

Sequence 18 failed before DNS diagnostics. The first 17 accepted packets generated
no DNS diagnostic events. The helper's independently sampled DNS totals also
remained zero, so the current record does **not** show a DNS-bearing packet lost
solely at the controller branch. The new Unix fixture deliberately supplies a
DNS-bearing packet at sequence 18 to prove branch behavior; its helper query count
is 1, unlike the native record. These are separate observations.

An abort releases active state as RESTART_GAP, blocks finalization/inference and
prevents automatic retry. A later helper exit zero does not reverse that decision.
Network and DNS statuses are derived from the same failed collection lifecycle;
DNS9 inference has an additional independent parity gate.

## DNS format compatibility and visibility

The real parser supports Ethernet/VLAN, IPv4/IPv6, UDP DNS and a **single complete
length-prefixed TCP DNS message in one packet**. DNS questions/responses have a
bounded parser, opcode zero and exactly one question. It extracts transaction ID,
question digest/type/class, response flag/code; no question text is retained.
TCP fragmentation, coalesced TCP messages and general TCP stream reassembly are
not supported. Malformed port-53 input yields a parse diagnostic. IP fragments and
unsupported IP/transport types fail closed earlier. The parser does not decrypt
DoH/DoT or inspect the virtual host-side DNS channel. An encrypted-port event is
visibility UNKNOWN, not a verified DNS query. Response matching is bounded and
ambiguity remains explicit.

Read-only observations on 2026-10-19:

- `/etc/resolv.conf` is WSL-generated and contains nameserver `10.255.255.254`.
- `ip route get 10.255.255.254` resolves to a **local lo route**, source the same
  resolver address. A default eth0 route does not override this local route.
- lo has `127.0.0.1/8`, `10.255.255.254/32` and `::1/128`.
- `ss -lunt 'sport = :53'` shows both UDP and TCP listeners at `10.255.255.254:53`.
- Kernel is `6.18.33.2-microsoft-standard-WSL2`. No resolver/interface was changed.

Microsoft documents `10.255.255.254` as the default DNS tunneling endpoint and
describes Windows DNS resolution through virtualization rather than a normal
guest-to-host network packet.
[WSL configuration](https://learn.microsoft.com/en-us/windows/wsl/wsl-config#experimental-settings),
[WSL networking](https://learn.microsoft.com/en-us/windows/wsl/networking#dns-tunneling).

Crucially, the Microsoft source adds the endpoint to **lo** in `GnsEngine` and
starts a local TCP/UDP DNS server in `DnsTunnelingManager`, then forwards DNS
messages through its host channel. These sources distinguish the local resolver
leg from the virtualized upstream leg. They do not justify claiming that *all*
DNS is invisible on lo. Source reviewed on the validation date; the installed WSL
binary was not matched to a source revision.
[GnsEngine.cpp](https://raw.githubusercontent.com/microsoft/WSL/master/src/linux/init/GnsEngine.cpp),
[DnsTunnelingManager.cpp](https://raw.githubusercontent.com/microsoft/WSL/master/src/linux/init/DnsTunnelingManager.cpp).

The lo endpoint and listener are consistent with DNS tunneling. Actual use during
this short failed session is unproved. A query to the local listener should be
distinguished from host/upstream traffic; current routing and source code support
the feasibility of seeing that local leg, not a native visibility PASS. Synthetic
UDP/TCP query/response frames with the WSL resolver address pass the existing parser.

| DNS absence classification | Finding |
| --- | --- |
| EARLY_ABORT | VERIFIED collection truncation at sequence 18; primary diagnostic disposition |
| NO_TRAFFIC | UNKNOWN for the session/host; no DNS observed in the accepted prefix |
| NOT_VISIBLE | Possible for host/upstream tunneled resolution, encrypted DNS, other interfaces; not proved for the local lo resolver leg |
| PARSE_REJECTED | Not observed: helper failures 0, controller parse events 0 in prefix |
| UNKNOWN | Whether any DNS request occurred during capture, and why none entered this prefix |

Neither querying a default eth0 route nor assuming DNS tunneling invisibility is
sufficient reason to change the interface. DNS queries 0 is a count, not DNS
visibility validation or evidence of a healthy DNS pipeline.

## Producer, model, GUI and recovery boundaries

Network14 v1.1.0 is unchanged (14 float32 features, event-time duration/IAT,
first-seen bidirectional direction, idle 30s/active 120s). Contract digest:
`84ba0916f0ce4e9e12bb70712db2cd1eaea84ba4173acd57b647faf38efb1c6e`.
Config digest: `7999723911ce3d2e9cd3b3b6e0d45e11f44b1316cdf9c7f4883d7e2a69ca21a7`.
No native eligible flow or feature vector exists in this session, so native parity
and Quality/Edge inference are **BLOCKED**, even though fixture parity can pass.
RF/LR SHA256 matches the existing trusted identities in the evidence record.
DNS9 raw-query training Producer parity remains **UNVERIFIED / BLOCKED**; no DNS7
compatibility was assumed and no DNS9 vector was generated.

The GUI's failed timestamp, packet sequence, raw frame/IP packet counts and zero
inference values correspond to the persisted native metrics. Network/DNS STOPPED
does not mean graceful verified completion: finalization remains BLOCKED and the
abort error remains visible. `transport_reader_running=true` in the saved error
snapshot was sampled before transport cleanup; it is not current process-liveness
evidence. No new native GUI session or capture was launched for this diagnosis.

Native audit integrity passed, but CLOSED and final counters are missing.
Checkpoint count is zero, so native investigation/checkpoint recovery is not
verified. Fixture recovery separately verifies that stored failure remains
blocked, collection is not LIVE and past receipts are not counted as new inference.
Operational promotion, OS WRITE and automatic privilege/capture retry remain denied.

## Changes and verification

Changes are limited to this report, sanitized native evidence and two test modules.
There is no proved implementation defect warranting a product/helper modification.
The new tests cover exact 11ns conversion/JSON preservation, global cross-flow
comparison, sequence-18 Total branch behavior, clean CLOSED versus event-time
abort, DNS parser endpoint compatibility, TCP coalescing/encrypted visibility,
recovery/gates and evidence digest tampering. No production session is opened by
these tests; temporary roots and mocked peer attestation are explicit.

Current-run results (not historical test counts):

- Guarded related regression: **423 passed, 1 skipped in 182.55s**. Groups:
  `tests/unit/network_capture`, `tests/unit/streaming_network`,
  `tests/integration/streaming_network`, `tests/unit/live_network`,
  `tests/integration/research_adapter`, `tests/gui_streaming_checks.py`,
  `tests/gui_total_monitoring_checks.py`, with `--import-mode=importlib`.
  The skip is an explicit retained-native-session opt-in test; it is not a PASS.
- Guard reported **0 network socket attempts**, no new native capture/test traffic.
  Unix socket fixtures are ordinary-user local metadata transport. Actual RF/LR
  artifacts were used in existing fixture E2E/READ-only investigation and WSLg
  GUI regressions; these are not native inference receipts for the failed session.
- Ruff `check src tests`, `format --check .` (1019 files) and `git diff --check`
  passed. No ML file was edited or formatted.
The initial new-test run was **7 passed, 2 failed** because the new fixture reset
its cumulative DNS query count to zero in PACKET after advertising one in
HEARTBEAT. Production correctly rejected it as STREAM_DNS_COUNTER_MISMATCH before
delivery. Only the fixture was corrected; the next focused run was **9 passed in
1.83s**, with zero network-socket attempts reported by the capture guard. These
runs are separate and are not summed as independent coverage.

Independent Export: SOC HEAD plus exactly these four new files, with ML HEAD in
a sibling export, excluded all baseline user modifications and Reliability Replay.
The same guarded groups passed **423 passed, 1 skipped in 173.83s**, with 0 network
socket attempts. Export Ruff check and format passed (975 files). The exported
reader independently matched all 13 original native evidence file SHA256s, the
native session digest, nine helper source hashes, audit head and both externally
referenced trusted model SHA256s. No binary or operational DB was copied into Git
or the export. Model references still require the installed trusted environment;
this is source/evidence reproducibility, not a self-contained model distribution.
Final report-only test-result updates were synchronized to the export; test source
and evidence bytes remained the versions exercised by both regression runs.

Preservation audit matched all 122 baseline SOC user/Replay files, 10 ML files,
80 Total-session files and both RF/LR binaries. Before committing, only this report,
the evidence JSON and the two new test files are eligible for staging. Stage hashes
must match the independently verified export. Existing stage was empty and all
baseline user changes remain unstaged. No new long-running soak was warranted:
there was no product time/worker/lifecycle change in this diagnostic-only task.

## Remaining blockers and next approval scope

Native Total E2E remains BLOCKED: no verified CLOSED/final counters, no eligible
durable flow, no RF/LR receipt or investigation, and no native DNS visibility proof.
The 11ns kernel-origin metadata regression is established; its generation cause
cannot be recovered from data that was not retained. Do not treat an unchanged
capture retry or a coarser datetime comparison as a resolution.

The next decision is a separately reviewed bounded diagnostic extension retaining
only current/previous ns, sequence, hashed flow identity, receive monotonic time and
DNS parse category/counters. No payload/name logging is needed. A helper/dependency
change would require new SHA/bundle review and explicit user authorization.
Only after that review should the user authorize a fresh session, lo only,
maximum 300s, 128 raw frames/s, burst 256, maximum 38,656 raw frames, temporary
CAP_NET_RAW, no retry, bounded queues and unchanged fail-closed/gates. If a DNS
visibility stimulus is needed, one user-owned bounded local resolver query must be
approved separately; no such query is authorized/executed by this diagnosis.
Changing to eth0, extending limits, changing DNS configuration or enabling DNS9
inference is outside that scope.

Unchanged source identities (no new helper approval was exercised):

- Total helper: `1c178e650e08f6c8da9957ee8020bd594cd71efff222dbfc8ac22739371d1e31`.
- Shared stream helper: `5f767a6e6cb69a9b79853d5f714649f5a8ebf74af9c05867f393273b68fb633b`.
- Legacy one-shot helper: `a8a0cafe7494922a0296a250129ab5695b681dbbec6febf512509b023ef44856`.
- Total nine-file bundle digest: `e26057b77534b552701826dd1c4d6829e76d94fcfc0bb8c263fd661f2038ac0f`.

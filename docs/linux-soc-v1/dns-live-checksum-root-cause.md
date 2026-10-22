# DNS Live checksum root-cause verification

## Verdict

`ROOT_CAUSE_UNKNOWN` for the historical Native packet checksum mismatch.
Transport checksum rejection before DNS analysis is confirmed. None of
`CHECKSUM_OFFLOAD_CONFIRMED`, `CAPTURE_PATH_MISMATCH_CONFIRMED`, or
`PACKET_CORRUPTION_CONFIRMED` is justified for those packets with the available
bytes/status evidence. Offload is a supported hypothesis, not a verified cause.

No Native execution, DNS traffic, installation, capability or offload setting
change was performed during this investigation. Native AI, DNS9 and operational
promotion remain BLOCKED. New campaign `NATIVE_JOURNAL_DNS_0516` remains Native
0/3 and installation 0/3. Old campaign history and source evidence are unchanged.

## Baseline and original evidence

- Code baseline: `ad8d1cda9c5601fa5b78cc8090a72884c029d847`.
- Installed release: 0.5.16, Manifest
  `2e5faaf4dac7381157adcc82b61465316946aa115c501073f25eb95ee9282289`.
- Original observation: `.git/native-zeek-control-campaign-0514/attempt-3/`.
- Client received one UDP and one TCP DNS response from 127.0.0.53:53 for the
  explicitly approved synthetic `.localhost` question; both RCODE 0.
- Zeek metadata contains the exact endpoint pairs: UDP two packets and TCP ten.
  Port-53 checksum rejections: 12. DNS analyzer dispatch/query/response: 0.
- Relevant Native directories contain no original PCAP/PCAPNG or packet-byte
  dump. `network14_packets.log` and `stream.jsonl` store metadata, not raw frames.
  The `packet-handoff-fixture` file is an executable, not captured packets.
- Generated PCAPs from offline tests are unrelated input and cannot replace
  missing historical Native bytes.

| Historical field | Evidence |
|---|---|
| IPv4 header checksum value / independently recomputed checksum | UNKNOWN |
| UDP checksum value / independently recomputed checksum | UNKNOWN |
| TCP checksum value / independently recomputed checksum | UNKNOWN |
| Captured and reported frame length | Present in metadata; equal for the 12 test packets |
| Packet time | Zeek seconds/microseconds retained; no invented cross-clock calibration |
| Endpoint query/response direction | Available from exact endpoint pair |
| Packet-socket ingress/outgoing direction | UNKNOWN; endpoint direction is not a substitute |
| Per-packet CSUMNOTREADY / CSUM_VALID | UNKNOWN; not recorded |
| IP IHL/options, VLAN/encapsulation, exact checksum input bytes | Insufficient metadata |

Equality of capture/frame lengths does not establish payload integrity. Successful
socket responses and cumulative kernel checksum-error counters of zero likewise
do not prove what bytes/auxiliary status the passive capture saw.

## Read-only offload observations

Kernel `6.18.33.2-microsoft-standard-WSL2`, namespace `net:[4026531833]`, interface
`lo`, IPv4 127.0.0.1 and 10.255.255.254, IPv6 ::1.

`ethtool -k lo` reports RX checksum on (fixed), TX checksum on, generic TX checksum
on (fixed), TSO/GSO/GRO on, LRO off. These are configuration observations; they do
not say whether an individual recorded packet had CHECKSUM_PARTIAL or validated
checksum state. No `ethtool -K`, network setting or service changes were made.

## Exact rejection path and source evidence

The reviewed command uses the pinned Zeek 9.0.0 image, `-i lo -f 'ip or ip6'`,
with no `-C` or project checksum-ignore policy.

1. The libpcap source calls `pcap_next_ex`, then initializes the Zeek packet using
   timestamp, captured length, reported length and bytes. This call does not carry
   Linux packet auxiliary checksum flags.
2. `Packet::Init` initializes `l4_checksummed` to false. The standard libpcap
   initialization path does not set it using per-packet kernel validation status.
3. UDP checks its pseudo-header/transport checksum unless checksum state/policy
   says otherwise. A bad result triggers bad-checksum handling and returns before
   forwarding to application analyzers. TCP has the equivalent early return.
4. The existing `visibility.zeek` callback counts bad TCP/UDP checksums on port 53.
   In the Native run it counted 12, while DNS callbacks were zero. Thus there were
   no DNS events for the stream producer or adapter to deliver; this is not an
   observed downstream DNS-adapter rejection.

Version-pinned upstream sources:

- [pcap packet initialization](https://github.com/zeek/zeek/blob/v9.0.0/src/iosource/pcap/Source.cc)
- [Packet::Init checksum state](https://github.com/zeek/zeek/blob/v9.0.0/src/iosource/Packet.cc)
- [UDP checksum early return](https://github.com/zeek/zeek/blob/v9.0.0/src/packet_analysis/protocol/udp/UDP.cc)
- [TCP checksum early return](https://github.com/zeek/zeek/blob/v9.0.0/src/packet_analysis/protocol/tcp/TCP.cc)
- [Zeek checksum/offload explanation](https://zeek.org/faq/)

The API evidence identifies a checksum-state propagation gap in this source path.
It does not prove this gap caused the historical mismatch: that requires the
missing per-packet status and bytes. Upstream source review is also distinct from
attesting every instruction in a deployed binary.

## Non-privileged cause-discrimination experiment

`tests/integration/zeek_attestation/test_checksum_root_cause.py` reuses the existing
DNS frame fixtures, TCP session construction, PCAP writer and StreamProcess.
Only generated files are fed to the pinned Zeek image, network=none,
cap-drop=ALL, ordinary UID. No sockets, live capture or checksum-ignore setting
are used. Checksum values below are **generated fixture values, not Native values**.

| Protocol / constructed state | Header checksum | Transport field | Recomputed transport | Zeek result |
|---|---:|---:|---:|---|
| UDP valid | 0xf6a8 | 0x5fd8 | 0x5fd8 | One query/response/match |
| UDP pseudo-header seed model | 0xf6a8 | 0x8441 | 0x5fd8 | Two checksum rejections, no DNS |
| UDP deliberately corrupted checksum | 0xf6a8 | 0x5ed8 | 0x5fd8 | Two checksum rejections, no DNS |
| TCP valid first segment | 0xf6cb | 0x78d7 | 0x78d7 | One query/response/match |
| TCP pseudo-header seed model, first segment | 0xf6cb | 0x841e | 0x78d7 | Eight checksum rejections, no DNS |
| TCP deliberately corrupted checksum, first segment | 0xf6cb | 0x79d7 | 0x78d7 | Eight checksum rejections, no DNS |

The seed model is explicitly constructed, not a Native offload observation.
All six cases have valid IPv4 header checksums and reach Counter/CLOSED with
verified file-process cleanup. A seventh focused test returns UNKNOWN for
truncation, VLAN or fragments outside the diagnostic's narrow fixture scope.
IPv4 UDP zero checksum is treated as not present, not as a bad checksum.

This demonstrates why a byte-checksum failure or a bad-checksum counter alone
cannot distinguish an incomplete offload seed from actual checksum corruption.
It also shows that globally ignoring checksums would bypass a real rejection
boundary, not merely fix a display problem. No packet repair or runtime admission
change was implemented. Ruff/format and these focused tests passed.

New private experiment receipts: `.git/dns-checksum-root-cause/`. These are labeled
GENERATED_PCAP_NOT_NATIVE_EVIDENCE. The original Native evidence is not edited.

## Minimum safe remediation and Native evidence required

A cause-specific runtime fix cannot safely be selected yet. The working TCX,
Network14, Journal and cleanup implementations remain untouched. In particular:

- Do not add global `-C`, change offloading, or mark bad-checksum packets valid.
- Do not equate a seed-like field value with proof of offloading.
- Do not feed rejected/incomplete traffic to Native AI or DNS9.

The smallest next diagnostic needs the **same packet's** raw checksum fields,
independently computed checksum, full-segment availability, captured/reported
length, link/encapsulation, direction, timestamp and kernel packet auxiliary
status. Linux `TP_STATUS_CSUMNOTREADY` and `TP_STATUS_CSUM_VALID` must be recorded
with their source and identity; absence of either flag does not itself prove
corruption. Existing classic-PCAP header fields cannot recover these missing
flags retrospectively. Header-only snapshots are insufficient to recompute a
transport checksum when payload is omitted.

A future explicitly approved, bounded diagnostic can inspect full test frames
only in memory, compute the checksum and discard bytes, retaining checksum/status
metadata rather than payload. Proposed scope: net:[4026531833], lo, exact approved
127.0.0.1 ↔ 127.0.0.53:53 test flows, at most 32 diagnostic packets, at most 512
bytes per frame in memory (larger/truncated frames remain UNKNOWN), at most 10s,
one UDP and one TCP `.localhost` transaction, no external DNS, no offload changes.
Any observer needs explicit Capture authority and trusted-execution packaging;
no arbitrary repository helper should run as Root. This diagnostic is not yet
implemented/packaged or authorized by this investigation, and is not scheduled.

After evidence is available:

- Proven partial/offload state: implement a narrowly scoped, explicitly admitted
  offload-aware capture policy/metadata path; retain unverified capture quality
  where independent integrity is absent. Do not globally skip validation.
- Proven completed-packet corruption: reject, count and retain ineligibility.
- Proven byte/length/offset alteration between sources: fix that exact conversion
  and verify matching original/Zeek interpretation.

## Release and budget decision

No new runtime Release is needed for the completed investigation/tests/docs.
Installed 0.5.16 and its Rollback copy are preserved. A future privileged checksum
observer or changed capture policy will require a reviewed diagnostic build,
exact image/Manifest/SHA and separate approval before execution; no such new
release is claimed ready here. The existing CHECK-only 0.5.16 retry image does
not acquire the missing evidence and repeating it cannot establish this cause.

New campaign remains Native **0/3**, Root installation **0/3**. No old ledger,
Audit, PCAP or Native diagnostic was rewritten. The historical full E2E remains
failed; this offline experiment is not Native success.

## Diagnostic capture candidate (2026-10-22; not executed)

The missing evidence now has a separate implementation in
`collectors/checksum_evidence.py` and a preparation-only image builder in
`ebpf_tc/checksum_image.py`. Existing Native receipts, ledgers, installed release,
TCX ABI, Network14, models, GUI, and Zeek checksum policy are unchanged.

The observer uses an IPv4 AF_PACKET/SOCK_DGRAM socket with PACKET_AUXDATA and
SO_TIMESTAMPNS. A locked classic socket filter limits delivery to nonfragmented
TCP/UDP between 127.0.0.1 and 127.0.0.53, port 53. This is a socket filter, not a
BPF_PROG_LOAD, tracing attachment, or TCX program. A protocol-zero socket prevents
pre-bind traffic delivery. The fixed socket binds only to lo/ifindex 1 in
net:[4026531833]. There is no packet transmission method in the observer.

Each received packet produces a single metadata receipt: L3 byte digest, capture
sequence, kernel realtime timestamp, packet type/direction, IP ID, endpoint tuple,
TCP sequence when applicable, actual and independently recomputed IP/transport
checksums, pseudo-header seed, lengths, auxiliary status, and DNS transaction ID
when a complete DNS message is present in that packet. TCP fragments of a DNS
message are not invented or reassembled into a claimed transaction. Header options
are included in checksum computation. Incomplete, fragmented, invalid-length and
truncated inputs cannot acquire a valid checksum verdict. IPv4 UDP checksum zero
means absent, not a successful checksum verification.

The entire transport segment is needed to recompute a checksum. At most 512 bytes
are received per packet and raw bytes are held only in RAM, with core dumps
disabled. Oversized or missing ancillary metadata fails explicitly. Up to 32
metadata records are retained for at most 10 seconds; no unbounded queue exists.
Receipts are emitted incrementally so a subsequent failure does not erase prior
observations. PACKET_STATISTICS socket drops are reported separately from checksum
mismatch, and socket context cleanup runs on both success and failure.

### Kernel evidence and limits

Linux v6.18 `packet_recvmsg()` constructs auxiliary status from the same skb whose
bytes are delivered: CHECKSUM_PARTIAL sets CSUMNOTREADY; non-outgoing
`skb_csum_unnecessary()` sets CSUM_VALID; TCP GSO sets GSO_TCP. See the
[official Linux packet socket implementation](https://github.com/torvalds/linux/blob/v6.18/net/packet/af_packet.c)
and [UAPI flags](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/if_packet.h).
These are upstream source contracts; running WSL2 behavior still requires the
approved observation. Current local headers contain the same three flags.

CSUM_VALID does not distinguish all internal checksum states. GRO state, GSO size,
segment count, and COMPLETE versus UNNECESSARY remain explicitly UNKNOWN. The
observer does not claim PCAP reveals them. An exact internal-state trace would
require a separately reviewed and approved kernel observation path; none is
implemented or loaded here. A same-packet partial flag plus checksum mismatch and
pseudo-header seed provides evidence unavailable in historical Zeek records, but
cannot retroactively prove the historical rejection cause. GSO checksum arithmetic
is recorded as arithmetic, not a packet-corruption verdict. Same-packet Zeek
rejection/correlation remains PENDING until evidence is actually collected.

### Trusted execution candidate and approval boundary

The diagnostic image embeds the existing installer verification helpers and OS
entry policy helpers. It reuses `unified_image.pinned_command()` for isolated
`/usr/bin/sudo -k -u root -- /usr/bin/python3 -I -S -c <SHA-held entry>` execution.
The root entry checks the held image bytes, fresh controller PID/start ticks,
numeric caller, namespace, release/bundle/program envelope and approval digest,
system dependencies, installed release integrity and password policy. Its only
installer action is `check`: it never installs, rolls back, starts Bootstrap
handoff, or starts TCX/Zeek collectors. Existing authentication mechanisms are
reused; no new setuid path or arbitrary shell is introduced.

After creating and locking the receive socket, the observer clears supplementary
groups and switches permanently to the original numeric UID/GID. Effective,
permitted, inheritable and ambient capabilities must be zero. PR_SET_DUMPABLE=0
protects the retained receive socket from ordinary same-UID ptrace; NO_NEW_PRIVS
prevents later privilege gains. The observer never passes this socket to GUI/AI
workers, spawns children, or executes additional commands. Privilege-drop behavior
is tested with mocks only, not claimed Native verified.

Prepared image (0400, private, no execution):

- Path: `.git/dns-checksum-evidence-capture/capture-image-v2.py`
- SHA256: `beb6e5b60d059e8a389cbbf4419867f6a14dcd2112234b56113954c63889dd8b`
- Scope digest: `3bc9933f715af29761cde1c5c64e95e7ae408ed29c995651a436eeb6920cdef7`
- Installed manifest: `2e5faaf4dac7381157adcc82b61465316946aa115c501073f25eb95ee9282289`
- Installed bundle: `bddd454656af79a4fac26ce0d4f20cb1d00f3afc2012e7531ce3f7778c271916`
- Installed release remains 0.5.16. No replacement release/install is required for
  this diagnostic. The diagnostic image itself requires explicit SHA approval.
- Candidate resource limits: address space 256MiB, CPU 20 seconds, observer wall
  time 10 seconds, 32 records, snaplen 512. No network or offload configuration
  changes. No BPF load or kernel hook.

An approved session would create a fresh standard envelope, verify image and
release again, bind the existing approval digest to that envelope and image SHA,
and use the existing pinned command. Do not reuse a historical session envelope
or mistake the release manifest digest for the session approval digest.

A separate ordinary-user process may run the existing fixed DNS probe only after
explicit approval and OBSERVER_READY: one UDP and one TCP A query for
native-0516.localhost. to the existing 127.0.0.53:53 service. There is no external
query, resolver setting change, or replacement DNS server. Probe source SHA is
`1b466afcb1fbaf0b5d9a56744640140ef07389342537f5d1bbb9245a2e403f8f`;
its traffic plan digest is
`0b6c59f501489f67da18e5a7f671b80853542376a8df7a2b0495cd9fbdeb5757`.
Approval of capture alone does not authorize this probe or a Zeek/TCX restart.

### Verification and current verdict

Ten focused nonprivileged tests pass: UDP/TCP completed/partial-seed models,
IP options, both filter directions and out-of-scope rejection, truncated/missing
auxiliary data, GSO status, rejected unprivileged entry, mocked UID-drop/socket
cleanup/drop statistics, and no-install/no-collector entry contract. Ruff and
format checks pass for changed Python files. No live socket, sudo authentication,
DNS probe, BPF load, collector restart, or configuration mutation was performed.

Read-only preflight still reports kernel 6.18.33.2-microsoft-standard-WSL2,
net:[4026531833], lo checksum offload/GSO/GRO/TSO on, and existing UDP/TCP listeners
at 127.0.0.53:53. These settings alone do not prove offload caused rejection.
Actual Native checksum fields/recomputed values/kernel per-packet flags remain
UNKNOWN until approved capture. Historical Zeek rejected 12 transport packets;
this observation remains unchanged. ROOT_CAUSE_UNKNOWN remains the verdict.
Campaign budget is unchanged at Native 0/3 and root installations 0/3. Native AI,
DNS9 and operational promotion remain BLOCKED.

## Approved Live diagnostic result (2026-10-22)

**CHECKSUM_OFFLOAD_CONFIRMED for the current controlled loopback test.** This is
new same-packet evidence; it does not replace or rewrite the historical Native
receipts, whose individual kernel flags remain unavailable.

Executed exactly the approved diagnostic image
`beb6e5b60d059e8a389cbbf4419867f6a14dcd2112234b56113954c63889dd8b`
in net:[4026531833], lo/ifindex 1. Root installation, TCX attachment and Zeek restart
were not performed. One OS authentication request was used. After readiness,
the existing local DNS probe sent exactly one UDP and one TCP A query for
native-0516.localhost. to the existing 127.0.0.53:53 service. Both received matching
55-byte responses, RCODE 0, transaction IDs 49665/49666. No external resolver
request or settings change was made.

The observer received 12 packets: UDP 2, TCP 10, all HOST packet type 0. Each
packet was joined to the probe's actual ephemeral port (UDP 45662, TCP 32961),
addresses, protocol and transaction ID where a complete DNS message was present.
All 12 had valid IPv4 header checksums, unequal stored/recomputed transport
checksums, and a stored transport checksum equal to the folded pseudo-header
seed. The same recvmsg's auxiliary status was 9 (USER | CSUMNOTREADY) in all 12.
This directly establishes CHECKSUM_PARTIAL at this packet-socket observation
point: the transport field has not yet become a completed checksum. This is not
evidence of a damaged DNS message or a completed bad checksum on an external wire.

Representative actual packet values (hexadecimal; full metadata receipt is private):

| Packet | IPv4 checksum, stored = recomputed | Transport stored | Transport recomputed | Kernel partial |
| --- | --- | --- | --- | --- |
| UDP query | 0x3a48 | 0xfe76 | 0x36b2 | true |
| UDP response | 0x1897 | 0xfe86 | 0x9dd1 | true |
| TCP DNS query segment | 0xc441 | 0xfe85 | 0xdf3e | true |
| TCP DNS response segment | 0x290d | 0xfe95 | 0x4632 | true |

GSO_TCP was false for every observed packet. Therefore enabled GSO/TSO settings
are not proof that these particular DNS packets were segmented. GRO internal
state, CHECKSUM_COMPLETE and CHECKSUM_UNNECESSARY remain UNKNOWN; CSUM_VALID was
not exported for these packets. No raw frame/DNS payload was persisted.

### Comparison with Zeek

Historical Zeek evidence recorded the same controlled test shape: UDP 2, TCP 10,
transport checksum rejected 12, DNS analyzer entered 0. Today's observation
establishes the missing kernel state for today's packets. The historical and
current packets have different ephemeral ports/timestamps; they are not presented
as the same capture. Zeek was not restarted under this diagnostic-only approval,
and a current same-packet Zeek rejection counter was therefore not measured.

The verified Zeek v9 UDP/TCP path rejects an uncompleted seed when it is treated
as a finished checksum, before forwarding to DNS. See the official
[UDP checksum gate](https://github.com/zeek/zeek/blob/v9.0.0/src/packet_analysis/protocol/udp/UDP.cc)
and [TCP checksum gate](https://github.com/zeek/zeek/blob/v9.0.0/src/packet_analysis/protocol/tcp/TCP.cc).
Together with the previously documented loss of checksum auxiliary metadata in
the pcap-to-Zeek input path and the completed/partial fixture comparison, this
explains the observed rejection mechanism. It does not retroactively recover the
historical packets or prove every future checksum failure is offload-related.

A subsequent fix should preserve kernel checksum provenance in the dedicated
loopback capture input and review a tightly scoped partial-checksum handling
policy. CHECKSUM_PARTIAL must not simply be relabeled as an already validated
checksum. Completed bad checksums, untrusted sources, truncation and malformed
packets must continue to fail. No global `-C`, offload toggle, parser bypass or
checksum rewriting policy was enabled by this diagnostic.

### Closure, timing and preservation

Counter reports socket_packets=12, socket_drops=0. Capture sequence 1..12 is intact,
CLOSED arrived, and exit status was 0. All observed packets span 30.834ms between
first and last kernel timestamps and match the two approved local transactions.
The configured receive deadline was 10 seconds; the measured observer elapsed
time was **10.010559 seconds**, a 10.559ms timeout/completion overrun. Its exact
scheduling/syscall contribution was not separately instrumented. This overrun is
recorded rather than silently reported as strictly <=10 seconds. No additional
capture or retry followed.

After socket setup the observer reported CapEff/CapPrm/CapInh/CapAmb all zero.
The sudo child, ordinary-user controller and diagnostic terminal exited.
`/proc/net/packet` contained only its header after completion (no remaining packet
sockets). CLOSED, normal exit and process absence establish diagnostic FD/process
cleanup. No BPF object/link was created, so no TCX detach or kernel resource
deletion was attempted. Per-close syscall return values were not instrumented.

The first terminal UI launcher exited before starting the one-shot script; the
persistent terminal then started it once. The exclusive `started` reservation,
one sudo process record and one probe receipt demonstrate one Native diagnostic,
not two capture attempts. Existing DNS listeners remained present. SHA comparisons
verified the installed release files, old Native verification, and historical
budget/audit files unchanged. The append-only supplemental diagnostic ledger
records this one attempt: campaign Native diagnostic usage 1/3, remaining 2;
root installation usage 0/3. Historical budget files are preserved byte-for-byte.

Private evidence:
`.git/dns-checksum-evidence-capture/live-attempt-1/{capture.jsonl,probe.json,completion.json,verification.json,preservation.json}`.
No product source changed during this approved execution, no broad regression was
repeated, and no commit/push was made. Native AI, DNS9 and operational promotion
remain BLOCKED. Zeek Native DNS E2E success is not claimed from this diagnostic.

## Offload remediation candidate 0.5.17 (approval pending)

The selected fix is a DNS analysis sidecar, not a replacement TCX collector or a
system checksum setting. The root-installed TCX release remains **0.5.16** and its
nine files are not installed, replaced or rolled back by this candidate. Version
0.5.17 identifies the separately SHA-approved DNS sidecar manifest and execution
image; it is not a claim that a new root release was installed.

Path: reviewed OS entry -> bounded AF_PACKET/AUXDATA capture -> ordinary UID ->
validated memory-only checksum copies -> pipe-backed PCAP -> pinned unprivileged
Zeek -> existing Producer/Consumer -> DNSPreprocessing -> append-only receipts.
Capture is limited to net:[4026531833], lo, the existing 127.0.0.53:53 endpoint and
its local test client. Only the actual probe's UDP/TCP client ports are forwarded
to Zeek; other local DNS observations are explicitly counted as excluded. The
root observer requests no installation, TCX or external network operation.

The existing capture filter, privilege drop, process restrictions, OS policy
checks and SHA-held entry are reused. A nine-second receive deadline reserves
margin below the approved ten-second diagnostic budget; each record is <=512
bytes and the entire memory batch is <=32 packets. The inherited output pipe
uses nonblocking writes with bounded POLLOUT waits. Error metadata retains stage
and errno; receive/copy/pipe failure still exits the socket context. Normal and
error paths do not automatically recapture or regenerate traffic.

### Four checksum states and copy contract

`offload_copy.analysis_copy()` returns one of:

- CHECKSUM_VALID: complete packet bytes independently verify; no rewrite.
- CHECKSUM_PARTIAL_CONFIRMED: kernel auxiliary status reports partial, the stored
  transport field exactly matches the expected pseudo-header seed, and IP,
  length, local endpoint and TCP/UDP bounds all validate. Only the two checksum
  bytes of an immutable analysis copy are changed.
- CHECKSUM_INVALID: completed checksum failure, wrong partial seed, invalid IP
  checksum, conflicting flags or malformed lengths; no analysis packet emitted.
- CHECKSUM_UNKNOWN: missing metadata, absent IPv4 UDP checksum, unsupported
  auxiliary flags, fragmentation, GSO/VLAN, unhandled IPv6 extension headers or
  out-of-scope source; no analysis packet emitted.

IPv4 and plain IPv6 TCP/UDP are covered by pure normalizer tests. The Native
candidate capture remains IPv4-only at the approved 127.0.0.53 endpoint; it does
not silently expand capture to IPv6. GSO packets are rejected instead of guessed.
CHECKSUM_COMPLETE, UNNECESSARY and GRO internal states remain unclaimed.

Each transformation receipt preserves original frame SHA256, original transport
checksum, IPv4 checksum where present, auxiliary status, analysis checksum and
analysis frame SHA256. Sequence, timestamp, packet type and complete auxiliary
bytes join the receipt digest chain. The controller reconstructs the original
checksum bytes from the analysis copy and independently verifies both hashes and
the transformation before forwarding it. Original packet bytes stay unchanged in
RAM; raw originals/copies/PCAP are not written to host disk or audit. Metadata
receipts are appended and fsynced before further processing.

Partial provenance cannot independently prove arbitrary payload authenticity:
a payload bit change before checksum completion is not detectable by a checksum
that has not yet been computed. The fix therefore never relabels a partial copy
as completed CHECKSUM_VALID, never claims full end-to-end Capture Integrity,
and never opens Native AI/DNS9/operational gates. Known completed bad checksums
remain rejected even if a kernel-valid flag is present. This limitation is tested,
not hidden by a false integrity claim.

### Existing Zeek integration and permissions

The official Zeek v9 source supports `-r -` input through stdin; its existing
`ExtractNextPacket()` path constructs Packet from pcap bytes without AUXDATA.
See [PcapSource](https://github.com/zeek/zeek/blob/v9.0.0/src/iosource/pcap/Source.cc).
The sidecar uses that existing input API instead of inventing a Zeek plugin or
passing privileged sockets to the container. Existing live.zeek, visibility.zeek,
Network14 policy, Producer/Consumer, DNS parser and transaction diagnostics are
reused without changing the checksum-validation policy.

`StreamProcess(pcap_input=...)` validates the entire bounded nanosecond/raw-IP PCAP
layout before launching Docker. It feeds stdin with the existing selector loop
while draining stdout, avoiding a blocking feed/read deadlock. Zeek runs with the
existing pinned image, network=none, cap-drop=ALL, ordinary numeric UID/GID,
read-only filesystem, no-new-privileges, RAM512MiB/CPU1 and owned-container cleanup.
It receives no CAP_NET_RAW, host network, Docker socket mount or original payload
file. No `-C` or ignore-checksums network policy is added.

Reports distinguish the Native AUXDATA capture from Zeek's memory-file analysis;
`native_capture` in the Zeek subprocess receipt remains false and
`analysis_copy_input` is true. The enclosing session carries the approved Native
source provenance. File-fixture and memory-copy success cannot manufacture a
Native capture receipt. Existing Supervisor proxies need only stdout/poll/wait;
new stdin handling is conditional and preserves the prior live path.

### Qualification, release identity and rollback

Focused qualification covers IPv4/IPv6 TCP/UDP partial/valid copies, corrupt
completed checksums, wrong seed, missing/conflicting metadata, fragments,
truncation, unsupported GSO, Queue32/PCAP bounds, transformation digest tampering,
pre-authentication manifest rejection, capture-bind failure cleanup, exact
embedded-image wiring without privileged entry execution, actual pinned Zeek DNS
parsing from synthetic memory copies, legacy Supervisor proxy behavior and
existing checksum/unsupported-stream regressions. Real Zeek file-only tests show
one UDP and one TCP transaction independently producing query=1, response=1,
matched=1, checksum rejection=0, DNS adapter acceptance, CLOSED and container
cleanup. These are non-Native integration results. Existing checksum rejection
fixtures still reject corrupt input. No broad model or GUI regression was run.

Prepared sidecar candidate:

- Version: 0.5.17, contract soc-dns-analysis-sidecar-release:v1.
- Manifest: `8c716217f14de4ee3c1279ccb0b426df080882c4a9215ea469f682d7b996ac7a`
- Source bundle: `be9c4ce3799475399ac41431fe9c8789733c0c657af8c79c4dda79e80fb00973`
- Execution image: `0828050020dfc047b3b2100877763a6677290fa91d6a79d758168fbd463f576b`
- Private directory: `.git/dns-offload-remediation-0517/candidate-final/`.
- Base installed root manifest remains
  `2e5faaf4dac7381157adcc82b61465316946aa115c501073f25eb95ee9282289`.
- TCX object remains
  `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06`.
- Existing Zeek image remains
  `zeek/zeek@sha256:3fac39de707be96cb1a8163cab98a11bb2a1aa9e3535247db0f17b9c4670a019`.

Rollback requires no root file operation because the sidecar does not install or
replace files. Stop the single observer/owned container and retain the original
installed release and historical evidence. Future execution refuses changed
source/image/base-release identity, reserves an exclusive one-shot attempt
folder, and will not repeat after failure. A fresh session envelope and image
approval digest are generated; the sidecar manifest is not substituted for the
installed root manifest or the authentication digest.

No new Native capture, query or root execution was performed during this
remediation. The prior diagnostic remains 1/3 used, 2 remaining; root installs
remain 0/3 in its supplemental ledger, with historical ledgers unchanged. The
new image and its two-query local DNS test require explicit approval before
Native E2E can be judged. Live DNS analyzer counts, Native copy-path integrity
and cleanup for this candidate remain PENDING. Native AI, DNS9 and operational
promotion remain BLOCKED.

## Approved 0.5.17 Native sidecar verification (2026-10-22)

The user approved commit 9c1ee1b, sidecar manifest
8c716217f14de4ee3c1279ccb0b426df080882c4a9215ea469f682d7b996ac7a,
bundle be9c4ce3799475399ac41431fe9c8789733c0c657af8c79c4dda79e80fb00973,
and image 0828050020dfc047b3b2100877763a6677290fa91d6a79d758168fbd463f576b.
These identities, source bytes, namespace, interface and installed base were
verified before the single execution. One OS authentication request was made.
No root install, TCX operation, offload toggle or DNS configuration change occurred.

**Functional Native DNS path VERIFIED; whole-session time qualification FAILED.**
The application's original completion receipt is retained unchanged; this
postflight qualification explicitly includes the timing check absent in 0.5.17.

Actual results, from the same captured packets and the pinned Zeek analyzer:

| Observation | Actual result |
| --- | --- |
| UDP query / received response | 1 / 1, transaction 49665, RCODE 0 |
| TCP query / received response | 1 / 1, transaction 49666, RCODE 0 |
| Kernel packet observations | 12: UDP 2, TCP 10 |
| CHECKSUM_PARTIAL_CONFIRMED / analysis copies | 12 / 12 |
| Normalizer rejection / socket drops | 0 / 0 |
| Independently verified original/copy digest pairs | 12 |
| DNS analyzer dispatch | 4 |
| Zeek parsed queries / responses | 2 / 2 |
| Zeek transaction / question matching | 2 / 2 |
| Zeek checksum rejection / parse failure | 0 / 0 |
| DNS Adapter received / accepted | 2 / 2 |
| Root capture counter and CLOSED | received, 12 packets |
| Zeek Counter / CLOSED / exit | received / received / 0 |
| Zeek stream records / sequence gaps / invalid records | 19 / 0 / 0 |
| Largest captured packet / configured maximum | 109 / 512 bytes |
| Observed packets / maximum | 12 / 32 |

Every kernel auxiliary status was 9 (USER | CSUMNOTREADY); GSO_TCP was unset.
Original transport fields were preserved as metadata, and every copy digest
matched the independently reconstructed original + permitted two-byte checksum
change. Original/copy hashes differ as expected because the copies changed;
"verified digest pairs" does not mean the two packets are byte-identical.
Representative actual transport fields -> analysis checksum: UDP query
0xfe76 -> 0x5568; UDP response 0xfe86 -> 0xbc87; TCP DNS query segment
0xfe85 -> 0xd816; TCP DNS response segment 0xfe95 -> 0x3f0b. IPv4 header checksums
were validated and preserved. No raw packet/PCAP was retained on disk.

The UDP client was 127.0.0.1:37800 and TCP client 127.0.0.1:41523, both targeting
the existing 127.0.0.53:53 service. Both responses matched the approved question.
The matching Zeek DNS records have those same client ports, transaction IDs,
QTYPE A and RCODE 0. This is live-source analysis, not a synthesized DNS receipt.
Only the two approved queries were generated; no bad-packet or missing-metadata
traffic injection was authorized or performed. Their rejection contracts remain
supported by the prior nonprivileged tests, not claimed as new Native adversarial
observations.

### Integrity and remaining metadata limitation

The existing Zeek raw-IP input produces all 12 packet summaries as UNSUPPORTED:
live.zeek checks `ip_length + 14 <= frame_length`, assuming an Ethernet header,
while this LINKTYPE_RAW input contains L3 bytes only. The summaries retain correct
TCP/UDP endpoints; the DNS analyzer and Network/DNS events succeeded. This
fail-closed classification is preserved and not relabeled as Network14 input.
The sidecar did not run TCX or prove a new Network14 path. The existing installed
TCX/Network14 path was unchanged.

Socket accounting, receipt chain and analysis-copy provenance are verified for
this controlled sample. This does not attest arbitrary payload authenticity,
CHECKSUM_COMPLETE/UNNECESSARY or GRO state. Zeek's subprocess receipt correctly
says native_capture=false and analysis_copy_input=true; Native provenance belongs
to the preceding approved AUXDATA observer. Native AI/DNS9/operational gates remain
BLOCKED despite successful DNS analysis.

### Time failure root cause and actual cleanup

A read-only observer recorded the packet socket appearing and disappearing; the
final `/proc/net/packet` table was empty. Controller observation of capture READY
to CLOSED was 9.018970756 seconds. Zeek processing and cleanup then took
1.166150447 seconds. These sequential monotonic intervals alone total at least
10.185121203 seconds. READY to the result file's timestamp was approximately
10.284795301 seconds. Thus the capture fits ten seconds, but the complete active
capture+analysis session does **not** meet the user's whole-session ten-second
limit. Authentication time is excluded from these measurements.

Failure stage: END_TO_END_TIME_BUDGET. API path:
offload_session.execute -> StreamProcess.run. Qualification code:
POLICY_WALL_TIME_EXCEEDED. errno: none (a policy/budget failure, not a kernel
syscall failure). Root and container exit codes were both 0. Root cause: the
nine-second capture and subsequent Zeek analysis were serial phases without a
shared absolute deadline; the original functional verdict omitted elapsed time.
No automatic Native retry followed.

Capture, normalizer/analysis and cleanup remain independently recorded: root
counter/CLOSED and Zeek counter/CLOSED were delivered, stream protocol finalized,
container absence was positively queried, the sudo/observer/controller/terminal
exited, and no packet socket remained. No privileged FD was delivered to GUI/AI.
Per-close syscall return values were not separately instrumented; process exit,
closed socket context and absence checks support diagnostic cleanup. All installed
root files (SHA, owner, group, mode), pre-existing Native evidence, historical
ledger files and original user changes matched the preservation snapshot.

Private immutable attempt evidence is under:
`.git/dns-offload-remediation-0517/candidate-final/live-attempt-1/` and
`.git/dns-offload-remediation-0517/live-launch-1/`. The supplemental execution
ledger references the old ledger digest without changing it: aggregate diagnostics
2/3 used, 1 remaining; root installation attempts remain 0. The old 0.5.17
manifest/image and raw application completion receipt are preserved.

### Minimal nonprivileged time-contract remediation: candidate 0.5.18

The fix reserves seven seconds for capture and shares a ten-second active-session
deadline, starting at authenticated observer readiness, with the analysis phase.
StreamProcess accepts that deadline only for bounded memory-PCAP analysis, not
for existing Native/Supervisor paths. Expired budgets reject before launch; the
analysis receive loop and completion checks also enforce the deadline. A half
second is reserved for finalization. The immutable pinned-image lookup is already
performed before authentication, so the deadline-bound analysis does not repeat
an independent ten-second Docker lookup after capture.

Deadline failure cannot skip owned-container or socket cleanup. Cleanup may need
to continue after a deadline under OS/daemon stalls; that is a reported budget
failure, never a false time-compliance claim. The final Native verdict now includes
elapsed-time eligibility rather than DNS parser success alone. This is not a hard
real-time scheduling guarantee. A new measured Native attempt is required.

Twelve focused nonprivileged tests passed: exact embedded image wiring, digest
rejection and bind-failure cleanup, expired deadline before Docker launch, rejection
of deadline changes to the legacy Native path, UDP/TCP analysis with and without
a shared deadline, and the unchanged Supervisor proxy contract. Actual Zeek in
these tests used generated file/memory input only; no new capture/query occurred.

Prepared DNS sidecar 0.5.18, **not executed**:

- Manifest: `35443757635f4dd5d4426fb9e0ba054cc5f83688518ad34f06cc9ac72441a443`
- Bundle: `ded51c5c57bfae846e59a7a78f0c71a59d45eddba3d8dfe46bc101587f6adb7f`
- Image: `1c4a2db64d625bb6d95bdc9f5d4d3137a30b2a4b439098ef67eda3edfdba4027`
- Directory: `.git/dns-offload-remediation-0518/candidate-final/`.
- The installed root/TCX release stays 0.5.16; no install/rollback action is needed.
- Namespace/interface/endpoint/question and UDP/TCP query counts remain fixed.
- Remaining Native diagnostics: 1. New SHA approval is required before using it.

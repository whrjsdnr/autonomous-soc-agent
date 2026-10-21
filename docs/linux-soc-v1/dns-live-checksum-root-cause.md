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

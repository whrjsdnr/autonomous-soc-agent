# Journal uint64 and DNS Live Integration — Release 0.5.16

## Status and preservation

Baseline: `6de36edee458d09696c89c370bde40b5f2d0d407`. Installed release remains 0.5.15.
No installation, OS authentication, BPF operation, Capture or DNS traffic generation
was performed in this remediation step. Campaign `NATIVE_ZEEK_CONTROL_0514` remains
2/3 Native and 2/3 installation slots used. The old ledgers and attempt-2 evidence
are immutable; private SHA preservation and receipts are in
`.git/journal-dns-integration-0516/`.

## Generation root cause and representation

`RunIdentity.generation` is a UUID. Its first eight little-endian bytes become the
nonzero uint64 Native generation. `REQUEST` `<IIQII32s56s`, C `uint64_t`, configuration
map and 80-byte packet event preserve these bits. Python packet/plan models admit
exact integers 1 through 2^64-1 and reject zero, negative, bool, float and overflow.
Zero is reserved for no generation, not a valid ownership lease.

The first signed conversion was `soc_data_counter_query()` in `data.c`: an
`int64_t[10]` held `(int64_t)s->generation`. The historical bit pattern remained
intact, but `recover_native()` decoded `<10q` and rejected `generation < 1`.
For attempt 2, original **12918548832694615738** became **-5528195241014935878**.
No Kernel errno caused this failure; the decoder raised `DATA_COUNTER_QUERY_SCHEMA`,
which `Handoff.close()` generalized to `HANDOFF_JOURNAL_UNVERIFIED`.

The writer now explicitly declares eight signed int64 fields, uint64 generation,
and signed source flags, with an 80-byte static size assertion. Python decodes
`<8qQq`. Signed syscall results and errno semantics are unchanged. No abs(), masks,
zero substitution, lease regeneration or authorization relaxation is used.
The resulting C binary SHA is unchanged: the previous x86 two's-complement output
already contained the correct bytes. Manifest/approval/digest semantics are unchanged.

Checkpoint and audit generation values are serialized in JSON **TEXT**, not bound
as SQLite signed INTEGER or extracted with SQLite numeric JSON operators. Tests
round-trip the real checkpoint/audit path at 2^63-1, 2^63 and 2^64-1, including
identity digests and recovery without automatic reattachment. No schema migration
or rewrite of old evidence is necessary.

## Historical evidence recovery

The modified decoder read attempt 2 in read-only mode. Its expected Native Plan
was reconstructed from the stored preparation plan plus the approved 0.5.15
release, using the existing TCX scope construction; the outer approval was checked
against the recorded handoff approval, rather than trusting the journal header.
The original Journal SHA stayed unchanged. Recovery now exposes the original
cleanup claim and three Map / one Program FD checks with result 0. These checks
mean libbpf object release followed by F_GETFD returning EBADF; individual raw
close() return values were not recorded.

This receipt is new read-only recovery evidence, **not a new Native execution**.
The original runtime Cleanup UNVERIFIED verdict and Audit records were not changed.
New-release whole-session Cleanup VERIFIED still requires approved Native execution.

## DNS visibility investigation

Read-only host inspection found:

- WSL resolver `/etc/resolv.conf`: 10.255.255.254.
- That address is assigned to `lo`; route lookup returns local/lo. This observation
  does not support simply blaming an eth0/lo mismatch.
- systemd-resolved is active with UDP/TCP listeners at 127.0.0.53 and 127.0.0.54.
- Live Zeek filter is `ip or ip6`, with its existing DNS analyzer loaded. No `-C`
  or checksum-ignore setting is added.
- Attempt 2 recorded 24 UDP/53 candidates, zero DNS header/dispatch/query/response
  callbacks and zero DNS adapter events. Raw packet bytes were deliberately not
  retained, so candidate protocol validity and historical rejection cause remain
  UNKNOWN. No evidence proves DoH/DoT, an analyzer defect or packet loss.

Zeek documents that checksum offload can affect local captures, and invalid
transport checksums can prevent protocol analysis. That is a **hypothesis**, not
an established cause here. The existing conn_weird path now exports a bounded
optional `transport_checksum_rejected` count for bad TCP/UDP checksums on port 53.
Old streams omit it as None/NOT_OBSERVED. The new counter does not retain addresses,
payload or question text, and does not prove the port-53 content is DNS or that an
observed bad checksum was caused by offload. A positive count distinguishes a
transport rejection from lack of DNS callbacks without bypassing the check.

References: [Zeek checksum/offload FAQ](https://zeek.org/faq/),
[Zeek 9 connection events](https://docs.zeek.org/en/v9.0.0/scripts/base/bif/event.bif.zeek.html).

## Controlled DNS test plan — not executed

Priority is to reuse the existing local resolver, avoiding a new privileged server,
port-53 binding capability, system DNS edits or external destinations.
`tests/native_dns_live_probe.py` defaults to printing its plan without creating any
socket. Execution requires its exact plan approval and the approved namespace,
rejects Root, uses an exclusive private receipt, and performs no retries.

Proposed separate traffic approval:

- Current namespace net:[4026531833], numeric destination **127.0.0.53:53** only.
- Fixed name **native-0516.localhost.**, QTYPE A.
- One UDP query, TXID 49665 (0xc201), and one TCP query, TXID 49666 (0xc202).
- At most two queries, two seconds per transaction, response bound 4096 bytes.
- No NSS/getaddrinfo/system resolver API, configurable destination/name, internet
  request, external domain or settings changes. No repeated probe on failure.
- Existing systemd-resolved synthesizes `.localhost` records without routing those
  names to the network; require the same resolved service/listeners before approval.
- Only run after the approved Zeek listener and TCX path are ready, within their
  existing 300s/4096-event budget. Stop normally; never increase the event limit.

Source: [systemd-resolved synthetic records and routing](https://www.freedesktop.org/software/systemd/man/249/systemd-resolved.service.html).
This uses an existing local service, so no temporary test server is needed.
Probe source hash: `1b466afcb1fbaf0b5d9a56744640140ef07389342537f5d1bbb9245a2e403f8f`.
Probe plan approval: `0b6c59f501489f67da18e5a7f671b80853542376a8df7a2b0495cd9fbdeb5757`.

The receipt labels CONTROLLED_LOCAL_DNS_TEST and records fixed TXIDs, numeric
endpoints/ephemeral source ports, timestamps, response-header identity and RCODE.
Correlate these identifiers with Zeek metadata/stage counters; do not label all
background DNS as test traffic. The known question is checked in memory; existing
Zeek privacy still excludes question/answer payload and plaintext names from its
stream and audit. TTL, RCODE, matching and missing-response diagnostics come from
the existing analyzer/adapter, not fabricated values.

## Integration and quality

The existing DNS producer, consumer, preprocessing, diagnostics and GUI System
`zeek_summary.dns_visibility.stage_counters` path remain authoritative. No GUI,
TCX program, packet parser, Network14 math or model artifact changes were made.
No new Capture integrity or AI eligibility assertion is added.

Relevant checks:

- 41 core cases: real C fault-injection/FD cleanup, unsigned boundaries, IPC/SQLite,
  DNS diagnostics and no-traffic probe approval/codec/error paths.
- 18 compatibility cases (overlap with core): historical signed writer bytes,
  digest stability, range checks and checkpoint recovery.
- 10 real pinned-Zeek file-only cases: UDP/TCP, duplicate, collision, multiple
  replies, NXDOMAIN, SERVFAIL, unanswered question, bad checksum, privacy parity,
  Counter/CLOSED and Unsupported handling (cases overlap protocol categories).
- One additional real pinned-Zeek test feeds the exact controlled probe wire over
  generated PCAP: two queries, two responses, two matching transactions, QTYPE A,
  RCODE 0 and TTL 60 reach the existing adapter; Counter/CLOSED and cleanup pass.
- Authentication-free whole startup validation on the candidate copy reaches the
  exact human approval boundary with authentication forbidden.
- Ordinary-UID install/update/explicit rollback simulation passes; it is not Root
  installation proof. Changed-file Ruff/Format and Diff checks pass.

All Zeek tests use generated PCAP, network=none/cap-drop=ALL, and no live traffic.
The old object.__new__ handoff test fixture was updated for its existing control
lock; runtime Handoff code was not changed. Initial helper test/preflight mistakes
(TTL tuple expectation and relative SQLite path) were corrected only in tests and
private qualification scripts; their original failure logs remain available.

## Release identity

| Item | SHA256 |
|---|---|
| Manifest | `2e5faaf4dac7381157adcc82b61465316946aa115c501073f25eb95ee9282289` |
| Source bundle | `bddd454656af79a4fac26ce0d4f20cb1d00f3afc2012e7531ce3f7778c271916` |
| Supervisor execution image | `229ada2373d1cabc7a23313e169f1fe65e5d0b72c696d81ec53a4492c2976ca4` |
| TCX object, unchanged | `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06` |

| Installation file | SHA256 | Root mode |
|---|---|---|
| bootstrap | `df183f29c4b73d5cd401e37d51ac4a95a13a756411df7ce21e1f6c5361372ee2` | `0555` |
| broker | `62b2019d09f606e0c59d8b47ca216c23240b725294f1f929b9fed9ae442725ee` | `0555` |
| entry | `8e4ef82c3fe45ae5a414509316a2922898148ed860bb7ebdde9f743509ce4455` | `0555` |
| libnative-tc.so | `138b6a4f7a30db599635a523c7abfbd912758ebee5624f00a7d5fc221c8f09e3` | `0444` |
| manifest.bin | `e09fdb120a62140345c24fc24ebd77dd210d1e088fc80bdd09878e4c8b35dc84` | `0444` |
| pam-policy.conf | `93af76067bf513b4db8c5a9bd606e348ccde334b83e52f7dc71544c9c1f82696` | `0444` |
| tc.bpf.o | `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06` | `0444` |
| release.json | `2e5faaf4dac7381157adcc82b61465316946aa115c501073f25eb95ee9282289` | `0444` |
| release.trust | `2e4978ddb5422806707d63b67ca79eecfd1c8d253c4afddddea64b0b30469ea3` | `0444` |

The nine-file installation remains `/usr/libexec/soc-agent-ebpf`, root:root.
Candidate, Manifest, system dependencies and source bundle were verified.
Current 0.5.15 is intact. An approved update atomically exchanges the complete
verified directory and retains it at `/usr/libexec/.soc-agent-ebpf.rollback-d06cdb224e070df01a3e9a646a3c9aa10514cbebac0f0274fb04c12d2b7ecb39`; that backup path is
currently absent (no collision). Rollback requires quiescence, verification of the
old Manifest and a separately approved atomic exchange. No automatic rollback or
automatic Native retry is scheduled. Older release backups are preserved.

## Next Native approval and verdict

Pending explicit approval of the SHA-pinned 0.5.16 install and one Native session:
net:[4026531833], lo/Ingress, maximum 300s, 4096 metadata, shared Queue32,
privileged task AS256MiB/CPU20s, passive Zeek same namespace/lo with its existing
512MiB/CPU1 profile. Inspector must clear existing Hook ownership conflicts first.
One fresh terminal authentication per application session; no sudo-cache dependency.
The two-query local DNS probe above additionally needs explicit traffic approval.
No campaign slot is reserved or consumed until approved execution starts.

Native DNS query/response counts, Network14 counts and whole Cleanup for this new
release are PENDING, not inferred from file tests or historical decoder recovery.
On execution: preserve first error; collect Counter/CLOSED, ring/worker/audit drain,
owned Link and Map/Program FD evidence, Zeek exit/removal, final Inspector inventory
and audit chains, including any partial collector failure.

Native AI, DNS9 and operational promotion remain BLOCKED.

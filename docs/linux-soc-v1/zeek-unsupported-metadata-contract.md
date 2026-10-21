# Zeek unsupported metadata contract — Release 0.5.15 candidate

## Native baseline and root cause

Baseline `d6e4fdb`. The immutable private evidence is
`.git/native-zeek-control-campaign-0514/attempt-1/verification.json`.
Release 0.5.14 delivered 4,096 TCX packets to Network14, drained successfully and
removed its owned resources. Zeek stopped after stream sequence 2,976 with
`STREAM_SCHEMA`, `Packet.model_validate/summary_allowlist`, ValidationError. This
is a Python schema rejection, not an OS errno or Kernel Verifier failure.

The fixed Zeek `network14.zeek` producer can emit `kind=UNSUPPORTED` with missing
parsed IP/transport fields. `live.zeek` previously wrapped every such row as
`packet`, while the consumer required the canonical TCP/UDP Packet model. The
observed literal error identifies the `kind` incompatibility; missing parsed
fields are also incompatible. The historical diagnostic omitted validation
locations and rejected input, so the specific length-bound field and exact packet
protocol remain UNKNOWN. A synthetic 70,000-byte wire / 65,535-byte captured
UNSUPPORTED record reproduces the old field failures; it is not a reconstruction
of the Native input. New diagnostics retain allowlisted field names and error
types without input values or secret text.

## Shared wire and type contract

The outer envelope remains `{sequence,kind,data}`. The existing `packet` spelling
is preserved for valid supported legacy streams. All new source bytes are bound
to the Zeek bundle, release and session approval; mixed versions are not silently
accepted as an approved release.

| Wire kind | Domain type | Processing |
| --- | --- | --- |
| ready | SESSION_READY | Existing authenticated/session-bound startup |
| packet | SUPPORTED_PACKET | Unchanged strict TCP/UDP Packet; Network14 |
| unsupported | UNSUPPORTED_PACKET | Typed diagnostic metadata; no Feature/DNS input |
| network | NETWORK_EVENT | Existing Zeek connection adapter |
| dns | DNS_EVENT | Existing DNS analyzer and adapter |
| counter | COUNTER | Independent final packet/event/NetStats snapshot |
| closed | CLOSED | Exact final sequence, byte and counter reconciliation |

Unsupported metadata preserves original observation sequence, timestamps, raw
wire/captured lengths and any actually parsed IP/transport metadata. Raw pcap
lengths use bounded uint32 fields in this diagnostic model; canonical Packet/IP
bounds are not widened. Captured length exceeding wire length, inconsistent
partial identities, unexpected fields/payload, bad types and false unsupported
classification remain fatal. Oversized/truncated parsed TCP/UDP metadata also
uses the diagnostic path without changing its original `kind` value.

No new packet queue is introduced: stream/output/event/packet budgets remain
bounded. The stream file retains validated metadata only. No payload, QNAME or
answer retention is added.

## Sequence, counters and eligibility

Global envelope sequence and per-packet observation sequence remain distinct.
Both supported and unsupported observations consume the 4,096 packet budget.
Later supported packets keep their original observation numbers. A Zeek-only
observation cursor excludes unsupported records without adding a Flow window,
packet, byte, timestamp or DNS event. The shared TCX/Network14 assembler and
feature calculation are unchanged.

Diagnostics separately expose received envelopes, packet observations, supported,
unsupported, network, DNS, invalid, duplicate and sequence-gap counts, Counter
Snapshot and CLOSED. Unsupported count is not a packet-loss count. Invalid,
replayed, missing-sequence or post-counter records remain fatal.

COUNTER and CLOSED each reserve one envelope and 2KiB within the existing 8MiB/
8,192-envelope bound. CLOSED must match its preceding independent snapshot,
actual supported/unsupported split, totals, sequence and exact original byte
count. Legacy CLOSED without split fields remains compatible only for streams
without unsupported observations or new Counter frames. Optional new fields are
omitted from legacy serialization to preserve historical recovery digests.

Unsupported observations degrade completeness and do not attest capture
integrity. Native capture remains UNVERIFIED and Native AI, DNS9 and operational
promotion remain BLOCKED. Offline inference is not started for an unsupported
mixed stream. DNS visibility is evaluated independently from the existing Zeek
analyzer's actual Query/Response/matching and terminal evidence; zero DNS events
are never automatically promoted to a successful capture.

## Verification

Focused tests cover TCP/UDP, valid/malformed unsupported metadata, exclusion from
Network14 and DNS, original sequence preservation, duplicate/gap failures,
Counter tampering, post-counter data, CLOSED, legacy evidence and downstream
preprocessing/attestation contracts. No model, GUI performance or full regression
suite is rerun.

An actual pinned Zeek 9.0.0 container was tested with a generated PCAP file only:
`--network=none`, `--cap-drop=ALL`, ordinary UID, no live interface, no sudo or host
capability change. Seven observations produced six supported and one unsupported
record, plus DNS Query/Response and matching, independent Counter and CLOSED.
Only six supported records entered Flow windows. The container exited and was
removed. Separate offline tests exercise the 4,096 observation budget and
reserved terminal envelopes. These are OFFLINE results, not Native success.

Private build/test/release receipts are under `.git/zeek-unsupported-remediation-0515/`.
A pytest collection collision between existing equal-named test modules was
resolved with `--import-mode=importlib`; no caches or user files were deleted.

## Native approval and remaining blockers

Installed 0.5.14 and its evidence remain intact. Candidate installation uses the
existing atomic retained-release/rollback contract. No Root installation,
authentication, Kernel resource query, BPF load, TCX attach or live capture is
performed during this remediation. The campaign remains Native 1/3 and Root
installation 1/3; no new slot is reserved.

A new explicit SHA-bound approval is required for one 0.5.15 installation/run:
`net:[4026531833]`, lo/Ingress, 300s, 4,096 metadata, queue32, privileged task
256MiB/CPU20s, passive Zeek in the same namespace/lo with its unchanged 512MiB/
CPU1 profile. Inspector pre/post checks and ownership-based cleanup remain
mandatory. No traffic generation or automatic retry is authorized. Native
UNSUPPORTED counts, DNS visibility and complete stream termination remain
PENDING until that run. TCX object and successful Control/Cleanup code are unchanged.

## Candidate identity

| Item | SHA256 |
| --- | --- |
| Manifest | `d06cdb224e070df01a3e9a646a3c9aa10514cbebac0f0274fb04c12d2b7ecb39` |
| Bundle | `65731055865698e49474e7899ba76c329c695ca50690337f11ad54b2e5a0b86b` |
| Execution image | `3251e3b3b4dc44328fe6313254e9f39642c223a966624b5e9717e05be9b6f99a` |
| TCX object | `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06` |

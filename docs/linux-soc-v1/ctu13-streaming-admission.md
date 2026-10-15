# CTU-13 streaming and admission: SOC readiness

2026-10-15, WSL2 Ubuntu. SOC baseline `ad2a56bd9e8cc43e3b4cebacd41eb1a994fdda17`;
ML baseline `8567c623b61fd29b16627cc101e457b1a7b12f06`. Overall **PARTIAL**.
No SOC application source is changed; this report records ML offline results and gates.

## Prior real-prefix evidence and new work

The historical 142032 excluded/incomplete segments are separated into:
139213 RESOURCE_EVICTION, 904 PACKET_LIMIT, 1915 INCOMPLETE_CAPTURE. Another 323
ACTIVE_TIMEOUT and 10046 IDLE_TIMEOUT segments bring total segments to 152401.
These are prior observations, not newly decoded packets or a fresh performance run.
The original coarse eviction count cannot be split reliably into flow-count versus
packet-buffer pressure. No real-corpus loss-reduction percentage is claimed.

ML `Flows` now compacts repeated packet metadata without changing its add/finish API
or Producer inputs. The original Packet records are reconstructed exactly at closure.
Default limits remain 20000 active flows, 100000 packets, 4096 packets/segment and
30/120-second idle/active boundaries. A 64 MiB retained-state charge budget is additional;
it is not a hard total-process RSS limit. MAX_ACTIVE_FLOWS, MAX_BUFFERED_PACKETS and
STATE_BYTE_BUDGET reasons, explicit capture gaps, duplicate active event detection and
capture-session validation are separate. Stable flow digests remain consumer receipt keys.
No new persistent queue, collector, model, GUI or SOC runtime is introduced.

## Fresh fixture comparison

Baseline and Candidate ran on this WSL host in fresh unprivileged processes using the
same 80000 lazily generated FIXTURE packets, 500 flows, packet/active budgets,
unchanged producer and evaluation. Input and output/Feature digests exactly matched.
The additional candidate memory charge limit did not fire.

| Metric | Baseline | Candidate |
|---|---:|---:|
| Processed packets | 80000 | 80000 |
| Created / completed lifecycle segments | 500 / 500 | 500 / 500 |
| Evicted / incomplete / excluded | 0 / 0 / 0 | 0 / 0 / 0 |
| Peak RSS bytes | 56811520 | 50499584 |
| Processing seconds | 2.187857 | 3.214735 |
| Packets/second | 36565.46 | 24885.41 |
| Closed segments/second | 228.53 | 155.53 |

RSS improved **11.11%**; time increased **46.94%** in this single matched fixture run.
It is not an overall performance PASS, an operational improvement claim or permission
to promote a model/strategy. Packet reconstruction adds CPU and transient memory;
finish still collects output tuples. Scheduling/cache effects were not controlled.
Real-PCAP before/after performance and eviction reductions remain unmeasured.

## No new expansion or raw acquisition

New dataset downloads **0**, live capture **0**, actual raw bytes decompressed **0**.
The old 512 MiB budget was exhausted (with the disclosed historical rejected guard byte);
this task grants no additional allowance. Original compressed/label SHA256 identities
were re-read and match. Full archive EOF/CRC and capture drops/gaps remain UNKNOWN;
FULL_STREAM_VERIFIED is not issued. New PCAPNG timestamp tests use tiny synthetic blocks.

Existing raw directory:
ML `data/raw/acquisition/ctu13-s07-header-pilot-v1` (ignored; unchanged).
The preserved original SHA values are recorded in the earlier SOC
[operational readiness report](ctu13-s07-operational-readiness.md).
No raw traffic, label originals or generated large dataset is committed.

## Label clock, direction and admission

Official metadata was reviewed, independently of match counts:

- [Scenario 7 README](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/README.html)
  documents capture timing in CEST; its older Aug 10 narrative is not mixed with Aug 16.
- [Published ra.conf](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/detailed-bidirectional-flow-labels/ra.conf)
  specifies microsecond wall-clock formatting but no RA_TZ.
- [Argus manual](https://qosient.com/argus/man/man5/rarc.5.pdf) allows environment or
  command overrides. Capture timezone alone does not prove label-export timezone.
- [Published argus.conf](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/detailed-bidirectional-flow-labels/argus.conf)
  documents bidirectional five-tuples and a 3600-second status interval. It is not
  attestation of executed binary/configuration; first-observed direction is not initiator.

**TIMEZONE_UNVERIFIED** remains. No offset search or feature/direction policy change
was used. Background and inbound-to label classes remain UNKNOWN.

New read-only verification checked both originals, all 237 saved candidate vectors,
external row references and digests. There is no full endpoint/packet snapshot for a
new raw-flow replay, so they remain CANDIDATE_MATCH. Verified matches **0**, admitted
samples **0**, Pilot Admission **BLOCKED**. A caller's clock_verified boolean cannot
promote a candidate. Duplicate/conflicting labels remain ambiguous; gaps and incomplete
flows are excluded. A single capture cannot furnish independent holdout.

## Contract and security boundary

Network Producer v1.0.0 and v1.1.0 source, Network14 order/float32 arithmetic and contract
digests are preserved. The new state container reproduces original Packet values and
therefore unchanged source/feature digests on compared fixtures. OFFLINE_PCAP,
NATIVE_AF_PACKET and FIXTURE origins are separate. No inference input gate is unlocked.
Network Quality, Network Edge and DNS Security retain NOT_INFERABLE / BLOCKED;
Finding promotion is blocked and WRITE_DENIED remains. Synthetic v2 and operational
provenance v3 are unchanged. There is no new training, artifact, policy, approval,
privilege, firewall, account, NIC, DNS setting or live Runtime change.

Owned-child fixture crash/restart tests reproduce stable receipts, with no partial
result emitted before crash. The flow table is not a durable checkpoint store. This
is not exactly-once capture or real-corpus stream restart verification. Existing SOC
queue/runtime recovery and governance paths are covered by fresh regression tests.

## Remaining decisions

1. Authoritative label-export TZ/environment/argv/revision is still needed.
2. Fresh real-PCAP performance/restart verification needs explicit new expansion budget.
3. Review CPU tradeoff and bounded flush design before wider offline use; loss reduction
   is not established by compact storage under unchanged packet count limits.
4. Obtain independent labeled sessions/holdout before admission, training or integration.
5. Physical Linux NIC, timestamp/drop/source and operational producer parity remain future work.

ML detail and sanitized measurements: `docs/ctu13-s07-streaming-admission.md` and
`docs/ctu13-s07-streaming-evidence.json` in the ML repository.

## Fresh verification ledger and selected scope

Each row is a separate execution; counts overlap and must not be added together.
No historical tests are substituted for these runs.

| Verification | Result |
|---|---|
| New streaming/binding/PCAPNG/admission/crash cases | 34 tests included in final suites |
| ML full related working-tree suite | 436 passed, 5.01 s |
| ML HEAD + selected files, independent export | 429 passed, 4.88 s |
| SOC runtime/capture/queue/GUI/governance/security suite | 768 passed, 307.15 s |
| Same SOC suite from independent HEAD export | 768 passed, 303.12 s |
| Independent export benchmark CLI | Same input/output digests, budgets, packets and closures |
| Final Ruff src tests, both repositories | PASS |
| ML independent export Ruff src tests benchmarks | PASS |
| SOC whole-tree format check | PASS, 884 files formatted |
| ML selected Python format check | PASS, 5 files formatted |
| ML whole-tree format check | 24 pre-existing files require formatting; excluded |
| Working/staged Git diff whitespace checks | PASS |

Seven extra ML working-tree tests come from the preserved user-modified test_offline.py;
they are excluded from this commit. Both baseline and selected export pass without
uncommitted parser/label/pilot/download fixes, legacy DNS sources or Reliability Replay.
The SOC guard blocked one intentional test socket per suite; no capture/traffic occurred.
Live LLM calls were disabled. No dependencies were installed.

The benchmark CLI was also executed from the independent export. That separate run used
56770560 / 50388992 peak RSS bytes and 1.957861 / 3.214428 seconds for baseline/candidate.
Its semantic digests match the primary run; timings are not averaged or represented as
identical. Tests include only owned fixture-child crash/exit and immutable replay, not
new privileged probes or real-corpus decompression.

Existing model/feature/label artifacts (seven reviewed hashes), both Producer source
versions and raw/candidate identities are unchanged. labels.py received an external
pairwise/import adjustment during this task; it was retained and excluded. Other
pre-existing user files were not overwritten. No index items predated this task.

Selected files for independent export and commit:

- ML src/ml/ctu13/flows.py
- ML src/ml/ctu13/admission.py
- ML benchmarks/ctu13_flow_benchmark.py
- ML benchmarks/fixtures/flows_8567c62.py (byte-pinned original baseline only)
- ML tests/ctu13/test_streaming.py
- ML docs/ctu13-s07-streaming-admission.md
- ML docs/ctu13-s07-streaming-evidence.json
- SOC docs/linux-soc-v1/ctu13-streaming-admission.md

Raw PCAP/labels and generated data are excluded. Successful source/test commits certify
fixture behavior and this BLOCKED admission assessment; they do not certify full-stream
integrity, label timezones, operational performance, producer parity or a new model.

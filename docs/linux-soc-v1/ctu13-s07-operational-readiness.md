# CTU-13 Scenario 7: SOC operational readiness

2026-10-15, WSL2 Ubuntu. SOC baseline `d68d0a9e0682ad69d5751d20ffddbc11dc505b7b`;
ML baseline `2b23a50fa79a57af20ec98bd9a8748bbd4dfa825`. Overall **PARTIAL**.
Only this SOC report is added; runtime, GUI, queue, provenance and model gates are unchanged.

## Actual acquisition and partial inspection

The approved two official CTU objects were acquired into the ML repository's ignored
`data/raw/acquisition/ctu13-s07-header-pilot-v1` directory, with no retries or overwrites.
Combined download: 127295508 bytes, within 256 MiB. Per-file hard timeout was 300 seconds.

| File | Bytes | SHA256 |
|---|---:|---|
| Header archive | 111664996 | `246e43ea206de437c1bf32fb07f865a8971c86dda0fd95e6597985d9f9c85577` |
| Bidirectional labels | 15630512 | `df0b5338190b967bd340a0d6c1bb3c34d1bbfb4b7ffa764c2dd26f77f1a26680` |

These are locally measured identities; publisher SHA256 is UNKNOWN. Label Content-Type
was absent, not invented. Exact URLs, GET timings, actual label schema, sanitized
arithmetic reference and exclusions are in ML `docs/ctu13-s07-pilot.md` and
`docs/ctu13-s07-evidence.json`; no raw traffic or label originals are committed.

The `.pcap.bz2` contains **PCAPNG**, not classic PCAP. Inspection hit its bounded
expansion limit before EOF. Prefix results: **6330279 raw packets**, **6323107 parsed
TCP/UDP packets**, **152401 flow segments**. Full archive integrity and total expanded
size remain BLOCKED/UNKNOWN. Real prefix has IPv4 only; IPv6 is fixture-tested.
No new live AF_PACKET capture or DNS traffic was generated.

The old ML bzip2 limiter decoded one rejected guard byte past the remaining limit.
Including two 64 KiB preflights, decoder output could reach **512 MiB + 1 byte**.
It was not yielded or stored, but the strict decoder-total requirement did not pass.
The limiter is corrected and a counting-decoder regression passes; the corpus was not
expanded again. This is disclosed as a failed original boundary check, not erased by tests.

## Binding, producer and admission

External labels contain 114077 flow rows. Valid TCP/UDP classification counts:
1668 From-Normal, 63 From-Botnet and 110369 UNKNOWN. Unsupported protocols: 1941;
invalid TCP/UDP rows: 36. Background and inbound-to labels stay UNKNOWN.

UTC+02:00 is an explicit, unverified clock hypothesis. Exact tuple/session/interval
matching yielded 237 unique NORMAL diagnostic candidates, 9813 UNKNOWN-label matches,
319 unmatched and zero observed ambiguous segments. Another 142032 segments were
incomplete/resource-excluded (including 139213 buffer evictions). Independent
verified matched ratio is **0%**, admitted samples **0**. Candidate ratio
237/152401 is a diagnostic statistic, not verified label admission.

ML adds a separate `ml.verified_producers.network_v1_1` contract with OFFLINE_PCAP,
NATIVE_AF_PACKET and FIXTURE origins. Old v1.0.0 and artifacts are preserved. Feature
contract remains Network14 v1.0.0; producer version is 1.1.0. It measures IP lengths,
first-observed bidirectional counts/bytes, duration, population length statistics,
SYN/FIN/RST and IAT; it does not fabricate payload, collector drops or legacy Top40.

An independent 60-digit Decimal calculation exactly reproduces float32 features for
five sanitized observed packets. This is **arithmetic reference validation only**.
Synthetic hand calculations and actual metadata references do not prove
training-to-live parity. Argus segmentation, capture completeness, independent labels
and operational-source attestation remain separate requirements.

237 feature candidate rows were generated privately, all `training_admitted: false`.
The entire capture is one split group; independent train/validation/test/holdout is
unavailable. Pilot Admission and Retraining Readiness remain **BLOCKED**.
No model training, new model artifact or operational inference occurred.

## Existing SOC connection points

Future path, contingent on reviewed compatible model and full admission:

```text
Existing AF_PACKET PacketObservation + SourceIdentity + kernel timestamp
 → existing persistent queue / source store
 → bounded, complete bidirectional packet metadata
 → reviewed Network Producer v1.1.0-compatible input
 → future separately trained and artifact-bound model
 → existing external adapter / advisory context
 → evidence-validated read-only investigation
 → deterministic policy / explicit human approval
```

The existing `network_capture.flows` diagnostic summary uses frame-length aggregates
and incomplete/diagnostic semantics. It must not be relabeled as this producer's
IP-length packet input. Offline PCAP timestamps are recorded file timestamps, not
`KERNEL_SO_TIMESTAMPNS`. `CaptureConfig` does not accept OFFLINE_PCAP as a live origin;
synthetic v2 cannot be used to disguise public PCAP. Operational provenance v3 and
source/evidence/incident binding are unchanged.

| Model | Operational input | Inference | Finding promotion |
|---|---|---|---|
| Network Quality | NOT_INFERABLE | BLOCKED | BLOCKED |
| Network Edge | NOT_INFERABLE | BLOCKED | BLOCKED |
| DNS Security | NOT_INFERABLE | BLOCKED | BLOCKED |

Collection/feature diagnostics do not confer execution authority. Existing GUI status
continues to report closed gates; no inference is triggered by queries. No model output
was promoted to an observed security fact. WRITE_DENIED, Policy/Approval, synthetic v2
and operational v3 remain intact. No SOC runtime process, capabilities, firewall,
account, DNS, NIC or model artifact was changed.

## Remaining blockers and decisions

1. Full archive completion and corrected real-corpus bound verification require a fresh,
   explicitly approved expansion budget; this task does not silently raise the limit.
2. Obtain independent Argus clock/revision/configuration and label interval provenance.
3. Address bounded-buffer eviction using a separately reviewed aggregation design;
   do not call excluded prefixes complete flows or claim capture drop=0.
4. Obtain additional independently labeled sessions/external holdout before training.
5. Train/package a new compatible model only under separate approval. Existing Top40
   and DNS9 are still incompatible with this new Network14 producer contract.
6. Physical Linux NIC/source/timestamp/drop/operational parity remains future validation.

See the execution ledger below for tests and independent Git-export verification.

## Final execution ledger

Results are separate invocations and **must not be added together**:

| Invocation | Result |
|---|---|
| ML new CTU + existing acquisition/producer tests (working tree) | 199 passed; includes 67 CTU tests |
| ML broad producer/acquisition/scripts/three existing packages (working tree) | 395 passed, 6.49 s |
| ML broad regression from HEAD + only the 10 selected ML files | 395 passed, 4.19 s |
| SOC capture/monitor/operational/external/runtime/GUI/approval/execution/queue (working tree) | 768 passed, 291.95 s |
| Same SOC regression from clean HEAD export without user changes or Replay | 768 passed, 266.16 s |
| SOC Ruff check / whole-tree format check | PASS / 882 files already formatted |
| ML Ruff check src tests / selected Python files format check | PASS / 8 files already formatted |
| ML whole-tree format check | Existing debt: 24 files need formatting; unchanged and excluded |
| Both git diff --check | PASS |

The SOC test guard blocked one intentional test socket attempt per invocation;
no new native capture or test traffic was generated. Live LLM was disabled.
No tests require the downloaded archive. The actual-corpus results above are a separate,
partial, bounded inspection; fixture passes do not cure its failed decoder-total check,
missing EOF/clock provenance or independent holdout.

Independent exports use each baseline HEAD plus only selected task files, excluding
uncommitted Reliability Replay, the eight SOC user-modified files and the untracked
legacy DNS package. ML tests use existing ML dependencies and the existing SOC pytest
installation; source imports resolve from the exported src/packages directories.
No dependencies or environments were installed or changed. Export tests neither download
nor decompress actual raw data. All 1031 pre-existing SOC files and 464 unmodified ML
files matched the baseline SHA inventory; only the selected existing ML storage helper
changed. Seven legacy artifact/feature/label identities match their prior reviewed hashes.

Selected paths:

- ML: `src/ml/ctu13/{__init__,pcap,labels,flows,pilot}.py`
- ML: `src/ml/verified_producers/network_v1_1.py`
- ML: `src/ml/raw_acquisition/storage.py`
- ML: `tests/ctu13/test_offline.py`
- ML: `docs/ctu13-s07-pilot.md`, `docs/ctu13-s07-evidence.json`
- SOC: `docs/linux-soc-v1/ctu13-s07-operational-readiness.md`

No original PCAP/labels, generated dataset, model binary, Replay code or unrelated user
change belongs to these commits. Successful commit/export checks certify the tested
code and the accuracy of this partial report, not dataset admission or operational AI
readiness. The original one-byte decoder overrun is explicitly retained as a failed
sub-check; full real-corpus validation needs fresh authorization.

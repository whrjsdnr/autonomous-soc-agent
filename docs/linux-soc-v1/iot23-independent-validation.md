# IoT-23 Capture3 independent validation readiness

2026-10-15, WSL2 Ubuntu. SOC baseline `78e1f8798fa3573f0623add902441691d235c006`;
ML baseline `484f9ac62b6d597113ebf44016410100a81a2f76`.

**Overall PARTIAL. Download PASS; Raw/Label Binding PARTIAL; Producer compatibility
PASS; Independent Validation BLOCKED; Network Quality BLOCKED; Network Edge BLOCKED.**
Admitted training samples0. No model training, native model inference, artifact change,
new capture, OS security response or operational gate unlock occurred.

## 1. Acquisition, identity and actual source

Exactly the approved original PCAP +Zeek files were downloaded from
[official capture3-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-3-1/),
without selecting its separate small `test.pcap`. Actual total **82303309 bytes**, cap 256 MiB,
per-file300s, retry0, expansion0, redirects denied and no overwrite. Both sizes matched
fresh HEAD and the previous plan. Existing bounded transfer/atomic finalization and
partial cleanup were reused; raw files remain ignored under the private ML acquisition root.

| File | Actual bytes | Local SHA256 | Seconds |
|---|---:|---|---:|
| 2018-05-21_capture.pcap | 57919772 | `c674dc0c8d584fa66e6f00c60df973c5fbacad551c850a76d75ec9952641d00b` | 21.757 |
| conn.log.labeled | 24383537 | `9851009bbca03e15089fa1a356dd4b5eee4a98161a51703626058a0b507f50d0` | 5.493 |

Publisher per-file SHA UNKNOWN; local hashes do not become publisher attestations.
URLs/timestamps/HTTP200/identity metadata and all digests are in ML
`docs/iot23-capture3-validation-evidence.json`; no payload, raw labels or credential is committed.

PCAP is classic2.4, Ethernet1, little-endian, microsecond clock, snaplen262144.
Full-stream SHA equals acquisition SHA. Raw packets **496959**, parsed IPv4 TCP/UDP
**489567** (TCP488060 /UDP1507). IPv6 observed0, snaplen truncation observed0;
unsupported link5658 /transport1734 excluded without invented fields.
Existing Flow segments **86378**, including one active timeout, no resource eviction.
Capture drop/gap provenance stays UNKNOWN; full file integrity is not loss-free capture proof.

## 2. Source labels, binding and Producer

Actual extended Zeek TSV has23columns, triple-space analyst suffix and validated types.
Source Zeek connections156103: **Benign4536 /Malicious151567 /Unknown0**.
Detailed malicious scan145597 /Attack5962 /C&C8. Protocol rowsTCP154158 /UDP738 /ICMP1207;
unsupported ICMP stays outside Network14. Full-row and UID duplicates0; duration unset73944.
Missing duration/counters/class labels are never inferred normal or imputed zero.

| Binding status, Flow unit | Strict baseline | Unchanged recovery |
|---|---:|---:|
|VERIFIED_MATCH|3386|76320|
|CANDIDATE_MATCH|82210|10044|
|AMBIGUOUS|0|0|
|UNMATCHED|1|1|
|EXCLUDED|781|13|

Verified **Benign2927 /Malicious73393**; Candidate Benign539 /Malicious9505;
Ambiguous Malicious0, Excluded Malicious0, Excluded Benign13, unknown unmatched1.
These are Flow-state counts; they do not imply no malicious packet was excluded upstream.
All existing verified matches are preserved, with72934 new verified associations.
Mappings72166 exact two-label partitions plus768 exact singleton records retain every
reference/cardinality. No ambiguous many-to-one mapping is disguised as one-to-one.

Frozen policy digest `304e76f801004bc4a5b372cb3dc088d3dc090ab1da3ebede8b2915dfdbaad893` and source lock remain unchanged;
no 3-1-specific threshold/timing/counter adjustment occurred. Independent byte counters
and exact SYN partition checks are reused; ACK/FIN/RST/data/reuse/quality failures stay
outside that promotion rule. Zeek UID is not independently observed in PCAP.

The unchanged Producer1.1.0 produces **76320 finite ordered float32 Feature14 vectors**,
OFFLINE_PCAP with source/config/feature digests. New actual reference samples are9-packet
Benign and4-packet source-labeled Malicious, independently checked by arithmetic/counters.
Existing Golden Pairs remain intact; operational native/offline parity is NOT_VERIFIED.
No legacy Top40 model/Scaler is adapted or overwritten.

## 3. Independence and holdout admission

Fixed proposed roles remain train8-1 /validation candidate3-1 /diagnostic20-1 /
**test34-1 SEALED**. The old train8/diagnostic20 audit is freshly reproduced unchanged.
Test34 bytes are hash-checked only: no new test parsing, role reassignment, training,
model/feature selection or threshold tuning occurs.

Train8 and candidate3 have zero exact raw-flow fingerprint overlap and zero observed
origin-address hash overlap. These checks do not prove independent physical devices,
campaigns or absence of retimed/copied data. Unique physical IDs remain unresolved;
Muhstik versus Hakai names are insufficient campaign-independence proof.

Actual PCAP/label epoch ranges agree without shifts:3-1 spans May19–21,2018;
train8 starts July31. No temporal overlap, but **validation predates training**, failing
the current forward-time split rule. A retrospective protocol would require explicit
review, not an automatic waiver. No split is rearranged for favorable results.
Capture quality remains UNKNOWN. Thus class presence and subset binding PASS do not
satisfy independent validation; both network models and dataset admission remain BLOCKED.
No model performance metrics or generic Linux-server suitability are claimed.

## 4. Security, fresh tests and reproducibility

No SOC source/runtime/collector/queue/GUI implementation was modified. Existing source,
provenance, external advisory, Finding/investigation and Policy/Approval boundaries remain.
**NOT_INFERABLE / operational inference and Finding promotion BLOCKED /
DIAGNOSTIC_ONLY / WRITE_DENIED** are preserved. Syntheticv2 and OperationalProvenancev3
semantics, all previous raw data and seven reviewed model/scaler/feature identities remain.

ML focused IoT23 run119 passed includes19 new Capture3 tests. Broad working 597 passed;
independent Git Export 590 passed; seven pre-existing user CTU tests explain the difference.
Counts are separate runs and not summed. Complete saved-byte validation manifests and
all binding/reference/feature digests match between working source and independent Export.
Only approved external raw directories are shared, with no raw content copied into Git.

SOC working regression **768 passed** (289.61s); independent SOC Export
**768 passed** (276.31s). Each guarded run blocked one intentional fixture socket attempt. Live LLM is disabled;
socket guard denies new AF_PACKET/IPv4/IPv6 sockets during regression. Ruff src/tests,
whole SOC Format and Diff checks PASS; ML owned Format PASS with 24 pre-existing whole-format
violations preserved. Staged and independently tested source SHAs are checked before commit.

## 5. Reports, files and next decision

Full method, exclusions, exact download plan, safe reproduction and changed ML file list:
[ML validation report](https://github.com/whrjsdnr/ML_teamproject/blob/main/docs/iot23-capture3-validation.md).
SOC change is this report only. Raw sources and large diagnostic Flow JSONL stay ignored.

Resolve physical device/campaign grouping and capture quality, and explicitly decide a
chronological redesign or retrospective validation protocol before a new admission review.
Do not promote source-labeled SYN traffic into observed completed attacks or operational
accuracy. No training, new capture, OS security response or gate unlock follows automatically.
Physical Linux-server validation remains future work.

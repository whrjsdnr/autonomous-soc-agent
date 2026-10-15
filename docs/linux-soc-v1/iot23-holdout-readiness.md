# IoT-23 binding recovery and holdout readiness

2026-10-15, WSL2 Ubuntu. SOC baseline `d07a796b2923f4e7b83bd56568feba04e965cd0f`;
ML baseline `52a01ae6de0d6433d2e0825c69ec58fed1ffc3f7`.

**Overall PARTIAL. Network Quality: BLOCKED. Network Edge: BLOCKED.**
Narrow offline TCP associations are recovered; independent retraining admission is not
granted. New raw downloads/capture, model training/inference, artifact changes, Producer
Feature contracts, OS security response and operational gates were not changed.

## Original distribution and current result

All six raw SHA256s match the previous acquisition receipt. Existing PCAPs and analyst Zeek
labels were read locally; no new PCAP or label body was downloaded. Unknown labels0.

| Capture | Zeek rows | Benign | Malicious | Original Flow segments | New verified Benign / Malicious |
|---|---:|---:|---:|---:|---:|
|8-1, train|10403|2181|8222|4237|2162 /2056|
|20-1, validation|3209|3193|16|3921|2300 /4|
|34-1, sealed regression|23145|1923|21222|7848|981 /3314|

Strict baseline freshly reproduced Benign/Malicious2162/0,2300/0,964/902. Original Flow
populations and features are unchanged; all prior verified bindings remain verified.
New verified counts2056,4,2429; total verified10817. **Admitted samples0**.
This is association recovery, not improved detection precision/recall or a completed attack claim.

## Root cause and independent evidence

8-1's SYN sequence repeats across multiple Zeek connection records within a single
30s-idle/120s-active producer Flow. A typical six-packet Flow maps exactly to external
counter groups3+1+1+1, not to one three-packet record. A failed duration predicate alone
did not prove the previous final-ACK explanation. 20-1 has similar SYN windows, plus
long/missed-byte connections that remain excluded. Its four recovered malicious windows
are failed SYN attempts labeled malicious by the source, not validated Torii payload traffic.

[Zeek primary connection semantics](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html)
clarify ts/counters and nonproductive trailing TCP packets;
[current TCP timeout definitions](https://docs.zeek.org/en/current/scripts/base/init-bare.zeek.html#id-tcp_attempt_delay)
are explanatory, not proof of the historical export config. No timeout default is assumed.

Three additive ML modules provide explicit offline auditing: independent PCAP/header byte
reference, exact SYN partition validator and bounded audit runner. They reuse existing
Flow/Producer/label parsing and do not replace SOC components or the legacy strict binder.
The independent byte decoder does not call the production packet parser/binder; row-first
wire counters independently check every disjoint label partition. Representative normal
TCP, malicious TCP, UDP, ACK-only, repeated sequence, FIN/RST metadata are recorded without
payload/address/absolute sequence/UID values. Actual ambiguous/sequence-changing reuse
was not observed inside these windows; those paths have explicit fixture tests only.

New promotion requires SYN-only, same sequence, zero ACK/payload, full packets, unique
source/session/timestamps, exact interval/point membership and directional counters,
zero missed_bytes, concordant known labels and complete disjoint coverage. Missing
duration is only an independently counted exact singleton; no duration is invented.
Every external reference/cardinality is retained; N connections to1producer Flow is
never disguised as1:1. No deduplication, dropped packets, tolerance fitting or label guessing.
ACK/FIN/RST/data/quality/ambiguity/reuse mismatches remain candidates/excluded.

Policy digest `304e76f801004bc4a5b372cb3dc088d3dc090ab1da3ebede8b2915dfdbaad893`.
Source/policy lock `cf6cba6aa1af76b5fafe8d2d6ee3d8d80e29b3286b9528d99f9e947640a17f7c` freezes code and train/validation result
before34-1 regression; changed/missing source lock is rejected. This is reproducibility
metadata, not new execution/approval authority. Test34-1 stays out of training, rule/model
selection, feature selection and threshold tuning. No model was trained.

## Holdout and admission

Train/validation class presence now PASS. Validation4malicious SYN windows are still
very limited and correlated. Physical device/campaign independence is unverified:
20-1 metadata saysRPi-01,34-1 saysRPi02,8-1 lacks a unique device identity. Different
addresses or family names do not establish independence; prior address overlap is retained.
Capture loss/gap is UNKNOWN despite zero missed_bytes on accepted external records.
Raw integrity, subset binding, Producer/Golden arithmetic and manifest checks pass;
**independence and capture-quality gates do not**. No train/validation/test roles change.

[ML report](https://github.com/whrjsdnr/ML_teamproject/blob/main/docs/iot23-binding-recovery.md) and ML
`docs/iot23-binding-recovery-evidence.json` contain complete status/failure tables,
raw SHAs, samples, locks, proof digests and fresh results. Local file digests are
not signed publisher attestations or a model promotion license.

## Additional candidates: two, no raw acquisition

[Official catalog](https://www.stratosphereips.org/datasets-iot23) and direct metadata only:

| Candidate | Original PCAP + Zeek HEAD bytes | Published labels | Decision |
|---|---:|---|---|
|3-1 Muhstik|57919772 +24383537 =82303309 (~78.49MiB)|Benign4536; non-benign151567|Preferred future acquisition candidate; not admitted |
|60-1 Gafgyt|22028429274 +467559811 =22495989085 (~20.95GiB)|Benign2476; non-benign3578552|Blocked for next bounded stage |

3-1 exact originals are `2018-05-21_capture.pcap` and `bro/conn.log.labeled` under
[official capture3-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-3-1/).
It predates the current training capture, so any future split must explicitly address
chronology rather than claim a later independent validation day. Device ID, actual
format/binding/Feature14 compatibility/capture quality remain unverified.
60-1 exceeds current transport/reference/label resource bounds and reportsRPi-02,
a potential shared device alias with test34-1RPi02. No limits are raised or raw files fetched.
No additional download is authorized by this task; separate exact-file approval is needed.

## Existing SOC boundaries and regression

No SOC source code, UI, queue, collector, source store or inference adapter was modified.
The future path stays `AF_PACKET → existing Flow/Source/Provenance → verified Producer →
future new model → advisory context → Finding → READ-only investigation → Policy/Approval`.
Current legacy models must not consume Network14 just because binding recovered.
**NOT_INFERABLE / BLOCKED inference and Finding promotion / DIAGNOSTIC_ONLY /
WRITE_DENIED** remain. Native/offline operational parity is not verified.
Seven reviewed legacy artifact/scaler/feature SHAs remain unchanged; Syntheticv2,
OperationalProvenancev3 and governance contracts remain intact.

Fresh ML broad regression 578 passed; independent Git Export 571 passed. Seven existing
user CTU tests explain the difference; counts are separate runs, not summed. Focused
IoT23 run100 passed includes43 new recovery tests. Both saved-byte trainval and sealed
audit exports reproduce identical complete manifests/proofs, excluding user/Replay code.
SOC working regression: **768 passed** (271.88s). Independent SOC Git Export:
**768 passed** (267.75s). Each run blocked one intentional fixture socket attempt. Socket guard denies new
AF_PACKET/IPv4/IPv6 connections; no new actual capture/traffic is created by the tests.
Ruff src/tests and whole SOC format PASS; ML owned format PASS,24 pre-existing full-format
violations preserved. Diff/staged SHA and independent-export checks precede commit.

## Next decision

Stop further time-offset/tolerance searches. Resolve independent device/campaign and
capture-quality evidence, and if more data is approved consider3-1's pinned PCAP+labels
with bounded admission checks. Preserve sealed34-1 and define a new explicit chronological
whole-session plan only on verified evidence. **Retraining and operational inference
remain BLOCKED.** No physical Linux-server validation was performed.

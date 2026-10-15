# Network training dataset and SOC readiness

2026-10-15, WSL2 Ubuntu. SOC baseline `37bff82a18b3f5aa0b1b15649df38467fce9768f`;
ML baseline `309d4836580682b8cb6589264ab3fc227965f0fb`.

**Dataset acquisition selection: IoT-23 / ACQUISITION_READY.
Network Quality and Network Edge: BLOCKED for retraining.**
No SOC runtime or GUI source changes; no training, new raw acquisition or gate unlock.

## CTU-13 S07 final decision

Existing pilot/streaming evidence, schema, official README and ra.conf findings were
reviewed once. No new independent label-export clock evidence was available. The 237
stored diagnostic rows still match their prior file digest; none become verified truth.

```text
CTU13_S07:
  label_timezone: TIMEZONE_UNVERIFIED
  verified_matches: 0
  training_admission: BLOCKED
  role: PRODUCER_DIAGNOSTIC_ONLY
```

Capture CEST/DST does not prove Argus export environment; first-observed PCAP direction
is not Argus initiator direction, and flow labels are not packet truth. Background is
not default benign. Original session/partial stream integrity remains separate. No new
full decode or S07 download was performed, and no exhausted expansion budget was reused.

## Selection evidence and scope

Screening order was other CTU scenarios, CIC-IDS2017, UNSW-NB15, then alternatives.
A sampled other-CTU ra.conf also lacks RA_TZ; this does not establish every CTU scenario
is unusable, but provides no basis for another same-uncertainty acquisition now.

| Final shortlist | Result / reason |
|---|---|
| CIC-IDS2017 | BLOCKED: current official download form error; exact raw file catalog/bytes not verified |
| UNSW-NB15 | BLOCKED: official SharePoint redirects to login; no access bypass or mirror |
| IoT-23 | ACQUISITION_READY: exact PCAP/labeled-Zeek endpoints and HEAD sizes verified; analyst label mechanism documented |

Sources: [CIC](https://www.unb.ca/cic/datasets/ids-2017.html),
[UNSW](https://research.unsw.edu.au/projects/unsw-nb15-dataset),
[IoT-23](https://www.stratosphereips.org/datasets-iot23).
Published dataset CC-BY-4.0 and attributed reuse policy are documented in
[Zenodo](https://zenodo.org/records/4743746) and the
[publisher FAQ](https://www.stratosphereips.org/datasets-faq).
Legacy per-capture README authorization wording is retained in the ML report/plan;
no message was sent or publisher rights inferred from user download approval.

Selected proposed sessions: 8-1 (Hakai), 20-1 (Torii), 34-1 (Mirai). They are different
reported families/capture days, not already proven host/campaign-independent data.
Actual schema, label counts, source identity and release equivalence are unverified.
Capture34's individual labels were modified in 2023; do not call them byte-identical
to the older frozen Zenodo v1.0.0 package or treat published counts as measured counts.

## Exact download proposal — approval pending

Official root:
`https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/`
Each row is under `CTU-IoT-Malware-Capture-<session>/` at that root.

| Session | Filename | HEAD bytes |
|---|---|---:|
| 8-1 | 2018-07-31-15-15-09-192.168.100.113.pcap | 2098362 |
| 8-1 | bro/conn.log.labeled | 1431000 |
| 20-1 | 2018-10-02-13-12-30-192.168.100.103.pcap | 4057401 |
| 20-1 | bro/conn.log.labeled | 419604 |
| 34-1 | 2018-12-21-15-50-14-192.168.1.195.pcap | 126317980 |
| 34-1 | bro/conn.log.labeled | 2926718 |
| Total | Six files only | **137251065 (~130.89 MiB)** |

Plan: ML `docs/network-training-download-plan.json`, exact URL list and manifest digest.
Proposed download cap **256 MiB**, hard timeout **300 seconds/file**, retries **0**,
archive expansion **0**, redirects denied, no overwrite, private ML storage
`data/raw/acquisition/iot23-network14-3sessions-v1/<capture>/...` (not created).
No file body was downloaded; HEAD MIME absence for labels remains UNKNOWN. ETags and
metadata hashes are not original-file SHA256. Raw and publisher per-file SHA remain UNKNOWN.

Existing bounded raw acquisition will be reused, but `.log.labeled`/Zeek prefix support
needs a narrow tested extension before transfer. Do not disguise logs as Argus CSV or
skip format validation. Actual PCAP magic/link type must also be checked after approval.
This is an exact acquisition proposal, not an already executable/authorized data import.

## Producer, binding and holdout

Unchanged Network Producer v1.1.0, Network14 feature order/float32, source/feature digests,
IP lengths, flags, first-observed bidirectional direction and 30/120-second segmentation
are preserved. OFFLINE_PCAP is distinct from NATIVE_AF_PACKET and FIXTURE. Raw bytes
should supply the observable fields, but actual compatibility remains BLOCKED until
headers, timestamps, loss/gaps and supported protocol fields are checked. Missing fields
must be excluded. No legacy model/scaler artifact is substituted or overwritten.

Zeek specifies epoch timestamp and orig/resp fields; the old capture's actual #fields,
#types and label columns must be inspected. This is specification-level evidence, not
an actual downloaded header. Bind exact tuple/protocol + capture ID + containing interval
uniquely; preserve the mapping between first observed direction and Zeek orig/resp.
No timezone search, arbitrary tolerance or unmatched-as-benign rule is allowed. The
CTU Argus parser is not silently reused for Zeek labels. Independent raw golden pairs
and row provenance remain required before any admission.

Fixed proposed whole-capture split: train 8-1, validation 20-1, sealed test 34-1.
Audit campaign/sample/device groups and duplicate flows; never use random row splits.
Host independence cannot be inferred from private addresses. A shared host/campaign or
missing class may invalidate this proposal and keep admission BLOCKED. Actual capture
epochs, split digest and leakage tests are not verified. No fitting, feature selection
or threshold tuning on test data. Sparse reported validation positives and IoT-to-Linux
server domain shift must remain evaluation limitations. No external holdout is acquired.

## Readiness and next action

| Condition | Status |
|---|---|
| Exact source/label endpoints and byte plan | ACQUISITION_READY |
| Dataset admission | NOT_ADMITTED |
| Actual raw/label binding | NOT_VERIFIED |
| Producer compatibility / independent golden pair | BLOCKED / NOT_RUN |
| Independent holdout | PROPOSED, NOT EXECUTED |
| Network Quality retraining | BLOCKED |
| Network Edge retraining | BLOCKED |
| Network/DNS operational inference / response | NOT_INFERABLE / WRITE_DENIED |

The ML pure pending-plan verifier rejects forged/rehashed approval, admission, file,
budget, producer or split-readiness claims. It never fetches or trains. It does not
widen the existing v1.0.0 pending manifests or create a dataset management platform.

Next action is explicit approval for these six files and stated limits. After narrowly
validating the transport format, acquire/verify bytes, raw-to-label binding, golden
pairs and group split. Training then requires separate authorization and new model IDs,
not an automatic readiness upgrade. Production source parity, physical Linux validation
and operational integration remain later work. No OS setting, privilege, policy,
approval rule, synthetic v2 or operational provenance v3 contract changed.

ML detailed report: `docs/network-training-dataset-selection.md`.

## Fresh verification and selected commit scope

Results are separate invocations with overlapping tests; do not sum counts:

| Execution | Result |
|---|---|
| New pending dataset-selection tests | 42 passed |
| ML selection + CTU13 + raw acquisition + producer + scripts + three package suites | 478 passed, 4.99 s |
| Same ML suite from baseline HEAD + only selected files | 471 passed, 5.33 s |
| SOC capture/source/queue/runtime/provenance/external/GUI/approval/execution security suite | 768 passed, 244.48 s |
| Same SOC suite from independent baseline HEAD export | 768 passed, 226.94 s |
| Ruff src tests, both working trees and ML export | PASS |
| SOC whole-tree format | PASS, 885 files already formatted |
| ML selected Python format | PASS, 2 files already formatted |
| ML whole-tree format | Existing 24 files require formatting; not changed |
| Git diff whitespace and selected stage checks | PASS |

Seven ML working-tree tests come from the existing user-modified test_offline.py and
are excluded from this commit. Independent exports exclude the five existing ML user
source/test modifications, untracked legacy DNS package, eight SOC user-modified files
and all uncommitted Reliability Replay files. Imports/tests use exported source plus
existing local dependencies/pytest; no new dependency is installed. All 1033 pre-existing
SOC files and 480 pre-existing ML files matched their initial SHA inventory. Seven
legacy artifact/feature/label hashes match the earlier reviewed identities.

The SOC guard blocked one intentional test socket attempt per invocation. No new
capture, test traffic, live LLM, original-data decompression or raw dataset GET occurred.
Tiny fixture and mock-transport tests are distinct from unacquired IoT-23 bytes.

New tests check immutable-plan integrity, rehashed admission/approval/promotion denial,
source/file/path/size identities, timeout/retry budgets, explicit unsupported Zeek label
transport, whole-session split leakage, unchanged producer and fixture epoch/direction
arithmetic. Existing suites cover actual binding primitives, label conflicts/UNKNOWN,
archive/download safety, golden tampering, flow/time/gap/restart and security contracts.
They do not verify a new IoT-23 Raw-to-Label pair, golden pair, actual schema or holdout.
Those remain NOT_RUN/BLOCKED, not fixture PASS promoted to dataset evidence.

Selected files only:

- ML docs/network-training-dataset-selection.md
- ML docs/network-training-download-plan.json
- ML src/ml/raw_acquisition/selection.py
- ML tests/dataset_selection/test_network_selection.py
- SOC docs/linux-soc-v1/network-training-readiness.md

No raw packet/log/label file, large generated dataset, model artifact or unrelated user
change belongs to these commits. Source/stage SHA identities and independent exports
are checked before commit. Commit/push covers this selection/readiness assessment only;
it does not approve the proposed download or authorize later model training.

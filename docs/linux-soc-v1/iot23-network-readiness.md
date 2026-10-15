# IoT-23 Network retraining readiness

2026-10-15, WSL2 Ubuntu. SOC baseline `e2c2acaf1736a9db43fd3754451227bb01ede0fc`;
ML baseline `48205646bacbca67eaa39d04b597c34551942a18`.

**Overall PARTIAL. Network Quality BLOCKED; Network Edge BLOCKED.**
The approved six IoT-23 files were acquired and inspected; neither model is ready for
retraining. No model training, native inference, artifact replacement, new capture,
OS security response or operational gate unlock was executed.

## Download and source integrity

Exactly Capture8-1 /20-1 /34-1 PCAP+Zeek label files were downloaded once each from
the URLs pinned in ML `docs/network-training-download-plan.json`: **137251065 bytes**.
All six HTTP200/Content-Length values matched the plan; no redirect, retry, archive
expansion or overwrite. Per-file hard watchdog300s was respected (longest16.754s).
Raw files remain in ignored ML `data/raw/acquisition/iot23-network14-3sessions-v1/`.
No raw PCAP/labels/payload or large generated dataset is committed.

Complete per-file URLs, timestamps, sizes, local SHA256 and timings are in ML
`docs/iot23-network-admission-evidence.json`; explanation in `docs/iot23-network-admission.md`.
Publisher per-file SHA256 UNKNOWN; local repeat-read SHA integrity is not an external
signed publisher assertion. Source/dataset analyst labeling is documented by the
[IoT-23 publisher](https://www.stratosphereips.org/datasets-iot23).

## Actual PCAP and Zeek inspection

All three: classicPCAP2.4, Ethernet, little-endian, microsecond clock, snaplen262144.
Full stream SHA equals each acquired raw SHA; IPv4 TCP/UDP observed, no snaplen-truncated
records. Actual IPv6 not observed (fixture tested separately).
Existing parser excludes non-IP/link traffic and34-1's57489 IP fragments; no reconstruction
or zeros were invented for those packets. Capture loss and gap provenance remain UNKNOWN.

8/20 labels use TSV with exact triple-space analyst suffix `label/detailed-label`;
34 uses full TSV with actual alias `det_label`. Strict schema/type validation now
supports those observed forms. Background/unknown/missing values never become benign.
Zeek UID is an external row reference, not claimed independently reconstructed fromPCAP.

## Binding and class coverage


| Capture | Raw packets | Parsed | Flow segments | Label rows | Verified | Candidate | Ambiguous | Unmatched | Excluded |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 8-1 | 23623 | 16677 | 4237 | 10403 | 2162 | 2056 | 0 | 0 | 19 |
| 20-1 | 50156 | 41207 | 3921 | 3209 | 2300 | 36 | 0 | 1 | 1584 |
| 34-1 | 233865 | 170980 | 7848 | 23145 | 1866 | 4755 | 0 | 4 | 1223 |

Verified means unique session/protocol/bidirectional tuple, exact first epoch, full interval
containment, matching directional packet/IP-byte counters, zero label missed_bytes and no
incomplete/resource-limited flow. Features generated from verified rows are diagnostic,
**not admitted training samples**. Total strict Flow matches6328; admitted samples0.

| Planned split | Strict Benign | Strict Malicious | Readiness |
|---|---:|---:|---|
| Train8-1 |2162|0|BLOCKED_CLASS_COVERAGE|
| Validation20-1 |2300|0|BLOCKED_CLASS_COVERAGE|
| Sealed test34-1 |964|902|Not an independent admitted holdout|

Epoch clocks agree without a timezone search/shift. The actual issue differs fromCTU13S07:
Zeek's TCP duration can omit trailing nonproductive packets, while Producer Flow uses all
packets; missing duration and long-connection segmentation also prevent strict association.
[Zeek's primary contract](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html)
explains those semantics; exact historical Zeek revision/config remains unknown.
Such rows stay CANDIDATE/EXCLUDED; they are not made malicious/benign through relaxed matching.

## Producer, Golden Pair and holdout

Existing Network Producer1.1.0 is unchanged: OFFLINE_PCAP,14float32 features,
IP lengths, first-observed direction,30s idle/120s active,4096packet cap, explicit source
and feature digests. Existing v1.0.0 remains intact. Configuration:
`7999723911ce3d2e9cd3b3b6e0d45e11f44b1316cdf9c7f4883d7e2a69ca21a7`;
feature contract `84ba0916f0ce4e9e12bb70712db2cd1eaea84ba4173acd57b647faf38efb1c6e`.

Three actual PCAP-derived two-packet arithmetic reference pairs pass a separate
statistics/counter calculation (rel1e-6/abs1e-7, finalfloat32). Fixture arithmetic,
actual offline reference pairs and **NOT_VERIFIED native/training parity** are distinct.
There is no new model artifact to bind; legacy Top40 models are not Network14 models.

Whole-session train8/validation20/test34 plan retained, no random rows or test-based
tuning. Capture time ranges do not overlap, exact raw-flow duplicate intersections0.
However one origin-address hash overlaps train/validation; physical device/campaign identity
is unverified. Small Network14 numeric-vector collisions92/80/79 are reported, not
misrepresented as duplicate raw flows or independent-source proof.
Train/validation lack verified malicious samples; holdout and leakage gates do not pass.
Local raw/label integrity and reference arithmetic success do not override those blockers.

Inspection Manifest digest:
`e833b021a361d35e968962ab5b3b1c626ca313523d89ef75f5496e5ffae909d6`.

## SOC connection and security boundary

Existing intended path remains:
`AF_PACKET → existing Flow/Source Store/Provenance → verified versioned Producer →
future separately trained model → External Model Context → advisory Finding → READ-only
Investigation → Threat Assessment → Policy/Human Approval`.

No new collector, queue, GUI, agent or inference framework was introduced here.
Actual offline sources are not relabeled NATIVE_AF_PACKET/FIXTURE. No model output is
promoted to observation or execution authority. Network Quality/Edge/DNS keep
**NOT_INFERABLE; native operational inference/Finding promotion BLOCKED;
DIAGNOSTIC_ONLY; WRITE_DENIED**. Existing policies/approvals/restricted executor and
Syntheticv2/OperationalProvenancev3 semantics are unchanged.
Seven existing ML artifact/scaler/feature SHA identities were rechecked unchanged.

## Tests and independent export

ML working regression **535 passed**; independent Git Export **528 passed**.
Seven pre-existing user CTU tests account for the difference and are excluded from this
commit. Runs are separate, never summed. Both exports use only committed baseline plus
owned changes, excluding ReliabilityReplay and existing user changes. Reprocessing
all three saved raw PCAPs in ML export gives an identical full Manifest and per-flow
record digests. No additional acquisition or privilege was required.

SOC working guarded regression: **768 passed** (242.58s).
Independent SOC Git Export: **768 passed** (255.00s). Both runs blocked one
intentional socket attempt in the fixture guard; new capture/test traffic0.
The guard denies AF_PACKET/IPv4/IPv6 sockets; no new capture or test traffic is generated.
Ruff src/tests and whole SOC format PASS; ML owned format PASS, whole ML has24pre-existing
format violations, untouched. Git diff/stage checks and owned SHA identities are checked.

## Remaining blockers and next action

1. Strictly verified malicious train/validation class coverage is absent.
2. Zeek connection/Flow segmentation needs an independently justified TCP association
   policy, not a fitted time shift or broader arbitrary interval.
3. Capture drop/gap quality, physical host/campaign grouping and native parity are unknown.
4. IoT laboratory data is not evidence of generic Linux-server production accuracy.
5. No physical Linux-server validation, retraining, artifact packaging or operational
   promotion was performed.

Review connection-aware label association without changing Producer14feature semantics.
If reliable association cannot be established, prepare exact additional source/reference
requests for separate approval. Do not train, move test samples into training, replace
legacy artifacts or unlock gates on the basis of this partial offline validation.

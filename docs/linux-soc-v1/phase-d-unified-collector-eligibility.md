# Phase D-1 — Unified collectors and Network14 eligibility

## Status and preservation

Development baseline: `da96e70`. Campaign: `NATIVE_SOC_PHASE_D`.
Native runs **0/5**; Root installations **0/5**. This phase performed no sudo,
Root installation, capability change, BPF load, attach, capture or DNS traffic.
Existing installed TCX release **0.5.16** and standalone DNS **0.5.20** remain
unchanged. Historical ledgers, 104 recorded evidence files and eight unrelated
tracked user changes are excluded from this change.

This is a prepared **0.6.0 integration candidate**, not Native E2E qualification.
Native AI, DNS9 and operational promotion remain **BLOCKED**.

## Unified execution boundary

```text
ordinary CLI / GUI / Network14 / DNS diagnostics
  -> exact combined release + source + scope preflight
  -> existing TTY authentication / sudo entry (once)
  -> trusted Supervisor
       -> isolated read-only Inspector: SYS_ADMIN, pre/post inventory
       -> existing TCX Broker: BPF + NET_ADMIN, owned Link FD
       -> one-use DNS worker: fixed START_DNS, read-only metadata pipe
  -> TCX Ring -> bounded data plane -> Network14
  -> DNS AUXDATA -> analysis-only corrected copy -> existing Zeek -> diagnostics
  -> owned TCX STOP -> bounded DNS drain -> Supervisor/Inspector final cleanup
```

`phase_d.prepare()` reuses the current release builder and Supervisor image
builder. The TCX C program, Loader, 80-byte ABI, data-plane implementation and
Network14 assembly/feature order are unchanged. The DNS capture, checksum-copy,
START peer/binding checks, Analyzer, Counter/CLOSED and traffic probe are reused.
The old standalone paths remain available.

The new DNS worker is forked in the trusted Supervisor child **before** Inspector,
Broker/Link FDs or stream threads exist. It receives only its fixed start channel
and metadata stdout. It waits with effective/inheritable/ambient capabilities
zero and permitted/bounding `NET_RAW + SETUID + SETGID`; the latter two permit the
existing numeric UID/GID drop after socket bind. On its one permitted activation,
it enables only that permitted mask, then reuses the existing capture/drop code.
After bind, UID/GID become the ordinary user's and E/P/I/A must be zero; the
restricted bounding mask remains with `NO_NEW_PRIVS`. No capability is passed to
GUI, model workers or the capless, network-isolated analysis container. These
transitions are **designed and fixture-tested; Native capability verification is
PENDING**. Inspector SYS_ADMIN is never passed to the DNS worker or TCX Broker.

`START_DNS` uses existing authenticated Supervisor IPC: peer credentials, common
binding, ordered sequence, hash chain, size/rate/time limits and an empty argument
schema. It accepts no command, path or environment. The command consumes its one
attempt even on failure. Only a read-only pipe FD reaches the Controller.
The existing separate DNS START socket still verifies the Root worker peer,
Session, actual execution image, Root manifest, approval, DNS scope and sequence1.
There is no second sudo call or credential-cache dependency.

## Session and pre-authentication contract

One application envelope/approval binds both collectors. TCX retains its exact
Program SHA, TCX RunIdentity, namespace, interface, hook and resource budget.
DNS has a distinct Collector ID; its store cursor and completion receipt also
record the common application session and approval digest. The baseline DNS
0.5.20 image is provenance; **the new combined image SHA authorizes execution**.
It is not represented as executing the unchanged standalone image.

Before authentication the integrated path checks the outer manifest and source
bundle, Root package and binary hashes, DNS manifest/source/scope, TCX Plan and
RunIdentity, Zeek plan, actual namespace, TTY, SHA-held probe, Docker environment
and the existing local UDP/TCP listener. The installation to replace is checked
against the image's previous manifest (0.5.16). After authentication the DNS task
checks the **new installed manifest** again. Source/scope mismatches stop before
requesting a password. Approval presentation includes the local DNS traffic and
worker capability contract.

TCX: `net:[4026531833]`, `lo/Ingress`, <=300s/4096 metadata, Queue32,
256MiB/CPU20s per privileged role. DNS: same namespace/lo, <=10s active window,
<=7s capture,32 packets,snaplen512,Queue32; fixed local endpoint
`127.0.0.53:53`, `native-0516.localhost.`, A, UDP1/TCP1. No external DNS,
settings change or offload change. Analysis container keeps RAM512MiB/CPU1,
network=none and cap-drop=ALL. The DNS window starts at its authenticated
Supervisor task activation; the enclosing application remains bounded to300s.

TCX reaching its budget does not revoke the DNS status channel mid-drain. The
existing owned-resource STOP releases TCX resources while keeping the Broker
session available; DNS finishes within its existing bounded task. Independent
close failures are retained. DNS status polling stays below the Supervisor rate
limit. Failure never authorizes restart. The live ordering/capability/cleanup
claims still require separate Native qualification.

## Candidate-specific Feature RCA

Primary evidence is the immutable 0.5.16 checkpoint and final counter receipt:

- `.git/journal-dns-integration-0516/candidate/session/data-run-1/monitor.sqlite`
- `.git/journal-dns-integration-0516/candidate/supervised-result.json`
- `.git/native-zeek-control-campaign-0514/attempt-3/verification.md`

The DB was opened with SQLite `mode=ro`; its checkpoint digest was verified.
[Machine-readable candidate RCA](phase-d-feature-eligibility-evidence.json)
records full Flow IDs, vector digests, source hashes and separate reasons.

| Flow ID prefix | Packets | Termination | Order/float32/digest | Eligibility |
|---|---:|---|---|---|
| `89751ff9e100` |16|INCOMPLETE|valid|BLOCKED|
| `6e6e7bcce539` |24|INCOMPLETE|valid|BLOCKED|
| `7254400bd0f1` |22|INCOMPLETE|valid|BLOCKED|
| `6e8caf439886` |28|INCOMPLETE|valid|BLOCKED|

The checkpoint records179 received,90 accepted,89 processing-discarded and0
queue-rejected. Three unrepresented CPU **observation attempts** are not proven
Ring Buffer loss. `end_metadata_stream()` conservatively closes outstanding
flows as INCOMPLETE when these attempts are unreconciled. These four flows have
no idle30s/active120s completion evidence. The session also records
`TCX_DATA_SOCKET_DELIVERY_LOSS`. These are shared session facts, not attribution
of a particular missing packet to a particular flow.

Final owned-map counters were retrieved successfully: observed432,emitted385,
delivered181,disabled47,ring reservation failures0. The emitted/delivered gap204
is unreconciled; it is **not** labeled204 Ring losses. The earlier checkpoint's
counter-UNKNOWN state is superseded only by this final receipt. Timestamp
inversions0 and late events0 are not failure causes here. Clock calibration is
DECLARED_ONLY, with no established offset/accuracy; bounded ordering alone does
not prove calibration.

The immediate flow/capture rejection is distinct from the existing global
Native AI gate. Even a correct 14-value vector and valid digest do not prove
Native Golden Parity or a bound model artifact receipt. Those claims remain
UNKNOWN and the Native AI policy remains BLOCKED. No feature values are filled
in, timestamps changed or incomplete flows reclassified.

Future summaries retain bounded candidate-level reason records. The Supervisor
combines these with terminal transport counters for the GUI/final report, so a
late counter receipt can resolve ring-UNKNOWN without changing old evidence.
Unretained historical candidates are explicitly counted UNKNOWN, with no invented
Flow ID or per-flow cause.

The earlier successful 0.5.13 TCX run (Program5245/Link6) was checked separately:
4096 received/accepted and six candidates. Its final receipt retains only four
candidate details: `0cfd3b34ffe4` (715 packets), `dd62505a4a6a` (833),
`45fccc537ca4` (4), `7f51bb9b9a20` (4), all INCOMPLETE. The other two candidates'
identities/reasons are UNKNOWN because they were not retained. Its three attempt
gaps remain unreconciled; ring reservation failure, processing discard and queue
rejection are zero, with no socket-send failure. Eight bounded inversions
(max1445ns) and zero late events do not establish calibration or explain capture
loss. Its emitted4119/delivered4096 boundary is reported separately from Ring
loss. The JSON includes this run as secondary evidence; it does not mix these
4096 packets with the 179-packet 0.5.16 session.

Flow contracts are unchanged: IDLE_TIMEOUT and ACTIVE_TIMEOUT are candidate
window boundaries; NORMAL_END, PACKET_LIMIT, CAPTURE_STOP, QUEUE_OVERFLOW,
CLOCK_INVALID and INCOMPLETE remain distinct. A termination label alone never
makes a Native feature AI-eligible.

## DNS, GUI and Audit/Recovery

The existing analysis-copy path still requires actual CHECKSUM_PARTIAL metadata,
checks original/corrected digests, rejects malformed/unconfirmed checksums and
feeds only approved probe flows to Zeek. Raw-IP UNSUPPORTED remains excluded
from Network14. DNS transaction matching, checksum rejection, capture counters,
sequence/chain and CLOSED remain independent of TCX counters and clocks.
DNS capture integrity remains partial provenance, not full Native AI attestation.

The four GUI screens and graphs are retained. System adds candidate reasons and
DNS transaction/quality fields through existing snapshots. Normalized DNS events
are committed through existing CollectorStore/RuntimeStore transactions and
append-only Audit. Recovery verifies that chain without authenticating,
reattaching or reinferencing. Completion/error state is retained separately from
TCX cleanup. No raw packet/PCAP is written by the integrated analysis path.

## Release, rollback and qualification

Final identifiers and validation receipts are in the accompanying release section
below. The private candidate is `.git/native-soc-phase-d/release-0.6.0-qualified/`.
Preparation compiles/verifies only and never performs installation.

Future exact-image approval is required before the existing unified atomic
installer may replace `/usr/libexec/soc-agent-ebpf`. It preserves the current
0.5.16 under `/usr/libexec/.soc-agent-ebpf.rollback-<previous-manifest>`; existing
conflicts must block replacement. Root-owned modes remain executables0555 and
other payloads0444. No installed file or rollback path was changed in D-1.

Before any Native attempt: reserve campaign budget, check approved image/source
identity, namespace and listener, use one real terminal authentication, obtain
Inspector pre-inventory with no foreign-hook conflict, then execute only the
approved scope. Validate DNS pre/post-bind caps, actual TCX/DNS delivery and
independent Counter/CLOSED, timing, drain, kernel/container absence and audit.
Native installation, integration, capability transitions, GUI Native data and
combined cleanup are **PENDING**. This phase reports fixture/file-only Zeek
results separately. Campaign stays0/5 for both Native and Root operations.

## Final candidate identity

- Integrated manifest: `cd421cc6f9cbfacc188d13cc3458c1bd978e55b0742954a652ef7a519bafae01`
- Runtime source bundle: `d811c209f742054c0b0b7b33c6a29f53ad14265b60e3fe739a1a2d9967b63100`
- Execution image: `c17b74cd04b3c8fca33451a5bb734e142d7b92425ec893912d61c2667124c5af`
- Root TCX release manifest: `7019079c4ec2f57c83945a33dd18eb1c9d896fd819f2b1454f371553015b52f8`
- Root TCX source bundle: `cd28d4b8aece3ece19c1526f0e3913099d57eac218bc6ec28f1f5ddaa9f3ae73`
- DNS component manifest: `e05c0c4ee3b29eaab2e378222299ad64063aae75ea01de78b1eb5baf2d0e3c7e`
- TCX program: `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06`

| Installation file (9 total) | SHA256 | Root mode |
|---|---|---|
|bootstrap|`df183f29c4b73d5cd401e37d51ac4a95a13a756411df7ce21e1f6c5361372ee2`|0555|
|broker|`62b2019d09f606e0c59d8b47ca216c23240b725294f1f929b9fed9ae442725ee`|0555|
|entry|`8e4ef82c3fe45ae5a414509316a2922898148ed860bb7ebdde9f743509ce4455`|0555|
|libnative-tc.so|`138b6a4f7a30db599635a523c7abfbd912758ebee5624f00a7d5fc221c8f09e3`|0444|
|manifest.bin|`b077437dffc38b84a9a80084fde357cffcb39424a2fad3688123a93bb5e3bdc0`|0444|
|pam-policy.conf|`93af76067bf513b4db8c5a9bd606e348ccde334b83e52f7dc71544c9c1f82696`|0444|
|release.json|`7019079c4ec2f57c83945a33dd18eb1c9d896fd819f2b1454f371553015b52f8`|0444|
|release.trust|`ad42f8a2e21f06c6e994c5ffd2fc9c272ab86b15614a54d2aafb225feff0093e`|0444|
|tc.bpf.o|`9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06`|0444|

## Qualification evidence

The frozen candidate's independent source export (HEAD plus15 explicit task
files, excluding the eight user changes/private Native data) passed **99 focused
tests** in222.61s. Coverage includes real CLI-to-approval-boundary TCX/DNS
preflight, same-session START without second authentication, replay/scope/source
rejection, isolated worker parent FD ownership (fake fork/no privileges),
independent partial-failure cleanup, packet-budget shutdown ordering, C fixture
transport through Packet Adapter/Network14 Golden Parity, CPU/clock/drain,
file-only capless Zeek UDP/TCP analysis through normalized DNS Store/Audit
recovery, and the four-screen GUI transport fixture. No test outcome is Native
installation/capture/capability verification.

Ruff, format and diff checks passed on the changed code/tests. No full model
validation, Wheel, GUI performance benchmark or screenshot regeneration was
performed. The GUI fixture was updated to wait for bounded asynchronous packet
processing; its earlier immediate assertion observed command ACK before worker
completion. The source/Export/index byte SHA comparison and preservation receipt
are private campaign preparation artifacts. Memory available at an observed
checkpoint was approximately4.2GiB; no Native performance claim follows.

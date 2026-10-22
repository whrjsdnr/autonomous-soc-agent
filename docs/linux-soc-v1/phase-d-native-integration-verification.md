# NATIVE_SOC_PHASE_D Final Verification

## Overall Status

**FAILED — the one authorized0.6.2 integrated execution failed.**
DNS analysis met its internal deadline and parsed the controlled UDP/TCP test.
TCX encountered an out-of-window timestamp inversion; subsequent Control and DNS
shutdown failures prevented complete integration. Kernel Maps/Links/lo filters
were empty at final inspection, but the global Program set changed, so overall
Cleanup remains UNVERIFIED. There was no second Native execution or Root retry.
Nonprivileged RCA/fixes/tests produced a separate, unexecuted0.6.3 candidate.

## Git / Release / SHA

Execution Git: `b05927d02324a086b3c414e2fdcebe56d44cd7be` (HEAD=origin/main at launch).
Release installed and executed: **0.6.2**.

|Approved artifact|SHA256|
|---|---|
|Manifest|`a63034f77d3a4ea9b1b2f9398adb2c2ceef53eff8ac3db3b21f5d16b14d09416`|
|Bundle|`d2425596030b1bc07b6e60e6c0bedacbeaf9deb2c8b9d029c042d1b8d802cc6d`|
|Execution image|`e131aafd8c5f52664c78b3585f0c0638696d76f5d3e4a69e1866faba3ace1b0c`|
|Root manifest|`56e1b7bc8a2a7a2ebd6902899f349b5fae7432f24d492ce8dab1a92b90e72dc4`|
|TCX object|`9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06`|

All nine installed files were verified read-only for SHA,root:root and0555/0444.
The prior0.6.1 installation is retained at `/usr/libexec/.soc-agent-ebpf.rollback-`
plus `1f205935cdb344178a848108b508d20a9f6e1028ad56f718b0a61cb4269478d3`.
The older0.5.16 rollback is also preserved. No rollback was executed.

## Approval / Budget

- Exact user approval materialized as `live-062/approval-062-user.json`.
- Approval receipt SHA: `9dbcca0ee2633ed2069ec5962c152b69bb4693d1b34db98c7ec264622c632f64`.
- Attempt: `fd1a892416fd4bccab579d5ae57764da`; public approval metadata is not an auth token.
- Scope: net:[4026531833],lo/Ingress,300s/4096/Queue32,privileged roleAS256MiB/CPU20s.
  DNS: same namespace/lo,127.0.0.53:53,native-0516.localhost. A,UDP1/TCP1,
  <=10s active/7s capture/32 packets/snaplen512; ZeekRAM512MiB/CPU1.
- One terminal scope confirmation and one pinned sudo authentication invocation;
  password remained in the OS TTY. No downstream sudo-cache dependency.
- Native **2/5 used**, Root **2/5 used**; each3 remaining. One reservation was
  appended before this executor, then FAILED finish, sequence4. The original
  declaration and older campaign records were not reset. Installation succeeded.
- No0.6.3 receipt, reservation, installation, authentication, load or attach.

## Unified Supervisor

Session: `fe6d42c5-c314-4075-91dd-bfe298d9b795`.
The existing Inspector verified pre-attach resource inventory with no Hook conflict.
Broker P/BoundingBPF+NET_ADMIN, E/I/A0 while idle; Inspector separately retained
SYS_ADMIN. GUI/Network14/DNS adapters remained ordinary user components.
Shared Release/Session/Approval and separate collector provenance were preserved.

The actual saved Supervisor `first_failure` was **null**, despite a processing
failure: background STATUS handling recorded HANDOFF_COMMAND_FAILED instead of
raising through the main-loop exception boundary. Do not mistake null for no error.
The precise first data failure is preserved in data_plane.error, processing.last_error
and ordering.examples. Main CLI returned0 even though result and Ledger said FAILED;
this exit-status defect is fixed for the new candidate, not rewritten in old evidence.

## TCX Native Capture

- Load/Attach VERIFIED: Program6331,tag5d24af0965a164b7,Link11,ifindex1,attach type46.
- Generation **9245281928320049646**, above2^63, retained as positive uint64 in
  journal/link/counter evidence. No generation coercion or SQL overflow was observed.
- **2433 received /186 Network14 accepted /2247 discarded**, queue rejection0.
  Post-error discard2245 is a subset of2247; the remaining two were pending/error
  metadata. Do not double-count those subsets or call them Kernel packet loss.
- Owned final Counter: observed2435,emitted2433,delivered2433,unsupported2,
  ring reservation failures0,malformed0,disabled0,budget0. Counter query succeeded.
- Final data sequence2435,2436 total frames; Counter and CLOSED received.
  Socket send failures0, no EAGAIN. Kernel-wide drops UNKNOWN.
- Ring/terminal transport accounting survived the processing error, but normal
  processing Drain is FAILED. Receipt closure is not successful feature processing.

## DNS Native Analysis

### Capture / Analysis / Export

- Controlled UDP and TCP each sent exactly one query and received a response.
- Twelve metadata copies reached Zeek: UDP2/TCP10, CHECKSUM_PARTIAL_CONFIRMED,
  checksum rejection0. Original/corrected provenance chain checks remained enforced;
  no raw PCAP was persisted. No offload, DNS configuration or external traffic change.
- Zeek parsed **2 queries /2 responses /2 matching transactions** (UDP1/TCP1).
  Analyzer dispatch4, emitted DNS events2, adapter rejected0. Normalized diagnostics
  persisted two DNS plus two Network events; four audit chains verify read-only.
- Counter/CLOSED observed, final stream sequence19, duplicates0,gaps0,
  `protocol_finalized=true`, container exit0/absent, no analysis cleanup failures.
- Raw-IP metadata12 remains UNSUPPORTED for Network14, never converted into TCP/UDP.
- Sidecar completion still FAILED with SUPERVISOR_CLIENT_CLOSED while waiting for
  the Supervisor-owned capture child. No completion.json was produced. Root capture
  terminal metadata had been read but was not published before this wait failure;
  final Root socket-drop counters cannot be recovered from the retained receipts.
  Zeek input counters are not substitutes for those socket counters.
- DNS parsing/matching and the analysis deadline are independently VERIFIED for
  this controlled test. Full capture/export/lifecycle integrity remains INCOMPLETE;
  saved session DNS visibility UNKNOWN is not retroactively rewritten.

### Timing (one monotonic domain, relative to DNS worker start530711.480792154)

|Stage|Elapsed seconds|Limit / interpretation|
|---|---:|---|
|Analysis process launched|0.118174|Inside DNS10s window|
|Zeek script init|2.578780|Cold startup included|
|Zeek READY|2.606705|Before START-triggered capture|
|Capture READY observed|2.608485|Capture overlaps analysis|
|Capture CLOSED received|8.771544|Capture starts/stops exact socket timestamps not retained|
|Analysis input closed|8.826374|EOF initiates final analysis|
|Counter received|8.946414|Before9.5s analysis cutoff|
|Zeek CLOSED received|8.946550|Before9.5s cutoff|
|Analysis process / protocol exit|9.265899|Recorded elapsed9.147726s since process launch|
|DNS finalization starts|9.274621|No second capture|
|DNS cleanup complete|9.317348|Total10s limit met|

`analysis_deadline_expired=false`; internal deadline9.5s, outer deadline10s,
remaining margin about0.1827s at cleanup. This verifies the0.6.2 analysis-budget
change in this run, not a latency guarantee. DNS worker start is after OS auth;
user typing/authentication time is not falsely included in this active interval.
Export-only and Supervisor-exit-only substage durations were not separately recorded.
The receipt's overall active_elapsed_seconds is9.317369; differences of microseconds
reflect later measurement, not a different clock. No wall/monotonic subtraction.

## Network14 RCA

Four new candidates; all **INCOMPLETE /0 eligible**. Sum of candidate packets186
matches accepted count, not the full2433 received. Full receipts are independently
reproduced in `live-062/candidate-readonly-review.json` with session,generation,
source receipt SHA, Counter, Clock and feature fingerprints.

|Candidate prefix|Accepted packets|State|Feature integrity|
|`fc7fe230ae84`|46|INCOMPLETE|valid float32/digest|
|`e6f1d3e3bc0b`|33|INCOMPLETE|valid float32/digest|
|`229fdda8d522`|65|INCOMPLETE|valid float32/digest|
|`8d14c2d92a14`|42|INCOMPLETE|valid float32/digest|

- Counter: matching epoch and successful final owned-map snapshot; emitted=delivered.
  Two forward observation-attempt gaps occurred midstream on CPUs1/8. Unsupported2
  is consistent at aggregate level, but does not prove per-CPU/time/flow attribution.
- Clock: Kernel monotonic ns preserved; calibration DECLARED_ONLY/native accuracy
  unverified. Three inversions,max **194004499ns**,late1. The late sample was CPU1,
  cpu_sequence28,data sequence188,timestamp530711793501600; prior max530711987506099.
  It exceeds the unchanged10ms admission window. No clamp, fabricated timestamp,
  larger reorder window or silent drop was introduced.
- Flow: no30s Idle/120s Active completion evidence. Flows were quarantined after
  the real late-event error; FIN/RST counts alone do not override the model window.
- Features: all four retained raw vectors pass14-feature order,float32,finite and
  digest checks. Valid arithmetic does not establish complete Native capture.
- Reasons: LATE_EVENT,PROCESSING_DISCARDED,unreconciled observation attempts,
  Flow incompleteness,unverified clock/capture/golden parity/model receipt.
- Historical0.6.1 nine candidates remain INCOMPLETE; earlier two unpreserved
  candidates remain UNKNOWN. No historical status or feature vector was modified.

## Root Cause / Minimal Fixes

### First observation and uncertainty

First processing error: **EBPF_REORDER_LATE_CAPTURE_GAP**, EventOrdering.observe,
no system errno. The recorded194ms event-time inversion is confirmed. Its underlying
WSL scheduling/pre-reservation delay is **UNKNOWN**; no Kernel scheduling trace or
second per-event timestamp was captured. SQLite latency is not proof of its cause.

Local BPF source samples time before parsing/reserving. Upstream documentation
states delivery follows reservation order, which is not evidence of monotonicity
for timestamps sampled earlier. This explains why that assumption is unsafe, but
is not proof of the exact194ms delay on this Kernel.
[Linux BPF ring buffer documentation](https://www.kernel.org/doc/html/v6.2/bpf/ringbuf.html).

### Confirmed implementation defects and corrections

1. Successful authenticated Control responses called data.pump(), which rethrew
   the background Flow error. The _packet() receive guard also rejected any data
   processing error. This revoked/closed the whole Supervisor and interfered with
   DNS finalization. Control and processing failure were incorrectly coupled.
   Both boundaries now distinguish background processing failure from broken
   transport. STATUS/STOP/DETACH/CLEANUP remain usable; PREPARE/ATTACH are explicitly
   denied after a data failure. Broken transport still revokes immediately.
2. Main loop now records/raises the original data error through TCX_DATA_PROCESSING
   before the later cleanup path. Safe EBPF symbolic codes are preserved rather
   than redacted as unrecognized text. Arbitrary error input remains redacted.
3. SupervisorClient.status() checked stopping outside its request lock. A concurrent
   STOP could win before request(), yielding SUPERVISOR_CLIENT_CLOSED. A deterministic
   ordinary-thread test reproduces that race. The check and request now share an
   RLock; completed STOP returns only its already authenticated final status.
   Exact live lock interleaving was not logged, so this is a reproduced defect
   consistent with the live failure, not invented scheduler evidence.
4. Observed Root capture terminal metadata is now saved as OBSERVED_NOT_VERIFIED
   before child.wait(). This preserves Counter evidence if status/wait fails;
   existing identity/accounting/process-exit validation still determines success.
5. CLI now returns nonzero for a failed result/cleanup instead of printing an
   ERROR result and exiting0. The frozen0.6.2 exit0 receipt remains unchanged.

The194ms admission failure itself is **not fixed or waived**. The new candidate
contains failure-isolation/diagnostic fixes; it does not claim Native eligibility.

## Cleanup / Remaining Resources

- Map3/Program1 observed FDs returned EBADF after libbpf close, Link11 state
  TCX_CLEANUP_VERIFIED. Individual raw close() return values remain unobserved.
- Final Inspector query succeeded: Maps0,Links0,lo ingress0/egress0; owned TCX
  Program6331 absent. Original11 cgroup Programs retained.
- Two additional cgroup_device Programs6332/6336 were present, total13. Inspector
  correctly reported **SUPERVISOR_RESOURCE_SET_CHANGED:programs**. Attribution
  to a container or unrelated process is UNKNOWN; no cgroup attachment ownership
  proof was collected. They were not deleted or exempted from comparison.
- Root entry exit2; Inspector exited0/revoked its authority. Broker/session closed
  and OS authorization revoked. Capture child exited0, analysis worker exited,
  Docker die/destroy and container absence observed. No automatic restart.
- Overall Cleanup **UNVERIFIED**, independently from the confirmed absence of
  owned TCX Maps/Links. Zero Maps/Links does not erase the global Program mismatch.

## Performance

|Metric|0.6.1 baseline|0.6.2 observed|
|---|---:|---:|
|DNS final active elapsed|9.774063s|9.317369s|
|DNS analysis internal deadline|FAILED|met|
|TCX received / accepted|2763/2763|2433/186|
|Processing discarded|0|2247|
|Max audit commit|23.540475ms|365.714223ms|
|Ring reservation / socket-send failure|0/0|0/0|

Different traffic, timing and failure paths prohibit a throughput/improvement
percentage claim. Current recv-gap max824.444671ms includes waiting for traffic;
max recv syscall1.432863ms,processing6.423440ms,queue wait8.069356ms. Audit3/3
committed,rejected0,outstanding0; audit drain completed but processing quality failed.
Peak RSS,CPU,export-only latency and a trusted complete-window capture rate were
not measured. No GUI or model performance test was repeated.

## Regression Tests

- Control isolation, preauth/startup, error/signal preservation and CLI:38 passed.
- Supervisor contract and deterministic STATUS/STOP race:28 passed.
- Formatted safe-error/CLI checks:3 passed.
- Related security/Flow/Clock/budget/Deadline regression: **77 passed**. That batch
  preceded the final STATUS-lock/new-work guard changes; final changed boundaries
  were checked again in the **62 passed** independent-export cases.
- Final startup/control batch:37 passed plus the corrected valid-ATTACH guard case
  passed separately (1). Its earlier failure constructed an invalid Command before
  reaching the intended guard; no production assertion was weakened.
- Independent export: **62 passed in25.80s**, including the final source STATUS/STOP
  race and real ordinary-UID Control/STOP/new-work-denial path.
- Ruff and Format passed all11 changed Python files; Diff whitespace check passed.
- The194004499ns fixture still fails admission; assertions retain10ms and exact
  timestamps. No failure is promoted to normal processing or Native success.
- Test development failures are preserved: two initial fixture-expectation failures
  and one SHA mismatch when a candidate/source edit overlapped a test build.
  Final checks use frozen source; no Native execution was retried for those tests.

## Evidence Integrity

Private evidence: `.git/native-soc-phase-d/live-062/`. Reservation/FAILED finish are
append-only in the existing campaign ledger. `native-attempt-file-hashes.json`
freezes the executed candidate/session files; evidence-review.json, DNS replay,
Audit review and installed-file review are new separate files. Four SQLite audit
chains were checked using mode=ro, without recovery/checkpoint or record rewriting.
Previous0.6.1 receipts,104 historical records and8 user modifications are preserved.

Before execution, bound source/artifact validation and Workspace/Export/Index
checks passed. New implementation changes intentionally produce a new identity;
the approved0.6.2 image/package/Native receipts were not rebuilt in place. The
pre-execution report is preserved as live-062/report-before-live.md.

## Next Release — Not Executed

Prepared final candidate: **0.6.3**, `.git/native-soc-phase-d/remediation-063/candidate-final/`.
No installation or Native approval is inferred from the0.6.2 approval.

|Identifier|SHA256|
|---|---|
|Manifest|`b1de40f8b801ff9345aefd37d128575438cbaa023618df724e50dc213331349e`|
|Bundle|`c25de380629e312b7feb1a091ae2e3692482459c400a60c4ea764317b71740a9`|
|Execution image|`7f8e299f4b9f7755005a87f5b857cb4d988c6cfa30499b2a8a6e2d8fecf29625`|
|Root manifest|`0bffe3b6fcf36931aa8ea6716bb8883cace3d50ffce5f27ddbb07c5a0e6cd743`|

The earlier unapproved preparation candidate in remediation-063/candidate/ is
preserved and superseded; only candidate-final matches final source. The new image
expects installed0.6.2 and retains it as rollback upon a separately approved atomic
replacement. Older0.6.1/0.5.16 backups stay intact. No capability/scope expansion.

## Final Decisions

|Area|Decision|
|Integrated Native E2E|FAILED|
|OS authentication/shared session|VERIFIED within this run|
|TCX Kernel load/attach/data transport|VERIFIED|
|TCX processing/Capture Integrity|FAILED at recorded late event|
|DNS controlled parsing and internal analysis deadline|VERIFIED|
|DNS complete sidecar lifecycle/Root capture Counter|INCOMPLETE / UNKNOWN|
|Network14 candidates|4 INCOMPLETE,0 eligible|
|Owned TCX Maps/Links absent|VERIFIED at final Inspector observation|
|Overall Cleanup/global Program preservation|UNVERIFIED|
|GUI rendering|PENDING; headless qualification|
|Audit chain verification|VERIFIED read-only|
|Native AI / DNS9 / Production|BLOCKED|

## Remaining Blockers

Identify the cause of the large pre-reservation event-time inversion without
fabricating times or weakening admission. Establish attribution for the extra
cgroup Programs before asserting complete resource preservation. Verify the new
Control/DNS isolation and terminal-evidence fixes under a separately approved
exact0.6.3 run; no automatic retry. Native clock attestation, complete Flow windows,
golden parity/model receipt and GUI rendering still need their own evidence.

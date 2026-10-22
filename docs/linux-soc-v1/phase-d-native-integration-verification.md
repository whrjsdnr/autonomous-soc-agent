# NATIVE_SOC_PHASE_D Native Verification Report

## Overall Status

**PARTIALLY_VERIFIED.** The authorized 0.6.1 integrated execution ran once.
TCX load/attach, packet delivery, owned-resource cleanup and actual DNS parsing
were observed. The integrated execution **FAILED** its DNS analysis deadline;
there was no automatic retry. DNS CLOSED is not equivalent to timely process exit.
The 0.6.2 fix below has only nonprivileged validation and needs separate approval.
Native AI, DNS9 and production promotion remain BLOCKED.

## Approval

- Git execution baseline: `8cb39798574dbfa329d101756fdf1620bd4bac2a` (then HEAD = origin/main).
- Release: **0.6.1**.
- Manifest SHA: `6aed33cbf761adb2e391783b6746a7815a5ce7a054953bd7214350ff82d0c2d3`.
- Bundle SHA: `ef7e223759b3efbb36486b53a5076ed87aed1934bf2195af26abd39890add812`.
- Execution image SHA: `c3857752a1ab8abdefd7c14516a66fb3740b01d14e9dd5ea9447d344db98e562`.
- Root manifest SHA: `1f205935cdb344178a848108b508d20a9f6e1028ad56f718b0a61cb4269478d3`.
- TCX object SHA: `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06`.
- Approval receipt SHA: `8be0ef066b5be369df49fd7e4eed21570749108104f24faefa6ed8736aba465e`.
- Receipt: `.git/native-soc-phase-d/stabilization-061/approval-061-user.json`,
  materialized from the user's explicit exact-image approval, not inferred from a
  development instruction. It is public decision metadata, not an auth token.
- Scope: `net:[4026531833]`, lo/Ingress, <=300s/4096 events/Queue32;
  privileged roles AS256MiB/CPU20s. DNS: same namespace/lo, <=10s total,
  <=7s capture,32 packets,snaplen512, local127.0.0.53:53,
  native-0516.localhost. A, exactly UDP1/TCP1. No external queries.
- Existing systemd-resolved listener was reused; no DNS/offload/settings change.

## Execution

- Attempt: `e97ef66d2ef547eb942ad06457db1166`; reserved before the executor.
- One visible OS terminal, one pinned `sudo -k -u root -- /usr/bin/python3 -I -S -c`
  invocation. Scope confirmation used `yes`; passwords were neither captured nor logged.
- Installation: **VERIFIED**, nine Root-owned files, modes0555/0444, payload/dependency
  verification passed after installation. Only manifest.bin/release.json/release.trust
  changed from the previous install; unchanged binaries retained their SHA.
- Installed version: **0.6.1**. Original0.5.16 retained under
  `/usr/libexec/.soc-agent-ebpf.rollback-2e5faaf4dac7381157adcc82b61465316946aa115c501073f25eb95ee9282289`.
  No rollback was executed. The prior install was never silently deleted.
- Supervisor session: `aa793b01-027b-4f43-9b57-ca69a73afb26`.
- Inspector: own SYS_ADMIN permitted/bounding mask2097152, effective/inheritable/ambient0
  while idle; authenticated pre/post inspection succeeded. Broker idle E/I/A0,
  P/Bounding549755817984 = BPF+NET_ADMIN. SYS_ADMIN was not given to the Broker.
- TCX: **VERIFIED** Native load and attach, Program6286/tag5d24af0965a164b7,
  Link10, ifindex1, attach type46, no pinning.
- TCX packets: **2763 received / 2763 Network14 accepted**, zero discarded/rejected.
- DNS: **12 copied packets**, UDP2/TCP10, all CHECKSUM_PARTIAL_CONFIRMED,
  GSO false, no copy rejections. Original/corrected receipts and chain verified by
  the existing consumer; raw analysis frames were not persisted.
- Zeek: **2 queries,2 responses,2 matched transactions (UDP1/TCP1)**,
  Analyzer dispatch4, checksum rejection0, DNS adapter accepted2/rejected0.
  Raw-IP metadata12 remained UNSUPPORTED and was excluded from Network14.
- Counter and CLOSED were received, sequence19, no duplicate/sequence gap.
  Docker exit0/container absent, but `protocol_finalized=false` because the strict
  analysis deadline failed. Session DNS visibility remains UNKNOWN; readonly
  stream review independently proves only the controlled local DNS was observed.
- GUI: not launched in this headless qualification; actual rendering remains PENDING.
  Ordinary-user normalized DNS diagnostics persisted four events. No AI inference.

## Root Cause Analysis

### First failure and evidence

- Surface: DNS_TASK / Future.result / ZEEK_LIVE_INTEGRITY_FAILED.
- Original: **ANALYSIS_BUDGET / time.monotonic / ZEEK_ANALYSIS_SESSION_DEADLINE**.
- Exception: ValueError; errno **not applicable**, not a Kernel permission errno.
  No signal, container exit0. Original cause is retained in Zeek exit.json and
  Supervisor first_failure; it is separate from TCX cleanup.
- Evidence: `.git/native-soc-phase-d/stabilization-061/candidate/`
  `supervised-result.json`, DNS `live-attempt-1/zeek/exit.json`, stream.jsonl,
  session-timing.json, container-timing.json and probe.json. Immutable hashes are
  in `native-attempt-1-file-hashes.json`; none of those records were edited.

### Reconstructed timeline (one monotonic domain)

|Stage|Seconds since DNS worker authentication|
|---|---:|
|Analysis process launched|0.091721|
|Zeek script init|2.424574|
|Zeek READY|2.443022|
|Capture started|2.443523|
|Capture CLOSED|9.280183|
|Analysis input closed|9.375903|
|Counter received|9.441751|
|Zeek CLOSED received|9.441965|
|Strict analysis deadline|9.500000|
|All DNS cleanup complete|9.774063|

Docker wall-clock events independently recorded create/start/die/destroy; those
wall timestamps were not directly compared to Kernel packet timestamps.
Capture lasted6.836659s, below7s. The overall10s limit was met, but the separate
9.5s analysis limit was not. Post-CLOSED process EOF/exit was still pending.

### Hypotheses and conclusion

|Hypothesis|Check / actual evidence|Decision|
|Checksum or DNS parser failure|Analyzer2 queries/2 responses, rejected0|Excluded for this local test|
|Missing stream terminal|Counter and CLOSED sequence19 present|Excluded|
|Counter/schema corruption|Readonly replay validated all19 records|Excluded|
|Whole DNS session exceeded10s|Cleanup at9.774063s|Excluded for recorded completion|
|Cold start consumed finalization budget|READY2.443s; capture allowed until9.25s, analysis deadline9.5s; exit pending at cutoff|Confirmed budget-allocation defect|
|Resource leak caused the timeout|Owned workers exited, container absent, final maps/links empty|No evidence of leak|

The old capture endpoint reserved only0.25s before the strict analysis deadline,
although completion also required stdin EOF, Zeek finalization and Docker EOF/exit.
Actual CLOSED arrived before that cutoff, but Docker exit did not. This is a
stage-budget defect, not evidence that successful DNS parsing can waive deadlines.

### Fix / reproduction / uncertainty

- `dns_copy_engine.capture_deadline()` now stops capture by total deadline-1.25s,
  leaving0.75s before the unchanged analysis deadline and the existing0.5s final
  cleanup reserve. Capture still never exceeds6.9s; a late READY shortens capture
  or fails before READY. Neither the10s outer limit nor9.5s analysis limit increased.
- `offload_session` failure receipts now retain the safe original exception chain;
  secret/raw stderr is not recorded. Existing Supervisor original-cause handling stays.
- New tests reproduce the recorded budget overlap, cold/late READY boundaries and
  strict failure even when CLOSED exists. No assertion grants an overdue run success.
- Two diagnostic embedding tests now use an actual ordinary-user0.5.16 package
  fixture instead of depending on the host's installed version. The Phase D preauth
  test verifies the descriptor's exact previous manifest rather than a fixed old SHA.
  Production installation checks were not relaxed.
- Additional0.5s finalization headroom is not a Native performance guarantee.
  Native0.6.2 timing and successful combined termination remain **PENDING**.

## Network14

- Counter generation1389916063768940779: observed2769,emitted2763,
  delivered2763,disabled6,unsupported0,malformed0,ring reservation failure0.
  Snapshot query succeeded; observed=emitted+disabled. Kernel-wide drops UNKNOWN.
- Data sequence2766 includes terminal/control frames; packet count2763 is separate.
- CPU observation attempts have4 initial forward gaps. They are not4 lost delivered
  packets. Disabled observations can create gaps, but aggregate counters do not
  prove per-packet/per-flow attribution. Completeness remains conservative.
- Four clock inversions, max309ns, reordered4,late0 under10ms/32-event policy.
  Original Kernel ns were retained; calibration DECLARED_ONLY/native accuracy UNVERIFIED.
- Nine feature candidates, all INCOMPLETE and Native AI blocked. Their packets sum2763.
  Stop was triggered by DNS failure before idle30s/active120s observation evidence;
  attempt-gap quarantine also prevents completeness. FIN/RST do not independently
  override the trained timeout-window contract.
- All nine retained checkpoint vector receipts have valid14-feature float32/digest
  evidence. Raw vectors are retained for only the final four and revalidated there;
  the preceding five use checkpoint receipts, not invented raw vectors.

|Flow prefix|Packets|Input state|Vector evidence|
|`338ca50430a9`|540|INCOMPLETE|CHECKPOINT_RECEIPT|
|`4ee2b99ab029`|894|INCOMPLETE|CHECKPOINT_RECEIPT|
|`a753f2e4813e`|478|INCOMPLETE|CHECKPOINT_RECEIPT|
|`90f0f27c43a7`|827|INCOMPLETE|CHECKPOINT_RECEIPT|
|`484764f21044`|4|INCOMPLETE|CHECKPOINT_RECEIPT|
|`fafc1e1957a0`|2|INCOMPLETE|VALUES|
|`b628bf37f067`|10|INCOMPLETE|VALUES|
|`1f4cd9686455`|4|INCOMPLETE|VALUES|
|`53d8ac3b89c1`|4|INCOMPLETE|VALUES|

- Final top-level candidate RCA incorporates terminal counter evidence (ring0).
  Nested processing checkpoint `RING_LOSS_UNKNOWN` predates final counters and is
  not the final RCA. No old receipt was rewritten to conceal this distinction.
- Other remaining reasons: capture integrity unproven, clock calibration unverified,
  Native golden parity unknown, model artifact receipt unknown, policy blocked.
- Historical four0.5.16 candidates remain INCOMPLETE; two unpreserved historical
  candidates remain UNKNOWN. These nine are a separate Native observation.

## Performance

- Queue peak14/32; socket send failures0/EAGAIN0; queue rejection0/discard0.
- Receiver max recv gap743.013469ms includes waiting for traffic; it is not proof
  of a743ms processing stall. Max recv syscall1.667139ms, packet processing1.763052ms,
  queue wait3.088412ms; no unsupported throughput claim.
- Audit16/16 FULL SQLite commits, failure0/rejection0/outstanding0;
  max commit23.540475ms, total259.720367ms.
- No before/after Native performance comparison: only0.6.1 ran. Peak RSS/CPU and
  full end-to-end capture rate were not measured. No GUI/model benchmark repeated.

## Cleanup

- TCX Ring/Data/Processing/Audit Drain: **VERIFIED**; CLOSED received, queue0,
  workers exited. Map3/Program1 observed FDs returned EBADF after libbpf close;
  raw close return values were not observed. Link state TCX_CLEANUP_VERIFIED.
- Root Supervisor and Inspector exit0, Inspector authority revoked/channel closed;
  application authorization REVOKED/Broker CLOSED. No automatic restart.
- Post-inspection: maps0,links0,lo ingress0/egress0, same11 cgroup Programs retained.
  New TCX program absent. Query success, not EPERM interpreted as absence.
- DNS capture worker exited0; Docker die/destroy observed, container absent,
  analysis worker exited; sockets finalized. Resource cleanup is VERIFIED by the
  separate owned-process/container and Inspector evidence. DNS protocol/deadline
  integrity FAILED; that failure is not reclassified as a successful normal drain.
- Root summary `zeek_container_removed=false` applies to its unused legacy Zeek
  branch. Analysis-copy container absence is evidenced independently in DNS exit.json.

## Verification

- Changed budget/embedding/preauth contracts: **38 passed**.
- Actual pinned Zeek with synthetic memory-only input: **7 passed**, network-none,
  cap-drop-ALL; these are offline Analyzer tests, not additional Native capture.
- Existing122 related cases: **122 passed in225.87s**, recorded in post-native-regression.log.
- Independent source export: **38 passed in32.83s**.
- Ruff/Format/Diff: all six changed Python files passed; no diff whitespace errors.
- No full model regression or GUI performance work; those components were unchanged.

## Evidence

- Native reservation/finish appended to existing execution-ledger.jsonl; its initial
  creation line and budget/baseline bytes remain unchanged. No ledger reset.
- Prior report preserved as stabilization-061/report-before-native.md.
- All104 historical evidence hashes and8 user modifications preserved.
- Four current SQLite audit chains read with mode=ro and independently verified:
  Controller26, preparation collector6, TCX processing20, DNS diagnostics6 records.
  No recovery/checkpoint was applied to historical databases.
- Pre-execution Workspace/HEAD/export SHA equal for all10 prior task files.
  New source/export/index comparison is in remediation-062/verification.json.
  Runtime source bytes changed after the authorized run; the original approved
  image/manifest/evidence remain frozen and were not rebuilt in place.

## Budget

- Native: **1/5 used,4 remaining**.
- Root installation: **1/5 reserved/used,4 remaining**; actual replacement succeeded.
- Original budget declaration remains0/5; effective use derives from the append-only
  reservation. Failed execution consumed its one reservation. No second session ran.

## Git / Next Release

Prepared but **not installed or executed**: **0.6.2**.

|Identifier|SHA256|
|---|---|
|Manifest|`a63034f77d3a4ea9b1b2f9398adb2c2ceef53eff8ac3db3b21f5d16b14d09416`|
|Bundle|`d2425596030b1bc07b6e60e6c0bedacbeaf9deb2c8b9d029c042d1b8d802cc6d`|
|Execution image|`e131aafd8c5f52664c78b3585f0c0638696d76f5d3e4a69e1866faba3ace1b0c`|
|Root manifest|`56e1b7bc8a2a7a2ebd6902899f349b5fae7432f24d492ce8dab1a92b90e72dc4`|

Candidate `.git/native-soc-phase-d/remediation-062/candidate/` validates against
current source. TCX object unchanged. Its pinned image expects current0.6.1 and
retains that version as rollback on an approved atomic replacement. Existing0.5.16
rollback remains untouched. No0.6.2 approval receipt has been created.

## Final Decision

|Area|Decision|
|Unified Native integration|FAILED at DNS analysis deadline|
|Single authentication/session/Inspector|VERIFIED within this run|
|TCX load/attach/data delivery|VERIFIED|
|DNS controlled-local parsing/matching|VERIFIED by retained Native stream review|
|DNS complete lifecycle within all stage budgets|FAILED;0.6.2 Native PENDING|
|Network14 Native input eligibility|INCOMPLETE;9 candidates,0 eligible|
|Kernel/container resource cleanup|VERIFIED with stated FD evidence limits|
|GUI rendering|PENDING; headless qualification|
|Audit chains|VERIFIED read-only|
|Native AI / DNS9 / production promotion|BLOCKED|

## Remaining Work

Separately approve exact0.6.2 installation and one Native run in the unchanged
scope to test the stage-budget fix. No automatic retry is authorized. Verify
cold-start exit timing and the complete10s lifecycle. Clock calibration, complete
flow observation, Native golden parity/model receipt and actual GUI rendering
still need evidence before AI input or broader E2E success can be declared.

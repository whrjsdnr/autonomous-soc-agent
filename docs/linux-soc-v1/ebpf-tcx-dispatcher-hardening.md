# Phase B-2D — TCX continuation and dispatcher hardening

## Scope and baseline

Baseline: `3955d646c570c355fac541419b009091a067ecb7` (main). This release candidate adds a separate TCX observer and a Broker-local dispatcher. No sudo/PAM, BPF load, hook attach/detach, qdisc changes, capture or test traffic ran. Native release, Native AI, DNS9 and operational promotion remain BLOCKED. Legacy TC Native attach/detach remains unsupported.

The initial index was empty. Existing 132 user files across SOC/ML, 394 protected evidence/source/artifact files and 58 raw-dataset stat records are checked separately from this task. Existing sessions, archives and audit chains are read-only. Original Legacy object SHA remains `69de609ea8ee90ecf90d091ec361e46e61ed0638b3175390c77305145e19d5f4`.

## 1. Return semantics and kernel evidence

[Linux 6.18 dev.c](https://github.com/torvalds/linux/blob/v6.18/net/core/dev.c#L4106) stops its TCX program loop on any return other than `TCX_NEXT`. Ingress and egress invoke Legacy TC only when the TCX result remains UNSPEC. Therefore OK/PASS is insufficient for an observer that must preserve subsequent filters.

| Return | TCX meaning | Later TCX | Legacy TC |
|---|---|---|---|
| TC_ACT_UNSPEC / TCX_NEXT (-1) | Continue | Evaluated | Evaluated if the chain continues |
| TC_ACT_OK / TCX_PASS (0) | Accept | Skipped | Skipped |
| TC_ACT_SHOT / TCX_DROP (2) | Drop | Skipped | Skipped |
| TC_ACT_PIPE (3) | Not the TCX continuation contract | Loop stops | Unknown-action mapping can reach Legacy |

[tcx_action_code](https://github.com/torvalds/linux/blob/v6.18/include/net/tcx.h#L136) maps unrecognized action values to NEXT after the loop has already stopped. PIPE consequently cannot substitute for NEXT. The separate program uses NEXT on every path. Object disassembly checks both optimized return epilogues, including disabled, malformed, unsupported, loss and budget branches.

These are upstream source contracts, not a verifier or compatibility test of the running Microsoft kernel. Official source URLs and retrieved SHA values are in the evidence JSON. Installed libbpf/header compatibility is compile/link-tested; Native capability remains pending.

## 2. Separate TCX program

`ebpf_tc/tcx.bpf.c` has distinct `tcx/ingress` and `tcx/egress` sections. It reuses the existing parser and event ABI without editing Legacy sources. IPv4/IPv6 TCP/UDP metadata, bounded per-CPU counters, a 256KiB ring, timestamp, interface and generation are retained. No packet payload is emitted or retained. Unsupported encapsulation, fragments, truncation and parser errors retain their existing classification.

The observer body is intentionally separate to preserve the approved Legacy object byte-for-byte. Parser/event contracts remain shared; future observer-body changes require the two implementations to be reviewed together. Compilation is not kernel verifier acceptance. Bounds are unchanged (300s, 4096 emitted records at userspace, queue32, 256MiB Broker address space, CPU20s); per-CPU observation counters are not kernel packet-drop counters or Zeek handle attestation.

## 3. Coexistence policy

[Linux mprog attach](https://github.com/torvalds/linux/blob/v6.18/kernel/bpf/mprog.c#L210) appends when relative target and flags are zero. The provider sets neither BEFORE/AFTER nor REPLACE, does not update existing programs, and never removes qdisc or positional filters. No peer-supplied ordering, object path, Link ID, pin path or FD is accepted.

Appending NEXT preserves existing program order and verdicts. An earlier external PASS/DROP/REDIRECT can prevent our observer from running. That is a visibility limitation, not zero traffic or verified capture coverage. Snapshot state is `APPEND_ONLY_VISIBILITY_NOT_ATTESTED`; Native AI stays blocked. Unknown external programs and privileged concurrent updates require Native qualification. Fixture evaluation checks pass, drop, redirect, continuation, PIPE, later programs and Legacy fallback; it is explicitly not a kernel execution test.

## 4. Dispatcher and Broker

The same six-command allowlist and 112-byte request schema are retained. A version2, 272-byte approval plan selects TCX; version1 remains Legacy. The mode is covered by the approval digest. Changing it invalidates approval. Python Native handoff and C admission gates remain closed; there is no command-line/environment override.

The actual Broker command loop branches into `soc_tcx_dispatch`. Existing peer credentials, start ticks, sealed object, message validation, sequence/rate limits, heartbeat and run history remain in front of this dispatcher. TCX load validates distinct section names and expected attach types, all existing map ABI checks and the approved object SHA. Only the selected hook is loaded. No Legacy filter snapshot or positional mutation is used by TCX.

LOAD precedes creation of a private Link FD. Config stays disabled until Link identity and journal commit succeed. The Broker owns the FD; replies retain the bounded owner schema rather than exporting it. Stop disables emission, detaches that held Link, verifies detached state and closes once. Explicit new runs require new generation/run identity; failed or ambiguous operations do not auto-retry. A load partially allocating resources is released even before loaded-state publication.

The root installation's old Legacy manifest is not automatically upgraded to TCX. A version2 plan alone cannot authorize a different object or open the release gate.

## 5. Link ownership and cleanup

[Linux TCX Link release](https://github.com/torvalds/linux/blob/v6.18/kernel/bpf/tcx.c#L158) removes the exact Link object under RTNL. This avoids positional Query/Detach replacement of a foreign filter. Broker evidence includes session, generation, namespace, broker PID/start ticks, program SHA/ID/tag, Link ID, interface and attach type. Link ID is descriptive, not deletion authority.

Only the held FD is used for query and explicit detach. The post-detach info check requires ifindex0 before closing. An ambiguous close is never retried against a potentially reused descriptor. No Link pinning, get-by-Link-ID or program update entry is provided. A duplicate/pinned reference can prolong attachment after process crash; explicit detach and post-verification are required before cleanup claims. External reference/pin absence is UNKNOWN. A privileged external actor that obtains the same Link may update its program between inspection and detach; held-FD authority identifies our Link object, not an atomic program-version predicate. This candidate does not claim immunity from that administrator race or erase a different Link; Native coexistence/ownership qualification remains blocked. Identity mismatch, partial attach/detach, interface disappearance, audit failure and lost FD remain ORPHANED/CLEANUP_UNVERIFIED. Recovery never reattaches.

## 6. Journal, audit and recovery

Existing 192-byte Legacy rows remain unchanged. TCX rows are 240 bytes and selected by a fixed TCX event-kind allowlist. They share the session approval, request sequence, ordinal, previous digest and SHA256 chain with Legacy rows. Full Link identity is recorded without an FD number or credentials. Bound: 1024 records / at most 240KiB. fsync commits before advancing the chain; IPC backpressure fails closed, with local cleanup evidence still writable after controller loss.

Events: TCX_ATTACH_REQUESTED, TCX_LINK_CREATED, TCX_LINK_VERIFIED, TCX_DETACH_REQUESTED, TCX_LINK_RELEASED, TCX_CLEANUP_VERIFIED, TCX_CLEANUP_UNVERIFIED. CREATED may precede successful identity inspection; its missing Link ID is never fabricated. Mutation without final cleanup is reported for orphan review. Readers reject partial/changed/corrupt files and wrong approval. A valid chain is a claim, not independent Native attestation or process-exit proof.

A separately approved, once-only application fixture invokes the same C dispatcher with fake providers, appends `TCX_DISPATCHER_FIXTURE` to the existing audit, and publishes GUI state only after audit success. The nested fake journal and owners are labelled synthetic. Actual Native provider events are never synthesized by this fixture. Recovery restores no authentication, attachment or inference.

## 7. Authentication and privileges

Startup terminal password once per application session is unchanged. Same-scope explicit Start/Stop/Restart does not prompt again; a new application requires new authentication and approval. No password/token storage, GUI password prompt, sudo-cache authority or GUI root inheritance is introduced. Bootstrap only links system authentication/crypto libraries; Native Broker embeds loader code. Candidate capabilities remain CAP_BPF and CAP_NET_ADMIN, subject to actual kernel/PAM/root-installation qualification. No actual privilege transition occurred.

## 8. GUI and downstream preservation

Dashboard, Security Events, Investigation and System retain their cards/charts/timelines. System additionally shows TCX candidate object SHA, dispatcher state, coexistence/visibility limitation, Broker state and existing Link/cleanup/Native gate fields. UNKNOWN stays distinct from zero. Preparation verifies both candidate Object and fixture executable hashes against fresh source builds; no Native launch option is added.

Zeek, DNS analyzer, visibility diagnostics, Network14 30s idle/120s active contract, Float32/order/digest/golden validation, model artifacts and READ-only investigation are preserved. Kernel and Zeek provenance remain separate. No Native fixture result promotes an incomplete flow or AI policy.

## 9. Tests and performance

Final source-bound results, artifact hashes, export manifest digest, source evidence and resource observations are in `ebpf-tcx-dispatcher-hardening-evidence.json`. Existing evidence from prior phases remains unchanged. Two initial assertion defects (unsigned disassembly formatting of -1; six lifecycle rows rather than seven) are recorded in private logs and corrected explicitly, not hidden by unchanged reruns. SIGILL root cause remains UNKNOWN.

## 10. Release blockers and next approval

Native release remains BLOCKED pending trusted root installation/dependency verification, terminal PAM authentication, actual least-capability transfer, Microsoft-kernel verifier/TCX support, coexistence/visibility observation, held-FD cleanup and explicit user approval. Legacy TC attach/detach stays BLOCKED. Native AI, DNS9 and operational promotion stay BLOCKED independently.

Future approval must bind the new Bootstrap/Broker/Loader/TCX object hashes and bundle, a fresh application/session, namespace, lo, one chosen ingress/egress hook and unchanged budgets. Initial validation forbids pins, external program replacement, filter/qdisc deletion, automatic restart and AI promotion. Root installation, Native kernel calls and actual password entry require a separate review; there is deliberately no runnable Native capture command in this release. Use the existing nonprivileged preparation/fixture tools to inspect candidates. Do not run development-directory binaries as root or reuse prior approval hashes.

## Final qualification results

- Final affected TCX/Bootstrap/ownership/GUI suite: **147 passed**. This supersedes intermediate 146-PASS evidence after the additional gate-interposition test.
- B-1 Broker: **63 passed**; existing unit regressions: **693 passed**; existing integration: **58 passed**; WSLg GUI preservation: **17 passed**; policy/Audit/Recovery: **125 passed**. Counts are separate and are not added to earlier attempts.
- Actual pinned Zeek 9.0.0 offline PCAP + RF/LR integration: **1 passed**, two COMPLETE receipts, READ-only investigations, queues drained to0, recovered audit digest unchanged, zero new recovery inferences. RF latency15.73ms; LR6.25ms. This is offline research evidence.
- The model test was initially NOT STARTED because PSI avg10=0.27. After GUI/Audit, three preflight samples had avg10=0.00 and >4.3GiB available; its first actual execution passed. No test failure was hidden by retry.
- One final review added independent TCX checks before Dispatcher and Loader work. The final 147-test suite covers both. Other regression source/tests were byte-identical; the evidence lists the three differences from their earlier export.

Same-environment measurements (3 WSLg starts per group, baseline3955d64):

| Metric | Before | After |
|---|---:|---:|
| GUI startup median | 2.144s | 2.235s |
| GUI idle RSS median | 175.059MiB | 174.942MiB |
| Idle CPU, one core | 0.240% | 0.235% |
| GUI response p50 | 0.01056ms | 0.01067ms |
| Developer preparation including fresh reference compilation | 3.770s | 4.499s |
| Fixture supervisor RSS median | 144.301MiB | 144.234MiB |
| Fixture IPC status median | 1.511ms | 1.733ms |
| B-1 fixture cleanup median | 256.25ms | 248.50ms |

Startup increased about4.2%; memory changed by about0.12MiB. These small samples do not establish an optimization improvement. Developer preparation adds a distinct BPF compilation and hash qualification. Shared host parser (100 warmup; five groups of10000) measured1327ns vs1152ns per call through ctypes; its source is unchanged, so this variation is not an algorithmic gain. Fake Link core medians: attach49→92ns, identity34→39ns, detach62→98ns, including extra evidence callbacks. Separate C dispatcher process + fsynced fake journal:17.51ms median over five runs after one warmup; observed peak RSS5.6–5.8MiB. Native kernel processing, Native Broker RSS and Native active RSS remain UNKNOWN. WSL has12 assigned CPUs; other processes were not stopped. Resource samples accompany measurements.

Build identities (unprivileged compile, not installation):

- `bootstrap`: `60fc1ffb70c009f1ba4ad691df6e0baa656d1c8724d532b829a5b81e537d3c54`
- `broker`: `70bda695d3569330b4daf6870412544d749e00c765516dd46b923b97ffd3ff4b`
- `libnative-tc.so`: `99036271b5db0cf5370ed13a1446cc72e3e117c40ae7cb8e31945bef03d7367d`
- `tcx.bpf.o`: `928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a`
- Source bundle: `55a6923866d07489d7ce6a62a302eec35e920866f7ea57111362709778687847`

Independent export, wheel/source bytes, Ruff, format, diff and rebuilt artifact SHA qualification are recorded in the companion JSON. Only this task's files are eligible for staging; binary outputs, model files, Native evidence, Replay and existing user changes are excluded. The executable candidates remain uninstalled and inadmissible.

Final verdicts: TCX_RETURN_SEMANTICS_VERIFIED (upstream contract), TCX_PROGRAM_COMPILE_VERIFIED, TCX_COEXISTENCE_FIXTURE_VERIFIED, TCX_DISPATCHER_FIXTURE_VERIFIED, TCX_LINK_OWNERSHIP_VERIFIED (fixture only), TCX_CLEANUP_FIXTURE_VERIFIED, GUI_PRESERVED, AUDIT_RECOVERY_VERIFIED. LEGACY_TC_NATIVE_BLOCKED, NATIVE_RELEASE_BLOCKED, NATIVE_AUTH_PENDING, NATIVE_VERIFIER_PENDING, NATIVE_TCX_ATTACH_PENDING, NATIVE_AI_BLOCKED, DNS9_BLOCKED and OPERATIONAL_PROMOTION_BLOCKED.

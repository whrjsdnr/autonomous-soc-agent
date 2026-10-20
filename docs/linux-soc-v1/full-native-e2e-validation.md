# Full Native E2E validation

## 1. Architecture and evidence boundary

The release at `ff582d0e1c85787a549ddd957b91ee24c349d015` does **not** demonstrate
Native packet → AI → SOC → GUI E2E. A historical Zeek session demonstrates Native
metadata capture and process finalization. A separate real offline PCAP demonstrates
Zeek → Network14 → unchanged RF/LR artifacts → READ-only investigation → audit/recovery.
These are different sessions and cannot be joined into one Native success claim.

The audit freezes the committed release in an independent Git archive. Existing dirty
workspace files are preserved, excluded from the candidate, and not claimed to have
passed release qualification. No root/authentication/kernel/capture operation was run.

| Layer | Implementation and contract | Executed evidence | Native blocker |
|---|---|---|---|
| CLI/startup | `cli.py`; total/zeek-live; separate `ebpf_tc` prepare/handoff commands | CLI fixtures | Main startup CLI has no TCX collector choice |
| OS authentication | Fixed sudo argv, session/approval/release digests, TTY contract | Policy mocks; actual ordinary-UID IPC | Effective sudo/PAM/password policy unqualified; admission returns false |
| Trusted release | Fixed `/usr/libexec/soc-agent-ebpf`, held-FD root/mode/SHA/dependency checks | User-owned install simulations | Directory absent; `native_install()` explicitly rejects |
| Bootstrap | `os_bootstrap.c`, no custom PAM or setuid | Compile, ELF inspection, denied-entry tests | C Native and OS admission gates closed |
| Broker | Fixed six-command ABI, numeric credentials and sealed FD transfer | Real unprivileged C/Python transport | No authenticated privileged execution |
| Supervisor | PID/start ticks, lifetime, crash, queue and cleanup contracts | Fixtures | Native process/capability lifetime unmeasured |
| TCX collector | Shared parser, bounded maps/ring, TCX_NEXT, private Link FD | Compile and host-parser fixtures | Verifier and actual hook pending; Native admission false |
| Zeek collector | Pinned 9.0.0 image; separate offline/live provenance | Offline execution plus historical Native session | Same-handle counter success/coverage unknown |
| Packet normalization | Separate Zeek standard events and eBPF ABI validation | IPv4/v6/TCP/UDP/adversarial fixtures | No admitted live TCX handoff-to-normalizer route |
| Network14 | Existing 14 float32 features, 30s idle/120s active | Matched golden PCAP/parser/ML comparison | Native packet population/window equivalence not proven |
| DNS | Zeek transaction adapter and diagnostic stages; eBPF port53 candidates | Actual offline DNS callbacks and negative fixtures | Historical Native analyzer/header evidence absent |
| Feature quality gate | Capture/flow/feature/artifact/policy checks | Eligible offline and blocked Native cases | Native integrity and policy remain blocked |
| Quality RF | Existing SHA-pinned artifact, no new scaler/imputer | Actual isolated offline inference | Native eligibility blocked |
| Edge LR | Existing artifact includes fitted StandardScaler | Actual isolated offline inference | Native eligibility blocked |
| SOC investigation | Existing evidence/assessment/policy READ-only route | Offline receipt → assessed investigation | No eligible Native model result |
| GUI | Dashboard/Security Events/Investigation/System, existing charts | Actual GUI fixture checks | No complete Native AI/GUI session |
| Audit/recovery | Append-only chain, identities/receipts; no automatic replay | Offline recovery and crash fixtures | Actual TCX crash/link cleanup untested |

## 2. Baseline and preservation

SOC HEAD and origin/main initially equal `ff582d0e1c85787a549ddd957b91ee24c349d015`;
ML HEAD is `e1a01260f0463a38d4d778859bc2a86f8e9cfbde`. Initial stage empty.
132 existing changed/untracked files (SOC122, ML10) are hashed independently.
Prior protected Native/model/helper evidence and raw dataset stat inventories are
checked before commit. Private audit: `.git/full-native-e2e-audit/`.
Only this report, its evidence JSON and a packet/control boundary reproduction test are release changes; runtime code is unchanged.
No failure justified weakening a gate or inventing an unqualified live adapter.

## 3. Authentication

The application-session contract remains one terminal password at startup, then
explicit Start/Stop/Restart within that scope without another password. New app,
broker death, expiration or scope change cannot restore previous authority.

The fixed proposed invocation uses `/usr/bin/sudo -k -u root --` and the installed
bootstrap plus numeric UID/GID/session/approval/manifest arguments. It is **display-only**
in the current admitted path. `soc_os_auth_admitted()` returns false and the manifest
accepts only `native_release=BLOCKED`. No actual password policy was exercised.
The sudo `-k` command form ignores cached credentials but still depends on the
security policy requiring authentication; it does not prove NOPASSWD cannot apply.
See the [upstream sudo manual](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/docs/sudo.man.in).
No password, token or authority is persisted; GUI/model processes remain ordinary UID.

The preserved Zeek startup calls `cli.terminal_authenticate()`, currently `sudo -v`,
then fixed `sudo -n` Docker commands. That path does not independently establish a
fresh password when the OS cache or NOPASSWD policy applies. Its historical success
is not evidence of the stronger fresh-per-application password requirement. Existing
Zeek approval/helper contracts are not silently changed during this qualification.

## 4. Trusted installation

The fixed installation is absent on this host. Packaging, root ownership/mode,
parent trust, dependency closure, sealed FD and installation/rollback simulations are
implemented. `installation.native_install()` deliberately raises instead of changing
`/usr/libexec`. User-owned package verification does not prove root installation.
Previous custom setuid manifests remain rejected; there is no setuid restoration.

## 5. Kernel TCX

Read-only preflight finds kernel `6.18.33.2-microsoft-standard-WSL2`, libbpf `1.3.0`,
BTF `/sys/kernel/btf/vmlinux`, namespace `net:[4026531833]`, lo ifindex1.
Read-only kernel config confirms BPF/BPF_SYSCALL/BPF_JIT/DEBUG_INFO_BTF=y and NET_CLS_BPF=m; bpffs is not mounted at `/sys/fs/bpf`. No mount is attempted.
These facts do not establish verifier acceptance or TCX attachment support.
[Kernel libbpf lifecycle documentation](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html)
distinguishes object open, kernel load, attachment and teardown; only compilation and
non-kernel fixtures are qualified here. No bpftool/tc mutation or BPF syscall probe ran.
Legacy TC Native remains blocked for the query/delete ownership race. TCX uses
TCX_NEXT(-1), no pinning and Broker-owned Link FDs, with external links preserved.
CAP_BPF/CAP_NET_ADMIN remain candidates; actual effective/permitted/bounding/ambient
transfer, privilege drop, LSM requirements and CAP_PERFMON necessity are UNKNOWN.

## 6. Zeek and historical Native session

Pinned image: `zeek/zeek@sha256:3fac39de707be96cb1a8163cab98a11bb2a1aa9e3535247db0f17b9c4670a019`.
Historical session: `session-b9fe165ac83046edb2b6f82f14fc4e10`.
Existing files are read-only and their hashes are compared with prior attestation evidence.
A fresh in-memory replay uses the current Stream/normalizer; it neither opens the
session database for writing nor invokes a model or capture process.

Exit evidence: CLOSED true, exit0, cleanup true, 126.717s, sequence4215,
4096 packet metadata records,117 final Network events,0 DNS events. The final Zeek
stop detail is PACKET_LIMIT_REACHED. Earlier GUI101 is not the persisted final count.
`pkts_link=8200`, `pkts_recvd=4096`, `pkts_dropped=0` are reported Zeek counters,
not an independently verified kernel packet/drop accounting proof. Counter retrieval
success and whole-interval same-handle coverage remain unknown; capture UNVERIFIED.
A TCX counter cannot substitute for the Zeek capture handle.

## 7. Network14

The exact ordered features, formulas, units and training preprocessing remain in
[the audited training contract](zeek-realtime-preprocessing.md#network14-training-contract).
Direction is first-observed endpoint pair, packet sizes are full IP bytes, all values
finite float32 after the existing arithmetic. Idle30/active120 event-time boundaries
are preserved. TCP FIN/RST flags do not create a new training boundary.
Golden PCAP, Zeek packet events and host C-parser/eBPF fixture are compared only for
matching admitted windows. Same-key closure vs global training watermark and late
arrival/population differences are unresolved for Native inputs.
Historical replay yields51 finalized windows, all PACKET_LIMIT, none eligible.
Feature metadata generation is not proof of complete flow or eligible Native input.

## 8. DNS

Historical metadata contains68 port53 candidates and0 DNS events. No payload or
FQDN is newly retained. Missing historical header/analyzer/transaction evidence
prevents selecting among non-DNS payload, analyzer dispatch, parse failure, incomplete
exchange, adapter rejection or WSL resolver behavior. DNS visibility stays UNKNOWN.
Offline plaintext query/response callbacks and rejection cases are tested independently.
Port53 metadata alone is not DNS; cache, other interfaces, DoH/DoT can limit visibility.
No new interface or synthetic network traffic was enabled. DNS9 stays BLOCKED.

## 9. RF/LR

Use unchanged actual artifacts and their existing SHA/schema contracts. Isolated
workers validate feature order, float32, digest and eligibility, record receipts only
after inference, and investigate READ-only. Native inference is not attempted.
The offline PCAP test checks two receipts, one per model, bounded queues, cached
request duplicate prevention, worker shutdown and zero new inference after recovery.
Missing metadata is rejected instead of zero-imputed. Models were not retrained.

## 10. SOC Agent

Offline receipts reach evidence collection, assessment, research advisory and report
export through the existing investigation route. Policy remains WRITE_DENIED and
research scores are not operational risk. No firewall/block/process termination tool
was enabled. A Native SOC investigation remains blocked without a valid Native receipt.

## 11. GUI

Existing four screens, charts and timelines are retained. GUI fixture checks exercise
collector/auth/link/cleanup/eligibility projections; they do not create Native live
traffic or Native AI scores. UNKNOWN counter/visibility states are not replaced with
zero. Native GUI E2E remains PENDING. The runtime GUI source was not edited.

## 12. Audit/recovery

Existing chains are never rewritten. Session, source, program/manifest, feature and
receipt digests are verified. Recovery tests require identical recovered receipts,
no new inference, no automatic authentication/capture/reattach and ordinary-UID GUI.
TCX orphan/foreign-link/partial cleanup behavior is fixture evidence only; actual
SIGKILL and last-FD kernel cleanup remain PENDING. Uncertain cleanup is not CLOSED.

## 13. E2E scenarios

Every row is nonprivileged evidence unless explicitly historical. No row proves an
actual Native event was inferred. Fixture audit/cleanup outcomes are checked by the
referenced suite; an actual Native error code/audit/cleanup trace is not available.

| Scenario | Qualified path / expected handling | Test evidence family |
|---|---|---|
| Normal start/stop | Ordinary-UID handoff and offline Zeek drain; Native pending | ebpf_handoff, zeek_live |
| Authentication failure | No child authority, revoked, no retry | ebpf_handoff |
| Manifest mismatch | Entry/release denial before new privileged work | ebpf_release, ebpf_install |
| Broker connection failure | Timeout/EOF revokes session | ebpf_handoff |
| TCX unsupported | No Native admission; missing feature fixture rejects | ebpf_tc, ebpf_install |
| Link create failure | No foreign removal; partial owner state retained | ebpf_tc |
| Ring loss | Counter/event loss not equated with kernel drop | ebpf unit/integration |
| Queue overflow | Explicit bounded backpressure/error | ebpf, zeek_live |
| Network14 mismatch | No receipt; feature gate blocked | ebpf parity, zeek_producer |
| DNS0 | UNKNOWN visibility; no fabricated DNS feature | zeek_attestation, historical replay |
| Model load failure | Artifact/worker failure; no success receipt | research_adapter |
| Inference delay | Bounded worker/deadline policy; no silent retry | research_adapter, streaming_network |
| GUI close | Stop handoff/worker; no new capture | GUI handoff/live checks |
| Broker crash | Revoke; cleanup uncertainty retained | ebpf_handoff, ebpf_tc |
| Controller crash | No automatic restart; private owned-link cleanup fixture | ebpf_tc, zeek_lifecycle |
| Collector crash | Error distinct from normal stop | zeek_live, zeek_finalization |
| SIGTERM | Process-identity/cleanup fixtures, Native pending | ebpf_tc, zeek_lifecycle |
| SIGKILL | Own ordinary-UID fixture only; Native link cleanup pending | ebpf_handoff, ebpf_tc |
| Cleanup failure | CLEANUP_UNVERIFIED/ORPHANED, no auto new capture | ebpf_handoff, ebpf_tc |
| Recovery | Preserve chain and receipts, no restored authority | audit, zeek_preprocessing |

## 14. Performance

All fresh measurements are isolated offline/GUI fixtures. Native authentication,
TCX latency, counters, ring delivery, capability cost and live kernel throughput are
UNKNOWN. Shared-host memory/PSI are recorded before each cohort; model tests run
serially only with available headroom. No Native performance improvement is claimed.
No runtime modification was made, so before/after performance attribution is inapplicable.
The historical approximate GUI reference (2.296s,174.98MiB) is not a controlled paired
measurement against this run. No improvement/regression is attributed from it.

## 15. Root cause analysis and remediation boundaries

| Failure ID | First failing boundary / evidence | Root cause / safe action |
|---|---|---|
| E2E-INSTALL | Trusted directory absent; native_install rejects | Installation is a simulation contract, not an installed release. Keep gate closed; prepare separately reviewed installer/rollback before A. |
| E2E-AUTH | Literal BLOCKED manifest and C admission0 | Actual OS password policy and privileged session are unqualified. An approval alone cannot make current binaries executable; do not patch gates as a test workaround. |
| E2E-AUTH-LEGACY | Zeek StreamProcess.authenticate calls shared sudo -v | Existing OS-policy-dependent path cannot guarantee fresh password. Qualify or revise the entry policy before claiming all-collector startup authentication. |
| E2E-TCX-STREAM | loader.c emit sends80-byte soc_event on control IPC; Handoff._next accepts journal notifications and expects control reply/hello | A live packet consumer/scheduler is not integrated in this handoff. An event arriving where a reply is expected causes schema failure. No native integration claim; require bounded demultiplexing and provenance/clock validation before capture admission. |
| E2E-TCX-CLOCK | event.h timestamp is monotonic bpf_ktime_get_ns | Cannot reinterpret it as Zeek/PCAP UTC. Require explicit session-bound calibration/time-domain contract for any live bridge. |
| E2E-FLOW | Historical current-parser replay:51 PACKET_LIMIT windows | Budget truncation plus unverified capture counters, not model failure. Keep all51 ineligible; do not change finalization/window semantics. |
| E2E-DNS |68 port53 candidates, no analyzer-stage historical proof | Cause UNKNOWN; offline callbacks do not prove historical dispatch. Preserve evidence and diagnose only in separately approved new session. |
| E2E-CAP-KERNEL | No approved privilege transfer/load/attach evidence | Fixture/headers cannot prove WSL capabilities or TCX. Split into B/C qualification after code blockers are removed. |

No newly reproduced runtime regression required a production-code patch. The structural
missing pieces above remain explicit release blockers; silently treating control IPC as
packet delivery, adding arbitrary timestamp offsets, or opening gates would hide them.
The current remediation is a source-linked qualification and an executable nonprivileged
validation record, not an assertion that these Native blockers have been eliminated.
SIGILL root cause remains UNKNOWN.

## 16. Remaining blockers

Trusted installation and effective sudo/PAM policy qualification; actual capability
minimization; Native verifier/TCX/coexistence/cleanup; integrated bounded packet-channel
consumer with correct monotonic time/provenance; same-handle Zeek counter retrieval;
Native window equivalence and complete flow evidence. Existing safe deny gates remain.

## 17. Approval requirements

No approval is inferred from this validation request. Current binaries cannot safely
complete Approval B/C solely by granting consent: they intentionally deny admission and
the live TCX event handoff is incomplete. Do not run the displayed sudo command as a
Native procedure, alter binary gate bytes or reuse prior session approval.

A: review exact package/manifest/dependencies, destination `/usr/libexec/soc-agent-ebpf`,
root-owned entry/bootstrap/broker0555 and data/loader0444, trusted parents, no setuid,
no file capabilities; atomic release switch only while quiescent; verify ownership/SHA;
rollback to separately verified previous release. Current native installer is absent;
a system-changing installer requires implementation and separate approval first.

B: after A and effective-policy qualification, one fresh terminal password for a new
app/session, exact fixed installed entry and manifest/approval digest; verify numeric
UID/GID, PID/start ticks, SO_PEERCRED and minimal capabilities. **No BPF load**.
No cached credential or NOPASSWD result counts as password authentication.

C: only after B plus qualified packet IPC/time-domain handling, a new approval bound
to namespace `net:[4026531833]` (recheck), lo ifindex1 (recheck), **INGRESS only**,
exact TCX object SHA below,300s,4096 events,queue32,AS256MiB,CPU20s, ring256KiB;
no pinning, no replacement, no qdisc/foreign-filter changes, no generated traffic.
Verify actual Link/Program identities and stop/drain/cleanup before any next run.
External FD duplication or uncertain cleanup leaves the session unverified.

D: independent Native AI approval only after actual capture/feature/flow/artifact
eligibility; never granted by A/B/C. DNS9 and operational promotion remain blocked.
No actual installation/authentication/kernel validation command is provided as ready
until the above code and policy blockers are resolved and the exact scope is approved.

## 18. Final verdict and fresh qualification

Fresh cohort results, identities, performance, export and preservation are appended
below and in `full-native-e2e-validation-evidence.json`. Counts are per run, not summed.

| Fresh cohort | Result |
|---|---|
| structural | 258 passed in 369.54s (0:06:09) |
| native_contract | 147 passed in 185.89s (0:03:05) |
| broker | 63 passed in 36.29s |
| regression | 695 passed in 67.53s (0:01:07) |
| integration | 58 passed in 65.79s (0:01:05) |
| model | SKIPPED: ACTUAL_MODEL_HEADROOM_REQUIRED |
| gui | 18 passed in 93.15s (0:01:33) |
| audit | 125 passed in 14.32s |
| Deferred serial actual RF/LR offline qualification | 1 passed in 9.46s |
| Packet/control boundary plus worker-timeout denial | 2 passed in 18.09s |

Fresh GUI n=3: startup median 2.3300s, idle RSS median 174.90MiB, response-p50 median 0.012ms. Offline package verification n=3 median 80.120ms. No paired runtime change or Native comparison is claimed.

The explicit packet/control reproduction raises `HANDOFF_REPLY_SCHEMA`, revokes the ordinary-UID fixture session, leaves sequence0 and Native Gate BLOCKED, and preserves audit. This proves rejection, not successful live packet delivery.

| Verdict | Result / scope |
|---|---|
| OS_AUTH_NATIVE | PENDING |
| TRUSTED_INSTALL_NATIVE | PENDING |
| CAPABILITY_SCOPE | UNKNOWN |
| TCX_KERNEL_VERIFIER | PENDING |
| TCX_NATIVE_ATTACH | PENDING |
| TCX_CLEANUP | PENDING |
| ZEEK_NATIVE_CAPTURE | PENDING_CAPTURE_INTEGRITY_HISTORICAL_PROCESS_FINALIZATION_VERIFIED |
| NETWORK14_NATIVE_PARITY | BLOCKED |
| DNS_NATIVE_VISIBILITY | UNKNOWN |
| RF_LR_OFFLINE | VERIFIED |
| RF_LR_NATIVE | BLOCKED |
| SOC_INVESTIGATION | VERIFIED_OFFLINE_READ_ONLY_NATIVE_BLOCKED |
| GUI_NATIVE_E2E | PENDING |
| AUDIT_RECOVERY | VERIFIED_OFFLINE_AND_FIXTURE |
| NATIVE_AI | BLOCKED |
| DNS9 | BLOCKED |
| OPERATIONAL_PROMOTION | BLOCKED |

Artifact rebuilds match B-2J; no new Native binary or approval scope is implied by this report.

| Artifact | SHA256 / digest |
|---|---|
| entry | `8e4ef82c3fe45ae5a414509316a2922898148ed860bb7ebdde9f743509ce4455` |
| bootstrap | `837b39ea68e2fe1e563c380e3610ad624a9f0a610a4aa8e4ed46d25a70fc8cb8` |
| broker | `177e879f707f4d3fa40d4b59abe4327dacb9c3b43f69adc45a4b4bd01c4b8894` |
| libnative-tc.so | `fa9b529ff1fd1f73e1f8e5f32c69a104188c8e1a11c13402b33b9714812473b3` |
| tc-fixture | `c7972a6c1f8a821f783ed527bf4c1544a956947932d1e80300172facb5203e29` |
| tcx-dispatch-fixture | `6dec643f83374aa4f11bc27ec7165dfd64747de7d7b4cb5e3e2c8a509fc2ea28` |
| tcx.bpf.o | `928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a` |
| source_bundle_digest | `5971ab08bb19a167a31a933364cb4eee5d9f01f52d2b1f14ccaef0a8b0da874f` |
| Bundle | `5971ab08bb19a167a31a933364cb4eee5d9f01f52d2b1f14ccaef0a8b0da874f` |
| Release manifest | `5fe21563dd2af5205e0e2f08ce728d3adc79802acbb1faeb7cbf37895bc5d394` |

Ruff/format/diff/wheel checks pass; 549 packaged source files match the export. Existing SOC122 + ML10 user files, 404 protected hashes and 58 raw dataset stat entries are preserved. The initial historical-hash comparator compared strings with metadata objects; corrected per-file comparisons verify all10 unchanged files. Its first receipt is retained as a harness error, not a Native failure or a retry-based fix.

Reproduction: run the existing `python -m tests.ebpf_verification_guard --import-mode=importlib -q` with the cohort paths recorded in the evidence JSON, using the independent export and read-only artifact configuration. The fresh models cohort is `tests/integration/zeek_live/test_models.py`; the new boundary test is `tests/integration/ebpf_handoff/test_native_e2e_boundary.py`. Do not run privileged entrypoints to reproduce these fixtures.

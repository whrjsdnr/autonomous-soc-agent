# TCX Native Release Candidate — Phase B-2F

## Architecture and trust boundary

Baseline: `980c66fbd249b99968543eeb21315924a16db59d`. This phase changes admission and packaging, not the collector, feature formulas, models, Zeek scope or four-screen GUI.

The prospective chain is root-owned release → Bootstrap → embedded Broker/Loader → sealed TCX object → private BPF Link. The C global Native gate and independent TCX gate remain compiled closed. No installation, authentication, capability modification, BPF load, attach, detach, capture or test traffic was performed.

The prior Python-only package qualification did not enforce JSON release identity in the C entry points. A 352-byte release approval envelope now contains the existing 272-byte plan, JSON manifest SHA256, a zero-padded release version and an outer approval SHA256. The outer approval binds the full plan, resource scope, application identity and release. Bare old plan FDs cannot enter Bootstrap/Broker. The existing 112-byte Broker request remains subordinate to this root-created sealed authority; it grants no independent release approval.

## Release manifest enforcement

`release.json` remains the strict Pydantic schema. Packaging additionally compiles `release.trust`, a bounded C execution schema: 232-byte header plus at most 72 records of 304 bytes, total dependency/configuration bytes ≤64 MiB. Its fields bind the JSON digest, version, four artifact hashes, source bundle and root-owned dependency/configuration snapshots. Paths, counts, sizes, modes, reserved fields, ordering, duplicates and fixed BLOCKED/UNKNOWN flags are checked in C. This avoids loading Python or a custom JSON DSO before authentication. It is a separate compiled execution manifest, not a general JSON parser; both manifests must be installed together from the reviewed package.

C Bootstrap verifies the root-owned execution manifest, approved JSON digest, artifacts, system dependencies and configurations before PAM and again afterwards. Broker independently verifies the sealed envelope, release, self identity and capability sets at startup and before each command. Loader repeats release/capability checks before opening/loading the BPF object. A mutable package with matching SHA values is never a root installation. Both compiled gates independently prevent activation.

Only the root-owned execution schema is authority for dependency records. Ordinary-UID package verification checks that it is exactly regenerated from the strict JSON model. This does not defend against a malicious root administrator rewriting the trusted release; root replacement is outside the threat model and requires quiescence.

## Root-owned installation and TOCTOU

The fixed directory stays `/usr/libexec/soc-agent-ebpf`. Bootstrap 04755, Broker 0555, Loader/object/JSON/execution manifest 0444, root UID/GID, no writable parent, no symlink traversal, regular files with one hardlink are required. `soc_trusted` traverses with directory FDs and O_NOFOLLOW. Executed Broker and sealed object derive from verified FDs. Actual Bootstrap/Broker inode identity is compared against `/proc/self/exe` rather than checking only a same-named file.

Dependencies are hashed through held descriptors with bounded streaming and before/after metadata checks. Approved JSON is hashed by held FD. Root-owned paths cannot be replaced by ordinary users; trusted-root updates still require all applications/brokers to quiesce. A staged library is not dlopened for verification. Bootstrap links system PAM/crypto only, Broker embeds Loader code. No operational root installer or rollback execution was added. Ordinary-UID simulation preserves all prior releases and requires explicit rollback.

## PAM / NSS and environment

The exact `soc-agent-ebpf` PAM service uses `pam_unix.so` for authentication and account checks. Packaging records `/etc/nsswitch.conf` and `/etc/ld.so.cache`, static DT_NEEDED/interpreter/PAM module dependencies and their SHA values. The C verifier rejects `/etc/ld.so.preload` if present. Dependency search-path injection is rejected through static RPATH/RUNPATH inspection; readelf runs against sealed bytes with a fixed environment. Bootstrap clears the environment; the fixed Broker fexecve environment contains only system PATH and C locale. No user-supplied path or shell execution is added.

**Dynamic PAM/NSS closure remains UNKNOWN.** The current NSS policy includes files/systemd and other services; static DT_NEEDED inventory cannot prove every runtime dlopen, resolver, PAM helper, OpenSSL provider or already mapped dynamic-loader dependency. Post-start file verification is not proof of the pre-main loaded image. Setuid secure-execution handling and complete runtime dependency provenance need separately approved Native qualification. Therefore PAM/NSS full trust and Native release readiness remain BLOCKED.

Authentication remains one terminal password challenge per application session, followed by account policy and session-bound scope checks. No sudo cache grants authority; no password/token is persisted. Broker loss, expiry or application exit revokes authority. Restarting the application requires a new challenge. Fixtures exercise the existing once-per-app lifecycle; they are not Native PAM evidence.

## Capability and kernel compatibility

The candidate profile remains CAP_BPF + CAP_NET_ADMIN. Linux v6.18 `bpf_prog_load` requires BPF authority and NET_ADMIN for SCHED_CLS; that program class is not in the perfmon-only class. CAP_PERFMON, SYS_ADMIN and NET_RAW are not silently added. Broker now checks effective, permitted, inheritable, ambient and bounding sets for exact equality, requires non-root UID and no_new_privs. Actual capability transfer/re-exec and scope qualification remain UNKNOWN.

Kernel/config/BTF/namespace/interface/libbpf observations are read-only. A matching version/config is not a successful BPF verifier or TCX feature probe. Native kernel support remains PENDING.

## TCX ownership, cleanup and recovery

The existing TCX_NEXT observer object, private Link FD ownership, no pinning, no external Link-ID deletion, no Legacy TC mutations and existing cleanup fixtures remain intact. Release changes block new commands/loads. The already owned-FD cleanup path is still attempted after a release failure; cleanup does not require reopening a now-invalid release. Ownership ambiguity, external references, SIGKILL or failed cleanup stay ORPHANED/CLEANUP_UNVERIFIED. There is no automatic reattach or inference recovery.

A new 216-byte `RC_RELEASE_VERIFIED` journal row binds manifest SHA, version, plan scope hash and existing hash-chain sequence. The decoder retains 192/240-byte compatibility and treats recovered records as claims requiring review, never authentication/Native attestation. Existing audit chains are not rewritten.

## GUI and SOC preservation

Dashboard, Security Events, Investigation and System retain their cards, charts and timelines. Prepared System adds candidate/digest/PAM-NSS state using the existing snapshot/render path. No extra worker or polling loop is introduced. No root GUI, unknown-to-zero conversion, Native AI, DNS9 or operational promotion is enabled. Network14 30s idle/120s active, Float32/order/digest, Zeek DNS diagnostics, RF/LR artifacts and READ-only investigation contracts are preserved.

## Tests and performance

Final source-bound results, measured timing/RSS, exported file manifest and artifact hashes are recorded in `ebpf-native-release-candidate-evidence.json`. Private append-preserved command logs are under `.git/ebpf-native-rc-audit/`.

Initial development failures are retained: one artifact/reference mismatch occurred while C sources were being edited during a workspace run; a legacy update fixture changed only JSON version without rebuilding the now-mandatory execution manifest. These are not counted as final PASS. The update fixture must explicitly regenerate the execution manifest, while a stale descriptor remains a negative test.

Benchmarks are ordinary-UID/offline/fixture measurements, not Native kernel performance. Native authentication, installed Broker RSS, BPF processing throughput and Native cleanup latency remain NOT_OBSERVED.

## Release candidate and remaining blockers

The package is an inspectable candidate, **not an authorized executable Native release**. JSON edits cannot open either compiled gate. Release identity, hashes, PAM service, capability candidate, interface lo, ingress/egress allowlist, 300s/run, 4096 events, queue32, 256MiB Broker address space, CPU20s, application3600s and 16 explicit runs are fixed in the package.

Pending: trusted root installation and quiescent update/rollback review; complete dynamic PAM/NSS/runtime loader closure; actual terminal PAM/account challenge; actual capability transfer; kernel verifier/TCX compatibility and coexistence; Native owned-Link detach/crash cleanup. Legacy TC remains blocked. Native AI, DNS9 and operational promotion remain blocked regardless of package verification.

## Next Native approval scope

This candidate intentionally has no usable Native execution command. Existing `native_handoff` and compiled gates reject it. A subsequent reviewed release/code change and new hashes are required before Native activation; approval alone cannot override this candidate's gates.

Separate approval must cover (1) root-owned installation and exact manifest/artifact/dependency/PAM configuration identities, (2) one application-bound terminal password challenge and constrained Broker capability transfer, and (3) one explicit lo/interface, namespace, hook, resource/time/event-bounded verifier/TCX attach-detach experiment with before/after Link ownership and cleanup evidence. No external filter/qdisc changes, pinning, traffic generation or AI promotion are included. Any wider interface/hook/scope requires new explicit approval. Codex has not performed these operations.

## Official source evidence

- [Linux v6.18 BPF syscall implementation](https://github.com/torvalds/linux/blob/v6.18/kernel/bpf/syscall.c): SCHED_CLS capability class and program/link entry checks.
- [Linux v6.18 TCX implementation](https://github.com/torvalds/linux/blob/v6.18/kernel/bpf/tcx.c): Link ownership and lifecycle; fixtures do not prove Native cleanup.
- [Linux-PAM pam_authenticate](https://github.com/linux-pam/linux-pam/blob/v1.5.3/libpam/pam_auth.c) and [account management](https://github.com/linux-pam/linux-pam/blob/v1.5.3/libpam/pam_account.c): distinct authentication/account boundaries. Ubuntu package patches require Native qualification.
- [Linux dynamic-loader manual](https://man7.org/linux/man-pages/man8/ld.so.8.html): dependency/search-path/dynamic-loading hardening; static hashes alone do not prove runtime closure.


## Final fixture qualification results

Independent Export: new security/interoperability 67, installation 50, TCX/Native contract 147, B-1 Broker 63, existing unit 693, existing integration 58, actual offline Zeek RF/LR 1, GUI 17, Audit/Recovery 125 — each cohort PASS, not summed. The extra C journal writer/decoder case was run on the expanded Export; the already-verified source hashes remained identical. Two model receipts are COMPLETE, queues finish at zero, recovered audit digest matches and recovery creates zero new inferences. Native capture is false.

Ruff, Format (1,236 files), Wheel and byte-for-byte wheel-source checks pass. Binary rebuild and source-bundle hashes match across Workspace/Export. Full Stage/Export equality is the final commit gate; its non-circular ledger is kept privately rather than embedding a document's own hash into itself.

| Ordinary-UID measurement | B-2E baseline | B-2F candidate |
| --- | ---: | ---: |
| WSLg GUI startup median, n=3 | 2.755s | 2.548s |
| Idle RSS median, n=3 | 175.13MiB | 175.07MiB |
| Response p50 median, n=3 | 0.01523ms | 0.01626ms |
| Full static package verification | 83.754ms | 45.373ms |
| Manifest parse | 0.055ms | 0.035ms |

Measurements ran sequentially on the same shared WSL host, with warmup and explicit repetition counts in evidence. Cache/order/host variation prevents attributing timing differences to optimization. Broker measurements are B-1 ordinary-UID fixture processes, not an installed privileged Broker. The actual model preflight had three >=2GiB samples and avg10=0.00; subsequent low-cost GUI work observed transient avg10=0.24, preserved in evidence. No heavier model test was started under that pressure.

Release version `0.2.6`, fixed native limits as above; Native qualification remains **BLOCKED**. File and source identities:

```text
bootstrap: 2664bf5cdbd07bed3647c53cf49839edac1f0a85133e07a6aeb22e05b9cbda7f
broker: e649e5020fd116cc943de94e27fa2ea38f644eefc98125857c5ce4de6fc2d6be
libnative-tc.so: 8cf200b557c25e5e77cb4499342482bef04d781cae807596c5b1689ebe0e7228
tcx.bpf.o: 928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a
Bundle: afaec6da9aa722333ebbfa81c3121922dd32afee1e5fd4f115f10eb96f0498f8
Manifest: 4cc4e23b5d0851b268ca527cf45f877be6fbbd7a0380d06e44956cebc6d92284
```

Read-only candidate verification (no authentication or Native activation):

```bash
.venv/bin/python -m soc_agent.security_ai.ebpf_tc verify-package \
  --package .git/ebpf-native-rc-audit/release-package \
  --manifest-sha 4cc4e23b5d0851b268ca527cf45f877be6fbbd7a0380d06e44956cebc6d92284
```

PAM/NSS full trust is BLOCKED; capability transfer and kernel compatibility remain UNKNOWN. Other VERIFIED verdicts in the evidence mean fixture/static contracts only. The candidate is prepared for review; it is not Native release-ready. All root-install/auth/verifier/TCX operations are pending, Native AI/DNS9/operational promotion are blocked. No runtime flag or manifest edit can authorize Native execution in this build.

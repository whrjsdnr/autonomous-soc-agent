# Phase B-2E — Trusted Native installation qualification

## 1. Architecture and scope

Baseline `389779e9c9f03a3631333f5fa7c1b44d54dc3539`. This phase packages and verifies the existing fixed Bootstrap/Broker/Loader/TCX observer, records a release contract and exercises bounded filesystem transactions under an ordinary UID. It does not authenticate, install as root, load BPF, attach/detach a hook, change network configuration, mount bpffs, generate traffic or enable Native inference. Native release remains BLOCKED in Python, C and manifest schemas.

Existing Zeek, Legacy TC, TCX program/Link code, Network14 producer, DNS diagnostics, RF/LR artifacts and READ-only investigations are preserved. Legacy TC Native mutation remains unsupported. New qualification modules own packaging/host observations; Application/Controller continue to own authentication and session authority. There is no second authorization database or privileged background service.

## 2. Trusted installation layout

Keep `/usr/libexec/soc-agent-ebpf` because the reviewed Bootstrap resolves this fixed path; changing to `/opt` would require a new executable contract. Files:

| File | Intended root owner/mode | Purpose |
|---|---|---|
| bootstrap | root:root / 4755 | Fixed future privilege entry, independent Native gate |
| broker | root:root / 0555 | Embedded loader, no repository DSO dependency |
| libnative-tc.so | root:root / 0444 | Reviewed loader identity |
| tc.bpf.o | root:root / 0444 | TCX-only object, logical name required by Bootstrap |
| manifest.bin | root:root / 0444 | Existing 160-byte Bootstrap hash contract |
| release.json | root:root / 0444 | Versioned qualification manifest, separate approved SHA |
| /etc/pam.d/soc-agent-ebpf | root:root, non-user-writable | Separately approved exact PAM policy |

The TCX payload source is `tcx.bpf.o`; Legacy object bytes are not renamed or overwritten in the development tree. Package files, including Bootstrap, are ordinary UID-owned 0444, never setuid or executable. A package is not a root installation. Runtime state uses a private 0700 user/session directory with a 0600 append-only audit FD and in-memory/sealed authority; credentials are not persisted.

The existing root mode/path verifier is reused. The new Python root-file verifier itself rejects effective UID0, so development code is never used as a privileged executable. The new root release checker has a fixed system path and hardcoded UID0 expectation, not a caller-selected trust UID. Parent traversal uses directory FDs and O_NOFOLLOW. Payloads require a single link, bounded regular-file size and stable inode/size/mtime/ctime/mode/link-count; consumed snapshots are not reopened for execution. Mutable parents, traversal, symlinks, hardlinks and concurrent metadata changes fail closed. Simulation may traverse root-owned sticky temporary ancestors; that exception is unavailable to UID0 dependency/root verification. In-place root-admin changes are outside unprivileged path protections; approved updates require quiescence.

## 3. Manifest and package

`ReleaseManifest` binds version, all payload hashes/sizes/root modes, source bundle, dependency inventory, fixed PAM service/policy location, capability profile, interface/hook allowlists, resource budgets and installation identity. It declares Linux6.18 source compatibility and libbpf1.3.0 compile compatibility; neither asserts Native support. Native release is a Literal BLOCKED field.

The externally retained manifest SHA is the trust anchor. Rehashing an edited manifest is insufficient to bypass schema, file allowlist, binary-manifest coherence, payload, dependency-closure or policy validation. The binary manifest remains Bootstrap/Broker/Loader/Program/Bundle, 32bytes each. Package output cannot overwrite an existing directory. The existing compiler/source-reference artifact check is performed before packaging. No staged artifact is executed by package verification.

Static DSO inspection uses the system `readelf` against sealed byte snapshots, not `ldd`, dlopen or staged executable launch. A clean child environment excludes LD_PRELOAD/LD_LIBRARY_PATH and Python path injection. RPATH/RUNPATH and unsafe names are rejected. Resolved system library paths must be canonical root-owned files with trusted ancestors, hashes and stable metadata. Needed/interpreter closure is regenerated from the actual payload snapshots; supplied missing dependencies cannot silently qualify. Limits:64 dependencies, 16MiB per library, 64MiB total inspected bytes, bounded readelf output/time. The local inventory also includes pam_unix.so and its static dependencies. Dynamic PAM/NSS/resolver loading, secure-execution loader behavior and deployment-machine state are UNKNOWN; this is not complete Native DSO attestation.

## 4. Atomic installation and rollback

The Native installation API always raises a pending-approval error. It neither copies system files nor changes mode, owner, capabilities or PAM. Installation plans require explicit approval, all application/Broker sessions quiesced, verified root staging, fsync, whole fixed-directory RENAMEAT2_EXCHANGE (or NOREPLACE on first install), parent fsync, read-only re-verification and retention of the prior release. Existing process-held descriptors must not be confused with the newly published generation. No running-session update is authorized.

PAM lives at another fixed system path and cannot be atomically exchanged with this directory in one filesystem operation. It therefore requires a separate quiescent approval/verification step; mixed or missing state blocks Native startup. Automatic rollback is forbidden. Root package promotion and root rollback remain implementation/qualification procedures to approve separately, not operations executed in this phase.

`InstallationSimulation` performs real unprivileged writes/fsync/NOREPLACE directory publication and atomic selector replacement in a caller-created private temporary directory. All artifacts remain non-executable. A private simulation identity is created only in an empty directory; foreign directories/files and later identity changes are rejected before activation. The hashed append-only transaction journal distinguishes PREPARED and COMMITTED. Crash after selector exchange but before commit yields CRASH_REVIEW_REQUIRED; recovery does not automatically select another release. Explicit rollback revalidates a retained manifest and payloads, preserving both releases. Limits:8 retained/pending release directories,6 payload files plus manifest per release (each payload≤1MiB),128 journal records/64KiB and64MiB free-disk floor. Incomplete staging is retained for review and consumes the bound. No evidence deletion or version reuse is performed.

## 5. PAM authentication and session lifetime

The existing gated Bootstrap owns the OS TTY and uses service `soc-agent-ebpf`, with exact policy `auth required pam_unix.so` followed by `account required pam_unix.so`. It requests PAM_DISALLOW_NULL_AUTHTOK, counts one ECHO_OFF challenge, checks foreground TTY/session ownership, performs account management and enforces a60s deadline. No sudo, askpass, GUI prompt, password storage or sudo-cache authority is added. [Linux-PAM authentication dispatch](https://github.com/linux-pam/linux-pam/blob/v1.5.3/libpam/pam_auth.c) and [account management](https://github.com/linux-pam/linux-pam/blob/v1.5.3/libpam/pam_account.c) are separate operations; the fixture requires both to succeed. Installed libpam version is recorded in evidence. Native challenge/PAM policy behavior has not been exercised.

`PamFixture` emits only qualification observations, never authority. Cached-only, absent/incorrect TTY, missing/extra challenges, cancellation, timeout, account denial/expiry and unguaranteed password policy are blocked. A successful observation is MOCK_PAM_NOT_NATIVE, not authentication success.

Existing Application/Controller retain the only in-memory grant, bound to application/controller identity, approved scope, program/bundle, Broker PID/start ticks and bounded lifetime. Same-scope manual Start/Stop/Restart reuses that grant, with fresh run generation, without a second password. New application approval cannot replay the prior session digest. Scope changes are denied pending explicit approval. App close, observed Broker loss and expiry revoke authority; recovery never restores it. Fixture tests verify authentication audit count1 over repeated runs. Actual root capability handoff/PAM remains PENDING.

## 6. Capability profile

Candidate Broker profile remains exactly CAP_BPF + CAP_NET_ADMIN; GUI/Runtime retain no effective/permitted/ambient capabilities. The existing C privilege transfer drops other bounding capabilities, clears groups/ambient state, changes UID/GID, installs the bounded sets and no_new_privs. None of those operations ran here.

[Linux6.18 bpf_prog_load](https://github.com/torvalds/linux/blob/v6.18/kernel/bpf/syscall.c#L2624) classifies SCHED_CLS as a network-admin program and checks BPF authority plus NET_ADMIN. Its perf-monitor program classification does not include SCHED_CLS. The existing observer uses no tracing/perf event collector, so CAP_PERFMON is not added. Broad SYS_ADMIN, SYS_RESOURCE and NET_RAW fallbacks are forbidden. Map creation, resource accounting, namespace permissions, LSM/lockdown and libbpf memlock behavior still require Native qualification.

Map/ring access and explicit Link detach use retained descriptors; identity/scope checks remain mandatory. Keeping BPF/NET_ADMIN within the bounded Broker session supports explicit fresh-generation reload/restart. Dropping BPF permanently after first load would prevent that behavior; no privilege-regain helper or extra long-lived root service is introduced. Exact capability fixture matching is a candidate contract only, and missing/excess capability fixtures are denied. Native capability scope remains UNKNOWN.

## 7. Kernel compatibility

Read-only observations: Microsoft WSL2 kernel6.18.33.2, libbpf1.3.0, CONFIG_BPF_SYSCALL, NET_CLS_BPF and NET_XGRESS present; vmlinux BTF present; bpffs not mounted; lo/index and network namespace recorded. No BPF feature probe, syscall, mount or TC command ran. Version/config/header evidence does not establish verifier acceptance or TCX support. BTF absence is reported separately; this non-CO-RE observer does not automatically require vmlinux BTF. No pinning means bpffs is not silently mounted or required merely for FD ownership. Namespace/interface mismatch or known missing config blocks qualification; otherwise Native compatibility remains UNKNOWN.

## 8. TCX ownership and cleanup

Retain the B-2D observer NEXT return contract and private Link FD dispatcher. The Broker queries/detaches its held Link, not an arbitrary global ID, filter priority or qdisc. Pins and FD export remain forbidden. Existing duplicate-reference, external pin, foreign Link preservation, partial attach/detach, Broker/controller crash, SIGKILL, ownership mismatch, lost FD and cleanup failure fixtures are reused. [Kernel Link release](https://github.com/torvalds/linux/blob/v6.18/kernel/bpf/tcx.c#L158) identifies the Link object under RTNL; it does not exclude a privileged actor updating the same Link between identity inspection and detach. External reference/pin absence and Native cleanup are not attested. Ambiguity stays ORPHANED/CLEANUP_UNVERIFIED. No automatic reattachment is added.

## 9. GUI and Audit/Recovery

Preserve Dashboard, Security Events, Investigation and System with existing cards, charts and timelines. System adds installed release, installation integrity, authentication, capability and kernel qualification state beside Link/cleanup/release status. Unobserved installed release is UNKNOWN; a verified ordinary-UID package is never an installed release. Host/dependency scans are explicit operations, not recurring GUI polling.

Package qualification appends INSTALLATION_PACKAGE_VERIFIED with manifest digest, source label, candidate capability scope and BLOCKED release decision through the existing Runtime audit chain. UI snapshot publication follows audit success. No credentials or new persistent authorization are recorded. Existing session/link/cleanup hashes remain append-only; recovery restores neither authentication, hook nor inference. New release JSON/FS simulation evidence is separate from historical Native audit.

## 10. Verification and performance

Final source-bound fixture, regression, offline model, GUI, performance, preservation and independent export results are in the companion evidence JSON. Tests exercise manifests/DSOs/ownership/path swaps, atomic publication, explicit rollback, crash review, journal corruption, PAM/account observation, session replay/expiry/Broker exit, candidate capabilities, kernel facts and closed Native admission. Actual Root/PAM/verifier/TCX performance remains UNKNOWN. A manual packaging smoke exposed Python's missing fcntl seal constant; the implementation reuses existing Linux ABI constants and verifies sealed readelf snapshots. No unchanged failing test was repeatedly rerun to claim repair. SIGILL root cause remains UNKNOWN.

## 11. Native approval requirements and blockers

Native release remains BLOCKED. Separate user approval must bind exact manifest SHA, Bootstrap/Broker/Loader/TCX object hashes, source bundle, destination/root ownership/modes, exact PAM policy, dependency inventory and capability profile. Root installation and rollback require independent approval and quiescence. Subsequent Native validation needs a fresh app/session approval, real terminal challenge, actual minimal-capability handoff, Microsoft-kernel verifier/TCX support and owned-FD cleanup evidence, limited to lo, a chosen ingress/egress hook,300s/4096 events/queue32/256MiB Broker address space/20CPU seconds and bounded app/run count. No pins, traffic generation, automatic restart or Native AI promotion is included. Dynamic dependency closure and external Link mutation/refcount risks remain unresolved. The existing C Bootstrap still consumes its binary manifest; the supplementary JSON verifier does not automatically become a Native launch gate. A future separately reviewed Native release must bind JSON/dependency qualification and the TCX-specific authorization plan into that launch boundary. This release supplies no runnable root installation or capture command.

Nonprivileged commands:

```bash
uv run python -m soc_agent.security_ai.ebpf_tc compile --output /path/to/new-build
uv run python -m soc_agent.security_ai.ebpf_tc package --artifacts /path/to/new-build --output /path/to/new-package --version 0.2.5
uv run python -m soc_agent.security_ai.ebpf_tc verify-package --package /path/to/new-package --manifest-sha <separately-approved-package-manifest-sha>
uv run python -m soc_agent.security_ai.ebpf_tc qualify-host
```

These commands do not install, authenticate, load BPF or attach a hook. Do not run development-directory binaries as root.

## Final qualification results

- Final installation/security suite: **50 passed**. This replaces the intermediate44/47/48/49 and earlier50-case attempts; counts are not accumulated. Final guards reject root execution of the development verifier, unknown simulation directories and activation after uncommitted selector publication.
- Existing TCX/Bootstrap/GUI: **147 passed**; B-1 Broker: **63 passed**; existing unit regressions: **693 passed**; integration: **58 passed**; GUI preservation: **17 passed**; Audit/Recovery/policy: **125 passed**.
- Actual pinned Zeek offline PCAP + RF/LR Artifact integration: **1 passed**, two COMPLETE receipts with READ-only investigations, queue final0, unchanged recovered audit digest and zero new recovery inferences. No Native input was inferred.
- One model preflight was deferred at PSI some avg10=0.53 (Native test not started), despite >4GiB memory. After GUI/Audit, three model preflight samples had avg10=0.00 and >4.5GiB available; the first actual model test passed. A separate shared-host pressure sample reached avg10=7.47 during an earlier fixture suite. Other processes were not stopped; this does not establish Native stability.
- Final-source installation tests cover late root-mode and simulation preservation/crash checks; the evidence lists differences from the earlier broad-regression export. Other source/test files are byte-identical. No production test failure was hidden by an unchanged rerun.
- Preservation: **132 existing user files,396 protected files,58 raw dataset stat records** unchanged. Original Stage was empty.

Same-environment measurement, three fresh GUI processes per group against389779e:

| Metric | Before | After |
|---|---:|---:|
| GUI startup median | 2.513s | 2.455s |
| Idle RSS median | 174.977MiB | 174.969MiB |
| Idle CPU, one core | 0.265% | 0.260% |
| GUI response p50 | 0.01582ms | 0.01886ms |

The small startup/RSS differences are within environment variation; no optimization or Native performance gain is claimed. Static package checks run explicitly and add no GUI poll/worker. Package verification includes dependency reinspection; native PAM, privilege transfer, root installation and Native Broker memory remain UNKNOWN. Source functions timed by these measurements were unchanged by the final simulation-only identity/crash guards. Detailed timings, repetition counts, RSS and resource samples are in the evidence JSON.

New qualification medians:

- `manifest`: 0.033481ms (100 repetitions after 10 warm-up).
- `package_full_static_verification`: 45.577562ms (3 repetitions after 1 warm-up).
- `pam_mock`: 0.001737ms (100 repetitions after 10 warm-up).
- `capability_mock`: 0.002000ms (100 repetitions after 10 warm-up).
- `kernel_read_only`: 1.960707ms (3 repetitions after 1 warm-up).

Final build identities (the C binaries/program are preserved from B-2D; the source bundle and release manifest are new):

- `bootstrap`: `60fc1ffb70c009f1ba4ad691df6e0baa656d1c8724d532b829a5b81e537d3c54`
- `broker`: `70bda695d3569330b4daf6870412544d749e00c765516dd46b923b97ffd3ff4b`
- `libnative-tc.so`: `99036271b5db0cf5370ed13a1446cc72e3e117c40ae7cb8e31945bef03d7367d`
- `tcx.bpf.o`: `928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a`
- Source Bundle: `4d5a9790ada5075129631bde9acfb56cf456392ebc4868f0f6c54f4e3bc74a9a`
- Release Manifest0.2.5: `ea8990e5dad9d164d5e1995b41a51f2733e7cd415a0def467a3b8c3ecf10ebdf`

The candidate package remains UID-owned/non-executable in private audit storage. Independent Export, wheel packaging, rebuilt binary/BPF hashes, source SHA, Ruff/format/diff and selective Stage/Export SHA qualification are recorded in the companion JSON/private completion record. Existing user changes, models, Raw Dataset, Native sessions and Replay are excluded from the commit.

Final verdicts: TRUSTED_INSTALLATION_CONTRACT_VERIFIED, RELEASE_MANIFEST_VERIFIED, PAM_AUTH_CONTRACT_VERIFIED, SESSION_AUTH_LIFETIME_VERIFIED, TCX_LINK_OWNERSHIP_FIXTURE_VERIFIED, CLEANUP_FIXTURE_VERIFIED, GUI_PRESERVED and AUDIT_RECOVERY_VERIFIED (all scoped to fixtures/read-only contracts). CAPABILITY_PROFILE_UNKNOWN, KERNEL_COMPATIBILITY_PREFLIGHT_UNKNOWN, NATIVE_ROOT_INSTALL_PENDING, NATIVE_AUTH_PENDING, NATIVE_VERIFIER_PENDING, NATIVE_TCX_ATTACH_PENDING, NATIVE_AI_BLOCKED, DNS9_BLOCKED, OPERATIONAL_PROMOTION_BLOCKED and NATIVE_RELEASE_BLOCKED.

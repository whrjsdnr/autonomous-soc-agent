# PAM/NSS and dynamic loader trust — Phase B-2G

## Threat model and existing path

Baseline `fb4c8f28d735d8bd368f0b81f66489949aa41967`. Ordinary users may control their environment, working directory, development files and IPC inputs. The fixed root-owned release, system library/configuration files and administrator are trusted only subject to ownership/mode/hash checks and quiescent updates. A hostile root administrator, unverified pre-main image or an incomplete dynamic dependency closure is not declared safe.

Prospective path: CLI's explicit application approval → fixed root-owned setuid Bootstrap → terminal PAM/account challenge → non-root Broker with exactly two candidate capabilities → embedded Loader → sealed TCX object → private Link FD. Both compiled Native gates and Python Native handoff remain closed. No Root installation, sudo/PAM authentication, capability mutation, BPF load, TCX attach/detach, network setting change, capture or traffic generation was performed.

## ELF dependency graph and dynamic loader

The three release ELFs are inspected as sealed byte snapshots with absolute system readelf and a minimal environment. The manifest now records their SHA, ELF interpreter, DT_NEEDED, SONAME (including absence), undefined dynamic imports, BIND_NOW, RELRO and executable-stack status. Transitive libraries include exact path, SHA, size, mode, SONAME and dependency edges. Compiler/linker hardening adds full RELRO/NOW and a non-executable stack to the Loader DSO as well as the executables. The Bootstrap embeds only reviewed code and system PAM/crypto; no user custom DSO is loaded for authentication. Broker embeds Loader code; unprivileged test drivers alone use $ORIGIN.

ELF inspection rejects RPATH, RUNPATH, AUDIT, DEPAUDIT, FILTER, AUXILIARY, slash/relative DT_NEEDED names and unsupported interpreters. This is static ELF analysis, not ldd, dlopen or execution of the inspected bytes. Dynamic interposition/IFUNC/provider behavior is not inferred from symbol names.

The resolver's search directories are static candidates, not evidence of what ld.so actually selected. The C release checker now walks actual dl_iterate_phdr base-namespace objects, verifies named distribution paths/parents, resolves root-owned aliases, hashes held canonical FDs, and compares file device/inode with the object's file-backed segment in `/proc/self/maps`. Main executable inode identity remains independently checked by the existing fixed-release mechanism. Kernel vDSO is explicitly outside disk attestation. Unlisted DSOs, relative paths, mutable/user-owned named parents, replaced inodes and mismatched bytes fail closed.

**Limits:** constructors run before these checks; dl_iterate_phdr does not attest every audit/dlmopen namespace. Environment removal inside main cannot undo pre-main code execution. The setuid Bootstrap additionally requires AT_SECURE, and Broker gets only a fixed PATH/LANG environment, but real secure execution is pending. A valid ordinary-UID LD_AUDIT fixture records the verifier's namespace limit; it is not Native trust success. Complete dynamic loader trust remains BLOCKED.

## PAM trust

The fixed `soc-agent-ebpf` service now names `/usr/lib/x86_64-linux-gnu/security/pam_unix.so` explicitly for auth/account, replacing a bare module name. Its exact source bytes and root service destination, module and transitive hashes are bound into the approved release. Arbitrary include/substack/service/module paths are not admitted. This x86-64 Ubuntu profile does not silently guess module directories on another platform.

Bootstrap verifies release/configuration/dependency evidence before NSS/PAM, after bounded NSS queries, after pam_start and before pam_authenticate, and again after the complete authentication/account path. TTY ownership/session/foreground checks, one ECHO_OFF challenge, cancellation/timeout/account rejection and no password storage remain. Module constructors/helper execution are not proven by a static module hash. Native PAM and the actual root-owned service remain PENDING. Updating the absolute-path PAM policy requires separate explicit root configuration approval and quiescence; this phase only edits repository source/package bytes.

## NSS trust

The manifest preserves configured database order and action clauses without implementing NSS lookup decisions. It lists configured service modules and their transitive dependencies. On this host, passwd/group/shadow use files/systemd; glibc source implements files/dns internally. libnss_systemd is added to the static graph. Configured db/nis modules are unavailable and remain explicit unresolved services. Missing modules/configuration or changed identity cannot become authentication success. Unrelated database configuration is not silently ignored to claim a complete closure.

Native lookup changes to bounded reentrant getpwuid_r and getpwnam_r. Both must return the approved non-root UID/GID and the same account name; failure, ERANGE, ambiguity and mismatches stop authentication. This avoids trusting one name lookup as identity. No NSS account lookup or password authentication is executed by these tests; the pure C identity predicate and static graph are fixtures. Conditional NSS/helper/provider behavior remains unobserved, so NSS full trust stays BLOCKED.

## Dependency manifest and trusted file verification

Release JSON contains typed dynamic-trust metadata in addition to the bounded C execution manifest. The package verifier regenerates the graph/ELF/PAM/NSS evidence and compares it, so recomputing ordinary-user JSON and execution-manifest hashes cannot forge dependency metadata. Execution manifest records use pinned dependency modes rather than reopening a path to obtain a fresh mode. All Native entry points retain the approved manifest/version/component/source/session/scope checks.

Canonical root-owned file verification still rejects mutable parents, final symlinks, hardlinks and mismatched SHA/modes. Mapping names may use root-owned distribution aliases such as /lib → usr/lib, with named-parent and canonical FD verification; this is not acceptance of a user alias. A system library/configuration update invalidates the candidate and requires rebuild/reapproval. Root updates are quiescent; an attacker with root control is outside this contract. These checks do not retroactively prove every byte initially mapped by the system loader.

## Capability and startup authentication

The candidate remains CAP_BPF + CAP_NET_ADMIN; CAP_PERFMON is not silently added for SCHED_CLS. All effective/permitted/inheritable/ambient/bounding sets must match exactly. Broker additionally rejects saved root UID/GID, mismatched real/effective/saved identities and supplementary groups. Privilege drop reasserts non-dumpability. Actual capability transfer remains UNKNOWN. No GUI/model child execution is added to the Native Broker; GUI/AI continue as ordinary-user processes.

Authentication is once per new application session. Same-scope explicit Start/Stop/Restart uses the in-memory authority; expiry, app/Broker exit or scope mismatch revoke/deny it. No persistent approval, password/PAM secret, sudo token or auth-cache grant is introduced. Fixtures remain explicitly mock; real password authentication is PENDING.

## Native enforcement, TCX cleanup, GUI and audit

Root release checks apply at Bootstrap, Broker command and Loader load boundaries. Mapping/identity failures block new work. Existing owned-Link FD cleanup is independent of reopening or trusting the changed release, so a trust failure does not deliberately suppress cleanup. External links remain untouched; uncertainty stays ORPHANED/CLEANUP_UNVERIFIED. No automatic reauthentication, reattach or inference recovery is introduced.

All four screens/cards/charts/timelines remain. Prepared System adds dependency integrity, PAM trust and NSS trust to the existing snapshot/render path, with static/native-pending states. No extra worker, polling loop or fake Native value is introduced. Package qualification appends dependency/PAM/NSS/capability/release-state metadata to the existing audit chain. It remains an ordinary-UID package claim, not an installation or authentication record. Existing audit evidence is unchanged.

## Tests and performance

Final source-bound cohort results, artifact hashes and before/after measurements are in `ebpf-pam-nss-dynamic-trust-evidence.json`. Private command logs and preservation inventories are retained in `.git/ebpf-dynamic-trust-audit/`. Initial 37-case development probes are preserved separately from the expanded final fixtures. No unchanged failing test is hidden by a retry. No SIGILL was observed in this phase; historical SIGILL cause remains UNKNOWN.

Measurements are offline/ordinary-UID fixture results. Shared WSL pressure and warm-cache/order effects are recorded; there is no Native performance or optimization claim. Actual authentication, privileged Broker RSS and Kernel collection throughput remain NOT_OBSERVED.

## Remaining blockers and approval requirements

Native Release remains **BLOCKED**: complete pre-main/audit namespace/runtime dependency evidence, missing NSS modules/scope review, conditional PAM helpers/OpenSSL providers, trusted Root installation, real terminal PAM/account validation, actual capability transfer and Kernel verifier/TCX/cleanup qualification remain unresolved. Static ELF graph verification is scoped and cannot stand for runtime closure.

A new reviewed release with new hashes and explicit approval is required before any Native gate change. Approval must identify root installation/configuration files (including the new absolute PAM module policy), exact manifest/component/dependency hashes, one terminal challenge per app session, candidate capability profile, lo interface/namespace/hook and fixed budgets: 300s/run, 4096 events, queue32, Broker address space256MiB, CPU20s, app3600s, max16 explicit runs. No traffic generation, pinning, external-filter/qdisc deletion, automatic restart or Native AI/DNS9/operational promotion is included. This candidate offers no command that can bypass the compiled gates.

## Primary sources

- [ld.so manual](https://man7.org/linux/man-pages/man8/ld.so.8.html): interpreter, search order, environment variables and AT_SECURE; clearing environment after startup is not pre-main proof.
- [Linux-PAM module loading](https://github.com/linux-pam/linux-pam/blob/v1.5.3/libpam/pam_dynamic.c), [authentication](https://github.com/linux-pam/linux-pam/blob/v1.5.3/libpam/pam_auth.c), [account policy](https://github.com/linux-pam/linux-pam/blob/v1.5.3/libpam/pam_account.c): separate loading/authentication/account steps. Ubuntu package patches require Native qualification.
- [glibc 2.39 NSS module implementation](https://github.com/bminor/glibc/blob/glibc-2.39/nss/nss_module.c): files/dns built-ins and dynamic NSS module loading. This is source evidence, not a Native lookup result.
- [Linux v6.18 BPF syscall source](https://github.com/torvalds/linux/blob/v6.18/kernel/bpf/syscall.c): SCHED_CLS capability class; actual capability transfer remains pending.


## Final qualification evidence

Final independent-source cohorts: dynamic trust 47, release enforcement 67, installation 50, TCX/Native contract 147, B-1 Broker 63, existing unit 693, integration 58, actual offline RF/LR 1, GUI 17 and Audit/Recovery 125 — all PASS, not summed. The expanded LD_AUDIT probe changes only test evidence; the already-verified implementation source hashes match. Two offline model receipts COMPLETE, queues finish at zero, audit/recovery digests agree and recovery creates zero new inferences. Native capture is false.

The valid LD_AUDIT module wrote its private fixture marker while the base-namespace verifier returned 0. This positively demonstrates an inspection limit, not a Native injection bypass proof: no setuid execution/authentication was attempted. DYNAMIC_LOADER_TRUST and complete ELF/NSS runtime closure remain BLOCKED. Static dependency manifest and PAM/mock contracts are verified only within their stated scope.

Ruff, Format (1,239 files), Wheel source-byte checks and deterministic binary/source bundle rebuild all pass. Full Workspace/Export/Stage/Commit SHA equality is the final Git gate and is logged privately without making this document contain its own digest.

| Ordinary-UID metric | B-2F baseline | B-2G candidate |
| --- | ---: | ---: |
| GUI startup median, n=3 | 2.638s | 2.481s |
| GUI Idle RSS median, n=3 | 174.96MiB | 175.34MiB |
| Response p50 median | 0.01483ms | 0.01050ms |
| Full static package verification | 47.009ms | 83.831ms |
| Manifest validation | 0.042ms | 0.065ms |

Candidate dependency SHA verification: 11.623ms; PAM/NSS static trust regeneration: 11.390ms (one warmup, n=3). The expanded graph costs more verification time. It runs on package qualification, not each GUI poll. Actual Native verification latency is unmeasured. No performance improvement claim is made.

Shared-host PSI varied during low-cost work. Actual model preflight sampled avg10 0.05→0.04→0.03 with >4.4GiB available; no model was started during the earlier 0.64 pressure sample. All resource samples are retained. No other process was terminated or WSL configuration changed.

Release candidate `0.2.7`, Native BLOCKED:

```text
bootstrap: 76260cb6ea334b7dfbb1fb277bfac46cd3ab163f2cec8224c58b6389d928163f
broker: 2258b674db39849fbc9ad145d82d0fd8f1731816f9b24ce514ba7c571cd6e1bc
libnative-tc.so: 19f200225cbc163c80b40fbf1de5f39f506fbde0e2b30eb056e3f1ad28f9fff4
tcx.bpf.o: 928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a
Bundle: 99259acf82c1d8b16cc1da4da75518d093d272a235d33a0d10da23969c618f6f
Manifest: 27b7130dded3499a97fdd6a940998be3e0cf57555b3bc9efaba71bafb955182b
```

Read-only candidate verification:

```bash
.venv/bin/python -m soc_agent.security_ai.ebpf_tc verify-package \
  --package .git/ebpf-dynamic-trust-audit/release-package \
  --manifest-sha 27b7130dded3499a97fdd6a940998be3e0cf57555b3bc9efaba71bafb955182b
```

This command does not authenticate, install, grant capabilities or collect packets. Existing B-2F packages must be regenerated for the new dependency/PAM schema; there is no automatic schema upgrade or Root installation. Native operation requires the separately approved work described above and a new reviewed gate change; neither a Manifest edit nor approval alone opens this build.

# Phase B-2H — Dynamic loader isolation and NSS trust closure

## Threat model and qualification scope

Baseline: `bfa71705942c05f9e5780453c5c3aac5ad97f8ce` (B-2G). This change strengthens the existing execution path; it does not introduce a collector or change TCX, Zeek, models, preprocessing or security policy. Native release remains **BLOCKED**. All executions in this qualification are ordinary-user compilation, static inspection, read-only observations or fixtures. No password authentication, privileged installation, capability changes, BPF load, TCX/TC changes, capture or traffic generation is performed.

A hostile application environment may load code before `main()`. An already compromised ordinary-user parent is not an authentication authority. Root-owned installation, a kernel-established secure entry, a fixed executable FD, approved session scope and fresh terminal PAM are independent prerequisites. Post-load hashing cannot make previously executed hostile code safe.

## LD_AUDIT root cause

B-2G's valid audit module wrote its fixture marker while the base-namespace checker returned success. The checker used `dl_iterate_phdr()` and checked `/proc/self/maps` only at addresses obtained from that enumeration. Audit libraries occupy a separate namespace, so consulting maps for selected base objects did not cover the audit module. This is an ordinary-user reproduction, not proof of an attack against a setuid/root installation.

The B-2H fixture requires the same valid audit module to execute its marker and the process-wide mapping verifier to reject it. This demonstrates **detection after execution**, not prevention before `main()`.

## Trusted exec boundary and alternatives

| Approach | Decision and limitation |
| --- | --- |
| Sanitized fresh exec | Use a shared fixed C environment at the existing verified Broker `fexecve` boundary. New process receives only `PATH=/usr/bin:/bin` and `LANG=C`. This does not repair an already compromised parent. |
| Kernel secure execution | Preserve the Bootstrap requirement for real ordinary UID, effective root and `AT_SECURE=1`. Plain sudo/root invocation is rejected. Actual installed secure execution remains pending. |
| Static Bootstrap | Not selected: PAM/NSS still use dynamic modules and helpers; statically linking glibc alone does not close that dependency boundary. No new static framework is introduced. |
| Root-owned launcher | Preserve the fixed `/usr/libexec/soc-agent-ebpf` installation, root-owned parents, verified manifest and held Broker executable FD. Actual installation is prohibited in this phase. |

The Bootstrap clears its inherited environment after validating the required secure entry. It never claims this removes previously loaded code. The Broker is executed through the held verified FD with `soc_clean_environment()`. Broker startup, command admission and Loader load admission reject any environment other than the exact two-variable allowlist, including duplicate, missing or mutated entries. Cleanup of already-owned links is outside this admission check.

All `LD_*` variables, `GLIBC_TUNABLES`, Python import settings, shell startup variables, locale overrides and arbitrary `PATH` values are absent from the new execution environment. No shell or caller-selected executable path is introduced. The fixture uses the same C environment in an actual ordinary-user `fexecve`; its polluted parent still executes the audit/preload marker, while the fresh child passes the mapping and environment checks.

## Runtime mapping attestation

`trust.c` retains the base-library checks and additionally scans the entire `/proc/self/maps` executable set across namespaces. The scan is bounded to 2,048 lines of at most 1,024 bytes. Each non-self file-backed executable mapping must resolve through trusted root-owned paths, match a release dependency, and match the held verified file's device, inode, mode, length and SHA256. Deleted, anonymous executable and memfd executable mappings are rejected. The main executable has a separate root-owned SHA/inode check at each release entry. The kernel vDSO is matched to `AT_SYSINFO_EHDR`; the x86-64 vsyscall exception is restricted to its fixed kernel range.

This is a **LIMITED current executable mapping snapshot**, not a complete mapping history or proof of all code ever executed. It does not establish that a constructor has not already run, that an object has not been unloaded, that writable memory has not been corrupted, or that a compromised observer reports truthfully. The `/proc` scan and hashing are not atomic against arbitrary hostile concurrent remapping. Those limitations keep loader isolation and runtime closure BLOCKED for Native release. No positive snapshot bypasses the compiled Native gates.

## NSS trust closure and identity

Read-only system configuration:

| Databases | Configured services | Scope |
| --- | --- | --- |
| passwd, group | files systemd | Direct Bootstrap identity queries |
| shadow, gshadow | files systemd | PAM/account-related scope; actual runtime usage pending |
| hosts | files dns | Declared configuration, not a claim of direct Bootstrap lookup |
| networks | files | Declared configuration |
| protocols, services, ethers, rpc | db files | `db` module missing on this host |
| netgroup | nis | `nis` module missing on this host |

A configured service is not proof that its module was loaded. The manifest now separates direct identity databases from account-related databases and records which databases refer to missing services. Policy is **ALL_CONFIGURED_NO_IMPLICIT_EXCLUSION**. Missing db/nis remain a release blocker; they are not silently omitted because direct Bootstrap code does not call these databases. Excluding them would require a reviewed proof of all PAM/NSS/helper lookup paths and an explicit scoped policy. Changing `/etc/nsswitch.conf` or installing packages would require separate approval; neither is done here.

The bounded, reentrant UID/name lookups already cross-check username, numeric UID and primary GID against the approved session. Bootstrap additionally cross-checks `getgrgid_r` and `getgrnam_r`, group name and numeric GID. A missing result, buffer/lookup failure or mismatch fails closed before PAM. Primary group membership follows the checked passwd GID; supplementary groups are cleared on Broker privilege separation and cannot grant Broker authority. NSS identity is not authentication.

## PAM and startup authentication preservation

The fixed service remains `soc-agent-ebpf`, with the existing absolute root-owned `pam_unix.so` auth/account module policy and pinned configuration/dependencies. Terminal ownership/session/foreground, bounded timeout, one password challenge, account management and release rechecks remain. There is no GUI password, sudo cache admission, stored password or persistent authorization. One fresh terminal challenge is required per application execution; approved in-session operations reuse only that application's live, scoped Broker authority. All PAM results here are Mock/Fixture; actual PAM is pending.

## Capability, release manifest and Native gates

Candidates remain CAP_BPF and CAP_NET_ADMIN. CAP_PERFMON is not established as necessary for this SCHED_CLS path; actual permitted/effective/inheritable/bounding/ambient behavior remains **UNKNOWN** until separately approved Native qualification. GUI/model workers receive no authority or Link FDs. No capability calls that modify process credentials are executed.

The strict release manifest binds the fixed new-exec environment policy, limited mapping scope, NSS database policy and per-database missing module evidence, alongside existing ELF graph, system config snapshots, PAM policy and artifact SHAs. Verification regenerates these facts; recomputing attacker-controlled JSON hashes does not establish root installation trust. Neither manifest edits nor these fixtures open the Native gates. Older packages require explicit regeneration and a new installation review.

## TCX, cleanup, GUI, audit and recovery

The TCX observer remains `TCX_NEXT(-1)` and its object is unchanged. Legacy TC remains blocked. Broker-private Link FD ownership, no pinning, foreign link preservation and uncertain cleanup reporting remain. New environment/release admission failures do not gate the owned-FD cleanup path. Recovery never authenticates, reattaches or infers automatically.

The existing four screens, cards, graphs and timelines remain. System adds loader trust, mapping scope, environment contract and NSS scope policy to the existing qualification panel; no new polling worker or payload retention is introduced. Before qualification these fields show UNKNOWN; after package qualification Native loader trust still reads BLOCKED. Existing append-only package qualification records and snapshot digest cover the new policy, without password data or modification of historical audit files.

## Tests, performance and independent Export

Final measured results and artifact identities are appended after frozen-source qualification. Initial failures are retained separately; a passing rerun alone is not treated as a fix. Workspace, independent Export, explicit Stage and committed blobs must match before Push. Existing user files, model artifacts, datasets, Native evidence and historical audit files are excluded from the selective change set.

## Remaining blockers and next approval scope

No Native release is ready. Required future approvals include reviewed root installation at `/usr/libexec/soc-agent-ebpf`, the exact PAM policy, a newly generated release manifest and artifact hashes, one terminal authentication per app, capability qualification, kernel verifier and TCX coexistence/ownership/cleanup tests. Proposed bounded scope stays `lo`, explicit namespace and ingress/egress selection, 300 seconds, 4,096 events, queue 32, 256MiB Broker address space and 20 CPU seconds; app authority expires within 3,600 seconds and at most 16 explicit runs. No pinning, automatic restart, traffic generation, Native AI, DNS9 or operational promotion is authorized. This phase supplies no working Native launch command and does not request opening the gates while loader/NSS closure is unresolved.

## Official sources

- [Linux dynamic loader manual](https://man7.org/linux/man-pages/man8/ld.so.8.html): secure execution, namespace-separated LD_AUDIT, search order and environment semantics.
- [dl_iterate_phdr manual](https://man7.org/linux/man-pages/man3/dl_iterate_phdr.3.html): scope and iteration API.
- [glibc 2.39 NSS module implementation](https://github.com/bminor/glibc/blob/glibc-2.39/nss/nss_module.c): built-in files/dns and dynamically resolved service modules. Source semantics do not prove Native runtime usage.

Additional source evidence: [glibc 2.39 dl_iterate_phdr implementation](https://github.com/bminor/glibc/blob/glibc-2.39/elf/dl-iteratephdr.c) explicitly selects the caller's namespace. [glibc 2.39 rtld implementation](https://github.com/bminor/glibc/blob/glibc-2.39/elf/rtld.c) contains the separate audit loading path and secure-name restrictions. These sources explain the B-2G observation; the host's patched glibc binary is independently hashed rather than assumed byte-identical to upstream. [Linux 6.18 BPF syscall source](https://github.com/torvalds/linux/blob/v6.18/kernel/bpf/syscall.c) informs the candidate capability profile; actual WSL2 kernel capability enforcement is still untested.

The proposed installation approval specifically includes the existing root-owned setuid Bootstrap mode `04755`, Broker `0555`, and Loader/BPF Object/release manifests `0444` under the fixed non-writable installation root; it is not permission for a root GUI or arbitrary sudo command. The PAM service remains a separate root-owned, non-user-writable system configuration approval. This is a documented future trust target, not an installation performed by this change.


## Final frozen-source qualification

Final dynamic trust cohort: **71 PASS**; strengthened installation snapshot/audit assertion: **1 PASS** (combined focused run 72). Broad cohorts: release 67, installation 50, TCX/Native 147, Broker 63, existing unit 693, integration 58, offline actual RF/LR 1, GUI 17, Audit/Recovery 125: all PASS. These overlap and are not summed. The broad initial dynamic cohort 67 is superseded by 71. All implementation source hashes match the final Export; the only subsequent test changes add contract forgery coverage, snapshot assertions and correct the evidence label from base namespace to process-wide snapshot. Expanded tests run from their final source.

One first-pass release test failed because it asserted the previous inline `env` expression. The assertion was updated to require the shared fixed environment function; the failed transcript is preserved. This was not a production security failure or a flaky-test rerun. No failed behavioral test is hidden by a rerun. Initial lint found one long embedded C fixture line; it was split without changing behavior.

Actual offline Zeek/PCAP input produced two COMPLETE RF/LR receipts and READ-only investigations. Queues drain to zero; audit/recovery digests match; recovery creates no new inference. This proves the existing offline integration, not Native AI.

Ruff, Format, Wheel source-byte checks, deterministic binary rebuild, bundle equality and Diff checks pass. Native commands remain blocked.

| Ordinary-user metric | B-2G baseline | B-2H candidate |
| --- | ---: | ---: |
| GUI startup median, n=3 | 2.7264s | 2.6020s |
| GUI Idle RSS median, n=3 | 175.0039MiB | 175.0117MiB |
| GUI response p50 median, n=3 | 0.0126ms | 0.0246ms |
| GUI idle CPU (one core), n=3 | 0.2734% | 0.2738% |
| Full static package verification | 99.7579ms | 94.8957ms |
| Manifest validation | 0.1186ms | 0.1245ms |

Candidate dependency SHA verification: 10.5621ms; PAM/NSS static regeneration: 12.6789ms (warmup 1, n=3). Fixed environment preparation/validation: 0.00039ms (warmup 1, n=100), excluding exec/authentication. Full static package verification: warmup 1, n=3; Manifest: warmup 10, n=100.

Shared WSL2 host, no GPU, ordinary-user fixtures. Memory and PSI samples are retained per suite and profile. Actual RF/LR tests ran serially only after three samples with >=2GiB available and memory PSI avg10 <0.2. Measurements do not establish a Native performance improvement. No extra polling worker or heavy chart library was introduced. Native authentication, Kernel mapping verification overhead and Native collector throughput are UNKNOWN.

Candidate version `0.2.8`, Native BLOCKED:

```text
bootstrap: fb74d77c628806a061a1867c6fa4b2a9d58f93670b4a9016ba7981d889ffe06b
broker: f2ee88b7aa0e55b208ab0d8c70046754bcdd229cefa9fc44e322c2cc66857c9c
libnative-tc.so: d94b3ee688eb4bf2595495509b50607ff38c1e1557d1a84fa9f7c8d2e88cd337
tcx.bpf.o: 928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a
Bundle: deae0d0f0fd06b2b57b13e588d458a7d3d143cbb3327f4938e3a7afb8d7f3e6d
Manifest: 66a79fe0cdd17d457243263dbdbf48cd6cbceae55600c2926f90899d57551025
```

Safe read-only package check (does not install, authenticate, grant capabilities or capture):

```bash
.venv/bin/python -m soc_agent.security_ai.ebpf_tc verify-package \
  --package .git/ebpf-loader-isolation-audit/release-package \
  --manifest-sha 66a79fe0cdd17d457243263dbdbf48cd6cbceae55600c2926f90899d57551025
```

Verdicts:

- `DYNAMIC_LOADER_ISOLATION`: `BLOCKED_NATIVE_PREMAIN_NOT_QUALIFIED`
- `LD_AUDIT_PREMAIN`: `UNRESOLVED_PARENT_EXECUTION_IS_NOT_UNDONE`
- `ELF_DEPENDENCY_CLOSURE`: `BLOCKED_COMPLETE_RUNTIME_HISTORY_NOT_PROVEN`
- `NSS_TRUST_CONTRACT`: `BLOCKED_MISSING_DB_NIS_NO_IMPLICIT_EXCLUSION`
- `PAM_TRUST`: `PRESERVED_STATIC_AND_MOCK`
- `RUNTIME_MAPPING_ATTESTATION`: `LIMITED_PROCESS_WIDE_EXECUTABLE_SNAPSHOT`
- `CAPABILITY_PROFILE`: `UNKNOWN`
- `STARTUP_AUTH_CONTRACT`: `VERIFIED_FIXTURE_ONCE_PER_APP`
- `TCX_CLEANUP`: `PRESERVED_FIXTURE`
- `GUI`: `PRESERVED`
- `AUDIT_RECOVERY`: `VERIFIED_FIXTURE`
- `NATIVE_RELEASE`: `BLOCKED`
- `NATIVE_ROOT_INSTALL`: `PENDING`
- `NATIVE_AUTH`: `PENDING`
- `NATIVE_VERIFIER`: `PENDING`
- `NATIVE_TCX_ATTACH`: `PENDING`
- `NATIVE_AI`: `BLOCKED`
- `DNS9`: `BLOCKED`
- `OPERATIONAL_PROMOTION`: `BLOCKED`

Stage/Export/Commit SHA receipts and remote-head equality are recorded privately after commit to avoid self-referential document digests. Root installation and Native qualification require separately reviewed changes and explicit approval; none is executed here.

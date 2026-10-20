# Phase B-2I — Root-cause security architecture remediation

The architecture decision and SUID installation proposal below are historical and superseded by [the OS-entry review](ebpf-native-os-entry-review.md). The current candidate removes custom SUID execution and blocks the unimplemented OS authentication handoff. Earlier results do not certify that handoff.

Baseline: `08442c589eeac5396dce47120482ce0632c44f9b`. This release is a nonprivileged architecture candidate, **not Native release qualification**. No root installation, PAM/sudo authentication, capability modification, BPF load, TCX/TC operation, network change, capture or generated traffic is performed. Native release, Native AI, DNS9 and operational promotion remain BLOCKED.

## 1. Root cause: hypotheses, evidence and counterevidence

| Problem / hypothesis | Evidence | Counterevidence / limit | Conclusion |
| --- | --- | --- | --- |
| LD_AUDIT is proof of Root injection | B-2G/H ordinary-user dynamic probes execute audit callbacks before main; base-namespace enumeration missed the audit namespace | No privileged/setuid execution was attempted. A compromised ordinary parent is not itself proof of Root compromise | The demonstrated flaw is a pre-main inspection boundary, not a demonstrated Root exploit |
| A post-main verifier can exclude all previously executed code | B-2H process-wide maps detects foreign executable mappings | Constructors may already have run or unloaded; hostile interposition/remapping can compromise the observer | Post-load maps is diagnostic evidence, not an authentication or pre-main isolation authority |
| Removing environment variables in the original process is enough | The fresh-child fixture receives a clean environment | `clearenv` does not unload an existing audit/preload DSO or discard parent memory | Put a true exec boundary before any dynamic loader in the trusted Entry |
| Whole-process dependency SHA closure is the security boundary | Release snapshot pins files, interpreter metadata and configuration; changed snapshots reject Native admission | This cannot attest every past instruction or defeat Root administrators who change trusted OS files; libraries may have legitimate security updates | Root-owned immutable paths and a fixed fresh exec are the execution trust boundary. SHA snapshots provide reproducibility/update admission, not complete code-execution history |
| Missing global db/nis modules necessarily break authentication | `/etc/nsswitch.conf` references db for protocols/services/ethers/rpc and nis for netgroup | Direct authentication identity code calls passwd, not these databases; numeric Broker authorization needs no NSS names | Distinguish configured services from required role scope. Keep all missing-module evidence; do not install, edit config or silently accept unknown PAM paths |
| BPF capabilities must remain Effective for the entire application | Load and TCX attach require privileged operations; approved restarts need future authority | Ownership of a private Link FD is different from authority to load new programs; no GUI/model privilege is necessary | Retain only the approved Permitted set for bounded explicit restarts; use Effective rights only around Load/Attach, and clear Inheritable/Ambient after Broker exec |

Read-only facts are observations. The source-derived capability/PAM scope is a design hypothesis until actual WSL2 qualification; it is not promoted to Native proof.

## 2. Architecture decision record (superseded by additional review)

Three alternatives were evaluated against the same once-per-application password policy.

| Criterion | A: custom PAM with static Entry + isolated Helper (historical selection) | B: OS sudo entry + restricted Broker | C: root-owned service + session authorization |
| --- | --- | --- | --- |
| Pre-main injection | Static syscall Entry has no interpreter, DT_NEEDED, dynamic segment or user DSO loader; clean FD exec precedes Helper loading | Relies on sudo's secure entry and policy/environment handling | Service starts from trusted service manager environment, not an interactive parent |
| Dynamic dependencies | Only the later fixed PAM Helper/Broker use root-owned system libraries | sudo, policy plugins and Broker dependencies remain | Service manager, daemon and authentication dependencies remain |
| NSS/PAM | Existing single terminal PAM policy retained; Helper owns names/account policy; Broker numeric | Additional sudoers/NOPASSWD/cache/PAM policy proof required | Separate authenticated session protocol and account policy needed |
| Capabilities | Bounded Root authentication phase, then nonroot Broker with scoped P; E only for work; I/A zero | Similar restriction required after sudo | Long-lived service authority or more complex workers |
| Session authentication | Existing one fresh password challenge per app; no cache authority | `sudo -k` cannot itself guarantee a password under NOPASSWD; policy must be qualified | Password proof and replay-resistant per-app authorization must be implemented |
| Root attack surface | Small freestanding Entry + existing bounded PAM path; no extra daemon | Mature OS tool but expands deployment/policy integration | Persistent privileged attack surface and service management |
| Link ownership | Existing Broker-private Link FD retained | Can retain same Broker | Service would own links or pass them to workers |
| Crash cleanup | Existing Broker lifetime/FD cleanup; no automatic reattach | Similar supervised child lifecycle | Service/application lifetimes require additional coordination |
| WSL2 | Static x86-64 build tested; actual SUID, capabilities and TCX pending | Actual sudo policy and TCX pending | Service manager availability and persistent service lifecycle add uncertainty |
| Maintainability | Reuses existing PAM/Broker/IPC/TCX contracts; one small new entry | Less custom authentication code, but incompatible password guarantee without extra policy work | More IPC/authentication/deployment architecture than this bounded collector needs |

Historical decision (superseded): **A with a structural split**, not more post-load exception checks. Existing dynamic `bootstrap` becomes a PAM authentication Helper with mode `0555`; only new syscall-only `entry` has a proposed `04755` installation contract. A direct Helper invocation cannot acquire privilege or mint a trusted entry proof. B/C are not implemented or automatically installed.

## 3. Selected trust boundary

```text
ordinary GUI / CLI (untrusted authority source)
  -> root-owned static Entry [no interpreter, libc, NSS, PAM or DSO]
  -> execveat(held fixed Helper FD, fixed argv, exact clean env)
  -> PAM Helper [fresh terminal challenge + account policy + approval]
  -> execve(held fixed Broker FD, fixed argv/env)
  -> nonroot numeric Broker [bounded session and command allowlist]
  -> reviewed Loader / TCX_NEXT observer / private Link FD
```

`entry.c` is x86-64 freestanding C with its own syscall startup, linked `-nostdlib -static -no-pie`, without a dynamic section/interpreter or unresolved dynamic symbols. It has a non-executable stack and no libc initialization or constructors. There is no custom static glibc/PAM build: avoiding their hidden dynamic loading is the point. Because it supplies no libc TLS startup it uses no compiler stack protector; the bounded code contains no formatted input, heap allocator, dynamic path parser or arbitrary command. This new privileged TCB still requires independent review and actual Root qualification.

Before its fixed exec, Native Entry checks real/effective identity, kernel AT_SECURE, fixed root-owned non-writable parent directories, no symlink traversal, single-link exact-mode files, and its own held inode versus `/proc/self/exe`. It opens only fixed `entry` and `bootstrap` names, holds the Helper executable FD, and executes that FD. The fixed input FDs are untrusted IPC/approval/audit requests until the Helper validates them; they are not authentication authority. Other inherited descriptors are closed. Before exec the Entry resets ignored signal dispositions and the blocked signal mask, cancels inherited alarm, fixes cwd to `/`, and sets umask `077`. Exec alone would preserve blocked/ignored signals, allowing a polluted parent to disable the PAM alarm; the ordinary-UID child fixture explicitly checks SIGALRM unblocked, SIGINT default and cwd `/`. Seccomp, no_new_privs, tracing or resource restrictions that prevent the required secure transition fail closed rather than being bypassed. User paths, Python imports, shell strings and arbitrary executables are not accepted.

The Helper is root-owned trusted release code. The root installation/manifest/reference build pins its ELF interpreter and disallows RPATH/RUNPATH. User-writable libraries and installation parents are rejected. A normal user cannot change these files between metadata checks and exec. An administrator capable of rewriting trusted Root files is outside this boundary; approved updates must quiesce sessions and atomically exchange a complete release. In-place mutation of a live release is unsupported.

## 4. Entry proof and authentication

The static Entry creates a sealed, root-UID-owned **376-byte boundary proof**, not a password token. It contains the exact 352-byte approval envelope, numeric UID/GID and current PID. The Helper requires seals, root creation, approved group, exact size, process identity and envelope equality; it closes reserved FD 31 immediately after checking it. The proof is never passed to GUI/Broker, written to disk, recovered or treated as PAM success. A stale proof cannot authorize another process/session. An unrelated privileged process could mint Root-owned evidence; compromise of Root is not claimed to be preventable here.

The existing post-PAM, root-created sealed Broker authority remains separate. Application password policy remains one terminal password at startup, no additional password for approved in-session Start/Stop/Restart, no stored password/token and no authority recovery after expiry/application/Broker exit. A new app needs fresh authentication.

The Helper still validates TTY ownership/session/foreground, explicitly displays approved scope/digests, uses the fixed `soc-agent-ebpf` PAM service, one echo-off challenge, `pam_authenticate` and `pam_acct_mgmt`, bounded timeout and release/scope rechecks. Root/sudo direct invocation is rejected by real-UID/entry-proof checks. No sudo cache or NOPASSWD result substitutes for PAM. All positive authentication results here are Mock/Fixture; actual challenge behavior remains pending. The static boundary does not repair a compromised ordinary-user account or terminal, prevent pre-existing user-session keylogging/phishing, or supply a protected attention/display path. Preventing DSO inheritance into a privileged image is narrower than proving the entire interactive session trustworthy.

## 5. NSS simplification without policy bypass

- **Static Entry:** zero NSS operations or DSO imports.
- **PAM Helper:** bounded getpwuid_r + getpwnam_r bind the approved numeric UID and primary GID to the PAM username. Name lookup failure or mismatch remains denial. The redundant getgrgid_r/getgrnam_r loop is removed because group names grant no authority; numeric primary GID and kernel Peer Credentials remain checked. Supplementary groups are cleared before Broker transfer.
- **Broker:** no direct passwd/group/name or PAM imports. Every command still verifies kernel peer UID/GID/PID, process start ticks, namespace, approval/session digest, sequence and approved resource scope. User-provided names cannot grant authority.
- **PAM account policy:** preserved. Fixed pam_unix auth/account source calls passwd/shadow helpers. The manifest records these as direct identity/account databases and separates missing required-role services from all configured missing services.

Current db/nis missing evidence and database associations remain in the manifest. They are not required by direct Entry/Broker operations and are not silently erased from diagnostics. No NSS package or system configuration is changed. This does **not** prove every transitive NSS/systemd/PAM/helper runtime lookup. PAM may reach additional implementation-dependent paths; full required Native scope remains BLOCKED until reviewed actual authentication/account observation. No fallback accepts lookup failure.

## 6. Capability and privilege lifetime

| Phase / operation | Proposed authority | Enforcement / status |
| --- | --- | --- |
| Entry and terminal PAM | Root only in fixed trusted bounded path | Actual Root/SUID/PAM pending; no general shell/command |
| Fixed Broker exec transfer | Existing BPF + NET_ADMIN P/E/I/A transfer | Existing guarded code, Native pending |
| Broker startup | Nonroot UID/GID; clear Ambient and Inheritable; Effective=0; P/B limited to two candidates | New guarded transition and exact-set checks |
| PREPARE / STATUS | E=0, I=0, A=0 | Numeric authorization and snapshots only |
| Explicit LOAD / ATTACH | E=BPF+NET_ADMIN temporarily; P/B same two | Fixed allowlisted operation, independently checked Loader; drop E after dispatch, including errors |
| ACTIVE / own-Link cleanup | E=0, I=0, A=0 | Own-FD operations/close; no ID-based foreign deletion or automatic escalation |
| Explicit approved restart | Retained bounded P permits an explicit work transition | No automatic retry; same session/scope/generation checks |
| App/Broker exit | Authority ends; owned FDs close | No persistent approval; uncertain cleanup stays unverified/orphaned |

CAP_PERFMON is not established as necessary for this SCHED_CLS program class; CAP_BPF and CAP_NET_ADMIN remain source-derived candidates. BPF Link ownership does not inherently require permanent effective load authority. Actual LSM/WSL2 map/link checks may deny FD operations without additional rights; this is **PENDING**, not a reason to silently broaden capabilities. Failure is fail-closed with owned-FD cleanup attempted and uncertainty reported.

Effective/Permitted/Bounding/Inherited/Ambient sets are checked separately. After Broker exec, I/A are zero: a subsequent exec cannot propagate them. The Broker has no arbitrary exec/fork command path, no FD handoff to GUI/model workers, and no new privileges flag prevents exec-based privilege gain. GUI and AI remain ordinary siblings. Permitted BPF/NET_ADMIN remain a residual Broker authority for bounded explicit restarts; a compromised Broker is still a security concern, not made harmless by clearing Effective rights. All capset/prctl credential-changing paths are behind the closed Native gates and were never executed by qualification.

## 7. TCX ownership, GUI and audit preservation

TCX object/ABI and `TCX_NEXT(-1)` remain unchanged. Broker retains Link FD ownership, no pinning, no foreign Link removal, no Legacy TC Native activation and no automatic reattach. Cleanup does not acquire new objects by ID or depend on successful reauthentication/release revalidation. Drop/cleanup failure remains fail-closed/unverified rather than being reported as successful cleanup.

The four existing screens/cards/charts/timelines remain. The existing System panel adds Entry SHA/architecture, authentication NSS scope and numeric Broker identity scope. Qualification is append-only and includes Entry identity, architecture and privilege-lifetime contract. Existing versioned audit rows, session identity, feature/model receipts and recovery prohibitions remain. Recovery never restores entry proof, PAM authority, hooks or unfinished inference.

## 8. Release migration and dependencies

Candidate `0.2.9` includes a new `entry` payload and requires it in the C execution descriptor, with SHA, size and exact `04755` mode. PAM Helper `bootstrap` changes to `0555`; Broker stays `0555`; Loader/Object/manifests remain read-only. The outer approved release digest binds Entry identity while the existing 272/352-byte plan/envelope ABI stays unchanged. Dynamic trust evidence adds the static Entry ELF contract and role-specific NSS policy; the manifest adds the explicit privilege-lifetime contract. Previous packages cannot be silently upgraded or activated by editing JSON.

No installation occurred. A future approved migration must remove the old Helper SUID mode, verify the new static Entry, quiesce all old processes, verify the PAM configuration separately, and atomically publish a complete release. Rollback is a separately approved complete-release operation; it must not reactivate an unqualified SUID Helper.

System library security updates require snapshot regeneration/requalification and a newly approved manifest. SHA pinning is retained for admission/change detection; it is not claimed as proof that only those instructions ever executed. Root-owned OS libraries/configuration form the system trust base. Runtime maps stays LIMITED diagnostic evidence and never authenticates a session.

## 9. Verification and evidence

Nonprivileged tests exercise actual syscall-only ELF execution with hostile LD_AUDIT/LD_PRELOAD parents and a fixed harmless dynamic child, pure entry-proof mutations/replay, numeric identity, missing/excess capabilities and exec leakage, old manifest/install/IPC/PAM contract regressions, TCX ownership and recovery. A separate compile-time ordinary-UID fixture target cannot create a Native entry proof or run as Root. Native `entry` itself remains unconditionally blocked.

Compilation proves neither Kernel verifier acceptance nor actual SUID/PAM/capability/TCX behavior. The first compile failed because GNU-only constants were not exposed; adding `_GNU_SOURCE` fixed that compile contract. A development lint unused import was removed. Initial failures are retained, not represented as flaky success. Two existing mocked-worker failure tests also depended on real host PSI and reached the production resource-denial branch instead of their intended mocked failure branch. Their resource inputs are now explicitly mocked, and two deterministic high-PSI cases assert that the worker is never invoked. No production Zeek/headroom code or threshold was changed. Final counts, digests, performance and independent-source identities are appended after qualification.

The remediation additionally found a kernel-state inheritance issue: removing env and replacing memory does not reset blocked or ignored signals. This was corrected structurally at the Entry exec boundary and the affected qualification was refrozen. Earlier passing tests are retained as historical evidence, not substituted for the final updated Entry qualification. A high-PSI preflight stopped before actual model execution; this is a resource guard event, not a failed model test.

## 10. Remaining blockers and Native approval plan

Native release remains BLOCKED. Needed future review/approval: exact Root-owned static Entry + Helper/Broker/Loader/Object installation; removal of old Helper SUID; fixed PAM configuration/modules/helpers and actual one-password/account behavior; secure-exec/SUID behavior on WSL mount/namespace; actual capability transitions and zero GUI/worker leakage; Kernel verifier/TCX support, coexistence, FD ownership and cleanup, including crash/SIGKILL. NSS/PAM runtime scope and OS dependency provenance are not declared closed.

Proposed bounded scope remains explicit `lo`, current approved namespace, ingress/egress allowlist selection, 300 seconds, 4,096 metadata event records (not a Kernel packet-count assertion), queue 32, 256MiB Broker address space and 20 CPU seconds; app authority <=3,600 seconds and 16 explicit runs. No pinning, automatic restart, generated traffic, Native AI, DNS9 or operational promotion. Approval does not open this build's independent compiled Entry, Loader/TCX and Native gates. No Native execution command is supplied while those blockers remain.

## Official source basis

- [Linux ld.so manual](https://man7.org/linux/man-pages/man8/ld.so.8.html): interpreter loading, secure execution and environment handling.
- [Linux 6.18 commoncap](https://github.com/torvalds/linux/blob/v6.18/security/commoncap.c): credentials/capability execution boundary. The running WSL2 patched kernel is not assumed byte-identical.
- [Linux 6.18 BPF syscall](https://github.com/torvalds/linux/blob/v6.18/kernel/bpf/syscall.c): program-class capability admission and Link FD detach. Source reasoning is not a Native probe.
- [Linux-PAM 1.5.3 pam_unix support](https://github.com/linux-pam/linux-pam/blob/v1.5.3/modules/pam_unix/support.c): passwd/shadow/authentication helper paths; distro patches/runtime behavior remain separate evidence requirements.
- [sudo manual](https://man7.org/linux/man-pages/man8/sudo.8.html): cache invalidation alone does not establish this application's fresh-password guarantee across sudoers policy.


## Final independent-source qualification

remediation: **30 PASS**; dynamic: **71 PASS**; release: **67 PASS**; installation: **50 PASS**; native: **147 PASS**; broker: **63 PASS**; unit: **695 PASS**; integration: **58 PASS**; model: **1 PASS**; gui: **17 PASS**; audit: **125 PASS**. Cohorts overlap and are not summed. All implementation source hashes match the frozen Export. The initial signal inheritance issue was fixed and final cohorts were rerun from the refrozen source. A previous model Preflight stopped at PSI 6.96 before any model test started. Three old artifact-list Fixture failures were fixed by including the now-mandatory Entry, without weakening production validation; the failed transcript is retained. Final test results correspond to the updated static Entry, including signal/cwd reset. The two host-PSI-dependent mocked-worker tests were isolated from host resources, with two explicit high-PSI blocking cases added; production headroom thresholds remain unchanged. Earlier logs remain historical evidence.

Actual offline Zeek/PCAP input yielded two COMPLETE RF/LR receipts and READ-only investigations. Both queues finish at zero, audit/recovery digests agree, and recovery creates zero new inference. This is offline Artifact regression, not Native inference. Ruff, Format, deterministic artifact/bundle rebuild, Wheel source-byte equality and Diff pass.

| Ordinary-UID metric | B-2H baseline | B-2I candidate |
| --- | ---: | ---: |
| GUI startup median, n=3 | 2.2296s | 2.6468s |
| GUI Idle RSS median, n=3 | 175.4727MiB | 175.1250MiB |
| GUI response p50 median, n=3 | 0.0137ms | 0.0180ms |
| GUI idle CPU (one core), n=3 | 0.2790% | 0.2652% |
| Full static package verification | 76.2585ms | 79.1258ms |
| Manifest validation | 0.0651ms | 0.0666ms |

Candidate dependency SHA verification: 11.2178ms; static PAM/NSS/Entry evidence generation: 14.5103ms (warmup 1, n=3). Environment preparation/validation: 0.00082ms (warmup 1, n=100, not exec/auth). Full package: warmup 1, n=3; manifest: warmup 10, n=100.

Initial startup median increased by 0.4172s. A targeted additional interleaved A/B measurement (n=3 each) gave 3.0262s before and 2.8533s after; its candidate samples include a 6.815s outlier. Both complete cohorts are retained, with no outlier removal or replacement of the first result. Startup regression causality remains UNKNOWN under variable shared-host pressure; no speedup or absence of regression is asserted. Functional GUI preservation is distinct from startup performance qualification.

Shared WSL2 host with other processes. Memory/PSI and exact profile samples are retained; actual model tests ran serially after three >=2GiB available / PSI avg10 <0.2 preflight samples. No Native performance improvement is claimed. Actual SUID/PAM/Kernel/capability latency and correctness are UNKNOWN. No extra polling worker or visualization library was added.

Candidate version `0.2.9`, Native BLOCKED:

```text
entry: cb55b17610b1d93d7d80f959532972c3f29684f347879c4af7248609fa4f2ef9
bootstrap: 874c1d1462f082e95dd1b72186c64d4554e0a687093f81ef68735987d62a50f5
broker: c54d99bfe02ff297b83ba7523a052c23be030bb163f00c3b6a39a3a6c40bfcb2
libnative-tc.so: 971c6f2c5921ea400fee86ce04f194baf40e8dbcd62e90ad2fe420b5690dc590
tcx.bpf.o: 928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a
Bundle: fe13bd5d769ab7754cb1425fcc178199d1f766161cf6a6b4eb9b7401bf4521c2
Manifest: 05def12a37bb953ff8ac88e9a1516ae2d7b501c41c77f398ef12ec650ec45d66
```

Safe read-only package verification:

```bash
.venv/bin/python -m soc_agent.security_ai.ebpf_tc verify-package \
  --package .git/ebpf-root-remediation-audit/release-package \
  --manifest-sha 05def12a37bb953ff8ac88e9a1516ae2d7b501c41c77f398ef12ec650ec45d66
```

Verdicts (VERIFIED refers to the stated nonprivileged contract/Fixture scope):

- `LD_AUDIT_ROOT_CAUSE`: `IDENTIFIED_ORDINARY_PARENT_EXECUTION_NOT_ROOT_EXPLOIT_PROOF`
- `TRUSTED_ENTRY_ARCHITECTURE`: `VERIFIED_STATIC_ELF_AND_ORDINARY_UID_EXEC_FIXTURE_NOT_ROOT`
- `ELF_DEPENDENCY_TRUST`: `BLOCKED_NATIVE_OS_DEPENDENCIES_NOT_OBSERVED`
- `NSS_REQUIRED_SCOPE`: `BLOCKED_COMPLETE_PAM_RUNTIME_ROLE_SCOPE_NOT_OBSERVED`
- `CAPABILITY_SCOPE`: `DESIGNED_IDLE_E0_IA0_WORK_BPF_NET_ADMIN_NATIVE_UNKNOWN`
- `STARTUP_AUTH_CONTRACT`: `VERIFIED_ONCE_PER_APP_MOCK_NATIVE_PENDING`
- `TCX_OWNERSHIP`: `PRESERVED`
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

Final Workspace/Export/Stage/committed-blob equality, exact selective file list and remote-head equality are recorded privately after commit to avoid self-referential document hashes. No actual Native/root action is authorized by this report or by the manifest.

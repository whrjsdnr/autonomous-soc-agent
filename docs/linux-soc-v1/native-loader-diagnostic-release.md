# Native Loader diagnostic release — 0.5.1

Baseline: `ad6d1b47ef4b403d4d90859b176f6334eee40bfd`. This is an unprivileged build and installation
simulation, not a Native execution. Installed 0.5.0 remains unchanged.

## Release identity

Manifest: `892bb7ab00a4bb47637f6ce9e5409dbe2864a0db9ba632b3012dae7138c45f7d`
Source Bundle: `2ea494836e666c48a0800991bdd6e765737dfc8f442461dda4b61a95545b26d6`
SHA-pinned unified installation/handoff image: `eb17266d4319d51b03d84104dfe0703a4cfd4e5ab4db1b0ba4ee2db5a0391919`

Prepared artifacts are retained in `.git/tcx-loader-diagnostic-release/`.
The image was prepared and hashed, never executed. It contains the exact new
payload and current 0.5.0 metadata. Manifest digest is not an approval digest.

| Installed filename | SHA256 (0.5.1) | Mode | Versus 0.5.0 |
|---|---|---|---|
| bootstrap | `80b1e23e0213cfcdb0543be5094c118b91c4c343575d8956a855326d6359ea9a` | 0o555 | unchanged |
| broker | `7320657347fc2eeb028576b8ee774ba312b9125ce60c1b5a053d414cba212a6f` | 0o555 | changed |
| entry | `8e4ef82c3fe45ae5a414509316a2922898148ed860bb7ebdde9f743509ce4455` | 0o555 | unchanged |
| libnative-tc.so | `fe990c670902831fa63f62bd125d1ca3dc8fb010e004f5e32b7c763849057475` | 0o444 | changed |
| manifest.bin | `1fa1783a2e6988973d657ce68cabe80850f0add27e47d578f1223e11526354a5` | 0o444 | changed |
| pam-policy.conf | `93af76067bf513b4db8c5a9bd606e348ccde334b83e52f7dc71544c9c1f82696` | 0o444 | unchanged |
| tc.bpf.o | `928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a` | 0o444 | unchanged |
| release.json | `892bb7ab00a4bb47637f6ce9e5409dbe2864a0db9ba632b3012dae7138c45f7d` | 0o444 | changed |
| release.trust | `93c45322e658fda2982a43c17adac6490c5a092f26ba884f14915bad8713e379` | 0o444 | changed |

Root-owned installed 0.5.0 passed the existing exact-release verifier, including
file hashes, ownership, modes and dependency contract. Its Manifest is
`aa09194b6ad9ea4e74fe1df11718977522a2b41842eea6db0794cdb6797e4230`. Broker/Loader diagnostics from ad6d1b4 are reused;
the only new production change selects version 0.5.1. No Gate, capability profile,
packet program, model, GUI or security policy was changed. Dependency checks are
not proof of the entire PAM/NSS runtime closure.

## Scope and installation plan

The release scope fields match 0.5.0: lo, 300s, 4096 metadata records, queue32,
256MiB address space, 20 CPU seconds, CAP_BPF/CAP_NET_ADMIN. The Manifest supports
Ingress/Egress, but the prospective diagnostic run is restricted to **Ingress**,
ifindex1, `net:[4026531833]`. No new run has been approved or started here.
Native AI, DNS9 and operational promotion remain BLOCKED.

After separately authorized installation, the reviewed image would check exact
0.5.0 and process quiescence, retain it under
`/usr/libexec/.soc-agent-ebpf.rollback-aa09194b6ad9ea4e74fe1df11718977522a2b41842eea6db0794cdb6797e4230`,
then publish the verified 0.5.1 directory without overwriting unknown contents.
The archive path does not currently exist. Exact files would be root:root,
executables0555 and other files0444, directory0755. No PAM/system configuration
is installed by this nine-file payload.

Ordinary-UID temporary-directory simulation checked old install/check, refused
new install over old with INSTALL_CONFLICT, retained exact old bytes on rollback,
then installed/checked the new package. This is not Root installation validation.
Publication uses no-replace rename for each directory operation; the update is
**not** a two-directory atomic exchange. If publication fails, retained old bytes
permit a separately reviewed restore. Rollback requires exact release identity
and quiescence; it does not remove unknown files or foreign Hooks. No automatic
restore or retry is claimed. Actual installation has not been attempted.

## Historical first failure and cleanup

Historical session `9f004895-eff5-41b2-93a7-a80d2752ab04` retains its original
Audit and Native Journal. The accepted Counter path supports runtime allocation
and OBJECT_OPEN reached, but not successful object open or Kernel load.
First failing API, raw return, errno, verifier log and Map/Program FD creation
remain **UNKNOWN**. LOAD_VERIFIED publication failure after successful load also
cannot be excluded. TCX attach was downstream and was not reached. Synthetic
EUCLEAN/-117 is not evidence of the original Kernel errno.

Original cleanup combined sticky capture failure with cleanup verdict, and could
return on snapshot/drain failure before explicit object release. This explains
why UNVERIFIED is not proof of leaked resources. The old evidence does not show
which cleanup branch ran or which FDs closed. The new diagnostic code separates
first loader/cleanup failures, preserves API results/errno provenance, inventories
observed FDs and records bounded verifier-log size/SHA. It attempts unattached
object release despite earlier cleanup-evidence errors. These diagnostics have
not yet run Native; an observed release fact would not promote an otherwise
unverified capture to success.

## Current read-only preflight and decision

Old Broker PID725214 is absent. lo has noqueue qdisc and no listed Legacy ingress
or egress filter. **Legacy filter inspection does not enumerate TCX Links.**
Unprivileged bpftool map/prog/link enumeration each returned255 with
`Operation not permitted`. No independent residual-resource or Link ownership
inventory was obtained. PID exit normally releases process-local references,
but is not an independent global resource measurement.

**NO-GO:** cleanup remains UNVERIFIED and current TCX ownership is UNKNOWN.
Therefore no diagnostic-run approval is requested, no password prompt opened,
and no installation, capability change, BPF load or TCX operation performed.
A separately authorized read-only privileged resource/Hook inventory and ownership
review are required before reconsidering installation and one diagnostic run.
Never delete an unowned resource to clear this prerequisite. Even after that
review, a new release-specific approval must bind the above Manifest/Bundle/image
and the single-Ingress scope. Keep one OS-terminal authentication per application
session and no automatic retry. If actual diagnostics identify a failure, report
it and its minimal remedy before further modification or execution.

## Focused verification

Twelve relevant existing tests passed: nine loader-diagnostic tests and three
installer integrity/conflict/rollback tests. Nine unrelated tests deselected.
Native components compiled with existing strict flags and package/reference
inspection passed. Changed-file Ruff/Format and Diff passed. No broad regression,
GUI/model performance run, Wheel or new Fixture framework was added.
All132 baseline user files and the four hashed historical Native evidence files
were verified unchanged. Exact file comparison, scope and preflight results are
in [the evidence JSON](native-loader-diagnostic-release-evidence.json).

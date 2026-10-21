# Native Live E2E attempt and root-cause remediation

Baseline: `02dafc27d186a812a6ba7be4970164eecee43e06`. Kernel 6.18.33.2-microsoft-standard-WSL2,
namespace `net:[4026531833]`, lo ifindex1. One approved Native run used installed
release0.5.1, session `6c2999eb-cefd-4535-a3b9-3fde60851b88`. There was no Native retry, traffic
generation, policy bypass, AI inference or foreign-resource removal.

## Release and authentication

The terminal displayed the exact scope, binary hashes, Manifest and image;
user confirmation preceded one fresh OS-terminal authentication in the existing
SHA-pinned unified entry. The same Broker served STATUS and ATTACH. Root install
replaced the published directory by retention/publication, preserving exact0.5.0
under `/usr/libexec/.soc-agent-ebpf.rollback-aa09194b6ad9ea4e74fe1df11718977522a2b41842eea6db0794cdb6797e4230`.
Each publication uses no-replace rename; the two-directory update is not an atomic
exchange. Unknown files/releases were not overwritten or removed.

Installed0.5.1 passed the existing Root ownership/mode/SHA/dependency verifier:
Manifest `892bb7ab00a4bb47637f6ce9e5409dbe2864a0db9ba632b3012dae7138c45f7d`, Bundle
`2ea494836e666c48a0800991bdd6e765737dfc8f442461dda4b61a95545b26d6`. Bootstrap/entry/packet object were unchanged.
The Broker reached BROKER_READY with PID783878 and start ticks43283248;
SO_PEERCRED, process identity and session/release binding passed the existing
handoff checks. Observed idle E/I/A sets were0; P/B were549755817984
(CAP_BPF+CAP_NET_ADMIN). This does not establish every in-load capability
transition or future TCX support. GUI/AI were never launched with privileges.
Terminal credentials and Broker authorization were not saved as reusable authority.
The later read-only inspection used a separate terminal authentication after the
application had revoked its authorization; it did not reuse or restart the Broker.

## First actual Loader failure

| Stage | Actual evidence |
|---|---|
| LOAD_PREPARE | Passed validation to object opening/load |
| OBJECT_OPEN | Completed sufficiently to enumerate object/maps/programs |
| OBJECT_VERIFY | Schema and attach type/autoload setup reached load |
| BPF_OBJECT_LOAD | `bpf_object__load()` returned-13, immediately saved errno13/EACCES |
| MAP_INIT / RING_BUFFER_INIT | Not reached by Loader after failed object load |
| TCX_ATTACH / LINK_VERIFY | Not reached |

The first diagnostic reports 24,355 bytes in the shared BTF/program Kernel log,
SHA `3b5671a1a050248564f99486ff8af63cc7f651f6ee14068075bcb382c644ef4d`, below64KiB.
0.5.1 persisted its length/SHA only and then erased the buffer. Therefore the
rejecting instruction, exact internal bpf subcommand and detailed cause remain
**UNKNOWN**. EACCES alone is insufficient to prescribe a capability expansion,
Kernel upgrade, parser rewrite or policy exemption. No such change was made.
The failure is now localized to the load API, rather than an invented EUCLEAN
Kernel errno. No exact per-stage timing was captured; Audit timestamps provide
only application transition times.

## Ring Buffer, Network14 and GUI

No TCX Link was created; no capture ran. Normalized Kernel packet events0,
Network14 finalizations/features0. No Native clock calibration/parity, loss rate,
Kernel drop count or GUI Live rendering is verified. Zero normalized events must
not be substituted for unknown Kernel counts. The existing GUI launches after
successful ATTACH, so it was not reached. The preparation/runtime plan's fixture
label is distinct from actual `TCX_UNIFIED_SESSION_NATIVE` handoff evidence;
preparation events are not Native capture success. Models, preprocessing, DNS and
GUI sources were not changed or broadly retested.

## Cleanup and independent inventory

At load return the visible Map/Program FD inventory was0/0; Link FD absent.
This is a post-failure observation, not proof that transient Maps never existed.
[libbpf1.3 source](https://github.com/libbpf/libbpf/blob/v1.3.0/src/libbpf.c)
unloads objects on load failure and closes visible Map/Program FDs; that explains
why a later inventory can be empty without proving that no creation occurred.

The separate cleanup diagnostic reports `owned_object_released=true`. It records
`capture_failure_sticky`, synthetic-117 with no exposed syscall errno. The
release path calls bpf_object__close/free, but their individual close syscall
return values are not separately traced. Entry exit2 and sticky capture failure
keep overall CLEANUP_UNVERIFIED. PID783878 is absent and authorization REVOKED.
No Drain of a ready ring was needed because RING_BUFFER_INIT was not reached.

A separately authenticated read-only post-inspection succeeded for all five
fixed commands: bpftool prog/map/link show and tc lo ingress/egress filter show.
Map0, Link0, sched_cls0, lo filters0. The same11 cgroup Programs remained;
no foreign resource was deleted. Current inventory is independent absence
evidence at inspection time, not retrospective proof of every close syscall or
historical cleanup execution. Past0.5.0 Cleanup remains UNVERIFIED.

Native Journal:8 records, digest `c10512d3e3d240a4b2b36114ed4e3d619de51346395249c5bd70049db7777bdc`.
Application Audit:24 records, digest `76dfb70b39e62dbfe3e876476c3c745fcf9d7f34d81454e2b2791db431d428ff`.
Both chains verified read-only. Existing historical evidence hashes and132
baseline user/ML files were preserved. Actual binaries, session databases,
Journals and terminal artifacts remain private under `.git/tcx-native-e2e-051/`.

## Minimal diagnostic remedy and next release

The diagnosed observability defect was deliberate log-text destruction before
investigation. Candidate0.5.2 fixes that defect, **not the unknown program rejection**:
existing LOADER_DIAGNOSTIC length/SHA is followed by bounded72-byte verifier-text
chunks in the same private append-only Journal. Each216-byte row has the existing
session/sequence/ordinal/hash-chain envelope, offset, length and zero padding.
The decoder checks bounds, contiguity and complete byte count/SHA before exposing
text. Partial evidence stays incomplete and cannot become success. Old0.5.1
Journals without text remain readable. Maximum65,536-byte log takes at most911
chunks under the existing1024-row/240KiB limits. This can add bounded failure-path
fsync latency; it is not a packet-throughput improvement.

No verifier text enters Control/Data IPC. No password, PAM token or packet payload
is recorded; verifier text may contain instruction/register diagnostics and is
restricted to the existing private session evidence. Rendering/export must treat
it as untrusted diagnostic text. Broker ownership, no-pinning, TCX_NEXT, cleanup,
Native AI/DNS9/operational Gates are unchanged. New tests use ordinary-UID injected
load failures and never forward Kernel load operations.

Candidate0.5.2 is **built, not installed or run**:

- Manifest: `7471b886adda9dff073e2f601091a9dece5eedc9a46c4c7a3f2111d77c34fadf`
- Bundle: `0d57b6cbd0de48ff9a48702dcd2849760e1855bd578643049dcf196c35e2984d`
- Unified image: `3933398bb61421e197bd97e14b602ebb93d4e9724eb34d1e21be46f8fcbb5777`

| Candidate installed filename | SHA256 |
|---|---|
| bootstrap | `80b1e23e0213cfcdb0543be5094c118b91c4c343575d8956a855326d6359ea9a` |
| broker | `04c23fce1504e308f77e48ef9e86ddd7ed9c26646d50f1a7a4754a0ba2d706e0` |
| entry | `8e4ef82c3fe45ae5a414509316a2922898148ed860bb7ebdde9f743509ce4455` |
| libnative-tc.so | `e427384eb0b82fc7239d5367560c4863e2636700cfe4c077d06d1369714d7b07` |
| manifest.bin | `f5e450fc8b025b25838dda66366bb5d566b8d8d7051c6f65a1c34fa028ac3b18` |
| pam-policy.conf | `93af76067bf513b4db8c5a9bd606e348ccde334b83e52f7dc71544c9c1f82696` |
| tc.bpf.o | `928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a` |
| release.json | `7471b886adda9dff073e2f601091a9dece5eedc9a46c4c7a3f2111d77c34fadf` |
| release.trust | `3066dd7256719a3ea2d6efeb11f8250d245684823e91c09d84f54f36a4ee9c67` |

A further execution needs fresh approval of these changed bytes and the same
lo/namespace/Ingress/300s/4096 events/queue32/256MiB/CPU20s scope. Exact0.5.1 would
be retained under its Manifest-named rollback path before0.5.2 publication.
Do not install or retry automatically. After a new run, first read the actual
Verifier text, determine the concrete cause, then review any program fix under
another changed-release approval. No claim of Native E2E completion is made.

## Focused verification

Loader diagnostics and Journal tests:16 passed (15 diagnostic cases plus the
existing Journal case). Related selected Dispatcher/Journal regression:11 passed,
4 deselected; these runs overlap and are not added together. Changed-file
Ruff/Format/Diff and strict Native compilation/package verification passed.
No full-model, GUI benchmark, broad regression or Wheel repetition was needed.

## Qualification verdict

| Item | Verdict |
|---|---|
| TRUSTED_INSTALL_NATIVE | VERIFIED |
| OS_AUTH_NATIVE | VERIFIED |
| BROKER_HANDOFF_NATIVE | VERIFIED |
| TCX_VERIFIER_NATIVE | FAILED: load API EACCES; detailed reason UNKNOWN |
| TCX_ATTACH_NATIVE | PENDING |
| TCX_DATA_PLANE_NATIVE | PENDING |
| NETWORK14_NATIVE | PENDING |
| GUI_NATIVE | PENDING |
| AUDIT_NATIVE | VERIFIED: evidence chains, not successful capture |
| CLEANUP_NATIVE | UNKNOWN: release fact and empty inventory, overall UNVERIFIED |

Native AI, DNS9 and operational promotion remain BLOCKED. Actual Kernel packet
metadata has **not** reached Network14 in this attempt.

# TCX variable-stack-pointer remediation — Release0.5.3 candidate

Baseline `95d4e0feea758599f199da045ee7df9564b5d660`; installed0.5.2 is unchanged by this preparation.
Historical diagnosis is retained under `.git/tcx-native-verifier-052/` and was
not rewritten. The first actual verifier error was instruction364 (`r2 += r1`),
EACCES: variable stack access prohibited in the restricted verifier mode.

## Minimal change and preserved contracts

TCX now uses `packet_parser.h`, a small skb-access parser with bounded packet
offsets and fixed-size stack destinations for Ethernet14, VLAN4, IPv4-20,
IPv6-40, TCP20 and UDP8-byte reads. Only the packet-offset argument of
bpf_skb_load_bytes varies. The parser never constructs stack_buffer+packet_offset.
Packet options are length-checked using the same existing formulas; their content
is not interpreted or retained. Port/IP-length conversion remains network order.

The shared host/Legacy `ebpf/parser.h` and `ebpf/tc.bpf.c` were not edited. A
TCX-specific memory-access implementation is needed because adapting the shared
array parser would either retain its variable stack indexing or change the
Legacy compilation contract. The unchanged Legacy parser is the host-test oracle;
no new framework or generic parser abstraction was introduced.

Existing semantics remain: IPv4 IHL5..15, two inline VLAN headers maximum,
IPv6 without extension-header parsing/jumbograms, TCP/UDP, fragment rejection,
malformed versus unsupported classification, and the128-byte inspection window.
Unsupported inputs are not guessed. The TCX caller still rejects hardware VLAN
metadata and multi-segment GSO. No payload/FQDN storage was introduced.

TCX_NEXT(-1), read-only helper use, three bounded maps, Ring Buffer,80-byte event
ABI, per-CPU sequence/counters, clock domains, Network14 Feature order and flow
policy, Link FD ownership, no-pinning and existing cleanup behavior are unchanged.
No capability expansion, mitigation change, verifier bypass or Gate relaxation
was made. Bootstrap/Broker/Loader binary SHAs are unchanged versus0.5.2; TCX
Object and bound manifests/Bundle/image change. Startup selects version0.5.3;
the diagnostic fixture's expected TCX Object hash follows this reviewed change.

## Focused verification

Executed84 related cases: IPv4 IHL5..15 crossed with TCP/UDP and0..2 VLANs;
IPv6 TCP/UDP and VLAN limit; fragments/extensions/jumbograms; invalid IP/TCP/UDP
lengths; truncated/helper-read failure; preserved128-byte window; byte-for-byte
successful80-byte event parity against the unchanged Legacy parser; real Clang
BPF compilation and TCX_NEXT exit-disassembly checks. The legacy compile hash
remains `69de609ea8ee90ecf90d091ec361e46e61ed0638b3175390c77305145e19d5f4`.
Host fixture packet reads cannot call Kernel helpers/load or attach. Changed-file
Ruff/Format/Diff passed. No broad regression, GUI/model benchmark or model run.

The actual generated helper calls use R3=frame-pointer+constant, R4=fixed size;
R2 alone carries the packet offset. Disassembly remains private under
`.git/tcx-parser-fix-053/disassembly-ingress.txt`. This supports removal of the
observed source/bytecode access pattern, **not Kernel Verifier acceptance**.
Any other verifier objection may still appear during a separately approved run.

## Release identity and installation plan

- Version:0.5.3
- Manifest:`5b135c3da785ea250664387b8e6e128412a0e260b8cc416d89118a30d84b8d19`
- Source Bundle:`1b2537b1ab5b7346c665db75b4cf47a45298c24c055fbf71dd7e1cda159911a8`
- Unified install/handoff image:`bb735defd0e413e1dacc555b39a15250bfe843193bd5c169e27f5db4fd14cadb`

| Installed filename | SHA256 |
|---|---|
| bootstrap | `80b1e23e0213cfcdb0543be5094c118b91c4c343575d8956a855326d6359ea9a` |
| broker | `04c23fce1504e308f77e48ef9e86ddd7ed9c26646d50f1a7a4754a0ba2d706e0` |
| entry | `8e4ef82c3fe45ae5a414509316a2922898148ed860bb7ebdde9f743509ce4455` |
| libnative-tc.so | `e427384eb0b82fc7239d5367560c4863e2636700cfe4c077d06d1369714d7b07` |
| manifest.bin | `f3344070f6978afe7951d0f57e2852f346d011095d1103c597d1ec9ff16b9ab1` |
| pam-policy.conf | `93af76067bf513b4db8c5a9bd606e348ccde334b83e52f7dc71544c9c1f82696` |
| tc.bpf.o | `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06` |
| release.json | `5b135c3da785ea250664387b8e6e128412a0e260b8cc416d89118a30d84b8d19` |
| release.trust | `7abce70c2774f32e3e4649c0df3fee1110e4c745c28b4a1d546e7da8c71d6a79` |

Candidate files are in `.git/tcx-parser-fix-053/candidate/release/`.
The existing package verifier rechecked exact files, SHA, dependencies and manifest;
source Bundle and the fixed image were verified. Root-owned0.5.2 also passed its
existing installation verifier. Candidate generation did not change root files.

An ordinary-UID temporary-directory simulation installed/checked exact0.5.2,
refused publication of0.5.3 over the existing directory, retained exact old bytes
on rollback, then installed/checked0.5.3. This is not a real Root installation.

After approval, the existing unified installation would preserve0.5.2 at
`/usr/libexec/.soc-agent-ebpf.rollback-7471b886adda9dff073e2f601091a9dece5eedc9a46c4c7a3f2111d77c34fadf` and publish the nine reviewed files under
`/usr/libexec/soc-agent-ebpf`: root:root, executables0555, remaining files0444,
directory0755. The rollback archive currently has no collision. Individual
publication renames are no-replace; the two-directory swap is not a single atomic
exchange. Publication failure stops Native start and retains bounded evidence.
A restore requires exact identity, process quiescence and separate review;
unknown files and foreign hooks are never deleted to make installation succeed.

## Native approval and remaining work

Actual Root installation, BPF Load and TCX Attach are **not performed** by the
preparation above. The changed Release needs its own explicit approval. Proposed
single-run scope: lo/ifindex1, `net:[4026531833]`, Ingress only, max300s,
4096 metadata events, queue32,256MiB address space, CPU20s,
CAP_BPF+CAP_NET_ADMIN only. One fresh OS-terminal authentication per application
session; no automatic retry, packet drop/modification, payload retention or pinning.

For an approved run, preserve first API/errno and complete bounded verifier text
on failure; record Program ID/tag, Link ID and packet/Network14 results only when
actually observed. No new packet traffic is generated by this task. Absence of
ordinary loopback traffic may yield zero events without proving delivery success.
Never promote incomplete windows or execute Native AI.

Verifier, Attach, Ring Buffer, Data Plane and Network14 Native results are PENDING;
actual packet/Feature counts are NOT_OBSERVED for this new release, not zero.
Current preparation performs no privileged resource action and creates no Kernel
FDs to clean up. Existing cleanup reports are not upgraded: individual Map/Program/
Link close return values are not traced by the current release. Even if future
close logic reports success and independent inventory is empty, report those
facts separately and keep full Cleanup unverified without the required evidence.
After execution, verify Broker exit, authorization disposal, both audit chains,
read-only Kernel inventory and external-filter preservation. Any failure stops;
changes to another release require fresh review/approval before another run.

Native AI, DNS9 and operational promotion remain BLOCKED. All132 baseline user/ML
files and hashed historical Native evidence were checked unchanged. No model,
raw dataset or Native database is included in source control. File-level evidence
and simulation results are in [the evidence JSON](tcx-verifier-parser-remediation-evidence.json).

# Native E2E remediation campaign — Release 0.5.9 candidate

Status: ordinary-user remediation and pre-authentication qualification complete.
No Root installation, sudo/PAM authentication, capability transition, kernel
inventory, BPF load, TCX attach, capture or traffic generation in this campaign.
Native AI, DNS9 and operational promotion remain BLOCKED.

## First failure and correction

The previous 0.5.8 Native attempt passed installation, OS handoff and both
Inspector inventories. `supervisor_startup.execute()` then computed its
RunIdentity digest from the Legacy preparation Scope. `Preparation.os_auth_handoff()`
had correctly replaced the program identity with the TCX program SHA. Consequently
`Handoff.command()` raised `HANDOFF_RUN_SCOPE` before sending ATTACH. This was a
local ValueError, with no kernel errno. No TCX load or attach was attempted.

The corrected startup builds RunIdentity from the existing Handoff application
and its TCX Scope. Before displaying approval or requesting OS authentication,
`prepare_run()` rechecks the current package/controller/namespace/interface,
Release/version/Bundle, sealed approval bytes, Program SHA, TCX Scope, fixed
resource limits and the Zeek Plan's namespace/interface/source Bundle. It uses
the existing Release verifier and TCX Plan construction path.

`Handoff.validate_run_identity()` contains the unchanged Session/Scope comparison
and is called both before authentication and immediately before sending IPC.
The immutable validated RunIdentity is retained for ATTACH. A mismatching run is
rejected rather than rewritten. The command allowlist, privileged C binaries,
Inspector authority and TCX FD ownership contracts are unchanged.

## Qualification

- Startup regression: 8 passed. Actual candidate preparation and startup through
  the approval boundary; authentication is forbidden in the tests. Valid TCX
  RunIdentity succeeds; Legacy Plan, Legacy Run Scope, foreign Session, changed
  namespace, Manifest, image and Zeek namespace fail before authentication.
- Existing ordinary-UID C/Python IPC: 2 passed, covering same-session commands,
  Audit/recovery and outside-scope run rejection. These are transport fixtures,
  not Native authentication or kernel qualification.
- Changed-file Ruff and Format checks passed. No GUI/model changes or broad
  regression/performance repetitions.
- The exact candidate was separately copied and exercised through CLI-equivalent
  `execute()` to the approval boundary with authentication prohibited. Run and
  Handoff Scope digests matched; the Legacy digest differed. The runnable
  candidate itself has no prior Session or DNS capture directory.

Private evidence is under `.git/native-e2e-remediation-campaign-059/`:
`release-identity.json`, `preauth-validation.json`, `budget.json`,
`campaign-audit.jsonl` and the immutable candidate directory. Pre-authentication
Session IDs/digests are test-specific and are never reused as Native approval.

## Exact candidate and installation review

| Identity | SHA256 |
|---|---|
| Manifest | `d9a59174d3d94b1e0e166a60e3059e61833b6cc8e0c2a75082c02167727f9f19` |
| Source Bundle | `7ade6ae05aa21eddf6a26deee093b51f37d5b05221ec3c3553571de851599167` |
| Supervisor execution image | `6286818f3376a4fe0374b782653c8fdbf0ac6c7542b3b603805e73a05444fdfc` |
| Bootstrap | `80b1e23e0213cfcdb0543be5094c118b91c4c343575d8956a855326d6359ea9a` |
| Broker | `9919d3c5d9e02aa88be31360c9e29a2b4c0fd6953fae03e8835c033d71809b76` |
| Loader | `943f0b2e42350d661b5d20c6879ec8ce0119fbd070889e12c29ac55cd7213ae9` |
| TCX Object | `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06` |
| Binary Manifest | `f82ebcab40e37e31f53e321219cc1b0e74095f385d4c3f537a2604c62be1b251` |
| Execution trust Manifest | `cff4f141701f421f8eb5d617474877ebe686a0fe5d7008f377a7156e6326a0eb` |

The installed 0.5.8 was independently verified through held-FD Root ownership,
mode, file SHA, dependency and configuration checks. It remains installed. The
new package changes `manifest.bin`, `release.json`, `release.trust`; the other
six installation files, including all executable code, are byte-identical.

The existing reviewed image performs atomic UPDATE_RETAIN_PREVIOUS for the fixed
`/usr/libexec/soc-agent-ebpf` directory. All nine files remain root:root, with
Bootstrap/Broker/entry 0555 and other files 0444. The proposed retained 0.5.8 path
is `/usr/libexec/.soc-agent-ebpf.rollback-a87e355d82eea4b9c5fe319ce98f6ff2417f3c441900ef1615397dc62f6c660d`;
it was absent at preparation. Earlier backups are preserved. Verify the current
installation and destination again immediately before installation. Rollback
uses the retained exact release and its verified identities, with no active
Collector/Link; it requires explicit authorization, never deletion of unknown
files or automatic repair of a conflicting destination.

## Proposed campaign and approval boundary

The historical `.git/native-continuous-debug/budget.json` is preserved byte for
byte; its exhausted 3/3 counters are not reset. The new separate campaign starts
with Native 0/5 and installation 0/5, pending approval of this exact candidate.
Before every authorized attempt, reserve its Native/install slots durably in
the new ledger and append an Audit event with exact Manifest/Bundle/image,
scope, approval reference and sequence. Flush that event before launch. Failed
attempts consume the reserved slots. Completion appends results; do not erase
reservations or historical evidence. Five slots are ceilings, not permission
to retry unchanged failures. New Release SHAs require explicit approval.

Proposed execution scope:

- Namespace `net:[4026531833]`, `lo` ifindex 1, Ingress only, <=300 seconds,
  TCX metadata <=4096, queue 32, AS256MiB and CPU20s per privileged worker.
- One fresh terminal password per application session through the existing
  fixed sudo entry; no downstream sudo/cache dependency or secret persistence.
- Inspector keeps SYS_ADMIN only for fixed read-only queries; Broker keeps
  BPF+NET_ADMIN, without SYS_ADMIN. GUI, adapters and AI stay ordinary-user.
- Existing separate Zeek container profile is unchanged: same namespace/lo,
  RAM512MiB, CPU1, packet4096, event8192, bounded8MiB output. The TCX worker
  AS256MiB limit is not an aggregate RAM ceiling for that container. This
  distinction must be included in approval; do not silently widen the profile.
- No generated traffic, pinning, packet blocking, foreign Link removal or
  unapproved Interface/Hook/Capability changes. TCX_NEXT(-1) is unchanged.
- Successful BEFORE inspection and absence of Link/filter conflicts are
  mandatory. AFTER inspection is performed by the same Inspector boundary.
  Query failure is UNKNOWN, never an empty inventory.

## Remaining Native blockers and evidence requirements

No Native packets, features or DNS events have been collected in the new
campaign. TCX clock reordering, loss, Network14, GUI and drain remain pending.
The 0.5.8 passive Zeek run delivered 216 metadata/4 Network records but DNS0;
its stock pcap success/identity attestation remained unverified. Absence of DNS
in that short lo window does not prove absence of network DNS or validate the
DNS analyzer. No new traffic or Interface change is authorized by this document.

The previous AFTER inventory was clear, but its TCX Broker cleanup journal
remained UNVERIFIED. Do not retroactively promote that state. At the next
authorized attempt, preserve individual FD-release evidence, both inventories,
original errors and terminal Zeek exit receipt. The latter is needed because
the outer 0.5.8 Zeek snapshot remained stale ACTIVE/PENDING after process exit.

If a new failure occurs, preserve its first Stage/API/errno, separately record
cleanup failures, complete owned-resource teardown and analyze before any new
attempt. Missing ownership or uncertain residual state blocks Native execution.
No fixture or candidate Manifest opens the Native AI/DNS9/promotion gates.

# Continuous Runtime

Updated extension: [TCX producer, authentication and recovery](continuous-runtime-operations.md).
The original replay verification below is retained; the new Native backend is now implemented
but unactivated. Native capture attestation/model admission remain blocked.

The `continuous` CLI runs an ordinary-user service independently of the GUI. The
existing Phase D diagnostic CLI, admission receipts and limits remain unchanged;
`analyze-offline` remains the single-run offline entry point.

## Implemented and verified scope

`CONTINUOUS` currently supports **PCAP_REPLAY** and **JSONL_REPLAY**. A running
service is not proof of live collection: status always includes
`collection_live=false`, the actual source and `REPLAY_ONLY_NO_NATIVE_CAPTURE`.
PCAP EOF is reported as `EOF_NOT_LIVE`; the service stays available for status,
queued analysis and explicit Stop. It does not silently loop the file.

Collection and consumption are independent asyncio tasks. PCAP parsing and model
inference use separate ordinary-user processes. Existing FlowTable/StreamingFlows,
Network14 producer, pinned RF/LR adapters, OfflineWorkflow, incident classification,
read-only investigation tools and verified audit are reused. No new API call or
system remediation is enabled by this mode. Investigations use SCRIPTED planning
unless a separately governed API path is explicitly used outside this service.

Flow windows close by event time: idle 30s or active 120s. DNS metadata uses separate
60s tumbling windows by default. An actual later event must witness expiry; EOF,
Stop, source loss and clock regression never fabricate eligible closed flows.
Window eligibility is offline metadata eligibility, **not P02/P03 Native capture
attestation**. Unknown, incomplete and invalid windows never call a model. Full
packet parsing retains metadata/digests, not payload or DNS query names.

A private SQLite EventQueue bounds pending work, deduplicates claims, accounts
queue drops, and poisons interrupted/failed work instead of silently repeating it.
Worker faults open a circuit while collection continues. Explicit `reset-worker`
accepts future work; it never reruns poisoned jobs. Collector recovery is bounded
by config (default one replay retry), isolates a new clock epoch and closes prior
flows incomplete. A repeated failure opens the collector circuit.

Stored inputs, outcomes and append-oriented hash-linked audit remain available.
Heartbeats are mutable projections protected by integrity checks; they are not
substitutes for evidence. Old heartbeats become `UNKNOWN_STALE_HEARTBEAT`.

## Run / stop / recover

Use the project's existing Python environment, never a global package installation.
Create a private config with absolute paths, the SHA of the existing input and an
explicit existing ML checkout. No download, capture or network traffic is involved.

```json
{
  "source": "PCAP_REPLAY",
  "input_file": "/absolute/path/capture.pcap",
  "input_sha256": "<calculate from the actual file>",
  "ml_root": "/home/geonug/kdt-linux/ML",
  "queue_capacity": 8,
  "max_active_flows": 128,
  "max_windows": 512,
  "max_storage_bytes": 268435456,
  "heartbeat_seconds": 1,
  "shutdown_seconds": 10
}
```

```bash
python -m soc_agent.cli continuous init /absolute/private/runtime --config /absolute/config.json
python -m soc_agent.cli continuous start /absolute/private/runtime
python -m soc_agent.cli continuous status /absolute/private/runtime
python -m soc_agent.gui --continuous-runtime /absolute/private/runtime
python -m soc_agent.cli continuous reset-worker /absolute/private/runtime
python -m soc_agent.cli continuous stop /absolute/private/runtime
```

Start checks a pinned digest of installed SOC Python modules and a single-instance
lifetime lock. Changed code requires a fresh initialized replay directory, not an
implicit integrity refresh. Start acknowledges a fresh heartbeat from its own PID.
Stop is a request: poll for `STOPPED` and `cleanup=VERIFIED`. Shutdown drains the
current AI claim within the configured deadline, then reaps only owned children.
Pending queue work is retained. A cancelled claim is poisoned and audited unknown.
GUI close only detaches; it does not stop this service. The GUI's separate one-shot
Analysis page continues to close its own analysis process as before.

`service-unit` emits an **uninstalled user-service unit** with `NoNewPrivileges`,
512MiB cgroup memory, 50% CPU quota, TasksMax32 and explicit Stop timeout. This task
does not install or start systemd units. Direct CLI runs report resource use but
cannot claim that uninstalled cgroup limits were enforced. The isolated PCAP helper
has 3GiB virtual address-space and 60 CPU-second limits, matching the existing
research process dependency footprint; this is not the Phase D 256MiB policy.

Retention is bounded, not silently destructive: max windows, stored bytes, seen IDs
and existing queue tombstones stop ingestion when exhausted. Production archival,
rotation and sustained throughput tuning remain required for unattended deployment.
No claim of an indefinite lossless service is made.

## Authentication and DNS

`authentication_runtime` can attach an explicitly configured existing Linux runtime
for read-only health/status. Stored authentication jobs reuse existing model package
and feature contracts; this service does not invent thresholds or start an auth
collector behind the operator's back. Raw/stored DNS jobs reuse transaction parsing
and evidence handling. DNS9 remains INCOMPLETE until the training extraction contract
exists. Continuous live authentication ingestion into the common collector service
is not implemented by this attachment.

## Native service authority: not activated and not deployment-ready

`NATIVE_SERVICE` fails closed with
`CONTINUOUS_NATIVE_SERVICE_INSTALLATION_AND_POLICY_NOT_ACTIVATED`. The original replay release did not implement the privileged TCX backend. The later
autonomous integration adds the separately gated producer and transport described in
the extension guide. It does not grant Native model inference or production promotion.

A future installed minimal collector must own attachment and deliver bounded,
authenticated TCX/DNS records with sequence, loss counters, clock epoch, namespace,
interface, socket cookie and executable provenance. It must preserve all Native
eligibility checks. AI, LLM and GUI must remain ordinary users. A transient launcher
may require namespace-entry capabilities; the collector's actual BPF/network
capabilities must be narrowed for the target kernel after installation review.

The service installation/policy proposal must bind executable integrity, approved
namespace/interface, capabilities, local DNS scope, IPC peer identity, resource
limits, retention, recovery budget and cleanup. Existing diagnostic, development
metering and R1/R2 receipts confer **no** Continuous service authority. AGENTS §33
human policy review and an explicit installation grant are required. No receipt,
reservation, privileged service or policy activation was created in this task.

Until that backend and its acceptance tests exist, use the preserved Offline demo
or separately approved bounded Native diagnostic. Never label replay results Native.

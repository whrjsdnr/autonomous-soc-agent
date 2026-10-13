# Backend 경계와 보호 범위

## 발급과 실행

Trusted application composition binds a registry and store once. RuntimeBoundary
issues a process-local opaque B-3.5 ReadOnlyCapability backed by exact object identity,
incident/context/contract/session binding and a monotonic five-minute lease. JSON,
model output, a copied/frozen dataclass or a deserialized handle is not an issuer.
Restore rotates the durable session and invalidates old capabilities.

Task-local scope spans planner, assessor and tool work. An accepted external
incident has a durable read-only disposition even outside that scope. Failed or
pending required inference also blocks legacy start and state/action mutation.
An active external scope cannot borrow another incident's legacy authority.

Read-only tool names are frozen at attachment. Registry/tool identity, metadata,
input/output schemas and the bound handler are checked. A task-local dispatch
permit binds the exact action/tool and validated input. Tool.execute and the
wrapped original handler recheck immediately before calling the actual handler;
raw handler calls and unbound-registry reuse do not remove this leaf guard.
For protected work, a validated tool input incident_id must match the bound Action
incident before dispatching the handler; aliasing the payload cannot redirect a
source-report read to another incident.
Approval does not override read-only disposition. Policy itself remains a pure
rule evaluator, not an issuance/execution interface.

## Actual entry point inventory

| Existing entry point | Enforcement / applicability |
|---|---|
| Tool.execute / wrapped Tool.handler | Exact dispatch permit and tool/input validation at leaf |
| ToolRegistry.register / dispatcher | Bind new trusted tools; existing capability allowlist does not grow |
| GovernedExecutor.preflight / execute | Action/disposition check, existing policy/approval, dispatch then leaf |
| GovernedExecutor.request_approval | Read-only action cannot request approval |
| ApprovalManager.create / decide | Bound manager denies issuance and human decision for protected work |
| InvestigationOrchestrator / Planner | Existing executor plus read-only catalog; tool input validation retained |
| ResponseCoordinator.execute_step / execute_plan | Existing GovernedExecutor; blocked result does not invoke spy |
| PromotionService.record_review / promote / validate_promoted | Durable mutation guard before authority consumption/promotion |
| ExecutionBridge approval and execute | Existing promotion validation and guarded executors |
| DurableExecutor.execute / execute_claim | Durable disposition guard before claim/EXECUTING/handler |
| PersistentHumanReviewService.record_review / authorize_change / apply | Durable guard before granting or consuming authority |
| SQLiteGovernanceStore.compare_and_apply | Durable guard before governed state CAS |
| External RuntimeGovernanceStore.append_assessment | Non-no-op model fact promotion denied |
| ImprovementActivationService.promote / rollback | Global mutation guard: external runtime context/requirement blocks activation |
| ApplicationService / authenticated ASGI service | Existing authenticated API routes delegate to the same guarded services; reads validate receipts |
| Desktop / Linux Headless composition | Same store, runtime, policy and guards; profile grants no authority |
| SOCRuntime start / restore / advance | Integrity extension mandatory for runtime store; session checks and atomic publication |
| Private runtime stage calls | require_scope denies skipping the public guarded step |
| Worker / queue | No autonomous action queue exists; native worker has only fixed inference entry point |
| Internal Python API | The listed supported service/tool APIs are guarded; raw SQL and arbitrary trusted Python reflection are not a sandbox |

## Audit failure and integrity

Durable denial events contain only fixed reason codes and binding identifiers, not
raw context, feature arrays, credentials or tokens. The separate security chain
anchors existing audit hashes without rewriting them. Checkpoint publication
includes its security audit in the same transaction. Audit storage failure prevents
a guarded handler call; integrity failure cannot grant authority.

The existing POSIX 0700/0600/owner/inode/sidecar policy and Windows NTFS owner/DACL,
TrustedInstaller root, OWNER RIGHTS, reparse and sidecar checks are unchanged.
The original model loader size limits, artifact pins, selection digests and
provenance checks are unchanged. Reference inference never replaces native inference.

## Explicit threat-model limit

The Python interpreter, composition factories, registered original adapters, native
model loaders and database code are trusted code. A malicious plugin with arbitrary
Python execution could use reflection, retain an original unguarded handler or
access raw SQLite/OS APIs. Object freezing cannot prevent that. Untrusted executable
code requires separate OS credentials/permissions and a constrained process/IPC
boundary. The optional native interpreter here isolates dependencies and faults;
it is **not** an OS authorization sandbox.

Legacy actions remain governed by existing trusted policy/human contracts. The
external advisory path never creates WRITE authority. An independently authorized
legacy operation is not evidence that a model-generated operation is authorized.
Privileged complete DB/audit rewriting or truncation requires an external signed
checkpoint/attestation to detect; a local hash chain alone is not that attestation.

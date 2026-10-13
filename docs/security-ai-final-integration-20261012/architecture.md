# External Security AI의 실제 SOC Runtime 통합

## 실제 실행 경로

```text
Bounded UTF-8 local events / existing authenticated service
 → EventIngestor → retained source event and IncidentState
 → explicitly supplied Top40 / DNS 9-feature source records
 → official external predictors (optional explicit native Python worker)
 → official EvidenceEnvelope → existing B-3.1 adapter/validation
 → existing ExternalModelContext v2 assembly
 → RuntimeBoundary.attach: context/source/provenance and immutable disposition
 → shared compose_application → existing SOCRuntime
 → existing Planner / InvestigationOrchestrator / GovernedExecutor (READ only)
 → ContextLLMClient → existing ThreatAssessor → existing IncidentDecisionEngine
 → companion AssessmentRun / ProvenanceReceipt / DecisionReceipt
 → atomic core checkpoint / companion publication / security audit
 → existing Policy / Human Approval / Execution Guard: external WRITE denied
```

Fusion v1, its SelectionReport, and external context v2 remain separate. A configured
legacy `model_analysis` callback remains supported by `compose_application` and
`desktop.initialize(packages=..., external_artifacts=...)`. The default external CLI
uses no implicit legacy package discovery. Missing legacy packages retain their
existing truthful coverage semantics. Network 5 features are never transformed to
Top40; external 15-class labels are never transformed to the existing four classes.
Authentication remains on its existing ingestion/model path. DNS is an explicit
precomputed feature observation, not a new DNS collector or disguised authentication.

## Runtime storage version

Existing v15 is an exact, isolated-validation schema with purpose
`ISOLATED_VALIDATION_ONLY`. Runtime publication and session state cannot be silently
added under that contract. The explicit **v16** runtime extension preserves all v14
core tables and v15 context/receipt tables and adds four companion tables:

- `external_runtime_requirements`: accepted required inference, including failure.
- `external_runtime_incidents`: immutable incident disposition, context and session binding.
- `external_runtime_publications`: checkpoint/trace/assessment invocation lineage.
- `external_security_audit`: a separate hash chain anchored to existing audit events.

`RuntimeDatabase` validates exact v16 DDL, purpose and legacy schema fingerprint.
Its `core_schema_version` exposes the validated unchanged v14 layout to selected
existing core readers. Ordinary `GovernanceDatabase` remains fail-closed above v14;
ordinary `ExternalDatabase` remains exact-v15. This is not a broad version allowlist.
New storage is opt-in. No operational database is automatically migrated or adopted.

## Atomicity and interruption

Context attachment is one transaction. Accepting inference is a prior durable
PENDING requirement; required failure stays FAILED and cannot become a legacy run.
These operations precede the workflow; they are not claimed to be one transaction
with native inference.

A workflow claim is committed before external work. In an external step, actual
READ evidence is staged and read for publication in task-local state; evidence/CAS/core audit, assessment
and decision receipts, core checkpoint/trace, publication and security audit are
committed in **one SQLite transaction**. No SQLite lock is held across inference,
LLM or tool work. Failed publication rolls back all published artifacts, leaving the
already committed claim. No second-store double commit is called atomic.

Resume validates the exact checkpoint, context, source references, receipt graph,
state anchors and audit publication before issuing a fresh process-local capability.
The v2 AssessmentRun input anchor continues to describe the original context source
snapshot. Publication separately preserves the actual assessor input anchor and
actual augmented LLM request digest; these two anchors are not conflated.

`ApplicationService.reconcile_external_interruption` is an explicit trusted operator
call. It accepts only the exact interrupted read-only run/revision with unchanged
state and no execution intent. It closes progress as UNCERTAIN/COMPLETE, records
recovery and does not replay tools. It does not infer successful completion.

## Product entry point

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m soc_agent.external_runtime \
  --profile DESKTOP \
  --directory /absolute/private/application-data \
  --input /absolute/synthetic-events.jsonl \
  --external-features /absolute/synthetic-feature-records.jsonl \
  --artifacts /absolute/verified-external-artifacts \
  --native-python /absolute/native-environment/bin/python
```

Linux Headless uses the same entry point with `--profile SERVER`. Windows Server is
explicitly rejected by this launcher. DESKTOP uses the existing Desktop initializer;
SERVER uses the same composition and existing source-report tool. Collection and
inference need no HTTP listener or browser. Existing authenticated ASGI interfaces
use the same service and receipt validation. No GUI, real-time collector, queue or
installer is introduced.

Each feature JSONL row has `event_id`, explicit unique `profiles`
(`detection_quality`, `edge`, `litert`), and a `SourceFeatureObservation` with no
caller-supplied incident association. `source_event_id` must equal `event_id`.
Feature schema, order, payload, event times, synthetic origin and derivation identity
must follow the existing typed contract. Quality and Edge share one source evidence
when their observation key is equal; DNS retains another observation. Cross-domain
correlation remains UNVERIFIED. File input is bounded, regular, UTF-8 and rejects
links/reparse paths; feature replay limits are 4 MiB, 1000 rows, 256 KiB per row.

Only explicitly supplied synthetic/prevalidated features are supported here.
Operational feature extraction and its assurance remain unverified. Predictions
are advisory, not attack facts, calibrated attack probability or authorization.

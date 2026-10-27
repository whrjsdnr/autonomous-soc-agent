"""Nonprivileged analysis -> existing policy/read tools -> investigation -> audited result.

One new output directory is one attempt. A crash preserves intent; it never retries
inference or restarts collectors. No OS/network response capability is registered.
"""

import asyncio
import json
import os
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel

from soc_agent.approval import ApprovalManager
from soc_agent.assessment import ThreatAssessor
from soc_agent.assessment.errors import AssessmentError
from soc_agent.desktop import OfflineDesktopClient, ReadReportInput
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.errors import ExecutionError
from soc_agent.investigation import InvestigationOrchestrator
from soc_agent.llm import LLMClient, LLMError, LLMRequest, LLMResponseValidationError
from soc_agent.llm.openai_compatible import OpenAICompatibleSettings
from soc_agent.planning import InvestigationPlanner
from soc_agent.planning.errors import PlanningError
from soc_agent.policy import PolicyEngine
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.security_ai.api_investigation import (
    APIInvestigationClient,
    APIInvestigationDraft,
    APIRunAuthorization,
)
from soc_agent.security_ai.ebpf.input_eligibility import input_receipts
from soc_agent.security_ai.errors import SecurityAIError
from soc_agent.security_ai.external.runtime_store import (
    RuntimeGovernanceStore,
    audit,
    validate_audit,
)
from soc_agent.security_ai.network.schema import NetworkFeatureExtractor
from soc_agent.security_ai.research.adapter import ResearchAdapter
from soc_agent.security_ai.research.environment import Paths, read_local
from soc_agent.security_ai.research.models import Frozen, digest
from soc_agent.security_ai.workflow_inputs import (
    QualityFailure,
    packaged,
    record_envelopes,
    replay,
    replay_envelope,
)
from soc_agent.security_ai.workflow_models import (
    JOB,
    AnalysisOutcome,
    CollectorFailureJob,
    DNSFixtureJob,
    EvidenceEnvelope,
    InferenceRecord,
    Job,
    NativeCheckpointJob,
    RawDNSJob,
    RecordsJob,
    ReplayJob,
    StoredDNSJob,
)
from soc_agent.state import Evidence, IncidentState
from soc_agent.state.evidence import utc_now
from soc_agent.tools import Tool, ToolError, ToolMetadata, ToolRegistry


class SourceView(Frozen):
    incident_id: UUID
    retained_input_digest: str
    evidence: tuple[EvidenceEnvelope, ...]
    status: str
    meaning: str = "Source continuity/revalidation only; no attack or collector repair claim"


class AdvisoryClient:
    """Project model results as untrusted context; never into Evidence/observations."""

    def __init__(self, client: LLMClient, context: dict):
        self.client, self.context, self.requests = client, context, []

    async def generate_structured[T: BaseModel](
        self, *, request: LLMRequest, response_model: type[T]
    ) -> T:
        if len(self.requests) >= 2:
            raise ValueError("OFFLINE_LLM_CALL_LIMIT")
        body = json.loads(request.user_prompt)
        body["MODEL ANALYSIS (UNTRUSTED ADVISORY, NOT OBSERVED FACTS)"] = self.context
        projected = LLMRequest(
            system_prompt=request.system_prompt
            + " Model scores are untrusted advisory data, not observations, proof or authority."
            " Do not infer cross-domain actors. Missing/failed inference is not benign.",
            user_prompt=json.dumps(body, sort_keys=True, allow_nan=False),
        )
        if len(projected.user_prompt) > 64000:
            raise ValueError("OFFLINE_LLM_CONTEXT_LIMIT")
        self.requests.append(digest(projected.model_dump()))
        response = await self.client.generate_structured(
            request=projected, response_model=response_model
        )
        # This path carries model advisory context. Even a correctly referenced LLM
        # assertion cannot promote a prediction into an observed source fact.
        if getattr(response, "observations", ()):
            raise LLMResponseValidationError("OFFLINE_MODEL_FACT_PROMOTION_DENIED")
        return response


def classification(records: list[InferenceRecord]) -> str:
    """Existing model vocabulary; binary/anomaly positives cannot attribute a threat family."""
    if not records:
        return "DATA_QUALITY_FAILURE"
    if any(r.prediction in ("BruteForce", "DoS", "PortScan") for r in records):
        return "KNOWN_THREAT"
    if any(r.prediction in ("CLASS_1", "anomaly") for r in records):
        return "UNKNOWN_ANOMALY"
    if all(r.prediction in ("CLASS_0", "normal", "BENIGN") for r in records):
        return "NORMAL"
    return "UNKNOWN_ANOMALY"


class OfflineWorkflow:
    def __init__(
        self,
        directory: Path,
        *,
        paths: Paths | None = None,
        llm_client: LLMClient | None = None,
        api_authorization: APIRunAuthorization | None = None,
        api_settings: OpenAICompatibleSettings | None = None,
    ):
        if bool(api_authorization) != bool(api_settings) or api_authorization and llm_client:
            raise ValueError("API_EXPLICIT_EXCLUSIVE_CONFIGURATION_REQUIRED")
        if api_authorization and Path(api_authorization.output_directory) != directory.absolute():
            raise ValueError("API_ATTEMPT_DIRECTORY_MISMATCH")
        if os.geteuid() == 0:
            raise ValueError("OFFLINE_ORDINARY_UID_REQUIRED")
        # Never adopt/reset an existing attempt, including one interrupted before output.
        self.directory = directory.absolute()
        create_private_directory(self.directory, exist_ok=False)
        self.store = RuntimeGovernanceStore.create_isolated(self.directory / "soc")
        self.paths, self.llm_client, self.claimed = paths, llm_client, False
        self.api_authorization, self.api_settings = api_authorization, api_settings

    def event(self, code: str, payload: object):
        with self.store.database.transaction() as c:
            validate_audit(c)
            audit(c, code, binding_digest=digest(payload))

    def write(self, name: str, payload: object):
        body = json.dumps(payload, sort_keys=True, allow_nan=False).encode()
        fd = os.open(
            self.directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "wb") as f:
            f.write(body)
            f.flush()
            os.fsync(f.fileno())

    async def run(self, job: Job) -> AnalysisOutcome:
        job = JOB.validate_python(job.model_dump(mode="json"))
        if self.claimed:
            raise ValueError("OFFLINE_ATTEMPT_ALREADY_CLAIMED_NO_RETRY")
        if len(job.model_dump_json().encode()) > 1024 * 1024:
            raise ValueError("OFFLINE_INPUT_LIMIT")
        self.claimed = True
        raw = job.model_dump(mode="json")
        self.write("input.json", raw)
        self.event("OFFLINE_ANALYSIS_STARTED", raw)
        api = None
        if self.api_authorization:
            import hashlib

            submitted = json.loads(
                read_local(self.directory / "submitted-input.json", 2 * 1024 * 1024)
            )
            if (
                hashlib.sha256(submitted["utf8"].encode()).hexdigest()
                != self.api_authorization.input_sha256
                or JOB.validate_json(submitted["utf8"]).model_dump(mode="json") != raw
            ):
                raise ValueError("API_INPUT_AUTHORIZATION_MISMATCH")
            api = APIInvestigationClient(
                self.api_authorization, self.api_settings, self.write, self.event
            )
        incident_ids = (
            {r.incident_id for r in job.records if r.incident_id is not None}
            if isinstance(job, RecordsJob)
            else set()
        )
        if isinstance(job, StoredDNSJob):
            incident_ids = {s.header.incident_id for s in job.sources}
        if len(incident_ids) > 1:
            raise QualityFailure("CROSS_INCIDENT_SOURCE_REJECTED")
        incident_id = next(iter(incident_ids), uuid4())
        state = IncidentState(incident_id=incident_id)
        records = []
        envelopes = ()
        reasons = []
        fusion = None
        eligible = "UNKNOWN"
        kind = "MODEL_ERROR"

        def record(r: InferenceRecord):
            # Immutable original receipt is committed before the next model/await.
            self.write(f"inference-{len(records)}.json", r.model_dump(mode="json"))
            self.event("OFFLINE_INFERENCE_COMPLETED", r.model_dump(mode="json"))
            records.append(r)

        try:
            if isinstance(job, RecordsJob):
                envelopes = record_envelopes(job)
                fusion = await packaged(job, state, record)
                eligible = "ELIGIBLE"
            elif isinstance(job, (ReplayJob, DNSFixtureJob)):
                envelopes = (replay_envelope(job),)
                adapter = ResearchAdapter(self.directory / "workers", paths=self.paths)
                await replay(job, adapter, record)
                if isinstance(job, ReplayJob):
                    envelopes = (
                        EvidenceEnvelope.model_validate(
                            envelopes[0].model_dump() | dict(integrity="REPLAY_VERIFIED")
                        ),
                    )
                eligible = "ELIGIBLE"
            elif isinstance(job, StoredDNSJob):
                envelopes = tuple(
                    EvidenceEnvelope(
                        event_identity=s.header.event_id,
                        domain="DNS",
                        origin="DECLARED_STORED_RECORDS",
                        source_digest=s.content_digest,
                        collector_identity=s.header.collector_id,
                        observed_at=s.header.observed_at,
                        source_incident=s.header.incident_id,
                        schema_version=s.contract_version,
                        integrity="DECLARED_UNATTESTED",
                        provenance=(s.header.source.model_dump_json(),),
                    )
                    for s in job.sources
                )
                eligible = "INCOMPLETE"
                reasons = ["DNS9_PRODUCER_PARITY_UNVERIFIED", "NO_GUESSED_DNS_FEATURES"]
            elif isinstance(job, RawDNSJob):
                from soc_agent.security_ai.dns_transactions import transactions

                try:
                    receipt = transactions(job)
                except ValueError as exc:
                    raise QualityFailure("RAW_DNS_TRANSACTION_OR_CLOCK_INVALID") from exc
                self.write("dns-transactions.json", receipt)
                self.event("OFFLINE_DNS_TRANSACTIONS_COMPLETED", receipt)
                eligible, reasons = receipt["eligibility"], receipt["reasons"]
                envelopes = (
                    EvidenceEnvelope(
                        event_identity=digest(raw),
                        domain="DNS",
                        origin=job.origin,
                        source_digest=job.source_sha256,
                        collector_identity="stored_dns_wire_transcript",
                        observed_at=None,
                        schema_version=receipt["contract"],
                        integrity="DECLARED_UNATTESTED",
                        provenance=(
                            "Pinned transcript; PCAP linkage declared, not Native attestation",
                        ),
                    ),
                )
            elif isinstance(job, NativeCheckpointJob):
                try:
                    receipts = input_receipts(job.summary, job.transport)
                except (ValueError, TypeError, AttributeError, KeyError) as exc:
                    raise QualityFailure("NATIVE_CHECKPOINT_SCHEMA_INVALID") from exc
                reasons = ["NATIVE_AI_POLICY_BLOCKED"] + [x for r in receipts for x in r["reasons"]]
                eligible = (
                    "INVALID"
                    if any(r["input_state"] == "INVALID" for r in receipts)
                    else "INCOMPLETE"
                )
                self.write("native-input-receipts.json", receipts)
            else:
                kind = "COLLECTOR_ERROR"
                reasons = [job.code, "CALLER_REPORTED_ERROR_NOT_NATIVE_ATTESTATION"]
            if not isinstance(job, CollectorFailureJob):
                kind = classification(records)
        except QualityFailure as exc:
            kind = "DATA_QUALITY_FAILURE"
            eligible = "INVALID"
            reasons = [str(exc)]
        except (ValueError, OSError, ImportError, SecurityAIError) as exc:
            kind = "MODEL_ERROR"
            reasons = ["MODEL_OR_ARTIFACT_VALIDATION_FAILED", type(exc).__name__]
        if not envelopes:
            envelopes = (
                EvidenceEnvelope(
                    event_identity=digest(raw),
                    domain="COLLECTOR",
                    origin=job.kind,
                    source_digest=digest(raw),
                    collector_identity="retained_offline_input",
                    observed_at=None,
                    schema_version="soc-offline-job:v1",
                    integrity="UNVERIFIED",
                    provenance=("Caller-retained bytes, no Native source authenticity assertion",),
                ),
            )
        evidence = Evidence(
            incident_id=incident_id,
            source="retained_offline_input",
            summary="Retained source metadata; model outputs are separate untrusted advisory data",
            raw_data=json.dumps([e.model_dump(mode="json") for e in envelopes], sort_keys=True),
            observed_at=utc_now(),
        )
        state = IncidentState(incident_id=incident_id, evidence=(evidence,))
        self.store.register(state)
        registry = ToolRegistry()
        input_pin = digest(raw)

        def retained():
            if (
                digest(json.loads(read_local(self.directory / "input.json", 1024 * 1024)))
                != input_pin
            ):
                raise ValueError("OFFLINE_RETAINED_SOURCE_CHANGED")

        async def read(query: ReadReportInput) -> SourceView:
            if query.incident_id != incident_id:
                raise ValueError("OFFLINE_TOOL_INCIDENT_MISMATCH")
            retained()
            return SourceView(
                incident_id=incident_id,
                retained_input_digest=input_pin,
                evidence=envelopes,
                status="SOURCE_CONTINUITY_VERIFIED",
            )

        registry.register(
            Tool(
                ToolMetadata(
                    name="read_local_source_report",
                    description="Read retained source continuity, no model facts or host actions",
                    permission="file_read",
                    risk_level="read_only",
                ),
                ReadReportInput,
                SourceView,
                read,
            )
        )
        # Existing PolicyEngine grants read-only in-memory revalidation, not worker restart.
        known = (
            isinstance(job, CollectorFailureJob)
            and job.code == "FEATURE_EXTRACTION_INTERRUPTED"
            and job.record is not None
        )
        if known:

            async def revalidate(query: ReadReportInput) -> SourceView:
                result = await read(query)
                NetworkFeatureExtractor().extract(job.record)
                return SourceView.model_validate(
                    result.model_dump() | dict(status="INPUT_REVALIDATED_NO_COLLECTOR_REPAIR")
                )

            registry.register(
                Tool(
                    ToolMetadata(
                        name="revalidate_stored_input",
                        description="Revalidate one network source in memory; no collector restart",
                        permission="file_read",
                        risk_level="read_only",
                    ),
                    ReadReportInput,
                    SourceView,
                    revalidate,
                )
            )
        executor = GovernedExecutor(
            registry=registry, policy=PolicyEngine(), approvals=ApprovalManager()
        )
        response = None
        investigation = None
        context = dict(
            classification=kind,
            reasons=reasons,
            # Keep full source/feature provenance in immutable local receipts. Prompts
            # reference it by digest, rather than duplicating thousands of source rows.
            model_results=[
                dict(
                    model_id=r.model_id,
                    model_version=r.model_version,
                    prediction=r.prediction,
                    score=r.score,
                    score_semantics=r.score_semantics,
                    feature_fingerprint=r.feature_fingerprint,
                    artifact_digest=r.artifact_digest,
                    model_manifest_digest=r.model_manifest_digest,
                    source_reference_count=len(r.evidence_references),
                    source_references_digest=digest(r.evidence_references),
                    source_reference_sample=list(r.evidence_references[:8]),
                    source_reference_sample_truncated=len(r.evidence_references) > 8,
                    original_receipt_digest=digest(r.model_dump(mode="json")),
                )
                for r in records
            ],
            fusion={
                k: fusion[k]
                for k in (
                    "fusion_id",
                    "agreement_state",
                    "confidence_state",
                    "coverage_state",
                    "missing_models",
                    "summary",
                    "limitations",
                )
            }
            if fusion
            else None,
        )
        # Known labels trigger only the same existing read policy; never model -> host action.
        action = ActionProposal(
            incident_id=incident_id,
            tool_name="revalidate_stored_input" if known else "read_local_source_report",
            tool_input={"incident_id": str(incident_id)},
        )
        self.event("OFFLINE_RESPONSE_REQUESTED", action.model_dump(mode="json"))
        try:
            result = await executor.execute(action, require_read_only=True)
            retained()
            response = dict(
                action=action.model_dump(mode="json"),
                result=result.model_dump(mode="json"),
                policy="EXISTING_READ_ONLY_ALLOW",
                postcondition="SOURCE_CONTINUITY_VERIFIED",
                automatic_attempts=1,
                host_remediation=False,
            )
            self.event("OFFLINE_RESPONSE_VERIFIED", response)
        except (ValueError, RuntimeError, ExecutionError, ToolError) as exc:
            response = dict(
                action=action.model_dump(mode="json"),
                status="FAILED_STOP_NO_RETRY",
                error_type=type(exc).__name__,
            )
            self.event("OFFLINE_RESPONSE_FAILED", response)
        if (
            kind in ("UNKNOWN_ANOMALY", "MODEL_ERROR")
            or isinstance(job, CollectorFailureJob)
            and not known
        ):
            client = AdvisoryClient(api or self.llm_client or OfflineDesktopClient(), context)
            try:
                planner_options = {"draft_model": APIInvestigationDraft} if api else {}
                planner = InvestigationPlanner(
                    llm_client=client, registry=registry, max_steps=2, **planner_options
                )
                deadline = self.api_authorization.timeout_seconds + 1 if api else 30
                plan = await asyncio.wait_for(planner.create_plan(state), deadline)
                result = await InvestigationOrchestrator(executor=executor).execute_plan(
                    incident_state=state, plan=plan, require_read_only=True
                )
                assessment = await asyncio.wait_for(
                    ThreatAssessor(llm_client=client).assess(result.incident_state), deadline
                )
                investigation = dict(
                    plan=plan.model_dump(mode="json"),
                    result=result.model_dump(mode="json"),
                    assessment=assessment.model_dump(mode="json"),
                    prompt_digests=client.requests,
                    status="COMPLETED_READ_ONLY"
                    if all(s.status.value == "completed" for s in result.plan.steps)
                    else "BLOCKED",
                    unresolved=[
                        "Independent source/capture validation",
                        "Model anomaly is not proof of compromise",
                    ],
                    recommended_response="Review evidence; host changes require human approval",
                    human_approval_for_host_response=True,
                    hypothesis_verification=[
                        dict(
                            hypothesis_id=str(h.hypothesis_id),
                            statement=h.statement,
                            supporting_evidence_ids=[str(e) for e in h.supporting_evidence_ids],
                            verification_methods=[s.purpose for s in plan.steps],
                            read_only_tools=[s.tool_name for s in plan.steps],
                            additional_evidence="Independent source/capture context",
                        )
                        for h in assessment.incident_state.hypotheses
                    ],
                )
                if api:
                    investigation["generated_draft"] = planner.last_draft.model_dump(mode="json")
                    investigation["api_receipt_digests"] = [digest(r) for r in api.receipts]
                    investigation["evaluation_kind"] = "API_ADVISORY_NOT_INDEPENDENT_GROUND_TRUTH"
                self.event("OFFLINE_INVESTIGATION_COMPLETED", investigation)
            except (
                ValueError,
                RuntimeError,
                TimeoutError,
                PlanningError,
                LLMError,
                AssessmentError,
            ) as exc:
                investigation = dict(
                    status="FAILED_STOP_NO_RETRY",
                    error_type=type(exc).__name__,
                    prompt_digests=client.requests,
                )
                self.event("OFFLINE_INVESTIGATION_FAILED", investigation)
        retained()
        outcome = AnalysisOutcome(
            incident_id=incident_id,
            classification=kind,
            eligibility=eligible,
            evidence=envelopes,
            inference=tuple(records),
            reasons=tuple(reasons),
            fusion=fusion,
            response=response,
            investigation=investigation,
            llm_mode="REAL_API" if api else "INJECTED_CLIENT" if self.llm_client else "SCRIPTED",
            external_provider_calls=api.calls if api else None if self.llm_client else 0,
        )
        self.write("result.json", outcome.model_dump(mode="json"))
        self.event("OFFLINE_ANALYSIS_COMPLETED", outcome.model_dump(mode="json"))
        return verify_result(self.directory)


def verify_result(directory: Path) -> AnalysisOutcome:
    """Reopen persisted result and every original inference receipt against existing audit."""
    result = AnalysisOutcome.model_validate_json(
        read_local(directory / "result.json", 4 * 1024 * 1024)
    )
    store = RuntimeGovernanceStore(directory / "soc/external-validation.sqlite")
    with store.database.transaction(write=False) as c:
        validate_audit(c)
        events = [
            json.loads(r[0])
            for r in c.execute("SELECT payload FROM external_security_audit ORDER BY sequence")
        ]
    if [e["binding_digest"] for e in events if e["code"] == "OFFLINE_ANALYSIS_COMPLETED"] != [
        digest(result.model_dump(mode="json"))
    ]:
        raise ValueError("OFFLINE_RESULT_AUDIT_MISMATCH")
    source = json.loads(read_local(directory / "input.json", 1024 * 1024))
    if [e["binding_digest"] for e in events if e["code"] == "OFFLINE_ANALYSIS_STARTED"] != [
        digest(source)
    ]:
        raise ValueError("OFFLINE_INPUT_AUDIT_MISMATCH")
    submitted_pins = [
        e["binding_digest"] for e in events if e["code"] == "OFFLINE_SUBMITTED_INPUT_RETAINED"
    ]
    if submitted_pins:
        import hashlib

        submitted = json.loads(read_local(directory / "submitted-input.json", 2 * 1024 * 1024))
        if (
            submitted_pins != [digest(submitted)]
            or hashlib.sha256(submitted["utf8"].encode()).hexdigest() != submitted["sha256"]
        ):
            raise ValueError("OFFLINE_SUBMITTED_INPUT_CHANGED")
        if JOB.validate_json(submitted["utf8"]).model_dump(mode="json") != source:
            raise ValueError("OFFLINE_NORMALIZED_INPUT_MISMATCH")
    pins = [e["binding_digest"] for e in events if e["code"] == "OFFLINE_INFERENCE_COMPLETED"]
    if pins != [digest(r.model_dump(mode="json")) for r in result.inference]:
        raise ValueError("OFFLINE_INFERENCE_AUDIT_MISMATCH")
    if {p.name for p in directory.glob("inference-*.json")} != {
        f"inference-{i}.json" for i in range(len(result.inference))
    }:
        raise ValueError("OFFLINE_UNSETTLED_INFERENCE_RECEIPT")
    for i, r in enumerate(result.inference):
        if json.loads(read_local(directory / f"inference-{i}.json", 1024 * 1024)) != r.model_dump(
            mode="json"
        ):
            raise ValueError("OFFLINE_ORIGINAL_RECEIPT_CHANGED")
    if result.llm_mode == "REAL_API":
        from soc_agent.security_ai.api_investigation import verify_api_receipts

        verify_api_receipts(directory, events, result.external_provider_calls)
    dns_pins = [
        e["binding_digest"] for e in events if e["code"] == "OFFLINE_DNS_TRANSACTIONS_COMPLETED"
    ]
    if dns_pins or source.get("kind") == "raw_dns" and result.eligibility != "INVALID":
        receipt = json.loads(read_local(directory / "dns-transactions.json", 4 * 1024 * 1024))
        if dns_pins != [digest(receipt)]:
            raise ValueError("OFFLINE_DNS_RECEIPT_AUDIT_MISMATCH")
    return result

"""Offline, non-executing core analysis trial. Production SOCRuntime activation is disabled."""

import asyncio
from datetime import UTC, datetime
from typing import NoReturn
from uuid import UUID, uuid4

from pydantic import BaseModel

from soc_agent.assessment import AssessmentResult, SecurityAnalysisDraft, ThreatAssessor
from soc_agent.decision import IncidentDecision, IncidentDecisionEngine
from soc_agent.investigation import InvestigationPlan
from soc_agent.llm import LLMRequest, MockLLMClient
from soc_agent.planning import InvestigationPlanner
from soc_agent.planning.models import LLMInvestigationPlanDraft
from soc_agent.review.identity import content_digest
from soc_agent.review.models import StoredIncident
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.review.persistence.session import GovernanceSession
from soc_agent.security_ai.external.assembly import ExternalModelContext
from soc_agent.security_ai.external.models import Hash, Snapshot
from soc_agent.security_ai.external.projection import add_context, project, projection_digest
from soc_agent.security_ai.external.records import (
    AssessmentRun,
    DecisionReceipt,
    ProvenanceReceipt,
    ResumeRequirement,
)
from soc_agent.security_ai.external.storage import ExternalContextStore
from soc_agent.tools import ToolRegistry


class ExternalRuntimeDisabled(ValueError):
    """B-3.5 immutable backend capability/checkpoint publication is not implemented."""


class DiagnosticResult(Snapshot):
    plan: InvestigationPlan
    assessment: AssessmentResult
    decision: IncidentDecision
    resume_requirement: ResumeRequirement
    planner_request_digest: Hash
    assessment_request_digest: Hash


class _ContextClient:
    def __init__(self, store: ExternalContextStore, digest: str, client: MockLLMClient) -> None:
        self.store, self.digest, self.client = store, digest, client
        self.requests: list[LLMRequest] = []
        self.projections: list[str] = []

    async def generate_structured[T: BaseModel](
        self, *, request: LLMRequest, response_model: type[T]
    ) -> T:
        if (
            response_model not in (LLMInvestigationPlanDraft, SecurityAnalysisDraft)
            or len(self.requests) >= 2
        ):
            raise ValueError("Only one plan and one advisory analysis request are permitted")
        context = self.store.load_context(self.digest)
        with self.store.database.transaction(write=False) as connection:
            current = GovernanceSession(connection, self.store.database.store_id).load(
                context.input_snapshot.incident_id
            )
            if current.anchor != context.input_snapshot:
                raise StoredDataError("External diagnostic snapshot changed")
        value = project(context)
        modified = add_context(request, value)
        self.requests.append(modified)
        self.projections.append(value)
        response = await self.client.generate_structured(
            request=modified, response_model=response_model
        )
        if type(response) is SecurityAnalysisDraft and (
            response.observations or response.hypotheses
        ):
            raise ValueError("External model context cannot publish observations or hypotheses")
        return response


class ExternalAdvisoryDiagnostic:
    """Explicitly isolated scripted trial, not an alternate SOC orchestrator.

    It invokes existing planning/assessment/decision logic and persists receipts only.
    No investigator/executor/approval/response service is created or called. The plan
    is advisory and is never dispatched. Loop/checkpoint processing stays with SOCRuntime.
    """

    def __init__(
        self,
        *,
        store: ExternalContextStore,
        context_digest: str,
        required_models: tuple[str, ...],
        llm_client: MockLLMClient,
        registry: ToolRegistry,
    ) -> None:
        if type(llm_client) is not MockLLMClient:
            raise ExternalRuntimeDisabled(
                "Offline scripted client required; provider activation disabled"
            )
        if not required_models or len(set(required_models)) != len(required_models):
            raise ValueError("Explicit unique required models are required")
        self._store, self._digest, self._required = store, context_digest, required_models
        copied = ToolRegistry()
        for metadata in registry.list():
            if not metadata.is_read_only_capability:
                raise ExternalRuntimeDisabled("External trial accepts only read-only tool metadata")
            copied.register(registry.get(metadata.name))
        if not copied.list():
            raise ValueError("A read-only planning catalog is required")
        self._registry, self._client = copied, llm_client
        self._lock = asyncio.Lock()
        self._attempted = False

    def _load(self) -> tuple[ExternalModelContext, StoredIncident]:
        context = self._store.load_context(self._digest)
        available = {r.binding.binding_id for r in context.results}
        if not set(self._required) <= available:
            raise StoredDataError("Required external model result unavailable or unlinked")
        with self._store.database.transaction(write=False) as connection:
            stored = GovernanceSession(connection, self._store.database.store_id).load(
                context.input_snapshot.incident_id
            )
        if stored.anchor != context.input_snapshot:
            raise StoredDataError("External context source snapshot is stale")
        return context, stored

    async def evaluate(self, *, run_id: UUID) -> DiagnosticResult:
        async with self._lock:
            if self._attempted:
                raise ValueError(
                    "Single trial already attempted; reconcile stored receipts before any retry"
                )
            self._attempted = True
            context, stored = self._load()
            client = _ContextClient(self._store, self._digest, self._client)
            plan = await InvestigationPlanner(
                llm_client=client, registry=self._registry
            ).create_plan(stored.state)
            # Real core assessor and validator; projection is a separate request section.
            result = await ThreatAssessor(llm_client=client).assess(stored.state)
            if type(result) is not AssessmentResult or result.incident_state != stored.state:
                raise ValueError("External assessment must preserve the exact authoritative state")
            decision = IncidentDecisionEngine().decide(stored.state, result.threat_assessment)
            current_context, current = self._load()
            if current_context != context or current != stored:
                raise StoredDataError("Context changed during external diagnostic requests")
            run = AssessmentRun(
                run_id=run_id,
                incident_id=stored.state.incident_id,
                input_anchor=stored.anchor,
                output_anchor=stored.anchor,
                context_digest=context.context_digest,
                core_result=result,
                assessment_reference=result.threat_assessment.assessment_id,
                created_at=datetime.now(UTC),
            )
            refs = {
                content_digest(ref): ref
                for item in context.results
                for ref in item.observation.association.source_evidence_references
            }
            receipt = ProvenanceReceipt(
                receipt_id=uuid4(),
                context_digest=context.context_digest,
                assessment_run_id=run_id,
                input_anchor=stored.anchor,
                output_anchor=stored.anchor,
                assessment_digest=content_digest(result.threat_assessment),
                request_projection_digest=projection_digest(client.projections[1]),
                source_evidence_references=tuple(refs[key] for key in sorted(refs)),
            )
            dr = DecisionReceipt(
                receipt_id=uuid4(),
                assessment_receipt_id=receipt.receipt_id,
                assessment_run_id=run_id,
                context_digest=context.context_digest,
                core_decision=decision,
                decision_digest=content_digest(decision),
                input_anchor=stored.anchor,
                output_anchor=stored.anchor,
            )
            self._store.save_bundle(context, run, receipt, dr)
            requirement = ResumeRequirement(
                run_id=run_id,
                incident_id=stored.state.incident_id,
                context_digest=context.context_digest,
                receipt_id=receipt.receipt_id,
                receipt_digest=content_digest(receipt),
                input_anchor=stored.anchor,
                output_anchor=stored.anchor,
                decision_receipt_id=dr.receipt_id,
                decision_receipt_digest=content_digest(dr),
            )
            self._store.resume(requirement)
            return DiagnosticResult(
                plan=plan,
                assessment=result,
                decision=decision,
                resume_requirement=requirement,
                planner_request_digest=content_digest(client.requests[0]),
                assessment_request_digest=content_digest(client.requests[1]),
            )

    def restore_receipts(
        self, expected: ResumeRequirement
    ) -> tuple[ExternalModelContext, AssessmentRun, ProvenanceReceipt, DecisionReceipt | None]:
        """Guarded read of diagnostic outputs, not workflow continuation."""
        self._load()
        if expected.context_digest != self._digest:
            raise StoredDataError("Diagnostic context differs from required lineage")
        return self._store.resume(expected)

    def start(self, incident_id: UUID, **kwargs: object) -> NoReturn:
        raise ExternalRuntimeDisabled(
            "SOCRuntime activation disabled until guarded checkpoint/backend integration"
        )

    advance = start
    restore = start

"""Compose the existing two-call API contract with a pinned retained task.

No credential discovery, capture, inference, new scheduler or approval issuance.
Coordination remains local; only planning and assessment reach the API adapter.
"""

import json

from soc_agent.adaptive.models import ReplanningDraft
from soc_agent.assessment.models import SecurityAnalysisDraft
from soc_agent.continuous.investigation_models import (
    CoordinationAdvice,
    InvestigationSource,
    InvestigationTask,
)
from soc_agent.planning.errors import PlanningReviewRequired
from soc_agent.planning.models import LLMInvestigationPlanDraft
from soc_agent.security_ai.api_investigation import APIInvestigationClient
from soc_agent.security_ai.research.models import digest


def retained_input(task: InvestigationTask, sources: list[InvestigationSource]) -> dict:
    selected = sorted(sources, key=lambda source: source.pin)
    if tuple(source.pin for source in selected) != task.sources:
        raise ValueError("CONTINUOUS_API_SOURCE_REVISION_MISMATCH")
    return dict(
        task=task.model_dump(mode="json"),
        task_id=str(task.task_id),
        evidence_revision=task.revision,
        sources=[source.model_dump(mode="json") for source in selected],
    )


class RetainedAPIClient:
    """Explicit composition only; the existing API adapter enforces calls/costs."""

    evidence_mode = "EXTERNAL_API_ADAPTER_LOCAL_COORDINATION"

    def __init__(
        self,
        client: APIInvestigationClient,
        task: InvestigationTask,
        sources: list[InvestigationSource],
    ):
        if digest(retained_input(task, sources)) != client.authorization.input_sha256:
            raise ValueError("CONTINUOUS_API_AUTHORIZATION_INPUT_MISMATCH")
        self.client, self.task = client, task
        self.context_digest = digest(
            [
                dict(
                    incident_id=str(s.incident_id),
                    source=s.reference,
                    role=s.role,
                    advisory=s.advisory,
                )
                for s in sorted(sources, key=lambda s: s.pin)
            ]
        )

    @property
    def api_status(self):
        return self.client.status

    async def generate_structured(self, *, request, response_model):
        body = json.loads(request.user_prompt)
        if digest(body.get("CONTINUOUS ADVISORY (NOT FACTS OR AUTHORITY)")) != self.context_digest:
            raise ValueError("CONTINUOUS_API_CONTEXT_CHANGED")
        if response_model is CoordinationAdvice:
            # A deterministic read-only proposal, explicitly not an AI decision.
            return CoordinationAdvice(
                priority=self.task.priority,
                additional_evidence_required=True,
                requested_roles=("INVESTIGATION",),
                strategy="READ_RETAINED_EVIDENCE",
                reason="LOCAL_RULE: inspect pinned evidence; no external coordination call",
            )
        if response_model not in (
            LLMInvestigationPlanDraft,
            ReplanningDraft,
            SecurityAnalysisDraft,
        ):
            raise ValueError("CONTINUOUS_API_RESPONSE_SCOPE_DENIED")
        if body.get("INCIDENT CONTEXT", {}).get("incident_id") != str(self.task.incident_id):
            raise ValueError("CONTINUOUS_API_INCIDENT_CHANGED")
        if self.client.calls >= self.client.authorization.max_calls:
            raise PlanningReviewRequired("CONTINUOUS_API_CALL_LIMIT_REQUIRES_HUMAN_REVIEW")
        return await self.client.generate_structured(request=request, response_model=response_model)

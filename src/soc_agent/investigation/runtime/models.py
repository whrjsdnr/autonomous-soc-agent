"""Workflow state is distinct from governed IncidentState status."""

from enum import StrEnum
from uuid import UUID

from soc_agent.assessment import AssessmentResult, FusionAssessmentResult
from soc_agent.decision import IncidentDecision
from soc_agent.investigation.models import InvestigationPlan
from soc_agent.response.advisory import ResponsePlan
from soc_agent.review.models import Frozen, StateAnchor


class WorkflowStep(StrEnum):
    OBSERVE = "observe"
    PLAN = "plan"
    ROUTE = "route"
    ANALYZE = "analyze"
    DECIDE = "decide"
    GOVERN = "govern"
    ACT = "act"
    EVALUATE = "evaluate"
    RECOVER = "recover"
    COMPLETE = "complete"


class WorkflowFailure(StrEnum):
    VALIDATION = "validation_failure"
    ANALYSIS = "analysis_failure"
    GOVERNANCE = "governance_blocked"
    INVESTIGATION = "investigation_failed"
    EXECUTION = "execution_failed"
    UNCERTAIN = "execution_uncertain"
    LOOP_GUARD = "investigation_loop_guard"


class ArtifactReference(Frozen):
    kind: str
    identity: str


class WorkflowResult(Frozen):
    incident_id: UUID
    current_step: WorkflowStep
    next_step: WorkflowStep
    reason: str
    references: tuple[ArtifactReference, ...] = ()
    waiting_for_human: bool = False
    terminal: bool = False
    failure: WorkflowFailure | None = None


class WorkflowArtifacts(Frozen):
    snapshot: StateAnchor
    investigation: InvestigationPlan | None = None
    assessment: FusionAssessmentResult | AssessmentResult | None = None
    decision: IncidentDecision | None = None
    response_plan: ResponsePlan | None = None
    execution_intent_id: str | None = None

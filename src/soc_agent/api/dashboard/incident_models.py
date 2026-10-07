"""Presentation snapshots contain selected metadata, never raw action input or credentials."""

from typing import Literal
from uuid import UUID

from soc_agent.api.dashboard.models import HumanActionView, SignalView
from soc_agent.investigation.runtime.models import WorkflowStep
from soc_agent.review.models import Frozen
from soc_agent.state.evidence import UTCTimestamp


class ReferenceView(Frozen):
    identity: str
    label: str
    anchor: str | None = None


class EvidenceView(Frozen):
    evidence_id: UUID
    source: str
    summary: str
    tool: str | None
    observed_at: UTCTimestamp
    collected_at: UTCTimestamp
    reliability: float | None


class ObservationView(Frozen):
    observation_id: UUID
    statement: str
    supporting: tuple[ReferenceView, ...]
    created_at: UTCTimestamp


class HypothesisView(Frozen):
    hypothesis_id: UUID
    statement: str
    supporting: tuple[ReferenceView, ...]
    confidence: float
    created_at: UTCTimestamp


class StageView(Frozen):
    step: WorkflowStep
    status: Literal[
        "UNKNOWN", "NOT OBSERVED", "ADVANCED", "CURRENT", "WAITING", "FAILED", "TERMINAL"
    ]


class TraceView(Frozen):
    sequence: int
    reference: str
    current: WorkflowStep
    next_step: WorkflowStep
    waiting: bool
    failure: str | None
    reason: str


class WorkflowDetail(Frozen):
    run_id: UUID
    revision: int
    snapshot_revision: int
    matches_current_state: bool
    current: WorkflowStep
    next_step: WorkflowStep
    failure: str | None
    claimed: bool
    terminal: bool
    stages: tuple[StageView, ...]
    trace: tuple[TraceView, ...]


class InvestigationStepView(Frozen):
    step_id: UUID
    action_id: UUID
    tool: str
    permission: Literal["NOT AVAILABLE"] = "NOT AVAILABLE"
    status: str
    purpose: str
    evidence: ReferenceView | None
    error_type: str | None


class InvestigationView(Frozen):
    plan_id: UUID
    goal: str | None
    created_at: UTCTimestamp
    steps: tuple[InvestigationStepView, ...]
    strategy_provenance: Literal["NOT AVAILABLE"] = "NOT AVAILABLE"


class AssessmentView(Frozen):
    assessment_id: UUID
    severity: str
    summary: str
    created_at: UTCTimestamp
    supporting: tuple[ReferenceView, ...]
    fusion_reference: str | None


class DecisionView(Frozen):
    decision_id: str
    outcome: str
    rationale: tuple[str, ...]
    review_reasons: tuple[str, ...]
    investigation_reasons: tuple[str, ...]
    uncertainties: tuple[str, ...]
    supporting: tuple[ReferenceView, ...]


class GovernanceView(Frozen):
    domain: str
    reference: str
    status: str
    actor: str | None = None
    timestamp: UTCTimestamp | None = None
    related: tuple[str, ...] = ()


class ResponseView(Frozen):
    proposal_id: str
    plan_id: str
    tool: str
    permission: str
    category: str
    status: Literal["PROPOSED", "PROMOTED"]
    purpose: str
    promoted_reference: str | None = None
    created_at: UTCTimestamp


class ExecutionView(Frozen):
    execution_id: str
    action_id: UUID
    proposal_id: str
    promoted_id: str
    tool: str
    status: str
    created_at: UTCTimestamp
    started_at: UTCTimestamp | None
    finished_at: UTCTimestamp | None
    reconciliation: str | None


class OutcomeView(Frozen):
    evaluation_id: str
    experience_id: str
    run_id: UUID
    execution_outcome: str
    governance_outcome: str
    terminal: bool
    recovery_observed: bool
    created_at: UTCTimestamp
    feedback_count: int | None


class TimelineView(Frozen):
    timestamp: UTCTimestamp
    description: str
    reference: str


class ProvenanceView(Frozen):
    source: ReferenceView
    target: ReferenceView
    relation: str


class IncidentDetailView(Frozen):
    incident_id: UUID
    status: str
    severity: str
    revision: int
    created_at: UTCTimestamp
    updated_at: UTCTimestamp
    sources: tuple[str, ...]
    workflow: WorkflowDetail | None
    human_actions: tuple[HumanActionView, ...]
    signals: tuple[SignalView, ...]
    evidence: tuple[EvidenceView, ...]
    observations: tuple[ObservationView, ...]
    hypotheses: tuple[HypothesisView, ...]
    investigation: InvestigationView | None
    assessment: AssessmentView | None
    decision: DecisionView | None
    governance: tuple[GovernanceView, ...]
    responses: tuple[ResponseView, ...]
    executions: tuple[ExecutionView, ...]
    outcomes: tuple[OutcomeView, ...]
    provenance: tuple[ProvenanceView, ...]
    timeline: tuple[TimelineView, ...]

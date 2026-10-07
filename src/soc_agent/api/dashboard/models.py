"""Immutable, deliberately small observation DTOs; no execution authority."""

from typing import Literal
from uuid import UUID

from soc_agent.investigation.runtime.models import WorkflowStep
from soc_agent.review.models import Frozen
from soc_agent.state.evidence import UTCTimestamp


class WorkflowView(Frozen):
    run_id: UUID
    current: WorkflowStep
    next_step: WorkflowStep
    terminal: bool
    claimed: bool
    reason: str
    updated_at: UTCTimestamp


class IncidentView(Frozen):
    incident_id: UUID
    status: str
    severity: str
    updated_at: UTCTimestamp
    evidence_count: int
    observation_count: int
    hypothesis_count: int
    sources: tuple[str, ...]
    workflow: WorkflowView | None


class HumanActionView(Frozen):
    incident_id: UUID
    run_id: UUID
    category: str
    reason: str


class SignalView(Frozen):
    domain: Literal["Network AI", "Authentication AI", "Fusion"]
    state: str = "UNKNOWN"
    incident_id: UUID | None = None
    run_id: UUID | None = None
    reference: str | None = None
    timestamp: UTCTimestamp | None = None
    provenance: tuple[str, ...] = ()
    confidence: Literal["UNKNOWN"] = "UNKNOWN"


class ActivityView(Frozen):
    incident_id: UUID
    timestamp: UTCTimestamp
    description: str
    reference: str


class DashboardOverview(Frozen):
    system_status: Literal["UNKNOWN"] = "UNKNOWN"
    posture: Literal["UNKNOWN", "INVESTIGATING", "ACTION REQUIRED", "RECOVERY REQUIRED"]
    active_incident_count: int
    active_workflow_count: int
    human_action_count: int
    security_signal_count: int
    incidents: tuple[IncidentView, ...]
    human_actions: tuple[HumanActionView, ...]
    signals: tuple[SignalView, ...]
    recent_activity: tuple[ActivityView, ...]
    scope: str = "Authorized incidents; latest retained workflow checkpoints only"

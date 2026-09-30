"""Checkpointed progress is not an issuance ledger or an approval."""

from typing import Self
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.assessment import FusionAssessmentResult
from soc_agent.investigation.runtime.models import WorkflowArtifacts, WorkflowResult, WorkflowStep
from soc_agent.review.models import Frozen, Hash
from soc_agent.review.persistence.models import StorageError
from soc_agent.state.evidence import UTCTimestamp


class StaleCheckpoint(StorageError):
    """Revision/run CAS mismatch; no step was allowed to start."""


class WorkflowInFlight(StorageError):
    """A claimed step may have begun. Operator recovery required; never steal/retry."""


class WorkflowAuthorityUnavailable(ValueError):
    """Required promotion/approval must be revalidated by the existing live bridge."""


class WorkflowCheckpoint(Frozen):
    run_id: UUID
    incident_id: UUID
    revision: int = Field(strict=True, ge=0)
    artifacts: WorkflowArtifacts
    result: WorkflowResult
    review_id: UUID | None = None
    promoted_id: Hash | None = None
    approval_id: UUID | None = None
    rounds: int = Field(strict=True, ge=0)
    round_limit: int = Field(strict=True, ge=1)
    attempted: tuple[tuple[str, str], ...] = ()
    created_at: UTCTimestamp
    updated_at: UTCTimestamp

    @model_validator(mode="after")
    def references(self) -> Self:
        a = self.artifacts
        if (
            self.incident_id != a.snapshot.incident_id
            or self.result.incident_id != self.incident_id
        ):
            raise ValueError("Checkpoint incident mismatch")
        if self.updated_at < self.created_at or self.rounds > self.round_limit:
            raise ValueError("Invalid checkpoint progress metadata")
        if tuple(sorted(set(self.attempted))) != self.attempted:
            raise ValueError("Attempted actions must be unique and canonical")
        step = self.result.next_step
        if self.result.terminal != (step == WorkflowStep.COMPLETE):
            raise ValueError("Checkpoint terminal/cursor mismatch")
        if step == WorkflowStep.DECIDE and a.assessment is None:
            raise ValueError("DECIDE requires cached assessment")
        if step in (WorkflowStep.GOVERN, WorkflowStep.ACT) and a.decision is None:
            raise ValueError("Governance requires cached decision")
        if step == WorkflowStep.ACT and (a.response_plan is None or self.promoted_id is None):
            raise ValueError("ACT requires exact promoted candidate references")
        if step in (WorkflowStep.RECOVER, WorkflowStep.EVALUATE) and a.execution_intent_id is None:
            raise ValueError("Recovery/evaluation requires durable execution identity")
        expected = {}
        for kind, identity in (
            ("investigation", a.investigation.plan_id if a.investigation else None),
            ("assessment", a.assessment.threat_assessment.assessment_id if a.assessment else None),
            ("decision", a.decision.decision_id if a.decision else None),
            ("incident_review", self.review_id),
            ("response_plan", a.response_plan.plan_id if a.response_plan else None),
            ("promoted_action", self.promoted_id),
            ("tool_approval", self.approval_id),
            ("execution_intent", a.execution_intent_id),
            (
                "fusion",
                a.assessment.model_derived_context.fusion_id
                if isinstance(a.assessment, FusionAssessmentResult)
                else None,
            ),
        ):
            if identity is not None:
                expected[kind] = str(identity)
        if {r.kind: r.identity for r in self.result.references} != expected:
            raise ValueError("Checkpoint artifact references differ from stored progress")
        if len(self.result.references) != len(expected):
            raise ValueError("Duplicate checkpoint reference")
        if a.investigation and a.investigation.incident_id != self.incident_id:
            raise ValueError("Foreign investigation")
        if a.decision and (
            not a.assessment or a.decision.assessment != a.assessment.threat_assessment
        ):
            raise ValueError("Decision and assessment binding mismatch")
        if a.response_plan and (
            a.response_plan.content.basis.decision != a.decision
            or a.response_plan.content.basis.review.review_id != self.review_id
            or a.response_plan.content.basis.snapshot != a.snapshot
        ):
            raise ValueError("Response plan source mismatch")
        return self

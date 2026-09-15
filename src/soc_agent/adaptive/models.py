"""Caller-owned context/budget and semantic one-decision replanning contracts."""

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from soc_agent.investigation import InvestigationPlan, InvestigationStepStatus
from soc_agent.planning.models import LLMInvestigationStepDraft
from soc_agent.security_ai import AISignal, SecurityAIInvestigationResult, SecurityAISelectionPlan
from soc_agent.security_ai.selection_models import SecurityAISelectionStepDraft
from soc_agent.state import IncidentState
from soc_agent.state.evidence import UTCTimestamp, utc_now

Reason = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]


class InvestigationBudget(BaseModel):
    """Completed replanning rounds; caller increments before its next call."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    max_rounds: int = Field(default=5, ge=1)
    current_round: int = Field(default=0, ge=0)


class InvestigationContext(BaseModel):
    """Trusted application snapshots, revalidated at the planner boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    incident: IncidentState
    signals: tuple[AISignal, ...] = ()
    tool_history: tuple[InvestigationPlan, ...] = ()
    ai_history: tuple[SecurityAIInvestigationResult, ...] = ()
    budget: InvestigationBudget = Field(default_factory=InvestigationBudget)


class AdaptiveDecisionType(StrEnum):
    CONTINUE_WITH_TOOL = "continue_with_tool"
    CONTINUE_WITH_AI = "continue_with_ai"
    READY_FOR_ASSESSMENT = "ready_for_assessment"
    STOP_INSUFFICIENT = "stop_insufficient"
    ESCALATE_TO_HUMAN = "escalate_to_human"


def _check_payload(decision: AdaptiveDecisionType, has_tool: bool, has_ai: bool) -> None:
    if has_tool != (decision == AdaptiveDecisionType.CONTINUE_WITH_TOOL):
        raise ValueError("Tool payload must occur only with CONTINUE_WITH_TOOL")
    if has_ai != (decision == AdaptiveDecisionType.CONTINUE_WITH_AI):
        raise ValueError("AI payload must occur only with CONTINUE_WITH_AI")


class ReplanningDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    decision: AdaptiveDecisionType
    reason: Reason
    tool: LLMInvestigationStepDraft | None = None
    ai: SecurityAISelectionStepDraft | None = None

    @model_validator(mode="after")
    def validate_choice(self) -> Self:
        _check_payload(self.decision, self.tool is not None, self.ai is not None)
        return self


class AdaptiveInvestigationDecision(BaseModel):
    """Advisory next step, never execution, response approval, or incident closure."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    decision_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    decision: AdaptiveDecisionType
    reason: Reason
    budget: InvestigationBudget
    next_tool_plan: InvestigationPlan | None = None
    next_ai_plan: SecurityAISelectionPlan | None = None
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_plans(self) -> Self:
        _check_payload(
            self.decision, self.next_tool_plan is not None, self.next_ai_plan is not None
        )
        for plan in (self.next_tool_plan, self.next_ai_plan):
            if plan is not None and (plan.incident_id != self.incident_id or len(plan.steps) != 1):
                raise ValueError("Continuation must be a single-step plan for this incident")
        if self.next_tool_plan is not None:
            if self.next_tool_plan.steps[0].status != InvestigationStepStatus.PENDING:
                raise ValueError("Next tool step must be pending")
        if self.budget.current_round >= self.budget.max_rounds:
            if self.decision != AdaptiveDecisionType.ESCALATE_TO_HUMAN:
                raise ValueError("Exhausted budget requires escalation")
        return self

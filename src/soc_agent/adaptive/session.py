"""Immutable session provenance and validated accumulation of existing outcomes."""

from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from soc_agent.adaptive.context import validate_context
from soc_agent.adaptive.models import (
    AdaptiveDecisionType,
    AdaptiveInvestigationDecision,
    InvestigationBudget,
    InvestigationContext,
)
from soc_agent.investigation import InvestigationPlan, InvestigationResult
from soc_agent.security_ai import SecurityAIInvestigationResult, build_ai_signal_context
from soc_agent.state.evidence import NonEmptyText, UTCTimestamp, utc_now

TERMINAL_DECISIONS = frozenset(
    {
        AdaptiveDecisionType.READY_FOR_ASSESSMENT,
        AdaptiveDecisionType.STOP_INSUFFICIENT,
        AdaptiveDecisionType.ESCALATE_TO_HUMAN,
    }
)


class AutonomousInvestigationRound(BaseModel):
    """One planner attempt, including terminal decisions or fatal attempt errors."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    round_number: int = Field(ge=1, strict=True)
    decision: AdaptiveInvestigationDecision | None = None
    tool_execution: InvestigationResult | None = None
    ai_execution: SecurityAIInvestigationResult | None = None
    new_evidence_ids: tuple[UUID, ...] = ()
    new_signal_ids: tuple[UUID, ...] = ()
    error_type: NonEmptyText | None = None
    failure_stage: Literal["planning", "execution", "validation"] | None = None
    started_at: UTCTimestamp
    completed_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_execution(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("Round completion precedes start")
        if (self.error_type is None) != (self.failure_stage is None):
            raise ValueError("Fatal errors require a failure stage")
        if self.error_type is not None:
            if (
                self.tool_execution
                or self.ai_execution
                or self.new_evidence_ids
                or self.new_signal_ids
            ):
                raise ValueError("Fatal round cannot contain an accepted execution")
            return self
        if self.decision is None:
            raise ValueError("Successful round requires a decision")
        choice = self.decision.decision
        if (self.tool_execution is not None) != (choice == AdaptiveDecisionType.CONTINUE_WITH_TOOL):
            raise ValueError("Tool execution differs from decision")
        if (self.ai_execution is not None) != (choice == AdaptiveDecisionType.CONTINUE_WITH_AI):
            raise ValueError("AI execution differs from decision")
        if self.tool_execution is not None:
            selected = self.decision.next_tool_plan
            executed = self.tool_execution.plan
            if selected is None or (executed.plan_id, executed.incident_id) != (
                selected.plan_id,
                selected.incident_id,
            ):
                raise ValueError("Tool execution plan binding differs")

            def inputs(plan: InvestigationPlan) -> dict[str, object]:
                return plan.model_dump(
                    exclude={"steps": {"__all__": {"status", "evidence_id", "failure"}}}
                )

            if inputs(selected) != inputs(executed):
                raise ValueError("Executed tool plan differs from selected plan")
            if any(
                step.status.value not in {"completed", "failed", "blocked"}
                for step in executed.steps
            ):
                raise ValueError("Tool continuation did not finish")
            ids = tuple(step.evidence_id for step in executed.steps if step.evidence_id is not None)
            if self.new_evidence_ids != ids or self.new_signal_ids:
                raise ValueError("Tool outcome identities differ")
        elif self.new_evidence_ids:
            raise ValueError("Only tool execution adds evidence")
        if self.ai_execution is not None:
            selected_ai = self.decision.next_ai_plan
            executed_ai = self.ai_execution
            if selected_ai is None or (executed_ai.selection_plan_id, executed_ai.incident_id) != (
                selected_ai.plan_id,
                selected_ai.incident_id,
            ):
                raise ValueError("AI execution plan binding differs")
            if tuple(step.selection for step in executed_ai.steps) != selected_ai.steps:
                raise ValueError("Executed AI selections differ")
            if self.new_signal_ids != tuple(signal.signal_id for signal in executed_ai.signals):
                raise ValueError("AI outcome identities differ")
        elif self.new_signal_ids:
            raise ValueError("Only AI execution adds signals")
        return self


def advance_context(
    context: InvestigationContext, record: AutonomousInvestigationRound
) -> InvestigationContext:
    """Use returned incident snapshots; never add Evidence directly in the coordinator."""
    if record.round_number != context.budget.current_round + 1:
        raise ValueError("Round progression differs from budget")
    if context.budget.current_round >= context.budget.max_rounds:
        raise ValueError("Round exceeds hard budget")
    if record.decision is not None:
        if (
            record.decision.incident_id != context.incident.incident_id
            or record.decision.budget != context.budget
        ):
            raise ValueError("Adaptive decision changed incident or budget")
    state = context.incident
    tool_history, ai_history, signals = context.tool_history, context.ai_history, context.signals
    if record.tool_execution is not None:
        updated = record.tool_execution.incident_state
        unchanged = set(type(state).model_fields) - {"evidence", "updated_at"}
        if state.model_dump(include=unchanged) != updated.model_dump(include=unchanged):
            raise ValueError("Tool execution changed non-evidence incident fields")
        if updated.evidence[: len(state.evidence)] != state.evidence:
            raise ValueError("Tool execution changed existing evidence")
        added = updated.evidence[len(state.evidence) :]
        if tuple(item.evidence_id for item in added) != record.new_evidence_ids:
            raise ValueError("Evidence delta differs from execution")
        if updated.updated_at < state.updated_at:
            raise ValueError("Incident timestamp moved backwards")
        state = updated
        tool_history = (*tool_history, record.tool_execution.plan)
    if record.ai_execution is not None:
        signals = (*signals, *record.ai_execution.signals)
        # Unlike history projection merging, appending duplicate outputs is an error.
        build_ai_signal_context(signals, state=state)
        ai_history = (*ai_history, record.ai_execution)
    updated_context = InvestigationContext(
        incident=state,
        signals=signals,
        tool_history=tool_history,
        ai_history=ai_history,
        budget=InvestigationBudget(
            max_rounds=context.budget.max_rounds, current_round=record.round_number
        ),
    )
    validated, combined = validate_context(updated_context)
    return InvestigationContext.model_validate(validated.model_dump() | {"signals": combined})


class AutonomousInvestigationSession(BaseModel):
    """In-memory provenance; the initial and current contexts bound every round."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    session_id: UUID = Field(default_factory=uuid4)
    initial_context: InvestigationContext
    context: InvestigationContext
    rounds: tuple[AutonomousInvestigationRound, ...] = ()
    terminal_decision: AdaptiveInvestigationDecision | None = None
    created_at: UTCTimestamp = Field(default_factory=utc_now)
    updated_at: UTCTimestamp = Field(default_factory=utc_now)

    @property
    def incident_id(self) -> UUID:
        return self.context.incident.incident_id

    @property
    def budget(self) -> InvestigationBudget:
        return self.context.budget

    @model_validator(mode="after")
    def validate_progress(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("Session update precedes creation")
        context, signals = validate_context(self.initial_context)
        context = InvestigationContext.model_validate(context.model_dump() | {"signals": signals})
        stopped = False
        decision_ids = set()
        for record in self.rounds:
            if stopped:
                raise ValueError("Round follows a terminal or fatal round")
            if not self.created_at <= record.started_at <= record.completed_at <= self.updated_at:
                raise ValueError("Round outside session interval")
            if record.decision is not None:
                if record.decision.decision_id in decision_ids:
                    raise ValueError("Duplicate adaptive decision")
                decision_ids.add(record.decision.decision_id)
            context = advance_context(context, record)
            stopped = record.error_type is not None or (
                record.decision is not None and record.decision.decision in TERMINAL_DECISIONS
            )
        if context != self.context:
            raise ValueError("Session context differs from accumulated progress")
        terminal = self.terminal_decision
        if terminal is not None:
            if (
                terminal.incident_id != self.incident_id
                or terminal.decision not in TERMINAL_DECISIONS
            ):
                raise ValueError("Invalid terminal decision")
            if self.rounds and terminal == self.rounds[-1].decision:
                if self.rounds[-1].error_type is not None:
                    raise ValueError("Fatal round cannot be a terminal decision")
            elif (
                self.budget.current_round < self.budget.max_rounds
                or terminal.budget != self.budget
                or terminal.decision != AdaptiveDecisionType.ESCALATE_TO_HUMAN
                or terminal.reason != "Investigation budget exhausted"
                or stopped
            ):
                raise ValueError("Synthetic terminal must represent budget exhaustion")
        elif (
            self.rounds
            and self.rounds[-1].decision is not None
            and self.rounds[-1].decision.decision in TERMINAL_DECISIONS
            and self.rounds[-1].error_type is None
        ):
            raise ValueError("Terminal round requires session terminal decision")
        return self

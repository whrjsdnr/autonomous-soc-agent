"""A finite composition of planning and existing execution/provenance boundaries."""

from collections.abc import Callable, Mapping
from typing import Literal
from uuid import UUID

from soc_agent.adaptive.context import validate_context
from soc_agent.adaptive.errors import InvalidInvestigationContextError
from soc_agent.adaptive.models import (
    AdaptiveDecisionType,
    AdaptiveInvestigationDecision,
    InvestigationContext,
)
from soc_agent.adaptive.planner import AdaptiveInvestigationPlanner
from soc_agent.adaptive.session import (
    TERMINAL_DECISIONS,
    AutonomousInvestigationRound,
    AutonomousInvestigationSession,
    advance_context,
)
from soc_agent.investigation import InvestigationOrchestrator, InvestigationResult
from soc_agent.security_ai import (
    SecurityAIInvestigationResult,
    SecurityAIInvestigator,
    SecurityAISelectionPlan,
)
from soc_agent.state import IncidentState
from soc_agent.state.evidence import utc_now

AISourceResolver = Callable[
    [IncidentState, SecurityAISelectionPlan], Mapping[UUID, tuple[UUID, ...]]
]


class BoundedInvestigationError(Exception):
    """Fatal coordination failure; accepted progress remains inspectable in session.

    The cause preserves the original failure. No retries are implied.
    """

    def __init__(self, session: AutonomousInvestigationSession | None) -> None:
        super().__init__("Bounded investigation stopped due to a planning or invariant failure")
        self.session = session


class BoundedInvestigationCoordinator:
    def __init__(
        self,
        *,
        planner: AdaptiveInvestigationPlanner,
        tool_orchestrator: InvestigationOrchestrator,
        ai_investigator: SecurityAIInvestigator,
        ai_source_resolver: AISourceResolver | None = None,
    ) -> None:
        self._planner = planner
        self._tools = tool_orchestrator
        self._ai = ai_investigator
        self._sources = ai_source_resolver

    async def run(self, context: InvestigationContext) -> AutonomousInvestigationSession:
        try:
            context, signals = validate_context(context)
            context = InvestigationContext.model_validate(
                context.model_dump() | {"signals": signals}
            )
            session = AutonomousInvestigationSession(initial_context=context, context=context)
        except (ValueError, TypeError, InvalidInvestigationContextError) as error:
            raise BoundedInvestigationError(None) from error
        # Range is fixed at entry. Neither planner nor results can extend it.
        for index in range(context.budget.current_round, context.budget.max_rounds):
            started_at = utc_now()
            decision = None
            stage: Literal["planning", "execution", "validation"] = "planning"
            try:
                proposed = await self._planner.replan(session.context)
                candidate = AdaptiveInvestigationDecision.model_validate(
                    proposed.model_dump(warnings=False)
                )
                if (
                    candidate.incident_id != session.incident_id
                    or candidate.budget != session.budget
                ):
                    raise ValueError("Planner changed incident or budget")
                decision = candidate
                stage = "execution"
                tool_result: InvestigationResult | None = None
                ai_result: SecurityAIInvestigationResult | None = None
                if decision.next_tool_plan is not None:
                    tool_result = await self._tools.execute_plan(
                        incident_state=session.context.incident,
                        plan=decision.next_tool_plan,
                        require_read_only=True,
                    )
                    tool_result = InvestigationResult.model_validate(
                        tool_result.model_dump(warnings=False)
                    )
                elif decision.next_ai_plan is not None:
                    sources = (
                        self._sources(session.context.incident, decision.next_ai_plan)
                        if self._sources
                        else None
                    )
                    ai_result = await self._ai.execute(
                        incident=session.context.incident,
                        selection_plan=decision.next_ai_plan,
                        source_evidence=sources,
                    )
                    ai_result = SecurityAIInvestigationResult.model_validate(
                        ai_result.model_dump(warnings=False)
                    )
                stage = "validation"
                record = AutonomousInvestigationRound(
                    round_number=index + 1,
                    decision=decision,
                    tool_execution=tool_result,
                    ai_execution=ai_result,
                    new_evidence_ids=tuple(
                        step.evidence_id
                        for step in tool_result.plan.steps
                        if step.evidence_id is not None
                    )
                    if tool_result
                    else (),
                    new_signal_ids=tuple(signal.signal_id for signal in ai_result.signals)
                    if ai_result
                    else (),
                    started_at=started_at,
                    completed_at=max(utc_now(), started_at),
                )
                updated = advance_context(session.context, record)
                terminal = decision if decision.decision in TERMINAL_DECISIONS else None
                session = AutonomousInvestigationSession.model_validate(
                    session.model_dump()
                    | {
                        "context": updated,
                        "rounds": (*session.rounds, record),
                        "terminal_decision": terminal,
                        "updated_at": max(utc_now(), record.completed_at),
                    }
                )
            except Exception as error:
                # Convert, never swallow: preserve accepted progress and chain the fatal cause.
                # CancelledError/BaseException deliberately bypass this path.
                failed = AutonomousInvestigationRound(
                    round_number=index + 1,
                    decision=decision,
                    error_type=type(error).__name__,
                    failure_stage=stage,
                    started_at=started_at,
                    completed_at=max(utc_now(), started_at),
                )
                partial = AutonomousInvestigationSession.model_validate(
                    session.model_dump()
                    | {
                        "context": advance_context(session.context, failed),
                        "rounds": (*session.rounds, failed),
                        "updated_at": max(utc_now(), failed.completed_at),
                    }
                )
                raise BoundedInvestigationError(partial) from error
            if session.terminal_decision is not None:
                return session
        terminal = AdaptiveInvestigationDecision(
            incident_id=session.incident_id,
            budget=session.budget,
            decision=AdaptiveDecisionType.ESCALATE_TO_HUMAN,
            reason="Investigation budget exhausted",
        )
        return AutonomousInvestigationSession.model_validate(
            session.model_dump()
            | {
                "terminal_decision": terminal,
                "updated_at": max(utc_now(), session.updated_at),
            }
        )

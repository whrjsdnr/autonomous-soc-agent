"""Validate history references and combine identical signal representations once."""

from soc_agent.adaptive.errors import InvalidInvestigationContextError
from soc_agent.adaptive.models import InvestigationContext
from soc_agent.security_ai import AISignal, build_ai_signal_context


def validate_context(
    context: InvestigationContext,
) -> tuple[InvestigationContext, tuple[AISignal, ...]]:
    try:
        context = InvestigationContext.model_validate(context.model_dump(warnings=False))
        state = context.incident
        build_ai_signal_context(context.signals, state=state)
        # History and explicit signals may both carry the same snapshot; never double-count it.
        signals = {signal.signal_id: signal for signal in context.signals}
        tool_plan_ids = set()
        ai_run_ids = set()
        tool_step_ids = set()
        evidence_ids = {item.evidence_id for item in state.evidence}
        for plan in context.tool_history:
            if plan.incident_id != state.incident_id or plan.plan_id in tool_plan_ids:
                raise ValueError("Invalid or duplicate tool history incident/plan")
            tool_plan_ids.add(plan.plan_id)
            for step in plan.steps:
                if step.step_id in tool_step_ids:
                    raise ValueError("Duplicate tool history step")
                tool_step_ids.add(step.step_id)
                if step.evidence_id is not None and step.evidence_id not in evidence_ids:
                    raise ValueError("Tool history evidence absent from current incident")
        for history in context.ai_history:
            if history.incident_id != state.incident_id or history.investigation_id in ai_run_ids:
                raise ValueError("Invalid or duplicate AI history incident/run")
            ai_run_ids.add(history.investigation_id)
            for signal in history.signals:
                if signal.signal_id in signals and signals[signal.signal_id] != signal:
                    raise ValueError("Conflicting copies of an AI signal")
                signals[signal.signal_id] = signal
        combined = tuple(signals.values())
        build_ai_signal_context(combined, state=state)
        if not (state.evidence or combined or context.tool_history or context.ai_history):
            raise ValueError("Replanning requires evidence, signals, or investigation history")
    except (ValueError, TypeError) as error:
        raise InvalidInvestigationContextError("Invalid replanning context") from error
    return context, combined

"""Preflight all steps, then sequential inference and trusted signal conversion."""

from collections.abc import Mapping
from uuid import UUID

from pydantic import TypeAdapter

from soc_agent.security_ai.errors import (
    SecurityAIInferenceError,
    SecurityAIInputValidationError,
    SecurityAIOutputValidationError,
)
from soc_agent.security_ai.investigation_errors import (
    SecurityAIInvestigationError,
    SecurityAIPreflightError,
)
from soc_agent.security_ai.investigation_models import (
    SecurityAIInvestigationResult,
    SecurityAIInvestigationStep,
)
from soc_agent.security_ai.investigation_models import (
    SecurityAIInvestigationStepStatus as Status,
)
from soc_agent.security_ai.investigation_preflight import validate_execution_step
from soc_agent.security_ai.registry import SecurityAIRegistry
from soc_agent.security_ai.selection_models import SecurityAISelectionPlan
from soc_agent.security_ai.signals import create_ai_signal
from soc_agent.state import IncidentState
from soc_agent.state.evidence import utc_now


def _terminal(
    step: SecurityAIInvestigationStep, status: Status, *, error_type: str, message: str
) -> SecurityAIInvestigationStep:
    return SecurityAIInvestigationStep.model_validate(
        step.model_dump()
        | {
            "status": status,
            "error_type": error_type,
            "error_message": message,
            "completed_at": max(utc_now(), step.started_at or utc_now()),
        }
    )


class SecurityAIInvestigator:
    """No LLM, tools, policy, retries, fallback, parallelism, or incident mutation.

    Each execute call is an explicit fresh attempt; no durable replay/resume support.
    Cancellation propagates, as in the Tool orchestrator.
    """

    def __init__(self, *, registry: SecurityAIRegistry) -> None:
        self._registry = registry

    async def execute(
        self,
        *,
        incident: IncidentState,
        selection_plan: SecurityAISelectionPlan,
        source_evidence: Mapping[UUID, tuple[UUID, ...]] | None = None,
    ) -> SecurityAIInvestigationResult:
        try:
            state = IncidentState.model_validate(incident.model_dump(warnings=False))
            plan = SecurityAISelectionPlan.model_validate(selection_plan.model_dump(warnings=False))
            references = TypeAdapter(dict[UUID, tuple[UUID, ...]]).validate_python(
                dict(source_evidence) if source_evidence is not None else {}
            )
        except (ValueError, TypeError) as error:
            raise SecurityAIInvestigationError("Invalid AI execution request") from error
        if plan.incident_id != state.incident_id:
            raise SecurityAIInvestigationError("Plan and incident IDs differ")
        if not set(references) <= {step.step_id for step in plan.steps}:
            raise SecurityAIInvestigationError(
                "Source mapping references an unknown selection step"
            )
        created_at = utc_now()
        steps = [
            SecurityAIInvestigationStep(
                selection=step, source_evidence_ids=references.get(step.step_id, ())
            )
            for step in plan.steps
        ]
        # No inference until every selected step passes preflight.
        for index, step in enumerate(steps):
            try:
                validate_execution_step(
                    step.selection,
                    registry=self._registry,
                    state=state,
                    source_evidence_ids=step.source_evidence_ids,
                )
            except SecurityAIPreflightError as error:
                steps[index] = _terminal(
                    step, Status.BLOCKED, error_type=type(error).__name__, message=str(error)
                )
                break
        else:
            for index, step in enumerate(steps):
                steps[index] = await self._execute_step(state, step)
                if steps[index].status != Status.COMPLETED:
                    break
        return SecurityAIInvestigationResult(
            selection_plan_id=plan.plan_id,
            incident_id=state.incident_id,
            decision=plan.decision,
            steps=tuple(steps),
            created_at=created_at,
            completed_at=max(utc_now(), created_at, *(s.completed_at or created_at for s in steps)),
        )

    async def _execute_step(
        self, state: IncidentState, step: SecurityAIInvestigationStep
    ) -> SecurityAIInvestigationStep:
        # Recheck current registry after each previous awaited inference.
        try:
            model = validate_execution_step(
                step.selection,
                registry=self._registry,
                state=state,
                source_evidence_ids=step.source_evidence_ids,
            )
        except SecurityAIPreflightError as error:
            return _terminal(
                step, Status.BLOCKED, error_type=type(error).__name__, message=str(error)
            )
        started_at = utc_now()
        try:
            result = await model.predict(
                {"incident_id": state.incident_id, "input": step.selection.input_payload()}
            )
        except SecurityAIInputValidationError:
            return _terminal(
                step,
                Status.BLOCKED,
                error_type="SecurityAIInputValidationError",
                message="Model wrapper rejected input before inference",
            )
        except (SecurityAIInferenceError, SecurityAIOutputValidationError) as error:
            return SecurityAIInvestigationStep.model_validate(
                step.model_dump()
                | {
                    "status": Status.FAILED,
                    "started_at": started_at,
                    "completed_at": max(utc_now(), started_at),
                    "error_type": type(error).__name__,
                    "error_message": "Security AI inference or output validation failed",
                }
            )
        try:
            signal = create_ai_signal(
                result, state=state, source_evidence_ids=step.source_evidence_ids
            )
        except (ValueError, TypeError):
            return SecurityAIInvestigationStep.model_validate(
                step.model_dump()
                | {
                    "status": Status.FAILED,
                    "started_at": started_at,
                    "completed_at": max(utc_now(), started_at),
                    "result": result,
                    "error_type": "AISignalConversionError",
                    "error_message": "AI signal conversion failed",
                }
            )
        return SecurityAIInvestigationStep.model_validate(
            step.model_dump()
            | {
                "status": Status.COMPLETED,
                "result": result,
                "signal": signal,
                "started_at": started_at,
                "completed_at": max(utc_now(), started_at),
            }
        )

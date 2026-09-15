"""AI-derived analytical snapshots; never observed facts or action authority."""

from uuid import UUID, uuid4

from pydantic import Field, TypeAdapter

from soc_agent.security_ai.enums import SecurityAITaskType
from soc_agent.security_ai.models import ModelName, SecurityAIPrediction, SecurityAIResult
from soc_agent.state import IncidentState
from soc_agent.state.evidence import NonEmptyText, UTCTimestamp, utc_now


class AISignal(SecurityAIPrediction):
    """Immutable agent-facing snapshot. Use create_ai_signal for trusted conversion.

    Direct construction/deserialization validates shape, not origin authenticity.
    As with SecurityAIResult, trusted Python is not a cryptographic trust boundary.
    """

    signal_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    source_result_id: UUID
    model_name: ModelName
    model_version: NonEmptyText
    task_type: SecurityAITaskType
    source_evidence_ids: tuple[UUID, ...] = ()
    source_created_at: UTCTimestamp
    created_at: UTCTimestamp = Field(default_factory=utc_now)


def _validate_references(
    incident_id: UUID, source_evidence_ids: tuple[UUID, ...], state: IncidentState
) -> None:
    if incident_id != state.incident_id:
        raise ValueError("AI signal and state must belong to the same incident")
    if len(source_evidence_ids) != len(set(source_evidence_ids)):
        raise ValueError("Duplicate source evidence IDs are not allowed")
    evidence = {item.evidence_id: item for item in state.evidence}
    for reference in source_evidence_ids:
        if reference not in evidence:
            raise ValueError("Source evidence must exist in this incident")
        if evidence[reference].incident_id != incident_id:
            raise ValueError("Source evidence must belong to the same incident")


def create_ai_signal(
    result: SecurityAIResult,
    *,
    state: IncidentState,
    source_evidence_ids: tuple[UUID, ...] = (),
) -> AISignal:
    """Copy provenance only from a validated result; do not execute or update state.

    Evidence references are application assertions checked against the supplied
    state, not proof of feature extraction. Empty references mean unspecified input.
    """
    if type(result) is not SecurityAIResult:
        raise TypeError("Source must be a SecurityAIResult")
    result = SecurityAIResult.model_validate(result.model_dump(warnings=False))
    state = IncidentState.model_validate(state.model_dump(warnings=False))
    references = TypeAdapter(tuple[UUID, ...]).validate_python(source_evidence_ids)
    _validate_references(result.incident_id, references, state)
    return AISignal(
        incident_id=result.incident_id,
        source_result_id=result.result_id,
        model_name=result.model_name,
        model_version=result.model_version,
        task_type=result.task_type,
        prediction=result.prediction,
        confidence=result.confidence,
        scores=result.scores,
        explanation=result.explanation,
        source_evidence_ids=references,
        source_created_at=result.created_at,
    )

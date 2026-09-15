"""Execution-time model and canonical input binding, without inference."""

from uuid import UUID

from pydantic import BaseModel
from pydantic_core import PydanticSerializationError

from soc_agent._json import canonical_json_object
from soc_agent.security_ai.base import SecurityAI
from soc_agent.security_ai.errors import SecurityAILookupError
from soc_agent.security_ai.investigation_errors import SecurityAIPreflightError
from soc_agent.security_ai.models import SecurityAIRequest
from soc_agent.security_ai.registry import SecurityAIRegistry
from soc_agent.security_ai.selection_models import SecurityAISelectionStep
from soc_agent.security_ai.signals import _validate_references
from soc_agent.state import IncidentState


def validate_execution_step(
    step: SecurityAISelectionStep,
    *,
    registry: SecurityAIRegistry,
    state: IncidentState,
    source_evidence_ids: tuple[UUID, ...],
) -> SecurityAI[BaseModel]:
    try:
        _validate_references(state.incident_id, source_evidence_ids, state)
    except ValueError as error:
        raise SecurityAIPreflightError("Invalid related source evidence references") from error
    try:
        model = registry.get(step.model_name)
    except SecurityAILookupError as error:
        raise SecurityAIPreflightError("Selected model is not currently registered") from error
    if type(model) is not SecurityAI:
        raise SecurityAIPreflightError("Registered model must be a SecurityAI wrapper")
    metadata = model.metadata
    if (step.model_name, step.model_version, step.task_type, step.input_type) != (
        metadata.name,
        metadata.version,
        metadata.task_type,
        metadata.input_type,
    ):
        raise SecurityAIPreflightError("Current model metadata differs from selection")
    try:
        value = model.input_model.model_validate(step.input_payload(), extra="forbid")
        payload = value.model_dump(mode="json", by_alias=True, round_trip=True)
        canonical = canonical_json_object(payload)
        request = SecurityAIRequest[model.input_model].model_validate(
            {"incident_id": state.incident_id, "input": payload}, extra="forbid"
        )
        envelope_canonical = canonical_json_object(
            request.input.model_dump(mode="json", by_alias=True, round_trip=True)
        )
    except (ValueError, TypeError, PydanticSerializationError) as error:
        raise SecurityAIPreflightError(
            "Input no longer satisfies the current model schema"
        ) from error
    if canonical != step.model_input or envelope_canonical != step.model_input:
        raise SecurityAIPreflightError("Canonical model input differs from selection")
    return model

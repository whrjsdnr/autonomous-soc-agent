"""Atomic draft normalization against the catalog snapshot, without inference."""

from collections.abc import Mapping
from uuid import UUID

from pydantic import BaseModel, ValidationError
from pydantic_core import PydanticSerializationError

from soc_agent._json import canonical_json_object
from soc_agent.llm import LLMResponseValidationError
from soc_agent.security_ai.base import SecurityAI
from soc_agent.security_ai.models import SecurityAIRequest
from soc_agent.security_ai.selection_errors import (
    InvalidSelectedModelInputError,
    SecurityAISelectionError,
    UnknownSelectedModelError,
)
from soc_agent.security_ai.selection_models import (
    SecurityAISelectionDraft,
    SecurityAISelectionPlan,
    SecurityAISelectionStep,
)


def normalize_selection(
    draft: SecurityAISelectionDraft,
    *,
    incident_id: UUID,
    models: Mapping[str, SecurityAI[BaseModel]],
) -> SecurityAISelectionPlan:
    try:
        draft = SecurityAISelectionDraft.model_validate(draft.model_dump(warnings=False))
    except ValidationError as error:
        raise LLMResponseValidationError("Invalid security AI selection draft") from error
    steps = []
    seen: set[tuple[str, str]] = set()
    for selection in draft.selections:
        if selection.model_name not in models:
            raise UnknownSelectedModelError("Selected model is outside the selection catalog")
        model = models[selection.model_name]
        try:
            value = model.input_model.model_validate(selection.model_input, extra="forbid")
            payload = value.model_dump(mode="json", by_alias=True, round_trip=True)
            canonical = canonical_json_object(payload)
            # Match the actual wrapper's envelope validation without calling predict.
            SecurityAIRequest[model.input_model].model_validate(
                {"incident_id": incident_id, "input": payload}, extra="forbid"
            )
        except (ValueError, TypeError, PydanticSerializationError) as error:
            raise InvalidSelectedModelInputError(
                "Selected input does not satisfy its schema"
            ) from error
        key = (selection.model_name, canonical)
        if key in seen:
            raise SecurityAISelectionError("Duplicate model and canonical input selection")
        seen.add(key)
        metadata = model.metadata
        steps.append(
            SecurityAISelectionStep(
                model_name=metadata.name,
                model_version=metadata.version,
                task_type=metadata.task_type,
                input_type=metadata.input_type,
                model_input=canonical,
                purpose=selection.purpose,
            )
        )
    return SecurityAISelectionPlan(
        incident_id=incident_id,
        decision=draft.decision,
        goal=draft.goal,
        reason=draft.reason,
        steps=tuple(steps),
    )

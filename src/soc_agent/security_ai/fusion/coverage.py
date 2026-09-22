"""Explicit expectations and execution availability; absence never means normal."""

from soc_agent.security_ai.fusion.errors import FusionValidationError
from soc_agent.security_ai.fusion.models import CoverageEntry, ModelAvailability
from soc_agent.security_ai.packaging.package import Kind


def coverage_entries(
    expected: tuple[Kind, ...], observed: set[Kind], unavailable: tuple[ModelAvailability, ...]
) -> tuple[CoverageEntry, ...]:
    if not isinstance(unavailable, tuple) or len(unavailable) > 3:
        raise FusionValidationError("At most three immutable availability records supported")
    declared = {}
    for value in unavailable:
        value = ModelAvailability.model_validate(value.model_dump())
        if value.model_kind in declared or value.model_kind in observed:
            raise FusionValidationError("Ambiguous observed/unavailable model status")
        declared[value.model_kind] = value
    entries = []
    for kind in sorted(set(expected) | observed | set(declared)):
        if kind in observed:
            entries.append(CoverageEntry(model_kind=kind, status="observed"))
        elif kind in declared:
            entries.append(CoverageEntry(**declared[kind].model_dump()))
        else:
            entries.append(CoverageEntry(model_kind=kind, status="not_reported"))
    return tuple(entries)

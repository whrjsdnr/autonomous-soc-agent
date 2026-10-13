"""Bounded advisory assembly, independent of Fusion v1 and incident mutation."""

from typing import Literal, Self

from pydantic import Field, model_validator

from soc_agent.review.identity import content_digest
from soc_agent.review.models import StateAnchor, StoredIncident
from soc_agent.security_ai.external.adapters import ExternalEvidenceAdapter
from soc_agent.security_ai.external.inference import ModelRun
from soc_agent.security_ai.external.models import ExternalModelResult, Hash, Snapshot, Text
from soc_agent.security_ai.external.validation import check_history, validate_source


class Coverage(Snapshot):
    binding_id: Text
    status: Literal[
        "AVAILABLE", "NOT_CONFIGURED", "NOT_RUN", "NOT_APPLICABLE", "UNAVAILABLE", "INVALID"
    ]
    code: Text


class ObservationGroup(Snapshot):
    observation_key: Hash
    result_digests: tuple[Hash, ...] = Field(min_length=1, max_length=16)
    correlation_status: Literal["SOURCE_BOUND", "UNLINKED"]


class ContextContent(Snapshot):
    contract_version: Literal["soc-external-model-context:v2"] = "soc-external-model-context:v2"
    input_snapshot: StateAnchor | None
    results: tuple[ExternalModelResult, ...] = Field(max_length=16)
    # Kept separate: never eligible for incident investigation consumption.
    unlinked_results: tuple[ExternalModelResult, ...] = Field(max_length=16)
    coverage: tuple[Coverage, ...] = Field(max_length=16)
    correlation_groups: tuple[ObservationGroup, ...] = Field(max_length=16)
    cross_domain_correlation: Literal["UNVERIFIED"] = "UNVERIFIED"
    uncertainty: Literal["UNKNOWN"] = "UNKNOWN"
    validation_rule: Literal["soc-external-assembly:v2"] = "soc-external-assembly:v2"
    limitations: tuple[Text, ...] = (
        "Synthetic precomputed features only; operational feature extraction is unverified.",
        "Model inference is not observed Evidence, statistical confidence or action authority.",
        "No cross-domain association, calibration, score averaging or severity assignment.",
    )


class ExternalModelContext(ContextContent):
    context_digest: Hash

    @model_validator(mode="after")
    def integrity(self) -> Self:
        content = ContextContent.model_validate(self.model_dump(exclude={"context_digest"}))
        if content_digest(content) != self.context_digest:
            raise ValueError("CONTEXT_DIGEST_MISMATCH")
        if len(self.model_dump_json().encode("utf-8")) > 128 * 1024:
            raise ValueError("CONTEXT_SIZE_LIMIT")
        if len(self.results) + len(self.unlinked_results) > 16:
            raise ValueError("CONTEXT_RESULT_LIMIT")
        return self


def assemble(
    runs: tuple[ModelRun, ...], *, incident: StoredIncident | None = None
) -> ExternalModelContext:
    """Revalidate each result and its source; never trust status alone.

    Missing required models cannot be represented as successful assembly. Callers
    select expected models explicitly; this function does not discover models.
    """
    if not runs or len(runs) > 16:
        raise ValueError("CONTEXT_RUN_LIMIT")
    runs = tuple(ModelRun.model_validate(run) for run in runs)
    seen_bindings = set()
    observations: dict[tuple[str, str, str, str], str] = {}
    history: tuple[ExternalModelResult, ...] = ()
    linked = []
    unlinked = []
    groups: dict[str, list[ExternalModelResult]] = {}
    coverage = []
    for run in sorted(runs, key=lambda r: r.binding.binding_id):
        identity = run.binding.binding_id
        if identity in seen_bindings:
            raise ValueError("DUPLICATE_MODEL_RESULT")
        seen_bindings.add(identity)
        if run.result is None:
            if run.required or run.status != "UNAVAILABLE":
                raise ValueError("REQUIRED_MODEL_UNAVAILABLE")
            coverage.append(Coverage(binding_id=identity, status="UNAVAILABLE", code=run.code))
            continue
        result = ExternalModelResult.model_validate(run.result)
        if run.status != "AVAILABLE" or run.binding != result.binding:
            raise ValueError("MODEL_RESULT_BINDING_MISMATCH")
        verified = ExternalEvidenceAdapter().adapt(
            result.original_envelope,
            binding=result.binding,
            observation=result.observation,
            provenance=result.provenance,
            received_at=result.received_at,
            incident=incident,
            history=history,
        )
        if verified.result is None or verified.result.model_dump(
            exclude={"original_envelope_digest", "result_digest"}
        ) != result.model_dump(exclude={"original_envelope_digest", "result_digest"}):
            raise ValueError("RESULT_REVALIDATION_FAILED")
        check_history(result, history)
        history += (result,)
        observation = result.observation
        key = (
            observation.source_namespace,
            observation.source_event_id,
            observation.source_observation_id,
            observation.observation_type,
        )
        previous = observations.setdefault(key, observation.source_content_digest)
        if previous != observation.source_content_digest:
            raise ValueError("OBSERVATION_IDENTITY_COLLISION")
        is_linked = validate_source(observation, incident)
        if is_linked != (result.validation.status == "VALIDATED_FOR_ADVISORY"):
            raise ValueError("SOURCE_ASSOCIATION_MISMATCH")
        (linked if is_linked else unlinked).append(result)
        groups.setdefault(observation.observation_key, []).append(result)
        coverage.append(Coverage(binding_id=identity, status="AVAILABLE", code="OK"))
    content = ContextContent(
        input_snapshot=None if incident is None else incident.anchor,
        results=tuple(linked),
        unlinked_results=tuple(unlinked),
        coverage=tuple(coverage),
        correlation_groups=tuple(
            ObservationGroup(
                observation_key=key,
                result_digests=tuple(r.result_digest for r in group),
                correlation_status="SOURCE_BOUND"
                if group[0].validation.status == "VALIDATED_FOR_ADVISORY"
                else "UNLINKED",
            )
            for key, group in sorted(groups.items())
        ),
    )
    return ExternalModelContext(**content.model_dump(), context_digest=content_digest(content))

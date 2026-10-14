"""Explicit monitor-source pattern; cannot masquerade as a core dataset sample."""

from typing import Literal, Self

from pydantic import Field, model_validator

from soc_agent.improvement_candidates.models import DatasetBinding, PatternType
from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.review.identity import content_digest
from soc_agent.security_ai.external.models import Hash, Snapshot


class RuntimePatternContent(Snapshot):
    schema_version: Literal["monitor-human-feedback-pattern:v1"] = (
        "monitor-human-feedback-pattern:v1"
    )
    dataset: DatasetBinding
    pattern_type: Literal[PatternType.FALSE_POSITIVE] = PatternType.FALSE_POSITIVE
    supporting_sample_refs: tuple[ArtifactReference, ...] = Field(min_length=2)
    supporting_feedback_refs: tuple[ArtifactReference, ...] = Field(min_length=2)
    occurrence_count: int = Field(ge=2)
    assurance: Literal["HUMAN_OPINION_NOT_GROUND_TRUTH"] = "HUMAN_OPINION_NOT_GROUND_TRUTH"


class RuntimeFailurePattern(Snapshot):
    pattern_id: Hash
    content: RuntimePatternContent

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.pattern_id != content_digest(self.content):
            raise ValueError("RUNTIME_PATTERN_DIGEST_REJECTED")
        return self

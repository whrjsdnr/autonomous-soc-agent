"""Model predictions are immutable data, never evidence or execution authority."""

from typing import Annotated
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    TypeAdapter,
    field_validator,
)

from soc_agent._json import canonical_json_object
from soc_agent.security_ai.enums import SecurityAIInputType, SecurityAITaskType
from soc_agent.state.evidence import Confidence, NonEmptyText, UTCTimestamp, utc_now

ModelName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")]


class SecurityAIModelMetadata(BaseModel):
    """Trusted setup chooses identity/version; no version routing is inferred."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    name: ModelName
    version: NonEmptyText
    description: NonEmptyText
    task_type: SecurityAITaskType
    input_type: SecurityAIInputType


class SecurityAIRequest[TInput: BaseModel](BaseModel):
    """Minimal context. Nested input mutability follows its schema.

    The wrapper detaches and revalidates even existing model instances before use.
    This envelope carries no IncidentState and is never copied into a result.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
    incident_id: UUID
    input: TInput


class SecurityAIPrediction(BaseModel):
    """Handler-controlled prediction payload without provenance fields.

    Prediction is a nonempty label for the supported tasks. Confidence is optional
    and never inferred from scores. Scores can be uncalibrated, negative, or above
    one; they and explanations are JSON objects stored as immutable canonical text.
    Payload helpers return fresh objects, preserving deeply immutable results.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
    prediction: NonEmptyText
    confidence: Confidence | None = None
    scores: str = "{}"
    explanation: str | None = None

    @field_validator("scores", mode="before")
    @classmethod
    def freeze_scores(cls, value: object) -> str:
        return canonical_json_object(value)

    @field_validator("explanation", mode="before")
    @classmethod
    def freeze_explanation(cls, value: object) -> str | None:
        return None if value is None else canonical_json_object(value)

    def scores_payload(self) -> dict[str, JsonValue]:
        return TypeAdapter(dict[str, JsonValue]).validate_json(self.scores, strict=True)

    def explanation_payload(self) -> dict[str, JsonValue] | None:
        if self.explanation is None:
            return None
        return TypeAdapter(dict[str, JsonValue]).validate_json(self.explanation, strict=True)


class SecurityAIResult(SecurityAIPrediction):
    """Validated prediction with application-owned provenance, not an observed fact.

    UUID/time are generated only after successful inference/output validation.
    No raw request is retained. Inheriting payload fields does not permit handlers
    to return provenance: the wrapper validates against SecurityAIPrediction only.
    """

    result_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    model_name: ModelName
    model_version: NonEmptyText
    task_type: SecurityAITaskType
    created_at: UTCTimestamp = Field(default_factory=utc_now)

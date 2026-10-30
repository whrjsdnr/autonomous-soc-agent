"""Fixed-role source links and advisory tasks; none of these records grants authority."""

from typing import Literal, Self
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import Field, JsonValue, model_validator

from soc_agent.review.models import Frozen, Hash
from soc_agent.security_ai.research.models import digest
from soc_agent.state.evidence import UTCTimestamp

Role = Literal["NETWORK", "DNS", "AUTHENTICATION", "INVESTIGATION"]


class InvestigationSource(Frozen):
    incident_id: UUID
    role: Role
    origin: str = Field(min_length=1, max_length=128)
    namespace: str = Field(min_length=1, max_length=128)
    scope: Hash
    reference: Hash
    observed_at: UTCTimestamp
    # Only a source adapter may populate a target/time key. The LLM never supplies it.
    target: Hash | None = None
    clock: str = Field(default="UNKNOWN", min_length=1, max_length=128)
    event_ns: int | None = Field(default=None, ge=0, strict=True)
    advisory: dict[str, JsonValue]

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if len(self.model_dump_json().encode()) > 60000:
            raise ValueError("CONTINUOUS_INVESTIGATION_SOURCE_LIMIT")
        return self

    @property
    def pin(self) -> str:
        return digest(self.model_dump(mode="json"))

    @property
    def group(self) -> str:
        if self.target is None or self.event_ns is None or self.clock == "UNKNOWN":
            return digest(dict(standalone=str(self.incident_id), scope=self.scope))
        return digest(
            dict(
                scope=self.scope,
                namespace=self.namespace,
                origin=self.origin,
                target=self.target,
                clock=self.clock,
                minute=self.event_ns // 60_000_000_000,
            )
        )


class InvestigationTask(Frozen):
    contract: Literal["soc-continuous-investigation-task:v1"] = (
        "soc-continuous-investigation-task:v1"
    )
    incident_id: UUID
    group: Hash
    sources: tuple[Hash, ...] = Field(min_length=1, max_length=64)
    related_incidents: tuple[UUID, ...] = Field(min_length=1, max_length=64)
    roles: tuple[Role, ...] = Field(min_length=1, max_length=4)
    priority: int = Field(ge=0, le=2, strict=True)
    conflict: bool
    created_at: UTCTimestamp

    @model_validator(mode="after")
    def canonical(self) -> Self:
        if self.sources != tuple(sorted(set(self.sources))):
            raise ValueError("CONTINUOUS_TASK_SOURCE_ORDER")
        if self.incident_id not in self.related_incidents:
            raise ValueError("CONTINUOUS_TASK_OWNER_BINDING")
        if self.related_incidents != tuple(sorted(set(self.related_incidents), key=str)):
            raise ValueError("CONTINUOUS_TASK_INCIDENT_ORDER")
        return self

    @property
    def revision(self) -> str:
        return digest(self.sources)

    @property
    def task_id(self) -> UUID:
        return uuid5(NAMESPACE_URL, "soc-investigation:" + self.group + ":" + self.revision)


class CoordinationAdvice(Frozen):
    """A bounded proposal. Additional models still require their independent action grant."""

    priority: int = Field(ge=0, le=2, strict=True)
    additional_evidence_required: bool
    reason: str = Field(min_length=1, max_length=1000)
    requested_roles: tuple[Role, ...] = Field(default=(), max_length=4)
    strategy: Literal["READ_RETAINED_EVIDENCE", "ESCALATE", "ASSESS"]

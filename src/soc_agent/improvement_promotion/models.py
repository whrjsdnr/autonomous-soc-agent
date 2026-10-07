"""Bounded version governance; payloads are constraints, never executable text."""

from enum import StrEnum
from typing import Literal, Self
from uuid import NAMESPACE_URL, uuid5

from pydantic import Field, model_validator

from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.improvement_review.models import ReviewRequestContent
from soc_agent.planning.strategy import InvestigationStrategy
from soc_agent.review.authentication import HumanActionContext, HumanVerificationRecord
from soc_agent.review.authority import HumanAction
from soc_agent.review.authorization import permission_for
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen, Hash
from soc_agent.state.evidence import UTCTimestamp, utc_now


class ArtifactFamily(StrEnum):
    INVESTIGATION_STRATEGY_DEFAULT = "INVESTIGATION_STRATEGY_DEFAULT"


FAMILY = ArtifactFamily.INVESTIGATION_STRATEGY_DEFAULT
# Existing confirmation infrastructure requires a UUID scope. It is a fixed family
# resource namespace, not an incident; registry keys never use incident IDs.
FAMILY_SCOPE = uuid5(NAMESPACE_URL, "soc-agent/improvement/INVESTIGATION_STRATEGY_DEFAULT")


class SourceSnapshot(Frozen):
    review_request: ArtifactReference
    review_record: ArtifactReference
    snapshot: ReviewRequestContent


class ArtifactContent(Frozen):
    artifact_family: Literal[FAMILY] = FAMILY
    artifact_type: Literal["INVESTIGATION_STRATEGY"] = "INVESTIGATION_STRATEGY"
    version: int = Field(ge=1)
    payload: InvestigationStrategy
    source_snapshot: SourceSnapshot


class VersionedImprovementArtifact(Frozen):
    artifact_id: Hash
    content_digest: Hash
    content: ArtifactContent
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.artifact_id != self.content_digest or self.content_digest != content_digest(
            self.content
        ):
            raise ValueError("Artifact identity mismatch")
        return self


class ActivePointer(Frozen):
    family: Literal[FAMILY] = FAMILY
    active_artifact: ArtifactReference | None = None
    active_version: int | None = Field(default=None, ge=1)
    revision: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def consistency(self) -> Self:
        if (self.active_artifact is None) != (self.active_version is None):
            raise ValueError("Pointer version binding mismatch")
        if self.active_artifact is None and self.revision != 0:
            raise ValueError("Initial NONE pointer must have revision zero")
        return self


class PromotionContent(Frozen):
    governance_version: Literal["soc-improvement-version-governance:v1"] = (
        "soc-improvement-version-governance:v1"
    )
    family: Literal[FAMILY] = FAMILY
    payload: InvestigationStrategy
    source_snapshot: SourceSnapshot
    expected: ActivePointer


class RollbackContent(Frozen):
    governance_version: Literal["soc-improvement-version-governance:v1"] = (
        "soc-improvement-version-governance:v1"
    )
    family: Literal[FAMILY] = FAMILY
    target: ArtifactReference
    target_version: int = Field(ge=1)
    expected: ActivePointer
    reason: Literal["RESTORE_REGISTERED_VERSION"] = "RESTORE_REGISTERED_VERSION"


class PromotionRequest(Frozen):
    request_id: Hash
    content: PromotionContent
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.request_id != content_digest(self.content):
            raise ValueError("Promotion request identity mismatch")
        return self


class RollbackRequest(Frozen):
    request_id: Hash
    content: RollbackContent
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.request_id != content_digest(self.content):
            raise ValueError("Rollback request identity mismatch")
        return self


def action_context(request: PromotionRequest | RollbackRequest) -> HumanActionContext:
    return HumanActionContext(
        incident_id=FAMILY_SCOPE,
        action=HumanAction.PROMOTE_IMPROVEMENT_ARTIFACT
        if isinstance(request, PromotionRequest)
        else HumanAction.ROLLBACK_IMPROVEMENT_ARTIFACT,
        binding_digest=content_digest(request.content),
        decision_id=None,
    )


class ActivationRecord(Frozen):
    record_id: Hash
    request: ArtifactReference
    action: Literal["PROMOTION", "ROLLBACK"]
    family: Literal[FAMILY] = FAMILY
    previous: ActivePointer
    current: ActivePointer
    verification: HumanVerificationRecord
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def consistency(self) -> Self:
        expected_action = (
            HumanAction.PROMOTE_IMPROVEMENT_ARTIFACT
            if self.action == "PROMOTION"
            else HumanAction.ROLLBACK_IMPROVEMENT_ARTIFACT
        )
        if (
            self.current.revision != self.previous.revision + 1
            or self.current.active_artifact is None
            or self.verification.permission != permission_for(expected_action)
            or self.verification.context.action != expected_action
            or self.verification.context.incident_id != FAMILY_SCOPE
            or self.verification.context.binding_digest != self.request.digest
            or self.record_id != record_identity(self.request, self.verification)
        ):
            raise ValueError("Activation audit binding mismatch")
        return self


class RecordIdentity(Frozen):
    request: ArtifactReference
    provider: str
    subject: str
    session: str


def record_identity(request: ArtifactReference, verification: HumanVerificationRecord) -> str:
    return content_digest(
        RecordIdentity(
            request=request,
            provider=verification.provider_id,
            subject=verification.subject_id,
            session=verification.session_id,
        )
    )

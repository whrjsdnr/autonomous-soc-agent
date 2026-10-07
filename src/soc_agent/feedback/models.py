"""Human adjudication, never Evidence or governance/execution authority."""

import re
from enum import StrEnum
from typing import Literal, Self, cast
from uuid import UUID

from pydantic import (
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
    model_validator,
)

from soc_agent.review.authentication import HumanVerificationRecord
from soc_agent.review.authority import HumanAction
from soc_agent.review.authorization import HumanPermission
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen, Hash, Subject
from soc_agent.state.evidence import UTCTimestamp, utc_now
from soc_agent.tools.models import ReadOnlyPermission


class Verdict(StrEnum):
    CORRECT = "correct"
    INCORRECT = "incorrect"
    INCONCLUSIVE = "inconclusive"


class DiagnosticLabel(StrEnum):
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    UNNECESSARY_INVESTIGATION = "unnecessary_investigation"
    MISSED_INVESTIGATION = "missed_investigation"


class ReviewCompleteness(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"


class InvestigationPathAdjudication(Frozen):
    """Human review of the three read-only permission classes, not tool-call counts."""

    adjudication_version: Literal["human-investigation-path-adjudication:v1"] = (
        "human-investigation-path-adjudication:v1"
    )
    unnecessary_permissions: tuple[ReadOnlyPermission, ...]
    review_completeness: ReviewCompleteness

    @model_validator(mode="after")
    def canonical(self) -> Self:
        if self.unnecessary_permissions != tuple(sorted(set(self.unnecessary_permissions))):
            raise ValueError("Canonical unique unnecessary permissions required")
        return self


def adjudications_conflict(
    required: set[ReadOnlyPermission], adjudications: tuple[InvestigationPathAdjudication, ...]
) -> bool:
    """Preserve disagreement; do not choose a reviewer or infer a complete allowlist."""
    complete = {
        a.unnecessary_permissions
        for a in adjudications
        if a.review_completeness == ReviewCompleteness.COMPLETE
    }
    if len(complete) > 1 or any(
        required.intersection(a.unnecessary_permissions) for a in adjudications
    ):
        return True
    if complete:
        (full,) = complete
        return any(not set(a.unnecessary_permissions) <= set(full) for a in adjudications)
    return False


class CoverageExpectation(Frozen):
    """Explicit human required paths; never inferred from overall defect labels."""

    contract_version: Literal["human-read-only-coverage:v1"] = "human-read-only-coverage:v1"
    required_permissions: tuple[ReadOnlyPermission, ...] = Field(min_length=1)
    path_adjudication: InvestigationPathAdjudication | None = None

    @model_validator(mode="after")
    def canonical(self) -> Self:
        if self.required_permissions != tuple(sorted(set(self.required_permissions))):
            raise ValueError("Canonical unique human coverage requirements required")
        if self.path_adjudication is not None and adjudications_conflict(
            set(self.required_permissions), (self.path_adjudication,)
        ):
            raise ValueError("Required and unnecessary permissions conflict")
        return self

    @model_serializer(mode="wrap")
    def legacy_serialization(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        value = cast(dict[str, object], handler(self))
        if self.path_adjudication is None:
            value.pop("path_adjudication", None)
        return value


class FeedbackRequest(Frozen):
    """A new submission ID denotes a new judgment; retain it across transport retries.

    OVERALL is the only supported scope. Labels apply to this overall evaluation,
    not an inferred component. All diagnostic labels assert a definite defect.
    """

    submission_id: UUID
    incident_id: UUID
    experience_id: Hash
    experience_digest: Hash
    evaluation_id: Hash
    evaluation_digest: Hash
    scope: Literal["overall"] = "overall"
    verdict: Verdict
    labels: tuple[DiagnosticLabel, ...] = ()
    coverage_expectation: CoverageExpectation | None = None
    # Plain text annotation only. Never interpolated into prompts or interpreted.
    note: str = Field(default="", max_length=1000)

    @model_validator(mode="after")
    def semantics(self) -> Self:
        if self.coverage_expectation is not None and (self.verdict == Verdict.INCONCLUSIVE):
            raise ValueError("Explicit human coverage requires conclusive feedback")
        if len(set(self.labels)) != len(self.labels):
            raise ValueError("Duplicate diagnostic label")
        if tuple(sorted(self.labels)) != self.labels:
            raise ValueError("Labels must be in canonical sorted order")
        if (
            DiagnosticLabel.FALSE_POSITIVE in self.labels
            and DiagnosticLabel.FALSE_NEGATIVE in self.labels
        ):
            raise ValueError("False positive and false negative conflict in the same scope")
        if self.labels and self.verdict != Verdict.INCORRECT:
            raise ValueError("Definite defect labels require INCORRECT verdict")
        if any(ord(char) < 32 and char not in "\n\t" for char in self.note):
            raise ValueError("Notes must be plain text")
        if re.search(
            r"(?i)(password|passwd|secret|token|credential|api[_ -]?key)\s*[:=]"
            r"|\bbearer\s+\S+|-----BEGIN.*PRIVATE KEY-----",
            self.note,
        ):
            raise ValueError("Do not include authentication material in notes")
        return self

    @model_serializer(mode="wrap")
    def legacy_serialization(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        value = cast(dict[str, object], handler(self))
        if self.coverage_expectation is None:
            value.pop("coverage_expectation", None)
        return value

    @property
    def digest(self) -> str:
        return content_digest(self)


class FeedbackIdentity(Frozen):
    request: FeedbackRequest
    provider: Subject
    subject: Subject
    session: Subject


def feedback_identity(request: FeedbackRequest, provider: str, subject: str, session: str) -> str:
    return content_digest(
        FeedbackIdentity(request=request, provider=provider, subject=subject, session=session)
    )


class AnalystFeedback(Frozen):
    feedback_id: Hash
    feedback_schema_version: Literal["analyst-feedback:v1"] = "analyst-feedback:v1"
    request: FeedbackRequest
    verification: HumanVerificationRecord
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def integrity(self) -> Self:
        v = self.verification
        if (
            v.context.action != HumanAction.SUBMIT_ANALYST_FEEDBACK
            or v.permission != HumanPermission.SUBMIT_ANALYST_FEEDBACK
            or v.context.binding_digest != self.request.digest
            or v.context.incident_id != self.request.incident_id
            or v.context.request_id != self.request.submission_id
            or self.feedback_id
            != feedback_identity(self.request, v.provider_id, v.subject_id, v.session_id)
        ):
            raise ValueError("Feedback verification binding mismatch")
        return self


class FeedbackAudit(Frozen):
    """Atomic submission receipt; no secrets and no inference of correctness."""

    event: Literal["analyst_feedback_submitted"] = "analyst_feedback_submitted"
    feedback_id: Hash
    feedback_digest: Hash
    created_at: UTCTimestamp

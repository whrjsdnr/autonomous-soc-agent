"""Synthetic all-PASS evidence tests governance contracts, not real adapter safety."""

import pytest
from pydantic import ValidationError
from tests.unit.offline_comparison.test_coverage import inputs

from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.improvement_review.models import (
    ImprovementReviewRequest,
    ReasonCode,
    ReviewDecision,
    ReviewRequestContent,
    ReviewSubmission,
    require_decision,
    safety_counts,
)
from soc_agent.offline_comparison.evaluation import reference
from soc_agent.offline_comparison.execution import execute_pair
from soc_agent.offline_comparison.models import VerdictState
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.identity import content_digest


def request_for_policy(state=VerdictState.PASS):
    source, facts, spec, plan, baseline, truths = inputs()
    artifacts = execute_pair(source, spec, plan, facts, baseline, truths)
    summary = artifacts.comparison.content.model_copy(
        update={
            "safety": tuple(
                i.model_copy(update={"baseline": state, "candidate": state})
                for i in artifacts.comparison.content.safety
            ),
            "acceptance": tuple(
                c.model_copy(update={"status": VerdictState.PASS})
                for c in artifacts.comparison.content.acceptance
            ),
        }
    )
    content = ReviewRequestContent(
        binding=summary.binding,
        variant=reference(artifacts.variant.variant_id, artifacts.variant.content),
        baseline_result=summary.baseline_result,
        candidate_result=summary.candidate_result,
        comparison=ArtifactReference(
            identity=content_digest(summary), digest=content_digest(summary)
        ),
        candidate=source.content,
        summary=summary,
        limitations=("SYNTHETIC_POLICY_TEST_ONLY",),
        reviewability="REVIEWABLE",
        blocking_reasons=(),
        approval_blockers=(),
        baseline_safety_counts=safety_counts(tuple(i.baseline for i in summary.safety)),
        candidate_safety_counts=safety_counts(tuple(i.candidate for i in summary.safety)),
        authorization_incident=facts[0].sources.incident_id,
    )
    return ImprovementReviewRequest(review_request_id=content_digest(content), content=content)


@pytest.mark.parametrize("state", list(VerdictState))
def test_improvement_cannot_override_safety_even_if_blocker_view_forged(state):
    request = request_for_policy(state)
    assert any(m.outcome == "IMPROVED" for m in request.content.summary.metrics)
    if state == VerdictState.PASS:
        require_decision(request, ReviewDecision.APPROVE)
    else:
        with pytest.raises(HumanAuthorizationDenied):
            require_decision(request, ReviewDecision.APPROVE)
    for decision in (ReviewDecision.REJECT, ReviewDecision.DEFER):
        require_decision(request, decision)


def test_request_identity_excludes_creation_metadata_and_is_frozen():
    r = request_for_policy()
    assert (
        ImprovementReviewRequest(
            review_request_id=r.review_request_id, content=r.content
        ).review_request_id
        == r.review_request_id
    )
    with pytest.raises(ValidationError):
        r.review_request_id = "0" * 64
    with pytest.raises(ValidationError):
        ImprovementReviewRequest(review_request_id="0" * 64, content=r.content)


@pytest.mark.parametrize("note", ["x" * 1001, "token=private", "Bearer private", "bad\x00"])
def test_bounded_notes_and_role_spoof(note):
    data = dict(
        review_request=ArtifactReference(identity="a" * 64, digest="a" * 64),
        decision=ReviewDecision.DEFER,
        reason=ReasonCode.INSUFFICIENT_EVIDENCE,
    )
    with pytest.raises(ValidationError):
        ReviewSubmission(**dict(data, note=note))
    with pytest.raises(ValidationError):
        ReviewSubmission(**dict(data, role="admin"))
    with pytest.raises(ValidationError):
        ReviewSubmission(**dict(data, decision="PROMOTE"))


def test_synthetic_all_pass_requires_trusted_human_and_yields_only_review_record():
    from tests.unit.identity.conftest import Boundary

    from soc_agent.improvement_review.models import ImprovementReviewRecord, record_identity
    from soc_agent.improvement_review.service import review_context
    from soc_agent.review.authorization import HumanRole

    request = request_for_policy()
    submission = ReviewSubmission(
        review_request=ArtifactReference(
            identity=request.review_request_id, digest=content_digest(request.content)
        ),
        decision=ReviewDecision.APPROVE,
        reason=ReasonCode.PROMOTION_CONSIDERATION,
    )
    boundary = Boundary()
    context = review_context(request, submission)
    token = boundary.issue(context, (HumanRole.APPROVER,))
    boundary.authority.verify(
        credential=token, action=context.action, binding_digest=submission.digest
    )
    (verification,) = boundary.authority.verification_records()
    record = ImprovementReviewRecord(
        review_record_id=record_identity(submission, verification),
        submission=submission,
        snapshot=request.content,
        verification=verification,
    )
    assert record.submission.decision == ReviewDecision.APPROVE
    assert record.authority == "PROMOTION_CONSIDERATION_ONLY"
    # Shape cannot claim an AI/system principal, even with otherwise valid roles.
    principal = boundary.provider.principals[token].model_dump()
    with pytest.raises(ValidationError):
        type(boundary.provider.principals[token]).model_validate(
            dict(principal, subject_kind="system")
        )

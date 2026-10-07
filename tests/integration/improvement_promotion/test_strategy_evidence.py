import pytest
from tests.integration.experience.test_storage import table_snapshot
from tests.integration.improvement_review.test_review import issue, submission
from tests.integration.offline_comparison.test_storage import reopen

from soc_agent.improvement_promotion import PromotionEligibilityService, PromotionReason
from soc_agent.improvement_review import ImprovementReviewStore, ReviewDecision, review_context
from soc_agent.offline_comparison.models import CONTRACT_EVALUATOR_VERSION, VerdictState
from soc_agent.review.authorization import HumanRole
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.state.evidence import utc_now


def test_new_evidence_persists_without_rewriting_reviews_or_creating_authority(
    review_case, monkeypatch
):
    c = review_case
    old_value = submission(c)
    old_record = c.service.submit(old_value, credential=issue(c, old_value))
    before = table_snapshot(c.store.database)

    def forbidden(*args, **kwargs):
        raise AssertionError("Evaluation invoked production")

    for obj, attribute in (
        (c.source.runtime, "advance"),
        (c.source.executor, "execute"),
        (c.source.llm, "generate_structured"),
    ):
        monkeypatch.setattr(obj, attribute, forbidden)
    artifacts = c.source.runner.evaluate(
        c.source.plan.plan_id,
        baseline_id=c.source.baseline.baseline_id,
        evaluator_version=CONTRACT_EVALUATOR_VERSION,
    )
    assert artifacts.comparison.comparison_id != c.artifacts.comparison.comparison_id
    after = table_snapshot(c.store.database)
    for table in before:
        if table not in {"offline_evaluation_results", "offline_comparisons"}:
            assert before[table] == after[table]
    assert not any("promotion" in table or "active_pointer" in table for table in after)
    with c.store.database.transaction(write=False) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 13
    request = c.store.create_request(artifacts.comparison.comparison_id)
    assert request.review_request_id != c.request.review_request_id
    assert request.content.candidate_safety_counts == (10, 0, 0)
    assert any(a.status == VerdictState.UNKNOWN for a in request.content.summary.acceptance)
    assert c.store.get_review_request(c.request.review_request_id) == c.request
    result = PromotionEligibilityService(c.store).assess(request.review_request_id)
    assert result.status == "NON_PROMOTABLE"
    assert set(result.reasons) == {
        PromotionReason.REVIEW_NOT_APPROVED,
        PromotionReason.ACCEPTANCE_NOT_PASS,
    }
    # A new comparison never supplies a human decision or Tool Approval.
    value = submission(c, ReviewDecision.APPROVE).model_copy(
        update={
            "review_request": result.review_request,
        }
    )
    c.boundary.now = utc_now()
    token = c.boundary.issue(review_context(request, value), (HumanRole.APPROVER,))
    with pytest.raises(HumanAuthorizationDenied):
        c.service.submit(value, credential=token)
    reopened = ImprovementReviewStore(reopen(c.store.database.path))
    assert PromotionEligibilityService(reopened).assess(request.review_request_id) == result
    assert reopened.get_review_request(c.request.review_request_id) == c.request
    assert reopened.get_review_record(old_record.review_record_id) == old_record
    replay = c.source.runner.evaluate(
        c.source.plan.plan_id,
        baseline_id=c.source.baseline.baseline_id,
        evaluator_version=CONTRACT_EVALUATOR_VERSION,
    )
    assert replay == artifacts
    assert c.store.get_review_record_for_request(request.review_request_id) is None
    assert (
        PromotionEligibilityService(c.store)
        .assess(c.request.review_request_id)
        .review_record.identity
        == old_record.review_record_id
    )


def test_tampered_new_safety_evidence_fails_closed(review_case):
    c = review_case
    artifacts = c.source.runner.evaluate(
        c.source.plan.plan_id,
        baseline_id=c.source.baseline.baseline_id,
        evaluator_version=CONTRACT_EVALUATOR_VERSION,
    )
    request = c.store.create_request(artifacts.comparison.comparison_id)
    result = artifacts.candidate_result
    evidence = result.content.strategy_safety.model_copy(update={"approvals_created": 1})
    content = result.content.model_copy(update={"strategy_safety": evidence})
    forged = result.model_copy(update={"content": content, "result_id": content_digest(content)})
    with c.store.database.transaction() as connection:
        connection.execute(
            "UPDATE offline_evaluation_results SET payload=?, digest=? WHERE id=?",
            (ledger.serialize(forged), content_digest(forged), result.result_id),
        )
    with pytest.raises(StoredDataError):
        PromotionEligibilityService(c.store).assess(request.review_request_id)

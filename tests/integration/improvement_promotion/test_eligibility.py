import pytest
from tests.integration.experience.test_storage import table_snapshot
from tests.integration.improvement_review.test_review import issue, submission
from tests.integration.offline_comparison.test_storage import reopen

from soc_agent.improvement_promotion import PromotionEligibilityService, PromotionReason
from soc_agent.improvement_review import ImprovementReviewStore, ReviewDecision
from soc_agent.review.persistence.models import StoredDataError


def test_measured_improvement_does_not_create_promotion_authority(review_case, monkeypatch):
    c = review_case
    before = table_snapshot(c.store.database)

    def forbidden(*args, **kwargs):
        raise AssertionError("Eligibility invoked production behavior")

    for obj, attribute in (
        (c.source.runtime, "advance"),
        (c.source.executor, "execute"),
        (c.source.llm, "generate_structured"),
    ):
        monkeypatch.setattr(obj, attribute, forbidden)
    service = PromotionEligibilityService(c.store)
    result = service.assess(c.request.review_request_id)
    assert any(m.outcome == "IMPROVED" for m in c.artifacts.comparison.content.metrics)
    assert result.status == "NON_PROMOTABLE"
    assert set(result.reasons) == {
        PromotionReason.REVIEW_NOT_APPROVED,
        PromotionReason.SAFETY_UNKNOWN,
        PromotionReason.ACCEPTANCE_NOT_PASS,
        PromotionReason.RUNTIME_CONTRACT_UNAVAILABLE,
    }
    assert result.candidate == c.request.content.binding.source.candidate
    assert result.comparison == c.request.content.comparison
    assert result.review_record is None
    assert service.assess(c.request.review_request_id) == result
    assert before == table_snapshot(c.store.database)


@pytest.mark.parametrize("decision", [ReviewDecision.REJECT, ReviewDecision.DEFER])
def test_terminal_review_remains_blocked_and_pinned_after_restart(review_case, decision):
    c = review_case
    value = submission(c, decision)
    record = c.service.submit(value, credential=issue(c, value))
    before = table_snapshot(c.store.database)
    result = PromotionEligibilityService(c.store).assess(c.request.review_request_id)
    restarted = ImprovementReviewStore(reopen(c.store.database.path))
    assert PromotionEligibilityService(restarted).assess(c.request.review_request_id) == result
    assert result.review_record.identity == record.review_record_id
    assert PromotionReason.REVIEW_NOT_APPROVED in result.reasons
    assert before == table_snapshot(c.store.database)


def test_source_and_confirmation_corruption_raise_integrity_errors(review_case):
    c = review_case
    value = submission(c)
    record = c.service.submit(value, credential=issue(c, value))
    service = PromotionEligibilityService(c.store)
    for table, column, identity in (
        ("improvement_candidates", "candidate_id", c.source.candidate.candidate_id),
        ("offline_comparisons", "id", c.artifacts.comparison.comparison_id),
        ("improvement_review_records", "id", record.review_record_id),
        ("human_confirmations", "confirmation_id", record.verification.confirmation_id),
    ):
        with c.store.database.transaction() as connection:
            digest = connection.execute(
                f"SELECT digest FROM {table} WHERE {column}=?", (identity,)
            ).fetchone()[0]
            connection.execute(
                f"UPDATE {table} SET digest=? WHERE {column}=?", ("0" * 64, identity)
            )
        try:
            with pytest.raises(StoredDataError):
                service.assess(c.request.review_request_id)
        finally:
            with c.store.database.transaction() as connection:
                connection.execute(
                    f"UPDATE {table} SET digest=? WHERE {column}=?", (digest, identity)
                )
    with pytest.raises(StoredDataError):
        service.assess("0" * 64)

from datetime import timedelta

import pytest
from tests.integration.experience.test_storage import table_snapshot
from tests.integration.offline_comparison.test_storage import reopen

from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.improvement_review import (
    BlockingReason,
    ImprovementReviewStore,
    ReasonCode,
    ReviewDecision,
    ReviewSubmission,
    review_context,
)
from soc_agent.review.authorization import HumanRole
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import StoredDataError


def submission(c, decision=ReviewDecision.DEFER):
    return ReviewSubmission(
        review_request=ArtifactReference(
            identity=c.request.review_request_id, digest=content_digest(c.request.content)
        ),
        decision=decision,
        reason={
            ReviewDecision.DEFER: ReasonCode.INSUFFICIENT_EVIDENCE,
            ReviewDecision.REJECT: ReasonCode.UNSUITABLE_PROPOSAL,
            ReviewDecision.APPROVE: ReasonCode.PROMOTION_CONSIDERATION,
        }[decision],
    )


def issue(c, value, roles=(HumanRole.APPROVER,)):
    return c.boundary.issue(review_context(c.request, value), roles)


def test_reviewable_summary_snapshot_and_idempotent_queries(review_case):
    c = review_case
    r = c.request.content
    assert r.reviewability == "REVIEWABLE" and not r.blocking_reasons
    assert BlockingReason.SAFETY_UNKNOWN in r.approval_blockers
    assert r.summary == c.artifacts.comparison.content
    assert r.binding == c.artifacts.variant.content.binding
    assert r.candidate_safety_counts == (8, 0, 2)
    assert "UNRESOLVED_SAFETY_EVIDENCE" in r.limitations
    assert c.store.create_request(c.artifacts.comparison.comparison_id) == c.request
    assert c.store.list_review_requests(r.binding.source.candidate.identity) == (c.request,)
    assert c.store.get_review_record_for_request(c.request.review_request_id) is None


@pytest.mark.parametrize("decision", [ReviewDecision.DEFER, ReviewDecision.REJECT])
def test_terminal_human_record_restart_and_no_authority(review_case, decision, monkeypatch):
    c = review_case
    before = table_snapshot(c.store.database)

    def forbidden(*args, **kwargs):
        raise AssertionError("Review invoked runtime")

    for obj, attr in [
        (c.source.runtime, "advance"),
        (c.source.executor, "execute"),
        (c.source.llm, "generate_structured"),
    ]:
        monkeypatch.setattr(obj, attr, forbidden)
    value = submission(c, decision)
    token = issue(c, value)
    record = c.service.submit(value, credential=token)
    assert record.submission == value and record.snapshot == c.request.content
    assert record.authority == "PROMOTION_CONSIDERATION_ONLY"
    assert c.service.submit(value, credential=token) == record
    store = ImprovementReviewStore(reopen(c.store.database.path))
    assert store.get_review_record(record.review_record_id) == record
    assert store.get_review_record_for_request(c.request.review_request_id) == record
    assert store.list_review_records(c.source.candidate.candidate_id) == (record,)
    other = submission(
        c, ReviewDecision.REJECT if decision == ReviewDecision.DEFER else ReviewDecision.DEFER
    )
    with pytest.raises(HumanAuthorizationDenied, match="terminal"):
        c.service.submit(other, credential=issue(c, other))
    after = table_snapshot(c.store.database)
    for table in before:
        if table not in {"human_confirmations", "improvement_review_records"}:
            assert before[table] == after[table]


def test_unknown_blocks_approve_without_consuming_confirmation(review_case):
    c = review_case
    value = submission(c, ReviewDecision.APPROVE)
    token = issue(c, value)
    before = table_snapshot(c.store.database)
    with pytest.raises(HumanAuthorizationDenied, match="APPROVE"):
        c.service.submit(value, credential=token)
    assert before == table_snapshot(c.store.database)


@pytest.mark.parametrize("roles", [(), (HumanRole.ANALYST,), (HumanRole.RESPONDER,)])
def test_separate_permission_and_unauthenticated_denied(review_case, roles):
    c = review_case
    value = submission(c)
    with pytest.raises(HumanAuthorizationDenied):
        c.service.submit(value, credential=issue(c, value, roles))
    with pytest.raises(HumanAuthorizationDenied):
        c.service.submit(value, credential="untrusted")


@pytest.mark.parametrize(
    "field", ["subject_id", "session_id", "action", "binding_digest", "expires_at"]
)
def test_confirmation_exact_identity_purpose_snapshot_expiry(review_case, field):
    from soc_agent.review.authority import HumanAction

    c = review_case
    value = submission(c)
    token = issue(c, value)
    receipt = c.boundary.provider.confirmations[token]
    wrong = {
        "subject_id": "someone-else",
        "session_id": "other-session",
        "action": HumanAction.RECORD_REVIEW,
        "binding_digest": "0" * 64,
        "expires_at": receipt.confirmed_at - timedelta(seconds=1),
    }[field]
    c.boundary.provider.confirmations[token] = receipt.model_copy(update={field: wrong})
    with pytest.raises(HumanAuthorizationDenied):
        c.service.submit(value, credential=token)
    assert c.store.get_review_record_for_request(c.request.review_request_id) is None


def test_forged_request_digest_and_source_corruption_fail_closed(review_case):
    c = review_case
    value = submission(c)
    forged = value.model_copy(
        update={
            "review_request": ArtifactReference(
                identity=c.request.review_request_id, digest="0" * 64
            )
        }
    )
    with pytest.raises(StoredDataError):
        c.service.submit(forged, credential="unused")
    with c.store.database.transaction() as connection:
        connection.execute(
            "UPDATE offline_comparisons SET digest=? WHERE id=?",
            ("0" * 64, c.artifacts.comparison.comparison_id),
        )
    with pytest.raises(StoredDataError):
        c.store.get_review_request(c.request.review_request_id)


def test_unavailable_evidence_is_normal_nonreviewable(planning_case):
    from soc_agent.improvement_review import migrate_improvement_review
    from soc_agent.offline_comparison import (
        OfflineComparisonStore,
        OfflineEvaluationRunner,
        migrate_frozen_baselines,
        migrate_offline_comparison,
    )

    c = planning_case
    migrate_offline_comparison(c.store.database)
    migrate_frozen_baselines(c.store.database)
    offline = OfflineComparisonStore(c.offline)
    plan = c.offline_planner.plan(c.candidate.candidate_id).test_plan
    result = OfflineEvaluationRunner(offline).evaluate(plan.plan_id)
    migrate_improvement_review(c.store.database)
    request = ImprovementReviewStore(offline).create_request(result.comparison.comparison_id)
    assert request.content.reviewability == "NOT_REVIEWABLE"
    assert set(request.content.blocking_reasons) == {
        BlockingReason.VARIANT_NOT_CONSTRUCTIBLE,
        BlockingReason.BASELINE_UNAVAILABLE,
        BlockingReason.NO_EXECUTED_COMPARISON,
        BlockingReason.NO_MEASURABLE_RESULT,
    }


def test_graph_corruption_never_becomes_normal_exclusion(review_case):
    c = review_case
    bindings = c.request.content
    for table, column, identity in (
        ("improvement_candidates", "candidate_id", bindings.binding.source.candidate.identity),
        ("improvement_datasets", "dataset_id", bindings.binding.source.dataset.dataset_id),
        ("frozen_offline_baselines", "baseline_id", bindings.binding.frozen_baseline.identity),
        ("offline_candidate_variants", "id", bindings.variant.identity),
        ("offline_evaluation_results", "id", bindings.baseline_result.identity),
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
                c.store.get_review_request(c.request.review_request_id)
        finally:
            with c.store.database.transaction() as connection:
                connection.execute(
                    f"UPDATE {table} SET digest=? WHERE {column}=?", (digest, identity)
                )


def test_new_candidate_and_comparison_do_not_rebind_old_review(review_case):
    from soc_agent.tools.enums import ToolPermission

    c = review_case
    value = submission(c)
    old_record = c.service.submit(value, credential=issue(c, value))
    new_candidate = c.source.candidates.declare_coverage_proposal(
        c.source.review.candidate_id,
        required_permission=ToolPermission.FILE_READ,
    )
    new_plan = c.source.offline_planner.plan(new_candidate.candidate_id).test_plan
    artifacts = c.source.runner.evaluate(
        new_plan.plan_id, baseline_id=c.source.baseline.baseline_id
    )
    new_request = c.store.create_request(artifacts.comparison.comparison_id)
    assert new_request.review_request_id != c.request.review_request_id
    assert new_request.content.binding.source.candidate.identity == new_candidate.candidate_id
    assert c.store.get_review_request(c.request.review_request_id) == c.request
    assert c.store.get_review_record(old_record.review_record_id) == old_record
    assert old_record.snapshot.comparison != new_request.content.comparison

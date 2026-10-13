"""Read-first learning history with explicit authority/version distinctions."""

import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from soc_agent.api.dashboard.self_improvement_query import project_self_improvement
from soc_agent.api.dashboard.self_improvement_render import render_self_improvement
from soc_agent.improvement_promotion import ImprovementPromotionStore, migrate_improvement_promotion
from soc_agent.improvement_promotion.eligibility import PromotionEligibilityService
from soc_agent.improvement_review import ReviewDecision
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.review.persistence.self_improvement import read_self_improvement
from soc_agent.state.evidence import utc_now
from soc_agent.tools.enums import ToolPermission as P
from tests.integration.api.test_dashboard import dump, fail, request
from tests.integration.improvement_promotion.conftest import (  # noqa: F401
    candidate_case,
    coverage_case,
    dataset_case,
    feedback_case,
    planning_case,
    review_case,
)
from tests.integration.improvement_promotion.test_activation import service, token
from tests.integration.improvement_promotion.test_path_adjudication import (
    evaluate,
    rebuild_and_plan,
    supply_human_facts,
)
from tests.integration.improvement_review.test_review import issue, submission

__all__ = [
    "candidate_case",
    "coverage_case",
    "dataset_case",
    "feedback_case",
    "planning_case",
    "review_case",
]

HTML = "/dashboard/self-improvement"
API = "/api/dashboard/self-improvement"


def read(c):
    return project_self_improvement(read_self_improvement(c.source.store, lambda _: True))


def approved(c, permission):
    _, plan = rebuild_and_plan(c.source, permission)
    artifacts = evaluate(c.source, plan, (P.NETWORK_READ,))
    request_value = c.store.create_request(artifacts.comparison.comparison_id)
    context = SimpleNamespace(request=request_value, boundary=c.boundary)
    value = submission(context, ReviewDecision.APPROVE)
    c.boundary.now = utc_now()
    c.service.submit(value, credential=issue(context, value))
    return request_value


@pytest.mark.asyncio
async def test_empty_unconfigured_storage_authentication_navigation(api_case):
    a = api_case()
    before = dump(a.c.store)
    for path in (HTML, API):
        assert (await request(a, path, token=False))[0] == 401
        assert (await request(a, path, method="POST"))[0] == 405
    status, headers, html = await request(a, HTML)
    assert status == 200 and headers[b"content-type"] == b"text/html; charset=utf-8"
    assert headers[b"cache-control"] == b"no-store" and b"content-security-policy" in headers
    assert "GOVERNED SELF-IMPROVEMENT" in html and "NOT AVAILABLE" in html
    assert "<form" not in html and "<script" not in html and "<pre" not in html
    status, _, body = await request(a, API)
    data = json.loads(body)
    assert status == 200 and data["experience_count"] is None
    assert data["candidate_count"] is None and data["active"]["state"] == "UNKNOWN"
    _, _, overview = await request(a)
    assert f'href="{HTML}"' in overview
    assert dump(a.c.store) == before
    a.access.denied = True
    assert (await request(a, HTML))[0] == 403


def test_historical_graph_unknown_metrics_and_domain_policy_match(review_case):
    c = review_case
    migrate_improvement_promotion(c.source.store.database)
    snapshot = read_self_improvement(c.source.store, lambda _: True)
    projected = project_self_improvement(snapshot)
    assert projected.experience_count > 0 and projected.candidate_count > 0
    assert projected.active.state == "NONE" and projected.active.pointer_revision == 0
    assert projected.rollback_target_count == 0
    assert projected.awaiting_review_count == 1
    sections = {s.name: s for s in projected.sections}
    for name in (
        "Historical Experience",
        "Outcome Evaluation",
        "Analyst Feedback",
        "Failure Analysis",
        "Improvement Candidates",
        "Dataset Snapshots",
    ):
        assert sections[name].records
    candidates = sections["Improvement Candidates"].records
    assert any("NOT SUPPORTED" in dict(r.facts)["Structured support"] for r in candidates)
    comparison = next(
        v for v in projected.comparisons if v.identity == c.artifacts.comparison.comparison_id
    )
    assert comparison.holdout_count > 0 and comparison.development_count > 0
    assert any("NOT_MEASURABLE" in row for row in comparison.metrics)
    assert any(row[2] == "UNKNOWN" for row in comparison.acceptance)
    eligibility = PromotionEligibilityService(c.store).assess(c.request.review_request_id)
    record = next(
        r
        for r in sections["Promotion Eligibility"].records
        if r.identity == c.request.review_request_id
    )
    assert record.title == eligibility.status
    assert dict(record.facts)["Reasons"] == ", ".join(eligibility.reasons)
    assert projected == project_self_improvement(snapshot)
    with pytest.raises(ValidationError):
        projected.candidate_count = 0
    html = render_self_improvement(projected)
    for text in (
        "NOT_MEASURABLE",
        "UNKNOWN",
        "HUMAN JUDGMENT",
        "NOT AUTHORITY",
        "DESCRIPTIVE FACTS",
        "PROMOTABLE ≠ PROMOTED",
        "ACTIVE VERSION",
        "NONE",
    ):
        assert text in html
    assert not projected.versions


def test_actual_approved_review_does_not_activate_and_projection_matches_domain(review_case):
    c = review_case
    migrate_improvement_promotion(c.source.store.database)
    supply_human_facts(c.source, "COMPLETE", ())
    request_value = approved(c, P.NETWORK_READ)
    projected = read(c)
    assert projected.active.state == "NONE" and not projected.versions
    eligibility = PromotionEligibilityService(c.store).assess(request_value.review_request_id)
    assert eligibility.status == "PROMOTABLE"
    section = next(s for s in projected.sections if s.name == "Promotion Eligibility")
    assert (
        next(r for r in section.records if r.identity == request_value.review_request_id).title
        == "PROMOTABLE"
    )
    reviews = next(s for s in projected.sections if s.name == "Human Improvement Review")
    assert any(r.title == "APPROVE" for r in reviews.records)
    assert "APPROVE permits promotion consideration only" in render_self_improvement(projected)


def test_promotion_and_rollback_history_runtime_not_inferred(review_case):
    c = review_case
    migrate_improvement_promotion(c.source.store.database)
    supply_human_facts(c.source, "COMPLETE", ())
    store = ImprovementPromotionStore(c.store)
    operation = service(store, c.boundary)
    records = []
    for permission in (P.NETWORK_READ, P.SYSTEM_READ):
        rr = approved(c, permission)
        req = store.create_promotion_request(rr.review_request_id)
        records.append(operation.promote(req, credential=token(c.boundary, req)))
    projected = read(c)
    assert [v.version for v in projected.versions] == [1, 2]
    assert [v.active for v in projected.versions] == [False, True]
    assert projected.active.artifact.artifact_id == records[-1].current.active_artifact.identity
    assert projected.active.runtime_consumption == "UNKNOWN"
    assert projected.active.pointer_revision == 2 and projected.rollback_target_count == 1
    req = store.create_rollback_request(records[0].current.active_artifact.identity)
    rolled = operation.rollback(req, credential=token(c.boundary, req))
    projected = read(c)
    assert [v.version for v in projected.versions] == [1, 2]
    assert projected.active.artifact.version == 1 and projected.active.pointer_revision == 3
    assert projected.active.activation_record == rolled.record_id
    assert projected.versions[0].rollback_to == (rolled.record_id,)
    assert projected.versions[1].rollback_from == (rolled.record_id,)
    assert all(v.promotion_records for v in projected.versions)
    assert projected.active.artifact.permissions == (P.NETWORK_READ.value,)
    hidden = project_self_improvement(read_self_improvement(c.source.store, lambda _: False))
    assert hidden.active.state == "UNKNOWN" and not hidden.versions
    assert hidden.rollback_target_count is None
    assert records[0].current.active_artifact.identity not in hidden.model_dump_json()
    assert "REGISTERED" in render_self_improvement(projected)
    assert "Rollback to initial NONE is not supported" in render_self_improvement(projected)


@pytest.mark.asyncio
async def test_get_never_computes_consumes_or_mutates(review_case, api_case, monkeypatch):
    import soc_agent.improvement_candidates.analysis as analysis
    from soc_agent.improvement_candidates.service import ImprovementCandidateService
    from soc_agent.improvement_dataset.service import ImprovementDatasetBuilder
    from soc_agent.improvement_promotion import ImprovementActivationService
    from soc_agent.offline_comparison import OfflineEvaluationRunner
    from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer

    c = review_case
    migrate_improvement_promotion(c.source.store.database)
    a = api_case()
    a.service.store = c.source.store
    before = dump(c.source.store)
    monkeypatch.setattr(a.service, "runtime_factory", fail)
    monkeypatch.setattr(c.source.llm, "generate_structured", fail)
    monkeypatch.setattr(analysis, "analyze", fail)
    monkeypatch.setattr(ImprovementCandidateService, "propose", fail)
    monkeypatch.setattr(ImprovementDatasetBuilder, "build", fail)
    monkeypatch.setattr(OfflineEvaluationRunner, "evaluate", fail)
    monkeypatch.setattr(ImprovementActivationService, "promote", fail)
    monkeypatch.setattr(ImprovementActivationService, "rollback", fail)
    monkeypatch.setattr(SQLiteConfirmationConsumer, "consume", fail)
    original, opened = c.source.store.database._connect, []

    def connect():
        connection = original()
        opened.append(connection)
        return connection

    monkeypatch.setattr(c.source.store.database, "_connect", connect)
    assert (await request(a, HTML))[0] == 200
    assert len(opened) == 1
    assert (await request(a, API))[0] == 200
    assert dump(c.source.store) == before


def test_access_filter_hides_cross_incident_learning_graph(review_case):
    c = review_case
    migrate_improvement_promotion(c.source.store.database)
    projected = project_self_improvement(read_self_improvement(c.source.store, lambda _: False))
    assert (
        projected.experience_count
        == projected.candidate_count
        == projected.awaiting_review_count
        == 0
    )
    assert not projected.comparisons and not projected.versions
    assert str(c.source.incident_id) not in projected.model_dump_json()


def test_untrusted_prose_is_escaped_without_verification_payload(review_case):
    c = review_case
    migrate_improvement_promotion(c.source.store.database)
    projected = read(c)
    attack = '<img src=x onerror="attack()">'
    sections = list(projected.sections)
    for index, section in enumerate(sections):
        if section.records:
            row = section.records[0].model_copy(
                update={"title": attack, "facts": (("Note", attack),)}
            )
            sections[index] = section.model_copy(update={"records": (row,)})
    html = render_self_improvement(projected.model_copy(update={"sections": tuple(sections)}))
    assert attack not in html and "&lt;img" in html and "&quot;attack()&quot;" in html
    data = projected.model_dump_json()
    assert '"verification"' not in data and '"confirmation_id"' not in data
    assert '"raw_data"' not in data and '"tool_input"' not in data


def test_corrupt_learning_content_fails_closed(review_case):
    c = review_case
    with c.source.store.database.transaction() as connection:
        connection.execute("UPDATE improvement_candidates SET digest=?", ("0" * 64,))
    with pytest.raises(StoredDataError):
        read(c)


def test_legacy_unexecuted_comparison_preserves_safety_unknown(planning_case):
    from tests.integration.offline_comparison.test_storage import setup

    c = setup(planning_case)
    c.runner.evaluate(c.plan.plan_id)
    projected = project_self_improvement(read_self_improvement(c.store, lambda _: True))
    assert projected.comparisons
    assert all(row[3] == "NOT_MEASURABLE" for row in projected.comparisons[0].metrics)
    assert any("UNKNOWN" in row[1:] for row in projected.comparisons[0].safety)
    assert all(row[2] == "UNKNOWN" for row in projected.comparisons[0].acceptance)
    sections = {s.name: s for s in projected.sections}
    assert any(
        dict(r.facts)["construction_status"] == "VARIANT_NOT_CONSTRUCTIBLE"
        for r in sections["Offline Candidate Variants"].records
    )
    assert any(
        dict(r.facts)["execution_status"] == "NOT_EXECUTED"
        for r in sections["Offline Evaluation Results"].records
    )
    html = render_self_improvement(projected)
    assert "NOT_MEASURABLE" in html and "UNKNOWN" in html
    assert projected.active.state == "UNKNOWN"  # No registry schema, not invented NONE/v0.

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from soc_agent.evaluation import EvaluationStore
from soc_agent.experience import ExperienceStore
from soc_agent.feedback import DiagnosticLabel as Label
from soc_agent.feedback import FeedbackRequest, FeedbackStore, Verdict
from soc_agent.review.authority import HumanAction
from soc_agent.review.authorization import HumanRole
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.models import StoredDataError
from tests.integration.experience.test_storage import table_snapshot

from .conftest import issue


@pytest.mark.parametrize(
    "verdict,labels",
    [
        (Verdict.CORRECT, ()),
        (Verdict.INCORRECT, ()),
        (Verdict.INCONCLUSIVE, ()),
        *[(Verdict.INCORRECT, (label,)) for label in Label],
        (Verdict.INCORRECT, (Label.FALSE_POSITIVE, Label.UNNECESSARY_INVESTIGATION)),
    ],
)
def test_judgment_roundtrip(feedback_case, verdict, labels):
    c = feedback_case
    request = c.request.model_copy(update={"verdict": verdict, "labels": labels})
    credential = issue(c, request)
    result = c.feedback.submit(request, credential=credential)
    assert result.request.verdict == verdict and result.request.labels == labels
    assert result.request.scope == "overall"
    assert result.request.experience_digest == c.request.experience_digest
    assert result.request.evaluation_digest == c.request.evaluation_digest
    assert result.verification.subject_id == "alice"
    assert result.verification.context.binding_digest == request.digest
    assert c.feedback.submit(request, credential=credential) == result
    reopened = FeedbackStore(
        EvaluationStore(ExperienceStore(SQLiteGovernanceStore(c.store.database.path)))
    )
    assert reopened.get(result.feedback_id) == result
    assert reopened.list_for_evaluation(request.evaluation_id) == (result,)
    assert reopened.list_for_experience(request.experience_id) == (result,)
    assert reopened.list_for_incident(c.incident_id) == (result,)
    with pytest.raises(ValidationError):
        result.request.verdict = Verdict.INCONCLUSIVE


@pytest.mark.parametrize(
    "update",
    [
        {"labels": (Label.FALSE_POSITIVE, Label.FALSE_NEGATIVE), "verdict": Verdict.INCORRECT},
        {"labels": (Label.FALSE_POSITIVE,)},
        {"labels": (Label.MISSED_INVESTIGATION,), "verdict": Verdict.INCONCLUSIVE},
        {"labels": (Label.FALSE_NEGATIVE, Label.FALSE_NEGATIVE), "verdict": Verdict.INCORRECT},
        {"note": "x" * 1001},
        {"note": "bad\x00note"},
        {"note": "token=do-not-store"},
        {"scope": "response"},
        {"analyst": "admin"},
        {"role": "ADMIN"},
    ],
)
def test_semantics_and_untrusted_fields(feedback_case, update):
    c = feedback_case
    with pytest.raises(ValidationError):
        FeedbackRequest.model_validate({**c.request.model_dump(), **update})


def test_identity_permission_and_provider_failure(feedback_case):
    c = feedback_case
    for credential in ("alice", "admin", "", {"trusted": True}):
        with pytest.raises(HumanAuthorizationDenied):
            c.feedback.submit(c.request, credential=credential)
    for roles in ((), (HumanRole.RESPONDER,), (HumanRole.APPROVER,), ("unknown",)):
        with pytest.raises(HumanAuthorizationDenied):
            c.feedback.submit(c.request, credential=issue(c, roles=roles))
    credential = issue(c)
    c.boundary.provider.failure = RuntimeError("provider unavailable")
    with pytest.raises(RuntimeError):
        c.feedback.submit(c.request, credential=credential)
    assert c.feedback_store.list_for_incident(c.incident_id) == ()


@pytest.mark.parametrize(
    "field,value",
    [
        ("subject_id", "other"),
        ("provider_id", "other"),
        ("session_id", "other"),
        ("action", HumanAction.APPROVE_PROMOTED_TOOL),
        ("binding_digest", "0" * 64),
        ("expires_at", None),
    ],
)
def test_confirmation_exact_binding(feedback_case, field, value):
    c = feedback_case
    credential = issue(c)
    confirmation = c.boundary.provider.confirmations[credential]
    value = c.boundary.now - timedelta(seconds=1) if field == "expires_at" else value
    c.boundary.provider.confirmations[credential] = confirmation.model_copy(update={field: value})
    with pytest.raises(HumanAuthorizationDenied):
        c.feedback.submit(c.request, credential=credential)
    assert c.feedback_store.list_for_incident(c.incident_id) == ()


@pytest.mark.parametrize(
    "field,value",
    [
        ("incident_id", None),
        ("experience_id", "0" * 64),
        ("evaluation_id", "0" * 64),
        ("experience_digest", "0" * 64),
        ("evaluation_digest", "0" * 64),
    ],
)
def test_forged_source(feedback_case, field, value):
    c = feedback_case
    request = c.request.model_copy(update={field: uuid4() if value is None else value})
    with pytest.raises(StoredDataError):
        c.feedback.submit(request, credential=issue(c, request))


@pytest.mark.parametrize("table", ["experiences", "evaluations"])
def test_corrupted_source(feedback_case, table):
    c = feedback_case
    with c.store.database.transaction() as connection:
        connection.execute(f"UPDATE {table} SET digest=?", ("0" * 64,))
    with pytest.raises(StoredDataError):
        c.feedback.submit(c.request, credential=issue(c))


def test_disagreement_conflicting_retry_and_durable_replay(feedback_case):
    c = feedback_case
    credential = issue(c)
    first = c.feedback.submit(c.request, credential=credential)
    other = c.request.model_copy(update={"verdict": Verdict.INCORRECT})
    second = c.feedback.submit(other, credential=issue(c, other, subject="bob"))
    assert {
        f.request.verdict for f in c.feedback_store.list_for_evaluation(c.evaluation.evaluation_id)
    } == {Verdict.CORRECT, Verdict.INCORRECT}
    assert first.feedback_id != second.feedback_id
    with pytest.raises(StoredDataError):
        c.feedback.submit(other, credential=credential)
    # Another session cannot read an authenticated idempotent retry via submission.
    with pytest.raises(StoredDataError):
        c.feedback.submit(c.request, credential=issue(c))
    # Same consumed confirmation cannot submit a different exact judgment.
    changed = c.request.model_copy(update={"submission_id": uuid4()})
    c.boundary.provider.used.clear()
    with pytest.raises(HumanAuthorizationDenied):
        c.feedback.submit(changed, credential=credential)
    # New explicitly confirmed judgment from the same analyst is independent.
    third = c.feedback.submit(changed, credential=issue(c, changed))
    assert third.feedback_id not in {first.feedback_id, second.feedback_id}


def test_capture_has_no_authority(feedback_case, monkeypatch):
    c = feedback_case
    before = table_snapshot(c.store.database)

    def forbidden(*args, **kwargs):
        raise AssertionError("Feedback invoked authority")

    monkeypatch.setattr(c.executor, "execute", forbidden)
    monkeypatch.setattr(c.runtime, "advance", forbidden)
    monkeypatch.setattr(c.evaluator, "evaluate", forbidden)
    result = c.feedback.submit(c.request, credential=issue(c))
    after = table_snapshot(c.store.database)
    allowed = {"analyst_feedback", "feedback_audit", "human_confirmations"}
    assert all(after[name] == rows for name, rows in before.items() if name not in allowed)
    assert c.mocks["inspect_logs"].call_count == 0
    assert "credential" not in result.model_dump_json()
    assert not {"approval", "authorization", "consensus", "accuracy"}.intersection(
        type(result).model_fields
    )


def test_durable_receipt_cannot_be_rebound_after_restart(feedback_case):
    from soc_agent.feedback import AnalystFeedbackService
    from soc_agent.review.authorization import RBACPermissionVerifier

    c = feedback_case
    credential = issue(c)
    c.feedback.submit(c.request, credential=credential)
    changed = c.request.model_copy(update={"submission_id": uuid4(), "note": "Additional review"})
    # Even a provider reusing a consumed public confirmation ID cannot rebind it.
    old = c.boundary.provider.confirmations[credential]
    c.boundary.provider.confirmations[credential] = old.model_copy(
        update={"binding_digest": changed.digest}
    )
    c.boundary.provider.used.clear()
    reopened = FeedbackStore(
        EvaluationStore(ExperienceStore(SQLiteGovernanceStore(c.store.database.path)))
    )
    service = AnalystFeedbackService(
        reopened,
        provider=c.boundary.provider,
        provider_id="test-identity",
        permissions=RBACPermissionVerifier(roles=c.boundary.roles),
    )
    with pytest.raises(HumanAuthorizationDenied):
        service.submit(changed, credential=credential)
    assert len(reopened.list_for_incident(c.incident_id)) == 1


@pytest.mark.parametrize("table", ["analyst_feedback", "feedback_audit", "human_confirmations"])
def test_query_detects_receipt_or_feedback_corruption(feedback_case, table):
    c = feedback_case
    result = c.feedback.submit(c.request, credential=issue(c))
    with c.store.database.transaction() as connection:
        connection.execute(f"UPDATE {table} SET digest=?", ("0" * 64,))
    with pytest.raises(StoredDataError):
        c.feedback_store.get(result.feedback_id)


def test_null_decision_context_for_domains_without_incident_decision(feedback_case):
    from soc_agent.review.authentication import HumanActionContext

    data = dict(
        incident_id=feedback_case.incident_id,
        binding_digest=feedback_case.request.digest,
        decision_id=None,
    )
    without_incident_decision = {
        HumanAction.PROMOTE_IMPROVEMENT_ARTIFACT,
        HumanAction.ROLLBACK_IMPROVEMENT_ARTIFACT,
        HumanAction.SUBMIT_ANALYST_FEEDBACK,
        HumanAction.REVIEW_IMPROVEMENT_CANDIDATE,
    }
    for action in HumanAction:
        if action in without_incident_decision:
            assert HumanActionContext(action=action, **data).decision_id is None
        else:
            with pytest.raises(ValidationError):
                HumanActionContext(action=action, **data)

import json

import pytest

from soc_agent.evaluation.models import EvaluationRecord
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import StoredDataError
from tests.integration.experience.test_capture import capture_service, finish
from tests.unit.investigation_runtime.conftest import decision_ready, promoted_ready

from .test_evaluation import evaluator


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["experience", "snapshot", "trace", "review", "execution"])
async def test_changed_referenced_records_fail_closed(runtime_case, target):
    case = runtime_case(durable_workflow=True)
    await promoted_ready(case)
    await finish(case)
    experience = capture_service(case).capture(case.incident_id)
    service = evaluator(case)
    service.evaluate(experience.experience_id)
    with case.store.database.transaction() as connection:
        if target == "experience":
            connection.execute("UPDATE experiences SET digest=?", ("0" * 64,))
        elif target == "snapshot":
            connection.execute("UPDATE snapshots SET fingerprint=?", ("0" * 64,))
        elif target == "trace":
            connection.execute("UPDATE workflow_trace SET digest=?", ("0" * 64,))
        elif target == "review":
            connection.execute("UPDATE reviews SET digest=?", ("0" * 64,))
        else:
            connection.execute("UPDATE execution_events SET digest=?", ("0" * 64,))
    with pytest.raises((StoredDataError, ValueError)):
        service.evaluate(
            experience.experience_id
        )  # Existing evaluation does not bypass validation.


@pytest.mark.asyncio
async def test_conflicting_evaluation_rejected(runtime_case):
    case = runtime_case(durable_workflow=True)
    await decision_ready(case)
    experience = capture_service(case).capture(case.incident_id)
    service = evaluator(case)
    value = service.evaluate(experience.experience_id)
    # Validly hashed but different facts for the SAME Experience/version must not be accepted.
    content = value.content.model_copy(update={"analysis_observed": False})
    conflicting = EvaluationRecord(evaluation_id=content_digest(content), content=content)
    with case.store.database.transaction() as connection:
        connection.execute(
            "UPDATE evaluations SET evaluation_id=?,payload=?,digest=?",
            (
                conflicting.evaluation_id,
                ledger.serialize(conflicting),
                content_digest(conflicting),
            ),
        )
    with pytest.raises(StoredDataError, match="Conflicting"):
        service.evaluate(experience.experience_id)


@pytest.mark.asyncio
async def test_forged_reference_with_recomputed_experience_hash_rejected(runtime_case):
    from soc_agent.experience.models import Experience

    case = runtime_case(durable_workflow=True)
    await decision_ready(case)
    experience = capture_service(case).capture(case.incident_id)
    service = evaluator(case)
    refs = tuple(
        ref.model_copy(update={"digest": "0" * 64}) for ref in experience.content.references
    )
    content = experience.content.model_copy(update={"references": refs})
    forged = Experience(experience_id=content_digest(content), content=content)
    with case.store.database.transaction() as connection:
        connection.execute(
            "UPDATE experiences SET experience_id=?,payload=?,digest=?",
            (
                forged.experience_id,
                ledger.serialize(forged),
                content_digest(forged),
            ),
        )
    with pytest.raises(StoredDataError, match="reference"):
        service.evaluate(forged.experience_id)


@pytest.mark.asyncio
async def test_no_mutation_no_authority_no_execution(runtime_case, monkeypatch):
    from soc_agent.approval import ApprovalManager
    from soc_agent.execution import GovernedExecutor
    from soc_agent.execution.durable.service import DurableExecutor
    from soc_agent.response.promotion.service import PromotionService
    from soc_agent.review.service import HumanReviewService
    from tests.integration.experience.test_storage import table_snapshot

    case = runtime_case(durable_workflow=True)
    await promoted_ready(case)
    await finish(case)
    experience = capture_service(case).capture(case.incident_id)
    service = evaluator(case)
    before = table_snapshot(case.store.database)

    def forbidden(*args, **kwargs):
        raise AssertionError("Evaluator attempted a governance/execution mutation")

    for owner, methods in (
        (ApprovalManager, ("create", "approve")),
        (HumanReviewService, ("record_review", "authorize_change", "apply")),
        (PromotionService, ("record_review", "promote")),
        (GovernedExecutor, ("execute",)),
        (DurableExecutor, ("execute", "execute_claim")),
    ):
        for method in methods:
            monkeypatch.setattr(owner, method, forbidden)
    value = service.evaluate(experience.experience_id)
    after = table_snapshot(case.store.database)
    assert all(after[key] == rows for key, rows in before.items() if key != "evaluations")
    assert service.store.experiences.get(experience.experience_id) == experience
    payload = json.loads(value.model_dump_json())
    assert "host_a" not in str(payload) and "reviewer-alice" not in str(payload)
    assert case.mocks["inspect_logs"].call_count == 1

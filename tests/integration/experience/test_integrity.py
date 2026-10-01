import json
from uuid import uuid4

import pytest

from soc_agent.experience.models import Experience
from soc_agent.investigation.runtime.persistence.models import WorkflowInFlight
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.state import Evidence, Severity
from soc_agent.state.evidence import utc_now
from tests.unit.investigation_runtime.conftest import decision_ready, promoted_ready

from .test_capture import capture_service, finish


@pytest.mark.asyncio
async def test_stale_snapshot_and_inflight_rejected(runtime_case):
    case = runtime_case(durable_workflow=True)
    await decision_ready(case)
    service = capture_service(case)
    checkpoint, _ = service.checkpoints.load(case.incident_id)
    service.checkpoints.claim(checkpoint)
    with pytest.raises(WorkflowInFlight):
        service.capture(case.incident_id)
    with case.store.database.transaction() as connection:
        connection.execute("UPDATE workflow_checkpoints SET claim=NULL")
    case.store.append_evidence(
        case.store.load(case.incident_id).anchor,
        Evidence(
            incident_id=case.incident_id,
            source="test",
            summary="new evidence",
            raw_data="{}",
            observed_at=utc_now(),
        ),
    )
    with pytest.raises(StoredDataError, match="Stale"):
        service.capture(case.incident_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["checkpoint", "review", "decision", "execution", "digest"])
async def test_corrupted_or_foreign_sources_rejected(runtime_case, mutation):
    case = runtime_case(durable_workflow=True)
    await promoted_ready(case)
    await finish(case)
    service = capture_service(case)
    with case.store.database.transaction() as connection:
        row = connection.execute("SELECT * FROM workflow_checkpoints").fetchone()
        payload = json.loads(row["payload"])
        if mutation == "checkpoint":
            payload["incident_id"] = str(uuid4())
        elif mutation == "review":
            payload["review_id"] = str(uuid4())
        elif mutation == "decision":
            payload["artifacts"]["decision"]["incident_id"] = str(uuid4())
        elif mutation == "execution":
            payload["artifacts"]["execution_intent_id"] = "0" * 64
        else:
            payload["artifacts"]["snapshot"]["fingerprint"] = "0" * 64
        connection.execute("UPDATE workflow_checkpoints SET payload=?", (json.dumps(payload),))
    with pytest.raises((StoredDataError, ValueError)):
        service.capture(case.incident_id)
    assert service.store.list_for_incident(case.incident_id) == ()


@pytest.mark.asyncio
async def test_foreign_registered_review_with_valid_checkpoint_digest_rejected(runtime_case):
    case, foreign = runtime_case(durable_workflow=True), runtime_case(durable_workflow=True)
    # Register another incident and review in the SAME authoritative store.
    await decision_ready(case)
    service = capture_service(case)
    checkpoint, trace = service.checkpoints.load(case.incident_id)
    from soc_agent.investigation.runtime.models import ArtifactReference
    from soc_agent.investigation.runtime.trace import OrchestrationTraceEntry

    await decision_ready(foreign)
    foreign_state = foreign.store.load(foreign.incident_id).state
    case.store.register(foreign_state)
    from tests.review_support import record_review

    request = case.reviews.request_review(
        foreign_state,
        foreign.runtime.artifacts(foreign.incident_id).decision,
    )
    foreign_review = record_review(case.reviews, case.authority, request)
    review_id = foreign_review.review_id
    result = checkpoint.result.model_copy(
        update={
            "references": checkpoint.result.references
            + (ArtifactReference(kind="incident_review", identity=str(review_id)),),
        }
    )
    altered = checkpoint.model_copy(update={"review_id": review_id, "result": result})
    content = trace.entries[-1].content.model_copy(update={"result": result})
    entry = OrchestrationTraceEntry(entry_id=content_digest(content), content=content)
    with case.store.database.transaction() as connection:
        connection.execute(
            "UPDATE workflow_checkpoints SET payload=?,digest=?",
            (
                ledger.serialize(altered),
                content_digest(altered),
            ),
        )
        connection.execute(
            "UPDATE workflow_trace SET payload=?,digest=?,entry_id=? WHERE sequence=?",
            (ledger.serialize(entry), content_digest(entry), entry.entry_id, content.sequence),
        )
    with pytest.raises(StoredDataError, match="review"):
        service.capture(case.incident_id)


@pytest.mark.asyncio
async def test_conflicting_identity_rejected(runtime_case):
    case = runtime_case(durable_workflow=True)
    await decision_ready(case)
    service = capture_service(case)
    value = service.capture(case.incident_id)
    # Simulate conflicting content stored under an existing key, with its row digest recomputed.
    changed = value.model_copy(
        update={"content": value.content.model_copy(update={"severity": Severity.HIGH})}
    )
    with case.store.database.transaction() as connection:
        connection.execute(
            "UPDATE experiences SET payload=?,digest=?",
            (
                ledger.serialize(changed),
                content_digest(changed),
            ),
        )
    with pytest.raises(StoredDataError):
        service.capture(case.incident_id)
    with pytest.raises(ValueError):
        Experience.model_validate_json(ledger.serialize(changed))

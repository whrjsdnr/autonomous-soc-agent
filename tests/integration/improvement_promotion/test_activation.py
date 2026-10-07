"""Executed/adjudicated source -> independent human review -> governed runtime versions."""

import asyncio
import multiprocessing
from types import SimpleNamespace

import pytest
from tests.integration.experience.test_storage import table_snapshot
from tests.integration.improvement_promotion.test_path_adjudication import (
    evaluate,
    rebuild_and_plan,
    supply_human_facts,
)
from tests.integration.improvement_review.test_review import issue, submission
from tests.integration.offline_comparison.test_storage import reopen
from tests.unit.planning.conftest import mock_tool, registry, response
from tests.unit.planning.test_strategy import add_tool

from soc_agent.improvement_promotion import (
    ImprovementActivationService,
    ImprovementPromotionStore,
    NoChange,
    RegistryBackedInvestigationStrategyProvider,
    StaleActivation,
    action_context,
    migrate_improvement_promotion,
)
from soc_agent.improvement_review import ImprovementReviewStore, ReviewDecision
from soc_agent.llm import MockLLMClient
from soc_agent.planning import InvestigationPlanner
from soc_agent.planning.strategy import StrategyCoverageError
from soc_agent.review.authorization import HumanRole, RBACPermissionVerifier
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.persistence.models import CommitOutcomeUnknown, StorageError, StoredDataError
from soc_agent.state import IncidentState
from soc_agent.state.evidence import utc_now
from soc_agent.tools.enums import ToolPermission as P

__all__ = ["registry", "mock_tool", "response"]


def service(store, boundary):
    return ImprovementActivationService(
        store,
        provider=boundary.provider,
        provider_id="test-identity",
        permissions=RBACPermissionVerifier(roles=boundary.roles),
    )


def token(boundary, request, roles=(HumanRole.ADMIN,)):
    boundary.now = utc_now()
    return boundary.issue(action_context(request), roles)


def worker(path, boundary, request, credential, start, output):
    try:
        store = ImprovementPromotionStore(ImprovementReviewStore(reopen(path)))
        store.database.timeout = 60
        start.wait(20)
        operation = service(store, boundary)
        record = (
            operation.promote(request, credential=credential)
            if request.__class__.__name__ == "PromotionRequest"
            else operation.rollback(request, credential=credential)
        )
        output.put(("committed", record.request.identity))
    except StaleActivation:
        output.put(("stale", request.request_id))
    except Exception as error:
        output.put(("error", type(error).__name__ + ":" + str(error)))


def race(store, boundary, requests):
    ctx = multiprocessing.get_context("fork")
    start, output = ctx.Event(), ctx.Queue()
    credentials = [token(boundary, r) for r in requests]
    processes = [
        ctx.Process(target=worker, args=(store.database.path, boundary, r, t, start, output))
        for r, t in zip(requests, credentials, strict=True)
    ]
    for p in processes:
        p.start()
    start.set()
    outcomes = [output.get(timeout=120) for _ in processes]
    for p in processes:
        p.join(120)
        assert p.exitcode == 0
    assert sorted(o[0] for o in outcomes) == ["committed", "stale"], outcomes
    return next(identity for state, identity in outcomes if state == "committed")


def test_governed_activation_runtime_rollback_atomicity_restart_and_process_cas(
    review_case, registry, mock_tool, response, monkeypatch
):
    c, source = review_case, review_case.source
    # Old UNKNOWN graph remains non-promotable; no approval or activation is fabricated.
    migrate_improvement_promotion(c.store.database)
    store = ImprovementPromotionStore(c.store)
    assert store.get_active_artifact() is None
    with pytest.raises(HumanAuthorizationDenied):
        store.create_promotion_request(c.request.review_request_id)
    before = table_snapshot(store.database)
    supply_human_facts(source, "COMPLETE", ())
    reviews = []
    for permission in (P.NETWORK_READ, P.SYSTEM_READ, P.FILE_READ):
        _, plan = rebuild_and_plan(source, permission)
        artifacts = evaluate(source, plan, (P.NETWORK_READ,))
        request = c.store.create_request(artifacts.comparison.comparison_id)
        context = SimpleNamespace(request=request, boundary=c.boundary)
        value = submission(context, ReviewDecision.APPROVE)
        c.boundary.now = utc_now()
        c.service.submit(value, credential=issue(context, value))
        reviews.append(request)
    assert store.get_active_artifact() is None  # APPROVE/PROMOTABLE alone do not activate.
    provider = RegistryBackedInvestigationStrategyProvider(store)
    state = IncidentState()
    state_before = state.model_dump()
    assert provider.get_strategy(state) is None
    requests = [store.create_promotion_request(r.review_request_id) for r in reviews]
    assert all(r.content.expected.revision == 0 for r in requests)
    assert store.create_promotion_request(reviews[0].review_request_id) == requests[0]
    operation = service(store, c.boundary)
    for obj, attr in (
        (source.executor, "execute"),
        (source.runtime, "advance"),
        (source.llm, "generate_structured"),
    ):
        monkeypatch.setattr(
            obj, attr, lambda *a, **k: pytest.fail("Activation reached production action")
        )
    # Authentication and separate RBAC fail without consuming any confirmation.
    for credential in ("", token(c.boundary, requests[0], (HumanRole.APPROVER,))):
        with pytest.raises(HumanAuthorizationDenied):
            operation.promote(requests[0], credential=credential)
    # Exact identity/session/purpose/digest/expiry are checked by reused authority.
    for field, value in (
        ("subject_id", "other"),
        ("session_id", "other"),
        ("action", "improvement_review_decision"),
        ("binding_digest", "0" * 64),
        ("expires_at", utc_now()),
    ):
        credential = token(c.boundary, requests[0])
        confirmation = c.boundary.provider.confirmations[credential]
        c.boundary.provider.confirmations[credential] = confirmation.model_copy(
            update={field: value}
        )
        with pytest.raises(HumanAuthorizationDenied):
            operation.promote(requests[0], credential=credential)
    # Source corruption between request and commit fails closed, before consumption.
    with store.database.transaction() as conn:
        saved = conn.execute(
            "SELECT digest FROM improvement_review_records WHERE id=?",
            (requests[0].content.source_snapshot.review_record.identity,),
        ).fetchone()[0]
        conn.execute(
            "UPDATE improvement_review_records SET digest=? WHERE id=?",
            ("0" * 64, requests[0].content.source_snapshot.review_record.identity),
        )
    with pytest.raises(StoredDataError):
        operation.promote(requests[0], credential=token(c.boundary, requests[0]))
    with store.database.transaction() as conn:
        conn.execute(
            "UPDATE improvement_review_records SET digest=? WHERE id=?",
            (saved, requests[0].content.source_snapshot.review_record.identity),
        )
    # Insert failure after consume and CAS must roll back receipts, artifact and pointer.
    with store.database.transaction() as conn:
        conn.execute(
            "CREATE TRIGGER reject_activation BEFORE INSERT ON improvement_promotion_records "
            "BEGIN SELECT RAISE(ABORT,'injected failure'); END"
        )
    snapshot = table_snapshot(store.database)
    with pytest.raises(StorageError):
        operation.promote(requests[0], credential=token(c.boundary, requests[0]))
    assert table_snapshot(store.database) == snapshot
    with store.database.transaction() as conn:
        conn.execute("DROP TRIGGER reject_activation")
    # Two independent processes with the same expected NONE pointer: one commit.
    winner = race(store, c.boundary, requests[:2])
    first = store.get_active_artifact()
    assert first.content.version == 1 and store.get_active_pointer().revision == 1
    assert not hasattr(store, "set_active") and not hasattr(store, "activate")
    with pytest.raises(StaleActivation):
        operation.promote(requests[2], credential=token(c.boundary, requests[2]))
    losing_review = reviews[1] if winner == requests[0].request_id else reviews[0]
    second_request = store.create_promotion_request(losing_review.review_request_id)
    credential = token(c.boundary, second_request)
    second_record = operation.promote(second_request, credential=credential)
    assert operation.promote(second_request, credential=credential) == second_record
    second = store.get_active_artifact()
    assert second.content.version == 2 and second_record.previous.active_version == 1
    with pytest.raises(NoChange):
        store.create_promotion_request(losing_review.review_request_id)
    # Real production planner uses the injected registry-backed provider and existing validation.
    add_tool(registry, mock_tool, "network_capability", P.NETWORK_READ)
    add_tool(registry, mock_tool, "system_capability", P.SYSTEM_READ)
    full = response | {
        "steps": [
            response["steps"][0] | {"tool_name": name}
            for name in ("network_capability", "system_capability")
        ]
    }
    narrow = response | {"steps": [response["steps"][0] | {"tool_name": "network_capability"}]}

    def planner(payload):
        return InvestigationPlanner(
            llm_client=MockLLMClient([payload]), registry=registry, strategy_provider=provider
        )

    assert asyncio.run(planner(full).create_plan(state))
    if second.content.payload.required_permissions == (P.SYSTEM_READ,):
        with pytest.raises(StrategyCoverageError):
            asyncio.run(planner(narrow).create_plan(state))
    else:
        assert asyncio.run(planner(narrow).create_plan(state))
    # Promotion vs rollback race, same expected revision.
    third_request = store.create_promotion_request(reviews[2].review_request_id)
    rollback = store.create_rollback_request(first.artifact_id)
    race(store, c.boundary, (third_request, rollback))
    active = store.get_active_artifact()
    if active.artifact_id == first.artifact_id:
        third_request = store.create_promotion_request(reviews[2].review_request_id)
        operation.promote(third_request, credential=token(c.boundary, third_request))
    assert len(store.list_artifacts()) == 3
    artifacts = store.list_artifacts()
    # rollback vs rollback with two distinct existing targets and one expected revision.
    current = store.get_active_artifact()
    targets = [a for a in artifacts if a.artifact_id != current.artifact_id]
    rollbacks = [store.create_rollback_request(a.artifact_id) for a in targets]
    race(store, c.boundary, rollbacks)
    assert [a.content.version for a in store.list_artifacts()] == [1, 2, 3]
    # Explicitly restore NETWORK coverage, proving post-rollback runtime semantics.
    network = next(
        a for a in artifacts if a.content.payload.required_permissions == (P.NETWORK_READ,)
    )
    if store.get_active_artifact().artifact_id == network.artifact_id:
        target = next(a for a in artifacts if a.artifact_id != network.artifact_id)
        r = store.create_rollback_request(target.artifact_id)
        operation.rollback(r, credential=token(c.boundary, r))
    system = next(
        a for a in artifacts if a.content.payload.required_permissions == (P.SYSTEM_READ,)
    )
    if store.get_active_artifact().artifact_id != system.artifact_id:
        restore_system = store.create_rollback_request(system.artifact_id)
        operation.rollback(restore_system, credential=token(c.boundary, restore_system))
    with pytest.raises(StrategyCoverageError):
        asyncio.run(planner(narrow).create_plan(state))
    r = store.create_rollback_request(network.artifact_id)
    # Promotion purpose cannot authorize rollback.
    credential = token(c.boundary, r)
    confirmation = c.boundary.provider.confirmations[credential]
    c.boundary.provider.confirmations[credential] = confirmation.model_copy(
        update={"action": "improvement_artifact_promotion"}
    )
    with pytest.raises(HumanAuthorizationDenied):
        operation.rollback(r, credential=credential)
    credential = token(c.boundary, r)
    record = operation.rollback(r, credential=credential)
    assert operation.rollback(r, credential=credential) == record
    assert asyncio.run(planner(narrow).create_plan(state))
    restarted = ImprovementPromotionStore(ImprovementReviewStore(reopen(store.database.path)))
    assert restarted.get_active_pointer() == store.get_active_pointer()
    assert (
        RegistryBackedInvestigationStrategyProvider(restarted).get_strategy(state)
        == network.content.payload
    )
    assert restarted.get_rollback_record(record.record_id) == record
    assert service(restarted, c.boundary).rollback(r, credential=credential) == record
    # Unknown commit outcome is reported, even if SQL actually committed.
    target = next(a for a in artifacts if a.artifact_id != network.artifact_id)
    uncertain = store.create_rollback_request(target.artifact_id)

    def commit_then_fail(conn):
        changed = conn.total_changes > 0
        conn.commit()
        if changed:
            raise OSError("injected uncertain acknowledgement")

    uncertain_credential = token(c.boundary, uncertain)
    with monkeypatch.context() as patch:
        patch.setattr(store.database, "_commit", commit_then_fail)
        with pytest.raises(CommitOutcomeUnknown):
            operation.rollback(uncertain, credential=uncertain_credential)
    assert store.get_active_artifact().artifact_id == target.artifact_id
    recovered = operation.rollback(uncertain, credential=uncertain_credential)
    assert recovered.request.identity == uncertain.request_id
    # Corrupted active payload cannot silently fall back.
    current = store.get_active_artifact()
    with store.database.transaction() as conn:
        conn.execute(
            "UPDATE improvement_artifacts SET digest=? WHERE id=?", ("0" * 64, current.artifact_id)
        )
    with pytest.raises(StoredDataError):
        provider.get_strategy(state)
    # No history deletion or protected incident changes, despite activation/rollback.
    assert state.model_dump() == state_before and mock_tool.call_count == 0
    after = table_snapshot(store.database)
    for table in ("incidents", "snapshots", "approvals", "applications", "authorizations"):
        if table in before:
            assert before[table] == after[table]

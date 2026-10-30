"""Real core runtime/claims/audit; explicit scripted proposals, no Native or API."""

import asyncio
import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from soc_agent.continuous.investigation import (
    ScriptedCoordinationClient,
    advance_task,
    application,
    consume,
)
from soc_agent.continuous.investigation_models import InvestigationSource
from soc_agent.continuous.investigation_store import InvestigationTasks
from soc_agent.investigation.runtime.persistence.models import WorkflowInFlight
from soc_agent.security_ai.research.models import digest
from tests.unit.continuous.test_runtime import make


def source(role="NETWORK", **changes):
    data = dict(
        incident_id=uuid4(),
        role=role,
        origin="FIXTURE",
        namespace="net:[4026532232]",
        scope="a" * 64,
        reference=digest(str(uuid4())),
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        target=digest("192.0.2.1"),
        clock="fixture-epoch",
        event_ns=1_000_000_000,
        advisory=dict(classification="UNKNOWN_ANOMALY", agreement_state="consistent"),
    )
    return InvestigationSource.model_validate(data | changes)


class Recorded(ScriptedCoordinationClient):
    def __init__(self):
        self.calls = []

    async def generate_structured(self, *, request, response_model):
        self.calls.append((request, response_model.__name__))
        return await super().generate_structured(request=request, response_model=response_model)


async def drained(tasks, client=None):
    stop, progress = asyncio.Event(), {}
    running = asyncio.create_task(consume(tasks, stop, progress, client=client))
    try:
        for _ in range(400):
            if tasks.queue.counts().get("DONE", 0) == len(tasks.tasks()):
                return progress
            if running.done():
                await running
            await asyncio.sleep(0.01)
        raise AssertionError((progress, tasks.snapshot()))
    finally:
        stop.set()
        await asyncio.wait_for(running, 5)


@pytest.mark.asyncio
async def test_correlated_sources_keep_incident_identity_and_investigate_once(tmp_path):
    _, store = make(tmp_path)
    tasks = InvestigationTasks(store)
    network, dns = source(), source("DNS")
    first = tasks.submit(network)
    latest = tasks.submit(dns)
    assert first.incident_id == latest.incident_id == network.incident_id
    assert set(latest.related_incidents) == {network.incident_id, dns.incident_id}
    assert tasks.submit(dns) == latest
    assert len(tasks.tasks()) == 2
    client = Recorded()
    await drained(tasks, client)
    rows = tasks.snapshot()["tasks"]
    assert {r["state"] for r in rows} == {"SUPERSEDED", "WAITING_HUMAN"}
    assert len(client.calls) == 5  # Initial advice/plan, assessment, follow-up advice/replan.
    assert sum(name == "ReplanningDraft" for _, name in client.calls) == 1
    service = application(tasks, latest, client)
    checkpoint = service.checkpoint(latest.incident_id)
    assert checkpoint.artifacts.investigation.steps[0].status.value == "completed"
    assert len(service.store.load(latest.incident_id).state.evidence) == 3
    assert service.trace(latest.incident_id).entries
    assert checkpoint.artifacts.execution_intent_id is None
    assert not service.store.load(latest.incident_id).state.observations
    before = len(client.calls)
    await drained(InvestigationTasks(store), client)
    assert len(client.calls) == before


@pytest.mark.parametrize(
    "change",
    [
        dict(target=digest("192.0.2.2")),
        dict(event_ns=61_000_000_000),
        dict(origin="REAL_NATIVE"),
        dict(namespace="net:[1234]"),
        dict(clock="other"),
        dict(scope="b" * 64),
        dict(target=None),
        dict(clock="UNKNOWN"),
    ],
)
def test_unproven_target_time_scope_never_correlates(tmp_path, change):
    _, store = make(tmp_path)
    tasks = InvestigationTasks(store)
    first = tasks.submit(source())
    second = tasks.submit(source("DNS", **change))
    assert first.group != second.group
    assert first.incident_id != second.incident_id


@pytest.mark.asyncio
async def test_conflict_routes_existing_adaptive_planner_without_model_authority(tmp_path):
    _, store = make(tmp_path)
    tasks = InvestigationTasks(store)
    task = tasks.submit(source(advisory=dict(agreement_state="conflicting")))
    client = Recorded()
    await drained(tasks, client)
    assert any(name == "ReplanningDraft" for _, name in client.calls)
    assert not any(name == "SecurityAISelectionDraft" for _, name in client.calls)
    assert tasks.snapshot()["tasks"][0]["decisions"]
    assert (
        application(tasks, task, client).checkpoint(task.incident_id).artifacts.execution_intent_id
        is None
    )


@pytest.mark.asyncio
async def test_evidence_arriving_during_plan_preserves_old_revision_and_runs_new(tmp_path):
    _, store = make(tmp_path)
    tasks = InvestigationTasks(store)
    first = tasks.submit(source())
    entered, release = asyncio.Event(), asyncio.Event()

    class Delayed(Recorded):
        async def generate_structured(self, *, request, response_model):
            if not entered.is_set():
                entered.set()
                await release.wait()
            return await super().generate_structured(request=request, response_model=response_model)

    client = Delayed()
    stop, progress = asyncio.Event(), {}
    running = asyncio.create_task(consume(tasks, stop, progress, client=client))
    await asyncio.wait_for(entered.wait(), 5)
    latest = tasks.submit(source("AUTHENTICATION"))
    assert latest.incident_id == first.incident_id and latest.revision != first.revision
    release.set()
    try:
        for _ in range(500):
            if tasks.queue.counts().get("DONE") == 2:
                break
            await asyncio.sleep(0.01)
        assert tasks.queue.counts()["DONE"] == 2
        assert {r["state"] for r in tasks.snapshot()["tasks"]} == {"SUPERSEDED", "WAITING_HUMAN"}
        assert (
            application(tasks, first, client).checkpoint(first.incident_id).revision
            < application(tasks, latest, client).checkpoint(latest.incident_id).revision
        )
    finally:
        stop.set()
        await asyncio.wait_for(running, 5)


@pytest.mark.asyncio
async def test_interrupted_core_claim_is_never_stolen_or_replayed(tmp_path):
    _, store = make(tmp_path)
    tasks = InvestigationTasks(store)
    task = tasks.submit(source())
    service = application(tasks, task, Recorded())
    service.start(task.incident_id)
    saved = service.checkpoint(task.incident_id)
    service.checkpoints.claim(saved)
    with pytest.raises(WorkflowInFlight):
        await advance_task(tasks, task, Recorded(), {})
    client = Recorded()
    await drained(tasks, client)
    assert tasks.snapshot()["tasks"][0]["state"] == "BLOCKED"
    assert not client.calls


@pytest.mark.asyncio
async def test_failed_llm_is_audited_and_does_not_repeat(tmp_path):
    _, store = make(tmp_path)
    tasks = InvestigationTasks(store)
    tasks.submit(source())

    class Failed(Recorded):
        async def generate_structured(self, **kwargs):
            self.calls.append("failed")
            raise TimeoutError("fixture timeout")

    client = Failed()
    await drained(tasks, client)
    assert len(client.calls) == 1
    assert tasks.snapshot()["tasks"][0]["state"] == "FAILED"
    await drained(InvestigationTasks(store), client)
    assert len(client.calls) == 1


def test_fair_priority_claim_and_stale_ack(tmp_path):
    _, store = make(tmp_path, queue_capacity=32)
    tasks = InvestigationTasks(store)
    normal = tasks.submit(source(advisory=dict(classification="NORMAL")))
    for i in range(20):
        tasks.submit(source(target=digest(str(i)), advisory=dict(agreement_state="conflicting")))
    claimed = []
    while claim := tasks.claim():
        task = tasks.task(claim)
        claimed.append(task.task_id)
        tasks.queue.finish(claim, dict(workflow="COMPLETED"))
        finished = claim
    assert claimed.index(normal.task_id) <= 8
    with pytest.raises(ValueError, match="Stale worker"):
        tasks.queue.finish(finished, dict(workflow="COMPLETED"))


def test_source_sha_tampering_is_blocked(tmp_path):
    _, store = make(tmp_path)
    tasks = InvestigationTasks(store)
    row = source()
    tasks.submit(row)
    path = tasks.directory / "sources" / (row.pin + ".json")
    value = json.loads(path.read_text())
    value["advisory"] = {}
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="SOURCE_SHA"):
        tasks.snapshot()

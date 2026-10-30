"""Failure boundaries and restoration of real core checkpoints; no Live authority."""

import asyncio
import json

import pytest

from soc_agent.api.models import StepRequest
from soc_agent.continuous.investigation import application, consume
from soc_agent.continuous.investigation_store import InvestigationTasks
from soc_agent.realtime.queue import QueueFull
from tests.integration.test_continuous_orchestration import Recorded, drained, source
from tests.unit.continuous.test_runtime import make


@pytest.mark.asyncio
async def test_saved_plan_resumes_without_replanning_or_duplicate_tools(tmp_path):
    _, store = make(tmp_path)
    tasks, client = InvestigationTasks(store), Recorded()
    task = tasks.submit(source())
    service = application(tasks, task, client)
    current = service.start(task.incident_id)
    for _ in range(2):
        current = await service.step(
            task.incident_id,
            StepRequest(
                run_id=current.workflow_id,
                expected_revision=current.checkpoint_revision,
            ),
        )
    assert len(client.calls) == 2
    assert current.next_step.value == "route"
    await drained(InvestigationTasks(store), client)
    restored = application(tasks, task, client)
    assert len(client.calls) == 5
    assert len(restored.store.load(task.incident_id).state.evidence) == 2
    assert restored.checkpoint(task.incident_id).result.waiting_for_human


@pytest.mark.asyncio
async def test_cancel_during_llm_keeps_claim_and_blocks_replay(tmp_path):
    _, store = make(tmp_path)
    tasks = InvestigationTasks(store)
    tasks.submit(source())
    entered = asyncio.Event()

    class Blocked(Recorded):
        async def generate_structured(self, **kwargs):
            self.calls.append("waiting")
            entered.set()
            await asyncio.Event().wait()

    progress, client = {}, Blocked()
    running = asyncio.create_task(consume(tasks, asyncio.Event(), progress, client=client))
    await asyncio.wait_for(entered.wait(), 5)
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    assert tasks.queue.counts() == {"CLAIMED": 1}
    replacement = Recorded()
    await drained(InvestigationTasks(store), replacement)
    assert not replacement.calls
    assert tasks.snapshot()["tasks"][0]["state"] == "BLOCKED"


@pytest.mark.asyncio
async def test_queue_backpressure_retains_source_and_recovers_without_loss(tmp_path):
    _, store = make(tmp_path, queue_capacity=1)
    tasks = InvestigationTasks(store)
    tasks.submit(source())
    with pytest.raises(QueueFull):
        tasks.submit(source(target="b" * 64))
    assert len(tasks.sources()) == 2
    await drained(tasks)
    assert tasks.queue.counts() == {"DONE": 2}


def test_task_metadata_tampering_fails_before_claim(tmp_path):
    _, store = make(tmp_path)
    tasks = InvestigationTasks(store)
    task = tasks.submit(source())
    path = tasks.directory / "tasks" / (str(task.task_id) + ".json")
    value = json.loads(path.read_text())
    value["priority"] = 2
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="CONTENT_SHA"):
        tasks.claim()
    assert tasks.queue.counts() == {"PENDING": 1}


def test_partial_source_publication_cannot_be_claimed(tmp_path, monkeypatch):
    from soc_agent.continuous import investigation_store

    _, store = make(tmp_path)
    tasks = InvestigationTasks(store)

    def fail(*_):
        raise OSError("injected partial publication")

    monkeypatch.setattr(investigation_store.os, "link", fail)
    with pytest.raises(OSError):
        tasks.submit(source())
    assert tasks.sources() == []
    assert tasks.tasks() == []
    assert tasks.queue.counts() == {}


@pytest.mark.asyncio
async def test_gui_reads_task_revision_and_detaches_without_stopping_backend(tmp_path):
    from soc_agent.gui.backend import Backend, GUIConfig
    from soc_agent.gui.continuous_projection import project

    directory, store = make(tmp_path)
    tasks = InvestigationTasks(store)
    task = tasks.submit(source())
    await drained(tasks)
    snapshot = tasks.snapshot() | dict(worker=dict(state="IDLE", provider="SCRIPTED"))
    store.update(
        dict(state="RUNNING", cleanup="PENDING", source="JSONL_REPLAY", orchestration=snapshot)
    )
    backend = Backend(GUIConfig(data_directory=tmp_path / "gui", continuous_directory=directory))
    rows = await backend.investigations()
    assert rows[0]["task_id"] == str(task.task_id)
    assert rows[0]["evidence_revision"] == task.revision
    assert rows[0]["assessment_mode"] == "SCRIPTED"
    assert rows[0]["status"] == "WAITING_HUMAN"
    assert rows[0]["decisions"]
    assert rows[0]["investigation"]["assessment"]["threat_assessment"]
    assert rows[0]["investigation"]["plan"]["steps"][0]["status"] == "completed"
    assert project(dict(continuous=store.state()))["orchestration"] == snapshot
    await backend.close()
    assert store.state()["state"] == "RUNNING"


@pytest.mark.asyncio
async def test_archive_contains_task_queue_sources_and_core_checkpoints(tmp_path):
    from pathlib import Path

    from soc_agent.continuous.retention import archive, restore
    from soc_agent.continuous.store import Store

    directory, store = make(tmp_path)
    (directory / "code-identity").write_text("a" * 64)
    tasks, client = InvestigationTasks(store), Recorded()
    task = tasks.submit(source())
    await drained(tasks, client)
    store.update(dict(state="STOPPED", cleanup="VERIFIED"))
    saved = Path(archive(directory)["path"])
    target = tmp_path / "restored"
    restore(saved, target)
    cloned = InvestigationTasks(Store(target))
    assert cloned.queue.counts() == {"DONE": 1}
    assert cloned.sources() == tasks.sources()
    assert application(cloned, task, client).checkpoint(task.incident_id) == application(
        tasks, task, client
    ).checkpoint(task.incident_id)
    calls = len(client.calls)
    await drained(cloned, client)
    assert len(client.calls) == calls


def test_published_source_without_audit_is_repaired_before_task_claim(tmp_path, monkeypatch):
    _, store = make(tmp_path)
    tasks = InvestigationTasks(store)
    item = source()
    real = store.event_once

    def fail(*_):
        raise OSError("fixture disk full")

    with monkeypatch.context() as patch:
        patch.setattr(store, "event_once", fail)
        with pytest.raises(OSError):
            tasks.submit(item)
    assert tasks.sources() == [item] and tasks.queue.counts() == {}
    tasks.recover()
    assert not real("CONTINUOUS_INVESTIGATION_SOURCE", item.model_dump(mode="json"))
    assert tasks.task(tasks.claim()).sources == (item.pin,)


def test_archive_rejects_pending_investigation_even_if_collector_stopped(tmp_path):
    from soc_agent.continuous.retention import archive

    directory, store = make(tmp_path)
    InvestigationTasks(store).submit(source())
    store.update(dict(state="STOPPED", cleanup="VERIFIED"))
    with pytest.raises(ValueError, match="QUIESCENCE"):
        archive(directory)


@pytest.mark.asyncio
async def test_known_tool_failure_uses_bounded_existing_replanner(tmp_path, monkeypatch):
    from dataclasses import replace

    from soc_agent.tools import Tool

    _, store = make(tmp_path)
    tasks, client = InvestigationTasks(store), Recorded()
    task = tasks.submit(source(advisory=dict(classification="COLLECTOR_ERROR")))
    real = Tool.execute
    calls = []

    async def failed_read(query):
        calls.append(query)
        raise TimeoutError("scripted retained-read timeout")

    async def fail(self, raw_input):
        if self.metadata.name == "read_local_source_report":
            return await real(replace(self, handler=failed_read), raw_input)
        return await real(self, raw_input)

    monkeypatch.setattr(Tool, "execute", fail)
    await drained(tasks, client)
    assert len(calls) == 1
    assert any(name == "ReplanningDraft" for _, name in client.calls)
    assert tasks.snapshot()["tasks"][0]["state"] == "WAITING_HUMAN"
    checkpoint = application(tasks, task, client).checkpoint(task.incident_id)
    assert checkpoint.artifacts.execution_intent_id is None


@pytest.mark.asyncio
async def test_waiting_planner_does_not_block_collector_delivery(tmp_path, monkeypatch):
    from uuid import uuid4

    from soc_agent.continuous.investigation import ScriptedCoordinationClient
    from soc_agent.continuous.service import ContinuousRuntime

    directory, store = make(tmp_path)
    InvestigationTasks(store).submit(source())
    entered, release = asyncio.Event(), asyncio.Event()
    real = ScriptedCoordinationClient.generate_structured

    async def delayed(self, **kwargs):
        entered.set()
        await release.wait()
        return await real(self, **kwargs)

    class RetainedSource:
        closed = False

        async def events(self):
            for sequence in range(1, 21):
                yield dict(
                    sequence=sequence, id=str(uuid4()), kind="excluded", affects_integrity=False
                )
                await asyncio.sleep(0.01)

        async def close(self):
            self.closed = True

    monkeypatch.setattr(ScriptedCoordinationClient, "generate_structured", delayed)
    retained = RetainedSource()
    runtime = ContinuousRuntime(directory, source=retained)
    running = asyncio.create_task(runtime.run())
    try:
        await asyncio.wait_for(entered.wait(), 5)
        for _ in range(150):
            if runtime.metrics["excluded"] == 20:
                break
            await asyncio.sleep(0.02)
        assert runtime.metrics["excluded"] == 20
        assert not release.is_set()
    finally:
        release.set()
        runtime.stop.set()
        await asyncio.wait_for(running, 15)
    assert retained.closed and store.state()["cleanup"] == "VERIFIED"

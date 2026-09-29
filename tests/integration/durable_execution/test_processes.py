"""Independent spawned interpreters and real process death; fixture tools only."""

import asyncio
import multiprocessing
import os
import time

import pytest
from tests.unit.execution.conftest import SampleInput, SampleOutput
from tests.unit.promotion.conftest import promoted

from soc_agent.execution.durable import DurableExecutor, ExecutionStore, Lifecycle
from soc_agent.execution.durable.errors import ClaimConflict
from soc_agent.policy import PolicyEngine
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.tools import Tool, ToolRegistry


def worker(path, identity, barrier, output, marker, mode):
    store = ExecutionStore(SQLiteGovernanceStore(path))
    record = store.load(identity)
    registry = ToolRegistry()

    async def handler(value):
        with open(marker, "a") as stream:
            stream.write("effect\n")
            stream.flush()
            os.fsync(stream.fileno())
        if mode == "tool_failure":
            raise RuntimeError("test failure after possible effect")
        return {"result": "ok"}

    registry.register(
        Tool(
            metadata=record.intent.promoted.content.request.target.proposal.details.metadata,
            input_model=SampleInput,
            output_model=SampleOutput,
            handler=handler,
        )
    )
    if mode in ("boundary", "side_effect", "tool_failure"):
        original = store.transition

        def transition(expected, state, **kwargs):
            if mode in ("side_effect", "tool_failure") and state in (
                Lifecycle.SUCCEEDED,
                Lifecycle.UNCERTAIN,
            ):
                os._exit(73)
            result = original(expected, state, **kwargs)
            if mode == "boundary" and state == Lifecycle.EXECUTING:
                os._exit(73)
            return result

        store.transition = transition
    if barrier:
        barrier.wait(timeout=30)
    if mode == "intent":
        os._exit(73)
    if mode == "claim":
        store.claim(identity, claimant=str(os.getpid()), lease_seconds=1)
        os._exit(73)
    try:
        if mode == "claim_race":
            store.claim(identity, claimant=str(os.getpid()))
        else:
            executor = DurableExecutor(store=store, registry=registry, policy=PolicyEngine())
            asyncio.run(executor.execute(identity, claimant=str(os.getpid()), lease_seconds=1))
        outcome = "success"
    except ClaimConflict:
        outcome = "conflict"
    output.put((os.getpid(), outcome))


@pytest.mark.parametrize("mode", ["claim_race", "execute_race"])
def test_two_process_same_intent(durable, tmp_path, mode):
    store, record, _, _ = durable
    ctx = multiprocessing.get_context("spawn")
    barrier, output = ctx.Barrier(2), ctx.Queue()
    marker = tmp_path / "effects"
    children = [
        ctx.Process(
            target=worker,
            args=(
                store.database.path,
                record.intent.execution_intent_id,
                barrier,
                output,
                marker,
                mode,
            ),
        )
        for _ in range(2)
    ]
    for child in children:
        child.start()
    results = [output.get(timeout=60) for _ in children]
    for child in children:
        child.join(30)
        assert child.exitcode == 0
    assert len({p for p, _ in results}) == 2
    assert sorted(r for _, r in results) == ["conflict", "success"]
    events = store.events(record.intent.execution_intent_id)
    assert sum(e.event_type == "claimed" for e in events) == 1
    if mode == "execute_race":
        assert marker.read_text().splitlines() == ["effect"]
        assert sum(e.event_type == "invocation_boundary" for e in events) == 1
        assert store.load(record.intent.execution_intent_id).state == Lifecycle.SUCCEEDED


@pytest.mark.parametrize("point", ["intent", "claim", "boundary", "side_effect", "tool_failure"])
def test_process_crash_recovery(durable, tmp_path, point):
    store, record, _, _ = durable
    ctx = multiprocessing.get_context("spawn")
    marker = tmp_path / "effects"
    output = ctx.Queue()
    child = ctx.Process(
        target=worker,
        args=(
            store.database.path,
            record.intent.execution_intent_id,
            None,
            output,
            marker,
            point,
        ),
    )
    child.start()
    child.join(30)
    assert child.exitcode == 73
    time.sleep(1.1)
    reopened = ExecutionStore(SQLiteGovernanceStore(store.database.path))
    reopened.recover()
    result = reopened.load(record.intent.execution_intent_id)
    if point in ("intent", "claim"):
        assert result.state == Lifecycle.PENDING
        assert not marker.exists()
    else:
        assert result.state == Lifecycle.UNCERTAIN
        assert marker.exists() == (point in ("side_effect", "tool_failure"))
        with pytest.raises(ClaimConflict):
            reopened.claim(record.intent.execution_intent_id, claimant="restarted")


def test_independent_intents_execute(durable, tmp_path):
    store, record, _, workflow = durable
    second = store.create(workflow[5], promoted(workflow, "inspect_logs"))
    ctx = multiprocessing.get_context("spawn")
    barrier, output = ctx.Barrier(2), ctx.Queue()
    children = [
        ctx.Process(
            target=worker,
            args=(
                store.database.path,
                r.intent.execution_intent_id,
                barrier,
                output,
                tmp_path / f"effect-{i}",
                "execute",
            ),
        )
        for i, r in enumerate((record, second))
    ]
    for child in children:
        child.start()
    results = [output.get(timeout=60) for _ in children]
    for child in children:
        child.join(30)
        assert child.exitcode == 0
    assert [r for _, r in results] == ["success", "success"]


def test_restart_execution_rejects_approval_replay(durable, tmp_path):
    store, record, _, _ = durable
    ctx = multiprocessing.get_context("spawn")
    marker = tmp_path / "effects"
    for expected in ("success", "conflict"):
        output = ctx.Queue()
        child = ctx.Process(
            target=worker,
            args=(
                store.database.path,
                record.intent.execution_intent_id,
                None,
                output,
                marker,
                "execute",
            ),
        )
        child.start()
        assert output.get(timeout=60)[1] == expected
        child.join(30)
        assert child.exitcode == 0
    assert marker.read_text().splitlines() == ["effect"]

"""Ordinary service faults only. No Root, Kernel, traffic or external API."""

import asyncio

import pytest
from tests.unit.continuous.test_runtime import make

from soc_agent.continuous.cli import status
from soc_agent.continuous.service import ContinuousRuntime


def test_stale_native_status_never_claims_current_capture(tmp_path):
    directory, store = make(tmp_path)
    stored = dict(
        state="RUNNING",
        source="NATIVE_SERVICE",
        collector="RUNNING",
        worker="ANALYZING",
        collection_live=True,
        heartbeat_unix=0,
        collector_cleanup="UNKNOWN",
    )
    store.update(stored)
    shown = status(directory)
    assert shown["state"] == "UNKNOWN_STALE_HEARTBEAT"
    assert not shown["collection_live"]
    assert shown["collector"] == shown["worker"] == "UNKNOWN_STALE_HEARTBEAT"
    assert shown["last_observed_collector"] == "RUNNING"
    assert shown["collector_cleanup"] == "UNKNOWN"
    assert store.state()["collection_live"] is True  # projection never rewrites evidence


@pytest.mark.parametrize("stale", [False, True])
def test_start_refuses_unverified_cleanup_before_spawning(tmp_path, monkeypatch, stale):
    from soc_agent.continuous.cli import code_identity, start

    directory, store = make(tmp_path)
    (directory / "code-identity").write_text(code_identity())
    store.update(
        dict(
            state="RUNNING" if stale else "DEGRADED",
            heartbeat_unix=0,
            cleanup="PENDING_SERVICE_STOP" if stale else "UNVERIFIED",
        )
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("Unreviewed restart")

    monkeypatch.setattr("soc_agent.continuous.cli.subprocess.Popen", forbidden)
    with pytest.raises(ValueError, match="UNVERIFIED_CLEANUP_REVIEW_REQUIRED"):
        start(directory)


@pytest.mark.asyncio
async def test_collector_task_cleanup_error_cannot_be_hidden_by_second_close(tmp_path):
    directory, store = make(tmp_path)

    class Source:
        def __init__(self):
            self.entered = asyncio.Event()
            self.closed = 0

        async def events(self):
            self.entered.set()
            await asyncio.Event().wait()
            if False:
                yield None

        async def close(self):
            self.closed += 1
            if self.closed == 1:
                raise RuntimeError("OWNED_COLLECTOR_CLEANUP_UNVERIFIED")

    source = Source()
    runtime = ContinuousRuntime(directory, source=source)
    task = asyncio.create_task(runtime.run())
    await asyncio.wait_for(source.entered.wait(), 3)
    store.control(stop=True)
    with pytest.raises(RuntimeError, match="COLLECTOR_CLEANUP_UNVERIFIED"):
        await asyncio.wait_for(task, 5)
    state = store.state()
    assert source.closed == 2
    assert state["cleanup"] == "UNVERIFIED" and state["state"] == "DEGRADED"
    assert "OWNED_COLLECTOR_CLEANUP_UNVERIFIED" in state["last_error"]
    assert not state["collection_live"]


@pytest.mark.asyncio
async def test_health_during_owned_worker_wait_is_not_model_progress(tmp_path):
    from tests.unit.continuous.test_runtime import FailedAnalysis

    from soc_agent.security_ai.workflow_models import CollectorFailureJob

    class SlowAnalysis(FailedAnalysis):
        def __init__(self):
            self.entered = asyncio.Event()
            self.release = asyncio.Event()

        async def start(self, path):
            self.monitor = asyncio.create_task(self.release.wait())
            self.entered.set()

    directory, store = make(tmp_path)
    analysis = SlowAnalysis()
    runtime = ContinuousRuntime(directory, analysis=analysis)
    await runtime.handoff(CollectorFailureJob(kind="collector_error", code="FIXTURE"))
    task = asyncio.create_task(runtime.consume())
    try:
        await asyncio.wait_for(analysis.entered.wait(), 3)
        first = runtime.snapshot()["component_health"]["worker_observed_unix"]
        await asyncio.sleep(0.25)
        health = runtime.snapshot()["component_health"]
        assert health["worker_observed_unix"] > first
        assert health["worker_heartbeat_scope"] == "SUPERVISOR_OBSERVATION_NOT_MODEL_PROGRESS"
        assert health["automatic_kernel_restart"] is False
        assert runtime.metrics["predictions"] == 0
    finally:
        analysis.release.set()
        runtime.stop.set()
        await asyncio.wait_for(task, 3)
        await runtime.analysis.close()

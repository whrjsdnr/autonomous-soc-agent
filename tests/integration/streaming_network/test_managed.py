"""Actual isolated RF/LR on explicit synthetic streaming flows; no native collection."""

import asyncio

import pytest
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import idle_source

from soc_agent.security_ai.operational.network_capture.stream_session import StreamPolicy
from soc_agent.security_ai.research.stream_service import StreamingMonitoring


@pytest.mark.asyncio
async def test_actual_two_model_stream_fixture_and_metadata_retention(tmp_path):
    owner = StreamingMonitoring(tmp_path, paths=research_paths())
    await owner.start_fixture(idle_source(owner), policy=StreamPolicy(seconds=120))
    await asyncio.wait_for(owner.task, 45)
    snapshot = owner.snapshot()
    assert snapshot["state"] == "STOPPED", snapshot
    records = snapshot["research"]["records"]
    assert len(records) == 2, snapshot
    assert all(
        r["status"] == "COMPLETE" and r["receipt"]["origin"] == "FIXTURE" for r in records
    ), records
    assert all(r["investigation"]["status"] == "ASSESSED_READ_ONLY" for r in records)
    assert owner.eligible == 1 and owner.excluded == 1
    assert owner.store.queue.counts() == {"DONE": 1}
    assert not list((owner.directory / "inputs").glob("*"))
    assert not list(owner.demo.directory.glob("worker-*"))
    attempts = list(owner.demo.directory.glob("attempt-*.json"))
    assert len(attempts) == 2
    assert all(
        "source_address" not in p.read_text() and '"packets"' not in p.read_text() for p in attempts
    )
    assert owner.aggregator.bytes == 0 and not owner.aggregator.packets
    assert snapshot["operational_gate"] == "OPERATIONAL_INFERENCE_BLOCKED"
    assert not snapshot["collection_live"]


@pytest.mark.asyncio
async def test_fixture_restart_restores_receipts_without_new_inference(tmp_path):
    owner = StreamingMonitoring(tmp_path, paths=research_paths())
    await owner.start_fixture(idle_source(owner), policy=StreamPolicy(seconds=120))
    await asyncio.wait_for(owner.task, 45)
    before = owner.snapshot()["research"]["records"]
    restored = StreamingMonitoring(tmp_path, paths=research_paths())
    snapshot = await restored.restore_latest()
    assert snapshot["state"] == "RETAINED_STREAM_NOT_LIVE"
    assert snapshot["collection_live"] is False
    assert snapshot["network"]["current_inference_count"] == 0
    assert snapshot["network"]["packets_per_second"] is None
    assert snapshot["research"]["records"] == before
    assert not snapshot["research"]["worker_running"]
    assert restored.capture is None and restored.task is None
    assert restored.store.queue.counts() == {"DONE": 1}
    assert not list((restored.directory / "inputs").glob("*"))


@pytest.mark.asyncio
async def test_collection_advances_while_mock_model_waits_and_shutdown_is_bounded(tmp_path):
    from tests.streaming_network_support import UnknownMockAdapter, packet

    waiting = asyncio.Event()
    release = asyncio.Event()
    owner = StreamingMonitoring(tmp_path, paths=research_paths())

    class Slow(UnknownMockAdapter):
        async def infer(self, request):
            self.calls += 1
            waiting.set()
            await release.wait()
            return {"status": "UNKNOWN", "error": "MOCK_TIMEOUT"}

    async def source():
        async for p in idle_source(owner):
            yield p
        await asyncio.wait_for(waiting.wait(), 5)
        for t in (32, 33, 34):
            yield packet(owner, t, port=5000)
        assert owner.metrics["packets_collected"] == 7
        release.set()

    adapter = Slow()
    await owner.start_fixture(source(), policy=StreamPolicy(seconds=120), model_adapter=adapter)
    await asyncio.wait_for(owner.task, 10)
    assert adapter.calls == 1
    assert owner.inference_blocked
    assert owner.state == "STOPPED"
    assert owner.metrics["finalization"] == "PARTIAL"
    assert owner.aggregator.bytes == 0
    assert owner.store.queue.counts() == {"DONE": 1}
    assert all(not row.get("receipt") for row in owner.snapshot()["research"]["records"])


@pytest.mark.asyncio
async def test_duplicate_prepare_stop_restart_and_gui_close_no_privilege(tmp_path):
    from tests.research_adapter_support import research_paths

    from soc_agent.gui.backend import Backend, GUIConfig

    backend = Backend(GUIConfig(data_directory=tmp_path))
    backend.streaming_monitoring.paths = research_paths()
    first = await backend.stream_start("both", False)
    assert first["listener_ready"]
    assert first["policy"]["dns_headers"] is False
    with pytest.raises(ValueError, match="ALREADY_ACTIVE"):
        await backend.stream_start()
    stopped = await backend.stream_stop()
    assert not stopped["listener_ready"]
    assert (await backend.stream_command(first["session_id"]))["status"] == "BLOCKED"
    second = await backend.stream_start("edge")
    assert second["session_id"] != first["session_id"]
    await backend.close()
    assert backend.streaming_monitoring.task.done()
    assert not backend.streaming_monitoring.capture.listener_ready()


@pytest.mark.asyncio
async def test_actual_models_complete_before_fixture_collection_ends(tmp_path):
    from tests.streaming_network_support import packet

    owner = StreamingMonitoring(tmp_path, paths=research_paths())

    async def source():
        async for item in idle_source(owner):
            yield item
        for tick in range(100):
            yield packet(owner, 32 + tick * 0.01, port=5000, flags=16)
            await asyncio.sleep(0.1)
            if owner.store.queue.counts().get("DONE") == 1:
                records = owner.demo.snapshot()["records"]
                assert len(records) == 2 and all(r["status"] == "COMPLETE" for r in records)
                assert owner.state == "FIXTURE_STREAMING"
                assert not owner.done.is_set()
                assert owner.metrics["inference_count"] == 2
                break
        else:
            raise AssertionError("Actual model pair did not complete during fixture collection")

    await owner.start_fixture(source(), policy=StreamPolicy(seconds=120))
    await asyncio.wait_for(owner.task, 45)
    assert owner.state == "STOPPED"
    assert owner.metrics["packets_collected"] > 4
    assert owner.metrics["inference_count"] == 2
    assert owner.store.queue.counts() == {"DONE": 1}
    assert owner.aggregator.bytes == 0

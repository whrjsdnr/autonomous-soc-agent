"""Pinned Zeek executable, offline file fixtures only; never open an interface."""

import asyncio
import json
import shutil
from pathlib import Path

import pytest
from tests.zeek_producer_support import valid_wire, write_pcap

from soc_agent.security_ai.collectors.finalization import Ledger
from soc_agent.security_ai.collectors.live_contract import docker_argv, new_plan
from soc_agent.security_ai.collectors.live_process import StreamProcess
from soc_agent.security_ai.collectors.live_stream import decode
from soc_agent.security_ai.collectors.offline import OfflineZeek


@pytest.fixture
def environment():
    try:
        OfflineZeek().environment()
    except (OSError, ValueError):
        pytest.skip("OFFICIAL_PINNED_ZEEK_UNAVAILABLE")


def pcap(path, count):
    return write_pcap(
        path, [(1800000000000000000 + i * 1000000, valid_wire(flags=16)) for i in range(count)]
    )


@pytest.mark.parametrize("count", [4095, 4096, 4097])
def test_real_zeek_packet_budget_hook_and_stdout_flush(tmp_path, environment, count):
    source = tmp_path / "input.pcap"
    pcap(source, count)
    r = StreamProcess(tmp_path, new_plan(), fixture=source)
    r.run()
    result = json.loads((tmp_path / "exit.json").read_text())
    lines = (tmp_path / "stream.jsonl").read_bytes().splitlines(keepends=True)
    ledger = Ledger()
    for line in lines:
        ledger.accept(decode(line), line)
    assert ledger.closed and ledger.packets == min(count, 4096)
    assert ledger.closed.stop_reason == ("ZEEK_DONE" if count < 4096 else "PACKET_LIMIT_REACHED")
    assert result["container_absent"] and result["cleanup_verified"]
    assert result["exit_code"] == 0 and result["error"] is None
    assert result["capture_integrity"] == "UNVERIFIED" and not result["native_capture"]
    assert sum(decode(line).kind == "closed" for line in lines) == 1


def test_script_event_and_output_reserve(tmp_path, environment):
    import subprocess

    policies = Path(__file__).resolve().parents[3] / "src/soc_agent/security_ai/collectors"
    source = tmp_path / "input.pcap"
    pcap(source, 40)
    for name in ("event", "output"):
        directory = tmp_path / name
        directory.mkdir()
        shutil.copy(policies / "network14.zeek", directory)
        shutil.copy(policies / "visibility.zeek", directory)
        text = (policies / "live.zeek").read_text()
        text = text.replace("8191", "7") if name == "event" else text.replace("8388608", "4096")
        (directory / "live.zeek").write_text(text)
        # Lowered limits apply only to this isolated offline test script copy.
        p = subprocess.run(
            docker_argv(new_plan(), directory, fixture=source), capture_output=True, timeout=15
        )
        assert p.returncode == 0, p.stderr.decode()[-1000:]
        rows = [json.loads(line) for line in p.stdout.splitlines()]
        assert rows[0]["kind"] == "ready" and rows[-1]["kind"] == "closed"
        assert rows[-1]["data"]["stop_reason"] == (
            "EVENT_LIMIT_REACHED" if name == "event" else "OUTPUT_LIMIT_REACHED"
        )
        assert [row["sequence"] for row in rows] == list(range(1, len(rows) + 1))
        if name == "event":
            assert len(rows) == 8 and rows[-1]["data"]["omitted_events"] > 0
        else:
            assert len(p.stdout) <= 4096 and rows[-1]["data"]["omitted_events"] > 0


@pytest.mark.asyncio
@pytest.mark.parametrize("stopping", ["timeout", "stop"])
async def test_real_zeek_timeout_and_sigint_drain(tmp_path, environment, monkeypatch, stopping):
    policies = Path(__file__).resolve().parents[3] / "src/soc_agent/security_ai/collectors"
    directory = tmp_path / "policy"
    directory.mkdir()
    shutil.copy(policies / "network14.zeek", directory)
    shutil.copy(policies / "visibility.zeek", directory)
    (directory / "live.zeek").write_text(
        "redef exit_only_after_terminate = T;\n" + (policies / "live.zeek").read_text()
    )
    original = docker_argv
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.live_process.docker_argv",
        lambda plan, policy, **kw: original(plan, directory, **kw),
    )
    source = tmp_path / "input.pcap"
    pcap(source, 1)
    plan = new_plan().model_copy(update={"duration_seconds": 2})
    r = StreamProcess(tmp_path, plan, fixture=source)
    task = asyncio.create_task(asyncio.to_thread(r.run))
    if stopping == "stop":
        for _ in range(150):
            if (tmp_path / "stream.jsonl").exists() and (tmp_path / "stream.jsonl").stat().st_size:
                break
            await asyncio.sleep(0.01)
        r.stop()
    await asyncio.wait_for(task, 15)
    result = json.loads((tmp_path / "exit.json").read_text())
    assert result["closed_observed"] and result["cleanup_verified"]
    assert result["termination_reason"] == (
        "USER_STOP" if stopping == "stop" else "SESSION_TIMEOUT"
    )
    assert result["exit_code"] in {0, 124} and not result["native_capture"]


@pytest.mark.asyncio
async def test_packet_limit_controller_drain_audit_and_recovery(tmp_path, environment, monkeypatch):
    from soc_agent.security_ai.collectors.live import LiveZeekCollector

    async def forbidden(*args, **kwargs):
        raise AssertionError("INCOMPLETE_PACKET_LIMIT_SESSION_MUST_NOT_INFER")

    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.producer_service.ProducerService.produce", forbidden
    )
    source = tmp_path / "input.pcap"
    sha = pcap(source, 4096)
    c = LiveZeekCollector(tmp_path)
    drain_states = []
    original_poll = c._poll

    def observed_poll(reader):
        if c.state == "DRAINING":
            drain_states.append(c.state)
        return original_poll(reader)

    monkeypatch.setattr(c, "_poll", observed_poll)
    try:
        await c.prepare(pcap=source, sha256=sha)
        await c.start()
        await asyncio.wait_for(c.task, 40)
        snap = c.snapshot()
        assert c.state == "STOPPED", c.last_error
        assert c.queue_depth == 0 and c.queue_peak <= 32
        assert drain_states, "Drain must be observable before EOF validation"
        assert c.stream.packet_count == 4096 and c.stream.closed
        assert all(not flow["eligible"] for flow in c.stream.finalized)
        assert c.producer is None and snap["research"]["records"] == []
        assert snap["termination_reason"] == "PACKET_LIMIT_REACHED"
        assert snap["finalization_state"] == "DEGRADED"
        assert snap["cleanup_verified"] and snap["closed_status"] == "OBSERVED"
        audit = c.store.runtime.verify_audit()
        restored = LiveZeekCollector(tmp_path)
        recovered = await restored.recover()
        assert recovered["state"] == "STOPPED" and not recovered["collection_live"]
        assert recovered["termination_reason"] == "PACKET_LIMIT_REACHED"
        assert recovered["research"]["records"] == []
        assert restored.store.runtime.verify_audit() == audit
        await restored.stop()
    finally:
        await c.stop()

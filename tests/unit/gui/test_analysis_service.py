"""Analysis lifecycle uses the real CLI except for the process fault boundary."""

import asyncio
import json
import os
import sys

import pytest

from soc_agent.gui.analysis_service import AnalysisService


@pytest.mark.asyncio
async def test_native_job_never_starts_process(tmp_path, monkeypatch):
    service = AnalysisService(tmp_path / "state")
    job = tmp_path / "job.json"
    job.write_text(json.dumps({"kind": "native_checkpoint", "summary": {}, "transport": {}}))

    async def forbidden(*args, **kwargs):
        pytest.fail("Native evidence must use the governed entrypoint")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden)
    with pytest.raises(ValueError, match="NATIVE_ANALYSIS_REQUIRES"):
        await service.start(job)
    assert service.state == "IDLE"


@pytest.mark.asyncio
async def test_stop_and_close_reap_only_owned_group(tmp_path, monkeypatch):
    original = asyncio.create_subprocess_exec

    async def bounded_worker(*args, **kwargs):
        return await original(sys.executable, "-c", "import time; time.sleep(60)", **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", bounded_worker)
    service = AnalysisService(tmp_path / "state")
    job = tmp_path / "job.json"
    job.write_text('{"kind":"network14_replay","flow_index":0}')
    await service.start(job)
    pid = service.process.pid
    assert os.getpgid(pid) == pid
    with pytest.raises(ValueError, match="ALREADY_RUNNING"):
        await service.start(job)
    stopped = await service.stop()
    assert stopped["state"] == "STOPPED"
    assert stopped["cleanup"] == "VERIFIED"
    with pytest.raises(ProcessLookupError):
        os.killpg(pid, 0)
    assert await service.close()
    with pytest.raises(ValueError, match="CLOSED"):
        await service.start(job)
    assert os.getpgid(os.getpid()) != pid


@pytest.mark.asyncio
async def test_failed_child_preserves_exit_no_retry(tmp_path, monkeypatch):
    original = asyncio.create_subprocess_exec
    calls = []

    async def failed_worker(*args, **kwargs):
        calls.append(args)
        return await original(sys.executable, "-c", "raise SystemExit(7)", **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", failed_worker)
    service = AnalysisService(tmp_path / "state")
    job = tmp_path / "job.json"
    job.write_text('{"kind":"network14_replay","flow_index":0}')
    await service.start(job)
    await service.monitor
    assert service.snapshot()["child_returncode"] == 7
    assert service.state == "ERROR"
    assert service.cleanup == "VERIFIED"
    assert len(calls) == 1
    assert not service.result


@pytest.mark.asyncio
async def test_unverified_report_is_not_displayed(tmp_path):
    service = AnalysisService(tmp_path / "state")
    with pytest.raises((ValueError, OSError)):
        await service.attach(tmp_path / "absent")
    assert service.result is None


@pytest.mark.asyncio
async def test_unknown_cleanup_blocks_successful_close_and_restart(tmp_path):
    service = AnalysisService(tmp_path / "state")
    service.state = "ERROR"
    service.cleanup = "UNVERIFIED"
    with pytest.raises(ValueError, match="ANALYSIS_SHUTDOWN_UNVERIFIED"):
        await service.close()
    assert not service.closed
    with pytest.raises(ValueError, match="ALREADY_RUNNING_OR_CLOSED"):
        await service.start(tmp_path / "not-read.json")
    with pytest.raises(ValueError, match="MUST_STOP_BEFORE_ATTACH"):
        await service.attach(tmp_path / "not-read")

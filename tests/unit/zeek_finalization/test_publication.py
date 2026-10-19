"""Reproduce the torn certificate race; ensure no-replace atomic publication fixes it."""

import asyncio
import json
import threading

import pytest
from tests.unit.zeek_lifecycle.test_handoff import prepared

from soc_agent.security_ai.collectors.finalization import publish
from soc_agent.security_ai.collectors.live_process import main


def test_publish_no_overwrite_private_complete_and_bounded(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "exit.json"
    publish(path, dict(status="fixture"))
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text()) == dict(status="fixture")
    with pytest.raises(FileExistsError):
        publish(path, dict(status="replacement"))
    with pytest.raises(ValueError, match="SIZE_LIMIT"):
        publish(tmp_path / "large.json", dict(value="x" * 8192))
    assert not list(tmp_path.glob(".publish-*"))
    assert json.loads(path.read_text()) == dict(status="fixture")


@pytest.mark.asyncio
@pytest.mark.parametrize("atomic", [False, True])
async def test_failure_publication_race_is_reproduced_and_prevented(tmp_path, monkeypatch, atomic):
    import os

    c = await prepared(tmp_path, monkeypatch)
    reached, release = threading.Event(), threading.Event()

    def forbidden():
        raise AssertionError("NO AUTHENTICATION OR CAPTURE")

    monkeypatch.setattr("soc_agent.cli.terminal_authenticate", forbidden)
    original_link = os.link

    def paused_link(source, destination, **kwargs):
        if destination.name == "launch-failure.json":
            reached.set()
            assert release.wait(3)
        return original_link(source, destination, **kwargs)

    def old_torn_write(path, value):
        # Exact old open('x') publication shape, with a deterministic scheduling pause.
        with path.open("x") as stream:
            if path.name == "launch-failure.json":
                reached.set()
                assert release.wait(3)
            stream.write(json.dumps(value))
        path.chmod(0o600)

    if atomic:
        monkeypatch.setattr("os.link", paused_link)
    else:
        monkeypatch.setattr(
            "soc_agent.security_ai.collectors.live_process.write_new", old_torn_write
        )
    task = asyncio.create_task(
        asyncio.to_thread(
            main, ["--session", str(c.directory), "--approve", "deliberately-wrong-fixture-digest"]
        )
    )
    try:
        assert await asyncio.to_thread(reached.wait, 2)
        if atomic:
            assert not (c.directory / "launch-failure.json").exists()
            await asyncio.sleep(0.12)
            assert c.last_error is None and not c.task.done()
        else:
            assert (c.directory / "launch-failure.json").exists()
            await asyncio.wait_for(asyncio.shield(c.task), 2)
            assert c.last_error == "ZEEK_LIVE_INTEGRITY_FAILED"
        release.set()
        with pytest.raises(ValueError, match="APPROVAL_DIGEST_MISMATCH"):
            await asyncio.wait_for(task, 3)
        await asyncio.wait_for(c.task, 3)
        if atomic:
            assert c.last_error == "ZEEK_APPROVAL_DIGEST_MISMATCH"
        c.store.verify()
        assert not c.snapshot()["command_valid"]
    finally:
        release.set()
        if not task.done():
            with pytest.raises(ValueError):
                await task
        await c.stop()

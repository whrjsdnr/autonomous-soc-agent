"""Existing Launcher race: concurrent stop must not suppress failure evidence."""

from types import SimpleNamespace
from uuid import uuid4

import pytest

from soc_agent.security_ai.collectors import live_process


def test_failure_certificate_precedes_concurrent_stop_publication(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    plan = SimpleNamespace(session_id=uuid4(), identity="a" * 64, controller_generation=uuid4())
    original = live_process.write_new

    def concurrent_stop(path, value):
        if path.name == "stop.request":
            # Emulate Controller publication between Launcher exists() and atomic create.
            original(path, value)
        original(path, value)

    monkeypatch.setattr(live_process, "write_new", concurrent_stop)
    with pytest.raises(FileExistsError):
        live_process.rejection(tmp_path, ValueError("ZEEK_DOCKER_START_FAILED"), plan)
    body = (tmp_path / "launch-failure.json").read_text()
    assert "ZEEK_DOCKER_START_FAILED" in body
    assert str(plan.session_id) in body and plan.identity in body
    assert len(list((tmp_path / "launcher-rejections").glob("*.json"))) == 1

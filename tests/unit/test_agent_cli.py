"""Real ordinary service lifecycle; no Root, journal or Kernel side effects."""

import hashlib
import json
from unittest.mock import Mock

import pytest

from soc_agent import agent_runtime
from soc_agent.cli import main
from soc_agent.continuous import cli as service
from soc_agent.continuous.models import ContinuousConfig
from soc_agent.continuous.store import Store


def configured(tmp_path):
    source = tmp_path / "input.jsonl"
    source.write_text(
        '{"kind":"excluded","id":"excluded-1","sequence":1,"affects_integrity":false}\n'
    )
    cfg = ContinuousConfig(
        source="JSONL_REPLAY",
        input_file=source,
        input_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        heartbeat_seconds=0.1,
    )
    path = tmp_path / "config.json"
    path.write_text(cfg.model_dump_json())
    home = tmp_path / "app"
    assert main(["setup", "--home", str(home), "--config", str(path)]) == 0
    return home, source


def test_one_command_service_start_status_duplicate_stop(tmp_path, capsys):
    home, _ = configured(tmp_path)
    try:
        assert main(["doctor", "--home", str(home)]) == 0
        assert main(["start", "--home", str(home)]) == 0
        actual = agent_runtime.status(home)
        assert actual["state"] == "RUNNING" and actual["source"] == "JSONL_REPLAY"
        assert not actual["collection_live"]
        assert main(["start", "--home", str(home)]) == 2
        assert "AGENT_ALREADY_RUNNING" in capsys.readouterr().err
    finally:
        assert main(["stop", "--home", str(home)]) == 0
    assert agent_runtime.status(home)["state"] == "STOPPED"
    assert main(["stop", "--home", str(home)]) == 0


def test_source_and_profile_tampering_block_before_spawn(tmp_path, monkeypatch):
    home, source = configured(tmp_path)
    monkeypatch.setattr(service, "start", lambda *_: pytest.fail("No process may start"))
    source.write_text("{}\n")
    assert main(["start", "--home", str(home)]) == 2
    doc = json.loads((home / "agent.json").read_text())
    doc["profile"]["runtime"] = str(tmp_path / "other")
    (home / "agent.json").write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="PROFILE_INTEGRITY"):
        agent_runtime.profile(home)


def test_native_attach_never_grants_start_or_models(tmp_path, monkeypatch):
    source = tmp_path / "policy.json"
    source.write_text("{}")
    cfg = ContinuousConfig(source="NATIVE_SERVICE", input_file=source, input_sha256="a" * 64)
    directory = tmp_path / "native"
    Store.create(directory, cfg)
    (directory / "code-identity").write_text("frozen-old-code")
    home = tmp_path / "app"
    agent_runtime.setup(home, runtime=directory)
    monkeypatch.setattr(agent_runtime, "doctor", lambda *_: {})
    with pytest.raises(ValueError, match="APPROVAL_REVIEW_REQUIRED"):
        agent_runtime.start(home)


def test_gui_delegates_to_existing_unprivileged_client(tmp_path, monkeypatch):
    home, _ = configured(tmp_path)
    from soc_agent.gui import __main__ as gui

    called = []
    monkeypatch.setattr(gui, "main", lambda args: called.append(args) or 0)
    assert main(["gui", "--home", str(home)]) == 0
    assert "--continuous-runtime" in called[0]


def test_failed_partial_start_reaps_only_owned_child(tmp_path, monkeypatch):
    home, _ = configured(tmp_path)
    path = agent_runtime.profile(home).runtime
    proc = Mock()
    proc.poll.return_value = None
    monkeypatch.setattr(service.subprocess, "Popen", lambda *_args, **_kw: proc)
    # Existing store is valid at admission; fail the first post-spawn health read.
    original = service.status
    calls = 0

    def status(directory):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise ValueError("INJECTED_HEALTH_FAILURE")
        return original(directory)

    monkeypatch.setattr(service, "status", status)
    with pytest.raises(ValueError, match="INJECTED_HEALTH_FAILURE"):
        service.start(path)
    proc.terminate.assert_called_once()
    proc.wait.assert_called_once()
    proc.kill.assert_not_called()

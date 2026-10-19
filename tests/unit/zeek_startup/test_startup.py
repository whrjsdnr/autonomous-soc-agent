"""Real controller/Unix listener, mocked OS authentication and process start only."""

import json
import subprocess
import threading
from types import SimpleNamespace

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.security_ai.collectors import startup


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.offline.OfflineZeek.environment", lambda _: {}
    )
    s = startup.Startup(GUIConfig(data_directory=tmp_path, collector_type="zeek-live"))
    s.prepare()
    yield s
    if s.worker.thread.is_alive():
        s.finish()


def test_same_controller_across_approval_auth_gui_and_no_second_auth(prepared, monkeypatch):
    s = prepared
    owner = s.worker.backend._owners["zeek_collector"]
    identity = owner.handoff.identity
    calls = []
    monkeypatch.setattr(
        "soc_agent.cli.terminal_authenticate", lambda: calls.append(threading.get_ident())
    )
    s.authenticate()
    assert calls == [threading.main_thread().ident]
    assert owner.state == "STARTING" and owner.handoff.identity == identity
    assert owner.task and not owner.task.done()
    assert not s.runner._launched and not (owner.directory / "process.json").exists()
    snap = owner.snapshot()
    assert not snap["command_valid"] and snap["collector_command"] is None
    assert snap["network_observation"] == snap["dns_observation"] == "NOT_OBSERVED"
    assert not snap["collection_live"] and snap["research"]["records"] == []
    # Backend admission uses the original approved runner and loop, no new session.
    invoked = threading.Event()
    monkeypatch.setattr(s.runner, "run", lambda: invoked.set())

    class GUI:
        def render(self, value):
            pass

        def call(self, method, runner, **kwargs):
            s.worker.submit(method, runner).result(5)

    s.gui_ready(GUI())
    assert invoked.wait(2) and owner.process_runner is s.runner
    assert owner.handoff.identity == identity and len(calls) == 1
    # Avoid pretending this intentionally incomplete mocked runner created CLOSED.
    s.worker.submit("collector_stop").result(5)
    with pytest.raises(ValueError, match="STARTUP_PHASE_INVALID"):
        s.gui_ready(GUI())


@pytest.mark.parametrize(
    "failure", [ValueError("denied"), KeyboardInterrupt(), subprocess.TimeoutExpired("sudo", 60)]
)
def test_auth_failure_never_starts_capture_and_invalidates_session(prepared, monkeypatch, failure):
    s = prepared

    def denied():
        raise failure

    monkeypatch.setattr("soc_agent.cli.terminal_authenticate", denied)
    with pytest.raises((ValueError, KeyboardInterrupt)):
        s.authenticate()
    assert not s.runner._launched
    assert s.finish("USER_STOP")
    end = json.loads((s.runner.directory / "cli-exit.json").read_text())
    assert end["cleanup"] == "NOT_STARTED" and end["audit_integrity"] == "VERIFIED"
    assert (s.runner.directory / "stop.request").exists()
    with pytest.raises(ValueError, match="SESSION_STOP_REQUESTED"):
        s.runner.authenticate()


def test_unapproved_wrong_session_and_duplicate_phase_cannot_launch(prepared):
    s = prepared
    with pytest.raises(ValueError, match="APPROVAL_DIGEST_MISMATCH"):
        s.worker.submit("zeek_launch_authenticated", s.runner).result(5)
    p = s.runner.plan
    with pytest.raises(ValueError, match="IDENTITY_MISMATCH"):
        s.worker.submit(
            "zeek_startup_phase",
            str(p.session_id),
            "0" * 64,
            str(p.controller_generation),
            "AUTHENTICATING",
        ).result(5)
    with pytest.raises(ValueError, match="STARTUP_PHASE_INVALID"):
        s.set_phase("STARTING")
    assert not s.runner._launched


def test_cleanup_failure_is_not_success(prepared, monkeypatch):
    s = prepared
    s.runner._launched = True
    s.worker.backend._owners["zeek_collector"].process_runner = s.runner
    assert not s.finish()
    end = json.loads((s.runner.directory / "cli-exit.json").read_text())
    assert end["cleanup"] == "UNVERIFIED" and not end["safe_shutdown"]


def test_scope_binds_controller_and_limits(prepared):
    text = prepared.scope()
    p = prepared.runner.plan
    for value in (
        p.identity,
        str(p.session_id),
        p.bundle_digest,
        "4096",
        "8192",
        "300s",
        "512MiB",
        "lo",
        "NET_RAW",
    ):
        assert value in text
    assert "Native AI, DNS9, operational gate BLOCKED" in text


def test_cli_dispatch_is_one_command_no_manual_copy(monkeypatch, tmp_path):
    from soc_agent.cli import main

    seen = []
    monkeypatch.setattr(startup, "start", lambda directory: seen.append(directory) or 0)
    assert (
        main(
            [
                "start",
                "--gui",
                "--monitor",
                "total",
                "--collector",
                "zeek-live",
                "--data-directory",
                str(tmp_path),
            ]
        )
        == 0
    )
    assert seen == [tmp_path]
    assert (
        main(
            [
                "start",
                "--gui",
                "--monitor",
                "total",
                "--collector",
                "zeek-live",
                "--pcap",
                "unapproved",
            ]
        )
        == 1
    )


@pytest.mark.parametrize(
    "answer,auth_failure",
    [("NO", None), ("yes", KeyboardInterrupt()), ("yes", ValueError("denied"))],
)
def test_whole_command_denial_or_interrupt_never_opens_gui_or_capture(
    tmp_path, monkeypatch, answer, auth_failure
):
    monkeypatch.setattr(startup, "preflight", lambda: None)
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.offline.OfflineZeek.environment", lambda _: {}
    )
    monkeypatch.setattr("builtins.input", lambda _: answer)

    def auth():
        if auth_failure:
            raise auth_failure

    monkeypatch.setattr("soc_agent.cli.terminal_authenticate", auth)
    monkeypatch.setattr(
        "soc_agent.gui.__main__.main", lambda *a, **k: pytest.fail("GUI must not start")
    )
    assert startup.start(tmp_path) == 1
    dirs = list((tmp_path / "zeek-live-collector").glob("session-*"))
    assert len(dirs) == 1
    assert not (dirs[0] / "process.json").exists()
    assert not (dirs[0] / "stream.jsonl").exists()
    assert json.loads((dirs[0] / "cli-exit.json").read_text())["cleanup"] == "NOT_STARTED"


def test_authenticated_run_does_not_prompt_again(prepared, monkeypatch):
    s = prepared
    calls = []
    monkeypatch.setattr("soc_agent.cli.terminal_authenticate", lambda: calls.append(1))
    s.authenticate()

    def blocked(*a, **kw):
        assert kw["process_group"] == 0
        assert kw["stdin"] == subprocess.DEVNULL
        assert a[0][:3] == ["sudo", "-n", "--"]
        raise OSError("mock start failure")

    monkeypatch.setattr("subprocess.Popen", blocked)
    monkeypatch.setattr(s.runner, "_absent", lambda: True)
    with pytest.raises(ValueError):
        s.runner.run()
    assert calls == [1]
    with pytest.raises(ValueError, match="SESSION_REUSE_DENIED"):
        s.runner.run()
    assert (s.runner.directory / "exit.json").exists()


@pytest.mark.parametrize("code,stdout", [(0, b"old-container\n"), (1, b"")])
def test_inventory_blocks_prior_or_unverifiable_containers(monkeypatch, code, stdout):
    monkeypatch.setattr(startup.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(startup, "require_headroom", lambda: {})
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.offline.OfflineZeek.environment", lambda _: {}
    )
    commands = []

    def run(argv, **kwargs):
        commands.append(argv)
        return SimpleNamespace(returncode=code, stdout=stdout)

    monkeypatch.setattr(startup.subprocess, "run", run)
    with pytest.raises(ValueError, match="PRIOR_CONTAINER_REVIEW_REQUIRED"):
        startup.preflight()
    assert commands[0][:3] == ["docker", "container", "ls"]
    assert not any("sudo" in value for value in commands[0])


def test_root_or_nonterminal_rejected(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)
    with pytest.raises(ValueError):
        startup.preflight()
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    monkeypatch.setattr(startup.sys, "stdin", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(ValueError, match="INTERACTIVE_TERMINAL_REQUIRED"):
        startup.preflight()


def test_duplicate_desktop_rejected_before_approval_or_auth(tmp_path, monkeypatch):
    from soc_agent.review.persistence.secure_storage import create_private_directory
    from soc_agent.runtime_lock import exclusive_runtime_lock

    monkeypatch.setattr(startup, "preflight", lambda: None)
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("approval after lock failure"))
    create_private_directory(tmp_path)
    with exclusive_runtime_lock(tmp_path / "desktop.lock"):
        with pytest.raises(BlockingIOError):
            startup.start(tmp_path)
    assert not (tmp_path / "zeek-live-collector").exists()


def test_gui_creation_failure_closes_original_listener_without_capture(tmp_path, monkeypatch):
    import tkinter as tk

    monkeypatch.setattr(startup, "preflight", lambda: None)
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.offline.OfflineZeek.environment", lambda _: {}
    )
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    calls = []
    monkeypatch.setattr("soc_agent.cli.terminal_authenticate", lambda: calls.append("auth"))

    def unavailable():
        raise tk.TclError("private display diagnostic")

    monkeypatch.setattr(tk, "Tk", unavailable)
    assert startup.start(tmp_path) == 1
    assert calls == ["auth"]
    d = next((tmp_path / "zeek-live-collector").glob("session-*"))
    end = json.loads((d / "cli-exit.json").read_text())
    assert not end["gui_ready"] and end["cleanup"] == "NOT_STARTED"
    assert end["error"] == "ZEEK_GUI_START_FAILED"
    assert not (d / "process.json").exists()
    from soc_agent.security_ai.collectors.handoff import exchange
    from soc_agent.security_ai.collectors.live_contract import LivePlan

    plan = LivePlan.model_validate_json((d / "plan.json").read_text())
    with pytest.raises(ValueError, match="SESSION_STOP_REQUESTED"):
        exchange(d, plan, "probe")

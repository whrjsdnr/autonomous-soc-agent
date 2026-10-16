from types import SimpleNamespace

import pytest

from soc_agent import cli


def test_terminal_auth_inherits_terminal_without_secret_api(monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    calls = []
    cli.terminal_authenticate(
        run=lambda *a, **kw: calls.append((a, kw)) or SimpleNamespace(returncode=0)
    )
    args, kwargs = calls[0]
    assert args == (["/usr/bin/sudo", "-v"],)
    assert kwargs == {"timeout": 60, "check": False}
    assert "-S" not in str(calls) and "PIPE" not in str(calls)


@pytest.mark.parametrize("code", [1, 130])
def test_auth_denied_cancelled_never_starts_gui(monkeypatch, code):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    with pytest.raises(ValueError, match="AUTH_DENIED_OR_CANCELLED"):
        cli.terminal_authenticate(run=lambda *a, **kw: SimpleNamespace(returncode=code))


def test_one_command_startup_mock_auth_and_gui(monkeypatch, tmp_path):
    import soc_agent.gui.__main__ as gui

    calls = []
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    monkeypatch.setattr(cli.ResearchAdapter, "status", lambda _: {"status": "READY"})
    monkeypatch.setattr(cli, "terminal_authenticate", lambda: calls.append("AUTH_MOCK"))
    monkeypatch.setattr(gui, "main", lambda args: calls.append(args) or 0)
    monkeypatch.setenv("DISPLAY", ":0")
    assert (
        cli.main(["start", "--gui", "--monitor", "total", "--data-directory", str(tmp_path)]) == 0
    )
    assert calls[0] == "AUTH_MOCK"
    assert "--total-approved-sha" in calls[1]


def test_scope_cancel_and_missing_artifact_never_authenticate(monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli, "terminal_authenticate", lambda: pytest.fail("no auth allowed"))
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(cli.ResearchAdapter, "status", lambda _: {"status": "BLOCKED"})
    assert cli.main(["start", "--gui", "--monitor", "total"]) == 1
    monkeypatch.setattr(cli.ResearchAdapter, "status", lambda _: {"status": "READY"})
    monkeypatch.setattr("builtins.input", lambda _: "no")
    assert cli.main(["start", "--gui", "--monitor", "total"]) == 1

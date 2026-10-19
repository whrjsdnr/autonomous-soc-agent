"""New SHA approval before OS authentication; no privileged executable is launched."""

from unittest.mock import Mock

import pytest

from soc_agent import cli
from soc_agent.gui.backend import GUIConfig
from soc_agent.security_ai.operational.network_capture import direction_session
from soc_agent.security_ai.research.models import digest


def test_cli_requires_separate_v3_approval(monkeypatch, capsys):
    auth = Mock(side_effect=AssertionError("Authentication must not run"))
    monkeypatch.setattr(cli, "terminal_authenticate", auth)
    sha = direction_session.verify_bundle()["direction_helper.py"]
    assert (
        cli.main(
            [
                "start",
                "--gui",
                "--monitor",
                "total",
                "--rate-policy",
                "direction-v3",
                "--approve-calibrated-sha",
                sha,
            ]
        )
        == 1
    )
    auth.assert_not_called()
    assert "V3_NEW_SHA_APPROVAL_REQUIRED" in capsys.readouterr().err


def test_v3_policy_config_and_bundle_match(tmp_path):
    config = GUIConfig(data_directory=tmp_path, total_rate_policy="direction-v3")
    assert config.total_rate_policy == "direction-v3" and config.total_approved_sha is None
    assert len(digest(direction_session.verify_bundle())) == 64


def test_new_peer_rejects_old_module_without_proc_access(tmp_path):
    from soc_agent.security_ai.operational.network_capture.direction_peer import validate_peer

    with pytest.raises(ValueError, match="HELPER_MODULE_NOT_ALLOWLISTED"):
        validate_peer(
            None,
            None,
            None,
            tmp_path,
            module="soc_agent.security_ai.operational.network_capture.calibrated_helper",
        )


def test_cli_explicit_v3_handoff_is_mocked_and_session_bound(monkeypatch):
    from types import SimpleNamespace

    from soc_agent.gui import __main__ as gui
    from soc_agent.security_ai.operational.network_capture import calibrated_policy

    sha = direction_session.verify_bundle()["direction_helper.py"]
    authenticate = Mock()
    launch = Mock(return_value=0)
    monkeypatch.setattr(cli, "terminal_authenticate", authenticate)
    monkeypatch.setattr(cli.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    monkeypatch.setattr(calibrated_policy, "require_headroom", lambda: None)
    monkeypatch.setattr(
        cli,
        "ResearchAdapter",
        Mock(return_value=SimpleNamespace(status=lambda: {"status": "READY"})),
    )
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(gui, "main", launch)
    assert (
        cli.main(
            [
                "start",
                "--gui",
                "--monitor",
                "total",
                "--rate-policy",
                "direction-v3",
                "--approve-direction-sha",
                sha,
            ]
        )
        == 0
    )
    authenticate.assert_called_once_with()
    args = launch.call_args.args[0]
    assert args[args.index("--total-rate-policy") + 1] == "direction-v3"
    assert args[args.index("--total-approved-sha") + 1] == sha
    assert args[args.index("--calibrated-approved-bundle") + 1] == digest(
        direction_session.verify_bundle()
    )


def test_corrupt_new_bundle_does_not_use_old_approval(monkeypatch):
    monkeypatch.setattr(direction_session, "read_local", lambda *args: "{}")
    with pytest.raises(ValueError, match="V3_HELPER_BUNDLE_MISMATCH"):
        direction_session.verify_bundle()

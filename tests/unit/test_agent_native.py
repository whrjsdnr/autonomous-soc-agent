"""Native orchestration with only the privileged transport/entry boundary simulated."""

import json
import subprocess
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
from tests.unit.test_agent_cli import configured

from soc_agent import agent_native, agent_runtime
from soc_agent.agent_diagnostics import api_settings, target_scope
from soc_agent.continuous.models import ContinuousConfig
from soc_agent.security_ai.research.models import digest


def put(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body))
    path.chmod(0o600)


def review(tmp_path, monkeypatch):
    """Ephemeral unsigned fixture. No human receipt and no privileged executable."""
    base = tmp_path / ".git"
    directory = base / "fixture-native-review"
    source = directory / "policy.json"
    put(source, {"fixture": "NOT_AN_INSTALLED_POLICY"})
    cfg = ContinuousConfig(
        source="NATIVE_SERVICE", input_file=source, input_sha256=agent_runtime.sha(source)
    )
    put(directory / "runtime-config-v2.json", cfg.model_dump(mode="json"))
    module = directory / "export/src/soc_agent/__init__.py"
    module.parent.mkdir(parents=True)
    module.write_text('"""Non-executable fixture source identity."""\n')
    pin = agent_runtime.sha(module)
    put(directory / "source-files.json", {"src/soc_agent/__init__.py": pin})
    code = digest({"__init__.py": pin})
    ledger = base / "native-stabilization-batch1/execution-v1/execution-ledger.jsonl"
    put(ledger, {"fixture": "UNSIGNED_CHAIN_ANCHOR_FOR_TRANSPORT_TEST_ONLY"})
    ledger.write_text(ledger.read_text() + "\n")
    entry = directory / "execution/terminal.py"
    entry.parent.mkdir()
    entry.write_text('raise SystemExit("FIXTURE_MUST_NEVER_EXECUTE")\n')
    put(directory / "execution/execution-pins.json", {str(entry): agent_runtime.sha(entry)})
    request = dict(
        contract="soc-operations-approval-review-only:v1",
        expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        files={
            p.name: dict(path=str(p), sha256=agent_runtime.sha(p))
            for p in (source, directory / "runtime-config-v2.json", directory / "source-files.json")
        },
        code_identity=code,
        ledger=dict(rows=1, sha256=agent_runtime.sha(ledger)),
    )
    put(directory / "approval-request-final-v2.json", request)
    # Namespace mount/lease discovery is the external privileged environment boundary.
    monkeypatch.setattr(agent_native, "namespace_binding", lambda *args: dict(target=cfg.namespace))
    home = tmp_path / "application"
    agent_runtime.setup(home, review=directory)
    return home, directory, ledger


def test_native_preview_no_spawn_reservation_or_grants(tmp_path, monkeypatch):
    home, directory, _ = review(tmp_path, monkeypatch)
    monkeypatch.setattr(
        agent_runtime.subprocess, "run", lambda *_a, **_k: pytest.fail("No execution")
    )
    monkeypatch.setattr(
        agent_runtime.subprocess, "Popen", lambda *_a, **_k: pytest.fail("No process")
    )
    before = {str(p): p.read_bytes() for p in directory.rglob("*") if p.is_file()}
    result = agent_runtime.start(home, preview=True, gui=True)
    assert result["root_executed"] is result["capture_started"] is False
    assert result["reservations_created"] is False and "SCOPE_R1_AND_SUDO" in result["status"]
    assert before == {str(p): p.read_bytes() for p in directory.rglob("*") if p.is_file()}


@pytest.mark.parametrize("fault", ["ledger", "config", "source", "consumed"])
def test_native_preview_rejects_changed_binding_and_replay(tmp_path, monkeypatch, fault):
    home, directory, ledger = review(tmp_path, monkeypatch)
    if fault == "ledger":
        ledger.write_text(ledger.read_text() + "{}\n")
    elif fault == "config":
        put(directory / "runtime-config-v2.json", {"different": True})
    elif fault == "source":
        (directory / "export/src/soc_agent/__init__.py").write_text("# changed")
    else:
        put(directory / "execution/root-execution-admitted.json", {"fixture_consumed": True})
    result = agent_runtime.start(home, preview=True)
    assert result["status"] == "BLOCKED" and not result["root_executed"]
    assert not (directory / "future-runtime").exists()


def test_native_entry_checks_tty_and_starts_gui_before_fixed_entry(tmp_path, monkeypatch):
    home, directory, _ = review(tmp_path, monkeypatch)
    monkeypatch.setattr(
        agent_runtime,
        "doctor",
        lambda _: dict(checks=dict(models={"quality": "VERIFIED_SHA", "edge": "VERIFIED_SHA"})),
    )
    monkeypatch.setattr(agent_runtime.sys.stdin, "isatty", lambda: False)
    with pytest.raises(ValueError, match="DIRECT_USER_TTY"):
        agent_runtime.start(home)
    monkeypatch.setattr(agent_runtime.sys.stdin, "isatty", lambda: True)
    order = []
    display = Mock(pid=4321)
    display.poll.return_value = None

    def launch(args, **kwargs):
        assert args[1:4] == ["-m", "soc_agent.cli", "gui"]
        assert kwargs["stdin"] is subprocess.DEVNULL
        order.append("GUI_READER_STARTED")
        return display

    def root_boundary(args, **kwargs):
        assert args == [agent_runtime.sys.executable, str(directory / "execution/terminal.py")]
        assert kwargs == dict(check=False)
        order.append("EXISTING_AUTHENTICATED_TERMINAL_BOUNDARY")
        return subprocess.CompletedProcess(args, 2)

    monkeypatch.setattr(agent_runtime.subprocess, "Popen", launch)
    monkeypatch.setattr(agent_runtime.subprocess, "run", root_boundary)
    result = agent_runtime.start(home, gui=True)
    assert result["returncode"] == 2 and not result["automatic_retry"]
    assert order == ["GUI_READER_STARTED", "EXISTING_AUTHENTICATED_TERMINAL_BOUNDARY"]
    display.terminate.assert_called_once()


def test_doctor_host_categories_and_no_secret_disclosure(tmp_path, monkeypatch):
    home, _ = configured(tmp_path)
    # Current namespace differs: no routes/socket probe or setns may execute.
    monkeypatch.setattr("soc_agent.agent_diagnostics.os.readlink", lambda _: "net:[1]")
    monkeypatch.setattr(
        "soc_agent.security_ai.ebpf_tc.namespace_isolation.inspect_current_isolation",
        lambda *_: pytest.fail("No inspection outside target"),
    )
    monkeypatch.setenv("SOC_LLM_API_KEY", "SECRET_DO_NOT_LOG")
    result = agent_runtime.doctor(home)
    assert result["diagnostics"]["namespace_internal"]["status"] == "WARN"
    assert set(result["diagnostics"]) >= {
        "python",
        "runtime_dependency",
        "model_registry",
        "namespace_lease",
        "root_service",
        "queue_storage",
        "gui_backend",
        "api_provider",
    }
    assert "SECRET_DO_NOT_LOG" not in json.dumps(result)
    assert result["diagnostics"]["api_provider"]["status"] == "FAIL"


def test_already_entered_target_doctor_reuses_read_only_isolation_probe(tmp_path, monkeypatch):
    home, _ = configured(tmp_path)
    selected = agent_runtime.profile(home)
    monkeypatch.setattr(
        "soc_agent.agent_diagnostics.os.readlink", lambda _: selected.configuration.namespace
    )
    monkeypatch.setattr(
        "soc_agent.security_ai.ebpf_tc.namespace_isolation.inspect_current_isolation",
        lambda _: dict(
            status="INCOMPLETE",
            observation=dict(
                interfaces=[[1, "lo"]],
                loopback_up=True,
                routes_outside_lo=[],
                socket_cookie="c0ffee",
            ),
        ),
    )
    result = target_scope(selected)
    assert not result["namespace_entered_by_doctor"] and result["dns_not_required_for_tcp_only"]
    assert result["legacy_dns_assessment"] == "INCOMPLETE"


def test_api_config_validation_has_no_provider_or_network(monkeypatch):
    monkeypatch.setenv("SOC_LLM_BASE_URL", "https://provider.invalid/v1")
    monkeypatch.setenv("SOC_LLM_MODEL", "configured-name")
    monkeypatch.setenv("SOC_LLM_API_KEY", "SECRET_DO_NOT_LOG")
    result = api_settings()
    assert result["configured"] and result["network_requests"] == 0
    assert "SECRET_DO_NOT_LOG" not in json.dumps(result)

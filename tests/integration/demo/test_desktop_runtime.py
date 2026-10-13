"""Portable file boundary and real packaged inference through the shared Desktop core."""

import asyncio
import json
import os
from pathlib import Path

import pytest
from pydantic import TypeAdapter

from soc_agent import desktop
from soc_agent.api.models import StepRequest
from soc_agent.deployment import DeploymentProfile
from soc_agent.ingestion.models import Event
from soc_agent.investigation.runtime import SOCRuntime
from soc_agent.llm.openai_compatible import OpenAICompatibleClient
from soc_agent.local_events import InputIssue, LocalJSONLSource, LocalSourceError
from soc_agent.runtime_driver import advance_until_stopped
from soc_agent.security_ai.packaging import ModelPackage, load_package
from tests.platform_support import make_test_symlink
from tests.scenarios.test_security_ai_fusion import PINS

ROOT = Path(__file__).parents[3]
FIXTURE = ROOT / "examples/live_security_ai_events.jsonl"


@pytest.fixture(autouse=True)
def no_provider_or_listener(monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("Desktop requires no provider request or HTTP listener")

    monkeypatch.setattr(OpenAICompatibleClient, "_post", forbidden)
    # Windows asyncio initializes an internal loopback socketpair before agent work.
    # Prepare only that stdlib infrastructure before monitoring the Desktop runtime.
    if os.name == "nt":
        with asyncio.Runner() as runner:
            runner.get_loop()
            monkeypatch.setattr(asyncio, "run", lambda coroutine: runner.run(coroutine))
            monkeypatch.setattr(socket.socket, "bind", forbidden)
            yield
    else:
        monkeypatch.setattr(socket.socket, "bind", forbidden)
        yield


def test_provider_and_listener_guards_remain_active():
    import socket

    with socket.socket() as probe:
        with pytest.raises(AssertionError, match="no provider request or HTTP listener"):
            probe.bind(("127.0.0.1", 0))
    with pytest.raises(AssertionError, match="no provider request or HTTP listener"):
        OpenAICompatibleClient._post(None, None)


@pytest.fixture(scope="module")
def packages():
    return tuple(
        load_package(
            ROOT / "tests/fixtures/security_ai_packages" / kind, expected_manifest_digest=pin
        )
        for kind, pin, _ in PINS
    )


def test_help_without_storage_or_configuration(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["soc_agent.desktop", "--help"])
    with pytest.raises(SystemExit) as exited:
        desktop.main()
    assert exited.value.code == 0
    assert "--input" in capsys.readouterr().out


def test_actual_inference_persistence_governance_restart(tmp_path, packages, monkeypatch, capsys):
    directory = desktop.prepare(tmp_path / "application")
    composition = desktop.initialize(directory, packages=packages)
    service = composition.service
    assert composition.deployment.profile == DeploymentProfile.DESKTOP
    assert type(service.runtime_factory()) is SOCRuntime
    calls = []
    original = ModelPackage.predict

    def counted(package, features):
        calls.append(package.manifest.model_kind)
        return original(package, features)

    monkeypatch.setattr(ModelPackage, "predict", counted)
    initial = {}
    for event in LocalJSONLSource(FIXTURE).events():
        identity = service.ingest(event).incident_id
        initial[identity] = service.incident(identity).state
    assert asyncio.run(desktop.replay(composition, LocalJSONLSource(FIXTURE))) == 0
    assert calls == ["network_classifier", "network_anomaly", "authentication_anomaly"]
    revisions = {}
    for identity, before in initial.items():
        workflow = service.workflow(identity)
        revisions[identity] = workflow.checkpoint_revision
        assert workflow.waiting_for_human
        checkpoint = service.checkpoint(identity)
        assert checkpoint.artifacts.execution_intent_id is None
        assert checkpoint.artifacts.decision is not None
        state = service.incident(identity).state
        assert (state.severity, state.status) == (before.severity, before.status)
        assert len(state.evidence) == 1  # governed source-report tool, not model output
        assert not state.observations and not state.hypotheses
        fusion = checkpoint.artifacts.assessment.model_derived_context
        assert fusion.confidence_state == "unknown"
        assert all(not signal.source_evidence_ids for signal in fusion.signals)
        assert len(fusion.signals) == (
            2 if service.ingestion.load(identity).event.event_type == "network" else 1
        )
        assert all(c.provenance.incident_id == identity for c in fusion.contributions)
    with service.store.database.transaction() as connection:
        for table in ("reviews", "authorizations", "applications", "execution_records"):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    monitor = service.dashboard_security_ai(lambda _: True)
    assert monitor.retained_signal_count == 3
    assert len(monitor.models) == 3
    # Existing human boundary stays durable: replay/restart never re-infers or submits authority.
    reopened = desktop.initialize(directory, packages=packages)
    assert asyncio.run(desktop.replay(reopened, LocalJSONLSource(FIXTURE))) == 0
    assert len(calls) == 3
    for identity, revision in revisions.items():
        assert reopened.service.workflow(identity).checkpoint_revision == revision
    assert reopened.service.dashboard_self_improvement(lambda _: True).candidate_count == 0
    output = capsys.readouterr().out
    assert "SYNTHETIC" in output and "Persisted signals: 2" in output


def test_checkpoint_resumes_existing_public_boundary(tmp_path):
    composition = desktop.initialize(desktop.prepare(tmp_path / "data"))
    service = composition.service
    event = next(LocalJSONLSource(FIXTURE).events())
    identity = service.ingest(event).incident_id
    workflow = service.start(identity)
    advanced = asyncio.run(
        service.step(
            identity,
            StepRequest(
                run_id=workflow.workflow_id, expected_revision=workflow.checkpoint_revision
            ),
        )
    )
    assert advanced.checkpoint_revision > workflow.checkpoint_revision
    restarted = desktop.initialize(tmp_path / "data")
    stopped = asyncio.run(advance_until_stopped(restarted.service, identity, notify=lambda _: None))
    assert stopped.waiting_for_human
    fusion = restarted.service.checkpoint(identity).artifacts.assessment.model_derived_context
    assert not fusion.signals
    assert {c.model_kind: c.status for c in fusion.coverage} == {
        "network_classifier": "not_run",
        "network_anomaly": "not_run",
        "authentication_anomaly": "insufficient_input",
    }


def test_file_source_preserves_non_synthetic_provenance(tmp_path):
    event = next(LocalJSONLSource(FIXTURE).events()).model_dump(mode="json")
    event.update(source="local-file:operator-export", synthetic=False, subject="local-host")
    source = tmp_path / "input.jsonl"
    source.write_text(json.dumps(event) + "\n")
    composition = desktop.initialize(desktop.prepare(tmp_path / "data"))
    assert asyncio.run(desktop.replay(composition, LocalJSONLSource(source))) == 0
    typed = TypeAdapter(Event).validate_python(event)
    identity = composition.service.ingest(typed).incident_id
    receipt = composition.service.ingestion.load(identity)
    assert receipt.event == typed and not receipt.event.synthetic
    assert receipt.event.source == "local-file:operator-export"


@pytest.mark.parametrize("content", [b'{"password":"DO-NOT-PRINT"}\n', b"\xff\xfe\n", b"{broken\n"])
def test_invalid_input_sanitized_and_valid_following_event_processed(tmp_path, content, capsys):
    source = tmp_path / "input.jsonl"
    source.write_bytes(content + FIXTURE.read_bytes().splitlines(keepends=True)[0])
    items = list(LocalJSONLSource(source).events())
    assert isinstance(items[0], InputIssue) and len(items) == 2
    composition = desktop.initialize(desktop.prepare(tmp_path / "data"))
    assert asyncio.run(desktop.replay(composition, LocalJSONLSource(source))) == 1
    diagnostic = capsys.readouterr().err
    assert "line 1" in diagnostic and "DO-NOT-PRINT" not in diagnostic
    assert composition.service.workflow(
        composition.service.ingest(items[1]).incident_id
    ).waiting_for_human


def test_limits_regular_file_symlinks_and_traversal(tmp_path, monkeypatch):
    from soc_agent import local_events

    source = tmp_path / "input.jsonl"
    source.write_bytes(b"x" * (local_events.MAX_EVENT_BYTES + 1))
    with pytest.raises(LocalSourceError):
        list(LocalJSONLSource(source).events())
    monkeypatch.setattr(local_events, "MAX_FILE_BYTES", 1)
    with pytest.raises(LocalSourceError):
        list(LocalJSONLSource(FIXTURE).events())
    for path in (Path("relative.jsonl"), tmp_path / ".." / "input.jsonl"):
        with pytest.raises(LocalSourceError):
            LocalJSONLSource(path)
    with pytest.raises(LocalSourceError):
        list(LocalJSONLSource(tmp_path).events())


def test_actual_file_source_symlink_rejected(tmp_path):
    source = tmp_path / "input.jsonl"
    source.write_bytes(b"synthetic")
    link = tmp_path / "redirect"
    make_test_symlink(link, source)
    with pytest.raises(LocalSourceError):
        LocalJSONLSource(link)


def test_line_limit_including_blank_lines_and_eof(tmp_path, monkeypatch):
    from soc_agent import local_events

    source = tmp_path / "input.jsonl"
    source.write_text("\n\n\n")
    monkeypatch.setattr(local_events, "MAX_LINES", 2)
    with pytest.raises(LocalSourceError):
        list(LocalJSONLSource(source).events())
    source.write_text("")
    assert list(LocalJSONLSource(source).events()) == []


def test_private_directory_and_writer_lock_cleanup(tmp_path):
    with pytest.raises(LocalSourceError):
        desktop.prepare(Path("relative"))
    foreign = tmp_path / "foreign"
    from soc_agent.review.persistence.secure_storage import create_private_directory

    # Test foreign data rejection after satisfying the real host storage contract.
    create_private_directory(foreign)
    (foreign / "keep.txt").write_text("existing")
    with pytest.raises(LocalSourceError):
        desktop.prepare(foreign)
    directory = desktop.prepare(tmp_path / "data")
    with pytest.raises(KeyboardInterrupt), desktop.writer_lock(directory):
        with pytest.raises(LocalSourceError), desktop.writer_lock(directory):
            pass
        raise KeyboardInterrupt
    assert not (directory / "desktop-writer.lock").exists()
    assert (foreign / "keep.txt").read_text() == "existing"


def test_cli_offline_eof_shutdown(tmp_path, monkeypatch, capsys):
    directory = tmp_path / "desktop"
    monkeypatch.setattr(
        "sys.argv", ["soc_agent.desktop", "--directory", str(directory), "--input", str(FIXTURE)]
    )
    assert desktop.main() == 0
    assert not (directory / "desktop-writer.lock").exists()
    assert "OFFLINE scripted advisory" in capsys.readouterr().out


def test_requested_provider_and_bad_package_fail_closed(tmp_path, monkeypatch, capsys):
    for name in ("SOC_LLM_BASE_URL", "SOC_LLM_API_KEY", "SOC_LLM_MODEL"):
        monkeypatch.delenv(name, raising=False)
    for extra in (
        ["--real-llm"],
        ["--auth-package", "missing"],
        ["--auth-package", "missing", "--manifest-digest", "0" * 64],
    ):
        directory = tmp_path / "not-created"
        monkeypatch.setattr(
            "sys.argv",
            ["soc_agent.desktop", "--directory", str(directory), "--input", str(FIXTURE), *extra],
        )
        assert desktop.main() == 1
        assert not directory.exists()
    assert "no fallback" in capsys.readouterr().err


def test_graceful_cli_interrupt_releases_lock(tmp_path, monkeypatch, capsys):
    async def interrupted(*args):
        raise KeyboardInterrupt

    monkeypatch.setattr(desktop, "replay", interrupted)
    directory = tmp_path / "data"
    monkeypatch.setattr(
        "sys.argv", ["soc_agent.desktop", "--directory", str(directory), "--input", str(FIXTURE)]
    )
    assert desktop.main() == 0
    assert not (directory / "desktop-writer.lock").exists()
    assert "checkpoint preserved" in capsys.readouterr().err


def test_explicit_model_analysis_injection(tmp_path, packages):
    from soc_agent.security_ai.model_analysis import PackagedAnalysis

    directory = desktop.prepare(tmp_path / "data")
    source_composition = desktop.initialize(directory)
    analysis = PackagedAnalysis(source_composition.service.ingestion, packages)
    seen = []

    async def callback(state):
        seen.append(state.incident_id)
        return await analysis(state)

    composition = desktop.initialize(directory, model_analysis=callback)
    assert asyncio.run(desktop.replay(composition, LocalJSONLSource(FIXTURE))) == 0
    assert len(seen) == 2
    assert composition.service.dashboard_security_ai(lambda _: True).retained_signal_count == 3
    with pytest.raises(ValueError):
        desktop.initialize(directory, packages=packages, model_analysis=callback)


@pytest.mark.parametrize(
    "failure,category",
    (
        (AttributeError("DO-NOT-PRINT platform path"), "platform_api_unavailable"),
        (ValueError("DO-NOT-PRINT manifest"), "validation"),
        (ImportError("DO-NOT-PRINT dependency"), "dependency_unavailable"),
        (OSError("DO-NOT-PRINT filesystem path"), "file_access"),
    ),
)
def test_startup_package_failure_reports_only_fixed_stage_and_category(
    tmp_path, monkeypatch, capsys, failure, category
):
    monkeypatch.setattr(
        desktop, "load_package", lambda *args, **kwargs: (_ for _ in ()).throw(failure)
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "soc_agent.desktop",
            "--directory",
            str(tmp_path / "data"),
            "--input",
            str(FIXTURE),
            "--auth-package",
            "sensitive-path",
            "--manifest-digest",
            "0" * 64,
        ],
    )
    assert desktop.main() == 1
    diagnostic = capsys.readouterr().err
    assert f"[package_auth:{category}]" in diagnostic
    assert "DO-NOT-PRINT" not in diagnostic and "sensitive-path" not in diagnostic
    assert not (tmp_path / "data").exists()

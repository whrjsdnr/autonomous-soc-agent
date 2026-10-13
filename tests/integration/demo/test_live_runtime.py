"""Offline observable runtime tests: no provider or privileged execution."""

import asyncio
import os
from io import StringIO
from uuid import uuid4

import pytest

from soc_agent.demo.command_center import manifest, observation_app, seed
from soc_agent.demo.local_server import read_response
from soc_agent.demo.scenarios import scenario_event
from soc_agent.live import consume, initialize, process_event
from soc_agent.llm.openai_compatible import OpenAICompatibleClient


@pytest.fixture(autouse=True)
def no_provider(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("No provider requests in runtime tests")

    monkeypatch.setattr(OpenAICompatibleClient, "_post", forbidden)


def test_runtime_fixture_uses_verified_storage_without_changing_linux_tmp_path(
    live_runtime_directory, tmp_path
):
    from soc_agent.review.persistence.secure_storage import validate_directory

    if os.name == "nt":
        from soc_agent.review.persistence.windows_storage import (
            ADMINISTRATORS,
            FULL_ACCESS,
            SYSTEM,
            NativeWin32,
        )

        assert live_runtime_directory.parent == tmp_path
        api = NativeWin32()
        with api.hold(str(live_runtime_directory)) as handle:
            value = api.snapshot(handle)
        assert value.owner == api.user and value.protected and not value.reparse
        assert {ace.sid for ace in value.aces} == {api.user, SYSTEM, ADMINISTRATORS}
        assert all(
            ace.kind == 0 and ace.mask == FULL_ACCESS and ace.flags == 3 for ace in value.aces
        )
    else:
        assert live_runtime_directory == tmp_path
    validate_directory(live_runtime_directory)


def test_live_same_database_dynamic_visibility_and_restart(live_runtime_directory, monkeypatch):
    service = initialize(live_runtime_directory)
    app, observer = observation_app(live_runtime_directory)
    assert asyncio.run(read_response(app, observer, "/dashboard"))[0] == 200
    revisions = []
    for name, severity in (("a", "info"), ("b", "high")):
        result = asyncio.run(
            process_event(
                service, live_runtime_directory, scenario_event(name), notify=revisions.append
            )
        )
        saved = service.checkpoint(result.incident_id)
        assert result.waiting_for_human
        assert saved.artifacts.assessment.threat_assessment.severity == severity
        assert saved.artifacts.decision is not None
        assert saved.artifacts.execution_intent_id is None
        assert len(service.incident(result.incident_id).state.evidence) == 1
        assert "Repeated investigation intent" in result.reason
        before = result.checkpoint_revision
        replay = asyncio.run(
            process_event(
                initialize(live_runtime_directory),
                live_runtime_directory,
                scenario_event(name),
                notify=lambda _: None,
            )
        )
        assert replay.checkpoint_revision == before
        status, headers, body = asyncio.run(
            read_response(app, observer, f"/dashboard/incidents/{result.incident_id}")
        )
        assert status == 200
        assert b"content-security-policy" in headers
        assert b"LIVE LOCAL RUNTIME" in body and b"AUTO REFRESH" in body
        assert b'http-equiv="refresh" content="3"' in body
        assert observer._credential.encode() not in body
    assert len(revisions) > 4
    assert len(manifest(live_runtime_directory).incidents) == 2
    assert asyncio.run(read_response(app, observer, f"/dashboard/incidents/{uuid4()}"))[0] == 403
    view = service.dashboard_self_improvement(lambda _: True)
    assert view.experience_count == 2 and view.candidate_count == 0
    assert view.active.state == "NONE"
    assert view.active.runtime_consumption == "UNKNOWN"
    from tests.integration.demo.test_command_center import digest

    read_service = app.startup()
    before = digest(read_service)

    def forbidden(*args, **kwargs):
        raise AssertionError("Dashboard must not schedule work or inference")

    monkeypatch.setattr(read_service, "runtime_factory", forbidden)
    monkeypatch.setattr(read_service, "step", forbidden)
    for path in (
        "/dashboard",
        "/dashboard/governance",
        "/dashboard/security-ai",
        "/dashboard/self-improvement",
    ):
        assert asyncio.run(read_response(app, observer, path))[0] == 200
    assert digest(read_service) == before
    with service.store.database.transaction(write=False) as connection:
        for table in ("analyst_feedback", "improvement_candidates", "improvement_review_records"):
            assert connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0


def test_snapshot_is_not_live_and_cannot_be_converted(live_runtime_directory):
    asyncio.run(seed(live_runtime_directory, "a"))
    with pytest.raises(ValueError, match="cannot be converted"):
        initialize(live_runtime_directory)
    app, observer = observation_app(live_runtime_directory)
    body = asyncio.run(read_response(app, observer, "/dashboard"))[2]
    assert b"DEMO / SYNTHETIC" in body
    assert b'http-equiv="refresh"' not in body


def test_real_mode_missing_config_fails_before_directory(live_runtime_directory, monkeypatch):
    for name in ("SOC_LLM_BASE_URL", "SOC_LLM_MODEL", "SOC_LLM_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    target = live_runtime_directory / "not-created"
    with pytest.raises(ValueError, match="CONFIGURATION"):
        initialize(target, real_llm=True)
    assert not target.exists()


def test_bad_event_rejected_and_independent_event_can_continue(live_runtime_directory):
    service = initialize(live_runtime_directory)
    invalid = scenario_event("a").model_copy(update={"synthetic": False})
    with pytest.raises(ValueError, match="synthetic"):
        asyncio.run(process_event(service, live_runtime_directory, invalid))
    assert not manifest(live_runtime_directory).incidents
    stream = StringIO("not-json\n" + scenario_event("a").model_dump_json() + "\n")
    assert asyncio.run(consume(service, live_runtime_directory, stream)) == 1
    assert len(manifest(live_runtime_directory).incidents) == 1


def test_model_analysis_injection_uses_existing_runtime(live_runtime_directory):
    from soc_agent.security_ai.fusion import ModelAvailability, MultiModelFusionEngine

    calls = []

    async def analysis(state):
        calls.append(state.incident_id)
        return MultiModelFusionEngine((), ("authentication_anomaly",)).fuse(
            incident_id=state.incident_id,
            inputs=(),
            unavailable=(
                ModelAvailability(
                    model_kind="authentication_anomaly", status="not_run", reason="Not configured"
                ),
            ),
        )

    service = initialize(live_runtime_directory, model_analysis=analysis)
    result = asyncio.run(
        process_event(service, live_runtime_directory, scenario_event("a"), notify=lambda _: None)
    )
    assert calls == [result.incident_id]
    assert service.checkpoint(result.incident_id).artifacts.assessment is not None


@pytest.mark.parametrize("already_locked", (False, True))
def test_cli_holds_single_writer_lock_during_consume(
    live_runtime_directory, monkeypatch, capsys, already_locked
):
    from contextlib import nullcontext

    from soc_agent import live
    from soc_agent.review.persistence.secure_storage import (
        StorageSecurityError,
        create_private_directory,
    )
    from soc_agent.runtime_lock import exclusive_runtime_lock

    directory = live_runtime_directory / "cli-private"
    create_private_directory(directory)
    lock = directory / "runtime.lock"
    monkeypatch.setattr("sys.argv", ["soc_agent.live", "--directory", str(directory)])
    monkeypatch.setattr(live, "initialize", lambda *args, **kwargs: object())
    entered = []

    async def consume(service, directory, stream):
        entered.append(True)
        with pytest.raises((OSError, StorageSecurityError)):
            with exclusive_runtime_lock(lock):
                pytest.fail("Concurrent writer entered while CLI was consuming")
        return 0

    monkeypatch.setattr(live, "consume", consume)
    with exclusive_runtime_lock(lock) if already_locked else nullcontext():
        assert live.main() == int(already_locked)
    assert bool(entered) is not already_locked
    with exclusive_runtime_lock(lock):
        pass
    if already_locked:
        assert "no fallback" in capsys.readouterr().err

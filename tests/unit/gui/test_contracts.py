"""GUI request boundary and display contracts, no display/server/provider required."""

import pytest
from pydantic import ValidationError

from soc_agent.gui.backend import Backend, GUIConfig
from soc_agent.gui.queries import display_data


@pytest.fixture
def backend(tmp_path):
    return Backend(
        GUIConfig(data_directory=tmp_path / "gui", runtime_directory=tmp_path / "offline")
    )


@pytest.mark.asyncio
async def test_offline_and_external_close_never_write_runtime(backend, tmp_path):
    assert (await backend.dashboard())["runtime_state"] == "OFFLINE"
    assert (await backend.close())["external_runtime_untouched"]
    assert not (tmp_path / "offline").exists()


@pytest.mark.asyncio
async def test_failed_status_not_stale_ready_or_fake_zero(backend, monkeypatch):
    from soc_agent.gui import backend as module

    backend.runtime.mkdir(mode=0o700)
    (backend.runtime / "monitor.sqlite").touch()

    def broken_status(*args):
        raise ValueError("password=must-never-display")

    monkeypatch.setattr(module, "status", broken_status)
    value = await backend.dashboard()
    assert value["runtime_state"] == "UNKNOWN" and value["readiness"] == "NOT_READY"
    assert value["queue_backlog"] is None and "must-never-display" not in str(value)


@pytest.mark.parametrize(
    "payload", [{"actor": "root"}, {"candidate_id": "x" * 10000}, {"expected_digest": "invalid"}]
)
@pytest.mark.asyncio
async def test_actor_forgery_and_oversized_inputs_rejected_before_transport(backend, payload):
    with pytest.raises(ValidationError):
        await backend.operator("approve", **payload)


@pytest.mark.asyncio
async def test_arbitrary_command_not_allowed(backend):
    with pytest.raises(ValueError, match="GUI_COMMAND_NOT_ALLOWED"):
        await backend.operator("shell", candidate_id="0" * 64)


@pytest.mark.asyncio
async def test_unknown_scenario_is_not_a_path(backend):
    with pytest.raises(ValueError, match="UNKNOWN_SCENARIO"):
        await backend.scenario("../../sources.sqlite")
    assert not (backend.directory / "scenarios").exists()


def test_catalog_is_exactly_existing_twelve(backend):
    rows = backend.scenario_catalog()
    assert [r["id"] for r in rows] == [f"S{i:02}" for i in range(1, 13)]
    assert all(r["origin"] == "FIXTURE" for r in rows)


def test_secrets_and_raw_source_hidden():
    data = display_data(
        {
            "raw_data": "host-secret",
            "api_key": "sensitive-value",
            "advisory_assessment": "password=private-value",
            "json": '{"api_key":"private-value"}',
        }
    )
    assert "private-value" not in str(data) and "host-secret" not in str(data)
    assert data["raw_data"] == "[REDACTED]"


def test_improvement_view_rejects_unknown_query_before_store_access(tmp_path):
    from soc_agent.gui.queries import improvement_records

    with pytest.raises(ValueError, match="UNKNOWN_IMPROVEMENT_VIEW"):
        improvement_records(tmp_path / "nonexistent", "shell")
    assert not (tmp_path / "nonexistent").exists()


@pytest.mark.asyncio
async def test_source_never_adopted_or_reset(backend, tmp_path):
    existing = tmp_path / "mine"
    existing.mkdir()
    sentinel = existing / "data"
    sentinel.write_text("USER")
    with pytest.raises(ValueError):
        await backend.initialize_runtime(existing, 5, 3, "READ_ONLY")
    assert sentinel.read_text() == "USER"


@pytest.mark.asyncio
async def test_transport_timeout_unknown_not_retry(backend, monkeypatch):
    from soc_agent.gui import backend as module

    calls = []

    async def timeout(*args, **kwargs):
        calls.append(1)
        raise TimeoutError()

    monkeypatch.setattr(module, "operator_request", timeout)
    result = await backend.operator("approve", candidate_id="0" * 64, expected_digest="1" * 64)
    assert result["status"] == "UNKNOWN" and len(calls) == 1


@pytest.mark.asyncio
async def test_model_query_does_not_infer(backend, monkeypatch):
    from soc_agent.security_ai.external import inference

    def no_inference(*args, **kwargs):
        pytest.fail("Inventory must not predict")

    monkeypatch.setattr(inference, "infer", no_inference)
    result = await backend.models()
    assert len(result["packages"]) == 3
    assert all(
        p["demo_inference"] == "UNKNOWN" and p["operational_input"] == "NOT_INFERABLE"
        for p in result["packages"]
    )
    service = backend.model_service
    with service.store.database.transaction(write=False) as c:
        before = tuple(c.iterdump())
    await backend.models()
    with service.store.database.transaction(write=False) as c:
        assert tuple(c.iterdump()) == before

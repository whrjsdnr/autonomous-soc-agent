"""An attached authentication store is observed without starting a host collector."""

from uuid import UUID

import pytest

from soc_agent.continuous.models import ContinuousConfig
from soc_agent.continuous.service import ContinuousRuntime
from soc_agent.continuous.store import Store
from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.service import initialize


@pytest.mark.asyncio
async def test_existing_authentication_store_status_and_cached_control(tmp_path, monkeypatch):
    auth = tmp_path / "authentication"
    initialize(
        auth,
        RuntimeConfig(
            incident_id=UUID(int=9),
            repeated_failures=5,
            multiple_accounts=3,
            assessment_mode="READ_ONLY",
        ),
    )
    directory = tmp_path / "continuous"
    input_file = tmp_path / "empty.jsonl"
    input_file.write_text("")
    Store.create(
        directory,
        ContinuousConfig(
            source="JSONL_REPLAY",
            input_file=input_file,
            input_sha256="0" * 64,
            authentication_runtime=auth,
        ),
    )
    runtime = ContinuousRuntime(directory)
    observed = await runtime.observed_snapshot()
    assert observed["authentication"]["runtime_state"] == "STOPPED"
    assert observed["authentication"]["assessment_mode"] == "READ_ONLY"
    assert observed["authentication"]["real_llm_enabled"] is False
    assert observed["authentication"]["collector_state"] == "NOT_STARTED"

    def no_storage(*_):
        pytest.fail("Control snapshot must use the supplied authentication cache")

    monkeypatch.setattr("soc_agent.linux_runtime.__main__.status", no_storage)
    assert (
        runtime.snapshot(authentication=dict(runtime.cached_authentication))["authentication"]
        == (observed["authentication"])
    )


def test_gui_uses_attached_authentication_runtime_state():
    from soc_agent.gui.continuous_projection import availability

    value = availability(dict(authentication=dict(runtime_state="RUNNING")), [])
    assert value["authentication"] == "RUNNING"
    assert availability({}, [])["authentication"] == "NOT_ATTACHED"

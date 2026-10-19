"""No research initialization or model load during the operator idle path."""

import pytest

from soc_agent.gui.backend import Backend, GUIConfig
from soc_agent.gui.production import event_rows


@pytest.mark.asyncio
async def test_idle_status_and_close_do_not_create_developer_owners(tmp_path):
    owner = Backend(GUIConfig(data_directory=tmp_path / "gui"))
    for _ in range(3):
        value = await owner.production_status()
        assert value["backend_owners"] == []
        assert not value["collection_live"] and not value["listener_ready"]
        assert value["operational_gate"] == "OPERATIONAL_INFERENCE_BLOCKED"
    assert owner.model_service is None
    await owner.close()
    assert owner._owners == {} and owner.closed
    with pytest.raises(ValueError, match="CLOSED"):
        _ = owner.total_monitoring


def test_lazy_owners_are_singletons_and_no_models_are_started(tmp_path):
    owner = Backend(GUIConfig(data_directory=tmp_path / "gui"))
    total = owner.total_monitoring
    assert total is owner.total_monitoring
    assert list(owner._owners) == ["total_monitoring"]
    assert total.task is None and total.demo is None and total.capture is None


def test_event_search_preserves_withdrawn_status_and_source():
    record = {
        "receipt": {"profile": "quality", "score": 0.9, "origin": "FIXTURE"},
        "advisory_current": "WITHDRAWN_RESEARCH_ONLY",
        "investigation": {"status": "ASSESSED_READ_ONLY"},
    }
    rows = event_rows({"research": {"records": [record]}}, "fixture")
    assert len(rows) == 1 and rows[0][1] is record
    assert "WITHDRAWN_RESEARCH_ONLY" in rows[0][0]
    assert not event_rows({"research": {"records": [record]}}, "NATIVE_AF_PACKET")

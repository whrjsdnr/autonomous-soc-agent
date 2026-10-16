"""WSLg display of actual research receipts on explicit synthetic FIXTURE input."""

import asyncio
import time
import tkinter as tk

import pytest

from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import Backend, GUIConfig
from soc_agent.security_ai.research.live_service import LiveResearch
from tests.gui_wslg_checks import close, idle
from tests.gui_wslg_checks import (
    release_display_objects_on_creator_thread as release_display_objects_on_creator_thread,
)
from tests.live_flow_eligibility_support import persisted_fixture
from tests.research_adapter_support import research_paths


@pytest.mark.asyncio
async def test_actual_fixture_model_receipts_eligibility_investigation_and_gui(
    tmp_path, monkeypatch
):
    paths = research_paths()
    monkeypatch.syspath_prepend(str((paths.producer_source or paths.ml) / "src"))
    monkeypatch.setattr("soc_agent.security_ai.research.adapter.defaults", lambda: paths)
    service, monitor, session, _, _ = await persisted_fixture(tmp_path, "IDLE_TIMEOUT")
    service.directory = tmp_path
    service.demo = LiveResearch(tmp_path / "demo", paths=paths)
    await service.demo.start()
    service.collection_done.set()
    await service._consume()
    research = service.demo.snapshot()
    await service.demo.stop()
    assert len(research["records"]) == 2
    assert all(r["receipt"]["origin"] == "FIXTURE" for r in research["records"])
    value = {
        "state": "FIXTURE_RESEARCH_RETAINED",
        "collection_live": False,
        "listener_ready": False,
        "prepare_active": False,
        "capture_permission": "NO_CAPTURE_SYNTHETIC_FIXTURE",
        "operational_gate": "OPERATIONAL_INFERENCE_BLOCKED",
        "session_id": str(session),
        "input_origin": "FIXTURE",
        "last_error": None,
        "network": {**monitor.metrics, "packets_per_second": None, "flows_per_minute": None},
        "flow_eligibility": service.flow_eligibility(),
        "research": research,
    }

    async def selected_fixture(self):
        # Presentation contract from actual persisted Fixture results, not generated scores.
        return value

    monkeypatch.setattr(Backend, "live_status", selected_fixture)
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui"))
    errors = []
    root.report_callback_exception = lambda *args: errors.append(args[0].__name__)
    try:
        await idle(root, app)
        app.navigate("Live Network")
        deadline = time.monotonic() + 10
        while len(app.current_records) != 2:
            if time.monotonic() >= deadline:
                raise AssertionError("FIXTURE_RECEIPTS_NOT_RENDERED")
            root.update()
            await asyncio.sleep(0.02)
        view = app.live_view
        assert "FIXTURE_RESEARCH_RETAINED" in view.headline.get()
        assert "Eligible (timeout only) 1" in view.metrics.get()
        assert "Excluded 1" in view.metrics.get() and "Finalization VERIFIED" in view.metrics.get()
        assert "quality: IDLE / confirmed 1" in view.metrics.get()
        assert "edge: IDLE / confirmed 1" in view.metrics.get()
        assert view.traffic.source == "FIXTURE" and not view.command
        view.show_record(app.current_records[0])
        root.update()
        assert (
            app.last_details["research_record"]["investigation"]["status"] == "ASSESSED_READ_ONLY"
        )
        view.show_record(app.current_records[0], mode="audit")
        root.update()
        assert app.last_details["research_view"] == "audit"
        assert app.last_details["audit_integrity"] == "VERIFIED"
        assert not errors
    finally:
        await close(root, app)
        await service.demo.stop()

"""Actual WSLg selector; default remains legacy and unapproved selections cannot launch."""

import asyncio
import tkinter as tk

import pytest

from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import GUIConfig
from soc_agent.security_ai.operational.network_capture.calibrated_session import verify_bundle
from tests.gui_wslg_checks import close, idle
from tests.gui_wslg_checks import (
    release_display_objects_on_creator_thread as release_display_objects_on_creator_thread,
)
from tests.research_adapter_support import research_paths


@pytest.mark.asyncio
async def test_gui_candidate_unapproved_state_stop_restart_and_scope_binding(tmp_path, monkeypatch):
    monkeypatch.setattr("soc_agent.security_ai.research.adapter.defaults", research_paths)
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path))

    async def forbidden(*args, **kwargs):
        pytest.fail("UNAPPROVED PRIVILEGE LAUNCH")

    app.worker.backend.total_auth.launcher = forbidden
    try:
        await idle(root, app)
        app.navigate("Total Monitoring")
        await idle(root, app)
        assert app.live_view.rate_policy.get() == "legacy"
        app.live_view.rate_policy.set("performance-v2")
        app.live_view.start()
        await idle(root, app)
        result = await asyncio.wrap_future(app.worker.submit("total_status"))
        app.live_view.render(result)
        assert not result["collection_live"]
        text = app.live_view.metrics.get()
        assert "Policy performance-v2" in text and "Approval APPROVAL_REQUIRED" in text
        assert "Configured rate 512" in text and "burst 512" in text
        assert "token balance UNKNOWN" in text and "DNS9 BLOCKED" in text
        assert "New Total helper approval required" in app.notice.get()
        assert result["network"]["inference_count"] == 0
        with pytest.raises(ValueError, match="SCOPE_EXPLICIT_APPROVAL_REQUIRED"):
            await asyncio.wrap_future(
                app.worker.submit(
                    "total_authenticate",
                    result["session_id"],
                    verify_bundle()["calibrated_helper.py"],
                )
            )
        first = result["session_id"]
        app.call("total_stop", callback=app.live_view.render)
        await idle(root, app)
        app.live_view.start()
        await idle(root, app)
        again = await asyncio.wrap_future(app.worker.submit("total_status"))
        assert again["session_id"] != first and not again["collection_live"]
        app.call("total_stop", callback=app.live_view.render)
        await idle(root, app)
    finally:
        await close(root, app)


@pytest.fixture(autouse=True)
def controlled_fixture_headroom(monkeypatch):
    # Policy behavior test only: not a Native resource-readiness assertion.
    monkeypatch.setattr(
        "soc_agent.security_ai.operational.network_capture.calibrated_policy.hardware",
        lambda: dict(affinity_cpus=4, available_memory_bytes=8 * 1024**3),
    )

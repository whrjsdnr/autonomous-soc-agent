"""Actual Tk displaying preserved real Native evidence. No new analysis or API."""

import os
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import Desktop
from soc_agent.security_ai.offline_workflow import verify_result
from tests.gui_wslg_checks import (  # noqa:F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)


@pytest.mark.asyncio
async def test_preserved_native_incident_investigation_audit_and_reconnect(tmp_path):
    selected = os.environ.get("SOC_RC_NATIVE_RESULT")
    if not selected:
        pytest.skip("Explicit preserved Native result is required; never use a fixture as Native")
    directory = Path(selected)
    result = verify_result(directory)
    assert len(result.inference) == 2
    assert all(r.receipt["origin"] == "REAL_NATIVE" for r in result.inference)
    assert result.llm_mode == "SCRIPTED" and result.external_provider_calls == 0
    for attempt in (1, 2):
        root = tk.Tk()
        app = Desktop(
            root, GUIConfig(data_directory=tmp_path / f"gui-{attempt}", analysis_result=directory)
        )
        try:
            await idle(root, app)
            assert "RETAINED_NATIVE / not live capture" in app.analysis_summary.cget("text")
            assert str(result.incident_id) in app.analysis_summary.cget("text")
            assert len(app.analysis_predictions.get_children()) == 2
            assert "COMPLETED_READ_ONLY" in app.analysis_investigation.get("1.0", "end")
            assert "feature_fingerprint" in app.analysis_detail.get("1.0", "end")
            app.navigate("Dashboard")
            await idle(root, app)
            assert "Continuous NOT_ATTACHED" in app.continuous_overview.cget("text")
            app.navigate("System")
            await idle(root, app)
            assert "INDEPENDENT CONTINUOUS SERVICE" in app.system.get("1.0", "end")
            assert not app.worker.backend.analysis_service.snapshot()["worker_running"]
        finally:
            await close(root, app)

"""Explicit actual WSLg + native models. No provider API or OS response."""

import asyncio
import gc
import json
import os
import time
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import GUIConfig
from tests.gui_visual_checks import screenshot_sizes
from tests.gui_wslg_checks import close, idle
from tests.gui_wslg_checks import (
    release_display_objects_on_creator_thread as release_display_objects_on_creator_thread,
)


async def startup(root, app):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        root.update()
        await asyncio.sleep(0.02)
        if app.ai_environment["status"] != "UNKNOWN" and not app.busy:
            return
    raise AssertionError("AI automatic environment check timed out")


@pytest.mark.asyncio
async def test_default_launch_native_oneclick_and_relaunch(tmp_path, monkeypatch):
    monkeypatch.setattr("soc_agent.gui.app.messagebox.askyesno", lambda *a, **kw: True)
    # No artifact/interpreter arguments or environment variables are supplied.
    for name in ("SOC_EXTERNAL_ARTIFACT_ROOT", "SOC_EXTERNAL_INFERENCE_PYTHON"):
        monkeypatch.delenv(name, raising=False)
    results = []
    for run in range(2):
        root = tk.Tk()
        app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui"))
        try:
            await startup(root, app)
            assert app.ai_environment["status"] == "READY", app.notice.get()
            assert app.last_probe is None  # startup has NOT run a model
            app.navigate("Security AI Models")
            await idle(root, app)
            assert all(p["demo_inference"] == "UNKNOWN" for p in app.current_records[:3])
            if run == 0:
                await screenshot_sizes(root, app, "ai-environment-ready")
            app.model_probe()
            assert app.busy
            app.model_probe()  # duplicate click must not start another inference
            assert "running" in app.notice.get()
            ticks = 0
            end = time.monotonic() + 180
            while app.busy and time.monotonic() < end:
                root.update()
                ticks += 1
                await asyncio.sleep(0.02)
            await idle(root, app)
            result = app.last_probe
            assert result is not None, app.notice.get()
            assert result["status"] == "VERIFIED"
            assert len(result["models"]) == 3 and result["correlation_groups"] == 2
            assert result["operational_input"] == "NOT_INFERABLE"
            assert result["action_policy"] == "WRITE_DENIED"
            assert result["llm_provider_calls"] == result["os_security_changes"] == 0
            assert all(m["status"] == "VALIDATED_FOR_ADVISORY" for m in result["models"])
            assert all(m["inference_latency_ms"] >= 0 for m in result["models"])
            assert all("VERIFIED (prior Fixture)" in str(row) for row in app.model_cards[:3])
            assert ticks > 10  # actual event loop kept processing during child inference
            assert len(app.latency_chart.find_withtag("latency-bar")) == 3
            await screenshot_sizes(root, app, "ai-native-results" if run == 0 else "ai-relaunch")
            results.append({k: v for k, v in result.items() if k != "inventory"})
        finally:
            await close(root, app)
        del app, root
        gc.collect()  # finalize the previous Tcl interpreter on its creator thread
    assert results[0]["context_digest"] != results[1]["context_digest"]
    # Independent fixture runs; same actual model class outputs, different incident identity.
    assert [m["output"].get("class_id") for m in results[0]["models"]] == [
        m["output"].get("class_id") for m in results[1]["models"]
    ]
    output = Path(os.getenv("SOC_ONECLICK_RESULT", str(tmp_path / "oneclick-result.json")))
    output.write_text(json.dumps(results, indent=2))


@pytest.mark.asyncio
async def test_demo_error_visible_and_retry_not_stuck(tmp_path, monkeypatch):
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui"))
    monkeypatch.setattr("soc_agent.gui.app.messagebox.askyesno", lambda *a, **kw: True)
    try:
        await startup(root, app)
        app.navigate("Security AI Models")
        await idle(root, app)
        original = app.worker.backend.fixture_probe

        async def fail():
            raise ValueError("password=never-display-this-secret")

        monkeypatch.setattr(app.worker.backend, "fixture_probe", fail)
        app.model_probe()
        await idle(root, app)
        assert "BLOCKED" in app.notice.get()
        assert "never-display" not in app.notice.get()
        assert "VALIDATION_FAILED" in app.ai_status.get()
        assert app.last_probe is None and not app.busy
        assert all("UNKNOWN" in str(row) for row in app.model_cards[:3])
        assert not app.latency_chart.models
        monkeypatch.setattr(app.worker.backend, "fixture_probe", original)
        app.refresh()
        await idle(root, app)
        assert app.ai_environment["status"] == "READY"
    finally:
        await close(root, app)

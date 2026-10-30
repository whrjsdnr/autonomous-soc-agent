"""Real Tk showing FAKE_HTTP timeout evidence; no Native/API/model authority."""

import tkinter as tk

import pytest

from soc_agent.continuous.store import Store
from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import Desktop
from tests.gui_screen_capture import capture
from tests.gui_wslg_checks import (  # noqa: F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)
from tests.integration.test_continuous_api_investigation import (
    test_assessment_timeout_keeps_plan_cost_uncertainty_checkpoint_and_gui as prepare_failure,
)


@pytest.mark.asyncio
async def test_gui_timeout_unknown_cost_failed_cleanup_and_reconnect(tmp_path, monkeypatch):
    await prepare_failure(tmp_path, monkeypatch)
    runtime = tmp_path / "runtime"
    store = Store(runtime)
    store.update(
        dict(
            state="STOPPED",
            source="JSONL_REPLAY",
            cleanup="UNVERIFIED",
            orchestration=store.state()["orchestration"],
        )
    )
    before = store.state()
    for index in (1, 2):
        root = tk.Tk()
        app = Desktop(
            root, GUIConfig(data_directory=tmp_path / f"gui-{index}", continuous_directory=runtime)
        )
        try:
            await idle(root, app)
            app.navigate("Continuous")
            await idle(root, app)
            text = app.continuous_summary.cget("text")
            assert "JSONL_REPLAY" in text and "Native live: False" in text
            assert "Runtime cleanup: UNVERIFIED" in text
            assert "total estimate=UNKNOWN" in text and "LLMTimeoutError" in text
            assert len(app.continuous_tasks.get_children()) == 1
            detail = app.continuous_detail.get("1.0", "end")
            assert "FAILED" in detail and "UNKNOWN_REQUIRES_REVIEW" in detail
            assert "completed" in detail  # Retained successful read-only tool.
            capture(root, tmp_path / f"fake-http-timeout-gui-{index}.png")
        finally:
            await close(root, app)
    assert store.state() == before  # GUI never rewrites cleanup or retries work.

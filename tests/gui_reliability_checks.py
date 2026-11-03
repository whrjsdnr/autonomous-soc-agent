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


@pytest.mark.asyncio
async def test_gui_control_alive_data_stalled_and_reconnect(tmp_path):
    import time

    from tests.unit.continuous.test_runtime import make
    from tests.unit.continuous.test_storage_control_isolation import control_snapshot

    directory, store = make(tmp_path)
    for index in (1, 2):
        value = control_snapshot(
            state="DEGRADED",
            last_error="CONTINUOUS_DATA_PROGRESS_STALLED",
            component_health=dict(
                storage=dict(
                    pending=True, operation="audit_flush", started_monotonic=time.monotonic() - 6
                ),
                data_progress=dict(active=True, operation="window_seal"),
                publication=dict(last_seconds=0.001, error=None),
            ),
        )
        value["control"]["data_stalled"] = True
        store.update(value)
        root = tk.Tk()
        app = Desktop(
            root,
            GUIConfig(
                data_directory=tmp_path / f"control-gui-{index}", continuous_directory=directory
            ),
        )
        try:
            await idle(root, app)
            app.navigate("Continuous")
            await idle(root, app)
            text = app.continuous_summary.cget("text")
            assert "DEGRADED" in text and "DATA_PROGRESS_STALLED" in text
            assert "soc-runtime-control:v1" in text and "window_seal" in text
            assert "audit_flush" in text and "Publication:" in text
            assert "Native live: False" in text
        finally:
            await close(root, app)
        assert store.state()["last_error"] == "CONTINUOUS_DATA_PROGRESS_STALLED"


@pytest.mark.asyncio
async def test_gui_exact_approval_controls_and_waiting_do_not_issue_authority(tmp_path):
    from tkinter import ttk

    from tests.unit.continuous.test_runtime import make

    directory, store = make(tmp_path)
    before = store.state()
    for index in (1, 2):
        root = tk.Tk()
        app = Desktop(
            root,
            GUIConfig(
                data_directory=tmp_path / f"approval-gui-{index}",
                continuous_directory=directory,
            ),
        )
        try:
            await idle(root, app)
            app.navigate("Continuous")
            await idle(root, app)

            def buttons(widget):
                result = []
                for child in widget.winfo_children():
                    if isinstance(child, ttk.Button):
                        result.append(child.cget("text"))
                    result.extend(buttons(child))
                return result

            names = buttons(root)
            assert "Review sealed RF/LR jobs" in names
            assert "Review LLM Plan / Assessment" in names
            assert store.state() == before
            capture(root, tmp_path / f"approval-controls-{index}.png")
        finally:
            await close(root, app)
    assert not (directory / "native-model-approvals").exists()


@pytest.mark.asyncio
async def test_gui_authentication_window_admission_audit_cleanup_and_reconnect(tmp_path):
    from tests.unit.continuous.test_runtime import make

    runtime, store = make(tmp_path)
    authentication = dict(
        runtime_state="STOPPED",
        host_events=3,
        input_origin="FIXTURE_RETAINED_STATE_NO_HOST_JOURNAL",
        authentication_windows=dict(total=2, eligible=1, incomplete=1),
        if_admission=dict(state="BLOCKED_NO_APPROVED_PACKAGE", predictions=0),
        rule_incidents=dict(DONE_READ_ONLY=1, PENDING=1),
        audit_store_health="VERIFIED_LOCAL",
        managed_lifecycle=dict(
            state="STOPPED", cleanup="VERIFIED", stop_ack=True, durable_cleanup=True
        ),
    )
    store.update(
        dict(
            state="STOPPED",
            source="JSONL_REPLAY",
            cleanup="VERIFIED",
            authentication=authentication,
        )
    )
    before = store.state()
    for index in (1, 2):
        root = tk.Tk()
        app = Desktop(
            root,
            GUIConfig(data_directory=tmp_path / f"auth-gui-{index}", continuous_directory=runtime),
        )
        try:
            await idle(root, app)
            app.navigate("System")
            await idle(root, app)
            text = app.system.get("1.0", "end")
            for field in (
                "host_events",
                "authentication_windows",
                "if_admission",
                "predictions",
                "rule_incidents",
                "audit_store_health",
                "stop_ack",
                "durable_cleanup",
            ):
                assert field in text
            assert "FIXTURE_RETAINED_STATE_NO_HOST_JOURNAL" in text
            assert "BLOCKED_NO_APPROVED_PACKAGE" in text
            app.canvas.yview_moveto(1)
            if index == 1:
                at = app.system.search("AUTHENTICATION · SOURCE", "1.0", "end")
                app.system.yview(at)
            else:
                app.system.see("end")
            capture(root, tmp_path / f"fixture-authentication-gui-{index}.png")
        finally:
            await close(root, app)
    assert store.state() == before

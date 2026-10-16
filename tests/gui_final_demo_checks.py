"""Explicit actual WSLg final rehearsal. Opt-in evidence paths; no capture/security WRITE."""

import asyncio
import gc
import json
import os
import re
import signal
import subprocess
import sys
import time
import tkinter as tk
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import GUIConfig
from tests.final_demo_support import (
    audit_state,
    database_hashes,
    invocation_summary,
    retained_authentication,
    screenshot_entry,
)
from tests.gui_final_ux_checks import find_button, scroll_to
from tests.gui_screen_capture import capture
from tests.gui_wslg_checks import (  # noqa: F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)
from tests.research_adapter_support import research_paths


@pytest.fixture(autouse=True)
def declared_dependencies(monkeypatch):
    """Export uses explicitly pinned original binaries and clean exported Producer source."""
    if os.environ.get("SOC_RESEARCH_VALIDATION_REPOSITORY"):
        monkeypatch.setattr("soc_agent.security_ai.research.adapter.defaults", research_paths)
        monkeypatch.setattr(
            "soc_agent.gui.environment.project_root",
            lambda: Path(os.environ["SOC_RESEARCH_VALIDATION_REPOSITORY"]),
        )


def output_directory() -> Path:
    directory = Path(os.environ["SOC_FINAL_DEMO_OUTPUT"])
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "screenshots").mkdir(exist_ok=True)
    return directory


def window_ids() -> set[str]:
    result = subprocess.run(
        ["xwininfo", "-root", "-tree"], capture_output=True, text=True, timeout=5, check=True
    )
    return set(re.findall(r'(0x[0-9a-f]+) "Autonomous SOC Agent · Linux v1"', result.stdout))


class ExistingWindow:
    """Read-only XGetImage adapter for the actual separate CLI window, not a UI mock."""

    def __init__(self, identity, width, height):
        self.identity, self.width, self.height = int(identity, 16), width, height

    def update_idletasks(self):
        pass

    def update(self):
        pass

    def winfo_id(self):
        return self.identity

    def winfo_width(self):
        return self.width

    def winfo_height(self):
        return self.height


def test_exact_one_command_launch_and_no_automatic_replay(tmp_path):
    directory, previous_windows = output_directory(), window_ids()
    env = os.environ.copy()
    env["XDG_DATA_HOME"] = str(tmp_path / "xdg")
    started = time.monotonic()
    child = subprocess.Popen(
        [sys.executable, "-m", "soc_agent.gui"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = started + 30
        identity = None
        while child.poll() is None and time.monotonic() < deadline:
            new = window_ids() - previous_windows
            status = Path(f"/proc/{child.pid}/status").read_text()
            mask = int(
                next(s.split()[1] for s in status.splitlines() if s.startswith("SigCgt:")), 16
            )
            if len(new) == 1 and mask & (1 << (signal.SIGTERM - 1)):
                candidate = new.pop()
                info = subprocess.check_output(["xwininfo", "-id", candidate], text=True, timeout=5)
                if "Map State: IsViewable" in info:
                    identity = candidate
                    break
            time.sleep(0.02)
        assert identity is not None and child.poll() is None
        elapsed = time.monotonic() - started
        width = int(re.search(r"Width: (\d+)", info)[1])
        height = int(re.search(r"Height: (\d+)", info)[1])
        capture(
            ExistingWindow(identity, width, height), directory / "screenshots/one-command-1600.png"
        )
        data = tmp_path / "xdg/autonomous-soc-agent/gui"
        assert not (data / "network-research").exists()
        assert not list(data.rglob("receipt-*.json"))
        child.send_signal(signal.SIGTERM)
        _, stderr = child.communicate(timeout=30)
        assert child.returncode == 0, stderr
        (directory / "launch.json").write_text(
            json.dumps(
                {
                    "command": ".venv/bin/python -m soc_agent.gui",
                    "mapped_window_and_registered_shutdown_seconds": elapsed,
                    "backend_data_ready_latency": "UNKNOWN",
                    "mapped_window": True,
                    "auto_research_invocations": 0,
                    "graceful_exit_code": child.returncode,
                    "data_scope": "isolated XDG_DATA_HOME; no extra CLI arguments",
                },
                indent=2,
            )
            + "\n"
        )
    finally:
        if child.poll() is None:
            child.terminate()
            child.communicate(timeout=30)


async def photographs(root, directory, name, *, app=None, anchor=None):
    for w, h in ((1920, 1080), (1366, 768)):
        root.geometry(f"{w}x{h}")
        root.update()
        await asyncio.sleep(0.05)
        if anchor is not None:
            await scroll_to(root, app, anchor)
            assert anchor.winfo_rooty() < root.winfo_rooty() + h - 100
        assert root.winfo_ismapped() and (root.winfo_width(), root.winfo_height()) == (w, h)
        capture(root, directory / "screenshots" / f"{name}-{w}.png")


@pytest.mark.asyncio
async def test_actual_native_models_retained_auth_investigation_audit_and_recovery(tmp_path):
    directory = output_directory()
    runtime = Path(os.environ["SOC_FINAL_DEMO_AUTH_RUNTIME"])
    auth = retained_authentication(runtime)
    config = GUIConfig(data_directory=tmp_path / "gui", runtime_directory=runtime)
    root = tk.Tk()
    app = Desktop(root, config)
    errors, observed_workers = [], set()
    root.report_callback_exception = lambda *a: errors.append(a[0].__name__)
    try:
        await idle(root, app)
        app.navigate("Dashboard")
        await idle(root, app)
        initial = app.last_dashboard
        r = initial["research"]
        assert initial["runtime_state"] == auth["runtime_state"] == "STOPPED"
        assert initial["queue_backlog"] == auth["queue_backlog"]
        assert r["status"] == r["dns"]["status"] == "READY"
        assert r["inference_counts"] == {"quality": 0, "edge": 0} and r["dns_inference_count"] == 0
        assert r["operational_inference"] == "BLOCKED" and not r["worker_running"]
        await photographs(root, directory, "dashboard-initial")
        app.navigate("Network Research")
        await idle(root, app)
        view = app.research_view
        for name, profile, inputs, shot in (
            ("Network · Quality", "quality", ("1", "3"), "network-quality"),
            ("Network · Edge", "edge", ("1", "3"), "network-edge"),
            ("DNS · Security", "dns", ("1", "2"), "dns-security"),
        ):
            view.selection.set(name)
            view.choose_model()
            assert view.profile.get() == profile
            for index in inputs:
                view.flow.set(index)
                view.replay_button.invoke()
                view.replay()  # Duplicate click must not dispatch another invocation.
                deadline, ticks = time.monotonic() + 120, 0
                while app.busy and time.monotonic() < deadline:
                    root.update()
                    await asyncio.sleep(0.02)
                    ticks += 1
                    activity = getattr(view, "last_activity", {})
                    if activity.get("worker_running"):
                        observed_workers.add(activity["active_model"])
                await idle(root, app, timeout=120)
                assert ticks > 10
            record = view.last_snapshot["records"][-1]
            assert record["profile"] == profile and record["status"] == "COMPLETE"
            app.tree.selection_set(str(len(view.last_snapshot["records"]) - 1))
            app.tree.yview("moveto", 1.0)
            root.update()
            view.show_record(record)
            await photographs(root, directory, shot)
        final = view.last_snapshot
        assert final["inference_counts"] == {"quality": 2, "edge": 2}
        assert final["dns_inference_count"] == 2 and len(final["records"]) == 6
        assert not final["worker_running"] and observed_workers == {"quality", "edge", "dns"}
        assert len(view.trend.find_withtag("replay-point")) == 2
        assert [v for _, v in view.dns_chart.points] == [0.55859375, 0.0]
        record = final["records"][-1]
        view.show_record(record, mode="investigation")
        await scroll_to(root, app, app.summary_frame)
        await photographs(root, directory, "investigation", app=app, anchor=app.summary_frame)
        db = config.data_directory / "network-research/soc/external-validation.sqlite"
        audit_before = audit_state(db)
        find_button(app.content, "Audit / receipt").invoke()
        await scroll_to(root, app, app.summary_frame)
        assert app.last_details["audit_integrity"] == "VERIFIED"
        await photographs(root, directory, "audit", app=app, anchor=app.summary_frame)
        app.navigate("Investigations")
        await idle(root, app)
        assert app.current_records and all(r["origin"] == "NATIVE_OS" for r in app.current_records)
        app.tree.selection_set("0")
        root.update()
        await photographs(root, directory, "authentication", app=app, anchor=app.tree)
        app.navigate("Dashboard")
        await idle(root, app)
        assert len(app.unified_panel.invocations.find_withtag("invocation-point")) == 6
        assert len(app.unified_panel.network.rows) == 2
        await photographs(root, directory, "unified-dashboard")
        root.geometry("1280x720")
        root.update()
        assert app.unified_panel.status.bbox("all")[2] <= app.unified_panel.status.winfo_width() + 1
        capture(root, directory / "screenshots/unified-dashboard-1280.png")
        assert not errors
    finally:
        await close(root, app)
    assert app.worker.backend.research_demo.adapter.process is None
    gc.collect()  # Drain retired page/widget cycles on the Tk creator before more threads run.
    request = {
        "data_directory": str(config.data_directory),
        "runtime": str(runtime),
        "output_directory": str(directory),
        "parent_pid": os.getpid(),
        "invocation_ids": [rec["receipt"]["invocation_id"] for rec in final["records"]],
        "audit": audit_before,
    }
    request_path = directory / "private-recovery-request.json"
    request_path.write_text(json.dumps(request))
    command = [
        sys.executable,
        "-c",
        "import asyncio,sys; from pathlib import Path; "
        "from tests.gui_final_demo_checks import recovery_window; "
        "asyncio.run(recovery_window(Path(sys.argv[1])))",
        str(request_path),
    ]
    with (directory / "private-recovery.log").open("w") as log:
        child = await asyncio.to_thread(subprocess.run, command, stdout=log, stderr=log, timeout=90)
    assert child.returncode == 0, "Fresh-process GUI recovery failed; inspect private recovery log"
    recovered = json.loads((directory / "recovery.json").read_text())
    after = database_hashes(runtime)
    assert after == auth["database_sha256_before"]
    auth["database_sha256_after"] = after
    evidence = {
        "run_id": os.environ.get("SOC_FINAL_DEMO_RUN_ID", str(uuid4())),
        "validation_date": datetime.now(UTC).isoformat(),
        "initial_gui": {
            "runtime_state": initial["runtime_state"],
            "queue_backlog": initial["queue_backlog"],
            "network_research": r["status"],
            "dns_research": r["dns"]["status"],
            "inference_counts": {"quality": 0, "edge": 0, "dns": 0},
            "worker_running": False,
            "operational_gate": "BLOCKED",
        },
        "authentication": auth,
        "invocations": [invocation_summary(rec) for rec in final["records"]],
        "audit": audit_before,
        "recovery": {**recovered, "actual_worker_profiles_observed": sorted(observed_workers)},
        "runtime_state": initial["runtime_state"],
        "operational_gate": "BLOCKED",
        "screenshots": [
            screenshot_entry(p) for p in sorted((directory / "screenshots").glob("*.png"))
        ],
    }
    (directory / "gui-evidence.json").write_text(
        json.dumps(evidence, indent=2, allow_nan=False) + "\n"
    )


async def recovery_window(request_path: Path):
    """Reopen in a fresh OS process, matching the real one-window CLI lifecycle."""
    request = json.loads(request_path.read_text())
    assert os.getpid() != request["parent_pid"]
    if os.environ.get("SOC_RESEARCH_VALIDATION_REPOSITORY"):
        from soc_agent.gui import environment
        from soc_agent.security_ai.research import adapter

        adapter.defaults = research_paths
        environment.project_root = lambda: Path(os.environ["SOC_RESEARCH_VALIDATION_REPOSITORY"])
    directory = Path(request["output_directory"])
    root = tk.Tk()
    config = GUIConfig(
        data_directory=Path(request["data_directory"]), runtime_directory=Path(request["runtime"])
    )
    app = Desktop(root, config)
    errors = []
    root.report_callback_exception = lambda *a: errors.append(a[0].__name__)
    try:
        await idle(root, app)
        app.navigate("Network Research")
        await idle(root, app)
        view = app.research_view
        restored = view.last_snapshot
        assert restored["demo_state"] == "STOPPED" and not restored["worker_running"]
        assert {r["receipt"]["invocation_id"] for r in restored["records"]} == set(
            request["invocation_ids"]
        )
        view.replay_button.invoke()
        await idle(root, app, timeout=90)
        assert "no new inference" in view.progress.get()
        view.stop_button.invoke()
        await idle(root, app)
        restored = view.last_snapshot
        assert restored["inference_counts"] == {"quality": 2, "edge": 2}
        assert restored["dns_inference_count"] == 2 and restored["demo_state"] == "STOPPED"
        assert not restored["worker_running"]
        db = config.data_directory / "network-research/soc/external-validation.sqlite"
        assert audit_state(db) == request["audit"]
        await photographs(root, directory, "runtime-recovery")
        assert not errors
    finally:
        await close(root, app)
    result = {
        "process_boundary": "NEW_PYTHON_PROCESS",
        "demo_state": restored["demo_state"],
        "worker_running": restored["worker_running"],
        "same_invocation_ids": True,
        "same_audit_head": True,
        "new_inferences_after_cached_replay": 0,
        "confirmed_by_model": {"quality": 2, "edge": 2, "dns": 2},
    }
    (directory / "recovery.json").write_text(json.dumps(result, indent=2) + "\n")
    del view, app, root
    gc.collect()  # Release this process's Tk cycles on their creating thread after shutdown.

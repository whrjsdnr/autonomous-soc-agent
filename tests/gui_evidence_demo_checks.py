"""Opt-in mapped GUI checks for the frozen Evidence Demo; never starts a live service.

Run with releases/research-mvp/.venv/bin/python -B tests/gui_evidence_demo_checks.py
unified 1 (manual), unified 2 --automatic (real 300 seconds), or a legacy view name.
"""

import argparse
import ctypes.util
import fcntl
import json
import runpy
import sys
import threading
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "releases/evidence-demo-20261104"
OUTPUT = RELEASE / "docs/unified-validation"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("view", choices=("unified", "native", "replay", "api", "authentication"))
    parser.add_argument("round", type=int)
    parser.add_argument("--automatic", action="store_true")
    parser.add_argument(
        "--quick", action="store_true", help="55s animation then test-only clock advance"
    )
    args = parser.parse_args()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    sys.path[:0] = [str(RELEASE), str(RELEASE / "python"), str(ROOT / "tests")]
    from gui_screen_capture import capture

    original_find = ctypes.util.find_library
    x11 = original_find("X11")
    ctypes.util.find_library = lambda name: x11 if name == "X11" else original_find(name)
    checks: dict = {"stages": [], "errors": []}
    started = time.monotonic()

    if args.view == "unified":
        import unified_viewer

        original = unified_viewer.UnifiedDesktop

        class Inspect(original):
            def __init__(self, root, *values):
                super().__init__(root, *values)
                self.seen = set()
                self.deadline = time.monotonic() + (330 if args.automatic else 60)
                self.auto_started = time.monotonic()
                self.packet_counts = []
                self.model_counts = []
                root.report_callback_exception = self.callback_error
                root.after(150, self.inspect)

            def callback_error(self, typ, value, _traceback):
                traceback.print_exception(typ, value, _traceback)
                checks["errors"].append(f"{typ.__name__}: {value}")
                self.close()

            def inspect(self):
                try:
                    i = self.clock.index
                    if args.automatic:
                        self.inspect_automatic()
                        return
                    if i not in self.seen:
                        assert self.root.winfo_ismapped()
                        assert self.root.title() == "E2E Scenario Replay"
                        source = self.evidence.sources[unified_viewer.STAGES[i].source]
                        assert source.trial_date in self.provenance.cget("text")
                        assert source.execution in self.provenance.cget("text")
                        assert source.identity in self.provenance.cget("text")
                        rows = 0
                        if i == 2:
                            rows = len(self.analysis_predictions.get_children())
                            assert rows == 8
                        if i in (3, 4):
                            rows = len(
                                (
                                    self.continuous_incidents if i == 3 else self.continuous_tasks
                                ).get_children()
                            )
                            assert rows == (2 if i == 3 else 5)
                        if i == 5:
                            assert self.evidence.api["llm_mode"] == "REAL_API"
                            assert "REAL_API" in self.analysis_investigation.get("1.0", "end")
                            assert "read_local_source_report" in self.analysis_investigation.get(
                                "1.0", "end"
                            )
                            assert "continuous" not in self.snapshot
                        if i == 6:
                            report = self.snapshot["analysis"]["result"]
                            assert report["audit"] == "VERIFIED"
                            assert (
                                report["predictions"][0]["model"]
                                == "authentication_anomaly_iforest"
                            )
                            assert report["predictions"][0]["prediction"] == "anomaly"
                            assert len(self.analysis_predictions.get_children()) == 1
                        if i == 0:
                            for chart in self.dashboard_charts:
                                assert any(
                                    v is not None
                                    for points in chart.points.values()
                                    for _, v in points
                                ), chart.title
                            assert self.snapshot["continuous"]["state"] == "STOPPED"
                            checks["dashboard_charts_connected"] = len(self.dashboard_charts)
                        if i == 7:
                            raw = json.loads(self.continuous_detail.get("1.0", "end"))
                            assert raw["result"]["global_cleanup"] == "UNKNOWN"
                        assert (
                            self.nav_buttons.keys()
                            == dict.fromkeys(
                                (
                                    "Dashboard",
                                    "Security Events",
                                    "Investigation",
                                    "AI Analysis",
                                    "Continuous",
                                    "System",
                                )
                            ).keys()
                        )
                        capture(self.root, OUTPUT / f"unified-{args.round}-stage-{i + 1}.png")
                        if i == 4:
                            first = self.continuous_tasks.get_children()[0]
                            self.continuous_tasks.selection_set(first)
                            self.inspect_task()
                            detail = json.loads(self.continuous_detail.get("1.0", "end"))
                            assert detail["source"]["identity"] == source.identity
                            assert detail["task"]["investigation"]["llm_mode"] == "SCRIPTED"
                        self.seen.add(i)
                        checks["stages"].append(
                            {
                                "stage": i + 1,
                                "source": source.model_dump(),
                                "rows": rows,
                                "elapsed": time.monotonic() - started,
                            }
                        )
                        print(f"PASS stage {i + 1}: {source.name} / {source.execution}", flush=True)
                    if args.automatic:
                        self.root.after(150, self.inspect)
                        return
                    elif i < 7:
                        self.next_button.invoke()
                        self.root.after(150, self.inspect)
                        return
                    assert len(self.seen) == 8
                    self.previous_button.invoke()
                    assert self.clock.index == 6
                    self.reconnect()
                    assert self.clock.index == 6 and not self.clock.playing
                    checks["reconnected"] = True
                    self.show_auth_failure()
                    assert "SOURCE_UNAVAILABLE" in self.system.get("1.0", "end")
                    assert "UNVERIFIED" in self.system.get("1.0", "end")
                    for chart in self.health_charts:
                        assert any(
                            v is not None for points in chart.points.values() for _, v in points
                        ), chart.title
                    checks["system_charts_connected"] = len(self.health_charts)
                    self.show_reference()
                    assert self.snapshot["continuous"]["metrics"]["predictions"] == 406
                    assert "2026-11-02" in self.provenance.cget("text")
                    self.restart()
                    assert self.clock.index == 0
                    self.toggle_details()
                    self.root.update_idletasks()
                    assert self.provenance.winfo_ismapped()
                    capture(self.root, OUTPUT / f"unified-{args.round}-source-details.png")
                    self.toggle_details()
                    checks["all_native_pages"] = []
                    for page in (
                        "Dashboard",
                        "Security Events",
                        "Investigation",
                        "AI Analysis",
                        "Continuous",
                        "System",
                    ):
                        self.navigate(page, refresh=False)
                        charts = (
                            self.dashboard_charts
                            if page == "Dashboard"
                            else self.event_charts
                            if page in ("Security Events", "Investigation")
                            else self.health_charts
                            if page == "System"
                            else []
                        )
                        for chart in charts:
                            assert any(
                                v is not None for points in chart.points.values() for _, v in points
                            ), (page, chart.title)
                        checks["all_native_pages"].append({"page": page, "charts": len(charts)})
                        if page in ("Dashboard", "System", "Investigation"):
                            self.canvas.yview_moveto(0.5)
                            capture(self.root, OUTPUT / f"unified-{args.round}-{page}-graphs.png")
                    self.toggle()
                    self.toggle()
                    assert not self.clock.playing
                    self.choose_stage(4)
                    self.continuous_tasks.selection_set(self.continuous_tasks.get_children()[0])
                    self.navigate("AI Analysis", refresh=False)
                    self.root.update()
                    before = (self.clock.index, self.clock.remaining)
                    self.show_result("api")
                    assert self.active_source == "api"
                    self.navigate("Dashboard")
                    assert (self.clock.index, self.clock.remaining) == before
                    assert "ASSESSMENT" in self.llm_feed.get("1.0", "end")
                    assert self.active_source == "native"
                    checks["explicit_source_navigation"] = True
                    checks["pause_resume_restart_previous"] = True
                    checks["normal_close"] = True
                    self.root.tk.call(self.root.protocol("WM_DELETE_WINDOW"))
                    assert self.closed and self.timer is None
                except Exception as error:
                    checks["errors"].append(f"{type(error).__name__}: {error}")
                    self.close()

            def navigate(self, page, refresh=True):
                self.navigation_calls = getattr(self, "navigation_calls", 0) + 1
                super().navigate(page, refresh=refresh)

            def tick(self):
                before = getattr(self, "navigation_calls", 0)
                super().tick()
                assert getattr(self, "navigation_calls", 0) == before, "TIMER_CHANGED_PAGE"
                checks["no_automatic_navigation"] = True

            def inspect_automatic(self):
                age = time.monotonic() - self.auto_started
                if self.clock.finished:
                    checks["automatic_seconds"] = age
                    assert (55 <= age <= 75) if args.quick else (299 <= age <= 310)
                    self.root.after(1000, self.verify_finished)
                    return
                assert self.clock.playing, "DEFAULT_AUTOPLAY_NOT_STARTED"
                assert time.monotonic() < self.deadline, "AUTO_TIMEOUT"
                assert "실행 중" in self.monitoring.cget("text")
                checks["default_autoplay"] = True
                if self.page == "Dashboard" and self.active_source == "native":
                    queue = int(self.status_cards["Queue backlog"].previous[0])
                    checks["queue_peak"] = max(checks.get("queue_peak", 0), queue)
                    checks["auth_if_visible"] = self.status_cards["Authentication"].previous[0]
                    packets = int(self.status_cards["Network"].previous[0].split()[0])
                    models = sum(
                        int(self.status_cards[k].previous[0].split()[0])
                        for k in ("Quality RF", "Edge LR")
                    )
                    if not self.packet_counts or self.packet_counts[-1] != packets:
                        self.packet_counts.append(packets)
                        if len(self.packet_counts) == 8:
                            capture(self.root, OUTPUT / "unified-collecting.png")
                    if not self.model_counts or self.model_counts[-1]["count"] != models:
                        self.model_counts.append({"count": models, "seconds": age})
                        if models == 8:
                            capture(self.root, OUTPUT / "unified-models-ready.png")
                if self.page in ("Dashboard", "Investigation"):
                    body = self.llm_feed.get("1.0", "end")
                    if "ASSESSMENT ·" in body and not checks.get("llm_assessment_visible"):
                        assert "read_local_source_report" in body
                        assert "REAL_API" in body
                        checks["llm_assessment_visible"] = True
                        checks["llm_assessment_seconds"] = age
                        capture(self.root, OUTPUT / "unified-llm-investigation.png")
                i = self.clock.index
                if i not in self.seen:
                    self.seen.add(i)
                    checks["stages"].append(
                        {
                            "stage": i + 1,
                            "elapsed": age,
                            "page": self.page,
                            "source": self.active_source,
                        }
                    )
                    print(f"PASS timer stage {i + 1}; no forced navigation", flush=True)
                if args.quick and age >= 55:
                    assert checks["queue_peak"] > 0
                    assert checks["auth_if_visible"] == "1 IF receipt"
                    checks["test_only_fast_forward"] = True
                    self.clock.advance(300)
                self.root.after(150, self.inspect)

            def verify_finished(self):
                try:
                    assert self.root.winfo_exists() and not self.closed
                    assert self.clock.finished and not self.clock.playing
                    checks["remains_open_after_completion"] = True
                    checks["automatic_close"] = False
                    checks["packet_counter_sequence"] = self.packet_counts
                    checks["model_counter_sequence"] = self.model_counts
                    assert any(0 < r["count"] < 8 and r["seconds"] < 10 for r in self.model_counts)
                    assert any(r["count"] == 8 and r["seconds"] < 30 for r in self.model_counts)
                    assert (args.quick or len(self.seen) == 8) and len(self.packet_counts) >= 10
                    assert checks.get("llm_assessment_visible")
                    checks["normal_close"] = True
                    self.root.tk.call(self.root.protocol("WM_DELETE_WINDOW"))
                except Exception as error:
                    checks["errors"].append(f"{type(error).__name__}: {error}")
                    self.close()

        unified_viewer.UnifiedDesktop = Inspect
    else:
        from soc_agent.gui import production

        original = production.Desktop

        class Inspect(original):
            def __init__(self, root, config, **kwargs):
                super().__init__(root, config, **kwargs)
                self.deadline = time.monotonic() + 60
                root.report_callback_exception = self.callback_error
                root.after(150, self.inspect)

            def callback_error(self, typ, value, _traceback):
                traceback.print_exception(typ, value, _traceback)
                checks["errors"].append(f"{typ.__name__}: {value}")
                self.close()

            def inspect(self):
                try:
                    if not self.startup_complete or self.busy:
                        assert time.monotonic() < self.deadline
                        self.root.after(150, self.inspect)
                        return
                    value = self.snapshot
                    if args.view in ("native", "replay"):
                        current = value["continuous"]
                        assert current["metrics"]["predictions"] == (
                            8 if args.view == "native" else 406
                        )
                        assert current["state"] == "STOPPED"
                        assert not current.get("collection_live")
                        self.navigate("Continuous", refresh=False)
                        checks["metrics"] = current["metrics"]
                    elif args.view == "api":
                        report = value.get("analysis", {}).get("result")
                        if not report:
                            assert time.monotonic() < self.deadline
                            self.root.after(150, self.inspect)
                            return
                        assert report["llm_mode"] == "REAL_API"
                        assert report["external_provider_calls"] == 2
                        assert report["audit"] == "VERIFIED"
                        self.navigate("AI Analysis", refresh=False)
                        checks["mode"] = report["llm_mode"]
                    else:
                        assert value["authentication"]["collector_state"] == "SOURCE_UNAVAILABLE"
                        assert value["authentication"]["inference_status"] == "NOT_INFERABLE"
                        self.navigate("System", refresh=False)
                        checks["authentication"] = "SOURCE_UNAVAILABLE / NOT_INFERABLE"
                    capture(self.root, OUTPUT / f"{args.view}-regression.png")
                    checks["normal_close"] = True
                    self.close()
                except Exception as error:
                    checks["errors"].append(f"{type(error).__name__}: {error}")
                    self.close()

        production.Desktop = Inspect

    sys.argv = [str(RELEASE / "evidence_viewer.py"), args.view]
    if args.view == "unified" and not args.automatic:
        sys.argv.append("--manual")
    try:
        runpy.run_path(str(RELEASE / "evidence_viewer.py"), run_name="__main__")
    except SystemExit as error:
        code = error.code or 0
    if args.view != "unified":
        with (RELEASE / "view-state" / args.view / "desktop.lock").open() as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(lock, fcntl.LOCK_UN)
        checks["os_lock_released"] = True
    threads = [
        t.name for t in threading.enumerate() if t is not threading.main_thread() and not t.daemon
    ]
    result = {
        "view": args.view,
        "round": args.round,
        "code": code,
        "checks": checks,
        "remaining_non_daemon_threads": threads,
        "seconds": time.monotonic() - started,
    }
    result["status"] = (
        "PASS"
        if (code == 0 and checks.get("normal_close") and not checks["errors"] and not threads)
        else "FAIL"
    )
    (OUTPUT / f"{args.view}-{args.round}.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)
    assert result["status"] == "PASS"


if __name__ == "__main__":
    main()

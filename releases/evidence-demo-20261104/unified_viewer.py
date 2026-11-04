"""Replay navigation on the original SOC desktop, with no execution backend."""

import json
import math
import os
import signal
import time
import tkinter as tk
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from tkinter import ttk

from unified_evidence import STAGES, Evidence, ReplayClock, load_evidence, stage_data
from unified_metrics import animate
from unified_metrics import apply as apply_metrics

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.components import BG, PRIMARY, Label
from soc_agent.gui.production import Desktop
from soc_agent.gui.redaction import display_data


class UnifiedDesktop(Desktop):
    """Keep the original layouts and renderers; replace only replay navigation/data access.

    No Worker/Backend is constructed. UI commands can only select already verified
    reports from this bundle. Production source and frozen package remain untouched.
    """

    def __init__(self, root: tk.Tk, evidence: Evidence, reload: Callable[[], Evidence]):
        self.evidence, self.reload = evidence, reload
        self.clock = ReplayClock()
        self.closed = False
        self.timer: str | None = None
        self.last_tick = time.monotonic()
        self.active_source = "native"
        self.presentation_animated = True
        self.animation_second = -1
        # Packing the small replay strip first preserves the original desktop below it.
        self.strip = strip = tk.Frame(root, bg=BG, padx=14, pady=4)
        strip.pack(fill="x")
        Label(strip, text="E2E Scenario Replay", size=12, fg="#94A3B8").pack(
            side="left", padx=(0, 16)
        )
        self.play_button = ttk.Button(strip, text="Play", command=self.toggle)
        self.play_button.pack(side="left", padx=3)
        self.previous_button = ttk.Button(strip, text="Previous", command=lambda: self.move(-1))
        self.previous_button.pack(side="left", padx=3)
        self.next_button = ttk.Button(strip, text="Next", command=lambda: self.move(1))
        self.next_button.pack(side="left", padx=3)
        ttk.Button(strip, text="Details", command=self.toggle_details).pack(side="left", padx=3)
        self.timing = Label(strip, text="", size=11, fg="#94A3B8")
        self.timing.pack(side="right")
        self.monitoring = Label(strip, text="모니터링 · 준비", size=11, fg=PRIMARY)
        self.monitoring.pack(side="right", padx=18)
        self.context = context = tk.Frame(root, bg=BG, padx=14)
        options = tk.Frame(context, bg=BG)
        options.pack(fill="x", pady=4)
        for label, callback in (
            ("Restart", self.restart),
            ("Reconnect", self.reconnect),
            ("API result", lambda: self.show_result("api")),
            ("Authentication IF", lambda: self.show_result("authentication_if")),
            ("PCAP reference", self.show_reference),
            ("Auth Runtime", self.show_auth_failure),
        ):
            ttk.Button(options, text=label, command=callback).pack(side="left", padx=3)
        self.provenance = Label(context, text="", size=11, fg=PRIMARY, max_width=1450)
        self.provenance.pack(anchor="w")
        self.explanation = Label(context, text="", size=11, max_width=1450)
        self.explanation.pack(anchor="w", pady=(2, 5))
        self.progress = ttk.Progressbar(context, maximum=300)
        self.progress.pack(fill="x")
        config = GUIConfig(data_directory=Path(__file__).parent / "view-state/unified")
        # All methods that use the live worker are overridden below. Passing a sentinel
        # prevents Desktop from constructing its usual execution-capable Worker.
        super().__init__(root, config, worker=object())
        root.title("E2E Scenario Replay")
        root.geometry("1440x1000")
        root.minsize(1100, 800)
        root.bind("<Right>", lambda _: self.move(1))
        root.bind("<Left>", lambda _: self.move(-1))
        root.bind("<space>", lambda _: self.toggle())
        self.choose_stage(0)
        self.tick()

    def toggle_details(self):
        if self.context.winfo_manager():
            self.context.pack_forget()
        else:
            self.context.pack(fill="x", after=self.strip)

    def _startup(self):
        self.startup_complete = True

    def refresh(self):
        self.last_render = None
        self._render_current()

    def call(self, operation, *args, callback=None, **kwargs):
        if operation == "production_status":
            if callback:
                callback(self.snapshot)
        elif operation == "analysis_attach" and args and str(args[0]) in self.evidence.reports:
            result = self.evidence.reports[str(args[0])]
            self.snapshot["analysis"] = self.analysis_snapshot(result)
            self.last_render = None
            self._render_current()
        else:
            self.status.set("READ_ONLY_REPLAY · operation unavailable")

    @staticmethod
    def analysis_snapshot(result: dict) -> dict:
        return {
            "state": "IMPORTED_VERIFIED_REPORT",
            "mode": "RETAINED_EVIDENCE",
            "result": result,
            "collection_live": False,
            "worker_running": False,
            "capture_started_by_gui": False,
            "cleanup": "HISTORICAL_REPORT_ONLY",
        }

    def snapshot_for(self, name: str) -> dict:
        if name in ("native", "replay"):
            value = deepcopy(getattr(self.evidence, name))
            outputs = value["continuous"]["recent_results"]
            # The first Native report contains all eight predictions; preserve the
            # incomplete second report as its own selectable Incident.
            if name == "native":
                value["analysis"] = self.analysis_snapshot(
                    self.evidence.reports[outputs[0]["output"]]
                )
            return value
        if name in ("api", "authentication_if"):
            report = self.evidence.api if name == "api" else self.evidence.authentication_if
            records = []
            for prediction in report["predictions"]:
                model = prediction["model"]
                profile = (
                    "quality"
                    if model.endswith("quality_rf")
                    else ("edge" if model.endswith("edge_lr") else "authentication")
                )
                records.append(
                    {
                        "receipt": prediction
                        | {"profile": profile, "origin": report["input_origins"][0]},
                        "incident_id": report["incident_id"],
                        "investigation": report["investigation_detail"],
                        "advisory_current": "RESEARCH_ONLY",
                    }
                )
            return {
                "state": "STOPPED",
                "collection_live": False,
                "input_origin": report["input_origins"][0],
                "analysis": self.analysis_snapshot(report),
                "research": {"records": records},
                "runtime_audit_integrity": report["audit"],
            }
        return {
            "state": self.evidence.authentication["runtime_state"],
            "collection_live": False,
            "input_origin": "FAILED_AUTHENTICATION_RUNTIME",
            "authentication": deepcopy(self.evidence.authentication),
            "runtime_audit_integrity": self.evidence.authentication["audit_store_health"],
        }

    def choose_stage(self, index: int) -> None:
        self.clock.select(index)
        self.last_tick = time.monotonic()
        stage = STAGES[index]
        self.active_source = stage.source
        self.snapshot = self.snapshot_for(stage.source)
        self.context_label()
        page = (
            "Dashboard",
            "Continuous",
            "AI Analysis",
            "Continuous",
            "Continuous",
            "AI Analysis",
            "AI Analysis",
            "Continuous",
        )[index]
        self.navigate(page, refresh=False)
        self.status.set(stage.title)
        if index == 5:
            notebook = self.analysis_investigation.master.master
            notebook.select(self.analysis_investigation.master)
        if index in (3, 4, 7):
            target = (
                self.continuous_incidents
                if index == 3
                else self.continuous_tasks
                if index == 4
                else self.continuous_detail
            )
            self.root.update_idletasks()
            self.canvas.yview_moveto(target.winfo_y() / max(1, self.content.winfo_height()))
        self.previous_button.configure(state="disabled" if index == 0 else "normal")
        self.next_button.configure(state="disabled" if index == 7 else "normal")

    def context_label(self):
        source = self.evidence.sources[self.active_source]
        session = source.session or (
            "multiple capture sessions; see details" if source.capture_sessions else "not recorded"
        )
        self.provenance.configure(
            text=f"{source.name.upper()} · {source.trial_date} · {source.execution}  |  "
            f"Session: {session}\n{source.identity}"
        )
        self.explanation.configure(
            text=STAGES[self.clock.index].explanation
            if self.active_source == STAGES[self.clock.index].source
            else source.note
        )

    def navigate(self, page, refresh=True):
        if (
            refresh
            and page in ("Dashboard", "Continuous")
            and self.active_source not in ("native", "replay")
        ):
            self.active_source = "native"
            self.snapshot = self.snapshot_for("native")
            self.context_label()
        super().navigate(page, refresh=False)
        if page == "Dashboard":
            streams = tk.Frame(self.content, bg=BG)
            streams.pack(fill="x", before=self.capture_summary, pady=(0, 10))
            self.packet_feed = tk.Text(
                streams,
                height=8,
                width=45,
                bg="#17243A",
                fg="#38BDF8",
                relief="flat",
                font=("monospace", 10),
                state="disabled",
            )
            self.packet_feed.pack(side="left", fill="both", expand=True, padx=(0, 8))
            self.llm_feed = tk.Text(
                streams,
                height=8,
                width=55,
                bg="#17243A",
                fg="#E2E8F0",
                relief="flat",
                wrap="word",
                font=("DejaVu Sans", 10),
                state="disabled",
            )
            self.llm_feed.pack(side="left", fill="both", expand=True)
            animate(self)
        elif page == "Investigation":
            self.llm_feed = tk.Text(
                self.content,
                height=14,
                bg="#17243A",
                fg="#E2E8F0",
                relief="flat",
                wrap="word",
                font=("DejaVu Sans", 10),
                state="disabled",
            )
            self.llm_feed.pack(fill="x", before=self.content.winfo_children()[0], pady=(0, 12))
            animate(self)
        self.disable_actions(self.content)

    def disable_actions(self, widget):
        # Preserve the existing view; execution controls remain visible but disabled.
        allowed = {"Inspect Selected Incident", "Raw detail", "Refresh", "Search", "Apply filter"}
        for child in widget.winfo_children():
            if isinstance(child, ttk.Button) and child.cget("text") not in allowed:
                child.configure(state="disabled")
            self.disable_actions(child)

    def _render_current(self):
        super()._render_current()
        if not self.snapshot:
            return
        source = self.evidence.sources[self.active_source].model_dump()
        if self.page == "AI Analysis":
            result = self.snapshot.get("analysis", {}).get("result") or {}
            if result.get("llm_mode") == "REAL_API":
                investigation = result["investigation_detail"]
                plan = investigation["plan"]
                assessment = investigation["assessment"]["threat_assessment"]
                self._text(
                    self.analysis_investigation,
                    "REAL_API · separate trial · 2026-10-27\n"
                    f"Historical calls: {result['external_provider_calls']} / no new calls\n\n"
                    f"PLAN\n{plan['goal']}\n\nTOOLS\n"
                    + "\n".join(f"{s['tool_name']} · {s['status']}" for s in plan["steps"])
                    + f"\n\nASSESSMENT · {assessment.get('severity')} / "
                    f"confidence {assessment.get('confidence')}\n{assessment.get('summary')}\n\n"
                    "Hypotheses and recommendations are not verified observations.\n"
                    "Full original result and evidence references: Evidence / Audit tab.",
                )
            self._text(
                self.analysis_detail,
                json.dumps(
                    display_data({"source": source, "analysis": self.snapshot.get("analysis")}),
                    indent=2,
                    ensure_ascii=False,
                ),
            )
        elif self.page == "Continuous":
            detail = {"source": source, "continuous": self.snapshot.get("continuous")}
            if self.clock.index == 7 and self.active_source == "native":
                detail = stage_data(self.evidence, 7)
                detail = {
                    "historical_audit_cleanup": {
                        "Native 2026-10-30": "Audit VERIFIED / owned cleanup VERIFIED",
                        "API 2026-10-27 (separate)": "Audit VERIFIED",
                        "Replay 2026-11-02 (separate)": "Audit VERIFIED / PENDING 4 retained",
                        "Authentication 2026-11-04 (failed)": "Runtime cleanup UNVERIFIED",
                        "Global kernel cleanup": "UNKNOWN",
                        "Viewer close": "GUI resources only; no new Runtime cleanup",
                    },
                    **detail,
                }
            self._text(
                self.continuous_detail,
                json.dumps(display_data(detail), indent=2, ensure_ascii=False),
            )
            self.continuous_tasks.bind("<<TreeviewSelect>>", self.inspect_task)
        elif self.page == "System" and self.active_source == "authentication":
            self._text(
                self.system,
                "READY_TIMEOUT / SOURCE_UNAVAILABLE · IF NOT_INFERABLE\n"
                "Historical Runtime cleanup: UNVERIFIED · Cause: UNKNOWN\n\n"
                + json.dumps(
                    display_data(stage_data(self.evidence, 6)), indent=2, ensure_ascii=False
                ),
            )
        self.disable_actions(self.content)
        apply_metrics(self)
        animate(self)

    def select(self, _event=None):
        if self.page not in ("Security Events", "Investigation"):
            return
        super().select(_event)
        apply_metrics(self)

    def inspect_task(self, _event=None):
        if self.page != "Continuous" or not self.continuous_tasks.winfo_exists():
            return
        selected = self.continuous_tasks.selection()
        if selected:
            task = next(
                t
                for t in self.snapshot["continuous"]["orchestration"]["tasks"]
                if t["task_id"] == selected[0]
            )
            self._text(
                self.continuous_detail,
                json.dumps(
                    display_data(
                        {
                            "source": self.evidence.sources[self.active_source].model_dump(),
                            "task": task,
                        }
                    ),
                    indent=2,
                    ensure_ascii=False,
                ),
            )
            self.root.update_idletasks()
            self.canvas.yview_moveto(
                self.continuous_detail.winfo_y() / max(1, self.content.winfo_height())
            )

    def show_auth_failure(self):
        self.clock.playing = False
        self.active_source = "authentication"
        self.snapshot = self.snapshot_for("authentication")
        self.context_label()
        self.explanation.configure(text="2026-11-04 failed Runtime · original evidence retained")
        self.navigate("System", refresh=False)
        self.root.update_idletasks()
        self.canvas.yview_moveto(self.system.winfo_y() / max(1, self.content.winfo_height()))

    def show_result(self, source):
        self.active_source = source
        self.snapshot = self.snapshot_for(source)
        self.context_label()
        self.navigate("AI Analysis", refresh=False)
        if source == "api":
            self.analysis_investigation.master.master.select(self.analysis_investigation.master)

    def show_reference(self):
        self.clock.playing = False
        self.active_source = "replay"
        self.snapshot = self.snapshot_for("replay")
        self.context_label()
        self.explanation.configure(
            text="Separate PCAP trial · 2026-11-02 · never added to Native totals"
        )
        self.navigate("Continuous", refresh=False)
        self.status.set("Separate stored-PCAP reference · Next returns to the presentation")

    def move(self, offset: int):
        self.choose_stage(max(0, min(7, self.clock.index + offset)))

    def toggle(self):
        if self.clock.finished or self.active_source == "replay":
            self.choose_stage(0 if self.clock.finished else self.clock.index)
        self.clock.playing = not self.clock.playing
        self.last_tick = time.monotonic()
        self.monitoring.configure(
            text="모니터링 · " + ("실행 중" if self.clock.playing else "일시정지")
        )
        self.play_button.configure(text="Pause" if self.clock.playing else "Play")
        self.last_render = None
        self._render_current()

    def restart(self):
        self.clock.playing = False
        self.choose_stage(0)

    def reconnect(self):
        self.clock.playing = False
        try:
            self.evidence = self.reload()
        except (ValueError, OSError, RuntimeError):
            self.close()
            raise
        self.choose_stage(self.clock.index)
        self.status.set("Reconnected · original evidence reverified · paused")

    def tick(self):
        now = time.monotonic()
        # The clock reveals values; the operator owns page and source selection.
        self.clock.advance(now - self.last_tick)
        self.last_tick = now
        elapsed = sum(s.seconds for s in STAGES[: self.clock.index + 1]) - self.clock.remaining
        self.progress.configure(value=elapsed)
        self.timing.configure(
            text=f"{self.clock.index + 1}/8 · "
            f"{'Playing' if self.clock.playing else 'Paused'} · "
            f"{math.ceil(self.clock.remaining)}s"
        )
        self.play_button.configure(text="Pause" if self.clock.playing else "Play")
        self.monitoring.configure(
            text="모니터링 · "
            + ("완료" if self.clock.finished else "실행 중" if self.clock.playing else "일시정지")
        )
        second = int(elapsed)
        if second != self.animation_second:
            self.animation_second = second
            self.last_render = None
            self._render_current()
        self.timer = self.root.after(250, self.tick)

    def close(self, reason="GUI_CLOSE"):
        if self.closed:
            return
        self.closed = self.closing = True
        self.clock.playing = False
        if self.timer is not None:
            self.root.after_cancel(self.timer)
            self.timer = None
        self.root.destroy()


def run(
    release: Path, manifest: dict, verify: Callable[[Path], dict], *, autoplay: bool = True
) -> int:
    if os.geteuid() == 0:
        raise PermissionError("SOC_GUI_REQUIRES_UNPRIVILEGED_USER")
    evidence = load_evidence(manifest)
    root = tk.Tk()
    app = UnifiedDesktop(root, evidence, lambda: load_evidence(verify(release)))
    app.presentation_animated = autoplay
    if autoplay:
        app.toggle()
    else:
        app.refresh()
    previous = {}
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous[signum] = signal.signal(signum, lambda *_: root.after(0, app.close))
    try:
        root.mainloop()
    finally:
        if not app.closed:
            app.close()
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return 0

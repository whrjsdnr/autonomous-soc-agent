"""Default operator desktop: one visible page, one bounded backend request at a time.

Research/replay views remain in ``--developer``; importing this module never imports them.
"""

import gc
import json
import re
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from soc_agent.gui import analysis_view, continuous_view, operator_view
from soc_agent.gui.charts import MetricHistory
from soc_agent.gui.components import Button, Label
from soc_agent.gui.redaction import display_data
from soc_agent.gui.visual_metrics import VisualHistory
from soc_agent.gui.worker import Worker

SCREENS = ("Dashboard", "Security Events", "Investigation", "AI Analysis", "Continuous", "System")
BG, PANEL, TEXT, ACCENT = "#0B1220", "#17243A", "#F1F5F9", "#38BDF8"


def safe_error(value):
    if isinstance(value, str):
        for prefix in ("ValueError:", "CaptureUnavailable:", "RuntimeError:"):
            if value.startswith(prefix):
                value = value.removeprefix(prefix)
                break
    return (
        value if isinstance(value, str) and re.fullmatch(r"[A-Z0-9_:]{1,128}", value) else "UNKNOWN"
    )


def event_rows(snapshot, search=""):
    """Retain provenance and withdrawn status; scores are not calibrated risk probabilities."""
    result = []
    for record in snapshot.get("research", {}).get("records", [])[:64]:
        receipt = record.get("receipt") or {}
        investigation = record.get("investigation") or {}
        row = (
            receipt.get("inferred_at", "UNKNOWN"),
            receipt.get("profile", "UNKNOWN"),
            receipt.get("prediction", "UNKNOWN"),
            receipt.get("score", "UNKNOWN"),
            record.get("advisory_current", "RESEARCH_ONLY"),
            receipt.get("origin", "UNKNOWN"),
            investigation.get("status", "UNKNOWN"),
        )
        if search.casefold() in str(row).casefold():
            result.append((row, record))
    for event in snapshot.get("collector", {}).get("events", [])[:128]:
        row = (
            str(event.get("event_ns", "UNKNOWN")),
            "Zeek " + event.get("kind", "event"),
            event.get("diagnostic", "UNKNOWN"),
            "UNKNOWN",
            "DIAGNOSTIC_ONLY",
            event.get("source", {}).get("origin", "UNKNOWN"),
            "NOT_STARTED_PARITY_BLOCKED",
        )
        if search.casefold() in str(row).casefold():
            result.append((row, {"collector_event": event}))
    for event in snapshot.get("authentication", {}).get("recent_events", [])[:16]:
        row = (
            event.get("observed_at", "UNKNOWN"),
            "Authentication event",
            event.get("result", "UNKNOWN"),
            "NOT_INFERABLE",
            "OBSERVED_EVENT_NOT_MODEL_FINDING",
            event.get("collector", "UNKNOWN"),
            "READ_ONLY_NO_MODEL_ASSESSMENT",
        )
        if search.casefold() in str(row).casefold():
            result.append((row, {"authentication_event": event}))
    for event in snapshot.get("dns", {}).get("recent_events", [])[-32:]:
        row = (
            event.get("event_ns", "UNKNOWN"),
            "DNS transaction",
            event.get("status", "UNKNOWN"),
            "NOT_INFERABLE",
            "DNS_METADATA_DIAGNOSTIC_ONLY",
            snapshot.get("dns", {}).get("transport", {}).get("origin", "REPLAY"),
            "DNS9_TRAINING_CONTRACT_BLOCKED",
        )
        if search.casefold() in str(row).casefold():
            result.append((row, {"dns_event": event}))
    return result


def friendly_model(profile):
    return {"quality": "Network Quality · RF", "edge": "Network Edge · LR"}.get(
        profile, "Research model"
    )


class Desktop:
    def __init__(self, root, config, *, worker=None, on_ready=None):
        self.root, self.config = root, config
        # Collect unreachable display objects on the creator thread before a new
        # backend thread can trigger cyclic GC. The historical SIGILL cause is
        # still unproven; this is ownership hygiene, not a claimed native fix.
        gc.collect()
        self.worker = worker if worker is not None else Worker(config)
        self.on_ready = on_ready
        self.history = MetricHistory(capacity=60)
        self.visual_history = VisualHistory(capacity=60)
        self.history_session = None
        self.history_sample = None
        self.page = "Dashboard"
        self.busy = self.closing = self.startup_complete = False
        self.pending = None
        self.generation = 0
        self.last_stamp = 0
        self.snapshot = {}
        self.command = ""
        self.command_session = None
        self.poll_timer = self.drain_timer = None
        self.last_render = None
        self.status = tk.StringVar(value="Starting local status view…")
        self.policy = tk.StringVar(value=config.total_rate_policy)
        self.collector_type = tk.StringVar(value=config.collector_type)
        self.search = tk.StringVar()
        root.title("SOC Command Center · Research advisory / WRITE_DENIED")
        root.geometry("1366x768")
        root.minsize(1000, 650)
        root.configure(bg=BG)
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT, font=("DejaVu Sans", 11))
        style.configure("TButton", padding=8)
        style.configure("Treeview", rowheight=30, background=PANEL, foreground=TEXT)
        style.configure(
            "TButton", background="#20314A", foreground=TEXT, borderwidth=0, padding=(12, 10)
        )
        style.map(
            "TButton", background=[("active", "#29425D")], foreground=[("disabled", "#64748B")]
        )
        style.configure("Accent.TButton", background="#0B6E99", foreground=TEXT)
        style.configure("Treeview", fieldbackground=PANEL, borderwidth=0)
        style.map("Treeview", background=[("selected", "#184661")])
        style.configure("Treeview.Heading", background="#20314A", foreground=TEXT, padding=10)
        shell = ttk.Frame(root)
        shell.pack(fill="both", expand=True)
        side = tk.Frame(shell, bg="#101C2D", width=180)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        Label(side, text="SENTINEL", size=23, bold=True, fg=ACCENT, bg="#101C2D").pack(
            anchor="w", padx=16, pady=(26, 3)
        )
        Label(side, text="SOC COMMAND CENTER", size=10, fg="#94A3B8", bg="#101C2D").pack(
            anchor="w", padx=16, pady=(0, 30)
        )
        self.nav_buttons = {}
        for name in SCREENS:
            button = Button(side, text=name, command=lambda n=name: self.navigate(n))
            button.pack(fill="x", padx=10, pady=5)
            self.nav_buttons[name] = button
        Label(
            side,
            text="HUMAN GOVERNED\nREAD-ONLY INVESTIGATION",
            size=10,
            fg="#94A3B8",
            bg="#101C2D",
            max_width=160,
        ).pack(side="bottom", padx=10, pady=22)
        workspace = ttk.Frame(shell)
        workspace.pack(side="left", fill="both", expand=True, padx=20, pady=18)
        top = ttk.Frame(workspace)
        top.pack(fill="x", pady=(0, 14))
        self.page_title = Label(top, text="COMMAND CENTER", size=11, fg="#94A3B8")
        self.page_title.pack(side="left")
        self.scope_label = Label(
            top, text="RESEARCH ONLY / OPERATIONAL GATE BLOCKED", size=10, fg="#FBBF24"
        )
        self.scope_label.pack(side="right")
        self.status_label = Label(
            workspace, textvariable=self.status, size=12, fg=ACCENT, max_width=1100
        )
        self.status_label.pack(anchor="w", pady=(0, 6))
        self.observability_label = Label(workspace, text="", size=11, fg="#FBBF24", max_width=1100)
        self.observability_label.pack(anchor="w", pady=(0, 10))
        scroll = ttk.Frame(workspace)
        scroll.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(scroll, background=BG, highlightthickness=0)
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(scroll, command=self.canvas.yview)
        scrollbar.pack(side="right", fill="y")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.content = ttk.Frame(self.canvas)
        self.content_window = self.canvas.create_window(0, 0, window=self.content, anchor="nw")

        def fit(_=None):
            self.canvas.itemconfigure(
                self.content_window, width=max(1, self.canvas.winfo_width() - 16)
            )
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))

        self.canvas.bind("<Configure>", fit)
        self.content.bind("<Configure>", fit)
        root.bind(
            "<MouseWheel>", lambda e: self.canvas.yview_scroll(-1 if e.delta > 0 else 1, "units")
        )
        root.bind("<Button-4>", lambda _: self.canvas.yview_scroll(-1, "units"))
        root.bind("<Button-5>", lambda _: self.canvas.yview_scroll(1, "units"))
        Label(
            workspace,
            text="DNS9 PARITY BLOCKED    ·    RESEARCH ADVISORY    ·    WRITE_DENIED",
            size=10,
            fg="#94A3B8",
        ).pack(anchor="w", pady=(12, 0))
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.navigate("Dashboard", refresh=False)
        root.after(0, self._startup)

    def _startup(self):
        self.call("production_status", callback=self._started)

    def _started(self, value):
        self.startup_complete = True
        self.render(value)
        if self.config.analysis_result:
            self.navigate("AI Analysis", refresh=False)
            self.call(
                "analysis_attach", str(self.config.analysis_result), callback=self.analysis_updated
            )
        elif self.config.continuous_directory:
            self.navigate("Continuous", refresh=False)
        elif self.config.collector_type.startswith("zeek-"):
            self.navigate("System", refresh=False)
        elif self.config.total_approved_sha:
            self.navigate("System", refresh=False)
            self.start()
        if self.on_ready is not None:
            ready, self.on_ready = self.on_ready, None
            ready(self)

    def navigate(self, page, refresh=True):
        if page not in SCREENS or self.closing:
            return
        self.page = page
        self.generation += 1
        self.last_render = None
        for child in self.content.winfo_children():
            child.destroy()
        for name, button in self.nav_buttons.items():
            button.configure(style="Accent.TButton" if name == page else "TButton")
        self.canvas.yview_moveto(0)
        if page == "Dashboard":
            operator_view.dashboard(self)
        elif page in ("Security Events", "Investigation"):
            operator_view.records(self)
        elif page == "Continuous":
            continuous_view.build(self)
        elif page == "AI Analysis":
            analysis_view.build(self)
        else:
            operator_view.system(self)
        self._render_current()
        if refresh:
            self.refresh()

    def continuous_updated(self, value):
        from soc_agent.gui.continuous_projection import project

        self.status.set(str(value.get("state", "UNKNOWN")) + " · Continuous service")
        self.snapshot = project(self.snapshot | dict(continuous=value))
        self.last_render = None
        self._render_current()

    def analysis_updated(self, value):
        from soc_agent.gui.continuous_projection import project

        origin = (
            "RETAINED_NATIVE"
            if "REAL_NATIVE" in (value.get("result") or {}).get("input_origins", [])
            else "OFFLINE"
        )
        self.status.set(str(value.get("state", "UNKNOWN")) + " · " + origin + " analysis")
        self.snapshot = project(self.snapshot | dict(analysis=value))
        self.last_render = None
        self._render_current()

    def _controller_unavailable(self):
        self.command = ""
        self.command_session = None
        self.busy, self.pending = False, None
        self.generation += 1
        value = {
            **self.snapshot,
            "state": "ERROR",
            "collection_live": False,
            "controller_alive": False,
            "handoff_listener_ready": False,
            "command_valid": False,
            "collector_command": None,
            "last_error": "ZEEK_CONTROLLER_NOT_RUNNING",
            "observation_started_ns": time.monotonic_ns(),
        }
        self.render(value)

    def call(self, operation, *args, callback=None, **kwargs):
        if not self.worker.thread.is_alive():
            self._controller_unavailable()
            return
        if self.busy or self.closing:
            return
        self.busy = True
        self.status.set("WORKING · " + operation)
        self.pending = (self.worker.submit(operation, *args, **kwargs), callback, self.generation)
        self.drain_timer = self.root.after(50, self._drain)

    def _drain(self):
        self.drain_timer = None
        if not self.worker.thread.is_alive():
            self._controller_unavailable()
            return
        future, callback, generation = self.pending
        if not future.done():
            self.drain_timer = self.root.after(50, self._drain)
            return
        self.pending = None
        self.busy = False
        try:
            result = future.result()
        except Exception as error:
            self.status.set("BLOCKED · " + safe_error(str(error)) + " · no automatic retry")
            self.command = ""
            self.command_session = None
            if self.page == "System":
                self.copy_button.configure(state="disabled")
        else:
            # Navigation invalidates callbacks tied to destroyed page widgets.
            if callback and (
                generation == self.generation
                or getattr(callback, "__name__", "") in ("render", "prepared", "_started")
            ):
                callback(result)
            elif isinstance(result, dict) and "observation_started_ns" in result:
                self.render(result)
        self._schedule_poll()

    def _schedule_poll(self):
        if self.poll_timer:
            self.root.after_cancel(self.poll_timer)
        if not self.closing:
            self.poll_timer = self.root.after(self.config.refresh_seconds * 1000, self.refresh)

    def refresh(self):
        if self.poll_timer:
            self.root.after_cancel(self.poll_timer)
        self.poll_timer = None
        if not self.busy:
            self.call("production_status", callback=self.render)

    def render(self, value):
        stamp = value.get("observation_started_ns", 0)
        if not isinstance(stamp, int) or stamp < self.last_stamp:
            return
        self.last_stamp = stamp
        self.snapshot = value
        self.visual_history.observe(value, at=stamp / 1e9)
        session = (value.get("session_id"), value.get("input_origin"))
        if session != self.history_session:
            self.history = MetricHistory(capacity=60)
            self.history_session = session
            self.history_sample = None
        # No imputed zeros. MetricHistory accepts only observed numeric fields.
        if value.get("session_id") and value.get("state") != "RETAINED_STREAM_NOT_LIVE":
            net = value.get("network", {})
            sample = (
                session,
                value.get("state"),
                net.get("packets_collected"),
                net.get("inference_count"),
                net.get("capture_uptime_seconds"),
            )
            if sample != self.history_sample:
                self.history_sample = sample
                self.history.observe(
                    {"network": net, "queue_backlog": net.get("queue_backlog")}, now=stamp / 1e9
                )
        if (
            value.get("collector_command")
            and value.get("command_valid") is True
            and value.get("handoff_listener_ready") is True
            and value.get("state") == "AUTHENTICATION_REQUIRED"
        ):
            self.command = value["collector_command"]
            self.command_session = value.get("session_id")
        elif not value.get("listener_ready"):
            self.command = ""
            self.command_session = None
        self.status.set(
            str(value.get("state", "UNKNOWN"))
            + " · "
            + (safe_error(value["last_error"]) if value.get("last_error") else "No reported error")
        )
        self._render_current()

    @staticmethod
    def _text(widget, body):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", body)
        widget.configure(state="disabled")

    def _render_current(self):
        value = self.snapshot
        if not value:
            return
        states = value.get("runtime_observability", {})
        self.scope_label.configure(
            text=(
                "NATIVE OBSERVED / MODEL ACTION SEPARATE"
                if value.get("continuous", {}).get("source") == "NATIVE_SERVICE"
                else "RESEARCH ONLY / OPERATIONAL GATE BLOCKED"
            )
        )
        self.observability_label.configure(
            text=(
                "AI / latency: "
                + str(states.get("inference", "NO_MEASURED_RESULT"))
                + " · Investigation: "
                + str(states.get("investigation", "NO_MEASURED_RESULT"))
                + "\nDNS transactions: "
                + str(states.get("dns", {}).get("transactions", "UNKNOWN"))
                + " · DNS message errors: "
                + str(states.get("dns", {}).get("semantic_parse_failures", "UNKNOWN"))
                + " · TCP control: "
                + str(states.get("dns", {}).get("transport_control", "UNKNOWN"))
                + " · Auth: "
                + str(states.get("authentication", "NOT_ATTACHED"))
            )
            if states
            else ""
        )
        projection = {k: v for k, v in value.items() if k != "observation_started_ns"}
        if self.page in ("Security Events", "Investigation"):
            projection = {
                "records": value.get("research", {}).get("records", []),
                "collector": value.get("collector"),
                "audit": value.get("runtime_audit_integrity"),
                "origin": value.get("input_origin"),
                "authentication": value.get("authentication"),
                "dns": value.get("dns"),
            }
        body = json.dumps(
            projection,
            sort_keys=True,
            default=str,
        )
        marker = (self.page, body, self.search.get())
        if marker == self.last_render:
            return
        self.last_render = marker
        if self.page == "Dashboard":
            operator_view.render_dashboard(
                self, value, [row for row in event_rows(value) if "collector_event" not in row[1]]
            )
        elif self.page in ("Security Events", "Investigation"):
            self.records = event_rows(
                value, self.search.get() if self.page == "Security Events" else ""
            )
            operator_view.render_records(self, value)
            self.tree.delete(*self.tree.get_children())
            for i, (row, _) in enumerate(self.records):
                self.tree.insert(
                    "",
                    "end",
                    iid=str(i),
                    values=tuple(f"{x:.3f}" if isinstance(x, float) else str(x)[:160] for x in row),
                )
            self.record_count.configure(
                text=f"{len(self.records)} events · {value.get('input_origin', 'NO_DATA')}"
            )
            self._text(
                self.detail,
                "Select an event to review model provenance and evidence.\n"
                "Investigations are READ-only.\n\n"
                "Research scores are not confirmed attacks.",
            )
        elif self.page == "Continuous":
            continuous_view.render(self, value.get("continuous", {}))
        elif self.page == "AI Analysis":
            analysis_view.render(
                self,
                value.get("analysis", {})
                | dict(
                    runtime_observability=states,
                    runtime_source=value.get("continuous", {}).get("source"),
                ),
            )
        else:
            operator_view.render_system(self, value)

    def select(self, _event=None):
        selected = self.tree.selection()
        if selected:
            original = self.records[int(selected[0])][1]
            if original.get("analysis_output"):
                self.navigate("AI Analysis", refresh=False)
                self.call(
                    "analysis_attach", original["analysis_output"], callback=self.analysis_updated
                )
                return
            record = display_data(original)
            if "dns_event" in record:
                self.detail_title.configure(text="DNS metadata · transaction evidence")
                self._text(
                    self.detail,
                    json.dumps(record["dns_event"], indent=2)
                    + "\nDNS9 inference BLOCKED: training extraction contract incomplete.",
                )
                return
            if "authentication_event" in record:
                self.detail_title.configure(text="Host authentication · observed event")
                self._text(
                    self.detail,
                    json.dumps(record["authentication_event"], indent=2)
                    + "\nNo per-event IF prediction. Complete compatible windows are required.",
                )
                return
            if "collector_event" in record:
                self.detail_title.configure(text="Zeek diagnostic · AI BLOCKED")
                self._text(
                    self.detail,
                    "SOURCE / DIAGNOSTIC ONLY · NOT AN AI FINDING\n"
                    + json.dumps(record["collector_event"], indent=2)
                    + "\nREAD-only investigation pending verified model input. "
                    "No receipt generated.",
                )
                return
            receipt = record.get("receipt") or {}
            investigation = record.get("investigation") or {}
            self.detail_title.configure(text=friendly_model(receipt.get("profile")))
            if self.page == "Investigation":
                self.event_charts[0].update_data(
                    {**self.snapshot, "research": {"records": [record]}}, self.visual_history
                )
            assessment = investigation.get("assessment")
            threat = assessment.get("threat_assessment", {}) if isinstance(assessment, dict) else {}
            incident = assessment.get("incident_state", {}) if isinstance(assessment, dict) else {}
            evidence = incident.get("evidence", [])
            timeline = investigation.get("timeline") or {}
            entries = timeline.get("entries", []) if isinstance(timeline, dict) else []
            progress = [
                str(e.get("content", {}).get("result", {}).get("reason", "UNKNOWN"))[:200]
                for e in entries[-16:]
            ]
            sections = [
                "SOURCE & ADVISORY",
                str(receipt.get("origin", "UNKNOWN")),
                str(record.get("advisory_current", "RESEARCH_ONLY")),
                "Session  " + str(receipt.get("capture_session", "UNKNOWN"))[:36],
                "Feature  " + str(receipt.get("feature_digest", "UNKNOWN"))[:20],
                "Artifact  " + str(receipt.get("artifact_digest", "UNKNOWN"))[:20],
                "",
                "MODEL RESULT · UNCALIBRATED",
                str(receipt.get("prediction", "UNKNOWN")),
                "Score  " + str(receipt.get("score", "UNKNOWN")),
                "Time   " + str(receipt.get("inferred_at", "UNKNOWN")),
                "Integrity  " + str(record.get("integrity_status_current", "UNKNOWN")),
                "",
                "READ-ONLY INVESTIGATION",
                str(investigation.get("status", "UNKNOWN")),
                "",
                "THREAT ASSESSMENT · RESEARCH ADVISORY",
                str(threat.get("severity", "UNKNOWN")).upper()
                + " · "
                + str(
                    threat.get(
                        "summary",
                        assessment if isinstance(assessment, str) else "No assessment available",
                    )
                )[:1600],
                "",
                "OBSERVED PROGRESS · no implied response execution",
                "\n".join(progress) if progress else "No recorded steps",
                "",
                "TOOL EVIDENCE",
                "\n".join(
                    str(e.get("tool_name", "UNKNOWN"))
                    + " · "
                    + str(e.get("summary", "UNKNOWN"))[:300]
                    for e in evidence[:16]
                )
                if evidence
                else "No tool evidence recorded",
                "",
                "EVIDENCE REFERENCES",
                json.dumps(investigation.get("evidence_references"), indent=2, default=str),
                "",
                "WRITE_DENIED · No operational finding promotion",
            ]
            self._text(self.detail, "\n".join(sections))

    def raw_detail(self):
        selected = self.tree.selection()
        if selected:
            self._text(
                self.detail,
                json.dumps(display_data(self.records[int(selected[0])][1]), indent=2, default=str)[
                    :64000
                ],
            )

    def developer_tools(self):
        messagebox.showinfo(
            "Research tools",
            "Research/replay tools remain available in a separate desktop:\n"
            ".venv/bin/python -m soc_agent.gui --developer\n"
            "Use a separate --data-directory for concurrent operation.",
        )

    def start(self):
        if self.config.continuous_directory or self.snapshot.get("continuous"):
            self.call("continuous_start", callback=self.continuous_updated)
            return
        if getattr(self, "terminal_managed", False):
            self.status.set("New Capture requires a fresh terminal command and approval")
            return
        if self.collector_type.get() == "zeek-live":
            self.command = ""
            self.command_session = None
            self.call("zeek_live_prepare", callback=self.render)
            return
        if self.collector_type.get().startswith("zeek-"):
            pcap = self.config.zeek_pcap
            sha = self.config.zeek_pcap_sha256
            if pcap is None:
                chosen = filedialog.askopenfilename(filetypes=(("Offline PCAP", "*.pcap"),))
                if not chosen:
                    return
                from pathlib import Path

                pcap = Path(chosen)
                sha = None  # The backend validates and hashes bounded files off the Tk thread.
            self.command = ""
            self.command_session = None
            self.call(
                "zeek_start",
                str(pcap),
                sha,
                self.collector_type.get() == "zeek-network14-offline",
                callback=self.render,
            )
            return
        self.command = ""
        self.command_session = None
        self.call("total_start", "both", True, self.policy.get(), callback=self.prepared)

    def prepared(self, result):
        stamp = result.get("observation_started_ns", 0)
        if not isinstance(stamp, int) or stamp < self.last_stamp:
            return
        self.render(result)
        command, sha, session = (
            result.get("command"),
            result.get("helper_sha256"),
            result.get("session_id"),
        )
        ready = (
            result.get("listener_ready") is True
            and isinstance(command, str)
            and 0 < len(command) <= 8192
            and isinstance(sha, str)
            and re.fullmatch(r"[a-f0-9]{64}", sha)
            and isinstance(session, str)
            and len(session) <= 128
        )
        if ready:
            self.command, self.command_session = command, session
            if self.config.total_approved_sha == sha and self.config.total_approved_sha:
                self.call("total_authenticate", session, sha, callback=lambda _: self.refresh())
        self.last_render = None
        self._render_current()
        if self.page == "System":
            self.copy_button.configure(state="normal" if ready else "disabled")

    def copy_command(self):
        if self.snapshot.get("collector", {}).get("type") == "zeek-live":
            session, command = self.command_session, self.command

            def checked(value):
                if (
                    command
                    and value.get("session_id") == session
                    and value.get("state") == "AUTHENTICATION_REQUIRED"
                    and value.get("command_valid") is True
                    and value.get("handoff_listener_ready") is True
                    and value.get("collector_command") == command
                    and self.command_session == session
                    and self.command == command
                ):
                    self.root.clipboard_clear()
                    self.root.clipboard_append(command)
                else:
                    self.command = ""
                    self.command_session = None
                    self.status.set("BLOCKED · ZEEK_SESSION_COMMAND_STALE")

            self.call(
                "zeek_live_command",
                session,
                self.snapshot.get("plan_digest"),
                self.snapshot.get("controller_generation"),
                callback=checked,
            )
            return
        if not self.command or self.snapshot.get("listener_ready") is not True:
            return
        session = self.command_session

        def confirmed(value):
            if (
                value.get("listener_ready") is True
                and value.get("session_id") == session
                and value.get("command") == self.command
            ):
                self.root.clipboard_clear()
                self.root.clipboard_append(self.command)
            else:
                self.command = ""
                self.command_session = None
                self.status.set("BLOCKED · STREAM_LISTENER_NOT_READY")
                if self.page == "System":
                    self.copy_button.configure(state="disabled")

        self.call("total_command", session, callback=confirmed)

    def archive(self):
        if messagebox.askyesno(
            "Preserve inactive evidence",
            "Verify and move inactive sessions into a bounded archive? "
            "No evidence will be deleted. Corrupt or active sessions block the transition.",
        ):
            self.call("archive_sessions", callback=self._system_result)

    def _system_result(self, value):
        if self.page == "System":
            self._text(self.system, json.dumps(value, indent=2, default=str)[:64000])

    def export(self, fmt):
        name = filedialog.asksaveasfilename(defaultextension=".json" if fmt == "json" else ".md")
        if name:
            self.call(
                "total_export",
                name,
                fmt,
                callback=lambda _: self.status.set("EXPORTED · local only"),
            )

    def close(self, reason="GUI_CLOSE"):
        if not self.worker.thread.is_alive():
            self.command, self.command_session = "", None
            if self.poll_timer:
                self.root.after_cancel(self.poll_timer)
            self.root.destroy()
            return
        if self.closing:
            return
        if self.busy:
            self.root.after(100, lambda: self.close(reason=reason))
            return
        self.closing = True
        if self.poll_timer:
            self.root.after_cancel(self.poll_timer)
        self.command = ""
        self.command_session = None
        future = self.worker.submit("close", reason)

        def finish():
            if not future.done():
                self.root.after(100, finish)
                return
            try:
                future.result()
            except Exception:
                self.closing = False
                self.status.set("UNKNOWN shutdown · review before closing")
                return
            self.worker.shutdown()
            self.root.destroy()

        self.root.after(50, finish)

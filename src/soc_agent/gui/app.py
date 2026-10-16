"""Tk presentation. Every backend task runs outside the Tk event loop."""

import asyncio
import json
import re
import threading
import tkinter as tk
from datetime import UTC, datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from soc_agent.gui.backend import Backend, GUIConfig
from soc_agent.gui.charts import Comparison, Distribution, MetricHistory, ModelLatency, Trend
from soc_agent.gui.components import Button, Hero, Label, Table, color
from soc_agent.gui.presentation import screen_data, sections, short
from soc_agent.gui.queries import display_data

BG = "#0B1220"
PANEL = "#17243A"
EDGE = "#20314A"
TEXT = "#F1F5F9"
MUTED = "#94A3B8"
ACCENT = "#38BDF8"
SCREENS = (
    "Dashboard",
    "Investigations",
    "Security AI Models",
    "Response & Approval",
    "Self-Improvement",
    "Network Research",
    "Live Network",
    "Streaming Network",
    "Scenario Demo",
)


class Worker:
    def __init__(self, config):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(
            target=self.loop.run_forever, name="soc-gui-backend", daemon=True
        )
        self.thread.start()
        self.backend = asyncio.run_coroutine_threadsafe(self._create(config), self.loop).result(10)

    async def _create(self, config):
        return Backend(config)

    def submit(self, operation, *args, **kwargs):
        async def execute():
            method = getattr(self.backend, operation)
            value = method(*args, **kwargs)
            return await value if asyncio.iscoroutine(value) else value

        return asyncio.run_coroutine_threadsafe(execute(), self.loop)

    def shutdown(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(2)
        self.loop.close()


class Desktop:
    def __init__(self, root: tk.Tk, config: GUIConfig):
        self.root = root
        self.config = config
        self.worker = Worker(config)
        # UI callbacks stay on the Tk thread, never in worker-owned Future callbacks.
        self.pending = None
        self.busy = False
        self.closing = False
        self.page = "Dashboard"
        self.records = {}
        self.current_records = []
        self.result_by_scenario = {}
        self.selected_result = None
        self.history = MetricHistory()
        self.history_scope = None
        self.last_probe = None
        self.ai_environment = {"status": "UNKNOWN"}
        self.last_dashboard = {}
        self.last_updated = "UNKNOWN"
        self.last_details = None
        self.last_model_view = None
        self.resize_timer = None
        self.raw_visible = False
        root.title("Autonomous SOC Agent · Linux v1")
        root.geometry("1600x940")
        root.minsize(1100, 700)
        root.configure(bg=BG)
        self._style()
        self.status_var = tk.StringVar(value="OFFLINE · NOT_READY")
        self.notice = tk.StringVar(
            value="READ-only investigation · Human-governed action · Network/DNS NOT_INFERABLE"
        )
        self._build()
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(50, self._drain)
        root.after(150, self._startup)
        self.poll_timer = root.after(config.refresh_seconds * 1000, self._poll)
        root.bind("<Configure>", self._on_resize, add="+")

    def _startup(self):
        if self.busy:
            self.root.after(100, self._startup)
            return
        self.call("models", callback=self._startup_models)

    def _startup_models(self, value):
        self.ai_environment = value.get("environment", {"status": "UNKNOWN"})
        self.ai_status.set("AI Fixture env: " + self.ai_environment["status"])
        if self.page == "Security AI Models":
            self.render_models(value)
        else:
            self.refresh()

    def _on_resize(self, event):
        if event.widget is not self.root:
            return
        if self.resize_timer is not None:
            self.root.after_cancel(self.resize_timer)
        self.resize_timer = self.root.after(120, self._resize_views)

    def _resize_views(self):
        self.resize_timer = None
        if self.page == "Security AI Models" and self.last_model_view:
            self._model_cards(*self.last_model_view)
        if self.page != "Dashboard" and self.last_details is not None:
            self.show_detail(self.last_details)

    def _style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=TEXT, font=("DejaVu Sans", 11))
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Muted.TLabel", foreground=MUTED)
        style.configure("Title.TLabel", font=("DejaVu Sans", 28, "bold"))
        style.configure("Header.TLabel", font=("DejaVu Sans", 15, "bold"))
        style.configure("TButton", background=EDGE, foreground=TEXT, padding=(12, 9), borderwidth=0)
        style.map(
            "TButton",
            background=[("active", "#35465b"), ("disabled", PANEL)],
            foreground=[("disabled", MUTED)],
        )
        style.configure("Accent.TButton", background="#155E75", foreground=TEXT)
        style.configure("Approve.TButton", background="#14532D", foreground=TEXT)
        style.configure("Reject.TButton", background="#7F1D1D", foreground=TEXT)
        style.configure(
            "Treeview",
            background=PANEL,
            fieldbackground=PANEL,
            foreground=TEXT,
            rowheight=38,
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background=EDGE,
            foreground=TEXT,
            padding=10,
            font=("DejaVu Sans", 10, "bold"),
        )
        style.map(
            "Treeview", background=[("selected", "#25483f")], foreground=[("selected", "#c4f9e8")]
        )
        style.configure("TEntry", fieldbackground=PANEL, foreground=TEXT, padding=8)
        style.configure("TCombobox", fieldbackground=PANEL, foreground=TEXT, padding=8)
        style.configure(
            "Vertical.TScrollbar",
            background=EDGE,
            troughcolor=BG,
            bordercolor=BG,
            arrowcolor=MUTED,
            lightcolor=EDGE,
            darkcolor=EDGE,
            width=12,
        )
        style.configure(
            "Horizontal.TProgressbar",
            background=ACCENT,
            troughcolor=PANEL,
            bordercolor=PANEL,
            lightcolor=ACCENT,
            darkcolor=ACCENT,
            thickness=4,
        )

    def _build(self):
        shell = ttk.Frame(self.root)
        shell.pack(fill="both", expand=True)
        side = tk.Frame(shell, bg="#111C2E", width=204)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        Label(
            side, text="SENTINEL / SOC", fg=ACCENT, bg="#111C2E", font=("DejaVu Sans", 18, "bold")
        ).pack(pady=(28, 4))
        Label(
            side, text="LINUX SECURITY  /  v1", fg=MUTED, bg="#111C2E", font=("DejaVu Sans", 10)
        ).pack(pady=(0, 24))
        self.nav_buttons = {}
        for name in SCREENS:
            button = Button(
                side,
                text="Research Demo" if name == "Network Research" else name,
                command=lambda n=name: self.navigate(n),
            )
            button.pack(fill="x", padx=12, pady=6)
            self.nav_buttons[name] = button
        Label(
            side,
            text="보안 관제 · 승인 기반 대응\nREAD-ONLY BY DEFAULT",
            fg=MUTED,
            bg="#111C2E",
            justify="left",
            font=("DejaVu Sans", 9),
        ).pack(side="bottom", padx=14, pady=24)
        body = ttk.Frame(shell)
        body.pack(side="left", fill="both", expand=True, padx=20, pady=14)
        header = ttk.Frame(body)
        header.pack(fill="x")
        self.title = Label(header, text=self.page, style="Title.TLabel")
        self.title.pack(side="left")
        Label(header, text="INPUT: " + self.config.source_label, size=11, fg=ACCENT).pack(
            side="right", padx=(12, 0)
        )
        self.ai_status = tk.StringVar(value="AI Fixture env: CHECKING")
        Label(header, textvariable=self.ai_status, size=11, fg=ACCENT).pack(side="right", padx=12)
        Label(header, textvariable=self.status_var, style="Muted.TLabel").pack(side="right")
        Label(body, textvariable=self.notice, style="Muted.TLabel", wraplength=1200).pack(
            fill="x", pady=(8, 10)
        )
        self.toolbar = ttk.Frame(body)
        self.toolbar.pack(fill="x", pady=(0, 10))
        scroll = ttk.Frame(body)
        scroll.pack(fill="both", expand=True)
        self.content_canvas = tk.Canvas(scroll, bg=BG, highlightthickness=0)
        self.content_canvas.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(scroll, orient="vertical", command=self.content_canvas.yview)
        scrollbar.pack(side="right", fill="y")
        self.content_canvas.configure(yscrollcommand=scrollbar.set)
        self.content = ttk.Frame(self.content_canvas)
        self.content_window = self.content_canvas.create_window(
            0, 0, window=self.content, anchor="nw"
        )

        def fit(_event=None):
            self.content_canvas.itemconfigure(
                self.content_window, width=self.content_canvas.winfo_width()
            )
            self.content_canvas.configure(scrollregion=self.content_canvas.bbox("all"))

        self.content.bind("<Configure>", fit)
        self.content_canvas.bind("<Configure>", fit)
        self.root.bind(
            "<MouseWheel>",
            lambda e: self.content_canvas.yview_scroll(-1 if e.delta > 0 else 1, "units"),
        )
        self.root.bind("<Button-4>", lambda _: self.content_canvas.yview_scroll(-1, "units"))
        self.root.bind("<Button-5>", lambda _: self.content_canvas.yview_scroll(1, "units"))
        self.navigate("Dashboard", refresh=False)

    def navigate(self, name, refresh=True):
        if name not in SCREENS:
            return
        self.page = name
        self.notice.set("READ-only views · explicit operator actions · source and mode per record")
        self.title.configure(text=name)
        for n, button in self.nav_buttons.items():
            button.configure(style="Accent.TButton" if n == name else "TButton")
        self.content_canvas.yview_moveto(0)
        self.current_records = []
        self.selected_result = None
        for container in (self.toolbar, self.content):
            for child in container.winfo_children():
                child.destroy()
        Button(self.toolbar, text="Refresh", command=self.refresh).pack(side="right")
        if name == "Dashboard":
            self._dashboard_layout()
        elif name == "Network Research":
            from soc_agent.gui.research_view import ResearchView

            self.research_view = ResearchView(self)
        elif name in ("Live Network", "Streaming Network"):
            from soc_agent.gui.live_view import LiveView

            self.live_view = LiveView(self, streaming=name == "Streaming Network")
        elif name == "Scenario Demo":
            self._scenario_layout()
        elif name == "Response & Approval":
            self._response_layout()
        elif name == "Security AI Models":
            self.ai_explanation = tk.StringVar(value="Checking AI environment…")
            Label(self.content, textvariable=self.ai_explanation, size=13, max_width=1100).pack(
                fill="x", pady=(0, 12)
            )
            self.loading = ttk.Progressbar(self.content, mode="indeterminate")
            self.loading.pack(fill="x", pady=(0, 8))
            self.model_grid = ttk.Frame(self.content)
            self.model_grid.pack(fill="x", pady=(0, 12))
            self.model_cards = []
            Button(self.toolbar, text="AI environment check", command=self.refresh).pack(
                side="left", padx=(0, 8)
            )
            Button(self.toolbar, text="Run native Fixture demo", command=self.model_probe).pack(
                side="left"
            )
            self.latency_chart = ModelLatency(self.content)
            self.latency_chart.pack(fill="x", pady=(0, 12))
            if self.last_probe:
                self.latency_chart.update_models(self.last_probe.get("models", []))
            self._table(("model", "import", "artifact", "backend", "demo", "operational"))
            self.detail_parent.pack(before=self.table_top, fill="x", pady=(8, 0))
        elif name == "Investigations":
            self.investigation_hero = tk.Frame(self.content, bg=PANEL, padx=16, pady=12)
            self.investigation_hero.pack(fill="x", pady=(0, 12))
            Label(
                self.investigation_hero,
                text="Select a finding to review evidence",
                size=18,
                bg=PANEL,
            ).pack(anchor="w")
            Label(
                self.toolbar,
                text="OBSERVED references ≠ UNTRUSTED assessment",
                style="Muted.TLabel",
            ).pack(side="left")
            self._table(("finding", "rule", "status", "origin", "mode"))
        else:
            self.improvement_count = tk.StringVar(
                master=self.root, value="Stored results • UNKNOWN until queried"
            )
            Label(self.content, textvariable=self.improvement_count, size=14).pack(
                anchor="w", pady=(0, 10)
            )
            for label, cmd in [
                ("Outcomes", "feedback"),
                ("Human Feedback", "feedback-list"),
                ("Candidates", "candidates"),
                ("Offline evaluation", "evaluations"),
                ("Human review", "reviews"),
            ]:
                Button(self.toolbar, text=label, command=lambda c=cmd: self.operation(c)).pack(
                    side="left", padx=(0, 6)
                )
            self.improvement_chart = Comparison(self.content)
            self.improvement_chart.pack(fill="x", pady=(0, 12))
            self.feedback_chart = Distribution(
                self.content, "FEEDBACK • operator opinion, not ground truth"
            )
            self.feedback_chart.pack(fill="x", pady=(0, 12))
            self._table(("reference", "kind", "status", "origin"))
        if refresh:
            self.refresh()

    def _dashboard_layout(self):
        for label, cmd in [
            ("Connect", self.connect),
            ("Initialize", self.initialize),
            ("Start Runtime", lambda: self.call("start")),
            ("Stop owned Runtime", lambda: self.call("stop")),
        ]:
            Button(self.toolbar, text=label, command=cmd).pack(side="left", padx=(0, 6))
        self.hero = Hero(self.content)
        self.hero.pack(fill="x", pady=(0, 14))
        from soc_agent.gui.unified import UnifiedPanel

        self.unified_panel = UnifiedPanel(self.content, self)
        self.cards = {}
        grid = ttk.Frame(self.content)
        grid.pack(fill="x", pady=(0, 16))
        for i, (key, label) in enumerate(
            [
                ("collected_events", "RETAINED EVENTS"),
                ("active_findings", "ACTIVE FINDINGS"),
                ("completed_total", "COMPLETED"),
                ("pending_approvals", "PENDING APPROVAL"),
                ("queue_backlog", "QUEUE BACKLOG"),
                ("failed_investigations", "FAILED JOBS"),
            ]
        ):
            frame = tk.Frame(
                grid, bg=PANEL, padx=14, pady=12, highlightthickness=1, highlightbackground=EDGE
            )
            frame.grid(row=0, column=i, sticky="nsew", padx=(0, 8))
            grid.columnconfigure(i, weight=1, uniform="kpi")
            Label(frame, text=label, size=11, fg=MUTED, bg=PANEL, max_width=180).pack(anchor="w")
            var = tk.StringVar(master=self.root, value="UNKNOWN")
            self.cards[key] = var
            Label(frame, textvariable=var, size=30, bold=True, bg=PANEL, max_width=180).pack(
                anchor="w", pady=(8, 0)
            )
        Label(self.content, text="Security activity", size=19, bold=True).pack(
            anchor="w", pady=(0, 5)
        )
        Label(
            self.content,
            text="Backend measurements • counts • session history • hover or use arrow keys",
            size=12,
            fg=MUTED,
        ).pack(anchor="w", pady=(0, 8))
        chart_frame = ttk.Frame(self.content)
        chart_frame.pack(fill="x", pady=(0, 14))
        self.trends = [
            Trend(chart_frame, self.history, "queue", "QUEUE BACKLOG", ACCENT),
            Trend(chart_frame, self.history, "completed", "COMPLETED INVESTIGATIONS", "#A78BFA"),
        ]
        for chart in self.trends:
            chart.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.network_summary = tk.StringVar(
            value="Network / DNS UNKNOWN • operational inference NOT_INFERABLE"
        )
        Label(self.content, textvariable=self.network_summary, size=12, max_width=1200).pack(
            fill="x", pady=(0, 10)
        )
        self.live_summary = tk.StringVar(value="Live Network UNKNOWN · operational gate BLOCKED")
        Label(self.content, textvariable=self.live_summary, size=12, max_width=1200).pack(fill="x")
        Button(
            self.content, text="Open Live Network", command=lambda: self.navigate("Live Network")
        ).pack(anchor="e", pady=(0, 10))
        Button(
            self.content,
            text="Streaming Monitoring",
            command=lambda: self.navigate("Streaming Network"),
        ).pack(anchor="e", pady=(0, 10))
        network_charts = ttk.Frame(self.content)
        network_charts.pack(fill="x", pady=(0, 12))
        extra = [
            Trend(
                network_charts, self.history, "network_rate", "NETWORK TRAFFIC", ACCENT, "packets/s"
            ),
            Trend(
                network_charts, self.history, "dns_rate", "DNS QUERIES", "#A78BFA", "queries/min"
            ),
            Trend(network_charts, self.history, "ai_count", "OPERATIONAL AI INVOCATIONS", ACCENT),
        ]
        for chart in extra:
            chart.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.trends.extend(extra)
        self.network_distribution = Distribution(
            self.content, "OPERATIONAL model results • no fixture mixing"
        )
        self.network_distribution.pack(fill="x", pady=(0, 12))
        lower = ttk.Frame(self.content)
        lower.pack(fill="x", pady=(0, 10))
        self.activity = tk.Frame(lower, bg=PANEL, padx=16, pady=12)
        self.activity.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.distribution = Distribution(lower, "INVESTIGATION STATUS")
        self.distribution.pack(side="right", fill="both", expand=True)
        self._detail(self.content, height=5)
        self.summary_frame.pack_forget()
        self.render_dashboard(self.last_dashboard or {"runtime_state": "OFFLINE"}, record=False)

    def _table(self, columns):
        top = ttk.Frame(self.content, height=252)
        top.pack(fill="x")
        top.pack_propagate(False)
        self.table_top = top
        self.tree = Table(top, columns)
        for col in columns:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=160, minwidth=80, stretch=True)
        scroll = ttk.Scrollbar(top, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.tag_configure("pass", foreground="#78dfba")
        self.tree.tag_configure("blocked", foreground="#f0b37c")
        self.tree.tag_configure("fail", foreground="#f68c9c")
        self.tree.bind("<<TreeviewSelect>>", self.select)
        bottom = ttk.Frame(self.content)
        bottom.pack(fill="x", pady=(8, 0))
        self.detail_parent = bottom
        self._detail(bottom)
        Button(bottom, text="Copy selected ID / digest", command=self.copy_reference).pack(
            anchor="e", pady=5
        )

    def _detail(self, parent, height=5):
        self.summary_frame = ttk.Frame(parent)
        self.summary_frame.pack(fill="x", pady=(8, 8))
        controls = ttk.Frame(parent)
        controls.pack(fill="x", pady=(4, 6))
        Button(controls, text="Technical details / JSON", command=self.toggle_raw).pack(side="left")
        Button(controls, text="Copy digest", command=lambda: self.copy_reference(digest=True)).pack(
            side="left", padx=6
        )
        self.raw_container = ttk.Frame(parent)
        self.detail = tk.Text(
            self.raw_container,
            height=height,
            bg=PANEL,
            fg=TEXT,
            wrap="word",
            relief="flat",
            padx=14,
            pady=10,
        )
        self.detail.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(self.raw_container, command=self.detail.yview)
        scroll.pack(side="right", fill="y")
        self.detail.configure(yscrollcommand=scroll.set)
        self.raw_visible = False
        self.show_detail({"status": "NO_DATA"})

    def toggle_raw(self):
        self.raw_visible = not self.raw_visible
        if self.raw_visible:
            self.raw_container.pack(fill="both", expand=True)
        else:
            self.raw_container.pack_forget()

    def show_detail(self, data):
        self.last_details = screen_data(display_data(data))
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert(
            "end", json.dumps(self.last_details, indent=2, ensure_ascii=False, default=str)
        )
        self.detail.configure(state="disabled")
        if (
            self.page == "Investigations"
            and isinstance(self.last_details, dict)
            and "rule_id" in self.last_details
        ):
            for child in self.investigation_hero.winfo_children():
                child.destroy()
            value = self.last_details
            Label(
                self.investigation_hero,
                text=value["rule_id"].replace("_", " ").title(),
                size=22,
                bold=True,
                bg=PANEL,
            ).pack(anchor="w")
            Label(
                self.investigation_hero,
                text="Severity "
                + str(value.get("severity", "UNKNOWN"))
                + " • "
                + str(value.get("status", "UNKNOWN"))
                + " • "
                + str(value.get("assessment_mode", "UNKNOWN")),
                size=13,
                fg=color(value.get("status")),
                bg=PANEL,
            ).pack(anchor="w", pady=(6, 0))
            Label(
                self.investigation_hero,
                text="Incident "
                + short(value.get("incident_id"))
                + " • source references are digest-checked, not independent source attestation",
                size=11,
                fg=MUTED,
                bg=PANEL,
                max_width=max(400, self.root.winfo_width() - 310),
            ).pack(anchor="w", pady=(4, 0))
        for child in self.summary_frame.winfo_children():
            child.destroy()
        for i, (heading, body) in enumerate(sections(self.page, self.last_details)):
            panel = tk.Frame(self.summary_frame, bg=PANEL, padx=14, pady=10)
            panel.grid(row=i // 2, column=i % 2, sticky="nsew", padx=(0, 8), pady=(0, 6))
            self.summary_frame.columnconfigure(i % 2, weight=1, uniform="detail")
            width = max(200, (self.root.winfo_width() - 300) // 2 - 45)
            Label(panel, text=heading, size=13, bold=True, bg=PANEL, max_width=width).pack(
                anchor="w"
            )
            Label(panel, text=body, size=12, fg=MUTED, bg=PANEL, max_width=width).pack(
                anchor="w", pady=(5, 0)
            )
        if self.page == "Response & Approval" and hasattr(self, "response_buttons"):
            self._response_heading(self.last_details)
            self._update_action_buttons()

    def _response_heading(self, value):
        if not isinstance(value, dict):
            return
        value = value.get("result", value)
        if not isinstance(value, dict) or "record" not in value:
            return
        for child in self.response_hero.winfo_children():
            child.destroy()
        fields = sections(self.page, value)
        width = max(350, self.root.winfo_width() - 300)
        Label(
            self.response_hero,
            text=fields[0][1] + " • " + str(value.get("status", "UNKNOWN")),
            size=17,
            bold=True,
            fg=color(value.get("status")),
            bg=PANEL,
            max_width=width,
        ).pack(anchor="w")
        Label(
            self.response_hero,
            text="Target: "
            + fields[2][1]
            + "   Expires: "
            + str(value["record"].get("approval", {}).get("expires_at", "UNKNOWN")),
            size=12,
            bg=PANEL,
            max_width=width,
        ).pack(anchor="w", pady=(5, 0))
        Label(
            self.response_hero,
            text="Evidence: "
            + fields[3][1]
            + " • policy revalidated on execution • no OS security response",
            size=11,
            fg=MUTED,
            bg=PANEL,
            max_width=width,
        ).pack(anchor="w", pady=(3, 0))

    def _scenario_layout(self):
        Label(
            self.toolbar,
            text="FIXTURE / REPLAY · SCRIPTED · RESPONSE_SIMULATION",
            style="Muted.TLabel",
        ).pack(side="left")
        Button(self.toolbar, text="Run selected", command=self.run_scenario).pack(
            side="left", padx=6
        )
        Button(
            self.toolbar,
            text="Run all S01–S12",
            command=lambda: self.run_scenario(all_scenarios=True),
        ).pack(side="left")
        self.loading = ttk.Progressbar(self.content, mode="indeterminate", length=300)
        self.loading.pack(fill="x", pady=(0, 8))
        self._table(("scenario", "description", "origin", "status"))
        self._render_catalog()

    def _render_catalog(self):
        if self.page != "Scenario Demo":
            return
        self.current_records = self.worker.backend.scenario_catalog()
        self._rows(
            [
                (
                    s["id"],
                    s["description"],
                    "FIXTURE",
                    self.result_by_scenario.get(s["id"], {}).get("overall_status", "NOT_RUN"),
                )
                for s in self.current_records
            ]
        )

    def _response_layout(self):
        for label, cmd in [
            ("Simulation approvals", "simulation-records"),
            ("Restricted test actions", "restricted-list"),
            ("Audit receipts", "audit"),
        ]:
            Button(self.toolbar, text=label, command=lambda c=cmd: self.operation(c)).pack(
                side="left", padx=(0, 5)
            )
        self.response_kind = tk.StringVar(value="simulation")
        ttk.Radiobutton(
            self.toolbar,
            text="Simulation",
            variable=self.response_kind,
            value="simulation",
            command=self._change_response_mode,
        ).pack(side="left")
        ttk.Radiobutton(
            self.toolbar,
            text="Test marker",
            variable=self.response_kind,
            value="restricted",
            command=self._change_response_mode,
        ).pack(side="left")
        bar = ttk.Frame(self.content)
        bar.pack(fill="x", pady=(0, 10))
        self.response_buttons = {}
        for label, op in [
            ("Approve", "approve"),
            ("Reject", "reject"),
            ("Execute", "execute"),
            ("Request action", "request"),
            ("Request rollback", "rollback-request"),
        ]:
            button = Button(
                bar,
                text=label,
                command=lambda o=op: self.response_action(o),
                style="Approve.TButton"
                if op == "approve"
                else "Reject.TButton"
                if op == "reject"
                else "TButton",
            )
            button.pack(side="left", padx=(0, 5))
            self.response_buttons[op] = button
        Button(bar, text="Prepare test mode", command=self.prepare).pack(side="right")
        self.response_hero = tk.Frame(self.content, bg=PANEL, padx=14, pady=10)
        self.response_hero.pack(fill="x", pady=(0, 10))
        Label(
            self.response_hero,
            text="Select an approval to review the exact action",
            size=15,
            bg=PANEL,
        ).pack(anchor="w")
        self.approval_chart = Distribution(self.content, "APPROVAL STATUS • selected ledger")
        self.approval_chart.pack(fill="x", pady=(0, 10))
        self._table(("candidate", "type", "status", "approval"))

    def _rows(self, rows):
        for child in self.tree.get_children():
            self.tree.delete(child)
        for index, row in enumerate(rows):
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=row,
                tags=(
                    "fail"
                    if "FAIL" in row
                    else "blocked"
                    if "BLOCKED" in row or "NOT_INFERABLE" in row
                    else "pass"
                    if "PASS" in row
                    else "",
                ),
            )

    def select(self, *_):
        selected = self.tree.selection()
        if not selected:
            return
        index = int(selected[0])
        if index >= len(self.current_records):
            return
        self.selected_result = self.current_records[index]
        data = self.selected_result
        if self.page == "Scenario Demo":
            data = self.result_by_scenario.get(data["id"], data)
        if self.page == "Network Research":
            self.research_view.show_record(data)
        elif self.page in ("Live Network", "Streaming Network"):
            self.live_view.show_record(data)
        else:
            self.show_detail(data)

    def copy_reference(self, digest=False):
        if not self.selected_result and not self.last_details:
            return
        data = self.selected_result or self.last_details
        if not isinstance(data, dict):
            return
        research = data.get("research_record", data)
        if isinstance(research, dict) and research.get("receipt"):
            receipt = research["receipt"]
            value = (
                receipt.get("feature_digest", receipt.get("input_digest"))
                if digest
                else (
                    research.get("investigation", {}).get("incident_id")
                    or receipt.get("invocation_id")
                )
            )
            if value:
                self.root.clipboard_clear()
                self.root.clipboard_append(str(value))
                self.notice.set("Selected research reference copied.")
            return
        value = (
            data.get("finding_id")
            or data.get("candidate_id")
            or data.get("feedback_id")
            or data.get("id")
            or data.get("binding_id")
        )
        if not value and isinstance(data.get("record"), dict):
            value = data["record"].get("candidate_id") or data["record"].get("request", {}).get(
                "candidate_id"
            )
        if digest:
            value = next(
                (
                    data.get(k)
                    for k in (
                        "record_digest",
                        "result_digest",
                        "context_digest",
                        "feedback_digest",
                        "evaluation_id",
                        "artifact_catalog_digest",
                        "audit_receipt",
                    )
                    if data.get(k)
                ),
                None,
            )
            if not value and isinstance(self.last_details, dict):
                value = next(
                    (
                        self.last_details.get(k)
                        for k in (
                            "record_digest",
                            "result_digest",
                            "context_digest",
                            "evaluation_id",
                            "audit_receipt",
                        )
                        if self.last_details.get(k)
                    ),
                    None,
                )
        if value:
            self.root.clipboard_clear()
            self.root.clipboard_append(str(value))
            self.notice.set("Selected identifier copied.")

    def call(self, operation, *args, callback=None, **kwargs):
        if self.busy or self.closing:
            self.notice.set(
                "작업 진행 중입니다. 완료 후 다시 시도하세요. / Operation already running"
            )
            return
        self.busy = True
        self.notice.set("WORKING • " + operation + " • response only after backend confirmation")
        if (
            operation in ("scenario", "models", "fixture_probe")
            and hasattr(self, "loading")
            and self.loading.winfo_exists()
        ):
            if self.page == "Security AI Models":
                self.loading.pack(fill="x", pady=(0, 8), before=self.model_grid)
            self.loading.start(12)
        future = self.worker.submit(operation, *args, **kwargs)
        self.pending = (future, callback)
        self.pending_operation = operation

    def _drain(self):
        if self.pending and self.pending[0].done():
            future, callback = self.pending
            self.pending = None
            self.busy = False
            if hasattr(self, "loading") and self.loading.winfo_exists():
                self.loading.stop()
                if self.page == "Security AI Models":
                    self.loading.pack_forget()
            try:
                result = future.result()
            except Exception as error:
                code = str(error)
                safe = code if re.fullmatch(r"[A-Z0-9_]{1,100}", code) else type(error).__name__
                self.notice.set("BLOCKED • " + safe + " • No automatic retry")
                if self.pending_operation in ("models", "fixture_probe"):
                    self.last_probe = None
                    self.ai_environment = {"status": "VALIDATION_FAILED"}
                    self.ai_status.set("AI Fixture env: VALIDATION_FAILED")
                    if self.page == "Security AI Models":
                        self.ai_explanation.set(
                            "AI 점검/분석 실패: " + safe + " — 환경 점검 후 다시 시도하세요."
                        )
                        self.latency_chart.update_models([])
                        self._invalidate_model_cards()
                        self.show_detail({"status": "BLOCKED", "error": safe})
                if self.page == "Network Research" and self.pending_operation.startswith(
                    "research_"
                ):
                    self.research_view.show_error(safe)
                if self.pending_operation == "dashboard":
                    self.status_var.set("UNKNOWN / NOT_READY")
                    self.last_dashboard = {
                        "runtime_state": "UNKNOWN",
                        "health": "UNKNOWN",
                        "readiness": "NOT_READY",
                        "last_error": safe,
                        "metric_scope": self.history_scope,
                    }
                    if self.page == "Dashboard":
                        self.render_dashboard(self.last_dashboard)
            else:
                self.notice.set("Completed · " + self.page + " · Source / mode shown per record")
                if callback:
                    callback(result)
                elif hasattr(self, "detail") and self.detail.winfo_exists():
                    self.show_detail(result)
        if not self.closing:
            self.root.after(50, self._drain)

    def refresh(self):
        if self.page == "Dashboard":
            self.call("dashboard", callback=self.render_dashboard)
        elif self.page == "Investigations":
            self.call("investigations", callback=self.render_investigations)
        elif self.page == "Network Research":
            self.call("research_status", callback=self.research_view.render)
        elif self.page in ("Live Network", "Streaming Network"):
            self.call(self.live_view.prefix + "_status", callback=self.live_view.render)
        elif self.page == "Security AI Models":
            self.call("models", callback=self.render_models)
        elif self.page == "Response & Approval":
            self.operation("simulation-records")
        elif self.page == "Self-Improvement":
            self.operation("feedback")
        else:
            self._render_catalog()

    def _poll(self):
        if self.poll_timer is not None:
            self.root.after_cancel(self.poll_timer)
            self.poll_timer = None
        if not self.busy and not self.closing:
            self.call("dashboard", callback=self.render_dashboard)
        if not self.closing:
            self.poll_timer = self.root.after(self.config.refresh_seconds * 1000, self._poll)

    def render_dashboard(self, value, record=True):
        scope = value.get("metric_scope")
        capture_generation = value.get("network", {}).get("capture_generation")
        if capture_generation:
            scope = str(scope) + ":capture:" + capture_generation
        if record:
            if scope != self.history_scope:
                self.history.samples.clear()
                self.history_scope = scope
            self.history.observe(value)
            self.last_dashboard = value
            self.last_updated = datetime.now(UTC).strftime("%H:%M:%S UTC")
        value = dict(value)
        value["display_updated"] = self.last_updated
        value["display_source"] = value.get(
            "display_source", getattr(self.config, "source_label", "UNVERIFIED")
        )
        self.status_var.set(
            str(value.get("runtime_state", "UNKNOWN"))
            + " / "
            + str(value.get("readiness", "NOT_READY"))
        )
        if self.page != "Dashboard":
            return
        self.hero.update_snapshot(value)
        live = value.get("live_network", {})
        streaming = value.get("streaming_network", {})
        self.live_summary.set(
            "Live Network "
            + live.get("state", "UNKNOWN")
            + " · "
            + live.get("operational_gate", "UNKNOWN")
            + "\nStreaming "
            + streaming.get("state", "UNKNOWN")
            + " · "
            + streaming.get("input_origin", "NO_DATA")
            + " · Research calls "
            + str(streaming.get("network", {}).get("inference_count", "UNKNOWN"))
            + " · Operational AI BLOCKED"
        )
        self.unified_panel.render(value)
        completed = self.history.samples[-1].completed if self.history.samples else None
        value["completed_total"] = completed
        for key, var in self.cards.items():
            var.set(str(value[key]) if value.get(key) is not None else "UNKNOWN")
        for chart in self.trends:
            chart.source = (
                value.get("network", {}).get("input_origin", "UNKNOWN")
                if chart.metric in ("network_rate", "dns_rate", "ai_count")
                else value["display_source"]
            )
            chart.redraw()
        self.distribution.update_counts(value.get("investigation_distribution"))
        network = value.get("network", {})

        def known(item):
            return "UNKNOWN" if item is None else str(item)

        self.network_summary.set(
            "Network / DNS: "
            + str(network.get("state", "UNKNOWN"))
            + " • Permission / error: "
            + str(network.get("last_error") or "UNKNOWN")
            + " • Packets: "
            + known(network.get("packets_collected"))
            + " • Capture drops: "
            + known(network.get("capture_drops"))
            + " • Gaps: "
            + known(network.get("gap_count"))
            + " • Queue: "
            + known(network.get("queue_backlog"))
            + " • Authentication: "
            + str(value.get("collector_state", "UNKNOWN"))
            + " • Models: NOT_INFERABLE"
        )
        self.network_distribution.update_counts({} if network.get("inference_count") == 0 else None)
        for child in self.activity.winfo_children():
            child.destroy()
        Label(self.activity, text="Recent security findings", size=16, bold=True, bg=PANEL).pack(
            anchor="w"
        )
        recent = value.get("recent_activity")
        if not recent:
            Label(
                self.activity,
                text="NO_DATA • No timestamped findings available",
                size=12,
                fg=MUTED,
                bg=PANEL,
                max_width=650,
            ).pack(anchor="w", pady=14)
        else:
            for row in recent[:4]:
                Label(
                    self.activity,
                    text=str(row["event_time"]) + "  •  " + row["rule_id"].replace("_", " "),
                    size=12,
                    bg=PANEL,
                    max_width=max(250, (self.root.winfo_width() - 300) // 2 - 40),
                ).pack(anchor="w", pady=4)
        self.last_details = display_data(value)
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", json.dumps(self.last_details, indent=2, default=str))
        self.detail.configure(state="disabled")

    def render_investigations(self, value):
        if self.page != "Investigations":
            return
        self.current_records = value
        self._rows(
            [
                (
                    v["finding_id"][:16] + "…",
                    v["rule_id"],
                    v["status"],
                    v["origin"],
                    v["assessment_mode"],
                )
                for v in value
            ]
        )
        self.show_detail(
            {
                "records": len(value),
                "observation_boundary": "Source references; detection / assessment are advisory.",
            }
        )

    def render_models(self, value):
        self.ai_environment = value.get("environment", {"status": "UNKNOWN"})
        self.ai_status.set("AI Fixture env: " + self.ai_environment["status"])
        if self.page != "Security AI Models":
            return
        explanation = {
            "READY": (
                "AI 환경 준비 완료 · 사전 점검만 수행했습니다. "
                "Fixture 분석 버튼으로 실제 모델을 실행합니다."
            ),
            "SETUP_REQUIRED": (
                "AI 실행 환경 설정이 필요합니다. 관리자에게 프로젝트 전용 환경 구성을 요청하세요."
            ),
            "ARTIFACT_MISSING": "검증된 모델 Artifact가 없거나 무결성 확인에 실패했습니다.",
            "BACKEND_UNAVAILABLE": (
                "AI 실행 환경을 찾지 못했거나 Native Backend를 사용할 수 없습니다."
            ),
            "VALIDATION_FAILED": (
                "환경 무결성 검증에 실패했습니다. 임의 경로는 자동으로 신뢰하지 않습니다."
            ),
            "UNKNOWN": "AI 환경 상태를 확인할 수 없습니다. 환경 점검을 다시 실행하세요.",
        }
        self.ai_explanation.set(
            explanation.get(self.ai_environment["status"], explanation["UNKNOWN"])
        )
        self.current_records = value["packages"] + [value["authentication"]]
        rows = [
            (
                p["binding_id"],
                p["package_import"],
                p["artifact"],
                p["backend_dependencies"],
                (
                    "VERIFIED (prior Fixture)"
                    if self.last_probe
                    and p["binding_id"] in self.last_probe["native_models"]
                    and (value.get("last_validation") or {}).get("context_digest")
                    == self.last_probe["context_digest"]
                    else p["demo_inference"]
                ),
                p["operational_input"],
            )
            for p in value["packages"]
        ]
        rows.append(
            (
                "authentication",
                "INTERNAL",
                "SOURCE_CHAIN",
                "NOT_QUERIED",
                "NOT_INFERABLE",
                "READ_ONLY",
            )
        )
        self._rows(rows)
        self._model_cards(value, rows)
        self.show_detail(value)

    def _invalidate_model_cards(self):
        if self.last_model_view:
            value, rows = self.last_model_view
            rows = [
                (r[0], "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", r[5]) if i < 3 else r
                for i, r in enumerate(rows)
            ]
            self._model_cards(value, rows)

    def _model_cards(self, value, rows):
        self.last_model_view = (value, rows)
        for child in self.model_grid.winfo_children():
            child.destroy()
        self.model_cards = []
        cols = 4 if self.root.winfo_width() >= 1280 else 2
        titles = ("Network Quality", "Network Edge", "DNS Security", "Authentication")
        for i, row in enumerate(rows):
            frame = tk.Frame(
                self.model_grid,
                bg=PANEL,
                padx=16,
                pady=14,
                highlightthickness=1,
                highlightbackground=EDGE,
            )
            frame.grid(row=i // cols, column=i % cols, sticky="nsew", padx=(0, 8), pady=(0, 8))
            self.model_grid.columnconfigure(i % cols, weight=1, uniform="models")
            width = max(220, (self.root.winfo_width() - 300) // cols - 48)
            Label(frame, text=titles[i], size=18, bold=True, bg=PANEL, max_width=width).pack(
                anchor="w", pady=(0, 12)
            )
            fields = [
                ("Native / demo", row[4]),
                ("Artifact integrity", row[2]),
                ("Backend", row[3]),
                ("Operational input", row[5]),
            ]
            for key, item in fields:
                Label(frame, text=key, size=11, fg=MUTED, bg=PANEL, max_width=width).pack(
                    anchor="w"
                )
                Label(frame, text=item, size=13, fg=color(item), bg=PANEL, max_width=width).pack(
                    anchor="w", pady=(2, 7)
                )
            reason = (
                " • ".join(value["packages"][i]["blocking_reasons"])
                if i < 3
                else "Native authentication source chain; external inference not queried"
            )
            Label(frame, text=reason, size=11, fg=MUTED, bg=PANEL, max_width=width).pack(
                anchor="w", pady=(6, 0)
            )
            self.model_cards.append(fields)

    def operation(self, command):
        requested_page = self.page

        def render(value):
            if self.page != requested_page:
                return
            if not value.get("ok"):
                self.show_detail(value)
                return
            result = value.get("result")
            if isinstance(result, list):
                records = result
            elif isinstance(result, dict):
                records = result.get("records", result.get("items", result.get("candidates", [])))
            else:
                records = []
            self.current_records = [r for r in records if isinstance(r, dict)]
            if self.page == "Response & Approval":
                from collections import Counter

                self.approval_chart.update_counts(
                    dict(Counter(r.get("status", "UNKNOWN") for r in self.current_records))
                )
            rows = []
            for r in self.current_records:
                inner = r.get("record", r)
                request = inner.get("request", {})
                content = inner.get("content", {})
                identity = inner.get(
                    "candidate_id",
                    request.get(
                        "candidate_id",
                        r.get(
                            "feedback_id",
                            r.get("finding_reference", r.get("evaluation_id", "AUDIT")),
                        ),
                    ),
                )
                rows.append(
                    (
                        str(identity)[:18] + "…",
                        str(
                            inner.get(
                                "version",
                                inner.get("category", content.get("candidate_type", command)),
                            )
                        ),
                        r.get(
                            "status",
                            inner.get(
                                "processing_status",
                                inner.get(
                                    "review_status",
                                    inner.get("verdict", content.get("status", "UNKNOWN")),
                                ),
                            ),
                        ),
                        r.get(
                            "approval_status",
                            inner.get(
                                "source_origin",
                                inner.get("experience", {}).get(
                                    "source_origin", inner.get("ground_truth_assurance", "UNKNOWN")
                                ),
                            ),
                        ),
                    )
                )
            self._rows(rows)
            if self.page == "Self-Improvement":
                self.improvement_count.set(
                    str(len(self.current_records))
                    + " stored "
                    + command.replace("-", " ")
                    + " records • no operational changes"
                )
                if command == "feedback-list":
                    from collections import Counter

                    self.feedback_chart.update_counts(
                        dict(
                            Counter(
                                r.get("request", {}).get("label", "UNKNOWN")
                                for r in self.current_records
                            )
                        )
                    )
                if command == "evaluations" and self.current_records:
                    self.improvement_chart.update_result(self.current_records[0])
            self.show_detail(value)

        if command in ("evaluations", "reviews"):
            self.call(
                "improvement_records",
                command,
                callback=lambda values: render({"ok": True, "result": values}),
            )
        elif command in ("simulation-records", "restricted-list"):
            restricted = command == "restricted-list"
            self.response_kind.set("restricted" if restricted else "simulation")
            self.call(
                "approvals",
                restricted=restricted,
                callback=lambda values: render({"ok": True, "result": values}),
            )
        else:
            self.call("operator", command, callback=render)

    def _change_response_mode(self):
        self.selected_result = None
        self._update_action_buttons()
        self.operation(
            "restricted-list" if self.response_kind.get() == "restricted" else "simulation-records"
        )

    def _update_action_buttons(self):
        value = self.selected_result or {}
        status = value.get("status", "UNKNOWN")
        record = value.get("record", {})
        restricted = self.response_kind.get() == "restricted"
        conditions = {
            "request": restricted,
            "approve": status == "PENDING_APPROVAL",
            "reject": status == "PENDING_APPROVAL",
            "execute": status == "APPROVED",
            "rollback-request": restricted
            and status == "TEST_RESOURCE_CHANGED"
            and bool(record.get("receipt")),
        }
        for key, button in self.response_buttons.items():
            button.configure(state="normal" if conditions[key] and not self.busy else "disabled")

    def response_action(self, operation):
        selected = self.selected_result
        restricted = self.response_kind.get() == "restricted"
        if operation == "request":
            if not restricted:
                return
            identity = simpledialog.askstring(
                "Finding reference", "Completed Finding ID (64 hex):", parent=self.root
            )
            if identity:
                self.call(
                    "operator",
                    "restricted-request",
                    finding_id=identity,
                    callback=self._action_result,
                )
            return
        if not selected:
            messagebox.showinfo(
                "Select a record",
                "Refresh and select the exact current approval record.",
                parent=self.root,
            )
            return
        record = selected.get("record", selected)
        request = record.get("request", {})
        identity = record.get("candidate_id", request.get("candidate_id"))
        digest = selected.get("record_digest")
        if not identity or not digest:
            return
        if not messagebox.askyesno(
            "Explicit operator action",
            operation + " the exact selected action?\n"
            "Only simulation or registered test marker; no OS security response.",
            parent=self.root,
        ):
            return
        fields = {"candidate_id": identity, "expected_digest": digest}
        if operation == "rollback-request":
            if not restricted:
                return
            fields["finding_id"] = json.loads(record.get("action", {}).get("tool_input", "{}")).get(
                "finding_id"
            )
            if not fields["finding_id"]:
                identity_input = simpledialog.askstring(
                    "Finding reference", "Original Finding ID:", parent=self.root
                )
                if not identity_input:
                    return
                fields["finding_id"] = identity_input
        command = ("restricted-" if restricted else "") + operation

        self.call("operator", command, callback=self._action_result, **fields)

    def _action_result(self, value):
        if self.page != "Response & Approval":
            return
        if value.get("ok"):
            self.selected_result = value["result"]
            self.current_records = [value["result"]]
            record = value["result"].get("record", {})
            identity = record.get(
                "candidate_id", record.get("request", {}).get("candidate_id", "UNKNOWN")
            )
            self._rows(
                [
                    (
                        str(identity)[:18] + "…",
                        self.response_kind.get(),
                        value["result"].get("status", "UNKNOWN"),
                        "OS_PEER_UID",
                    )
                ]
            )
            self.tree.selection_set("0")
        self.show_detail(value)
        if value.get("ok"):
            self.approval_chart.update_counts(None)

            def counts(records):
                if self.page == "Response & Approval":
                    from collections import Counter

                    self.approval_chart.update_counts(
                        dict(Counter(r.get("status", "UNKNOWN") for r in records))
                    )

            self.call(
                "approvals", restricted=self.response_kind.get() == "restricted", callback=counts
            )

    def prepare(self):
        restricted = self.response_kind.get() == "restricted"
        if messagebox.askyesno(
            "Explicit test preparation",
            "Runtime must be stopped.\n"
            + (
                "Create a registered private test marker?"
                if restricted
                else "Enable pure response simulation?"
            )
            + "\nNo automatic approval.",
            parent=self.root,
        ):
            self.call("prepare", restricted=restricted)

    def connect(self):
        path = filedialog.askdirectory(title="Existing private Linux Runtime")
        if path:
            self.call("attach", Path(path))

    def initialize(self):
        parent = filedialog.askdirectory(title="Parent for a fresh private Runtime")
        if not parent:
            return
        name = simpledialog.askstring(
            "New Runtime", "New directory name (no existing data):", parent=self.root
        )
        if not name or Path(name).name != name or name in (".", ".."):
            return
        repeated = simpledialog.askinteger(
            "Operator configuration",
            "Repeated failure threshold (2–10000), unvalidated:",
            minvalue=2,
            maxvalue=10000,
            parent=self.root,
        )
        accounts = simpledialog.askinteger(
            "Operator configuration",
            "Multiple account threshold (2–10000), unvalidated:",
            minvalue=2,
            maxvalue=10000,
            parent=self.root,
        )
        if repeated is None or accounts is None:
            return
        mode = simpledialog.askstring(
            "Assessment mode",
            "READ_ONLY (default) or SCRIPTED (test analysis):",
            initialvalue="READ_ONLY",
            parent=self.root,
        )
        if mode not in ("READ_ONLY", "SCRIPTED"):
            return
        self.call("initialize_runtime", Path(parent) / name, repeated, accounts, mode)

    def model_probe(self):
        if messagebox.askyesno(
            "Explicit synthetic Native demo",
            "Run official models on synthetic precomputed features?\n"
            "SCRIPTED assessment, NOT_INFERABLE operational input. No actual OS response.",
            parent=self.root,
        ):
            self.call("fixture_probe", callback=self._probe_result)

    def _probe_result(self, value):
        if value.get("status") == "VERIFIED":
            self.last_probe = value
            if self.page == "Security AI Models":
                self.render_models(value["inventory"])
                self.latency_chart.update_models(value["models"])
                self.ai_explanation.set(
                    "실제 Native Fixture 분석 완료 · SCRIPTED 조사 · "
                    "운영 입력 NOT_INFERABLE · WRITE_DENIED"
                )
        else:
            self.last_probe = None
            if self.page == "Security AI Models":
                self.ai_explanation.set(
                    "분석 차단 — 환경 점검 후 다시 시도하세요. "
                    + str(value.get("environment", {}).get("status", "UNKNOWN"))
                )
                self.latency_chart.update_models([])
                self._invalidate_model_cards()
        if self.page == "Security AI Models":
            self.show_detail(value)

    def run_scenario(self, all_scenarios=False):
        identity = self.selected_result.get("id") if self.selected_result else None
        if not all_scenarios and identity is None:
            return
        identities = (
            [s["id"] for s in self.worker.backend.scenario_catalog()]
            if all_scenarios
            else [identity]
        )

        def next_run(result=None):
            if result:
                self.result_by_scenario[result["scenario_id"]] = result
                if self.page == "Scenario Demo":
                    self._render_catalog()
                    self.show_detail(result)
            if identities:
                self.call("scenario", identities.pop(0), callback=next_run)

        next_run()

    def close(self):
        if self.closing:
            return
        if self.busy:
            self.notice.set("Shutdown pending · waiting for the current bounded backend action")
            self.root.after(150, self.close)
            return
        self.closing = True
        self.notice.set("Closing · Runtime keeps running; use Stop explicitly")
        future = self.worker.submit("close")

        def check():
            if not future.done():
                self.root.after(100, check)
                return
            try:
                result = future.result()
            except Exception:
                result = {"status": "UNKNOWN"}
            if result.get("status") == "UNKNOWN":
                self.closing = False
                self.notice.set("UNKNOWN shutdown · GUI stays open for operator review")
                self.root.after(50, self._drain)
                return
            for timer in self.root.tk.call("after", "info"):
                self.root.after_cancel(timer)
            self.worker.shutdown()
            self.root.destroy()

        self.root.after(100, check)

"""Tk presentation. Every backend task runs outside the Tk event loop."""

import asyncio
import json
import re
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from soc_agent.gui.backend import Backend, GUIConfig
from soc_agent.gui.charts import MetricHistory, Trend
from soc_agent.gui.queries import display_data

BG = "#0d131c"
PANEL = "#151e2b"
EDGE = "#293548"
TEXT = "#e0e8f2"
MUTED = "#8c9cb2"
ACCENT = "#5fd2b1"
SCREENS = (
    "Dashboard",
    "Investigations",
    "Security AI Models",
    "Response & Approval",
    "Self-Improvement",
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
        root.after(150, self.refresh)
        root.after(config.refresh_seconds * 1000, self._poll)

    def _style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=TEXT, font=("DejaVu Sans", 11))
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Muted.TLabel", foreground=MUTED)
        style.configure("Title.TLabel", font=("DejaVu Sans", 24, "bold"))
        style.configure("Header.TLabel", font=("DejaVu Sans", 15, "bold"))
        style.configure("TButton", background=EDGE, foreground=TEXT, padding=(14, 9), borderwidth=0)
        style.map(
            "TButton",
            background=[("active", "#35465b"), ("disabled", PANEL)],
            foreground=[("disabled", MUTED)],
        )
        style.configure("Accent.TButton", background="#245546", foreground="#b4f4da")
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

    def _build(self):
        shell = ttk.Frame(self.root)
        shell.pack(fill="both", expand=True)
        side = tk.Frame(shell, bg=PANEL, width=240)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Label(
            side, text="◎  SENTINEL / SOC", fg=ACCENT, bg=PANEL, font=("DejaVu Sans", 16, "bold")
        ).pack(pady=(28, 4))
        tk.Label(
            side, text="LINUX AGENT  /  v1", fg=MUTED, bg=PANEL, font=("DejaVu Sans", 10)
        ).pack(pady=(0, 34))
        for name in SCREENS:
            ttk.Button(side, text=name, command=lambda n=name: self.navigate(n)).pack(
                fill="x", padx=16, pady=5
            )
        tk.Label(
            side,
            text="AUTONOMOUS INVESTIGATION\nHUMAN-GOVERNED ACTION",
            fg=MUTED,
            bg=PANEL,
            justify="left",
            font=("DejaVu Sans", 9),
        ).pack(side="bottom", padx=14, pady=24)
        body = ttk.Frame(shell)
        body.pack(side="left", fill="both", expand=True, padx=28, pady=22)
        header = ttk.Frame(body)
        header.pack(fill="x")
        self.title = ttk.Label(header, text=self.page, style="Title.TLabel")
        self.title.pack(side="left")
        ttk.Label(header, textvariable=self.status_var, style="Muted.TLabel").pack(side="right")
        ttk.Label(body, textvariable=self.notice, style="Muted.TLabel", wraplength=1200).pack(
            fill="x", pady=(12, 18)
        )
        self.toolbar = ttk.Frame(body)
        self.toolbar.pack(fill="x", pady=(0, 16))
        self.content = ttk.Frame(body)
        self.content.pack(fill="both", expand=True)
        self.navigate("Dashboard", refresh=False)

    def navigate(self, name, refresh=True):
        if name not in SCREENS:
            return
        self.page = name
        self.notice.set("READ-only views · explicit operator actions · source and mode per record")
        self.title.configure(text=name)
        self.current_records = []
        self.selected_result = None
        for container in (self.toolbar, self.content):
            for child in container.winfo_children():
                child.destroy()
        ttk.Button(self.toolbar, text="Refresh", command=self.refresh).pack(side="right")
        if name == "Dashboard":
            self._dashboard_layout()
        elif name == "Scenario Demo":
            self._scenario_layout()
        elif name == "Response & Approval":
            self._response_layout()
        elif name == "Security AI Models":
            ttk.Button(self.toolbar, text="Run native Fixture demo", command=self.model_probe).pack(
                side="left"
            )
            self._table(("model", "import", "artifact", "backend", "demo", "operational"))
        elif name == "Investigations":
            ttk.Label(
                self.toolbar,
                text="OBSERVED references ≠ UNTRUSTED assessment",
                style="Muted.TLabel",
            ).pack(side="left")
            self._table(("finding", "rule", "status", "origin", "mode"))
        else:
            for label, cmd in [
                ("Outcomes", "feedback"),
                ("Human Feedback", "feedback-list"),
                ("Candidates", "candidates"),
                ("Offline evaluation", "evaluations"),
                ("Human review", "reviews"),
            ]:
                ttk.Button(self.toolbar, text=label, command=lambda c=cmd: self.operation(c)).pack(
                    side="left", padx=(0, 6)
                )
            self._table(("reference", "kind", "status", "origin"))
        if refresh:
            self.refresh()

    def _dashboard_layout(self):
        for label, cmd in [
            ("Connect", self.connect),
            ("Initialize", self.initialize),
            ("Start owned Runtime", lambda: self.call("start")),
            ("Stop owned Runtime", lambda: self.call("stop")),
        ]:
            ttk.Button(self.toolbar, text=label, command=cmd).pack(side="left", padx=(0, 6))
        self.cards = {}
        grid = ttk.Frame(self.content)
        grid.pack(fill="x")
        for i, (key, label) in enumerate(
            (
                ("runtime_state", "RUNTIME"),
                ("health", "HEALTH"),
                ("readiness", "READINESS"),
                ("queue_backlog", "QUEUE BACKLOG"),
                ("authentication_events", "AUTH RECORDS STORED"),
                ("findings_total", "ADVISORY FINDINGS"),
                ("journal_cursor_health", "JOURNAL CURSOR"),
                ("audit_store_health", "AUDIT"),
            )
        ):
            card = tk.Frame(
                grid, bg=PANEL, highlightbackground=EDGE, highlightthickness=1, padx=18, pady=18
            )
            card.grid(row=i // 4, column=i % 4, sticky="nsew", padx=5, pady=5)
            grid.columnconfigure(i % 4, weight=1)
            tk.Label(card, text=label, bg=PANEL, fg=MUTED, font=("DejaVu Sans", 9, "bold")).pack(
                anchor="w"
            )
            var = tk.StringVar(value="UNKNOWN")
            self.cards[key] = var
            tk.Label(
                card,
                textvariable=var,
                bg=PANEL,
                fg=TEXT,
                font=("DejaVu Sans", 15, "bold"),
                wraplength=220,
            ).pack(anchor="w", pady=(10, 0))
        ttk.Label(
            self.content,
            text="No synthetic counters · No automatic approval · OS response disabled",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=20)
        charts = ttk.Frame(self.content)
        charts.pack(fill="x", pady=(0, 14))
        self.trends = [
            Trend(charts, self.history, "queue", "QUEUE BACKLOG · retained work", "#5fd2b1"),
            Trend(charts, self.history, "completed", "COMPLETED INVESTIGATIONS · count", "#85b8f7"),
        ]
        for chart in self.trends:
            chart.pack(side="left", fill="both", expand=True, padx=5)
        self._detail(self.content, height=8)

    def _table(self, columns):
        pane = ttk.Panedwindow(self.content, orient="vertical")
        pane.pack(fill="both", expand=True)
        top = ttk.Frame(pane)
        pane.add(top, weight=3)
        self.tree = ttk.Treeview(top, columns=columns, show="headings", selectmode="browse")
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
        bottom = ttk.Frame(pane)
        pane.add(bottom, weight=2)
        self._detail(bottom)
        ttk.Button(bottom, text="Copy selected ID / digest", command=self.copy_reference).pack(
            anchor="e", pady=5
        )

    def _detail(self, parent, height=12):
        self.detail = tk.Text(
            parent,
            height=height,
            bg=PANEL,
            fg=TEXT,
            insertbackground=TEXT,
            wrap="word",
            font=("DejaVu Sans Mono", 10),
            relief="flat",
            padx=16,
            pady=14,
        )
        self.detail.pack(fill="both", expand=True)
        self.show_detail(
            {
                "status": "UNKNOWN",
                "note": "Select a record. Raw source logs and credentials are not shown.",
            }
        )

    def show_detail(self, data):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert(
            "end", json.dumps(display_data(data), indent=2, ensure_ascii=False, default=str)
        )
        self.detail.tag_configure("advisory", foreground="#e3bf83")
        self.detail.tag_configure("source", foreground="#7fc8ef")
        for text, tag in (("advisory_assessment", "advisory"), ("evidence_references", "source")):
            position = self.detail.search(text, "1.0", stopindex="end")
            if position:
                self.detail.tag_add(tag, position, position + "+" + str(len(text)) + "c")
        self.detail.configure(state="disabled")

    def _scenario_layout(self):
        ttk.Label(
            self.toolbar,
            text="FIXTURE / REPLAY · SCRIPTED · RESPONSE_SIMULATION",
            style="Muted.TLabel",
        ).pack(side="left")
        ttk.Button(self.toolbar, text="Run selected", command=self.run_scenario).pack(
            side="left", padx=6
        )
        ttk.Button(
            self.toolbar,
            text="Run all S01–S12",
            command=lambda: self.run_scenario(all_scenarios=True),
        ).pack(side="left")
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
            ttk.Button(self.toolbar, text=label, command=lambda c=cmd: self.operation(c)).pack(
                side="left", padx=(0, 5)
            )
        self.response_kind = tk.StringVar(value="simulation")
        ttk.Radiobutton(
            self.toolbar, text="Simulation", variable=self.response_kind, value="simulation"
        ).pack(side="left")
        ttk.Radiobutton(
            self.toolbar, text="Test marker", variable=self.response_kind, value="restricted"
        ).pack(side="left")
        bar = ttk.Frame(self.content)
        bar.pack(fill="x", pady=(0, 10))
        for label, op in [
            ("Approve", "approve"),
            ("Reject", "reject"),
            ("Execute", "execute"),
            ("Request action", "request"),
            ("Request rollback", "rollback-request"),
        ]:
            ttk.Button(bar, text=label, command=lambda o=op: self.response_action(o)).pack(
                side="left", padx=(0, 5)
            )
        ttk.Button(bar, text="Prepare test mode", command=self.prepare).pack(side="right")
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
        self.show_detail(data)

    def copy_reference(self):
        if not self.selected_result:
            return
        data = self.selected_result
        value = (
            data.get("finding_id")
            or data.get("candidate_id")
            or data.get("feedback_id")
            or data.get("id")
        )
        if not value and isinstance(data.get("record"), dict):
            value = data["record"].get("candidate_id") or data["record"].get("request", {}).get(
                "candidate_id"
            )
        if value:
            self.root.clipboard_clear()
            self.root.clipboard_append(str(value))
            self.notice.set("Selected identifier copied.")

    def call(self, operation, *args, callback=None, **kwargs):
        if self.busy or self.closing:
            return
        self.busy = True
        self.notice.set("WORKING · " + operation + " · UI remains responsive")
        future = self.worker.submit(operation, *args, **kwargs)
        self.pending = (future, callback)

    def _drain(self):
        if self.pending and self.pending[0].done():
            future, callback = self.pending
            self.pending = None
            self.busy = False
            try:
                result = future.result()
            except Exception as error:
                code = str(error)
                safe = code if re.fullmatch(r"[A-Z0-9_]{1,100}", code) else type(error).__name__
                self.notice.set("BLOCKED · " + safe + " · No fallback or automatic retry")
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
        elif self.page == "Security AI Models":
            self.call("models", callback=self.render_models)
        elif self.page == "Response & Approval":
            self.operation("simulation-records")
        elif self.page == "Self-Improvement":
            self.operation("feedback")
        else:
            self._render_catalog()

    def _poll(self):
        if not self.busy and not self.closing:
            self.call("dashboard", callback=self.render_dashboard)
        if not self.closing:
            self.root.after(self.config.refresh_seconds * 1000, self._poll)

    def render_dashboard(self, value):
        scope = value.get("metric_scope")
        if scope != self.history_scope:
            self.history.samples.clear()
            self.history_scope = scope
        self.history.observe(value)
        self.status_var.set(
            str(value.get("runtime_state", "UNKNOWN"))
            + " · "
            + str(value.get("readiness", "NOT_READY"))
        )
        if self.page == "Dashboard":
            for chart in self.trends:
                chart.redraw()
            for key, var in self.cards.items():
                var.set(str(value.get(key, "UNKNOWN")) if value.get(key) is not None else "UNKNOWN")
            self.show_detail(value)

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
        if self.page != "Security AI Models":
            return
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
        self.show_detail(value)

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
        self.notice.set("Closing · graceful shutdown of owned Runtime only")
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

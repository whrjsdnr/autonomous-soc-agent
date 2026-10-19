"""Operator presentation using the existing Tk/Pango components and measured charts.

No runtime construction, background task, model load or polling belongs here.
"""

import tkinter as tk
from tkinter import ttk

from soc_agent.gui.charts import Trend
from soc_agent.gui.components import (
    ELEVATED,
    PRIMARY,
    SECONDARY,
    SURFACE,
    TEXT,
    Button,
    Label,
    color,
)


def friendly(value):
    if value is None:
        return "Unknown"
    return {
        "FIXTURE_NO_CAPTURE": "Fixture input",
        "LIVE_COLLECTION": "Live collection",
        "LIVE_HEADERS_ONLY": "Live metadata",
    }.get(str(value), str(value).replace("_", " ").title())


class Card(tk.Frame):
    def __init__(self, parent, title, *, width=250):
        super().__init__(
            parent, bg=SURFACE, padx=16, pady=12, highlightthickness=1, highlightbackground=ELEVATED
        )
        Label(self, text=title.upper(), size=11, fg=SECONDARY, bg=SURFACE, max_width=width).pack(
            anchor="w"
        )
        self.value = Label(self, text="Unknown", size=21, bold=True, bg=SURFACE, max_width=width)
        self.value.pack(anchor="w", pady=(8, 3))
        self.note = Label(
            self, text="Not yet observed", size=11, fg=SECONDARY, bg=SURFACE, max_width=width
        )
        self.note.pack(anchor="w")
        self.previous = None

    def update_value(self, value, note="", state=None):
        current = (value, note, state)
        if current != self.previous:
            tone = color(state or ("UNKNOWN" if value is None else str(value)))
            if tone == "#64748B":
                tone = "#94A3B8"
            self.value.configure(text=friendly(value), fg=tone)
            self.note.configure(text=note)
            self.previous = current


def heading(parent, title, subtitle):
    Label(parent, text=title, size=25, bold=True).pack(anchor="w")
    Label(parent, text=subtitle, size=12, fg=SECONDARY, max_width=1100).pack(
        anchor="w", pady=(4, 14)
    )


def cards(parent, titles):
    grid = ttk.Frame(parent)
    grid.pack(fill="x", pady=(0, 12))
    result = {}
    for i, title in enumerate(titles):
        card = Card(grid, title, width=220)
        card.grid(
            row=i // 4, column=i % 4, sticky="nsew", padx=(0 if i % 4 == 0 else 8, 0), pady=(0, 8)
        )
        result[title] = card
    for column in range(4):
        grid.columnconfigure(column, weight=1, uniform="cards")
    columns = [None]

    def fit(event):
        count = 4 if event.width >= 1080 else 2
        if columns[0] == count:
            return
        columns[0] = count
        for c in range(4):
            grid.columnconfigure(
                c, weight=1 if c < count else 0, uniform="cards" if c < count else ""
            )
        for i, card in enumerate(result.values()):
            card.grid(
                row=i // count, column=i % count, padx=(0 if i % count == 0 else 8, 0), pady=(0, 8)
            )

    grid.bind("<Configure>", fit)
    return result


def dashboard(app):
    heading(
        app.content,
        "Security overview",
        "Network + DNS collection · Research advisory · Current session only",
    )
    app.status_cards = cards(
        app.content,
        (
            "Network",
            "DNS diagnostics",
            "Capture integrity",
            "Queue backlog",
            "Quality RF",
            "Edge LR",
            "Memory / CPU",
            "Authentication",
        ),
    )
    charts = ttk.Frame(app.content)
    charts.pack(fill="x", pady=(0, 14))
    app.traffic_chart = Trend(
        charts, app.history, "network_rate", "PACKET RATE", PRIMARY, units="packets / second"
    )
    app.inference_chart = Trend(
        charts,
        app.history,
        "inference_rate",
        "RESEARCH INFERENCE",
        "#A78BFA",
        units="inferences / minute",
    )
    for i, chart in enumerate((app.traffic_chart, app.inference_chart)):
        chart.configure(height=190)
        chart.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 12, 0))
        charts.columnconfigure(i, weight=1, uniform="charts")
    Label(app.content, text="RECENT ADVISORIES", size=12, bold=True, fg=PRIMARY).pack(
        anchor="w", pady=(0, 8)
    )
    app.summary = tk.Frame(
        app.content,
        bg=SURFACE,
        padx=16,
        pady=12,
        highlightthickness=1,
        highlightbackground=ELEVATED,
    )
    app.summary.pack(fill="x")
    app.recent_marker = None
    Button(
        app.content, text="View security events →", command=lambda: app.navigate("Security Events")
    ).pack(anchor="e", pady=8)


def render_dashboard(app, value, rows):
    net, collectors = value.get("network", {}), value.get("collectors", {})
    models = value.get("research", {}).get("model_metrics", {})
    origin = value.get("input_origin", "NO_DATA")
    app.status_cards["Network"].update_value(collectors.get("network", "UNKNOWN"), origin)
    app.status_cards["DNS diagnostics"].update_value(
        collectors.get("dns", "UNKNOWN"), "DNS9 model · BLOCKED"
    )
    app.status_cards["Capture integrity"].update_value(
        net.get("capture_integrity"), "Counter / timestamp / drop validation"
    )
    app.status_cards["Queue backlog"].update_value(
        net.get("queue_backlog"), "Bounded ingestion + inference queues"
    )
    for name, profile in (("Quality RF", "quality"), ("Edge LR", "edge")):
        model = models.get(profile, {})
        app.status_cards[name].update_value(
            model.get("state", "NOT_LOADED"),
            f"{model.get('successful', 0)} receipts · RESEARCH_ONLY",
        )
    resources = value.get("gui_resources", {})
    rss, cpu = resources.get("rss_bytes"), resources.get("cpu_seconds")
    memory = f"{rss / 1024**2:.1f} MiB" if isinstance(rss, (float, int)) else "UNKNOWN"
    app.status_cards["Memory / CPU"].update_value(
        memory,
        f"GUI/controller CPU {cpu:.2f}s" if isinstance(cpu, (float, int)) else "CPU · UNKNOWN",
    )
    auth = value.get("authentication", {})
    app.status_cards["Authentication"].update_value(
        auth.get("runtime_state", "NOT_ATTACHED"), "Retained evidence is not live collection"
    )
    for chart in (app.traffic_chart, app.inference_chart):
        chart.source = origin
        chart.history = app.history
        chart.redraw()
    recent = [row for row, _ in rows[-4:]]
    marker = str(recent)
    if marker != app.recent_marker:
        for child in app.summary.winfo_children():
            child.destroy()
        app.recent_marker = marker
        if not recent:
            Label(app.summary, text="No verified advisory events", size=14, bg=SURFACE).pack(
                anchor="w"
            )
            Label(
                app.summary,
                text="Prepare monitoring or recover retained evidence from System.",
                size=11,
                fg=SECONDARY,
                bg=SURFACE,
            ).pack(anchor="w", pady=(5, 2))
        for at, model, prediction, score, advisory, source, investigation in recent:
            measured = f"{score:.3f}" if isinstance(score, (int, float)) else "UNKNOWN"
            title = f"{model.upper()}   {prediction}   /   uncalibrated score {measured}"
            Label(app.summary, text=title, size=13, bg=SURFACE, max_width=1000).pack(
                anchor="w", pady=(3, 2)
            )
            Label(
                app.summary,
                text=f"{at}  ·  {source}  ·  {advisory}  ·  {investigation}",
                size=10,
                fg=SECONDARY,
                bg=SURFACE,
                max_width=1000,
            ).pack(anchor="w", pady=(0, 5))


def records(app):
    investigation = app.page == "Investigation"
    heading(
        app.content,
        "Investigation workspace" if investigation else "Security events",
        "READ-only investigation · Evidence and model provenance remain distinct from assessment"
        if investigation
        else "Uncalibrated research scores · Filter by model, source, prediction or status",
    )
    bar = ttk.Frame(app.content)
    bar.pack(fill="x", pady=(0, 12))
    if investigation:
        for fmt in ("json", "markdown"):
            Button(bar, text="Export " + fmt.upper(), command=lambda f=fmt: app.export(f)).pack(
                side="left", padx=(0, 8)
            )
    else:
        ttk.Entry(bar, textvariable=app.search, width=42).pack(side="left", padx=(0, 8))
        Button(bar, text="Apply filter", command=app._render_current).pack(side="left")
    app.record_count = Label(bar, text="No events", fg=SECONDARY, size=12)
    app.record_count.pack(side="right")
    split = ttk.Frame(app.content)
    split.pack(fill="both", expand=True)
    left, right = ttk.Frame(split), ttk.Frame(split)
    left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
    right.grid(row=0, column=1, sticky="nsew")
    split.columnconfigure(0, weight=3)
    split.columnconfigure(1, weight=2)
    split.rowconfigure(0, weight=1)
    cols = ("time", "model", "prediction", "score", "advisory", "origin", "investigation")
    app.tree = ttk.Treeview(
        left,
        columns=cols,
        displaycolumns=("model", "prediction", "score", "origin"),
        show="headings",
        height=16,
    )
    for col in cols:
        app.tree.heading(col, text=col.title())
        app.tree.column(col, width=130, minwidth=65, stretch=True)
    app.tree.pack(side="top", fill="both", expand=True)
    ys = ttk.Scrollbar(left, command=app.tree.yview)
    app.tree.configure(yscrollcommand=ys.set)
    ys.pack(side="right", fill="y")
    app.tree.bind("<<TreeviewSelect>>", app.select)
    app.detail_title = Label(right, text="Select an event", size=18, bold=True, max_width=400)
    app.detail_title.pack(anchor="w", pady=(0, 8))
    Label(
        right, text="MODEL RESULT / EVIDENCE / ASSESSMENT", size=10, fg=PRIMARY, max_width=400
    ).pack(anchor="w", pady=(0, 10))
    app.detail = tk.Text(
        right,
        height=24,
        width=34,
        bg=SURFACE,
        fg=TEXT,
        relief="flat",
        wrap="word",
        padx=14,
        pady=14,
        highlightthickness=1,
        highlightbackground=ELEVATED,
    )
    app.detail.pack(fill="both", expand=True)
    Button(right, text="Technical detail", command=app.raw_detail).pack(anchor="e", pady=8)


def system(app):
    heading(
        app.content,
        "System & monitoring",
        "Explicit operator control · Terminal-only authentication · Bounded research inference",
    )
    app.system_cards = cards(
        app.content, ("Monitoring", "Helper approval", "Audit integrity", "Recovery")
    )
    Label(app.content, text="MONITORING CONTROLS", size=12, fg=PRIMARY, bold=True).pack(
        anchor="w", pady=(0, 8)
    )
    bar = ttk.Frame(app.content)
    bar.pack(fill="x", pady=(0, 10))
    ttk.Combobox(
        bar,
        textvariable=app.policy,
        values=("legacy", "conservative-v2", "balanced-v2", "performance-v2"),
        state="readonly",
        width=20,
    ).pack(side="left", padx=(0, 12))
    app.start_button = Button(
        bar, text="Prepare monitoring", command=app.start, style="Accent.TButton"
    )
    app.start_button.pack(side="left", padx=(0, 8))
    Button(
        bar, text="Stop & drain", command=lambda: app.call("total_stop", callback=app.render)
    ).pack(side="left", padx=(0, 8))
    Button(
        bar, text="Recover retained", command=lambda: app.call("total_restore", callback=app.render)
    ).pack(side="left")
    app.copy_button = Button(bar, text="Copy helper command", command=app.copy_command)
    app.copy_button.pack(side="left", padx=8)
    Label(
        app.content,
        text="No root GUI or password entry. "
        "The reviewed CLI hands authentication to your terminal.",
        size=12,
        fg=SECONDARY,
        max_width=1000,
    ).pack(anchor="w", pady=(0, 18))
    Label(app.content, text="EVIDENCE & MAINTENANCE", size=12, fg=PRIMARY, bold=True).pack(
        anchor="w", pady=(0, 8)
    )
    bar2 = ttk.Frame(app.content)
    bar2.pack(fill="x", pady=(0, 12))
    Button(bar2, text="Archive inactive sessions", command=app.archive).pack(
        side="left", padx=(0, 8)
    )
    Button(
        bar2,
        text="Verify archive manifests",
        command=lambda: app.call("archive_status", callback=app._system_result),
    ).pack(side="left", padx=(0, 8))
    Button(bar2, text="Developer tools", command=app.developer_tools).pack(side="left")
    app.system = tk.Text(
        app.content,
        height=10,
        bg=SURFACE,
        fg=TEXT,
        relief="flat",
        wrap="word",
        padx=18,
        pady=16,
        highlightthickness=1,
        highlightbackground=ELEVATED,
    )
    app.system.pack(fill="both", expand=True)
    Button(
        app.content,
        text="Technical status / SHA",
        command=lambda: app._system_result(app.system_details),
    ).pack(anchor="e", pady=8)


def render_system(app, value):
    net = value.get("network", {})
    app.system_cards["Monitoring"].update_value(
        value.get("state", "UNKNOWN"), value.get("input_origin", "NO_DATA")
    )
    app.system_cards["Helper approval"].update_value(
        net.get("policy_approval", "NOT_PREPARED"), "READY listener required before copy / auth"
    )
    app.system_cards["Audit integrity"].update_value(
        value.get("runtime_audit_integrity", "UNKNOWN"), "Hash chain validation retained"
    )
    app.system_cards["Recovery"].update_value(
        net.get("recovery_state", "NO_SESSION"), "No automatic capture restart"
    )
    app.copy_button.configure(state="normal" if app.command else "disabled")
    app.start_button.configure(
        state="disabled" if value.get("prepare_active") or value.get("listener_ready") else "normal"
    )
    details = {
        "helper": "READY" if app.command else "NOT_PREPARED",
        "last_error": value.get("last_error"),
        "selected_policy": net.get("selected_rate_policy", app.policy.get()),
        "helper_sha256": net.get("helper_sha256", "NOT_PREPARED"),
        "quality_edge_health": value.get("research", {}).get("model_metrics", "NOT_LOADED"),
        "queue_backlog": net.get("queue_backlog", "UNKNOWN"),
        "capture_drops": net.get("capture_drops", "UNKNOWN"),
        "capture_gaps": net.get("gap_count", "UNKNOWN"),
        "operational_gate": value.get("operational_gate", "OPERATIONAL_INFERENCE_BLOCKED"),
        "dns9": "BLOCKED_PRODUCER_PARITY_UNVERIFIED",
        "write_policy": "WRITE_DENIED",
    }
    app.system_details = details
    models = value.get("research", {}).get("model_metrics", {})
    lines = [
        "SESSION & MODEL HEALTH",
        "Helper   " + details["helper"],
        "Policy   " + str(details["selected_policy"]),
        "",
    ]
    for name in ("quality", "edge"):
        model = models.get(name, {})
        lines.append(
            name.upper()
            + "   "
            + model.get("state", "NOT_LOADED")
            + "   /   "
            + str(model.get("successful", 0))
            + " verified receipts"
        )
    lines += [
        "",
        "Queue   " + str(details["queue_backlog"]),
        "Drops   "
        + str(details["capture_drops"])
        + "   /   Gaps   "
        + str(details["capture_gaps"]),
        "Last error   " + str(details["last_error"] or "None reported"),
        "",
        "DNS9 parity remains BLOCKED. Research scores are uncalibrated.",
        "Operational inference remains BLOCKED. All investigations are READ-only.",
    ]
    app._text(app.system, "\n".join(lines))

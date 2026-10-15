"""Read-only cross-domain presentation; never merge sources into one incident."""

import tkinter as tk
from tkinter import ttk

from soc_agent.gui.charts import Distribution
from soc_agent.gui.components import Button, Label
from soc_agent.gui.typography import text


class MeasuredSeries(tk.Canvas):
    def __init__(self, parent, title):
        super().__init__(parent, bg="#17243A", height=150, highlightthickness=0)
        self.title, self.points = title, []
        self.bind("<Configure>", lambda _: self.redraw())

    def update_points(self, points):
        self.points = points
        self.redraw()

    def redraw(self):
        self.delete("all")
        self.text_images = []
        w = max(280, self.winfo_width())
        text(self, 14, 18, self.title, size=12, width=w - 28)
        if self.points is None:
            text(self, 14, 75, "UNKNOWN • measurement unavailable", size=12, width=w - 28)
            return
        if not self.points:
            text(self, 14, 75, "NO_DATA • no confirmed inference", size=12, width=w - 28)
            return
        previous = None
        for i, (label, value) in enumerate(self.points):
            x = 50 + (w - 105) * i / max(1, len(self.points) - 1)
            y = 108 - 55 * value
            self.create_oval(
                x - 4, y - 4, x + 4, y + 4, fill="#38BDF8", outline="", tags="measured-point"
            )
            text(self, x, y - 16, f"{value:.4f}", size=11, anchor="center", width=80)
            text(self, x, 133, label, size=10, anchor="center", width=115)
            if previous:
                self.create_line(*previous, x, y, fill="#38BDF8", width=2)
            previous = (x, y)


class UnifiedPanel:
    def __init__(self, parent, app):
        self.app = app
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill="x", pady=(0, 16))
        Label(
            self.frame,
            text="AI RESEARCH & AUTHENTICATION • separate source identities",
            size=19,
            bold=True,
        ).pack(anchor="w")
        self.summary = tk.StringVar(value="Checking • operating Network / DNS BLOCKED")
        Label(self.frame, textvariable=self.summary, size=12, max_width=1400, fg="#F59E0B").pack(
            fill="x", pady=8
        )
        grid = ttk.Frame(self.frame)
        grid.pack(fill="x")
        self.cards = {}
        for i, key in enumerate(("quality", "edge", "dns", "authentication")):
            box = tk.Frame(grid, bg="#17243A", padx=12, pady=10)
            box.grid(row=0, column=i, sticky="nsew", padx=(0, 8))
            grid.columnconfigure(i, weight=1, uniform="ai")
            title = {
                "quality": "NETWORK QUALITY",
                "edge": "NETWORK EDGE",
                "dns": "DNS SECURITY",
                "authentication": "AUTHENTICATION",
            }[key]
            Label(box, text=title, size=13, bold=True, bg="#17243A").pack(anchor="w")
            var = tk.StringVar(value="UNKNOWN")
            Label(box, textvariable=var, size=12, max_width=330, bg="#17243A").pack(
                fill="x", pady=(7, 0)
            )
            self.cards[key] = var
        actions = ttk.Frame(self.frame)
        actions.pack(fill="x", pady=10)
        Button(
            actions,
            text="Network / DNS Research Demo",
            command=lambda: app.navigate("Network Research"),
        ).pack(side="left", padx=(0, 8))
        Button(
            actions, text="Review Authentication", command=lambda: app.navigate("Investigations")
        ).pack(side="left")
        self.latest = tk.StringVar(value="NO_DATA • no advisory inference stored")
        Label(self.frame, textvariable=self.latest, size=12, max_width=1450).pack(
            fill="x", pady=(0, 8)
        )
        charts = ttk.Frame(self.frame)
        charts.pack(fill="x")
        self.dns = MeasuredSeries(charts, "DNS FIXTURE SCORE • uncalibrated • UTC / replay order")
        self.dns.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.progress = Distribution(charts, "RESEARCH INVESTIGATION PROGRESS")
        self.progress.pack(side="left", fill="x", expand=True)
        self.timeline = tk.StringVar(value="NO_DATA • model inference timeline")
        Label(self.frame, textvariable=self.timeline, size=11, max_width=1450).pack(
            fill="x", pady=7
        )
        self.events = Distribution(self.frame, "INPUT TYPE • retained/replayed units, not attacks")
        self.events.pack(fill="x")

    def render(self, value):
        r = value.get("research", {})
        records = r.get("records", [])
        metrics = r.get("model_metrics", {})
        dns_status = r.get("dns", {})
        models = {m["profile"]: m for m in r.get("models", [])}
        models["dns"] = dns_status
        self.summary.set(
            "Network research "
            + r.get("status", "UNKNOWN")
            + " · DNS fixture "
            + dns_status.get("status", "UNKNOWN")
            + " · operational Network/DNS BLOCKED / NOT_INFERABLE · WRITE_DENIED"
        )
        for p in ("quality", "edge", "dns"):
            m = models.get(p, {})
            s = metrics.get(p, {})
            self.cards[p].set(
                "RESEARCH_ONLY · "
                + s.get("state", "UNKNOWN")
                + "\nArtifact "
                + m.get("artifact", "UNKNOWN")
                + "\nSuccess "
                + str(s.get("successful", "UNKNOWN"))
                + " / Unknown "
                + str(s.get("unknown", "UNKNOWN"))
                + "\nLast "
                + str(s.get("last_inference") or "NO_DATA")
                + "\nError "
                + str(s.get("last_error") or m.get("reason") or "NONE_RECORDED")
            )
        self.cards["authentication"].set(
            "RUNTIME · "
            + str(value.get("runtime_state", "UNKNOWN"))
            + "\nCollector "
            + str(value.get("collector_state", "UNKNOWN"))
            + "\nSource "
            + ("RETAINED / " if value.get("runtime_state") != "RUNNING" else "CONNECTED / ")
            + ",".join(
                sorted({x.get("origin", "UNKNOWN") for x in (value.get("recent_activity") or [])})
            )
            + "\nRetained events "
            + str(
                value.get("authentication_events")
                if value.get("authentication_events") is not None
                else "UNKNOWN"
            )
            + "\nQueue "
            + str(
                value.get("queue_backlog") if value.get("queue_backlog") is not None else "UNKNOWN"
            )
        )
        receipts = [x["receipt"] for x in records if x.get("receipt")]
        dns = [p for p in receipts if p["profile"] == "dns"]
        self.dns.update_points(
            None
            if r.get("inference_counts") is None
            else [(p["inferred_at"][11:19], p["score"]) for p in dns]
        )
        self.progress.update_counts(
            None
            if r.get("inference_counts") is None
            else {
                "ASSESSED_READ_ONLY": sum(x.get("status") == "COMPLETE" for x in records),
                "UNKNOWN": r.get("errors", 0),
            }
        )
        self.latest.set(
            "\n".join(
                p["profile"].upper()
                + " · "
                + p["origin"]
                + " · "
                + p.get("validation_level", "OFFLINE_VERIFIED_FLOW")
                + f" · score {p['score']:.5f} (uncalibrated) · "
                + p["inferred_at"]
                for p in receipts[-3:]
            )
            or "NO_DATA • no advisory inference stored"
        )
        self.timeline.set(
            "INFERENCE TIMELINE (actual UTC, no assumed intervals): "
            + " → ".join(p["inferred_at"][11:19] + " " + p["profile"] for p in receipts[-6:])
            + "\nAudit "
            + r.get("audit_integrity", "UNKNOWN")
            + " · each advisory has its own incident/evidence; Authentication is not correlated"
        )
        if r.get("inference_counts") is None:
            self.events.update_counts(None)
        else:
            counts = {
                "Offline network flows": r.get("flow_count", 0),
                "DNS fixture inputs": len({p["input_digest"] for p in dns}),
            }
            auth = value.get("authentication_events")
            if auth is not None:
                counts["Retained authentication"] = auth
            self.events.heading = "INPUT UNITS • Authentication " + (
                "UNKNOWN / excluded" if auth is None else "retained records"
            )
            self.events.update_counts(counts)

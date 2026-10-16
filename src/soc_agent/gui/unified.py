"""Existing cross-domain DTOs presented as separate research and operational sources."""

import math
import tkinter as tk
from datetime import datetime
from tkinter import ttk

from soc_agent.gui.charts import Distribution, ModelLatency
from soc_agent.gui.components import (
    ELEVATED,
    PRIMARY,
    SECONDARY,
    SURFACE,
    TEXT,
    Button,
    Label,
    ModelCard,
    StatusRibbon,
)
from soc_agent.gui.insights import (
    dated_stamp,
    measured_receipts,
    model_view,
    number,
    operational,
    stamp,
    status_items,
)
from soc_agent.gui.typography import text

VIOLET = "#A78BFA"
TONES = {"quality": PRIMARY, "edge": VIOLET, "dns": "#FBBF24"}


class MeasuredSeries(tk.Canvas):
    def __init__(self, parent, title):
        super().__init__(
            parent, bg=SURFACE, height=210, highlightthickness=1, highlightbackground=ELEVATED
        )
        self.title, self.points = title, []
        self.bind("<Configure>", lambda _: self.redraw())

    def update_points(self, points):
        self.points = points
        if points is not None:
            self.points = (
                points[-120:]
                if all(
                    type(p[1]) in (int, float) and math.isfinite(p[1]) and 0 <= p[1] <= 1
                    for p in points
                )
                else None
            )
        self.redraw()

    def redraw(self):
        self.delete("all")
        self.text_images = []
        w, h = max(280, self.winfo_width()), max(150, self.winfo_height())
        text(self, 18, 23, self.title, size=13, bold=True, fill=TEXT, width=w - 36)
        if not self.points:
            text(
                self,
                18,
                89,
                "UNKNOWN" if self.points is None else "NO_DATA",
                size=22,
                bold=True,
                fill=SECONDARY,
                width=w - 36,
            )
            text(
                self,
                18,
                119,
                "Run an explicit DNS fixture demo to see measured scores.",
                size=12,
                width=w - 36,
            )
            return
        text(
            self,
            18,
            44,
            "Uncalibrated · UTC / replay order · not live traffic",
            size=10,
            width=w - 36,
        )
        top, bottom = 70, h - 43
        for fraction in (0, 0.5, 1):
            y = bottom - (bottom - top) * fraction
            self.create_line(48, y, w - 28, y, fill=ELEVATED)
            text(self, 12, y, f"{fraction:.1f}", size=10, width=32)
        previous = None
        for i, (label, value) in enumerate(self.points):
            x = 65 + (w - 105) * i / max(1, len(self.points) - 1)
            y = bottom - (bottom - top) * value
            if previous:
                self.create_line(*previous, x, y, fill=VIOLET, width=2)
            self.create_oval(
                x - 4, y - 4, x + 4, y + 4, fill=VIOLET, outline="", tags="measured-point"
            )
            text(self, x, y - 14, f"{value:.4f}", size=11, anchor="center", fill=TEXT, width=80)
            text(self, x, h - 21, str(label), size=10, anchor="center", width=95)
            previous = (x, y)


class InvocationTimeline(tk.Canvas):
    def __init__(self, parent):
        super().__init__(parent, bg=SURFACE, height=185, highlightthickness=0)
        self.receipts = None
        self.bind("<Configure>", lambda _: self.redraw())

    def update_records(self, receipts):
        self.receipts = receipts
        self.redraw()

    def redraw(self):
        self.delete("all")
        self.text_images = []
        w = max(300, self.winfo_width())
        text(
            self,
            16,
            22,
            "MODEL INVOCATIONS · actual UTC",
            size=13,
            bold=True,
            fill=TEXT,
            width=w - 32,
        )
        rows = self.receipts
        if not rows:
            text(
                self,
                16,
                90,
                "UNKNOWN" if rows is None else "NO_DATA · no native calls recorded",
                size=15,
                width=w - 32,
            )
            return
        dates = [
            datetime.fromisoformat(p["inferred_at"].replace("Z", "+00:00")).timestamp()
            for p in rows
        ]
        first, last = min(dates), max(dates)
        span = max(last - first, 0.001)
        for i, profile in enumerate(TONES):
            y = 58 + i * 34
            text(self, 16, y, profile.title(), size=11, width=78)
            self.create_line(100, y, w - 30, y, fill=ELEVATED)
        for p, when in zip(rows, dates, strict=True):
            x = 105 + (w - 145) * (when - first) / span
            y = 58 + list(TONES).index(p["profile"]) * 34
            self.create_oval(
                x - 4,
                y - 4,
                x + 4,
                y + 4,
                fill=TONES[p["profile"]],
                outline="",
                tags="invocation-point",
            )
        text(self, 100, 156, stamp(rows[0]["inferred_at"]), size=10, width=110)
        text(self, w - 18, 156, stamp(rows[-1]["inferred_at"]), size=10, anchor="e", width=110)


class UnifiedPanel:
    def __init__(self, parent, app):
        self.app = app
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill="x", pady=(0, 16))
        self.status = StatusRibbon(self.frame)
        self.status.pack(fill="x", pady=(0, 8))
        header = ttk.Frame(self.frame)
        header.pack(fill="x", pady=(0, 12))
        Label(header, text="Research observatory", size=20, bold=True).pack(side="left")
        Button(
            header,
            text="Open Research Demo",
            style="Accent.TButton",
            command=lambda: app.navigate("Network Research"),
        ).pack(side="right")
        self.summary = tk.StringVar(value="UNKNOWN · checking current environment")
        Label(self.frame, textvariable=self.summary, size=11, fg=SECONDARY).pack(
            fill="x", pady=(0, 10)
        )
        charts = ttk.Frame(self.frame)
        charts.pack(fill="x", pady=(0, 14))
        from soc_agent.gui.research_view import ReplayChart

        self.network = ReplayChart(charts)
        self.network.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self.dns = MeasuredSeries(charts, "DNS SCORE · FIXTURE / UNCALIBRATED")
        self.dns.pack(side="left", fill="both", expand=True)
        grid = ttk.Frame(self.frame)
        grid.pack(fill="x", pady=(0, 14))
        self.cards, self.card_widgets, self.card_counts = {}, {}, {}
        for i, key in enumerate(("quality", "edge", "dns", "authentication")):
            var = tk.StringVar(value="UNKNOWN")
            self.cards[key] = var
            self.card_counts[key] = tk.StringVar(value="UNKNOWN")
            box = ModelCard(
                grid,
                var,
                metric=self.card_counts[key],
                unit="retained events" if key == "authentication" else "stored calls",
                title={
                    "quality": "NETWORK QUALITY",
                    "edge": "NETWORK EDGE",
                    "dns": "DNS SECURITY",
                    "authentication": "AUTHENTICATION",
                }[key],
                accent=TONES.get(key, "#34D399"),
            )
            box.grid(row=0, column=i, sticky="nsew", padx=(0, 8 if i < 3 else 0))
            grid.columnconfigure(i, weight=1, uniform="models")
            self.card_widgets[key] = box
        grid2 = ttk.Frame(self.frame)
        grid2.pack(fill="x", pady=(0, 12))
        self.invocations = InvocationTimeline(grid2)
        self.invocations.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self.latency = ModelLatency(
            grid2,
            heading="LATEST MODEL TIME · measured ms",
            caption="Prediction vs DNS package timings differ; not a benchmark",
        )
        self.latency.pack(side="left", fill="both", expand=True)
        self.latest = tk.StringVar(value="NO_DATA · no advisory stored")
        Label(self.frame, textvariable=self.latest, size=12, max_width=1500).pack(
            fill="x", pady=(0, 12)
        )
        lower = ttk.Frame(self.frame)
        lower.pack(fill="x")
        self.progress = Distribution(lower, "RESEARCH INVESTIGATIONS")
        self.progress.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self.events = Distribution(lower, "INPUT UNITS · separate sources, not attacks")
        self.events.pack(side="left", fill="both", expand=True)
        self.timeline = tk.StringVar(value="Audit UNKNOWN")
        Label(self.frame, textvariable=self.timeline, size=11).pack(fill="x", pady=(10, 0))

    def render(self, value):
        r = value.get("research", {})
        self.status.update_items(status_items(value))
        self.summary.set(
            "Network "
            + r.get("status", "UNKNOWN")
            + " · DNS "
            + r.get("dns", {}).get("status", "UNKNOWN")
            + " · RESEARCH_ONLY · operational "
            + operational(value)
            + " · no automatic inference"
        )
        for p in TONES:
            m = model_view(value, p)
            self.card_counts[p].set(m["count"])
            self.cards[p].set(
                "RESEARCH_ONLY · "
                + m["worker"]
                + "\nReplay "
                + ("READY" if m["readiness"] == "READY_FOR_OFFLINE_REPLAY" else m["readiness"])
                + " · Artifact "
                + m["artifact"]
                + "\n"
                + m["origin"]
                + " · "
                + m["validation"]
                + "\nUnknown outcomes "
                + m["unknown"]
                + "\nLast "
                + m["last"]
                + "\nError "
                + str(m["error"])
                + "\nOperational "
                + m["operational"]
            )
        self.card_counts["authentication"].set(number(value.get("authentication_events")))
        self.cards["authentication"].set(
            "RUNTIME · "
            + value.get("runtime_state", "UNKNOWN")
            + "\nCollector "
            + value.get("collector_state", "UNKNOWN")
            + "\nSource "
            + ("RETAINED / " if value.get("runtime_state") != "RUNNING" else "CONNECTED / ")
            + ",".join(
                sorted({x.get("origin", "UNKNOWN") for x in (value.get("recent_activity") or [])})
            )
            + "\nRetained events "
            + number(value.get("authentication_events"))
            + "\nQueue "
            + number(value.get("queue_backlog"))
            + "\nAudit "
            + value.get("audit_store_health", "UNKNOWN")
        )
        receipts = measured_receipts(r)
        records = r.get("records", [])
        dns = [p for p in receipts or [] if p["profile"] == "dns"]
        self.network.update_records(records if receipts is not None else None)
        self.dns.update_points(
            None if receipts is None else [(stamp(p["inferred_at"])[:8], p["score"]) for p in dns]
        )
        self.invocations.update_records(receipts)
        latest = {p["profile"]: p for p in receipts or []}
        self.latency.update_models(
            None
            if receipts is None
            else [
                {
                    "binding_id": p.title(),
                    "tone": TONES[p],
                    "inference_latency_ms": latest[p].get("inference_latency_ms"),
                }
                for p in TONES
                if p in latest
            ]
        )
        self.progress.update_counts(
            None
            if receipts is None
            else {
                "ASSESSED_READ_ONLY": sum(x.get("status") == "COMPLETE" for x in records),
                "UNKNOWN": r.get("errors"),
            }
        )
        self.latest.set(
            "\n".join(
                p["profile"].upper()
                + " · "
                + p["origin"]
                + f" · score {p['score']:.5f} (uncalibrated) · "
                + dated_stamp(p["inferred_at"])
                for p in (receipts or [])[-3:]
            )
            or (
                "UNKNOWN · results unavailable"
                if receipts is None
                else "NO_DATA · run an explicit research demo"
            )
        )
        self.timeline.set(
            "Audit "
            + r.get("audit_integrity", "UNKNOWN")
            + " · retained receipts; no new call on refresh"
            + " · separate incident / evidence per source"
        )
        if receipts is None:
            self.events.update_counts(None)
        else:
            counts = {
                "Offline network flows": r.get("flow_count"),
                "DNS fixture inputs": len({p["input_digest"] for p in dns}),
            }
            auth = value.get("authentication_events")
            if auth is not None:
                counts["Retained authentication"] = auth
            self.events.heading = "INPUT UNITS · Authentication " + (
                "UNKNOWN / excluded" if auth is None else "retained"
            )
            self.events.update_counts(counts)

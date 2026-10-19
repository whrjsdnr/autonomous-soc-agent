"""Small Tk Canvas charts using bounded measured observations and existing typography."""

import tkinter as tk
from tkinter import ttk

from soc_agent.gui.components import ELEVATED, SECONDARY, SURFACE, TEXT
from soc_agent.gui.typography import text
from soc_agent.gui.visual_metrics import record_series

COLORS = ("#38BDF8", "#A78BFA", "#34D399", "#FBBF24")


class Chart(tk.Canvas):
    def __init__(self, parent, title: str, series: tuple, units: str, *, mode="metrics"):
        super().__init__(
            parent,
            bg=SURFACE,
            height=230,
            highlightthickness=1,
            highlightbackground=ELEVATED,
            takefocus=True,
        )
        self.title, self.series, self.units, self.mode = title, series, units, mode
        self.snapshot, self.history = {}, None
        self.marker = None
        self.points = {}
        self.bind("<Configure>", lambda _: self.redraw(force=True))
        self.bind("<Button-1>", lambda _: self.focus_set())

    def update_data(self, snapshot, history):
        self.snapshot, self.history = snapshot, history
        self.redraw()

    def redraw(self, force=False):
        if self.history is None:
            return
        snapshot, history = self.snapshot, self.history
        points = {}
        if self.mode == "distribution":
            levels = [
                item[1] for item in record_series(snapshot, "severity") if item[1] is not None
            ]
            points["severity"] = (
                [(i, float(levels.count(float(i)))) for i in range(5)] if levels else []
            )
        elif self.mode == "metrics":
            for key, _ in self.series:
                points[key] = [(row.at, row.values.get(key)) for row in history.samples]
        else:
            for key, _ in self.series:
                points[key] = [(i, item[1]) for i, item in enumerate(record_series(snapshot, key))]
        marker = (
            repr(points),
            repr([record_series(snapshot, key) for key, _ in self.series])
            if self.mode != "metrics"
            else None,
            snapshot.get("network", {}).get("integrity_state"),
            snapshot.get("session_id"),
            snapshot.get("input_origin"),
            snapshot.get("state"),
        )
        if not force and marker == self.marker:
            return
        self.marker, self.points = marker, points
        self.delete("all")
        self.text_images = []
        width, height = max(280, self.winfo_width()), max(210, self.winfo_height())
        text(self, 16, 22, self.title, size=12, bold=True, fill=TEXT, width=width - 32)
        legend = "   ".join(label for _, label in self.series)
        text(self, 16, 45, legend, size=10, fill=SECONDARY, width=width - 32)
        if self.mode == "records":
            event_points = record_series(snapshot, self.series[0][0])
            if event_points:
                text(
                    self,
                    45,
                    height - 54,
                    event_points[0][0][:19].replace("T", " "),
                    size=9,
                    width=150,
                )
                text(
                    self,
                    width - 20,
                    height - 54,
                    event_points[-1][0][:19].replace("T", " "),
                    size=9,
                    width=150,
                    anchor="e",
                )
        nums = [v for rows in points.values() for _, v in rows if v is not None]
        origin = str(snapshot.get("input_origin", "NO_DATA"))
        session = str(snapshot.get("session_id") or "NO_SESSION")[:12]
        state = str(snapshot.get("state", "UNKNOWN"))
        integrity = snapshot.get("network", {}).get("integrity_state", "UNKNOWN")
        state += " / " + str(integrity)
        text(
            self,
            16,
            height - 16,
            f"{origin} / {session} · {state}",
            size=9,
            fill=SECONDARY,
            width=width - 32,
        )
        text(self, 16, height - 37, self.units, size=9, fill=SECONDARY, width=width - 32)
        if not nums:
            text(
                self,
                width / 2,
                height / 2,
                "NOT OBSERVED · no measured values",
                size=12,
                anchor="center",
                width=width - 40,
            )
            return
        left, right, top, bottom = 45, width - 20, 70, height - 65
        peak = max(1, max(nums))
        xs = [x for rows in points.values() for x, _ in rows]
        start, end = min(xs), max(xs)
        for fraction in (0, 0.5, 1):
            y = bottom - fraction * (bottom - top)
            self.create_line(left, y, right, y, fill=ELEVATED)
            text(self, left - 5, y, f"{peak * fraction:.1f}", size=9, anchor="e", width=40)
        for index, (key, label) in enumerate(self.series):
            previous = None
            tone = COLORS[index % len(COLORS)]
            for x, value in points[key]:
                if value is None:
                    previous = None
                    continue
                px = (
                    left + (right - left) * (x - start) / (end - start)
                    if end > start
                    else (left + right) / 2
                )
                py = bottom - (bottom - top) * value / peak
                if self.mode == "distribution":
                    self.create_rectangle(px - 10, py, px + 10, bottom, fill=tone, outline=tone)
                if previous is not None and self.mode != "distribution":
                    self.create_line(*previous, px, py, fill=tone, width=2)
                self.create_oval(px - 2, py - 2, px + 2, py + 2, fill=tone, outline=tone)
                previous = (px, py)
            latest = points[key][-1][1] if points[key] else None
            if self.mode == "distribution" and points[key]:
                latest = sum(value for _, value in points[key] if value is not None)
            # Colored measured legend values, never impute a missing latest point.
            text(
                self,
                left + index * (right - left) / len(self.series),
                top - 8,
                f"{label}: {latest:.1f}" if latest is not None else f"{label}: N/A",
                size=9,
                fill=tone,
                width=max(65, int((right - left) / len(self.series))),
            )


def grid(parent, specs):
    frame = ttk.Frame(parent)
    frame.pack(fill="x", pady=(0, 14))
    charts = [
        Chart(frame, *spec[:3], mode=spec[3] if len(spec) > 3 else "metrics") for spec in specs
    ]
    count = [None]

    def fit(event):
        columns = 2 if event.width >= 820 else 1
        if count[0] == columns:
            return
        count[0] = columns
        for c in range(2):
            frame.columnconfigure(c, weight=1 if c < columns else 0, uniform="visual")
        for i, chart in enumerate(charts):
            chart.grid(
                row=i // columns,
                column=i % columns,
                sticky="nsew",
                padx=(0 if i % columns == 0 else 12, 0),
                pady=(0, 12),
            )

    frame.bind("<Configure>", fit)
    return charts


def render(charts, app, snapshot):
    for chart in charts:
        chart.update_data(snapshot, app.visual_history)

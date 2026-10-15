"""Bounded measured charts; no synthetic telemetry, imputation or execution authority."""

import math
import time
import tkinter as tk
from collections import deque
from dataclasses import dataclass

from soc_agent.gui.components import ELEVATED, PRIMARY, SECONDARY, SURFACE, TEXT, color
from soc_agent.gui.typography import text


@dataclass(frozen=True)
class Sample:
    measured_at: float
    queue: int | None
    completed: int | None


def count(value) -> int | None:
    return value if type(value) is int and value >= 0 else None


class MetricHistory:
    def __init__(self, capacity: int = 120):
        if not 2 <= capacity <= 1000:
            raise ValueError("CHART_CAPACITY")
        self.samples: deque[Sample] = deque(maxlen=capacity)

    def observe(self, snapshot: dict, *, now: float | None = None):
        when = time.monotonic() if now is None else now
        if not math.isfinite(when):
            raise ValueError("INVALID_MEASUREMENT_TIME")
        if self.samples and when < self.samples[-1].measured_at:
            raise ValueError("MEASUREMENT_TIME_REVERSED")
        parts = [
            count(snapshot.get(k))
            for k in ("completed_read_only", "completed_llm", "completed_scripted")
        ]
        completed = sum(parts) if all(p is not None for p in parts) else None
        sample = Sample(when, count(snapshot.get("queue_backlog")), completed)
        if self.samples and when == self.samples[-1].measured_at:
            if sample != self.samples[-1]:
                raise ValueError("CONFLICTING_MEASUREMENT")
            return
        self.samples.append(sample)


class Trend(tk.Canvas):
    def __init__(self, parent, history: MetricHistory, metric: str, title: str, color: str):
        super().__init__(
            parent,
            bg=SURFACE,
            height=244,
            highlightthickness=1,
            highlightbackground=ELEVATED,
            takefocus=True,
        )
        self.history, self.metric, self.heading, self.color = history, metric, title, color
        self.source = "UNVERIFIED SOURCE"
        self.hover = None
        self.bind("<Configure>", lambda _: self.redraw())
        self.bind("<Motion>", self.on_hover)
        self.bind("<Leave>", lambda _: self.clear_hover())
        self.bind("<Left>", lambda _: self.move(-1))
        self.bind("<Right>", lambda _: self.move(1))
        self.bind("<Button-1>", lambda _: self.focus_set())

    def clear_hover(self):
        self.hover = None
        self.redraw()

    def move(self, offset):
        if self.history.samples:
            start = self.hover if self.hover is not None else len(self.history.samples) - 1
            self.hover = max(0, min(len(self.history.samples) - 1, start + offset))
            self.redraw()
        return "break"

    def on_hover(self, event):
        samples = list(self.history.samples)
        if samples:
            target = (event.x - 48) / max(1, self.winfo_width() - 72)
            first, last = samples[0].measured_at, samples[-1].measured_at
            self.hover = min(
                range(len(samples)),
                key=lambda i: abs(samples[i].measured_at - (first + target * (last - first))),
            )
            self.redraw()

    def redraw(self):
        self.delete("all")
        self.text_images = []
        width, height = max(250, self.winfo_width()), max(180, self.winfo_height())
        samples = list(self.history.samples)
        text(self, 18, 24, self.heading, size=12, bold=True, fill=TEXT, width=max(150, width - 170))
        latest = getattr(samples[-1], self.metric) if samples else None
        text(
            self,
            width - 18,
            24,
            "Latest  " + ("UNKNOWN" if latest is None else str(latest)),
            size=14,
            fill=self.color,
            anchor="e",
            width=160,
        )
        numbers = [getattr(s, self.metric) for s in samples if getattr(s, self.metric) is not None]
        if not numbers:
            text(
                self,
                width / 2,
                height / 2,
                "UNKNOWN • no measured values",
                size=15,
                anchor="center",
                width=width - 30,
            )
            return
        peak = max(1, max(numbers))
        left, right, top, bottom = 48, width - 24, 58, height - 58
        for value in sorted({0, peak // 2, peak}):
            y = bottom - (bottom - top) * value / peak
            self.create_line(left, y, right, y, fill=ELEVATED)
            text(self, left - 10, y, str(value), anchor="e", size=11, width=40)
        first = samples[0].measured_at
        span = max(1, samples[-1].measured_at - first)
        segment = []

        def draw():
            if len(segment) >= 4:
                self.create_line(*segment, fill=self.color, width=2.5, tags="series-" + self.metric)
            elif len(segment) == 2:
                x, y = segment
                self.create_oval(
                    x - 3,
                    y - 3,
                    x + 3,
                    y + 3,
                    fill=self.color,
                    outline="",
                    tags="series-" + self.metric,
                )

        for sample in samples:
            value = getattr(sample, self.metric)
            if value is None:
                draw()
                segment = []
                continue
            x = left + (right - left) * (sample.measured_at - first) / span
            y = bottom - (bottom - top) * value / peak
            segment.extend((x, y))
        draw()
        text(self, left, height - 37, "0s", size=11, width=60)
        text(
            self,
            right,
            height - 37,
            f"{samples[-1].measured_at - first:.1f}s",
            size=11,
            anchor="e",
            width=90,
        )
        text(
            self,
            left,
            height - 16,
            self.source + " • measured elapsed time • counts",
            size=10,
            width=width - 65,
        )
        if self.hover is not None and samples:
            self.hover = min(self.hover, len(samples) - 1)
            sample = samples[self.hover]
            value = getattr(sample, self.metric)
            x = left + (right - left) * (sample.measured_at - first) / span
            self.create_line(x, top, x, bottom, fill=SECONDARY, dash=(3, 3), tags="crosshair")
            label = (
                f"{sample.measured_at - first:.1f}s  /  {value if value is not None else 'UNKNOWN'}"
            )
            self.create_rectangle(
                left + 5, top + 4, left + 215, top + 31, fill=ELEVATED, outline="", tags="tooltip"
            )
            text(self, left + 14, top + 18, label, size=12, fill=TEXT, width=195, tags="tooltip")


class Distribution(tk.Canvas):
    def __init__(self, parent, title):
        super().__init__(parent, bg=SURFACE, height=158, highlightthickness=0)
        self.heading, self.counts = title, None
        self.bind("<Configure>", lambda _: self.redraw())

    def update_counts(self, counts):
        self.counts = counts
        self.redraw()

    def redraw(self):
        self.delete("all")
        self.text_images = []
        width = max(280, self.winfo_width())
        text(self, 16, 20, self.heading, size=12, bold=True, fill=TEXT, width=width - 30)
        if self.counts is None or any(count(v) is None for v in self.counts.values()):
            text(self, 18, 85, "UNKNOWN • distribution not measured", size=13, width=width - 30)
            return
        total = sum(self.counts.values())
        if not total:
            text(self, 18, 85, "NO_DATA • no stored records", size=13, width=width - 30)
            return
        angle = 90
        items = list(self.counts.items())
        for key, value in items:
            if value:
                extent = 360 * value / total
                if value == total:
                    self.create_oval(
                        18, 48, 110, 140, outline=color(key), width=12, tags="distribution-arc"
                    )
                else:
                    self.create_arc(
                        18,
                        48,
                        110,
                        140,
                        start=angle,
                        extent=-extent,
                        style="arc",
                        outline=color(key),
                        width=12,
                        tags="distribution-arc",
                    )
                angle -= extent
        text(self, 64, 94, str(total), size=23, fill=TEXT, anchor="center", width=80, bold=True)
        for i, (key, value) in enumerate(items[:4]):
            x = 138 + (i // 4) * 180
            y = 58 + (i % 4) * 23
            self.create_oval(x, y - 3, x + 6, y + 3, fill=color(key), outline="")
            text(
                self,
                x + 14,
                y,
                key.replace("_", " ") + "  " + str(value),
                size=11,
                width=width - x - 25,
            )
        if len(items) > 4:
            text(
                self,
                width - 12,
                143,
                f"+{len(items) - 4} categories in details",
                size=10,
                anchor="e",
                width=220,
            )


class Comparison(tk.Canvas):
    def __init__(self, parent):
        super().__init__(parent, bg=SURFACE, height=145, highlightthickness=0)
        self.result = None
        self.bind("<Configure>", lambda _: self.redraw())

    def update_result(self, result):
        self.result = result
        self.redraw()

    def redraw(self):
        self.delete("all")
        self.text_images = []
        width = max(280, self.winfo_width())
        text(
            self,
            16,
            22,
            "OFFLINE EVALUATION • stored baseline / candidate",
            size=13,
            bold=True,
            fill=TEXT,
            width=width - 30,
        )
        result = self.result or {}
        baseline, trial = result.get("baseline", {}), result.get("trial", {})
        if not baseline.get("ground_truth_digest") or baseline.get(
            "ground_truth_digest"
        ) != trial.get("ground_truth_digest"):
            text(
                self,
                16,
                85,
                "UNKNOWN • select a valid stored same-dataset evaluation",
                size=13,
                width=width - 30,
            )
            return
        for i, (name, row, tone) in enumerate(
            (("Baseline", baseline, PRIMARY), ("Candidate", trial, "#A78BFA"))
        ):
            value = row.get("metrics", {}).get("f1")
            y = 61 + i * 34
            text(self, 16, y, name, size=12, width=110)
            if (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and math.isfinite(value)
                and 0 <= value <= 1
            ):
                self.create_rectangle(
                    135, y - 7, 135 + max(1, (width - 440) * value), y + 7, fill=tone, outline=""
                )
                text(self, width - 260, y, f"F1 {value:.3f}", size=12, fill=tone, width=110)
            else:
                text(self, 135, y, "F1 UNKNOWN", size=12, width=180)
        verdict = str(
            result.get(
                "regression_result", result.get("regression_gate", result.get("verdict", "UNKNOWN"))
            )
        )
        text(
            self,
            width - 16,
            110,
            verdict + " • promotion " + str(result.get("promotion", "UNKNOWN")),
            size=12,
            fill=color(verdict),
            anchor="e",
            width=330,
        )

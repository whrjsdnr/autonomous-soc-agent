"""Small bounded display-only charts. No generated telemetry or attack probability."""

import math
import time
import tkinter as tk
from collections import deque
from dataclasses import dataclass


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
        self.samples.append(Sample(when, count(snapshot.get("queue_backlog")), completed))


class Trend(tk.Canvas):
    def __init__(self, parent, history: MetricHistory, metric: str, title: str, color: str):
        super().__init__(
            parent, bg="#151e2b", height=170, highlightthickness=1, highlightbackground="#293548"
        )
        self.history, self.metric, self.heading, self.color = history, metric, title, color
        self.bind("<Configure>", lambda _: self.redraw())

    def redraw(self):
        self.delete("all")
        width, height = max(220, self.winfo_width()), max(120, self.winfo_height())
        self.create_text(14, 16, text=self.heading, anchor="w", fill="#e0e8f2")
        samples = list(self.history.samples)
        numbers = [getattr(s, self.metric) for s in samples if getattr(s, self.metric) is not None]
        if not numbers:
            self.create_text(
                width / 2,
                height / 2,
                text="UNKNOWN · waiting for Backend measurements",
                fill="#8c9cb2",
            )
            return
        peak = max(1, max(numbers))
        left, right, top, bottom = 44, width - 18, 40, height - 30
        for fraction in (0, 0.5, 1):
            y = bottom - (bottom - top) * fraction
            self.create_line(left, y, right, y, fill="#293548")
            self.create_text(
                left - 7, y, text=str(round(peak * fraction, 1)), anchor="e", fill="#8c9cb2"
            )
        first = samples[0].measured_at
        span = max(1, samples[-1].measured_at - first)
        segment = []

        def draw():
            if len(segment) >= 4:
                self.create_line(*segment, fill=self.color, width=2, tags="series-" + self.metric)
            elif len(segment) == 2:
                x, y = segment
                self.create_oval(
                    x - 2,
                    y - 2,
                    x + 2,
                    y + 2,
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
        latest = getattr(samples[-1], self.metric)
        self.create_text(
            right,
            16,
            text="Latest: " + ("UNKNOWN" if latest is None else str(latest)),
            anchor="e",
            fill=self.color,
        )
        self.create_text(
            left,
            height - 12,
            text=f"Observed {samples[-1].measured_at - first:.1f}s · gaps = UNKNOWN",
            anchor="w",
            fill="#8c9cb2",
        )

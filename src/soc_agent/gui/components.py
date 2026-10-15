"""Small Tk presentation components; no backend or authority logic."""

import tkinter as tk
from tkinter import ttk

from soc_agent.gui.typography import Label as ScalableLabel
from soc_agent.gui.typography import text, typography

BG, SIDE, SURFACE, ELEVATED = "#0B1220", "#111C2E", "#17243A", "#20314A"
PRIMARY, TEXT, SECONDARY = "#38BDF8", "#F1F5F9", "#94A3B8"
HEALTHY, WARNING, CRITICAL, UNKNOWN = "#22C55E", "#F59E0B", "#EF4444", "#64748B"


def color(value):
    word = str(value).upper()
    if word == "NO_FP_FN_COUNT_REGRESSION":
        return WARNING
    if any(
        v in word
        for v in ("NOT_READY", "NOT_INFERABLE", "DEGRADED", "PENDING", "EXPIRED", "INCONCLUSIVE")
    ):
        return WARNING
    if any(v in word for v in ("FAILED", "FAIL", "BLOCKED", "REGRESS", "REJECTED")):
        return CRITICAL
    if any(
        v in word
        for v in (
            "UNKNOWN",
            "OFFLINE",
            "STOPPED",
            "NO_DATA",
            "NOT_",
            "UNVERIFIED",
            "UNAVAILABLE",
            "UNLINKED",
        )
    ):
        return UNKNOWN
    if any(
        v in word
        for v in (
            "PASS",
            "VERIFIED",
            "HEALTHY",
            "READY",
            "COMPLETED",
            "DONE",
            "SIMULATED",
            "ROLLED_BACK",
        )
    ):
        return HEALTHY
    return PRIMARY


def Label(parent, **kwargs):
    style = kwargs.pop("style", "")
    font = kwargs.pop("font", None)
    size = 28 if style == "Title.TLabel" else 18 if style == "Header.TLabel" else 13
    if font:
        size = max(11, abs(font[1]))
        kwargs.setdefault("bold", "bold" in font)
    kwargs.setdefault("size", size)
    kwargs.setdefault("fg", SECONDARY if style == "Muted.TLabel" else TEXT)
    kwargs.setdefault("bg", BG)
    if "wraplength" in kwargs:
        kwargs["max_width"] = max(24, kwargs.pop("wraplength"))
    return ScalableLabel(parent, **kwargs)


def Button(parent, *, text: str, command, style="TButton", **kwargs):
    image = typography(parent).photo(text, 13, TEXT, bold=False, width=240)
    button = ttk.Button(
        parent, text=text, image=image, command=command, style=style, takefocus=True, **kwargs
    )
    button.soc_image = image
    return button


class Hero(tk.Canvas):
    def __init__(self, parent):
        super().__init__(
            parent, bg=SIDE, height=108, highlightthickness=1, highlightbackground=ELEVATED
        )
        self.value = {}
        self.bind("<Configure>", lambda _: self.redraw())

    def update_snapshot(self, value):
        self.value = value
        self.redraw()

    def redraw(self):
        self.delete("all")
        self.text_images = []
        value, width = self.value, max(300, self.winfo_width())
        state = value.get("runtime_state", "UNKNOWN")
        ready = (
            state == "RUNNING"
            and value.get("health") == "HEALTHY"
            and value.get("readiness") == "READY"
            and not value.get("last_error")
        )
        tone = (
            HEALTHY
            if ready
            else CRITICAL
            if value.get("last_error") or state == "FAILED"
            else WARNING
            if state == "RUNNING"
            else UNKNOWN
        )
        title = (
            "Monitoring active"
            if ready
            else "Attention required"
            if state in ("RUNNING", "FAILED")
            else "Monitoring paused"
        )
        self.create_rectangle(0, 0, 5, 110, fill=tone, outline="")
        self.create_oval(22, 23, 34, 35, fill=tone, outline="", tags="health-indicator")
        text(self, 48, 28, title, size=25, fill=TEXT, bold=True, width=440)
        text(
            self,
            width - 20,
            28,
            state + "  /  " + ("READY" if ready else "NOT_READY"),
            size=14,
            fill=tone,
            anchor="e",
            width=350,
        )
        detail = (
            "Health "
            + str(value.get("health", "UNKNOWN"))
            + "    Collector "
            + str(value.get("collector_state", "UNKNOWN"))
        )
        detail += "    Queue " + str(
            value.get("queue_backlog") if value.get("queue_backlog") is not None else "UNKNOWN"
        )
        text(self, 22, 61, detail, size=12, width=max(200, width - 40))
        source = value.get("display_source", "UNVERIFIED SOURCE")
        mode = value.get("assessment_mode", "UNKNOWN")
        note = str(
            value.get("last_error")
            or "READ-only investigation • Explicit approval • No OS security response"
        )
        text(
            self,
            22,
            88,
            source + "  /  " + mode + "  •  " + note,
            size=11,
            fill=WARNING if value.get("last_error") else SECONDARY,
            width=max(200, width - 210),
        )
        text(
            self,
            width - 20,
            87,
            "Updated " + value.get("display_updated", "UNKNOWN"),
            size=11,
            anchor="e",
            width=180,
        )


class Table(tk.Canvas):
    """A bounded, keyboard-selectable Tk list with scalable text and familiar row API."""

    def __init__(self, parent, columns):
        super().__init__(
            parent,
            bg=SURFACE,
            highlightthickness=0,
            takefocus=True,
            yscrollincrement=42,
            height=190,
        )
        self.columns, self.headings = tuple(columns), dict.fromkeys(columns, "")
        self.rows, self.selected, self.timer = {}, (), None
        self.bind("<Configure>", lambda _: self.schedule())
        self.bind("<Button-1>", self.click)
        self.bind("<Up>", lambda _: self.move(-1))
        self.bind("<Down>", lambda _: self.move(1))
        self.bind("<Home>", lambda _: self.selection_set(next(iter(self.rows), "")))
        self.bind("<End>", lambda _: self.selection_set(next(reversed(self.rows), "")))
        self.bind("<MouseWheel>", lambda e: self.scroll(-1 if e.delta > 0 else 1))
        self.bind("<Button-4>", lambda _: self.scroll(-1))
        self.bind("<Button-5>", lambda _: self.scroll(1))
        self.bind(
            "<FocusIn>", lambda _: self.configure(highlightthickness=1, highlightbackground=PRIMARY)
        )
        self.bind("<FocusOut>", lambda _: self.configure(highlightthickness=0))

    def heading(self, key, *, text):
        self.headings[key] = text

    def column(self, *_args, **_kwargs):
        return None

    def tag_configure(self, *_args, **_kwargs):
        return None

    def get_children(self):
        return tuple(self.rows)

    def delete(self, key):
        self.rows.pop(key, None)
        if key in self.selected:
            self.selected = ()
        self.schedule()

    def insert(self, _parent, _where, *, iid, values, tags=()):
        self.rows[iid] = {"values": tuple(str(v) for v in values), "tags": tags}
        self.schedule()

    def item(self, key, option=None):
        return self.rows[key].get(option) if option else self.rows[key]

    def selection(self):
        return self.selected

    def selection_set(self, key):
        if key in self.rows:
            self.selected = (key,)
            self.event_generate("<<TreeviewSelect>>")
            self.schedule()

    def click(self, event):
        self.focus_set()
        index = int((self.canvasy(event.y) - 42) // 42)
        if event.y > 42 and 0 <= index < len(self.rows):
            self.selection_set(tuple(self.rows)[index])

    def move(self, direction):
        keys = tuple(self.rows)
        if keys:
            i = keys.index(self.selected[0]) if self.selected else -1
            index = max(0, min(len(keys) - 1, i + direction))
            self.selection_set(keys[index])
            if index * 42 < self.canvasy(42) or index * 42 + 84 > self.canvasy(self.winfo_height()):
                super().yview_moveto(index / max(1, len(keys)))
        return "break"

    def scroll(self, units):
        super().yview_scroll(units, "units")
        self.schedule()
        return "break"

    def yview(self, *args):
        result = super().yview(*args)
        if args:
            self.schedule()
        return result

    def schedule(self):
        if self.timer is None:
            self.timer = self.after_idle(self.redraw)

    def redraw(self):
        self.timer = None
        super().delete("all")
        self.text_images = []
        width, height = max(280, self.winfo_width()), self.winfo_height()
        self.configure(scrollregion=(0, 0, width, max(height, len(self.rows) * 42 + 42)))
        top = self.canvasy(0)
        colwidth = width / len(self.columns)
        start = max(0, int(top // 42) - 1)
        stop = min(len(self.rows), start + int(height // 42) + 3)
        for i, (key, row) in enumerate(self.rows.items()):
            if not start <= i < stop:
                continue
            y = 42 + i * 42
            self.create_rectangle(
                0,
                y,
                width,
                y + 42,
                fill=ELEVATED if key in self.selected else SURFACE,
                outline=SIDE,
            )
            for j, value in enumerate(row["values"]):
                text(
                    self,
                    12 + j * colwidth,
                    y + 21,
                    value,
                    size=13,
                    fill=color(value) if j >= 2 else TEXT,
                    width=max(24, int(colwidth) - 24),
                )
        self.create_rectangle(0, top, width, top + 42, fill=SIDE, outline="")
        for j, key in enumerate(self.columns):
            text(
                self,
                12 + j * colwidth,
                top + 21,
                self.headings[key] or key.upper(),
                size=11,
                fill=SECONDARY,
                bold=True,
                width=max(24, int(colwidth) - 24),
            )
        if not self.rows:
            text(
                self,
                width / 2,
                top + height / 2 + 20,
                "NO_DATA • No records in this view",
                size=15,
                anchor="center",
            )

    def destroy(self):
        if self.timer is not None:
            self.after_cancel(self.timer)
        super().destroy()

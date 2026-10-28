"""Service attachment does not transfer ownership of its independent lifetime."""

import json
import tkinter as tk
from tkinter import filedialog, ttk

from soc_agent.gui.redaction import display_data


def build(app):
    ttk.Label(app.content, text="Continuous Runtime · independent service").pack(
        anchor="w", pady=10
    )
    controls = ttk.Frame(app.content)
    controls.pack(fill="x", pady=8)

    def attach():
        path = filedialog.askdirectory(
            parent=app.root, title="Attach initialized Continuous Runtime"
        )
        if path:
            app.call("continuous_attach", path, callback=app.continuous_updated)

    for name, callback in [
        ("Attach", attach),
        ("Start Service", lambda: app.call("continuous_start", callback=app.continuous_updated)),
        ("Stop Service", lambda: app.call("continuous_stop", callback=app.continuous_updated)),
        ("Reset AI Circuit", lambda: app.call("continuous_reset", callback=app.continuous_updated)),
    ]:
        ttk.Button(controls, text=name, command=callback).pack(side="left", padx=4)
    ttk.Label(
        app.content,
        text=(
            "Closing this UI leaves the service running. "
            "Native service authority is separate from diagnostic approval."
        ),
        wraplength=950,
    ).pack(anchor="w", pady=8)
    app.continuous_summary = ttk.Label(app.content, wraplength=950)
    app.continuous_summary.pack(anchor="w", pady=8)
    app.continuous_detail = tk.Text(
        app.content, height=28, wrap="word", bg="#17243A", fg="#F1F5F9", state="disabled"
    )
    app.continuous_detail.pack(fill="both", expand=True)


def render(app, value):
    app.continuous_summary.configure(
        text=(
            f"{value.get('state', 'NOT_ATTACHED')} · {value.get('source', 'NO_SOURCE')}\n"
            f"Collector: {value.get('collector', 'UNKNOWN')} · "
            f"AI: {value.get('worker', 'UNKNOWN')}\n"
            f"Native live: {value.get('collection_live', False)} · "
            f"Cleanup: {value.get('cleanup', 'UNKNOWN')}"
        )
    )
    app._text(app.continuous_detail, json.dumps(display_data(value), indent=2, ensure_ascii=False))

"""Service attachment does not transfer ownership of its independent lifetime."""

import json
import tkinter as tk
from tkinter import filedialog, ttk

from soc_agent.gui.continuous_projection import availability
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
    app.continuous_incidents = ttk.Treeview(
        app.content,
        columns=("origin", "domain", "classification", "eligibility", "audit"),
        show="headings",
        height=6,
    )
    for name in ("origin", "domain", "classification", "eligibility", "audit"):
        app.continuous_incidents.heading(name, text=name.title())
    app.continuous_incidents.pack(fill="x", pady=6)
    app.continuous_outputs = {}

    def inspect_incident(*_):
        selected = app.continuous_incidents.selection()
        if selected and selected[0] in app.continuous_outputs:
            output = app.continuous_outputs[selected[0]]
            app.navigate("AI Analysis", refresh=False)
            app.call("analysis_attach", output, callback=app.analysis_updated)

    app.continuous_incidents.bind("<Double-1>", inspect_incident)
    ttk.Button(app.content, text="Inspect Selected Incident", command=inspect_incident).pack(
        anchor="w"
    )
    app.continuous_detail = tk.Text(
        app.content, height=18, wrap="word", bg="#17243A", fg="#F1F5F9", state="disabled"
    )
    app.continuous_detail.pack(fill="both", expand=True)


def render(app, value):
    dns_transport = value.get("dns_transport", {})
    helper_process = dns_transport.get("helper_process", {}).get("state", "NOT_RECORDED")
    heartbeat_status = dns_transport.get("heartbeat_status", "NOT_RECORDED")
    app.continuous_summary.configure(
        text=(
            f"{value.get('state', 'NOT_ATTACHED')} · {value.get('source', 'NO_SOURCE')}\n"
            f"Collector: {value.get('collector', 'UNKNOWN')} · "
            f"AI: {value.get('worker', 'UNKNOWN')}\n"
            f"Native live: {value.get('collection_live', False)} · "
            f"Runtime cleanup: {value.get('cleanup', 'UNKNOWN')} · "
            f"Collector cleanup: {value.get('collector_cleanup', 'UNKNOWN')}\n"
            "Capture: "
            f"{value.get('capture_window', {}).get('assessment', {}).get('status', 'UNKNOWN')} · "
            f"Queue: {value.get('queue', {})} · "
            f"Drops: {value.get('metrics', {}).get('queue_dropped', 0)}\n"
            f"Packets: {value.get('metrics', {}).get('packets', 0)} · "
            f"Flows: {value.get('metrics', {}).get('flows', 0)} · "
            f"Eligible: {value.get('metrics', {}).get('eligible', 0)} · "
            f"Incomplete: {value.get('metrics', {}).get('incomplete', 0)} · "
            f"Predictions: {value.get('metrics', {}).get('predictions', 0)}\n"
            f"DNS: {value.get('dns_transport', {}).get('state', 'NOT_COLLECTED_IN_THIS_SCOPE')} · "
            f"Metadata: {value.get('metrics', {}).get('dns_inputs', 0)} · "
            f"Transactions: {value.get('dns', {}).get('counts', {})} · DNS9 BLOCKED\n"
            "DNS Helper process: "
            f"{helper_process} · "
            f"Heartbeat: {heartbeat_status} · "
            f"Cleanup: {value.get('dns_transport', {}).get('cleanup', 'UNKNOWN')}\n"
            "Worker observed (supervisor, not model progress): "
            f"{value.get('component_health', {}).get('worker_observed_unix', 'UNKNOWN')} · "
            f"Last error: {display_data(value.get('last_error') or 'NONE')}"
            f"\nController: {display_data(value.get('controller_error') or 'NO_REPORTED_ERROR')}"
            f"\nAI measurements: {availability(value, [])['inference']} · "
            f"Investigation: {availability(value, [])['investigation']}"
        )
    )
    selected = app.continuous_incidents.selection()
    app.continuous_incidents.delete(*app.continuous_incidents.get_children())
    app.continuous_outputs = {}
    for result in value.get("recent_results", []):
        identity = result["incident_id"]
        app.continuous_incidents.insert(
            "",
            "end",
            iid=identity,
            values=(
                ", ".join(result.get("origins", [])),
                ", ".join(result.get("domains", [])),
                result["classification"],
                result["eligibility"],
                result["audit"],
            ),
        )
        app.continuous_outputs[identity] = result["output"]
    if selected and app.continuous_incidents.exists(selected[0]):
        app.continuous_incidents.selection_set(selected)
    app._text(app.continuous_detail, json.dumps(display_data(value), indent=2, ensure_ascii=False))

"""Verified offline outcomes in the existing unprivileged operator desktop."""

import json
import tkinter as tk
from tkinter import filedialog, ttk

from soc_agent.gui.redaction import display_data


def build(app):
    ttk.Label(app.content, text="AI Analysis · Evidence → Model → Incident → Audit").pack(
        anchor="w", pady=8
    )
    controls = ttk.Frame(app.content)
    controls.pack(fill="x", pady=8)

    def start():
        path = filedialog.askopenfilename(parent=app.root, title="Select offline analysis job")
        if path:
            app.call("analysis_start", path, callback=app.analysis_updated)

    def attach():
        path = filedialog.askdirectory(parent=app.root, title="Select audited result directory")
        if path:
            app.call("analysis_attach", path, callback=app.analysis_updated)

    ttk.Button(controls, text="Run Offline Job", command=start).pack(side="left", padx=4)
    ttk.Button(
        controls,
        text="Stop Owned Analysis",
        command=lambda: app.call("analysis_stop", callback=app.analysis_updated),
    ).pack(side="left", padx=4)
    ttk.Button(controls, text="Open Verified Report", command=attach).pack(side="left", padx=4)
    ttk.Label(
        app.content,
        text="Native: separate governed terminal required · DNS9: INCOMPLETE · No API calls here",
        wraplength=950,
    ).pack(anchor="w", pady=8)
    app.analysis_summary = ttk.Label(
        app.content, text="No verified analysis loaded", wraplength=950
    )
    app.analysis_summary.pack(anchor="w", pady=8)
    app.analysis_predictions = ttk.Treeview(
        app.content,
        columns=("model", "prediction", "score", "semantics"),
        show="headings",
        height=4,
    )
    for column in ("model", "prediction", "score", "semantics"):
        app.analysis_predictions.heading(column, text=column.title())
        app.analysis_predictions.column(column, width=150, stretch=True)
    app.analysis_predictions.pack(fill="x", pady=8)
    ttk.Label(app.content, text="Incident / Investigation / Provenance / Audit").pack(anchor="w")
    notebook = ttk.Notebook(app.content)
    notebook.pack(fill="both", expand=True, pady=8)
    for name, attribute in (
        ("Incident", "analysis_incident"),
        ("Investigation", "analysis_investigation"),
        ("Evidence / Audit", "analysis_detail"),
    ):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=name)
        text = tk.Text(frame, height=18, wrap="word", bg="#17243A", fg="#F1F5F9", state="disabled")
        text.pack(fill="both", expand=True)
        setattr(app, attribute, text)


def render(app, value):
    state = value.get("state", "NOT_STARTED")
    result = value.get("result") or {}
    origin_label = (
        "RETAINED_NATIVE" if "REAL_NATIVE" in result.get("input_origins", []) else "OFFLINE"
    )
    app.analysis_summary.configure(
        text=(
            f"{state} · {origin_label} / not live capture · "
            + (
                "Produced by attached Continuous Runtime · "
                if value.get("mode") == "ATTACHED_CONTINUOUS_RESULT"
                else ""
            )
            + f"Cleanup: {value.get('cleanup', 'NOT_STARTED')}\n"
            f"Incident: {result.get('incident_id', '—')} · "
            f"{result.get('classification', 'NO_RESULT')} · "
            f"Eligibility: {result.get('eligibility', 'UNKNOWN')}\n"
            f"Origins: {', '.join(result.get('input_origins', [])) or 'NONE'} · "
            f"LLM: {result.get('llm_mode', 'NOT_REQUESTED')} · "
            f"Audit: {result.get('audit', 'PENDING')}"
        )
    )
    tree = app.analysis_predictions
    tree.delete(*tree.get_children())
    for row in result.get("predictions", []):
        tree.insert(
            "",
            "end",
            values=tuple(
                str(row.get(k, "UNKNOWN"))
                for k in ("model", "prediction", "score", "score_semantics")
            ),
        )
    detail = result.get("detail") or {}
    response = detail.get("response") or {}
    app._text(
        app.analysis_incident,
        f"Classification: {result.get('classification', 'NO_RESULT')}\n"
        f"Meaning: {result.get('classification_basis', 'NO_VERIFIED_RESULT')}\n"
        f"Evidence eligibility: {result.get('eligibility', 'UNKNOWN')}\n"
        f"Eligibility scope: {result.get('eligibility_scope', 'UNKNOWN')}\n"
        f"Response policy: {response.get('policy', 'NOT_REQUESTED')}\n"
        f"Response postcondition: {result.get('response_status', 'NOT_REQUESTED')}\n"
        f"Cleanup: {value.get('cleanup', 'NOT_STARTED')}\n"
        f"Error: {value.get('last_error') or 'NONE'}\n\n"
        "Model scores are uncalibrated. "
        "Source continuity is not attack confirmation or host repair.\n"
        "This analysis does not start Native capture or change the network.",
    )
    app._text(
        app.analysis_investigation,
        "Investigation mode: "
        + result.get("llm_mode", "NOT_REQUESTED")
        + "\nHypotheses and recommendations are not verified observations.\n\n"
        + json.dumps(display_data(detail.get("investigation") or {}), indent=2, ensure_ascii=False),
    )
    app._text(app.analysis_detail, json.dumps(display_data(value), indent=2, ensure_ascii=False))

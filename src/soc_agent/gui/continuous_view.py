"""Service attachment does not transfer ownership of its independent lifetime."""

import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

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
    if getattr(app.config, "operator_home", None):

        def sessions_ready(value):
            window = tk.Toplevel(app.root)
            window.title("Preserved Sessions · attach only, no execution")
            choices = tk.Listbox(window, width=105, height=10)
            choices.pack(fill="both", expand=True)
            for row in value["sessions"]:
                choices.insert("end", f"{row['index']} · {row['source']} · {row['runtime']}")

            def selected():
                indices = choices.curselection()
                if indices:
                    app.call(
                        "operator_session_attach",
                        value["sessions"][indices[0]]["index"],
                        callback=app.continuous_updated,
                    )
                    window.destroy()

            ttk.Button(window, text="Attach selected Session", command=selected).pack()

        ttk.Button(
            controls,
            text="Sessions",
            command=lambda: app.call("operator_sessions", callback=sessions_ready),
        ).pack(side="left", padx=4)
    review_controls = ttk.Frame(app.content)
    review_controls.pack(fill="x", pady=4)

    def review_models(batch):
        if not batch.get("jobs"):
            messagebox.showinfo(
                "RF/LR approval", batch.get("status", "NO_PENDING_JOBS"), parent=app.root
            )
            return
        summary = [
            "Approve only the displayed already sealed ELIGIBLE jobs?",
            f"Session: {batch['runtime_session']}",
            f"Operator: {batch['actor']}",
            f"Prior calls: {batch['previous_invocations']} / {batch['maximum_invocations']}",
            "No Root, capture, DNS or API authority. No future-input approval.",
        ]
        for job in batch["jobs"]:
            summary.append(
                f"Job {job['job']}: eligible={job['eligible']}, RF/LR calls={job['calls']}"
            )
        summary.append("Models / fingerprints: " + json.dumps(batch["models"], sort_keys=True))
        if messagebox.askyesno("Exact RF/LR job approval", "\n".join(summary), parent=app.root):
            app.call(
                "model_review_approve",
                batch["batch_digest"],
                True,
                callback=app.continuous_updated,
            )

    ttk.Button(
        review_controls,
        text="Review sealed RF/LR jobs",
        command=lambda: app.call("model_review_prepare", callback=review_models),
    ).pack(side="left", padx=4)

    def review_api(summary):
        if not summary.get("ready"):
            messagebox.showinfo(
                "LLM approval", summary.get("status", "WAITING_INPUT"), parent=app.root
            )
            return
        details = "\n".join(
            (
                f"Incident: {summary['incident_id']}",
                f"Evidence revision: {summary['evidence_revision']}",
                f"Provider: {summary['base_url']} / {summary['model']}",
                f"Requests <= {summary['max_calls']}; USD <= {summary['budget_usd']}",
                f"Timeout {summary['timeout_seconds']}s; automatic retries=0",
                "Plan + Assessment; read-only tools; no Root/Native/model authority.",
                "Raw payloads, addresses, domains, accounts and credentials stay local.",
            )
        )
        if messagebox.askyesno("Approve exact LLM investigation input", details, parent=app.root):
            app.call(
                "api_review_approve",
                summary["review_digest"],
                True,
                callback=lambda value: app.status.set(value["status"]),
            )

    ttk.Button(
        review_controls,
        text="Review LLM Plan / Assessment",
        command=lambda: app.call("api_review_prepare", callback=review_api),
    ).pack(side="left", padx=4)
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
    ttk.Label(
        app.content, text="Investigation tasks · priority / evidence revision / wait reason"
    ).pack(anchor="w")
    app.continuous_tasks = ttk.Treeview(
        app.content,
        columns=("role", "task", "state", "priority", "revision", "wait"),
        show="headings",
        height=5,
    )
    for column in ("role", "task", "state", "priority", "revision", "wait"):
        app.continuous_tasks.heading(column, text=column.title())
    app.continuous_tasks.pack(fill="x", pady=6)
    app.continuous_detail = tk.Text(
        app.content, height=18, wrap="word", bg="#17243A", fg="#F1F5F9", state="disabled"
    )
    app.continuous_detail.pack(fill="both", expand=True)


def render(app, value):
    app.continuous_tasks.delete(*app.continuous_tasks.get_children())
    for task in value.get("orchestration", {}).get("tasks", []):
        app.continuous_tasks.insert(
            "",
            "end",
            iid=task["task_id"],
            values=(
                ", ".join(task["roles"]),
                task["task_id"],
                task["state"],
                task["priority"],
                task["evidence_revision"],
                task.get("waiting_reason") or "",
            ),
        )
    dns_transport = value.get("dns_transport", {})
    helper_process = dns_transport.get("helper_process", {}).get("state", "NOT_RECORDED")
    heartbeat_status = dns_transport.get("heartbeat_status", "NOT_RECORDED")
    tcx_cleanup = value.get("producer", {}).get("cleanup_evidence", {})
    producer_control = value.get("producer", {}).get("control") or {}
    api = value.get("orchestration", {}).get("worker", {}).get("api_status")
    if api is None:
        api = next(
            (
                (task.get("investigation") or {}).get("api_status")
                for task in reversed(value.get("orchestration", {}).get("tasks", []))
                if (task.get("investigation") or {}).get("api_status") is not None
            ),
            None,
        )
    api_text = "NO_API_RECEIPT_IN_THIS_RUNTIME"
    if api is not None:
        total = api.get("total_estimated_usd")
        api_text = (
            f"adapter requests={api.get('calls')} · total estimate="
            f"{total if total is not None else 'UNKNOWN'} · "
            f"reserved USD={api.get('reserved_usd')} · "
            f"billing={api.get('billing_outcome')} · requests={api.get('requests', [])}"
        )
    app.continuous_summary.configure(
        text=(
            f"{value.get('state', 'NOT_ATTACHED')} · {value.get('source', 'NO_SOURCE')}\n"
            f"Collector: {value.get('collector', 'UNKNOWN')} · "
            f"AI: {value.get('worker', 'UNKNOWN')}\n"
            f"Native live: {value.get('collection_live', False)} · "
            f"Runtime cleanup: {value.get('cleanup', 'UNKNOWN')} · "
            f"Collector cleanup: {value.get('collector_cleanup', 'UNKNOWN')}\n"
            f"TCX STOP ACK: {tcx_cleanup.get('stop_ack', 'NOT_RECORDED')} · "
            f"TCX cleanup evidence: {tcx_cleanup.get('status', 'NOT_RECORDED')} · "
            f"Diagnostic seals: {len(tcx_cleanup.get('seals', []))} "
            "(failed-stream evidence does not authorize inference)\n"
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
            f"\nInvestigation worker: {value.get('orchestration', {}).get('worker', {})}"
            f"\nSource roles: {value.get('orchestration', {}).get('agents', {})}"
            f"\nProducer control: {producer_control.get('worker', 'NOT_RECORDED')} · "
            f"receive latency seconds: {producer_control.get('receive_latency_seconds', 'UNKNOWN')}"
            f"\nRuntime control: {value.get('control', 'LEGACY_OBSERVATION')} · "
            f"Storage: {value.get('component_health', {}).get('storage', 'UNKNOWN')}"
            "\nData progress: "
            f"{value.get('component_health', {}).get('data_progress', 'UNKNOWN')} · "
            f"Publication: {value.get('component_health', {}).get('publication', 'UNKNOWN')}"
            f"\nAPI: {api_text}"
            "\nAPI source/cleanup: "
            f"{display_data(value.get('api_investigation') or 'NOT_ATTACHED')}"
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

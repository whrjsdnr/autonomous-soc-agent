"""Live-research presentation. Permission commands are displayed/copied, never executed."""

import tkinter as tk
from tkinter import ttk

from soc_agent.gui.charts import Distribution, MetricHistory, Trend
from soc_agent.gui.components import Button, Label


def display_state(value):
    state = value.get("state", "UNKNOWN")
    if state.startswith("LIVE_") and value.get("collection_live") is not True:
        return "UNKNOWN"
    return state


class LiveView:
    def __init__(self, app):
        self.app = app
        self.history = MetricHistory()
        self.session = None
        self.command = ""
        self.command_session = None
        self.last_snapshot = {}
        self.pending = False
        self.headline = tk.StringVar(value="STOPPED · no active helper")
        self.metrics = tk.StringVar(value="UNKNOWN · waiting for backend")
        Label(app.content, text="Live Network · research advisory", size=22, bold=True).pack(
            anchor="w"
        )
        Label(
            app.content,
            text="lo only · up to 60 seconds / 512 frames · no payload · no operational promotion",
            size=12,
            max_width=1200,
        ).pack(anchor="w", pady=(8, 12))
        Label(app.content, textvariable=self.headline, size=18, max_width=1200).pack(
            anchor="w", pady=8
        )
        controls = ttk.Frame(app.content)
        controls.pack(fill="x", pady=8)
        self.profile = tk.StringVar(value="both")
        ttk.Combobox(
            controls,
            textvariable=self.profile,
            values=("both", "quality", "edge"),
            state="readonly",
            width=12,
        ).pack(side="left", padx=(0, 10))
        self.start_button = Button(controls, text="Prepare live session", command=self.start)
        self.start_button.pack(side="left", padx=(0, 10))
        self.copy_button = Button(controls, text="Copy helper command", command=self.copy_command)
        self.copy_button.pack(side="left", padx=(0, 10))
        self.copy_button.configure(state="disabled")
        Button(
            controls, text="Stop live", command=lambda: app.call("live_stop", callback=self.render)
        ).pack(side="left")
        self.instructions = tk.Text(
            app.content,
            height=6,
            wrap="word",
            bg="#17243A",
            fg="#F1F5F9",
            insertbackground="#F1F5F9",
            relief="flat",
        )
        self.instructions.pack(fill="x", pady=8)
        self.instructions.insert(
            "end",
            "Prepare creates an unprivileged observer. Authenticate and run the reviewed helper "
            "yourself in a terminal. No password is entered here. No automatic capture restart.",
        )
        self.instructions.configure(state="disabled")
        Label(app.content, textvariable=self.metrics, size=12, max_width=1200).pack(
            fill="x", pady=8
        )
        charts = ttk.Frame(app.content)
        charts.pack(fill="x", pady=8)
        self.traffic = Trend(
            charts, self.history, "network_rate", "NATIVE INPUT · packets/s", "#38BDF8", "packets/s"
        )
        self.traffic.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self.counts = Distribution(
            charts, "CONFIRMED RESEARCH CALLS · separate from operational AI"
        )
        self.counts.pack(side="left", fill="both", expand=True)
        app._table(("model", "source", "score", "prediction", "investigation"))
        row = ttk.Frame(app.detail_parent)
        row.pack(before=app.summary_frame, fill="x")
        Button(row, text="Investigation", command=self.show_record).pack(side="left", padx=8)
        Button(row, text="Audit / receipt", command=lambda: self.show_record(mode="audit")).pack(
            side="left"
        )
        self.poll()

    def start(self):
        if self.app.busy or self.app.closing:
            return
        self.clear_command("Preparing listener; no helper command available yet.")
        self.start_button.configure(state="disabled")
        self.app.call("live_start", self.profile.get(), callback=self.prepared)

    def prepared(self, result):
        if not self.headline.get() or not self.instructions.winfo_exists():
            return
        self.command = result.get("command", "") if result.get("listener_ready") is True else ""
        self.command_session = result.get("session_id") if self.command else None
        self.copy_button.configure(state="normal" if self.command else "disabled")
        self.instructions.configure(state="normal")
        self.instructions.delete("1.0", "end")
        self.instructions.insert(
            "end",
            (
                result.get(
                    "authentication",
                    result.get("error", "Environment unavailable; inspect model status."),
                )
                + "\n"
                + self.command
                + "\n"
                + result.get("stop", "No capture started.")
                + "\n"
                + "Review helper SHA256: "
                + result.get("helper_sha256", "UNKNOWN")
            ),
        )
        self.instructions.configure(state="disabled")
        self.headline.set(
            "LISTENER READY · waiting for your terminal authentication"
            if self.command
            else result.get("status", "UNKNOWN")
        )

    def clear_command(self, reason):
        self.command, self.command_session = "", None
        self.copy_button.configure(state="disabled")
        self.instructions.configure(state="normal")
        self.instructions.delete("1.0", "end")
        self.instructions.insert("end", reason)
        self.instructions.configure(state="disabled")

    def copy_command(self):
        if self.app.busy or self.app.closing:
            return
        session_id = self.command_session or self.last_snapshot.get("session_id")
        if session_id:
            self.app.call("live_command", session_id, callback=self.copy_verified_command)

    def copy_verified_command(self, result):
        if self.app.page != "Live Network" or not self.instructions.winfo_exists():
            return
        self.prepared(result)
        if not self.command:
            self.app.notice.set("Listener unavailable. Stop live, then prepare a new session.")
            return
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(self.command)
        self.app.notice.set(
            "Helper command copied. Review SHA and scope; authenticate in your terminal."
        )

    def poll(self):
        if (
            self.app.closing
            or self.app.page != "Live Network"
            or not self.instructions.winfo_exists()
        ):
            return
        if self.pending:
            return
        self.pending = True
        future = self.app.worker.submit("live_status")

        def finish():
            if self.app.closing or not self.instructions.winfo_exists():
                return
            if not future.done():
                self.app.root.after(50, finish)
                return
            self.pending = False
            try:
                self.render(future.result())
            except (OSError, ValueError, RuntimeError):
                self.clear_command("Status unavailable; Stop live and prepare a new session.")
                self.headline.set("UNKNOWN · status unavailable; Stop live before retry")
            self.app.root.after(1000, self.poll)

        self.app.root.after(50, finish)

    def render(self, value):
        if self.app.page != "Live Network" or not self.instructions.winfo_exists():
            return
        self.last_snapshot = value
        state = display_state(value)
        listener_ready = value.get("listener_ready") is True
        if not listener_ready or (
            self.command_session and self.command_session != value.get("session_id")
        ):
            if self.command:
                self.clear_command("Helper command no longer valid. Prepare a new live session.")
        self.copy_button.configure(state="normal" if listener_ready else "disabled")
        self.start_button.configure(
            state="disabled"
            if value.get("prepare_active")
            or state
            in (
                "STARTING",
                "HELPER_VALIDATING",
                "AUTHENTICATION_REQUIRED",
                "LIVE_COLLECTION",
                "LIVE_RESEARCH_INFERENCE",
                "COLLECTION_STOPPED_RESEARCH_DRAINING",
            )
            else "normal"
        )
        self.headline.set(
            state
            + " · "
            + value.get("capture_permission", "UNKNOWN")
            + " · "
            + value.get("operational_gate", "UNKNOWN")
            + (" · LISTENER READY (no capture yet)" if listener_ready else "")
        )
        if self.session != value.get("session_id"):
            self.session = value.get("session_id")
            self.history.samples.clear()
        network, research = value.get("network", {}), value.get("research", {})
        eligibility = value.get("flow_eligibility", {})
        self.history.observe({"network": network, "queue_backlog": network.get("queue_backlog")})
        self.traffic.source = value.get("input_origin", "UNKNOWN")
        self.traffic.redraw()
        model_metrics = research.get("model_metrics", {})
        counts = {p: m["successful"] for p, m in model_metrics.items() if p in ("quality", "edge")}
        self.counts.update_counts(counts if model_metrics else None)

        def known(v):
            return "UNKNOWN" if v is None else str(v)

        self.metrics.set(
            f"Packets {known(network.get('packets_collected'))} · "
            f"Flows {known(network.get('flow_records'))} · "
            f"Flows/min {known(network.get('flows_per_minute'))} · "
            f"Drops {known(network.get('capture_drops'))} · "
            f"Gaps {known(network.get('gap_count'))} · "
            f"Queue {known(network.get('queue_backlog'))}\n"
            + f"Eligible (timeout only) {known(eligibility.get('eligible'))} · "
            + f"Excluded {known(eligibility.get('rejected'))} · "
            + f"Pending {known(eligibility.get('pending'))} · "
            + f"Finalization {known(network.get('finalization'))}\n"
            + " · ".join(
                f"{p}: {m['state']} / confirmed {m['successful']} / unknown {m['unknown']}"
                for p, m in model_metrics.items()
                if p != "dns"
            )
            + "\nAudit "
            + research.get("audit_integrity", "UNKNOWN")
            + " · Last error "
            + (value.get("last_error") or "NONE_RECORDED")
            + " · RESEARCH_ONLY / uncalibrated score / WRITE_DENIED"
        )
        records = research.get("records", [])
        self.app.current_records = records
        self.app._rows(
            [
                (
                    r.get("profile", "UNKNOWN"),
                    (r.get("receipt") or {}).get("origin", "UNKNOWN"),
                    (r.get("receipt") or {}).get("score", "UNKNOWN"),
                    (r.get("receipt") or {}).get("prediction", "UNKNOWN"),
                    (r.get("investigation") or {}).get("status", r.get("status", "UNKNOWN")),
                )
                for r in records
            ]
        )

    def show_record(self, record=None, *, mode="investigation"):
        record = record or self.app.selected_result
        self.app.show_detail(
            {
                "research_view": mode,
                "research_record": record,
                "audit_integrity": self.last_snapshot.get("research", {}).get(
                    "audit_integrity", "UNKNOWN"
                ),
            }
        )

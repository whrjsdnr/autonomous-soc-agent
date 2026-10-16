"""Tk research presentation. All inference/IO remains in the existing worker loop."""

import tkinter as tk
from tkinter import ttk

from soc_agent.gui.charts import Distribution
from soc_agent.gui.components import Button, Label
from soc_agent.gui.typography import text


class ReplayChart(tk.Canvas):
    def __init__(self, parent):
        super().__init__(parent, bg="#17243A", height=210, highlightthickness=0)
        self.rows = []
        self.bind("<Configure>", lambda _: self.redraw())

    def update_records(self, records):
        seen = set()
        self.rows = None if records is None else []
        for item in records or []:
            receipt = item.get("receipt")
            if receipt and receipt["profile"] != "dns" and receipt["flow_id"] not in seen:
                seen.add(receipt["flow_id"])
                self.rows.append(receipt)
        self.redraw()

    def redraw(self):
        self.delete("all")
        self.text_images = []
        width = max(300, self.winfo_width())
        text(
            self,
            16,
            20,
            "OFFLINE FLOW TREND • observed packets per replay flow",
            size=13,
            width=width - 32,
        )
        if not self.rows:
            text(
                self,
                16,
                90,
                "UNKNOWN • source unavailable"
                if self.rows is None
                else "NO_DATA • run an explicit offline demo",
                size=13,
                width=width - 32,
            )
            return
        self.create_line(48, 163, width - 28, 163, fill="#20314A")
        highest = max(r["packet_count"] for r in self.rows) or 1
        for i, row in enumerate(self.rows):
            x = 60 + (width - 130) * i / max(1, len(self.rows) - 1)
            y = 163 - 85 * row["packet_count"] / highest
            self.create_oval(
                x - 4, y - 4, x + 4, y + 4, fill="#38BDF8", outline="", tags="replay-point"
            )
            text(self, x, y - 14, str(row["packet_count"]), size=12, anchor="center", width=70)
            text(
                self,
                x,
                187,
                "Flow " + str(row["flow_index"] + 1),
                size=11,
                anchor="center",
                width=95,
            )
            if i:
                previous = self.rows[i - 1]
                px = 60 + (width - 130) * (i - 1) / max(1, len(self.rows) - 1)
                py = 163 - 85 * previous["packet_count"] / highest
                self.create_line(px, py, x, y, fill="#38BDF8", width=2)


class ResearchView:
    def __init__(self, app):
        self.app = app
        style = ttk.Style(app.root)
        style.configure(
            "Research.TCombobox", fieldbackground="#17243A", foreground="#F1F5F9", padding=8
        )
        style.map(
            "Research.TCombobox",
            fieldbackground=[("disabled", "#111C2E"), ("readonly", "#20314A")],
            foreground=[("disabled", "#64748B"), ("readonly", "#F1F5F9")],
            selectbackground=[("readonly", "#20314A")],
            selectforeground=[("readonly", "#F1F5F9")],
        )
        self.polling = False
        self.last_snapshot = {}
        self.detail_mode = "investigation"
        self.profile = tk.StringVar(value="both")
        self.flow = tk.StringVar(value="1")
        self.choices = {
            "Network · Quality + Edge": "both",
            "Network · Quality": "quality",
            "Network · Edge": "edge",
            "DNS · Security": "dns",
        }
        self.selection = tk.StringVar(value="Network · Quality + Edge")
        self.headline = tk.StringVar(value="Checking current environment…")
        self.model_state = tk.StringVar(value="UNKNOWN")
        self.health = tk.StringVar(value="Runtime UNKNOWN · Audit UNKNOWN")
        self.cards = tk.StringVar(value="UNKNOWN · no confirmed measurements yet")
        self.progress = tk.StringVar(value="STOPPED · explicit user action required")
        self.investigation = tk.StringVar(value="NO_DATA · no stored investigation")
        self.origin = tk.StringVar(
            value="OFFLINE_PCAP · preselected verified training flows · RESEARCH_ONLY"
        )
        self.warning = Label(app.content, text="Research workspace", size=22, bold=True)
        self.warning.pack(anchor="w", pady=(0, 4))
        Label(
            app.content,
            text="Offline evidence → native model → advisory → READ-only investigation",
            size=12,
            fg="#94A3B8",
        ).pack(anchor="w", pady=(0, 14))
        controls = tk.Frame(app.content, bg="#17243A", padx=14, pady=14)
        controls.pack(fill="x", pady=(0, 12))
        row = tk.Frame(controls, bg="#17243A")
        row.pack(fill="x")
        Label(row, text="Model", bg="#17243A", size=12).pack(side="left", padx=(0, 8))
        self.profile_box = ttk.Combobox(
            row,
            textvariable=self.selection,
            values=tuple(self.choices),
            state="readonly",
            style="Research.TCombobox",
            width=27,
        )
        self.profile_box.pack(side="left", padx=(0, 12))
        self.profile_box.bind("<<ComboboxSelected>>", lambda _: self.choose_model())
        Label(row, text="Input", bg="#17243A", size=12).pack(side="left", padx=(0, 6))
        self.input_box = ttk.Combobox(
            row,
            textvariable=self.flow,
            values=("1", "2", "3", "4"),
            state="readonly",
            style="Research.TCombobox",
            width=4,
        )
        self.input_box.pack(side="left", padx=(0, 12))
        self.replay_button = Button(
            row, text="Run Demo", command=self.replay, style="Accent.TButton"
        )
        self.replay_button.pack(side="left", padx=(0, 8))
        self.replay_button.configure(state="disabled")
        self.start_button = Button(row, text="Prepare / Restart", command=self.start)
        self.start_button.pack(side="left", padx=(0, 8))
        self.stop_button = Button(row, text="Stop research", command=self.stop)
        self.stop_button.pack(side="left")
        Label(controls, textvariable=self.origin, size=12, fg="#A78BFA", bg="#17243A").pack(
            fill="x", pady=(12, 0)
        )
        Label(app.content, textvariable=self.progress, size=13, fg="#38BDF8").pack(
            fill="x", pady=(0, 5)
        )
        Label(app.content, textvariable=self.headline, size=11, fg="#94A3B8").pack(
            fill="x", pady=(0, 5)
        )
        Label(app.content, textvariable=self.cards, size=16, bold=True).pack(fill="x", pady=(0, 12))
        charts = ttk.Frame(app.content)
        charts.pack(fill="x", pady=(0, 14))
        self.trend = ReplayChart(charts)
        self.trend.pack(side="left", fill="both", expand=True, padx=(0, 10))
        from soc_agent.gui.unified import MeasuredSeries

        self.dns_chart = MeasuredSeries(charts, "DNS SCORE · FIXTURE / UNCALIBRATED")
        self.dns_chart.pack(side="left", fill="both", expand=True)
        Label(app.content, text="Advisory results", size=19, bold=True).pack(
            anchor="w", pady=(0, 8)
        )
        app._table(("model", "source", "score", "threshold", "prediction", "investigation"))
        buttons = ttk.Frame(app.detail_parent)
        buttons.pack(before=app.summary_frame, fill="x", pady=(4, 6))
        Button(
            buttons, text="Investigation", command=lambda: self.show_record(mode="investigation")
        ).pack(side="left", padx=(0, 8))
        Button(
            buttons, text="Audit / receipt", command=lambda: self.show_record(mode="audit")
        ).pack(side="left")
        Label(
            buttons,
            text="READ-only · source-bound · no operational promotion",
            size=11,
            fg="#94A3B8",
        ).pack(side="right")
        extras = ttk.Frame(app.content)
        extras.pack(fill="x", pady=(14, 0))
        self.count_chart = Distribution(extras, "CONFIRMED NATIVE INVOCATIONS")
        self.count_chart.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self.scores = Distribution(extras, "SCORE BINS · separate model thresholds")
        self.scores.pack(side="left", fill="both", expand=True)

    def choose_model(self):
        self.profile.set(self.choices[self.selection.get()])
        self.profile_changed()

    def show_record(self, record=None, *, mode=None):
        if mode:
            self.detail_mode = mode
        if record is None:
            record = self.app.selected_result
        if not isinstance(record, dict) or not record.get("receipt"):
            rows = [r for r in self.last_snapshot.get("records", []) if r.get("receipt")]
            record = rows[-1] if rows else None
        self.app.show_detail(
            {
                "research_view": self.detail_mode,
                "research_record": record,
                "audit_integrity": self.last_snapshot.get("audit_integrity", "UNKNOWN"),
            }
        )

    def profile_changed(self):
        name = next((k for k, v in self.choices.items() if v == self.profile.get()), None)
        if name:
            self.selection.set(name)
        self.origin.set(
            "FIXTURE · precomputed DNS9 · producer parity UNVERIFIED · RESEARCH_ONLY"
            if self.profile.get() == "dns"
            else "OFFLINE_PCAP · preselected verified training flows · RESEARCH_ONLY"
        )
        values = ("1", "2") if self.profile.get() == "dns" else ("1", "2", "3", "4")
        self.input_box.configure(values=values)
        if self.flow.get() not in values:
            self.flow.set("1")
        if hasattr(self, "last_snapshot"):
            self.render(self.last_snapshot)

    def start(self):
        if self.app.busy or self.app.closing:
            return
        self.set_busy()
        self.progress.set("START REQUESTED • no inference yet")
        self.app.call(
            "research_start",
            "dns" if self.profile.get() == "dns" else "quality",
            callback=self.render,
        )

    def operation(self, name):
        self.progress.set("WORKING • " + name + " • bounded request, no automatic retry")
        self.app.call(name, callback=self.render)

    def set_busy(self):
        self.start_button.configure(state="disabled")
        self.replay_button.configure(state="disabled")
        self.profile_box.configure(state="disabled")
        self.input_box.configure(state="disabled")

    def replay(self):
        if self.app.busy or self.app.closing:
            return
        profile, index = self.profile.get(), int(self.flow.get()) - 1
        self.set_busy()

        def run():
            self.set_busy()
            self.progress.set("RUNNING · native model → advisory → READ-only investigation")
            self.app.call("research_replay", profile, index, callback=self.render)
            if not self.polling:
                self.polling = True
                self.app.root.after(200, self.poll_work)

        if self.last_snapshot.get("demo_state") == "STOPPED":
            self.progress.set("PREPARING · verifying environment; explicit demo request")

            def prepared(value):
                if (
                    self.app.closing
                    or self.app.page != "Network Research"
                    or not self.warning.winfo_exists()
                ):
                    return
                self.render(value)
                if value.get("demo_state") == "STARTED":
                    run()

            self.app.call(
                "research_start", "dns" if profile == "dns" else "quality", callback=prepared
            )
        else:
            run()

    def poll_work(self):
        if (
            self.app.closing
            or self.app.page != "Network Research"
            or not self.app.busy
            or not self.warning.winfo_exists()
        ):
            self.polling = False
            return
        future = self.app.worker.submit("research_activity")

        def done():
            if self.app.closing:
                return
            if not future.done():
                self.app.root.after(50, done)
            else:
                try:
                    self.last_activity = future.result()
                    if self.app.page == "Network Research" and self.warning.winfo_exists():
                        self.progress.set(
                            "Worker RUNNING: " + str(self.last_activity["active_model"])
                            if self.last_activity["worker_running"]
                            else "WAITING • dispatch / investigation / result commit; "
                            "no active model worker"
                        )
                except (ValueError, OSError):
                    self.show_error("WORKER_STATUS_UNKNOWN")
                if self.app.busy:
                    self.app.root.after(500, self.poll_work)
                else:
                    self.polling = False

        self.app.root.after(50, done)

    def stop(self):
        if not self.app.busy:
            self.operation("research_stop")
            return
        future = self.app.worker.submit("research_stop")
        self.progress.set("STOPPING • cancelling owned research worker; Runtime untouched")

        def finish():
            if not future.done():
                self.app.root.after(50, finish)
            elif self.app.page == "Network Research":
                try:
                    self.render(future.result())
                except (ValueError, OSError):
                    self.show_error("DEMO_STOP_FAILED_UNKNOWN")

        self.app.root.after(50, finish)

    def show_error(self, code):
        self.headline.set(
            "UNKNOWN · " + code + " · check environment, then retry only a new confirmed request"
        )
        self.profile_box.configure(state="readonly")
        self.input_box.configure(state="readonly")
        self.progress.set(
            "UNKNOWN · Refresh to inspect the outcome; previous measurements are retained"
        )

    def render(self, value):
        if self.app.page != "Network Research" or not self.warning.winfo_exists():
            return
        self.last_snapshot = value
        state = value.get("demo_state", "UNKNOWN")
        self.progress.set(
            state
            + " • Network OFFLINE_PCAP / DNS FIXTURE; not live detection"
            + (
                " · Worker RUNNING: " + str(value.get("active_model"))
                if value.get("worker_running")
                else " · no active model worker"
            )
        )
        ready = (value.get("dns", {}) if self.profile.get() == "dns" else value).get(
            "status"
        ) == "READY"
        self.replay_button.configure(
            state="normal"
            if state in ("STARTED", "STOPPED") and ready and not self.app.busy
            else "disabled"
        )
        self.start_button.configure(
            state="normal" if state == "STOPPED" and ready and not self.app.busy else "disabled"
        )
        self.profile_box.configure(state="disabled" if self.app.busy else "readonly")
        self.input_box.configure(state="disabled" if self.app.busy else "readonly")
        if value.get("replay_outcomes"):
            outcomes = value["replay_outcomes"]
            if "UNKNOWN" in outcomes:
                self.progress.set(
                    "UNKNOWN · no retry; review Investigation / Audit before a new request"
                )
            elif all(v == "CACHED_NO_NEW_INFERENCE" for v in outcomes):
                self.progress.set(
                    "RETAINED · no new inference · original receipt and investigation restored"
                )
            else:
                self.progress.set(
                    "COMPLETE · confirmed result received · review Investigation / Audit below"
                )
        self.headline.set(
            "Network environment "
            + value.get("status", "UNKNOWN")
            + " · DNS fixture "
            + value.get("dns", {}).get("status", "UNKNOWN")
            + " · Operational gates BLOCKED"
        )
        runtime = value.get("runtime", {})
        self.health.set(
            "SOC Runtime "
            + str(runtime.get("runtime_state", "UNKNOWN"))
            + " · health "
            + str(runtime.get("health", "UNKNOWN"))
            + " · Queue "
            + str(
                runtime.get("queue_backlog")
                if runtime.get("queue_backlog") is not None
                else "UNKNOWN"
            )
            + " · Research audit "
            + value.get("audit_integrity", "UNKNOWN")
        )
        self.model_state.set(
            "\n".join(
                f"{m['profile'].title()} · {m['model_id']} · Artifact {m['artifact']} · "
                f"threshold {m['threshold']} · RESEARCH_ONLY / operating BLOCKED"
                for m in value.get("models", [])
            )
            or "Quality / Edge artifact status UNKNOWN — preflight failed"
        )
        dns = value.get("dns", {})
        self.model_state.set(
            self.model_state.get()
            + "\nDNS · "
            + dns.get("model_id", "UNKNOWN")
            + " · "
            + dns.get("status", "UNKNOWN")
            + " · FIXTURE_NATIVE_ONLY · producer UNVERIFIED · operating BLOCKED"
        )
        counts = value.get("inference_counts")
        if counts is None:
            self.cards.set("UNKNOWN • research audit/storage failed; counts not replaced with zero")
            self.count_chart.update_counts(None)
            self.trend.update_records(None)
            self.scores.update_counts(None)
            self.dns_chart.update_points(None)
            self.app.current_records = []
            self.app._rows([])
            self.show_record()
            return
        self.cards.set(
            f"Quality {counts['quality']}  ·  Edge {counts['edge']}  ·  "
            f"DNS {value.get('dns_inference_count', 0)} · "
            f"Unique flows {value.get('flow_count', 0)}  ·  "
            f"Errors / UNKNOWN {value.get('errors', 0)}"
        )
        self.count_chart.update_counts({**counts, "dns": value.get("dns_inference_count", 0)})
        records = value.get("records", [])
        self.trend.update_records(records)
        bins = {
            "quality <0.35": 0,
            "quality ≥0.35": 0,
            "edge <0.8": 0,
            "edge ≥0.8": 0,
            "dns <0.5": 0,
            "dns ≥0.5": 0,
        }
        table = []
        for record in records:
            receipt = record.get("receipt")
            if not receipt:
                continue
            suffix = (" <" if receipt["score"] < receipt["threshold"] else " ≥") + str(
                receipt["threshold"]
            )
            bins[receipt["profile"] + suffix] += 1
            table.append(
                (
                    receipt["profile"],
                    receipt["origin"],
                    f"{receipt['score']:.5f}",
                    receipt["threshold"],
                    receipt["prediction"],
                    (record.get("investigation") or {}).get("status", record["status"]),
                )
            )
        self.scores.update_counts(bins)
        self.dns_chart.update_points(
            [
                (r["receipt"]["inferred_at"][11:19], r["receipt"]["score"])
                for r in records
                if r.get("receipt") and r["receipt"]["profile"] == "dns"
            ]
        )
        self.app.current_records = [r for r in records if r.get("receipt")]
        self.app._rows(table)
        if records:
            last = records[-1]
            inv = last.get("investigation") or {}
            receipt = last.get("receipt") or {}
            stages = [
                e.get("content", {}).get("result", {}).get("current_step", "")
                for e in inv.get("timeline", {}).get("entries", [])
            ]
            self.investigation.set(
                "Latest: "
                + receipt.get("profile", "UNKNOWN")
                + " · "
                + inv.get("status", last["status"])
                + " · "
                + str(last.get("error") or "No worker error")
                + " · inferred "
                + receipt.get("inferred_at", "UNKNOWN")
                + "\nEvidence references: "
                + ", ".join(inv.get("evidence_references", []))
                + "\nSCRIPTED assessment; model score is not an observed fact. "
                + " → ".join(str(v) for v in stages if v)
            )
        self.show_record()

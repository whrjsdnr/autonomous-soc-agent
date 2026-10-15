"""Tk research presentation. All inference/IO remains in the existing worker loop."""

import tkinter as tk
from tkinter import ttk

from soc_agent.gui.charts import Distribution
from soc_agent.gui.components import Button, Label
from soc_agent.gui.typography import text


class ReplayChart(tk.Canvas):
    def __init__(self, parent):
        super().__init__(parent, bg="#17243A", height=175, highlightthickness=0)
        self.rows = []
        self.bind("<Configure>", lambda _: self.redraw())

    def update_records(self, records):
        seen = set()
        self.rows = []
        for item in records:
            receipt = item.get("receipt")
            if receipt and receipt["flow_id"] not in seen:
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
                "NO_DATA • Start demo, then run an offline replay",
                size=13,
                width=width - 32,
            )
            return
        highest = max(r["packet_count"] for r in self.rows)
        for i, row in enumerate(self.rows):
            x = 60 + (width - 130) * i / max(1, len(self.rows) - 1)
            y = 130 - 70 * row["packet_count"] / highest
            self.create_oval(
                x - 4, y - 4, x + 4, y + 4, fill="#38BDF8", outline="", tags="replay-point"
            )
            text(self, x, y - 14, str(row["packet_count"]), size=12, anchor="center", width=70)
            text(
                self,
                x,
                151,
                "Flow " + str(row["flow_index"] + 1),
                size=11,
                anchor="center",
                width=95,
            )
            if i:
                previous = self.rows[i - 1]
                px = 60 + (width - 130) * (i - 1) / max(1, len(self.rows) - 1)
                py = 130 - 70 * previous["packet_count"] / highest
                self.create_line(px, py, x, y, fill="#38BDF8", width=2)


class ResearchView:
    def __init__(self, app):
        self.app = app
        style = ttk.Style(app.root)
        style.map(
            "Research.TCombobox",
            fieldbackground=[("readonly", "#17243A")],
            foreground=[("readonly", "#F1F5F9")],
            selectbackground=[("readonly", "#20314A")],
            selectforeground=[("readonly", "#F1F5F9")],
        )
        self.profile = tk.StringVar(value="both")
        self.flow = tk.StringVar(value="1")
        self.headline = tk.StringVar(
            value="Checking research models… Operating inference remains BLOCKED"
        )
        self.model_state = tk.StringVar(value="Quality / Edge artifact verification pending")
        self.health = tk.StringVar(value="Runtime health UNKNOWN • Queue UNKNOWN")
        self.cards = tk.StringVar(value="Confirmed inference counts: Quality 0 · Edge 0")
        self.progress = tk.StringVar(value="STOPPED • no automatic inference")
        self.investigation = tk.StringVar(value="No offline investigation stored")
        self.warning = Label(
            app.content,
            text="RESEARCH ONLY · OFFLINE PCAP · UNCERTAINTY UNKNOWN · WRITE_DENIED",
            size=17,
            fg="#F59E0B",
            bold=True,
            max_width=1250,
        )
        self.warning.pack(fill="x", pady=(0, 10))
        Label(app.content, textvariable=self.headline, size=14, max_width=1250).pack(
            fill="x", pady=(0, 5)
        )
        Label(app.content, textvariable=self.health, size=12, max_width=1250).pack(
            fill="x", pady=(0, 8)
        )
        Label(app.content, textvariable=self.model_state, size=12, max_width=1250).pack(
            fill="x", pady=(0, 8)
        )
        controls = ttk.Frame(app.content)
        controls.pack(fill="x", pady=(0, 10))
        self.start_button = Button(
            controls, text="Start Research Demo", command=lambda: self.operation("research_start")
        )
        self.start_button.pack(side="left", padx=(0, 8))
        ttk.Combobox(
            controls,
            textvariable=self.profile,
            values=("both", "quality", "edge"),
            state="readonly",
            style="Research.TCombobox",
            width=10,
        ).pack(side="left", padx=5)
        Label(controls, text="Flow", size=12).pack(side="left")
        ttk.Combobox(
            controls, textvariable=self.flow, values=("1", "2", "3", "4"), state="readonly", width=4
        ).pack(side="left", padx=5)
        self.replay_button = Button(controls, text="Run Offline Replay", command=self.replay)
        self.replay_button.pack(side="left", padx=8)
        self.replay_button.configure(state="disabled")
        self.stop_button = Button(controls, text="Stop Demo", command=self.stop)
        self.stop_button.pack(side="left")
        Label(app.content, textvariable=self.progress, size=12, max_width=1250).pack(
            fill="x", pady=(0, 8)
        )
        Label(app.content, textvariable=self.cards, size=18, bold=True, max_width=1250).pack(
            fill="x", pady=(0, 10)
        )
        self.trend = ReplayChart(app.content)
        self.trend.pack(fill="x", pady=(0, 10))
        charts = ttk.Frame(app.content)
        charts.pack(fill="x", pady=(0, 12))
        self.count_chart = Distribution(charts, "REAL RESEARCH INFERENCE COUNT")
        self.count_chart.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.scores = Distribution(charts, "UNCALIBRATED SCORES • no probability fusion")
        self.scores.pack(side="left", fill="x", expand=True)
        Label(app.content, textvariable=self.investigation, size=12, max_width=1250).pack(
            fill="x", pady=(0, 10)
        )
        app._table(("model", "source", "score", "threshold", "prediction", "investigation"))

    def operation(self, name):
        self.progress.set("WORKING • " + name + " • bounded request, no automatic retry")
        self.app.call(name, callback=self.render)

    def replay(self):
        self.progress.set("RUNNING • selected model → advisory → READ-only investigation")
        self.app.call(
            "research_replay", self.profile.get(), int(self.flow.get()) - 1, callback=self.render
        )

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
        self.headline.set("UNKNOWN • " + code + " • check artifact/environment; no automatic retry")
        self.progress.set("BLOCKED • previous measurements retained")

    def render(self, value):
        if self.app.page != "Network Research" or not self.warning.winfo_exists():
            return
        self.last_snapshot = value
        state = value.get("demo_state", "UNKNOWN")
        self.progress.set(state + " • OFFLINE_PCAP train-session replay; not live Linux detection")
        self.replay_button.configure(
            state="normal" if state == "STARTED" and value.get("status") == "READY" else "disabled"
        )
        self.start_button.configure(
            state="normal" if state == "STOPPED" and value.get("status") == "READY" else "disabled"
        )
        if value.get("replay_outcomes"):
            self.progress.set(self.progress.get() + " · " + " / ".join(value["replay_outcomes"]))
        self.headline.set(
            "Research environment "
            + value.get("status", "UNKNOWN")
            + " · Producer 1.1.0 / Network14 · Operational gate BLOCKED"
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
        counts = value.get("inference_counts")
        if counts is None:
            self.cards.set("UNKNOWN • research audit/storage failed; counts not replaced with zero")
            self.count_chart.update_counts(None)
            return
        self.cards.set(
            f"Quality {counts['quality']}  ·  Edge {counts['edge']}  ·  "
            f"Unique flows {value.get('flow_count', 0)}  ·  "
            f"Errors / UNKNOWN {value.get('errors', 0)}"
        )
        self.count_chart.update_counts(counts)
        records = value.get("records", [])
        self.trend.update_records(records)
        bins = {"quality <0.35": 0, "quality ≥0.35": 0, "edge <0.8": 0, "edge ≥0.8": 0}
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
        self.app.show_detail(value)

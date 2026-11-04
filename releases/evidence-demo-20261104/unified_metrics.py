"""Presentation-only graph inputs. Never stored as incident evidence or model receipts.

Historical series and user-authorized synthetic telemetry are distinct in this
module and the delivery data map. The presenter requested no MOCK badges in GUI.
"""

import math
from dataclasses import dataclass
from types import SimpleNamespace


@dataclass(frozen=True)
class Point:
    at: float
    values: dict[str, float]


def demo_telemetry() -> tuple[Point, ...]:
    """Deterministic cosmetic measurements for unavailable historical time series."""
    return tuple(
        Point(
            float(i),
            {
                "cpu": round(14 + 7 * math.sin(i / 6) + 3 * math.sin(i / 2), 2),
                "rss": round(190 + i * 0.55 + 4 * math.sin(i / 7), 2),
                "queue": float(max(0, round(2 + 2 * math.sin(i / 5)))),
                "transport_queue": float(max(0, round(1 + math.sin(i / 4)))),
                "drops": 0.0,
                "gaps": 0.0,
                "observation_tokens": round(160 + 25 * math.sin(i / 8), 2),
                "analysis_tokens": round(32 + 8 * math.sin(i / 7), 2),
                "tokens": round(80 + 12 * math.sin(i / 9), 2),
            },
        )
        for i in range(60)
    )


def history(points):
    return SimpleNamespace(samples=points)


def presentation_queue(packets: int, receipts: int) -> int:
    """Display-only arrivals minus displayed completions, bounded to eight receipts."""
    arrivals = min(8, (packets + 3) // 6)
    return max(0, arrivals - receipts)


def plot(chart, snapshot, points, *, title=None, series=None, units=None):
    if title:
        chart.title = title
    if series:
        chart.series = series
    if units:
        chart.units = units
    chart.mode = "metrics"
    chart.marker = None
    chart.update_data(snapshot | {"state": "REPLAY"}, history(points))


def apply(app):
    """Connect existing chart objects without changing the frozen GUI implementation."""
    snapshot = app.snapshot
    source = app.active_source
    continuous = snapshot.get("continuous", {})
    metrics = continuous.get("metrics", {})
    if app.page == "Dashboard":
        if continuous:
            app.status_cards["Network"].update_value(
                f"{metrics['packets']} packets", "Packets collected"
            )
            dns = continuous["dns"]["counts"]
            app.status_cards["DNS diagnostics"].update_value(
                f"{dns.get('MATCHED_RESPONSE', 0)} responses",
                f"{dns.get('QUERY', 0)} queries · retained metadata",
            )
            resources = continuous["resources"]
            app.status_cards["Memory / CPU"].update_value(
                f"{resources['peak_rss_bytes'] / 1024**2:.1f} MiB peak",
                f"Runtime cumulative CPU {resources['cpu_seconds']:.2f}s",
            )
            app.status_cards["Authentication"].update_value(
                "1 IF receipt", "Separate trial · Authentication stage"
            )
            for name, profile in (("Quality RF", "quality"), ("Edge LR", "edge")):
                count = snapshot["research"]["model_metrics"][profile]["successful"]
                app.status_cards[name].update_value(
                    f"{count} receipts", "Verified retained inference"
                )
            if source == "native":
                flows = app.evidence.flows
                total = 0
                points = []
                for i, flow in enumerate(flows):
                    total += flow["packet_count"]
                    points.append(Point(float(i + 1), {"packets": float(total)}))
                plot(
                    app.dashboard_charts[0],
                    snapshot,
                    points,
                    title="NETWORK · RETAINED FLOW PACKETS",
                    series=(("packets", "Packets"),),
                    units="cumulative packets by flow completion order · 7 retained flows",
                )
            else:
                plot(
                    app.dashboard_charts[0],
                    snapshot,
                    [Point(0, {"packets": float(metrics["packets"])})],
                    title="NETWORK · RETAINED PCAP PACKETS",
                    series=(("packets", "Packets"),),
                    units="historical final count · independent PCAP trial",
                )
            queries = responses = 0
            dns_points = []
            for i, event in enumerate(
                sorted(continuous["dns"]["recent_events"], key=lambda r: r["event_ns"])
            ):
                if event["status"] not in ("QUERY", "MATCHED_RESPONSE"):
                    continue
                queries += event["status"] == "QUERY"
                responses += event["status"] == "MATCHED_RESPONSE"
                dns_points.append(
                    Point(float(i), {"queries": float(queries), "responses": float(responses)})
                )
            if not dns_points:
                dns_points = [
                    Point(
                        0,
                        {
                            "queries": float(dns.get("QUERY", 0)),
                            "responses": float(dns.get("MATCHED_RESPONSE", 0)),
                        },
                    )
                ]
            plot(
                app.dashboard_charts[1],
                snapshot,
                dns_points,
                title="DNS · RETAINED EVENTS",
                series=(("queries", "Queries"), ("responses", "Responses")),
                units="cumulative counts in recorded event order · DNS9 separate",
            )
            tasks = continuous["orchestration"]["tasks"]
            levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            assessments = []
            for i, task in enumerate(tasks):
                inv = task.get("investigation") or {}
                severity = inv.get("assessment", {}).get("threat_assessment", {}).get("severity")
                if severity in levels:
                    assessments.append(Point(float(i), {"severity": float(levels[severity])}))
            plot(
                app.dashboard_charts[4],
                snapshot,
                assessments,
                title="RESEARCH ASSESSMENT · TASKS",
                series=(("severity", "Severity"),),
                units="ordinal 0=Info … 4=Critical · one recorded assessment per Task",
            )
            steps = next(
                (
                    (t.get("investigation") or {}).get("plan", {}).get("steps", [])
                    for t in tasks
                    if t.get("investigation")
                ),
                [],
            )
            completed = 0
            progress = []
            for i, step in enumerate(steps):
                completed += step["status"] == "completed"
                progress.append(Point(float(i + 1), {"progress": float(completed)}))
            plot(
                app.dashboard_charts[5],
                snapshot,
                progress,
                title="INVESTIGATION · FIRST RECORDED TASK",
                series=(("progress", "Completed tools"),),
                units="actual completed tool count",
            )
    elif app.page == "Investigation":
        records = snapshot.get("research", {}).get("records", [])
        if records:
            steps = (records[-1].get("investigation") or {}).get("plan", {}).get("steps", [])
            count = 0
            points = []
            for i, step in enumerate(steps):
                count += step.get("status") == "completed"
                points.append(Point(float(i + 1), {"progress": float(count)}))
            plot(
                app.event_charts[0],
                snapshot,
                points,
                title="READ-ONLY INVESTIGATION · COMPLETED TOOLS",
                series=(("progress", "Completed tools"),),
                units="recorded plan steps; no percentage",
            )
    elif app.page == "System":
        # These are presentation telemetry only. Original queues, counters and source
        # status are untouched and remain available in the existing detail panel.
        app.system_cards["Monitoring"].update_value("Results loaded", "Read-only view")
        app.system_cards["Helper approval"].update_value("Read only", "No capture or execution")
        app.system_cards["Recovery"].update_value("Retained", "Original data available")
        points = demo_telemetry()
        for chart in app.health_charts:
            plot(chart, {"input_origin": "Telemetry", "session_id": "display"}, points)


def animate(app):
    """Reveal retained results on a presentation clock without modifying snapshots.

    Packet totals are paced, not new measured arrivals. Only the 14 stored packet
    samples are used for packet rows; never fabricate missing packet headers.
    """
    from unified_evidence import STAGES, model_revealed_count, revealed_count

    if not app.snapshot:
        return
    if (
        app.page in ("Dashboard", "Investigation")
        and hasattr(app, "llm_feed")
        and app.llm_feed.winfo_exists()
    ):
        body = llm_body(app)
        app._text(app.llm_feed, body)
        # Keep the newly revealed Plan / Tool / Assessment visible in the small panel.
        app.llm_feed.see("end")

    def count(total, stage):
        if not app.presentation_animated:
            return total
        if stage == 2:
            return total * model_revealed_count(app.clock) // 8
        if stage == 6:
            elapsed = sum(s.seconds for s in STAGES[: app.clock.index + 1]) - app.clock.remaining
            return min(total, max(0, int(total * elapsed / 20)))
        if stage == 1 and app.clock.index == 0:
            elapsed = STAGES[0].seconds - app.clock.remaining
            return min(total, max(0, int(total * (elapsed - 2) / 23)))
        return revealed_count(total, stage, app.clock)

    state = "완료" if app.clock.finished else "실행 중" if app.clock.playing else "일시정지"
    index = app.clock.index
    elapsed = STAGES[index].seconds - app.clock.remaining
    if app.page == "System":
        app.system_cards["Monitoring"].update_value(state, "")
        points = demo_telemetry()
        if app.presentation_animated:
            total = sum(s.seconds for s in STAGES[:index]) + elapsed
            points = points[: max(1, min(len(points), int(total) + 1))]
        for chart in app.health_charts:
            plot(chart, {"input_origin": "Telemetry", "session_id": "display"}, points)
    if app.page == "Dashboard" and app.active_source == "native":
        packets = count(54, 0)
        queries = responses = 0
        events = sorted(
            (
                e
                for e in app.evidence.native["continuous"]["dns"]["recent_events"]
                if e["status"] in ("QUERY", "MATCHED_RESPONSE")
            ),
            key=lambda e: e["event_ns"],
        )
        visible_dns = events[: count(len(events), 0)]
        dns_points = [Point(0, {"queries": 0, "responses": 0})]
        for i, event in enumerate(visible_dns, 1):
            queries += event["status"] == "QUERY"
            responses += event["status"] == "MATCHED_RESPONSE"
            dns_points.append(Point(float(i), {"queries": queries, "responses": responses}))
        app.status_cards["Network"].update_value(f"{packets} packets", state)
        app.status_cards["DNS diagnostics"].update_value(
            f"{responses} responses", f"{queries} queries · {state}"
        )
        app.status_cards["Capture integrity"].update_value(
            "Verified" if count(5, 1) else "Window open", "Window seal → Eligibility"
        )
        visible_records = app.snapshot["research"]["records"][: count(8, 2)]
        for name, profile in (("Quality RF", "quality"), ("Edge LR", "edge")):
            receipts = sum(r["receipt"]["profile"] == profile for r in visible_records)
            app.status_cards[name].update_value(f"{receipts} receipts", "Network14")
        app.status_cards["Authentication"].update_value(
            f"{count(1, 6)} IF receipt",
            f"{count(42, 6)} inputs · " + ("score 0.9667" if count(1, 6) else "Window → IF"),
        )
        queue = presentation_queue(packets, count(8, 2)) if app.presentation_animated else 0
        app.status_cards["Queue backlog"].update_value(queue, "Pending inputs → model receipts")
        plot(
            app.dashboard_charts[0],
            app.snapshot,
            [Point(float(i), {"packets": float(i)}) for i in range(packets + 1)],
            title="NETWORK · PACKETS",
            series=(("packets", "Packets"),),
            units="packets · presentation timeline",
        )
        plot(
            app.dashboard_charts[1],
            app.snapshot,
            dns_points,
            title="DNS · EVENTS",
            series=(("queries", "Queries"), ("responses", "Responses")),
            units="queries / responses · event order",
        )
        if count(8, 2) == 0:
            for chart, series in (
                (app.dashboard_charts[2], (("quality", "Quality RF"), ("edge", "Edge LR"))),
                (app.dashboard_charts[3], (("latency", "Worker latency"),)),
            ):
                plot(
                    chart,
                    app.snapshot,
                    [Point(0, {name: 0 for name, _ in series})],
                    series=series,
                    units="Waiting for Network14",
                )
        else:
            for chart in app.dashboard_charts[2:4]:
                chart.mode = "records"
                chart.update_data(
                    app.snapshot | {"research": {"records": visible_records}}, app.visual_history
                )
        if count(5, 4) == 0:
            for chart, key in (
                (app.dashboard_charts[4], "severity"),
                (app.dashboard_charts[5], "progress"),
            ):
                plot(chart, app.snapshot, [Point(0, {key: 0})], units="Waiting for investigation")
        app.capture_summary.configure(
            text=f"Packets {packets} · DNS {queries} queries / {responses} responses · "
            f"Eligible {count(5, 1)} · Predictions {count(8, 2)}"
        )
        app.collector_summary.configure(text=f"모니터링 · {state}")
        app.continuous_overview.configure(
            text=f"Window → Network14 → Incident → Investigation · "
            f"Incidents {count(2, 3)} · Tasks {count(5, 4)}"
        )
        app.observability_label.configure(
            text=f"Packet {packets} · DNS {queries + responses} · "
            f"RF/LR {count(8, 2)} · Investigation {count(5, 4)}"
        )
        if hasattr(app, "packet_feed") and app.packet_feed.winfo_exists():
            samples = [p for f in app.evidence.flows for p in f["packets"]]
            visible = samples[: count(len(samples), 0)]
            rows = [
                f"{p['protocol'].upper():4}  {p['source']}:{p['source_port']} → "
                f"{p['destination']}:{p['destination_port']}   {p['ip_length']} bytes"
                for p in visible[-3:]
            ]
            rows += [
                f"DNS   {e['status']}   query {e['query_digest'][:12]}" for e in visible_dns[-2:]
            ]
            app._text(app.packet_feed, "\n".join(rows) or "Packet · DNS 채널 준비 중…")
    if app.page == "Continuous" and app.active_source == "native" and index < 7:
        for tree, stage, total in ((app.continuous_incidents, 3, 2), (app.continuous_tasks, 4, 5)):
            children = tree.get_children()
            for child in children[count(total, stage) :]:
                tree.delete(child)
        app.continuous_summary.configure(
            text=f"모니터링 · {state}\n"
            f"Packets 54 · Window {'VERIFIED' if count(1, 1) else 'SEALING'} · "
            f"Eligible {count(5, 1)} / Incomplete {count(2, 1)}\n"
            f"Predictions {count(8, 2)} · Incidents {count(2, 3)} · Tasks {count(5, 4)}"
        )
    if app.page == "AI Analysis":
        tree = app.analysis_predictions
        children = tree.get_children()
        phase = (
            2
            if app.active_source == "native"
            else 6
            if app.active_source == "authentication_if"
            else 5
        )
        total = len(app.snapshot["analysis"]["result"]["predictions"])
        visible = count(total, phase) if app.active_source == "native" or index == phase else total
        for child in children[visible:]:
            tree.delete(child)
        if app.active_source == "native":
            app._text(
                app.analysis_incident,
                f"Network14 · RF / LR\n\nPrediction {count(total, phase)} / {total}\n"
                "Feature window → Model receipt → Incident",
            )
        if app.active_source == "api":
            full = app.analysis_investigation.get("1.0", "end")
            if app.presentation_animated and index == 5:
                if elapsed < 12:
                    full = "PLAN\n조사 계획을 구성하고 있습니다…"
                elif elapsed < 28:
                    full = full.split("\n\nTOOLS")[0]
                elif elapsed < 43:
                    full = full.split("\n\nASSESSMENT")[0]
                app._text(app.analysis_investigation, full)
        elif app.active_source == "authentication_if" and index == 6 and count(1, 6) == 0:
            app._text(
                app.analysis_incident,
                f"Authentication events  {count(42, 6)} / 42\n\n"
                "Window → Isolation Forest → Assessment",
            )


def llm_body(app) -> str:
    """Reveal the independent actual API trial; no provider calls or joined incidents."""
    from unified_evidence import STAGES

    elapsed = sum(s.seconds for s in STAGES[: app.clock.index + 1]) - app.clock.remaining
    if not app.presentation_animated:
        elapsed = 300
    report = app.evidence.api
    investigation = report["investigation_detail"]
    plan = investigation["plan"]
    assessment = investigation["assessment"]["threat_assessment"]
    title = "LLM · REAL_API · 2026-10-27 · separate trial\n"
    if elapsed < 24:
        return title + "\n모델 결과 대기 → Plan → Tool → Assessment"
    if getattr(app, "page", "") == "Dashboard":
        body = title + "PLAN · " + plan["goal"][:90] + "…\n"
        if elapsed >= 34:
            body += (
                "\n".join(
                    f"TOOL · {step['tool_name']} · {step['status']}" for step in plan["steps"]
                )
                + "\n"
            )
        if elapsed >= 48:
            body += (
                f"ASSESSMENT · {assessment['severity']} / {assessment['confidence']}\n"
                + assessment["summary"][:120]
                + "…"
            )
        return body
    body = title + "\nPLAN\n" + plan["goal"] + "\n"
    if elapsed >= 34:
        body += "\nTOOLS\n" + "\n".join(
            f"{step['tool_name']} · {step['status']}" for step in plan["steps"]
        )
    if elapsed >= 48:
        body += (
            f"\n\nASSESSMENT · {assessment['severity']} / "
            f"{assessment['confidence']}\n{assessment['summary']}"
        )
    return body

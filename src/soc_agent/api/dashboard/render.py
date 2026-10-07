"""Escaped HTML presentation only; no persistence, domain mutation or JavaScript."""

import base64
import hashlib
from html import escape
from importlib.resources import files

from soc_agent.api.dashboard.models import DashboardOverview
from soc_agent.investigation.runtime.models import WorkflowStep
from soc_agent.state.evidence import UTCTimestamp

CSS = files(__package__).joinpath("style.css").read_text(encoding="utf-8")
STYLE_HASH = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
CSP = (
    "default-src 'none'; style-src 'sha256-"
    + STYLE_HASH
    + "'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
)


def e(value: object) -> str:
    return escape(str(value), quote=True)


def identity(value: object) -> str:
    return f'<span class="id" title="{e(value)}">{e(str(value)[:12])}</span>'


def timestamp(value: UTCTimestamp | None) -> str:
    if value is None:
        return '<span class="muted">—</span>'
    return (
        f'<time datetime="{e(value.isoformat())}">{e(value.strftime("%m-%d %H:%M:%S UTC"))}</time>'
    )


def badge(value: object) -> str:
    return f'<span class="badge">{e(value)}</span>'


def empty(message: str) -> str:
    return f'<div class="empty">{e(message)}</div>'


def panel(title: str, body: str, note: str = "") -> str:
    return (
        f'<section class="panel"><div class="panel-head"><h2>{e(title)}</h2>'
        f'<span class="muted">{e(note)}</span></div>{body}</section>'
    )


def render_overview(view: DashboardOverview, refreshed_at: UTCTimestamp) -> str:
    cards = "".join(
        f'<div class="kpi"><div class="label">{label}</div><div class="value">{value}</div>'
        f"<small>{hint}</small></div>"
        for label, value, hint in (
            (
                "ACTIVE INCIDENTS",
                view.active_incident_count,
                "Authorized · status other than closed",
            ),
            (
                "WORKFLOWS IN PROGRESS",
                view.active_workflow_count,
                "Non-terminal checkpoints · includes waiting",
            ),
            (
                "HUMAN ACTION REQUIRED",
                view.human_action_count,
                "Workflow-scoped · not all approval queues",
            ),
            (
                "SECURITY SIGNALS",
                view.security_signal_count,
                "Unique signals in retained Fusion contexts",
            ),
        )
    )
    rows = ""
    for item in view.incidents:
        if item.status == "closed":
            continue
        stage = item.workflow.next_step.value.upper() if item.workflow else "UNKNOWN"
        rows += (
            f'<tr><td><a href="/dashboard/incidents/{e(item.incident_id)}">'
            f"{identity(item.incident_id)}</a></td><td>{badge(item.status.upper())}</td>"
            f"<td>{e(item.severity.upper())}</td><td>{e(stage)}</td>"
            f"<td>{timestamp(item.updated_at)}</td><td><details><summary>Provenance</summary>"
            f"Evidence {item.evidence_count} · Observations {item.observation_count} · "
            f"Hypotheses {item.hypothesis_count}<br>Sources: {e(', '.join(item.sources) or '—')}"
            "</details></td></tr>"
        )
    incident_html = (
        '<div class="table-wrap"><table><thead><tr><th>Incident ID</th><th>Status</th>'
        "<th>State severity</th><th>Next stage</th><th>State updated</th><th>Sources</th>"
        f"</tr></thead><tbody>{rows}</tbody></table></div>"
        if rows
        else empty("No active incidents")
    )
    workflow_html = ""
    for item in view.incidents:
        w = item.workflow
        if not w or w.terminal:
            continue
        stages = ""
        for step in WorkflowStep:
            style = "current" if step == w.current else "next" if step == w.next_step else ""
            annotation = (
                " · LAST" if step == w.current else " · NEXT" if step == w.next_step else ""
            )
            stages += f'<span class="stage {style}">{e(step.value.upper() + annotation)}</span>'
        workflow_html += (
            f'<article class="workflow"><h3>Workflow {identity(w.run_id)}</h3>'
            f'<span class="muted">Incident {identity(item.incident_id)} · '
            f"{timestamp(w.updated_at)}</span>"
            f'<div class="stages">{stages}</div><p class="reason">{e(w.reason)}</p>'
            + (badge("CLAIMED · OUTCOME UNKNOWN") if w.claimed else "")
            + "</article>"
        )
    workflow_html = (
        '<p class="legend">LAST = last recorded step · NEXT = saved cursor. '
        "Other stages are not marked complete.</p>" + workflow_html
        if workflow_html
        else empty("No active workflow")
    )
    human_html = "".join(
        f'<article class="action"><h3>{e(a.category)}</h3><p class="reason">{e(a.reason)}</p>'
        f'<span class="muted">Incident {identity(a.incident_id)} · '
        f"Run {identity(a.run_id)}</span></article>"
        for a in view.human_actions
    ) or empty("No human actions in retained workflows")
    signal_html = (
        '<div class="signals">'
        + "".join(
            f'<article class="signal"><h3>{e(s.domain)}</h3>{badge(s.state)}'
            f'<p class="muted">Confidence: {e(s.confidence)}</p>{timestamp(s.timestamp)}'
            + (
                f"<details><summary>Source / provenance</summary>Incident {identity(s.incident_id)}"
                f"<br>Run {identity(s.run_id)}<br>Artifact {identity(s.reference)}<br>"
                + "<br>".join(e(p) for p in s.provenance)
                + "</details>"
                if s.reference
                else '<p class="muted">No retained signal available</p>'
            )
            + "</article>"
            for s in view.signals
        )
        + '</div><p class="legend">Anomaly rank is not attack probability. '
        "Fusion agreement is not statistical confidence.</p>"
    )
    activity_html = "".join(
        f'<div class="activity">{timestamp(a.timestamp)}<div>{e(a.description)}<br>'
        f'<span class="muted">Incident {identity(a.incident_id)} · '
        f"Ref {identity(a.reference)}</span></div></div>"
        for a in view.recent_activity
    ) or empty("No recent activity")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>SOC Command Center</title>
<style>{CSS}</style></head><body><a class="skip" href="#main">Skip to overview</a>
<header><div><div class="brand">AUTONOMOUS SOC</div><h1>SOC Command Center</h1></div>
<div class="header-meta"><span>SYSTEM {badge(view.system_status)}</span>
<span>Refreshed {timestamp(refreshed_at)}</span>
<a class="refresh" href="/dashboard" aria-label="Refresh overview">↻ Refresh</a></div></header>
<div class="layout"><aside><nav aria-label="Main navigation">
<a href="/dashboard" aria-current="page">Overview</a>
<span aria-disabled="true">Incidents<small>Not available yet</small></span>
<a href="/dashboard/security-ai">Security AI</a>
<span aria-disabled="true">Workflow<small>Not available yet</small></span>
<a href="/dashboard/governance">Human governance</a>
<span aria-disabled="true">Learning<small>Not available yet</small></span></nav>
<p class="aside-note">Human-governed operations<br>Read-only observation surface</p></aside>
<main id="main"><div class="intro"><div><h2>Operations overview</h2>
<p class="muted">{e(view.scope)}</p></div>
<div>{badge(view.posture)}<p class="muted">Workflow posture · not a risk score</p></div></div>
<div class="kpis">{cards}</div>{panel("Active Incidents", incident_html, "Governed state")}
<div class="grid"><div>{panel("Agent Workflow", workflow_html)}</div>
<div>{panel("Human Action Required", human_html, "Read only")}</div></div>
<p><a href="/dashboard/security-ai">Open Security AI Monitoring</a></p>
{panel("Security AI Signals", signal_html, "Model-derived context")}
{panel("Recent Activity", activity_html, "Creation + latest checkpoint · up to 20")}
<footer>UNKNOWN means this snapshot cannot establish the value.
System health has no configured health contract.</footer>
</main></div></body></html>"""

"""Read-only incident presentation. All backend text is escaped, never raw JSON."""

from soc_agent.api.dashboard.incident_models import IncidentDetailView, ReferenceView
from soc_agent.api.dashboard.render import CSS, badge, e, empty, identity, panel, timestamp
from soc_agent.state.evidence import UTCTimestamp


def section(title: str, anchor: str, body: str, note: str = "") -> str:
    return f'<div id="{e(anchor)}">{panel(title, body, note)}</div>'


def references(items: tuple[ReferenceView, ...]) -> str:
    result = []
    for item in items:
        text = f"{e(item.label)} {identity(item.identity)}"
        if item.anchor:
            text = f'<a href="#{e(item.anchor)}">{text}</a>'
        result.append(text)
    return '<span class="refs">' + " · ".join(result) + "</span>" if result else "—"


def statements(items: tuple[str, ...]) -> str:
    return "<ul>" + "".join(f"<li>{e(text)}</li>" for text in items) + "</ul>" if items else "—"


def table(headings: tuple[str, ...], rows: list[str], missing: str) -> str:
    if not rows:
        return empty(missing)
    return (
        '<div class="table-wrap"><table><thead><tr>'
        + "".join(f'<th scope="col">{e(h)}</th>' for h in headings)
        + "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def render_incident(view: IncidentDetailView, refreshed_at: UTCTimestamp) -> str:
    w = view.workflow
    workflow = empty("Workflow NOT AVAILABLE")
    trace_html = empty("Trace NOT AVAILABLE")
    if w:
        workflow = (
            f"<p>Run {identity(w.run_id)} · Revision {w.revision} · Source state revision "
            f'{w.snapshot_revision}</p><div class="detail-stages">'
            + "".join(
                f'<div class="detail-stage"><strong>{e(s.step.value.upper())}</strong>'
                f"{badge(s.status)}</div>"
                for s in w.stages
            )
            + '</div><div class="human-boundary">HUMAN GOVERNANCE BOUNDARY · '
            "Assessment and Decision are advisory. GOVERN does not replace independent "
            "state authorization, response review or Tool Approval.</div>"
            f'<p class="muted">Last recorded: {e(w.current.value.upper())} · '
            f"Saved cursor: {e(w.next_step.value.upper())} · "
            f"Failure field: {e(w.failure or 'NONE RECORDED')}</p>"
            + (
                '<p class="notice">Outstanding claim: outcome UNKNOWN. No automatic retry.</p>'
                if w.claimed
                else ""
            )
            + (
                '<p class="notice">Retained workflow source differs from current IncidentState.</p>'
                if not w.matches_current_state
                else '<p class="muted">Pinned source matches current IncidentState.</p>'
            )
            + '<p class="legend">ADVANCED means a recorded cursor transition, not proof of '
            "successful execution. TERMINAL is not a success verdict. NOT OBSERVED is not an "
            "inferred skipped step.</p>"
        )
        trace_html = table(
            ("Sequence", "Recorded transition", "Wait / failure", "Reason", "Reference"),
            [
                f"<tr><td>#{t.sequence}</td><td>{e(t.current.value.upper())} → "
                f"{e(t.next_step.value.upper())}</td><td>"
                f"{e('HUMAN WAIT' if t.waiting else 'NO WAIT')}"
                f"<br>{e(t.failure or 'NONE RECORDED')}</td><td>{e(t.reason)}</td>"
                f"<td>{identity(t.reference)}</td></tr>"
                for t in w.trace
            ],
            "Trace NOT AVAILABLE",
        )
        trace_html += (
            '<p class="legend">Trace sequences have no event timestamps; no times are inferred.</p>'
        )
    human = "".join(f"<p>{badge(a.category)} {e(a.reason)}</p>" for a in view.human_actions)
    human = human or '<p class="muted">No wait recorded in the retained workflow.</p>'
    governance = human + table(
        ("Domain", "Recorded status", "Actor attribution", "Recorded time", "Reference"),
        [
            f"<tr><td>{e(g.domain)}</td><td>{badge(g.status)}</td>"
            f"<td>{e(g.actor or 'NOT AVAILABLE')}</td>"
            f"<td>{timestamp(g.timestamp)}</td><td>{identity(g.reference)}"
            f'<br><span class="muted">Related: {e(", ".join(g.related) or "—")}</span></td></tr>'
            for g in view.governance
        ],
        "Governance records NOT AVAILABLE",
    )
    governance += (
        '<p class="legend">Incident Review ≠ State Change Authorization ≠ Response Action Review '
        "≠ Tool Approval. Actor attribution does not imply a current role. No decisions can be "
        "submitted here.</p>"
    )
    governance += (
        '<p><a class="refresh" href="/dashboard/governance">'
        "Review accessible ACTION REQUIRED requests in Governance Inbox</a></p>"
    )
    assessment = empty("Threat Assessment NOT AVAILABLE")
    if view.assessment:
        a = view.assessment
        assessment = (
            f"{badge('ADVISORY')} {badge(a.severity.upper())}<p>{e(a.summary)}</p>"
            f"<p>{identity(a.assessment_id)} · {timestamp(a.created_at)}</p>"
            f"<p>Supporting records: {references(a.supporting)}</p>"
            f'<p class="muted">Fusion context: '
            f"{identity(a.fusion_reference) if a.fusion_reference else 'NOT AVAILABLE'}</p>"
            '<p class="legend">Advisory severity is not authoritative IncidentState severity.</p>'
        )
    decision = empty("Incident Decision NOT AVAILABLE")
    if view.decision:
        d = view.decision
        decision = (
            f"{badge('ADVISORY DECISION')} {badge(d.outcome)}<p>{identity(d.decision_id)}</p>"
            f"<h3>Rationale</h3>{statements(d.rationale)}<h3>Human review reasons</h3>"
            f"{statements(d.review_reasons)}<h3>Investigation reasons</h3>"
            f"{statements(d.investigation_reasons)}<details><summary>Uncertainties / "
            f"limitations</summary>"
            f"{statements(d.uncertainties)}</details><p>{references(d.supporting)}</p>"
            '<p class="legend">This decision has no applied-state or execution authority.</p>'
        )
    signals = (
        '<div class="signals">'
        + "".join(
            f'<article class="signal"><h3>{e(s.domain)}</h3>{badge(s.state)}'
            f'<p class="muted">Confidence: {e(s.confidence)}</p>{timestamp(s.timestamp)}'
            + (
                f"<details><summary>Artifact provenance</summary>{identity(s.reference)}<br>"
                + "<br>".join(e(t) for t in s.provenance)
                + "</details>"
                if s.reference
                else '<p class="muted">NOT AVAILABLE in retained context</p>'
            )
            + "</article>"
            for s in view.signals
        )
        + '</div><p class="legend">IsolationForest rank is not attack probability. Fusion '
        "agreement is not statistical confidence.</p>"
    )
    evidence = "".join(
        f'<article class="artifact" id="evidence-{e(r.evidence_id)}"><h3>{badge("EVIDENCE")} '
        f'{identity(r.evidence_id)}</h3><p>{e(r.summary)}</p><p class="muted">Source: '
        f"{e(r.source)} · "
        f"Tool: {e(r.tool or 'NOT AVAILABLE')} · Reliability: "
        f"{e(r.reliability if r.reliability is not None else 'UNKNOWN')}</p>"
        f"<p>Observed {timestamp(r.observed_at)} · Collected "
        f"{timestamp(r.collected_at)}</p></article>"
        for r in view.evidence
    ) or empty("No Evidence records")
    observations = "".join(
        f'<article class="artifact" '
        f'id="observation-{e(o.observation_id)}"><h3>{badge("OBSERVATION")} '
        f"{identity(o.observation_id)}</h3><p>{e(o.statement)}</p><p>{references(o.supporting)}</p>"
        f"<p>{timestamp(o.created_at)}</p></article>"
        for o in view.observations
    ) or empty("No Agent Observations")
    hypotheses = "".join(
        f'<article class="artifact hypothesis" '
        f'id="hypothesis-{e(h.hypothesis_id)}"><h3>{badge("UNVERIFIED HYPOTHESIS")} '
        f"{identity(h.hypothesis_id)}</h3><p>{e(h.statement)}</p><p>{references(h.supporting)}</p>"
        f'<p class="muted">Recorded confidence: {e(h.confidence)} · Not a calibrated attack '
        f"probability</p>"
        f"<p>{timestamp(h.created_at)}</p></article>"
        for h in view.hypotheses
    ) or empty("No Investigation Hypotheses")
    investigation = empty("Investigation Plan NOT AVAILABLE")
    if view.investigation:
        p = view.investigation
        investigation = (
            f"<p>{identity(p.plan_id)} · {timestamp(p.created_at)}</p><p>{e(p.goal or '—')}</p>"
            f'<p class="muted">Strategy provenance: {e(p.strategy_provenance)}</p>'
        )
        investigation += table(
            ("Step / action", "Tool", "Permission", "Status", "Purpose / Evidence"),
            [
                f"<tr><td>{identity(s.step_id)}<br>{identity(s.action_id)}</td><td>{e(s.tool)}</td>"
                f"<td>{e(s.permission)}</td><td>{badge(s.status.upper())}<br>"
                f"{e(s.error_type or '')}</td>"
                f"<td>{e(s.purpose)}<br>"
                f"{references((s.evidence,)) if s.evidence else '—'}</td></tr>"
                for s in p.steps
            ],
            "No retained investigation steps",
        )
        investigation += (
            '<p class="legend">Tool inputs are withheld. Permissions and applied '
            "strategy are not inferred from the current registry.</p>"
        )
    response = table(
        ("Proposal / plan", "Tool / permission", "Proposal status", "Purpose"),
        [
            f"<tr><td>{identity(r.proposal_id)}<br>{identity(r.plan_id)}</td><td>{e(r.tool)}<br>"
            f"{e(r.permission)}</td><td>{badge(r.status)}<br>"
            f"{identity(r.promoted_reference) if r.promoted_reference else '—'}</td>"
            f"<td>{e(r.purpose)}</td></tr>"
            for r in view.responses
        ],
        "Durable response proposals NOT AVAILABLE",
    )
    response += (
        '<p class="legend">PROPOSED and PROMOTED are not EXECUTED. Execution state '
        "is displayed separately.</p>"
    )
    execution = table(
        ("Execution / stable action", "Tool", "Lifecycle", "Invocation / finish", "Reconciliation"),
        [
            f"<tr><td>{identity(x.execution_id)}<br>{identity(x.action_id)}</td><td>{e(x.tool)}</td>"
            f"<td>{badge(x.status.upper())}</td><td>{timestamp(x.started_at)}<br>{timestamp(x.finished_at)}</td>"
            f"<td>{e(x.reconciliation or 'NOT AVAILABLE')}</td></tr>"
            for x in view.executions
        ],
        "Durable execution evidence NOT AVAILABLE",
    )
    execution += (
        '<p class="legend">UNCERTAIN is preserved as a separate lifecycle. No '
        "automatic retry is implied. SUCCEEDED is a durable execution outcome, not "
        "an independent verification of external security effect.</p>"
    )
    outcome = table(
        (
            "Evaluation / experience",
            "Run",
            "Descriptive outcomes",
            "Terminal / recovery",
            "Feedback records",
        ),
        [
            f"<tr><td>{identity(o.evaluation_id)}<br>{identity(o.experience_id)}</td><td>{identity(o.run_id)}</td>"
            f"<td>Execution: {e(o.execution_outcome)}<br>Governance: {e(o.governance_outcome)}</td>"
            f"<td>{e(o.terminal)} / "
            f"{e(o.recovery_observed)}</td><td>"
            f"{e(o.feedback_count if o.feedback_count is not None else 'UNKNOWN')}</td></tr>"
            for o in view.outcomes
        ],
        "Outcome Evaluation NOT AVAILABLE",
    )
    outcome += (
        '<p class="legend">Historical, incident-linked descriptive facts. An '
        "evaluation does not determine correctness or authorize action.</p>"
    )
    provenance = (
        '<div class="inventory">'
        + "".join(
            f'<a href="#{anchor}">{label} {badge("AVAILABLE" if present else "NOT AVAILABLE")}</a>'
            for label, anchor, present in (
                ("Evidence", "evidence", bool(view.evidence)),
                ("Observation", "observations", bool(view.observations)),
                ("Hypothesis", "hypotheses", bool(view.hypotheses)),
                ("Assessment", "assessment", view.assessment is not None),
                ("Decision", "decision", view.decision is not None),
                ("Governance", "governance", bool(view.governance)),
                ("Action", "execution", bool(view.executions)),
            )
        )
        + '</div><p class="legend">Inventory is not a causal chain. Only explicit source '
        "references form the links below; no EVENT → SIGNAL → EVIDENCE relationship is "
        "invented.</p>"
    )
    provenance += table(
        ("Source", "Recorded relationship", "Target"),
        [
            f"<tr><td>{references((p.source,))}</td><td>{e(p.relation)}</td>"
            f"<td>{references((p.target,))}</td></tr>"
            for p in view.provenance
        ],
        "Explicit provenance links NOT AVAILABLE",
    )
    timeline = table(
        ("UTC timestamp", "Artifact event", "Reference"),
        [
            f"<tr><td>{timestamp(t.timestamp)}</td><td>{e(t.description)}</td><td>{identity(t.reference)}</td></tr>"
            for t in view.timeline
        ],
        "Timestamped artifacts NOT AVAILABLE",
    )
    summary = f"""<div class="detail-summary">
<div><span class="muted">AUTHORITATIVE STATE</span>
<p>{badge(view.status.upper())} {badge(view.severity.upper())}</p></div>
<div><span class="muted">WORKFLOW CURSOR</span>
<p>{badge(w.next_step.value.upper() if w else "UNKNOWN")}</p></div>
<div><span class="muted">HUMAN ACTION</span>
<p>{badge("REQUIRED" if view.human_actions else "NONE RECORDED")}</p></div>
<div><span class="muted">SOURCE STATE REVISION</span><p>{view.revision}</p></div></div>
<p class="muted">Created {timestamp(view.created_at)}
State updated {timestamp(view.updated_at)} ·
Sources: {e(", ".join(view.sources) or "NOT AVAILABLE")}</p>"""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Incident Detail · SOC Command Center</title>
<style>{CSS}</style></head><body><a class="skip" href="#main">Skip to incident detail</a>
<header><div><div class="brand">AUTONOMOUS SOC</div><h1>Incident Detail</h1></div>
<div class="header-meta"><span>Read only · {timestamp(refreshed_at)}</span>
<a class="refresh" href="/dashboard">Command Center</a>
<a class="refresh" href="/dashboard/incidents/{e(view.incident_id)}">Refresh detail</a></div>
</header>
<div class="layout"><aside><nav aria-label="Incident navigation"><a href="/dashboard">Overview</a>
<a href="#workflow">Workflow</a><a href="#assessment">Assessment</a>
<a href="#governance">Governance</a>
<a href="#evidence">Evidence</a><a href="#observations">Observations</a>
<a href="#hypotheses">Hypotheses</a>
<a href="#provenance">Provenance</a></nav></aside><main id="main">
<div class="intro"><div><h2>Incident <span class="id">{e(view.incident_id)}</span></h2>
<p class="muted">Evidence → Reasoning Artifact → Decision → Human Governance</p>
</div>{badge("READ ONLY")}</div>
{summary}{section("Agent Workflow", "workflow", workflow)}
<div class="grid"><div>{section("Threat Assessment", "assessment", assessment, "Advisory")}
{section("Incident Decision", "decision", decision, "Advisory routing")}</div>
<div>{section("Human Governance", "governance", governance, "Independent authority domains")}</div>
</div>
{section("Security AI Signals", "signals", signals, "Retained model-derived context")}
{section("Evidence", "evidence", evidence, "Source records; reliability is not assumed")}
<div class="grid">
<div>{section("Agent Observations", "observations", observations, "Evidence-supported")}
</div>
<div>{section("Investigation Hypotheses", "hypotheses", hypotheses, "Unverified")}
</div></div>
{section("Investigation Plan", "investigation", investigation)}
{section("Response Proposals", "response", response)}
{section("Execution / Recovery", "execution", execution)}
{section("Outcome Evaluation", "outcome", outcome)}{section("Provenance", "provenance", provenance)}
<details class="trace-disclosure">
<summary>Workflow trace — sequence only</summary>{section("Trace", "trace", trace_html)}</details>
{section("Artifact Timeline", "timeline", timeline, "Oldest → newest · actual timestamps only")}
<footer>UNKNOWN remains UNKNOWN. This view does not authorize any operation.</footer>
</main></div></body></html>"""

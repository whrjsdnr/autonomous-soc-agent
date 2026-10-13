"""Escaped structured learning history; no buttons that create authority."""

from soc_agent.api.dashboard.render import CSS, badge, e, empty, identity, panel, timestamp
from soc_agent.api.dashboard.self_improvement_models import SelfImprovementView


def measured(value: int | None) -> str:
    return str(value) if value is not None else "UNKNOWN"


def table(headers: tuple[str, ...], rows: tuple[tuple[str, ...], ...]) -> str:
    return (
        '<div class="table-wrap"><table><thead><tr>'
        + "".join(f"<th>{e(h)}</th>" for h in headers)
        + "</tr></thead><tbody>"
        + "".join("<tr>" + "".join(f"<td>{e(v)}</td>" for v in row) + "</tr>" for row in rows)
        + "</tbody></table></div>"
    )


def render_self_improvement(view: SelfImprovementView) -> str:
    cards = "".join(
        f'<article class="kpi"><div class="label">{e(label)}</div>'
        f'<div class="value">{e(value)}</div></article>'
        for label, value in (
            ("EXPERIENCES", measured(view.experience_count)),
            ("IMPROVEMENT CANDIDATES", measured(view.candidate_count)),
            ("AWAITING HUMAN REVIEW", measured(view.awaiting_review_count)),
            ("ROLLBACK TARGETS", measured(view.rollback_target_count)),
        )
    )
    lifecycle = "".join(
        f'<span class="stage">{e(label)} · {measured(count)}</span>'
        for label, count in view.lifecycle_counts
    )
    active = f"<p>ACTIVE VERSION {badge(view.active.state)}</p>"
    if view.active.artifact:
        v = view.active.artifact
        active += (
            f"<h3>Version {v.version} · {e(v.family)}</h3><p>Artifact {identity(v.artifact_id)}</p>"
            f"<p>{e(v.operation)} · {e(', '.join(v.permissions))}</p>"
            f"<p>Source Candidate {identity(v.source_candidate)}<br>"
            f"Pointer revision {view.active.pointer_revision}<br>"
            f"Activation record {identity(view.active.activation_record)}<br>"
            f"Activated {timestamp(view.active.activated_at)}</p>"
        )
    active += (
        f"<p>Runtime consumption {badge(view.active.runtime_consumption)}</p>"
        "<p>Registry-backed strategy is available through the typed provider boundary. "
        "This query does not prove the running planner was composed with that provider.</p>"
        "<p>Initial NONE uses existing unconstrained planning behavior; it is not version 0. "
        "Rollback to initial NONE is not supported.</p>"
    )
    comparisons = ""
    for c in view.comparisons:
        comparisons += (
            f'<article class="workflow"><h3>OFFLINE / SANDBOX {identity(c.identity)}</h3>'
            f"<p>Candidate {identity(c.candidate_id)} · Dataset {identity(c.dataset_id)}</p>"
            f"<p>DEVELOPMENT {c.development_count} · HOLDOUT {c.holdout_count}<br>"
            f"Baseline result {identity(c.baseline_id)}<br>"
            f"Candidate result {identity(c.candidate_result_id)}</p>"
            + table(("Metric", "BASELINE", "CANDIDATE", "Delta", "Result"), c.metrics)
            + "<h4>Safety invariants · scoped offline observations, not production safety</h4>"
            + table(("Invariant", "Baseline", "Candidate"), c.safety)
            + "<h4>Required acceptance</h4>"
            + table(("Metric", "Criterion", "Status"), c.acceptance)
            + f"<p>Recorded {timestamp(c.created_at)}</p></article>"
        )
    history = ""
    for v in view.versions:
        history += (
            f'<article class="workflow"><h3>Version {v.version} '
            f"{badge('ACTIVE' if v.active else 'REGISTERED')}</h3>"
            f"<p>Artifact {identity(v.artifact_id)} · {e(v.family)}<br>"
            f"{e(v.operation)} · {e(', '.join(v.permissions))}<br>"
            f"Source Candidate {identity(v.source_candidate)}<br>"
            f"Registered {timestamp(v.created_at)}</p>"
            + "".join(f"<p>Promotion record {identity(i)}</p>" for i in v.promotion_records)
            + "".join(f"<p>ROLLED BACK FROM · Record {identity(i)}</p>" for i in v.rollback_from)
            + "".join(f"<p>ROLLBACK TARGET · Record {identity(i)}</p>" for i in v.rollback_to)
            + "</article>"
        )
    sections = ""
    for section in view.sections:
        rows = ""
        for r in section.records:
            rows += (
                f'<article class="workflow"><h3>{e(r.title)}</h3><p>{identity(r.identity)}</p>'
                + "<dl>"
                + "".join(f"<dt>{e(k)}</dt><dd>{e(v)}</dd>" for k, v in r.facts)
                + "</dl>"
                + "".join(
                    f'<p>Incident <a href="/dashboard/incidents/{e(i)}">{identity(i)}</a></p>'
                    for i in r.incidents
                )
                + (f"<p>Recorded {timestamp(r.created_at)}</p>" if r.created_at else "")
                + "</article>"
            )
        sections += panel(
            section.name,
            rows
            or empty(
                "No durable records"
                if section.available
                else "NOT AVAILABLE · storage is not configured"
            ),
        )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Governed Self-Improvement · SOC Command Center</title><style>{CSS}</style></head>
<body><a class="skip" href="#main">Skip to self-improvement</a>
<header><div><div class="brand">AUTONOMOUS SOC</div><h1>SOC Command Center</h1></div>
<div class="header-meta"><a href="/dashboard">Overview</a>
<a href="/dashboard/self-improvement">Refresh learning history</a></div></header>
<main id="main" class="governance-main"><h2>GOVERNED SELF-IMPROVEMENT</h2>
<p>Offline learning, human-reviewed improvement, versioned promotion and rollback.</p>
{panel("ACTIVE RUNTIME STRATEGY", active)}<div class="kpis">{cards}</div>
<div class="stages">{lifecycle}</div>
<p>PROPOSED ≠ EVALUATED ≠ REVIEWED. APPROVED ≠ PROMOTED. PROMOTABLE ≠ PROMOTED.
REGISTERED ≠ ACTIVE.</p>
<div class="human-boundary">Human Improvement Review approval is not promotion.</div>
<p>APPROVE permits promotion consideration only. Improvement Review is separate from
Tool Approval, Incident Review, State Change Authorization and Response Review.</p>
{panel("Baseline vs Candidate", comparisons or empty("Offline comparison NOT AVAILABLE"))}
{sections}
{panel("Immutable Version History", history or empty("No accessible registered versions"))}
<section class="panel"><h2>Promotion / Rollback Governance</h2>
<p>READ ONLY · no activation actions are connected.</p></section>
<p>Promotion and rollback are separate privileged actions. ADMIN requires
PROMOTE_IMPROVEMENT_ARTIFACT or ROLLBACK_IMPROVEMENT_ARTIFACT respectively, a separate
request-specific durable confirmation, exact source pins and active-pointer CAS.</p>
<p>Promotion confirmation cannot authorize rollback. Improvement Review confirmation cannot
activate a version. Stale requests never automatically rebase. Unknown commit outcome requires
durable-state inspection, not blind retry. Rollback preserves immutable history.</p>
<div class="stages"><span class="stage">OBSERVE → LEARN → PROPOSE → EVALUATE</span>
<span class="stage">HUMAN REVIEW → PROMOTE → RUNTIME → ROLLBACK</span></div>
<p>Improvement is offline-evaluated, human-governed, versioned and reversible.</p>
<footer>The system proposes structured improvement artifacts;
it does not rewrite its own source code.
Historical experience produces offline candidates, not online model-weight updates.
UNKNOWN is not SAFE. NOT_MEASURABLE is not zero. This GET only reads durable state.</footer>
</main></body></html>"""

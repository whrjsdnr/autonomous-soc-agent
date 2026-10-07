"""Escaped read-only monitoring cards and retained lineage, never raw model inputs."""

from soc_agent.api.dashboard.render import CSS, badge, e, empty, identity, panel, timestamp
from soc_agent.api.dashboard.security_ai_models import RetainedModelView, SecurityAIMonitorView


def reference(value) -> str:
    return identity(value) if value else "UNKNOWN"


def number(value: int | None) -> str:
    return e(value if value is not None else "UNKNOWN")


def linked_incident(value: RetainedModelView) -> str:
    if value.incident_id is None:
        return "NOT AVAILABLE"
    return (
        f'<a href="/dashboard/incidents/{e(value.incident_id)}">{identity(value.incident_id)}</a>'
    )


def model_card(value: RetainedModelView) -> str:
    numbers = "".join(f"<li>{e(v.name)}: {e(v.value)}</li>" for v in value.values)
    probabilities = "".join(
        f"<li>{e(label)}: {e(probability)}</li>" for label, probability in value.class_probabilities
    )
    details = (
        f"<p>Adapter contract: {e(value.adapter)}</p>"
        f"<p>Model name: {e(value.model_name or 'UNKNOWN')} · "
        f"Version: {e(value.model_version or 'UNKNOWN')}</p>"
        f"<p>Feature schema: {e(value.feature_schema or 'UNKNOWN')}<br>"
        f"Extractor: {e(value.extractor or 'UNKNOWN')} · "
        f"Feature count: {number(value.feature_count)}</p>"
        f"<p>Manifest SHA256: {reference(value.manifest_digest)}</p>"
        f"<p>Artifact file integrity validation: {e(value.integrity_status)}</p>"
        "<p>Retained digest metadata does not establish current file validation or "
        "model health.</p>"
        + "".join(f"<p>{e(h.path)} SHA256: {identity(h.sha256)}</p>" for h in value.file_hashes)
        + f"<p>Incident: {linked_incident(value)} · "
        f"Run: {reference(value.run_id)}</p>"
        f"<p>Contribution: {reference(value.contribution_id)}<br>"
        f"Assessment: {reference(value.assessment_id)}<br>"
        f"Fusion: {reference(value.fusion_id)}</p>"
        + "".join(f"<p>Signal: {identity(i)}</p>" for i in value.signal_ids)
        + "".join(f"<p>Source result: {identity(i)}</p>" for i in value.source_result_ids)
        + f"<p>Source types: {e(', '.join(value.source_types) or 'NOT AVAILABLE')}<br>"
        f"Source records: {number(value.source_record_count)}</p>"
        "<p>Evidence references are source assertions, not proof of feature extraction.</p>"
        + "".join(
            f"<p>Source Evidence reference: {identity(i)}</p>" for i in value.evidence_references
        )
        + "<details><summary>Feature names (no values)</summary>"
        + e(", ".join(value.feature_names) or "NOT AVAILABLE")
        + "</details>"
    )
    return (
        f'<article class="signal"><h3>{e(value.title)}</h3>{badge(value.availability)} '
        f"{badge('MODEL-DERIVED CONTEXT · NOT EVIDENCE')}"
        f"<p>Retained result: {e(value.signal_state)}</p>"
        f"<p>Last source result: {timestamp(value.last_observed)}</p>"
        f"<p>Reported coverage: {e(value.reported_coverage or 'UNKNOWN')}</p>"
        + (
            "<h4>MODEL CLASS PROBABILITY</h4><ul>" + probabilities + "</ul>"
            if probabilities
            else ""
        )
        + ("<h4>ANOMALY MEASUREMENTS</h4><ul>" + numbers + "</ul>" if numbers else "")
        + f"<p>Score semantics: {e(value.score_semantics or 'UNKNOWN')}<br>"
        f"Operating point: {e(value.operating_point or 'UNKNOWN')}</p>"
        + (
            '<p class="legend">Anomaly score is not an attack probability. '
            "Higher empirical rank / -score_samples means more anomalous relative to "
            "the stored benign reference; this is not a SOC verdict.</p>"
            if value.kind != "network_classifier"
            else '<p class="legend">Class probabilities are model outputs, not incident '
            "probabilities, attack certainty or SOC confidence.</p>"
        )
        + f"<details><summary>Metadata / provenance</summary>{details}</details></article>"
    )


def render_security_ai(view: SecurityAIMonitorView) -> str:
    models = '<div class="signals">' + "".join(model_card(m) for m in view.models) + "</div>"
    fusions = ""
    for fusion in view.fusion_contexts:
        fusions += (
            f'<article class="workflow"><h3>Fusion {identity(fusion.fusion_id)}</h3>'
            f"<p>AGREEMENT {badge(fusion.agreement)} · COVERAGE {badge(fusion.coverage)} · "
            f"CONFIDENCE {badge(fusion.confidence)}</p>"
            f'<p>Incident <a href="/dashboard/incidents/{e(fusion.incident_id)}">'
            f"{identity(fusion.incident_id)}</a> → Advisory Assessment "
            f"{identity(fusion.assessment_id)}</p>"
            f"<p>Run {identity(fusion.run_id)} · Checkpoint revision "
            f"{fusion.checkpoint_revision} · "
            f"Source snapshot revision {fusion.snapshot_revision}</p>"
            f"<p>Fusion version {e(fusion.version)} · Source-time watermark "
            f"{timestamp(fusion.created_at)}</p>"
            f"<p>Missing model contributions: "
            f"{e(', '.join(fusion.missing_models) or 'NONE REPORTED')}<br>"
            f"Cross-domain identity mapping: {e(fusion.cross_domain_state)}</p>"
            + "".join(
                f"<p>{e(kind)} → Contribution {identity(ref)}</p>"
                for kind, ref in fusion.contributions
            )
            + "<details><summary>Limitations</summary><ul>"
            + "".join(f"<li>{e(text)}</li>" for text in fusion.limitations)
            + "</ul></details></article>"
        )
    signals = "".join(
        f"<tr><td>{e(s.title)}</td><td>{e(s.signal_state)}</td><td>{timestamp(s.last_observed)}</td>"
        f"<td>{linked_incident(s)}</td><td>{identity(s.contribution_id)}</td>"
        f"<td>{identity(s.assessment_id)}</td></tr>"
        for s in view.latest_retained_signals
    )
    signal_table = (
        "<div "
        'class="table-wrap"><table><thead><tr><th>Model</th><th>Result</th><th>Source time</th>'
        "<th>Incident</th><th>Contribution</th><th>Advisory assessment</th></tr></thead>"
        f"<tbody>{signals}</tbody></table></div>"
        if signals
        else empty("No retained model signals")
    )
    network_count = sum(
        m.availability == "AVAILABLE" for m in view.models if m.kind != "authentication_anomaly"
    )
    intro = (
        f'<div class="kpis"><div class="kpi"><div class="label">NETWORK MODELS</div>'
        f'<div class="value">{network_count} / 2</div><small>With retained '
        f"contributions · not live health</small></div>"
        f'<div class="kpi"><div class="label">AUTHENTICATION</div><div class="value">'
        f"{e(view.models[2].availability)}</div><small>Retained contribution "
        f"availability</small></div>"
        f'<div class="kpi"><div class="label">LINKED INCIDENTS</div><div class="value">'
        f"{view.linked_incident_count}</div><small>Authorized retained contexts "
        f"only</small></div>"
        f'<div class="kpi"><div class="label">LATEST SIGNAL</div>'
        f"{timestamp(view.latest_signal_at)}<small>Source result time · no execution "
        f"clock</small></div></div>"
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security AI · SOC Command Center</title>
<style>{CSS}</style></head><body><a class="skip" href="#main">Skip to Security AI monitoring</a>
<header><div><div class="brand">AUTONOMOUS SOC</div><h1>SOC Command Center</h1></div>
<div class="header-meta"><a href="/dashboard">Overview</a>
<a href="/dashboard/governance">Governance Inbox</a>
<a href="/dashboard/security-ai">Refresh signals</a></div></header>
<main id="main" class="governance-main"><h2>Security AI Monitoring</h2>
<p>{e(view.scope)}</p><p>System health {badge(view.system_status)}</p>{intro}
<div class="human-boundary">MODEL SIGNAL ≠ EVIDENCE ≠ INCIDENT SEVERITY AUTHORITY</div>
<p>Model-derived signals are investigation context, not Evidence.</p>
<div class="stages"><span class="stage">NETWORK XGBOOST / NETWORK IF / AUTH IF</span>
<span class="stage">FUSION CONTEXT</span><span class="stage">INVESTIGATION</span>
<span class="stage">SEPARATE EVIDENCE / ANALYSIS</span>
<span class="stage">ADVISORY ASSESSMENT</span>
<span class="stage">DECISION → HUMAN GOVERNANCE</span></div>
<p class="legend">Conceptual lifecycle, not inferred causal edges.
Model outputs do not create Evidence.</p>
{panel("Model Signals", models, "Latest retained snapshot per model contract")}
{panel("Fusion", fusions or empty("Fusion context NOT AVAILABLE"))}
<p>Fusion combines available model-derived signals for investigation context.
Fusion agreement is not statistical confidence.</p>
{panel("Latest Retained Signals", signal_table, "Not a complete historical signal log")}
<footer>Missing model data is preserved as UNKNOWN or NOT AVAILABLE.
No durable value is available for unknown fields. 
No live health, latency, offline performance metrics
or trend series is fabricated. The monitoring view does not execute model inference.</footer>
</main></body></html>"""

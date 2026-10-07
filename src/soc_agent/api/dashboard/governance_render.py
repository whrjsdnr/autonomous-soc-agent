"""Escaped native-form UX; presentation never authenticates, confirms or decides."""

from soc_agent.api.dashboard.governance_models import (
    GovernanceActionView,
    GovernanceConfirmationView,
    GovernanceDomain,
    GovernanceInbox,
    GovernanceResultView,
)
from soc_agent.api.dashboard.render import CSS, badge, e, empty, identity, panel, timestamp

LABELS = {
    GovernanceDomain.INCIDENT_REVIEW: "INCIDENT REVIEW",
    GovernanceDomain.STATE_AUTHORIZATION: "STATE CHANGE AUTHORIZATION",
}
DECISIONS = {
    "acknowledged_without_authorization": "Acknowledge Without Authorization",
    "additional_investigation_requested": "Request Additional Investigation",
    "state_change_rejected": "Reject State Change",
    "state_change_may_be_proposed": "Allow State Change Proposal",
    "authorize_state_change": "Authorize State Change",
}


def action_path(action: GovernanceActionView) -> str:
    return (
        f"/dashboard/governance/incidents/{action.incident_id}/"
        f"{action.domain.value}/{action.request_id}"
    )


def shell(title: str, body: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)} · SOC Command Center</title><style>{CSS}</style></head>
<body><a class="skip" href="#main">Skip to governance</a><header>
<div><div class="brand">AUTONOMOUS SOC</div><h1>SOC Command Center</h1></div>
<div class="header-meta"><a href="/dashboard">Overview</a>
<a href="/dashboard/governance">Governance Inbox</a></div></header>
<main id="main" class="governance-main"><h2>{e(title)}</h2>{body}
<footer>The dashboard does not grant governance authority. Approval does not imply execution.
Trusted Bearer-header forwarding and domain-specific human confirmation are required.</footer>
</main></body></html>"""


def render_inbox(view: GovernanceInbox) -> str:
    actions = ""
    for action in view.actions:
        actions += (
            f'<article class="action"><h3>{e(LABELS[action.domain])}</h3>'
            f"{badge(action.status)}<p>Incident {identity(action.incident_id)}</p>"
            f"<p>{e(' · '.join(action.summary))}</p>"
            f"<p>Risk: {e(action.risk)} · Impact: {e(action.impact)}</p>"
            f"<p>Permission: {e(action.required_permission)} · Confirmation REQUIRED</p>"
            f"<p>Created: {timestamp(action.created_at)}</p>"
            f'<a class="refresh" href="{e(action_path(action))}">'
            f"Review {e(LABELS[action.domain])}</a>"
            + (
                ""
                if action.actionable
                else "<p>READ ONLY · Stale or confirmation preview unavailable</p>"
            )
            + "</article>"
        )
    return shell(
        "Human Governance Inbox",
        panel("Action Required", actions or empty("No accessible pending governance actions"))
        + panel("Read-only domains", "".join(f"<p>{e(s)}</p>" for s in view.unavailable)),
    )


def facts(action: GovernanceActionView) -> str:
    return (
        f'<p>Incident <a href="/dashboard/incidents/{e(action.incident_id)}">'
        f"{identity(action.incident_id)}</a> · {badge(action.status)}</p>"
        f"<p>Request {identity(action.request_id)}</p>"
        f"<p>Request digest: {identity(action.request_digest)}</p>"
        f"<p>Risk: {e(action.risk)} · Expected impact: {e(action.impact)}</p>"
        f"<p>Required permission: {e(action.required_permission)}</p>"
        + panel("Current Incident State", "".join(f"<p>{e(s)}</p>" for s in action.current_state))
        + panel("Proposed State", "".join(f"<p>{e(s)}</p>" for s in action.proposed_state))
        + panel("Recommendation / Request", "".join(f"<p>{e(s)}</p>" for s in action.summary))
        + panel("Evidence / Assessment Basis", "".join(f"<p>{e(s)}</p>" for s in action.basis))
    )


def hidden(name: str, value: object) -> str:
    return f'<input type="hidden" name="{e(name)}" value="{e(value)}">'


def render_action(action: GovernanceActionView) -> str:
    form = empty("READ ONLY · Stale request or trusted confirmation/hosting unavailable")
    if action.actionable:
        options = ""
        if action.domain == GovernanceDomain.INCIDENT_REVIEW:
            options = (
                '<label for="outcome">Incident Review Decision</label>'
                '<select id="outcome" name="outcome">'
            )
            options += "".join(
                f'<option value="{e(o)}">{e(DECISIONS[o])}</option>'
                for o in action.decision_options
            )
            options += (
                '</select><label for="reason">Human Reason (no credentials)</label>'
                '<textarea id="reason" name="reason" required maxlength="2000"></textarea>'
            )
        form = (
            f'<form method="post" action="{e(action_path(action))}/preview">'
            + hidden("expected_request_digest", action.request_digest)
            + options
            + "<p>Step 1 of 2 · Review your exact decision and existing confirmation "
            "before submission.</p>"
            + '<button type="submit">Review Confirmation Details</button></form>'
        )
    return shell(LABELS[action.domain], facts(action) + panel("Review Request", form))


def render_confirmation(view: GovernanceConfirmationView) -> str:
    a = view.action
    label = DECISIONS[view.decision]
    fields = hidden("expected_request_digest", a.request_digest)
    if a.domain == GovernanceDomain.INCIDENT_REVIEW:
        fields += hidden("outcome", view.decision) + hidden("reason", view.reason)
    fields += hidden("confirmation_id", view.confirmation_id)
    fields += hidden("expected_confirmation_digest", view.context.binding_digest)
    confirmation = (
        f"<p>Decision: {e(label)}</p><p>Reason: {e(view.reason or 'NOT AVAILABLE')}</p>"
        f"<p>Purpose: {e(view.context.action.value)}</p>"
        f"<p>Exact action digest: {identity(view.context.binding_digest)}</p>"
        f"<p>Confirmation reference: {identity(view.confirmation_id)}</p>"
        f"<p>Expires: {timestamp(view.expires_at)}</p>"
        "<p>Bound to your authenticated identity, session, exact request and action purpose.</p>"
        "<p>Step 2 of 2 · Records governance only. Does not apply state or execute a Tool.</p>"
        f'<form method="post" action="{e(action_path(a))}/decision">{fields}'
        f'<a class="refresh" href="{e(action_path(a))}">Cancel</a> '
        f'<button type="submit">Confirm {e(label)}</button></form>'
    )
    return shell(
        f"Confirm {LABELS[a.domain]}", facts(a) + panel("HUMAN CONFIRMATION REQUIRED", confirmation)
    )


def render_result(view: GovernanceResultView) -> str:
    return shell(
        "Governance Decision Recorded",
        panel(
            LABELS[view.domain],
            f"<p>Recorded decision: {e(view.decision)}</p><p>Record: {identity(view.record_id)}</p>"
            f"<p>Recorded at: {timestamp(view.recorded_at)}</p>"
            "<p>State Applied: NO · Tool Execution: NO · Response Execution: NO</p>"
            f'<a href="/dashboard/incidents/{e(view.incident_id)}">Return to Incident Detail</a>',
        ),
    )


def render_error(status: int, code: str) -> str:
    return shell(
        "Governance Request Requires Verification",
        panel(
            "Request result could not be confirmed",
            f"<p>HTTP {status} · {e(code)}</p>"
            "<p>Do not automatically retry. Refresh the request and inspect durable records. "
            "An uncertain commit requires reconciliation; this page is not proof of rollback.</p>"
            '<a href="/dashboard/governance">Return to Governance Inbox</a>',
        ),
    )

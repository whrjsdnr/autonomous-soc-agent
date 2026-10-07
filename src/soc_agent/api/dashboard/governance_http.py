"""Browser transport to typed application commands; Bearer hosting remains explicit."""

import json
from urllib.parse import parse_qs
from uuid import UUID

from soc_agent.api.dashboard.governance_commands import GovernanceUX
from soc_agent.api.dashboard.governance_models import (
    GovernanceDomain,
    ReviewDecisionInput,
    StateAuthorizationInput,
    SubmitReviewDecision,
    SubmitStateAuthorization,
)
from soc_agent.api.dashboard.governance_render import (
    render_action,
    render_confirmation,
    render_error,
    render_inbox,
    render_result,
)
from soc_agent.api.dashboard.render import CSP
from soc_agent.review.errors import HumanAuthorizationDenied


def require_access(app, principal, incident_id=None, domain=None, suffix=None):
    try:
        app._access.require_access(principal, None, "GET:dashboard/governance")
        if incident_id is not None:
            for operation in ("GET:", "GET:artifacts", "GET:dashboard/incident-detail"):
                app._access.require_access(principal, incident_id, operation)
            if domain:
                app._access.require_access(principal, incident_id, f"GET:governance/{domain.value}")
            if suffix:
                command = (
                    "reviews"
                    if domain == GovernanceDomain.INCIDENT_REVIEW
                    else "state-authorizations"
                )
                app._access.require_access(principal, incident_id, "POST:" + command)
                app._access.require_access(
                    principal, incident_id, f"POST:governance/{domain.value}/{suffix}"
                )
    except Exception as error:
        raise HumanAuthorizationDenied("Governance object access denied") from error


def header(scope, name: bytes):
    values = [v for k, v in scope.get("headers", []) if k.lower() == name]
    if len(values) != 1:
        return None
    return values[0].decode("ascii")


async def body_for(app, scope, receive):
    from soc_agent.api.http import APIError

    # Trusted configuration, never an origin inferred from attacker-controlled headers.
    origin = app.dashboard_origin
    if (
        origin is None
        or header(scope, b"origin") != origin
        or header(scope, b"host") != origin.split("://", 1)[1]
        or header(scope, b"sec-fetch-site") not in (None, "same-origin", "none")
    ):
        raise APIError(403, "browser_origin_denied")
    content_type = (header(scope, b"content-type") or "").split(";", 1)[0].strip().lower()
    if content_type not in ("application/json", "application/x-www-form-urlencoded"):
        raise APIError(415, "unsupported_content_type")
    data = bytearray()
    while True:
        event = await receive()
        if event["type"] == "http.disconnect":
            raise APIError(400, "request_disconnected")
        data.extend(event.get("body", b""))
        if len(data) > 16384:
            raise APIError(413, "request_too_large")
        if not event.get("more_body", False):
            break
    text = data.decode("utf-8")
    if content_type == "application/json":

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate JSON field")
                result[key] = value
            return result

        return json.loads(text, object_pairs_hook=unique)
    fields = parse_qs(text, keep_blank_values=True, strict_parsing=True, max_num_fields=12)
    if any(len(values) != 1 for values in fields.values()):
        raise ValueError("Duplicate form field")
    return {name: values[0] for name, values in fields.items()}


async def handle_governance(app, scope, receive, send, credential, principal):
    from soc_agent.api.http import APIError, error_response

    as_json = header(scope, b"accept") == "application/json"
    try:
        parts = scope["path"].strip("/").split("/")
        ux = GovernanceUX(app.startup())
        if parts == ["dashboard", "governance"]:
            if scope["method"] != "GET":
                raise APIError(405, "method_not_allowed")
            require_access(app, principal)

            def visible(incident):
                try:
                    require_access(app, principal, incident)
                except HumanAuthorizationDenied:
                    return False
                return True

            # Permission-filter each domain without confirmation consumption.
            view = ux.inbox(principal, credential, visible)
            allowed = []
            for action in view.actions:
                try:
                    require_access(app, principal, action.incident_id, action.domain)
                except HumanAuthorizationDenied:
                    continue
                allowed.append(
                    action.model_copy(update={"actionable": False})
                    if app.dashboard_origin is None
                    else action
                )
            result = view.model_copy(update={"actions": tuple(allowed)})
            html = render_inbox(result)
        else:
            if len(parts) not in (6, 7) or parts[:3] != ["dashboard", "governance", "incidents"]:
                raise APIError(404, "not_found")
            incident_id, domain, request_id = (
                UUID(parts[3]),
                GovernanceDomain(parts[4]),
                UUID(parts[5]),
            )
            suffix = parts[6] if len(parts) == 7 else None
            method = "POST" if suffix else "GET"
            if suffix not in (None, "preview", "decision"):
                raise APIError(404, "not_found")
            if scope["method"] != method:
                raise APIError(405, "method_not_allowed")
            require_access(app, principal, incident_id, domain, suffix)
            if not suffix:
                result = ux.detail(incident_id, domain, request_id, principal, credential)
                if app.dashboard_origin is None:
                    result = result.model_copy(update={"actionable": False})
                html = render_action(result)
            else:
                body = await body_for(app, scope, receive)
                if suffix == "preview":
                    schema = (
                        ReviewDecisionInput
                        if domain == GovernanceDomain.INCIDENT_REVIEW
                        else StateAuthorizationInput
                    )
                    _, result = ux.prepare(
                        incident_id,
                        domain,
                        request_id,
                        principal,
                        credential,
                        schema.model_validate(body),
                    )
                    html = render_confirmation(result)
                elif domain == GovernanceDomain.INCIDENT_REVIEW:
                    result = ux.submit_review(
                        incident_id,
                        request_id,
                        principal,
                        credential,
                        SubmitReviewDecision.model_validate(body),
                    )
                    html = render_result(result)
                else:
                    result = ux.submit_authorization(
                        incident_id,
                        request_id,
                        principal,
                        credential,
                        SubmitStateAuthorization.model_validate(body),
                    )
                    html = render_result(result)
        status = 200
        payload = result.model_dump_json().encode() if as_json else html.encode()
    except Exception as error:
        status, code = error_response(error)
        payload = (
            json.dumps({"error": code}).encode() if as_json else render_error(status, code).encode()
        )
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json" if as_json else b"text/html; charset=utf-8"),
                (b"cache-control", b"no-store"),
                (
                    b"content-security-policy",
                    CSP.replace("form-action 'none'", "form-action 'self'").encode(),
                ),
                (b"x-content-type-options", b"nosniff"),
                (b"referrer-policy", b"no-referrer"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})

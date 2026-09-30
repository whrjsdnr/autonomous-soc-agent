"""Small ASGI transport, with no server, background tasks or development auth bypass."""

import json
import sqlite3
from collections.abc import Callable
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ValidationError

from soc_agent.api import models
from soc_agent.api.service import ApplicationService, Conflict, NotFound
from soc_agent.approval.errors import ApprovalError
from soc_agent.execution.durable import ReconciliationRequest
from soc_agent.execution.durable.errors import (
    ClaimConflict,
    ExecutionOutcomeUnknown,
    ExecutionReplay,
)
from soc_agent.execution.errors import ExecutionError
from soc_agent.investigation.runtime.persistence.models import StaleCheckpoint, WorkflowInFlight
from soc_agent.response.promotion.errors import PromotionPolicyDenied
from soc_agent.review.authentication import AuthenticatedPrincipal, AuthenticationProvider
from soc_agent.review.errors import HumanAuthorizationDenied, StaleSnapshotError
from soc_agent.review.persistence.models import CommitOutcomeUnknown, StorageError
from soc_agent.review.validation import checked
from soc_agent.state.evidence import utc_now


class AccessPolicy(Protocol):
    def require_access(
        self, principal: AuthenticatedPrincipal, incident_id: UUID | None, operation: str
    ) -> None:
        """Trusted composition checks incident-scoped API access, not execution permission."""
        ...


class AuthenticationRequired(Exception):
    pass


class APIError(Exception):
    def __init__(self, status: int, code: str) -> None:
        self.status, self.code = status, code


def error_response(error: Exception) -> tuple[int, str]:
    if isinstance(error, APIError):
        return error.status, error.code
    if isinstance(error, AuthenticationRequired):
        return 401, "authentication_required"
    if isinstance(error, HumanAuthorizationDenied):
        return 403, "human_authorization_denied"
    if isinstance(error, NotFound):
        return 404, "not_found"
    if isinstance(
        error,
        (
            Conflict,
            StaleCheckpoint,
            WorkflowInFlight,
            StaleSnapshotError,
            ClaimConflict,
            ExecutionReplay,
            ApprovalError,
        ),
    ):
        return 409, "conflict"
    if isinstance(error, (CommitOutcomeUnknown, ExecutionOutcomeUnknown)):
        return 503, "outcome_unknown_reconcile_before_retry"
    if isinstance(error, StorageError):
        if isinstance(error.__cause__, sqlite3.IntegrityError):
            return 409, "conflict"
        return 503, "persistence_unavailable"
    if isinstance(error, (ExecutionError, PromotionPolicyDenied)):
        return 403, "governance_blocked"
    if isinstance(error, (ValidationError, ValueError, TypeError)):
        return 422, "invalid_request"
    return 500, "internal_error"


class SOCApplication:
    """Dependencies are explicitly composed on lifespan startup (or first request)."""

    def __init__(
        self,
        service_factory: Callable[[], ApplicationService],
        *,
        provider: AuthenticationProvider | None = None,
        provider_id: str | None = None,
        access: AccessPolicy | None = None,
    ) -> None:
        self._factory, self._service = service_factory, None
        self._provider, self._provider_id, self._access = provider, provider_id, access

    def startup(self) -> ApplicationService:
        if self._service is None:
            # Factory opens/migrates configured DB and constructs all existing services.
            self._service = self._factory()
        return self._service

    def authenticate(self, headers) -> tuple[str, AuthenticatedPrincipal]:
        if self._provider is None or not self._provider_id or self._access is None:
            raise AuthenticationRequired()
        tokens = [v for k, v in headers if k.lower() == b"authorization"]
        if len(tokens) != 1 or not tokens[0].startswith(b"Bearer "):
            raise AuthenticationRequired()
        try:
            credential = tokens[0][7:].decode("ascii")
            principal = checked(AuthenticatedPrincipal, self._provider.authenticate(credential))
            if (
                principal.provider_id != self._provider_id
                or not principal.authenticated_at <= utc_now() < principal.expires_at
            ):
                raise AuthenticationRequired()
        except Exception as error:
            raise AuthenticationRequired() from error
        return credential, principal

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                event = await receive()
                if event["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
                try:
                    self.startup()
                except Exception:
                    await send({"type": "lifespan.startup.failed", "message": "Startup failed"})
                    return
                await send({"type": "lifespan.startup.complete"})
        if scope["type"] != "http":
            return
        try:
            credential, principal = self.authenticate(scope.get("headers", []))
            parts = scope["path"].strip("/").split("/")
            if not parts or parts[0] != "incidents":
                raise APIError(404, "not_found")
            incident_id = UUID(parts[1]) if len(parts) > 1 else None
            operation = "/".join(parts[2:]) if incident_id else "incidents"
            try:
                self._access.require_access(
                    principal, incident_id, scope["method"] + ":" + operation
                )
            except Exception as error:
                raise HumanAuthorizationDenied("API access denied") from error
            data = bytearray()
            while True:
                event = await receive()
                if event["type"] == "http.disconnect":
                    return
                data.extend(event.get("body", b""))
                if len(data) > 65536:
                    raise APIError(413, "request_too_large")
                if not event.get("more_body", False):
                    break
            body = json.loads(data) if data else {}
            service = self.startup()
            result = await self.dispatch(
                service, scope["method"], incident_id, operation, body, credential
            )
            status = 200
            if isinstance(result, BaseModel):
                result = result.model_dump(mode="json")
        except Exception as error:
            status, code = error_response(error)
            result = {"error": code}
        payload = json.dumps(result, allow_nan=False).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload})

    async def dispatch(self, service, method, incident_id, operation, body, credential):
        if incident_id is None:
            if method != "POST":
                raise APIError(405, "method_not_allowed")
            request = models.CreateIncident.model_validate(body)
            return service.create(request.incident_id)
        if method == "GET":
            models.Empty.model_validate(body)
            handlers = {
                "": service.incident,
                "workflow": service.workflow,
                "trace": service.trace,
                "artifacts": lambda identity: service.checkpoint(identity).artifacts,
            }
            if operation not in handlers:
                raise APIError(404, "not_found")
            return handlers[operation](incident_id)
        if method != "POST":
            raise APIError(405, "method_not_allowed")
        if operation == "workflow/start":
            models.Empty.model_validate(body)
            return service.start(incident_id)
        if operation in ("workflow/step", "workflow/resume"):
            return await service.step(incident_id, models.StepRequest.model_validate(body))
        if operation == "review-requests":
            models.Empty.model_validate(body)
            return service.review_request(incident_id)
        routes = {
            "reviews": (models.IncidentReview, service.record_review, True),
            "response-review-requests": (
                models.ResponseReviewDraft,
                service.response_review_request,
                False,
            ),
            "response-reviews": (models.ResponseReview, service.response_review, True),
            "promotions": (models.Promotion, service.promote, False),
            "approval-requests": (models.ApprovalDraft, service.approval_request, False),
            "approvals": (models.Approval, service.approve, True),
            "reconciliation": (ReconciliationRequest, service.reconcile, True),
        }
        if operation not in routes:
            raise APIError(404, "not_found")
        schema, handler, human = routes[operation]
        request = schema.model_validate(body)
        if not human:
            return handler(incident_id, request)
        try:
            return handler(incident_id, request, credential)
        except KeyError as error:
            # A trusted context/confirmation resolver could not resolve this human operation.
            raise HumanAuthorizationDenied("Human confirmation context unavailable") from error

"""Provider-independent roles; trusted role lookup is distinct from authentication/Policy."""

from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from soc_agent.review.authority import HumanAction
from soc_agent.review.errors import HumanAuthorizationDenied

if TYPE_CHECKING:
    from soc_agent.review.authentication import AuthenticatedPrincipal, HumanActionContext


class HumanRole(StrEnum):
    ANALYST = "analyst"
    RESPONDER = "responder"
    APPROVER = "approver"
    ADMIN = "admin"


class HumanPermission(StrEnum):
    SUBMIT_ANALYST_FEEDBACK = "submit_analyst_feedback"
    INCIDENT_REVIEW = "incident_review"
    RESPONSE_REVIEW = "response_review"
    TOOL_APPROVE = "tool_approve"
    EXECUTION_RECONCILE = "execution_reconcile"
    STATE_CHANGE_AUTHORIZE = "state_change_authorize"


def permission_for(action: HumanAction) -> HumanPermission:
    return {
        HumanAction.SUBMIT_ANALYST_FEEDBACK: HumanPermission.SUBMIT_ANALYST_FEEDBACK,
        HumanAction.RECORD_REVIEW: HumanPermission.INCIDENT_REVIEW,
        HumanAction.REVIEW_RESPONSE_ACTION: HumanPermission.RESPONSE_REVIEW,
        HumanAction.APPROVE_PROMOTED_TOOL: HumanPermission.TOOL_APPROVE,
        HumanAction.RECONCILE_EXECUTION: HumanPermission.EXECUTION_RECONCILE,
        HumanAction.AUTHORIZE_STATE_CHANGE: HumanPermission.STATE_CHANGE_AUTHORIZE,
    }[action]


class HumanRoleProvider(Protocol):
    def roles_for(
        self, principal: "AuthenticatedPrincipal", context: "HumanActionContext"
    ) -> tuple[HumanRole, ...]:
        """Resolve incident-scoped roles from trusted records, not request body claims.

        Bind assignments to provider AND subject. Failure must raise; no fallback role.
        """
        ...


class RBACPermissionVerifier:
    def __init__(self, *, roles: HumanRoleProvider) -> None:
        self._roles = roles

    def require_permission(
        self, principal: "AuthenticatedPrincipal", context: "HumanActionContext"
    ) -> None:
        try:
            roles = tuple(HumanRole(role) for role in self._roles.roles_for(principal, context))
        except Exception as error:
            raise HumanAuthorizationDenied("Trusted role resolution failed") from error
        required = permission_for(context.action)
        grants = {
            HumanRole.ANALYST: frozenset(
                {HumanPermission.INCIDENT_REVIEW, HumanPermission.SUBMIT_ANALYST_FEEDBACK}
            ),
            HumanRole.RESPONDER: frozenset({HumanPermission.RESPONSE_REVIEW}),
            HumanRole.APPROVER: frozenset(
                {
                    HumanPermission.TOOL_APPROVE,
                    HumanPermission.EXECUTION_RECONCILE,
                    HumanPermission.STATE_CHANGE_AUTHORIZE,
                }
            ),
            HumanRole.ADMIN: frozenset(HumanPermission),
        }
        if not any(required in grants[role] for role in roles):
            raise HumanAuthorizationDenied("Authenticated subject lacks required permission")

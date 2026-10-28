"""Public exports loaded on demand; importing a Controller must not load AI models."""

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from soc_agent.review.authority import HumanAction as HumanAction
    from soc_agent.review.authority import HumanAuthority as HumanAuthority
    from soc_agent.review.authority import VerifiedHumanAction as VerifiedHumanAction
    from soc_agent.review.errors import AuthorizationAlreadyApplied as AuthorizationAlreadyApplied
    from soc_agent.review.errors import HumanAuthorizationDenied as HumanAuthorizationDenied
    from soc_agent.review.errors import ReviewError as ReviewError
    from soc_agent.review.errors import StaleSnapshotError as StaleSnapshotError
    from soc_agent.review.errors import StateTransitionDenied as StateTransitionDenied
    from soc_agent.review.models import ApplicationResult as ApplicationResult
    from soc_agent.review.models import HumanReviewRecord as HumanReviewRecord
    from soc_agent.review.models import HumanReviewRequest as HumanReviewRequest
    from soc_agent.review.models import ReviewOutcome as ReviewOutcome
    from soc_agent.review.models import SeverityChange as SeverityChange
    from soc_agent.review.models import StateChangeAuthorization as StateChangeAuthorization
    from soc_agent.review.models import StateChangeRequest as StateChangeRequest
    from soc_agent.review.models import StatusChange as StatusChange
    from soc_agent.review.service import HumanReviewService as HumanReviewService
    from soc_agent.review.store import IncidentStateStore as IncidentStateStore
    from soc_agent.review.store import InMemoryIncidentStateStore as InMemoryIncidentStateStore

_EXPORTS = {
    "ApplicationResult": "soc_agent.review.models",
    "AuthorizationAlreadyApplied": "soc_agent.review.errors",
    "HumanAction": "soc_agent.review.authority",
    "HumanAuthority": "soc_agent.review.authority",
    "HumanAuthorizationDenied": "soc_agent.review.errors",
    "HumanReviewRecord": "soc_agent.review.models",
    "HumanReviewRequest": "soc_agent.review.models",
    "HumanReviewService": "soc_agent.review.service",
    "InMemoryIncidentStateStore": "soc_agent.review.store",
    "IncidentStateStore": "soc_agent.review.store",
    "ReviewError": "soc_agent.review.errors",
    "ReviewOutcome": "soc_agent.review.models",
    "SeverityChange": "soc_agent.review.models",
    "StaleSnapshotError": "soc_agent.review.errors",
    "StateChangeAuthorization": "soc_agent.review.models",
    "StateChangeRequest": "soc_agent.review.models",
    "StateTransitionDenied": "soc_agent.review.errors",
    "StatusChange": "soc_agent.review.models",
    "VerifiedHumanAction": "soc_agent.review.authority",
}
__all__ = list(_EXPORTS)


def __getattr__(name: str):
    try:
        module = _EXPORTS[name]
    except KeyError:
        raise AttributeError(name) from None
    return getattr(import_module(module), name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_EXPORTS))

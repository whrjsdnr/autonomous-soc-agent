"""Injected human authentication, authorization and exact-intent confirmation boundary."""

from enum import StrEnum
from typing import Protocol

from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.models import Frozen, Hash, Subject


class HumanAction(StrEnum):
    RECORD_REVIEW = "record_human_review"
    AUTHORIZE_STATE_CHANGE = "authorize_incident_state_change"


class VerifiedHumanAction(Frozen):
    subject_id: Subject
    action: HumanAction
    binding_digest: Hash


class HumanAuthority(Protocol):
    def verify(
        self, *, credential: str, action: HumanAction, binding_digest: str
    ) -> VerifiedHumanAction:
        """Verify authenticated HUMAN, permission and explicit intent for this exact digest.

        A session login alone is insufficient. Reject expired/replayed/unbound confirmations.
        Credentials must never be persisted in review or application audit records.
        Implementations belong to trusted composition, never to LLM/tool inputs.
        """
        ...


class DenyHumanAuthority:
    def verify(
        self, *, credential: str, action: HumanAction, binding_digest: str
    ) -> VerifiedHumanAction:
        raise HumanAuthorizationDenied("No trusted human authorization boundary configured")

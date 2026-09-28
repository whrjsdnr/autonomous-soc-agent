"""Read-only authoritative review provenance; models alone do not authenticate humans."""

from typing import Protocol

from soc_agent.decision import IncidentDecision
from soc_agent.review.identity import content_digest, state_fingerprint
from soc_agent.review.models import HumanReviewRecord, StateAnchor
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.session import GovernanceSession
from soc_agent.state import IncidentState


class PlanningSource(Protocol):
    def validate_sources(
        self, state: IncidentState, decision: IncidentDecision, review: HumanReviewRecord
    ) -> StateAnchor:
        """Trusted read boundary: require exact registered review, decision and current state."""
        ...


class PersistentPlanningSource:
    def __init__(self, store: SQLiteGovernanceStore) -> None:
        self._store = store

    def validate_sources(
        self, state: IncidentState, decision: IncidentDecision, review: HumanReviewRecord
    ) -> StateAnchor:
        with self._store.database.transaction(write=False) as connection:
            session = GovernanceSession(connection, self._store.store_id)
            service = session.restore_service()
            current = session.load(state.incident_id)
            if (
                current.state != state
                or current.anchor.fingerprint != state_fingerprint(state)
                or review.target.snapshot != current.anchor
                or service._reviews.get(review.review_id) != review
                or service._decisions.get(content_digest(decision)) != decision
            ):
                raise ValueError("Unknown, changed or stale planning source")
            return current.anchor

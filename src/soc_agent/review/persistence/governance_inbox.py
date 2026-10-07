"""Pending Incident governance read snapshot; no new queues or authority records."""

from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from soc_agent.decision import IncidentDecision
from soc_agent.review.models import (
    HumanReviewRecord,
    HumanReviewRequest,
    StateChangeRequest,
    StoredIncident,
)
from soc_agent.review.persistence import SQLiteGovernanceStore, ledger
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.review.persistence.session import GovernanceSession


@dataclass(frozen=True)
class GovernancePendingSource:
    incident: StoredIncident
    request: HumanReviewRequest | StateChangeRequest
    decision: IncidentDecision
    review: HumanReviewRecord | None


def read_governance_pending(
    store: SQLiteGovernanceStore, visible: Callable[[UUID], bool]
) -> tuple[GovernancePendingSource, ...]:
    with store.database.transaction(write=False) as connection:
        connection.execute("PRAGMA query_only=ON")
        session = GovernanceSession(connection, store.store_id)
        result = []
        for row in connection.execute("SELECT incident_id FROM incidents ORDER BY incident_id"):
            incident_id = UUID(row["incident_id"])
            if not visible(incident_id):
                continue
            incident = session.load(incident_id)
            for table, completed in (
                ("review_requests", "reviews"),
                ("requests", "authorizations"),
            ):
                for pending in connection.execute(
                    f"SELECT p.* FROM {table} p WHERE p.incident_id=? AND NOT EXISTS "
                    f"(SELECT 1 FROM {completed} c WHERE c.parent=p.id) ORDER BY p.id",
                    (str(incident_id),),
                ):
                    request = ledger.decode_artifact(table, pending)
                    target = request.target
                    decision_row = connection.execute(
                        "SELECT * FROM decisions WHERE id=?", (target.decision_digest,)
                    ).fetchone()
                    if decision_row is None:
                        raise StoredDataError("Governance decision missing")
                    decision = ledger.decode_artifact("decisions", decision_row)
                    review = None
                    if isinstance(request, StateChangeRequest):
                        parent = connection.execute(
                            "SELECT * FROM reviews WHERE id=?", (str(request.review_id),)
                        ).fetchone()
                        if parent is None:
                            raise StoredDataError("Governance review missing")
                        review = ledger.decode_artifact("reviews", parent)
                        if review.target != target:
                            raise StoredDataError("Governance review binding mismatch")
                    if (
                        target.incident_id != incident_id
                        or decision.decision_id != target.decision_id
                        or decision.decision_version != target.decision_version
                        or decision.rule_version != target.decision_rule_version
                    ):
                        raise StoredDataError("Governance pending source mismatch")
                    session.snapshot(target.snapshot)
                    result.append(GovernancePendingSource(incident, request, decision, review))
        return tuple(result)

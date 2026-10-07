"""One read snapshot, without restoring governance services or invoking runtimes."""

from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from soc_agent.investigation.runtime.persistence.models import WorkflowCheckpoint
from soc_agent.review.models import StoredIncident
from soc_agent.review.persistence import SQLiteGovernanceStore, ledger
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.review.persistence.session import GovernanceSession


@dataclass(frozen=True)
class DashboardSource:
    incident: StoredIncident
    checkpoint: WorkflowCheckpoint | None
    claimed: bool = False


def read_dashboard_snapshot(
    store: SQLiteGovernanceStore, visible: Callable[[UUID], bool]
) -> tuple[DashboardSource, ...]:
    """Authorization is checked before loading any incident payload.

    Decodes current records, not the complete approval/promotion/source graph.
    A claim is displayed as unresolved, never cleared or interpreted as successful.
    """
    with store.database.transaction(write=False) as connection:
        connection.execute("PRAGMA query_only=ON")
        session = GovernanceSession(connection, store.store_id)
        result = []
        for row in connection.execute("SELECT incident_id FROM incidents ORDER BY incident_id"):
            identity = UUID(row["incident_id"])
            if not visible(identity):
                continue
            incident = session.load(identity)
            item = connection.execute(
                "SELECT * FROM workflow_checkpoints WHERE incident_id=?", (str(identity),)
            ).fetchone()
            checkpoint = ledger.decode(WorkflowCheckpoint, item) if item else None
            if checkpoint is not None and (
                checkpoint.incident_id != identity
                or str(checkpoint.run_id) != item["run_id"]
                or checkpoint.revision != item["revision"]
            ):
                raise StoredDataError("Dashboard checkpoint binding mismatch")
            if checkpoint is not None:
                anchor = checkpoint.artifacts.snapshot
                if (
                    anchor.repository_id != store.store_id
                    or anchor.revision > incident.anchor.revision
                ):
                    raise StoredDataError("Dashboard checkpoint snapshot mismatch")
                session.snapshot(anchor)
            result.append(DashboardSource(incident, checkpoint, bool(item and item["claim"])))
        return tuple(result)

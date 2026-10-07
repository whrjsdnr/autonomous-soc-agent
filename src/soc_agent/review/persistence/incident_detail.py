"""Incident-scoped, single read snapshot; never restores an authority service."""

from dataclasses import dataclass
from uuid import UUID

from soc_agent.evaluation.models import EvaluationRecord
from soc_agent.execution.durable.models import ExecutionEvent, ExecutionRecord
from soc_agent.execution.durable.store import ExecutionStore
from soc_agent.investigation.runtime.persistence.store import CheckpointStore
from soc_agent.investigation.runtime.trace import OrchestrationTrace
from soc_agent.review.persistence import SQLiteGovernanceStore, ledger
from soc_agent.review.persistence.dashboard import DashboardSource
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.review.persistence.session import GovernanceSession


class IncidentDetailNotFound(ValueError):
    pass


@dataclass(frozen=True)
class IncidentDetailSource:
    source: DashboardSource
    trace: OrchestrationTrace | None
    governance: tuple[ledger.Artifact, ...]
    executions: tuple[ExecutionRecord, ...]
    execution_events: tuple[ExecutionEvent, ...]
    evaluations: tuple[EvaluationRecord, ...]
    feedback_counts: tuple[tuple[str, int], ...]


def read_incident_detail(
    store: SQLiteGovernanceStore,
    checkpoints: CheckpointStore,
    execution: ExecutionStore,
    incident_id: UUID,
) -> IncidentDetailSource:
    with store.database.transaction(write=False) as connection:
        connection.execute("PRAGMA query_only=ON")
        identity = str(incident_id)
        if (
            connection.execute(
                "SELECT 1 FROM incidents WHERE incident_id=?", (identity,)
            ).fetchone()
            is None
        ):
            raise IncidentDetailNotFound("Incident not found")
        session = GovernanceSession(connection, store.store_id)
        incident = session.load(incident_id)
        checkpoint, trace, claim = None, None, None
        if connection.execute(
            "SELECT 1 FROM workflow_checkpoints WHERE incident_id=?", (identity,)
        ).fetchone():
            checkpoint, trace, claim = checkpoints._read(connection, incident_id)
            anchor = checkpoint.artifacts.snapshot
            if anchor.repository_id != store.store_id or anchor.revision > incident.anchor.revision:
                raise StoredDataError("Detail checkpoint snapshot mismatch")
            session.snapshot(anchor)
        governance = []
        for table in ("review_requests", "reviews", "requests", "authorizations", "applications"):
            for row in connection.execute(
                f"SELECT * FROM {table} WHERE incident_id=? ORDER BY id", (identity,)
            ):
                governance.append(ledger.decode_artifact(table, row))
        records, events = [], []
        for row in connection.execute(
            "SELECT id FROM execution_records WHERE incident_id=? ORDER BY id", (identity,)
        ):
            record = execution._load(connection, row["id"])
            records.append(record)
            for event_row in connection.execute(
                "SELECT * FROM execution_events WHERE execution_id=? ORDER BY revision",
                (row["id"],),
            ):
                event = ledger.decode(ExecutionEvent, event_row)
                if (
                    str(event.event_id) != event_row["event_id"]
                    or event.record.revision != event_row["revision"]
                    or event.record.intent != record.intent
                    or (
                        event.reconciliation is not None
                        and (
                            event.reconciliation.request.incident_id != incident_id
                            or event.reconciliation.request.execution_intent_id != row["id"]
                        )
                    )
                ):
                    raise StoredDataError("Detail execution event binding mismatch")
                events.append(event)
        if checkpoint and checkpoint.artifacts.execution_intent_id is not None:
            bound = next(
                (
                    r
                    for r in records
                    if r.intent.execution_intent_id == checkpoint.artifacts.execution_intent_id
                ),
                None,
            )
            if bound is None or (
                bound.intent.plan != checkpoint.artifacts.response_plan
                or bound.intent.promoted.promoted_id != checkpoint.promoted_id
                or bound.intent.binding.approval_id != checkpoint.approval_id
            ):
                raise StoredDataError("Detail execution/checkpoint binding mismatch")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        evaluations, feedback = [], []
        if version >= 6:
            for row in connection.execute(
                "SELECT * FROM evaluations WHERE incident_id=? ORDER BY evaluation_id", (identity,)
            ):
                value = ledger.decode(EvaluationRecord, row)
                c = value.content
                if (
                    value.evaluation_id,
                    c.experience_id,
                    str(c.incident_id),
                    c.evaluator_version,
                ) != (
                    row["evaluation_id"],
                    row["experience_id"],
                    identity,
                    row["evaluator_version"],
                ):
                    raise StoredDataError("Detail evaluation binding mismatch")
                evaluations.append(value)
                if version >= 7:
                    count = connection.execute(
                        "SELECT COUNT(*) FROM analyst_feedback "
                        "WHERE evaluation_id=? AND incident_id=?",
                        (value.evaluation_id, identity),
                    ).fetchone()[0]
                    feedback.append((value.evaluation_id, count))
        return IncidentDetailSource(
            DashboardSource(incident, checkpoint, claim is not None),
            trace,
            tuple(governance),
            tuple(records),
            tuple(events),
            tuple(evaluations),
            tuple(feedback),
        )

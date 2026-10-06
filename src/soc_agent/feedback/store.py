"""Immutable queries with source, receipt and atomic audit binding validation."""

from sqlite3 import Connection, Row
from uuid import UUID

from soc_agent.evaluation.store import EvaluationStore
from soc_agent.experience.models import Experience
from soc_agent.feedback.models import AnalystFeedback, FeedbackAudit, FeedbackRequest
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer
from soc_agent.review.persistence.models import StoredDataError, UnsupportedSchemaError


class FeedbackStore:
    def __init__(self, evaluations: EvaluationStore) -> None:
        self.evaluations = evaluations
        self.database = evaluations.database
        with self.database.transaction(write=False) as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] not in (
                7,
                8,
                9,
                10,
                11,
                12,
                13,
            ):
                raise UnsupportedSchemaError("Explicit feedback migration required")
            connection.execute("SELECT feedback_id FROM analyst_feedback LIMIT 0")
            connection.execute("SELECT feedback_id FROM feedback_audit LIMIT 0")

    def validate_sources(self, connection: Connection, request: FeedbackRequest) -> Experience:
        row = connection.execute(
            "SELECT * FROM evaluations WHERE evaluation_id=?", (request.evaluation_id,)
        ).fetchone()
        if row is None:
            raise StoredDataError("Unknown evaluation")
        evaluation = self.evaluations._decode(connection, row)
        c = evaluation.content
        if (
            c.incident_id != request.incident_id
            or c.experience_id != request.experience_id
            or c.experience_digest != request.experience_digest
            or content_digest(evaluation) != request.evaluation_digest
        ):
            raise StoredDataError("Foreign or stale feedback source")
        source = connection.execute(
            "SELECT * FROM experiences WHERE experience_id=?", (request.experience_id,)
        ).fetchone()
        return self.evaluations.experiences._decode(source)

    def _decode(self, connection: Connection, row: Row) -> AnalystFeedback:
        value = ledger.decode(AnalystFeedback, row)
        r, v = value.request, value.verification
        if (
            value.feedback_id,
            str(r.submission_id),
            v.provider_id,
            v.subject_id,
            v.session_id,
            str(r.incident_id),
            r.experience_id,
            r.evaluation_id,
        ) != tuple(
            row[name]
            for name in (
                "feedback_id",
                "submission_id",
                "provider_id",
                "subject_id",
                "session_id",
                "incident_id",
                "experience_id",
                "evaluation_id",
            )
        ):
            raise StoredDataError("Feedback indexed bindings mismatch")
        experience = self.validate_sources(connection, r)
        decision = next(
            (ref.identity for ref in experience.content.references if ref.kind == "decision"), None
        )
        if (
            v.context.decision_id != decision
            or v.context.review_id is not None
            or v.context.changes
        ):
            raise StoredDataError("Feedback context does not match historical source")
        receipt = SQLiteConfirmationConsumer._load(connection, v.provider_id, v.confirmation_id)
        if receipt is None or not receipt.consumed or receipt.verification != v:
            raise StoredDataError("Feedback confirmation receipt mismatch")
        audit_row = connection.execute(
            "SELECT * FROM feedback_audit WHERE feedback_id=?", (value.feedback_id,)
        ).fetchone()
        if audit_row is None:
            raise StoredDataError("Feedback audit missing")
        audit = ledger.decode(FeedbackAudit, audit_row)
        if audit != FeedbackAudit(
            feedback_id=value.feedback_id,
            feedback_digest=content_digest(value),
            created_at=value.created_at,
        ):
            raise StoredDataError("Feedback audit mismatch")
        return value

    def _insert(self, connection: Connection, value: AnalystFeedback) -> None:
        r, v = value.request, value.verification
        connection.execute(
            "INSERT INTO analyst_feedback VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                value.feedback_id,
                str(r.submission_id),
                v.provider_id,
                v.subject_id,
                v.session_id,
                str(r.incident_id),
                r.experience_id,
                r.evaluation_id,
                ledger.serialize(value),
                content_digest(value),
            ),
        )
        audit = FeedbackAudit(
            feedback_id=value.feedback_id,
            feedback_digest=content_digest(value),
            created_at=value.created_at,
        )
        connection.execute(
            "INSERT INTO feedback_audit VALUES (?,?,?)",
            (value.feedback_id, ledger.serialize(audit), content_digest(audit)),
        )

    def get(self, feedback_id: str) -> AnalystFeedback:
        with self.database.transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM analyst_feedback WHERE feedback_id=?", (feedback_id,)
            ).fetchone()
            if row is None:
                raise StoredDataError("Unknown feedback")
            return self._decode(connection, row)

    def _list(self, column: str, identity: str) -> tuple[AnalystFeedback, ...]:
        if column not in {"evaluation_id", "experience_id", "incident_id"}:
            raise ValueError("Unsupported feedback query")
        with self.database.transaction(write=False) as connection:
            return tuple(
                self._decode(connection, row)
                for row in connection.execute(
                    f"SELECT * FROM analyst_feedback WHERE {column}=? ORDER BY feedback_id",
                    (identity,),
                )
            )

    def list_for_evaluation(self, evaluation_id: str) -> tuple[AnalystFeedback, ...]:
        return self._list("evaluation_id", evaluation_id)

    def list_for_experience(self, experience_id: str) -> tuple[AnalystFeedback, ...]:
        return self._list("experience_id", experience_id)

    def list_for_incident(self, incident_id: UUID) -> tuple[AnalystFeedback, ...]:
        return self._list("incident_id", str(incident_id))

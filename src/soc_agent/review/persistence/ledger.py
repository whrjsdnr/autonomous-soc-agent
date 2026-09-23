"""Validated SQL artifact graph; only trusted storage restores service issuance provenance."""

import sqlite3

from pydantic import BaseModel, ValidationError

from soc_agent._json import canonical_json_object
from soc_agent.decision import IncidentDecision
from soc_agent.review.identity import content_digest
from soc_agent.review.models import (
    ApplicationResult,
    HumanReviewRecord,
    HumanReviewRequest,
    StateChangeAuthorization,
    StateChangeRequest,
)
from soc_agent.review.persistence.models import GovernanceEvent, StoredDataError
from soc_agent.review.persistence.schema import PARENTS

Artifact = (
    IncidentDecision
    | HumanReviewRequest
    | HumanReviewRecord
    | StateChangeRequest
    | StateChangeAuthorization
    | ApplicationResult
)

MODELS = {
    "decisions": IncidentDecision,
    "review_requests": HumanReviewRequest,
    "reviews": HumanReviewRecord,
    "requests": StateChangeRequest,
    "authorizations": StateChangeAuthorization,
    "applications": ApplicationResult,
}


def serialize(value: BaseModel) -> str:
    return canonical_json_object(value.model_dump(mode="json"))


def coordinates(value: Artifact) -> tuple[str, str, str, str | None]:
    if isinstance(value, IncidentDecision):
        return "decisions", content_digest(value), str(value.incident_id), None
    if isinstance(value, HumanReviewRequest):
        return (
            "review_requests",
            str(value.review_request_id),
            str(value.target.incident_id),
            value.target.decision_digest,
        )
    if isinstance(value, HumanReviewRecord):
        return (
            "reviews",
            str(value.review_id),
            str(value.target.incident_id),
            str(value.review_request_id),
        )
    if isinstance(value, StateChangeRequest):
        return (
            "requests",
            str(value.request_id),
            str(value.target.incident_id),
            str(value.review_id),
        )
    if isinstance(value, StateChangeAuthorization):
        return (
            "authorizations",
            str(value.authorization_id),
            str(value.request.target.incident_id),
            str(value.request.request_id),
        )
    return (
        "applications",
        str(value.audit.application_id),
        str(value.incident_state.incident_id),
        str(value.audit.authorization_id),
    )


def insert(connection: sqlite3.Connection, value: Artifact) -> None:
    table, identity, incident, parent = coordinates(value)
    parameters = (identity, incident, serialize(value), content_digest(value))
    if table == "decisions":
        old = connection.execute("SELECT * FROM decisions WHERE id=?", (identity,)).fetchone()
        if old is not None:
            if decode_artifact(table, old) != value:
                raise StoredDataError("Decision content identity collision")
            return
        cursor = connection.execute(
            "INSERT INTO decisions(id,incident_id,payload,digest) VALUES (?,?,?,?)", parameters
        )
    else:
        cursor = connection.execute(
            f"INSERT INTO {table}(id,incident_id,payload,digest,parent) VALUES (?,?,?,?,?)",
            (*parameters, parent),
        )

    if cursor.rowcount != 1:
        raise StoredDataError("Artifact INSERT did not persist exactly one record")


def decode[T: BaseModel](model: type[T], row: sqlite3.Row) -> T:
    try:
        value = model.model_validate_json(row["payload"])
        if content_digest(value) != row["digest"] or canonical_json_object(
            row["payload"]
        ) != serialize(value):
            raise StoredDataError("Stored artifact digest mismatch")
        return value
    except (ValidationError, TypeError) as error:
        raise StoredDataError("Stored artifact violates model contract") from error


def decode_artifact(table: str, row: sqlite3.Row) -> Artifact:
    value = decode(MODELS[table], row)
    _, identity, incident, parent = coordinates(value)
    if (
        row["id"] != identity
        or row["incident_id"] != incident
        or (PARENTS[table] and row["parent"] != parent)
    ):
        raise StoredDataError("Stored artifact columns differ from its validated payload")
    return value


def get(connection: sqlite3.Connection, table: str, identity: str) -> Artifact:
    if table not in MODELS:
        raise ValueError("Unknown artifact table")
    row = connection.execute(f"SELECT * FROM {table} WHERE id=?", (identity,)).fetchone()
    if row is None:
        raise StoredDataError(f"Unknown persistent {table} reference")
    return decode_artifact(table, row)


def all_records(connection: sqlite3.Connection, table: str) -> tuple[Artifact, ...]:
    if table not in MODELS:
        raise ValueError("Unknown artifact table")
    return tuple(
        decode_artifact(table, row)
        for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid")
    )


def append_event(connection: sqlite3.Connection, event: GovernanceEvent) -> None:
    cursor = connection.execute(
        "INSERT INTO audit_events(event_id,event_type,payload,digest) VALUES (?,?,?,?)",
        (str(event.event_id), event.event_type, serialize(event), content_digest(event)),
    )

    if cursor.rowcount != 1:
        raise StoredDataError("Audit INSERT did not persist exactly one event")

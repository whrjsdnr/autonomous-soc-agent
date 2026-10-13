"""Explicit additive v14 -> v15, restricted to newly created validation databases."""

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from soc_agent.application import open_application_store
from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.models import StoredDataError, UnsupportedSchemaError
from soc_agent.review.persistence.secure_storage import create_private_directory, guard_directory
from soc_agent.review.persistence.store import SQLiteGovernanceStore
from soc_agent.security_ai.external.models import content_digest_payload

STATEMENTS = (
    "CREATE TABLE external_metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
    "contract TEXT NOT NULL, purpose TEXT NOT NULL, legacy_schema_digest TEXT NOT NULL)",
    "CREATE TABLE external_contexts (id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES "
    "incidents(incident_id), payload TEXT NOT NULL, digest TEXT NOT NULL)",
    "CREATE TABLE external_sources (context_id TEXT NOT NULL REFERENCES external_contexts(id), "
    "position INTEGER NOT NULL CHECK(position>=0), payload TEXT NOT NULL, digest TEXT NOT NULL, "
    "PRIMARY KEY(context_id,position))",
    "CREATE TABLE external_provenance (context_id TEXT NOT NULL REFERENCES external_contexts(id), "
    "position INTEGER NOT NULL CHECK(position>=0), payload TEXT NOT NULL, digest TEXT NOT NULL, "
    "PRIMARY KEY(context_id,position))",
    "CREATE TABLE external_assessment_runs (id TEXT PRIMARY KEY, context_id TEXT NOT NULL "
    "REFERENCES external_contexts(id), incident_id TEXT NOT NULL "
    "REFERENCES incidents(incident_id), "
    "payload TEXT NOT NULL, digest TEXT NOT NULL)",
    "CREATE TABLE external_receipts (id TEXT PRIMARY KEY, run_id TEXT NOT NULL UNIQUE REFERENCES "
    "external_assessment_runs(id), context_id TEXT NOT NULL REFERENCES external_contexts(id), "
    "payload TEXT NOT NULL, digest TEXT NOT NULL)",
    "CREATE TABLE external_decision_receipts (id TEXT PRIMARY KEY, receipt_id TEXT NOT NULL "
    "REFERENCES external_receipts(id), decision_id TEXT NOT NULL UNIQUE, "
    "payload TEXT NOT NULL, digest TEXT NOT NULL)",
    "CREATE INDEX external_context_incident ON external_contexts(incident_id)",
    "CREATE INDEX external_run_incident ON external_assessment_runs(incident_id)",
)


def legacy_schema_digest(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE tbl_name NOT LIKE 'external_%' "
        "ORDER BY type,name"
    ).fetchall()
    return content_digest_payload({"schema": [list(row) for row in rows]})


def validate_schema(
    connection: sqlite3.Connection,
    *,
    version: int = 15,
    extra_statements: tuple[str, ...] = (),
    purpose: str = "ISOLATED_VALIDATION_ONLY",
) -> None:
    if connection.execute("PRAGMA user_version").fetchone()[0] != version:
        raise UnsupportedSchemaError("External context storage requires exact schema v15")
    # Exact DDL comparison, not a broad numeric allowlist or table-presence check.
    for statement in (*STATEMENTS, *extra_statements):
        name = statement.split()[2]
        row = connection.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone()
        if row is None or row[0] != statement:
            raise StoredDataError("External companion schema mismatch")
    names = connection.execute(
        "SELECT name FROM sqlite_master WHERE sql IS NOT NULL AND "
        "(name LIKE 'external_%' OR tbl_name LIKE 'external_%')"
    ).fetchall()
    if {row[0] for row in names} != {s.split()[2] for s in (*STATEMENTS, *extra_statements)}:
        raise StoredDataError("Unexpected external companion schema")
    row = connection.execute("SELECT * FROM external_metadata").fetchall()
    if len(row) != 1 or tuple(row[0]) != (
        1,
        "soc-external-storage:v2",
        purpose,
        legacy_schema_digest(connection),
    ):
        raise StoredDataError("External storage metadata mismatch")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise StoredDataError("Persistent foreign key violation")


class ExternalDatabase(GovernanceDatabase):
    """Same secure connection, transaction, rollback and sidecar boundary; no v14 bypass."""

    def _metadata(self, connection: sqlite3.Connection) -> UUID:
        validate_schema(connection)
        rows = connection.execute("SELECT store_id FROM metadata WHERE singleton=1").fetchall()
        try:
            if len(rows) != 1:
                raise ValueError
            return UUID(rows[0][0])
        except (ValueError, TypeError) as error:
            raise StoredDataError("Invalid external store identity") from error


@dataclass(frozen=True, init=False)
class ValidationWorkspace:
    """Issued only for an exclusively created directory; existing/operator DB paths rejected."""

    legacy: SQLiteGovernanceStore
    path: Path

    @classmethod
    def create(cls, directory: Path) -> "ValidationWorkspace":
        directory = Path(directory)
        if not directory.is_absolute() or directory.exists() or directory.is_symlink():
            raise ValueError(
                "A new isolated validation directory is required; existing paths refused"
            )
        create_private_directory(directory, exist_ok=False)
        path = directory / "external-validation.sqlite"
        legacy = open_application_store(path, create=True)
        with legacy.database.transaction(write=False) as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] != 14:
                raise UnsupportedSchemaError("Actual application schema is not v14")
        result = object.__new__(cls)
        object.__setattr__(result, "legacy", legacy)
        object.__setattr__(result, "path", path)
        return result


def migrate_validation_workspace(workspace: ValidationWorkspace) -> ExternalDatabase:
    """No arbitrary-path migration API; do not migrate an operator or user incident database."""
    if (
        type(workspace) is not ValidationWorkspace
        or workspace.path != workspace.legacy.database.path
    ):
        raise ValueError("Invalid isolated validation workspace")
    # Idempotent validation for a previously migrated workspace without relaxing legacy Reader.
    with guard_directory(workspace.path.parent):
        connection = workspace.legacy.database._connect()
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            workspace.legacy.database._permissions()
        finally:
            connection.close()
    if version == 15:
        return ExternalDatabase(workspace.path)
    if version != 14:
        raise UnsupportedSchemaError("External migration requires exact schema v14")
    with workspace.legacy.database.transaction() as connection:
        fingerprint = legacy_schema_digest(connection)
        for statement in STATEMENTS:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO external_metadata VALUES (1,?,?,?)",
            (
                "soc-external-storage:v2",
                "ISOLATED_VALIDATION_ONLY",
                fingerprint,
            ),
        )
        connection.execute("PRAGMA user_version=15")
        validate_schema(connection)
    return ExternalDatabase(workspace.path)

"""Explicit runtime schema v16 extends v15 without changing legacy payloads or readers."""

import sqlite3
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from soc_agent.review.identity import content_digest, state_fingerprint
from soc_agent.review.models import StateAnchor, StoredIncident
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import GovernanceEvent, StoredDataError
from soc_agent.review.persistence.session import GovernanceSession
from soc_agent.review.persistence.store import SQLiteGovernanceStore
from soc_agent.security_ai.external.models import Hash, Snapshot
from soc_agent.security_ai.external.records import ResumeRequirement
from soc_agent.security_ai.external.storage_schema import (
    ExternalDatabase,
    ValidationWorkspace,
    migrate_validation_workspace,
    validate_schema,
)
from soc_agent.state import Evidence
from soc_agent.state.evidence import UTCTimestamp, utc_now

DDL = (
    "CREATE TABLE external_runtime_requirements (incident_id TEXT PRIMARY KEY "
    "REFERENCES incidents(incident_id), payload TEXT NOT NULL, digest TEXT NOT NULL)",
    "CREATE TABLE external_runtime_incidents (incident_id TEXT PRIMARY KEY "
    "REFERENCES incidents(incident_id), payload TEXT NOT NULL, digest TEXT NOT NULL)",
    "CREATE TABLE external_runtime_publications (run_id TEXT NOT NULL, revision INTEGER NOT NULL, "
    "incident_id TEXT NOT NULL REFERENCES external_runtime_incidents(incident_id), "
    "payload TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(run_id,revision))",
    "CREATE TABLE external_security_audit (sequence INTEGER PRIMARY KEY, "
    "payload TEXT NOT NULL, digest TEXT NOT NULL)",
)


class RuntimeRequirement(Snapshot):
    contract_version: Literal["soc-external-runtime-requirement:v1"] = (
        "soc-external-runtime-requirement:v1"
    )
    incident_id: UUID
    request_digest: Hash
    required_models: tuple[str, ...]
    status: Literal["PENDING", "FAILED", "ATTACHED"]


class RuntimeBinding(Snapshot):
    contract_version: Literal["soc-external-runtime-binding:v1"] = "soc-external-runtime-binding:v1"
    incident_id: UUID
    context_digest: Hash
    session_id: UUID
    allowed_tools: tuple[str, ...]


class Publication(Snapshot):
    contract_version: Literal["soc-external-runtime-publication:v1"] = (
        "soc-external-runtime-publication:v1"
    )
    incident_id: UUID
    run_id: UUID
    revision: int
    session_id: UUID
    context_digest: Hash
    checkpoint_digest: Hash
    trace_head: Hash
    assessment_input_anchor: StateAnchor | None = None
    assessment_request_digest: Hash | None = None
    requirement: ResumeRequirement | None = None


class SecurityAudit(Snapshot):
    contract_version: Literal["soc-backend-security-audit:v1"] = "soc-backend-security-audit:v1"
    sequence: int
    event_id: UUID
    code: str
    incident_id: UUID | None
    session_id: UUID | None
    context_digest: Hash | None
    previous_digest: Hash | None
    binding_digest: Hash | None = None
    publication_digest: Hash | None = None
    legacy_audit_head: Hash | None
    created_at: UTCTimestamp


def validate_audit(connection: sqlite3.Connection) -> None:
    previous = None
    for sequence, row in enumerate(
        connection.execute("SELECT * FROM external_security_audit ORDER BY sequence"), 1
    ):
        if sequence > 100_000:
            raise StoredDataError("Security audit capacity requires explicit archival")
        value = ledger.decode(SecurityAudit, row)
        if (
            value.sequence != sequence
            or row["sequence"] != sequence
            or value.previous_digest != previous
        ):
            raise StoredDataError("Security audit chain mismatch")
        if (
            value.legacy_audit_head is not None
            and not connection.execute(
                "SELECT 1 FROM audit_events WHERE digest=?", (value.legacy_audit_head,)
            ).fetchone()
        ):
            raise StoredDataError("Security audit legacy anchor mismatch")
        previous = row["digest"]


def audit(
    connection: sqlite3.Connection,
    code: str,
    binding: RuntimeBinding | None = None,
    *,
    binding_digest: str | None = None,
    publication_digest: str | None = None,
    incident_id: UUID | None = None,
) -> None:
    # Codes originate in trusted implementation, not exception text or client payloads.
    if not code.isupper() or len(code) > 64 or not code.replace("_", "").isalnum():
        raise StoredDataError("Invalid security audit code")
    last = connection.execute(
        "SELECT sequence,digest FROM external_security_audit ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    legacy = connection.execute(
        "SELECT digest FROM audit_events ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    value = SecurityAudit(
        sequence=last[0] + 1 if last else 1,
        event_id=uuid4(),
        code=code,
        incident_id=binding.incident_id if binding else incident_id,
        session_id=binding.session_id if binding else None,
        context_digest=binding.context_digest if binding else None,
        previous_digest=last[1] if last else None,
        legacy_audit_head=legacy[0] if legacy else None,
        created_at=utc_now(),
        binding_digest=binding_digest,
        publication_digest=publication_digest,
    )
    connection.execute(
        "INSERT INTO external_security_audit VALUES (?,?,?)",
        (value.sequence, ledger.serialize(value), content_digest(value)),
    )


class RuntimeDatabase(ExternalDatabase):
    def _metadata(self, connection: sqlite3.Connection) -> UUID:
        validate_schema(connection, version=16, extra_statements=DDL, purpose="EXTERNAL_RUNTIME")
        validate_audit(connection)
        row = connection.execute("SELECT store_id FROM metadata WHERE singleton=1").fetchone()
        if row is None:
            raise StoredDataError("Runtime store identity missing")
        return UUID(row[0])

    def guard_mutation(self, incident_id: UUID | None, code: str) -> None:
        from soc_agent.security_ai.external.read_only_backend import CapabilityDenied

        with self.transaction() as connection:
            suffix = " WHERE incident_id=?" if incident_id else ""
            query = (
                "SELECT 1 FROM external_contexts" + suffix + " UNION "
                "SELECT 1 FROM external_runtime_requirements" + suffix + " LIMIT 1"
            )
            protected = connection.execute(
                query, (str(incident_id), str(incident_id)) if incident_id else ()
            ).fetchone()
            if protected:
                audit(connection, code)
        if protected:
            raise CapabilityDenied("Persistent external disposition prohibits mutation")

    def core_schema_version(self, connection: sqlite3.Connection) -> int:
        self._metadata(connection)
        return 14  # Exact validated unchanged legacy layout, not raw v16 numeric acceptance.


@dataclass
class EvidenceStage:
    incident_id: UUID
    expected: StateAnchor | None = None
    evidence: Evidence | None = None
    result: StoredIncident | None = None


class RuntimeGovernanceStore(SQLiteGovernanceStore):
    requires_external_runtime = True

    def __init__(self, path: Path) -> None:
        self.database = RuntimeDatabase(path)
        self.boundary = None
        self._stage: ContextVar[EvidenceStage | None] = ContextVar(
            "external_evidence_stage", default=None
        )

    def configure_backend(self, registry):
        from soc_agent.security_ai.external.runtime_guard import RuntimeBoundary

        if self.boundary is not None:
            if self.boundary.registry is not registry:
                raise ValueError("Runtime backend registry cannot be replaced")
            return self.boundary
        return RuntimeBoundary(self, registry)

    @classmethod
    def activate_validation_workspace(
        cls, workspace: ValidationWorkspace
    ) -> "RuntimeGovernanceStore":
        if type(workspace) is not ValidationWorkspace:
            raise ValueError("Only an explicitly issued isolated workspace may be activated")
        external = ExternalDatabase(workspace.path)
        with external.transaction() as connection:
            for statement in DDL:
                connection.execute(statement)
            connection.execute("UPDATE external_metadata SET purpose='EXTERNAL_RUNTIME'")
            connection.execute("PRAGMA user_version=16")
            validate_schema(
                connection, version=16, extra_statements=DDL, purpose="EXTERNAL_RUNTIME"
            )
        return cls(workspace.path)

    @classmethod
    def create_isolated(cls, directory: Path) -> "RuntimeGovernanceStore":
        workspace = ValidationWorkspace.create(directory)
        from soc_agent.ingestion import migrate_ingestion

        migrate_ingestion(workspace.legacy)
        migrate_validation_workspace(workspace)
        return cls.activate_validation_workspace(workspace)

    def append_evidence(self, expected: StateAnchor, evidence: Evidence) -> StoredIncident:
        stage = self._stage.get()
        if stage is None:
            if self.boundary is not None:
                self.boundary.mutation(expected.incident_id, "EVIDENCE_DIRECT")
            return super().append_evidence(expected, evidence)
        if expected.incident_id != stage.incident_id or stage.evidence is not None:
            raise StoredDataError("Invalid runtime evidence staging")
        current = super().load(expected.incident_id)
        if current.anchor != expected:
            raise StoredDataError("Runtime evidence CAS changed")
        evidence = Evidence.model_validate_json(evidence.model_dump_json())
        updated = current.state.add_evidence(evidence)
        result = StoredIncident(
            state=updated,
            anchor=StateAnchor(
                repository_id=self.store_id,
                incident_id=expected.incident_id,
                revision=expected.revision + 1,
                fingerprint=state_fingerprint(updated),
            ),
        )
        stage.expected, stage.evidence, stage.result = expected, evidence, result
        return result

    def append_assessment(self, expected, result):
        current = self.load(expected.incident_id)
        if result.incident_state != current.state:
            from soc_agent.execution.security import mutation_guard

            mutation_guard(self, expected.incident_id, "MODEL_FACT_PROMOTION")
        return super().append_assessment(expected, result)

    def flush_evidence(self, connection: sqlite3.Connection, stage: EvidenceStage) -> None:
        if stage.evidence is None:
            return
        session = GovernanceSession(connection, self.store_id)
        if session.load(stage.incident_id).anchor != stage.expected:
            raise StoredDataError("Staged evidence CAS mismatch")
        anchor = session.save_state(stage.expected, stage.result.state)
        if anchor != stage.result.anchor:
            raise StoredDataError("Staged evidence anchor mismatch")
        ledger.append_event(
            connection,
            GovernanceEvent(
                event_type="evidence_appended",
                incident_id=stage.incident_id,
                before=stage.expected,
                after=anchor,
            ),
        )

    def fault(self, point: str) -> None:
        """Explicit overridable fault boundary for isolated crash/rollback tests."""


def mutation_guard(store: SQLiteGovernanceStore, incident_id: UUID | None, code: str) -> None:
    boundary = getattr(store, "boundary", None)
    if boundary is not None:
        boundary.mutation(incident_id, code)

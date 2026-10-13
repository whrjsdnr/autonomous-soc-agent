"""Companion SQLite persistence and explicit lineage restore; never resumes the orchestrator."""

import sqlite3
from hashlib import sha256
from pathlib import Path

from pydantic import BaseModel, ValidationError

from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import GovernanceEvent, StoredDataError
from soc_agent.review.persistence.session import GovernanceSession
from soc_agent.security_ai.external.assembly import ExternalModelContext, assemble
from soc_agent.security_ai.external.inference import ModelRun
from soc_agent.security_ai.external.records import (
    AssessmentRun,
    DecisionReceipt,
    ProvenanceReceipt,
    ResumeRequirement,
)
from soc_agent.security_ai.external.storage_schema import ExternalDatabase


class ExternalContextStore:
    def __init__(self, path: Path, *, database: ExternalDatabase | None = None) -> None:
        if database is not None and database.path != Path(path):
            raise ValueError("Companion and runtime database paths must match")
        self.database = database if database is not None else ExternalDatabase(path)

    def _context(self, connection: sqlite3.Connection, context: ExternalModelContext) -> None:
        session = GovernanceSession(connection, self.database.store_id)
        session.restore_service()  # Existing issuance graph, not a newly issued capability.
        for row in connection.execute("SELECT * FROM audit_events ORDER BY sequence"):
            event = ledger.decode(GovernanceEvent, row)
            if str(event.event_id) != row["event_id"] or event.event_type != row["event_type"]:
                raise StoredDataError("Existing audit columns mismatch")
        context = ExternalModelContext.model_validate_json(ledger.serialize(context))
        if context.input_snapshot is None:
            raise StoredDataError("Incident context requires a retained source snapshot")
        snapshot = GovernanceSession(connection, self.database.store_id).snapshot(
            context.input_snapshot
        )
        models = {r.binding.binding_id: r for r in (*context.results, *context.unlinked_results)}
        if len(models) != len(context.results) + len(context.unlinked_results):
            raise StoredDataError("Duplicate model binding")
        runs = []
        seen = set()
        for coverage in context.coverage:
            if coverage.binding_id in seen:
                raise StoredDataError("Duplicate coverage binding")
            seen.add(coverage.binding_id)
            if coverage.status == "UNAVAILABLE" and coverage.binding_id not in models:
                continue  # Preserve unavailable metadata only; no prediction or authority.
            if coverage.status != "AVAILABLE" or coverage.binding_id not in models:
                raise StoredDataError("Coverage/result binding mismatch")
            result = models.pop(coverage.binding_id)
            runs.append(
                ModelRun(
                    binding=result.binding,
                    required=True,
                    status="AVAILABLE",
                    code="OK",
                    result=result,
                )
            )
        if models:
            raise StoredDataError("Context result lacks coverage")
        if runs:
            rebuilt = assemble(tuple(runs), incident=snapshot)
            expected = context.model_dump(exclude={"context_digest", "coverage"})
            if rebuilt.model_dump(exclude={"context_digest", "coverage"}) != expected:
                raise StoredDataError("Context assembly or source validation mismatch")
        elif context.results or context.unlinked_results or context.correlation_groups:
            raise StoredDataError("Unavailable context contains model output")

    @staticmethod
    def _put(
        connection: sqlite3.Connection,
        table: str,
        columns: tuple[str, ...],
        values: tuple[str, ...],
    ) -> None:
        # Identifiers are static internal constants, never request fields.
        payload = values[columns.index("payload")]
        if len(payload.encode("utf-8")) > 1024 * 1024:
            raise StoredDataError("Companion record size limit")
        row = connection.execute(f"SELECT * FROM {table} WHERE id=?", (values[0],)).fetchone()
        if row is not None:
            if tuple(row) != values:
                raise StoredDataError("Companion identity/content conflict")
            return
        placeholders = ",".join("?" for _ in values)
        connection.execute(
            f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})", values
        )

    @staticmethod
    def _parts(context: ExternalModelContext) -> tuple[tuple[str, ...], tuple[str, ...]]:
        observations = {
            r.observation.observation_key: r.observation
            for r in (*context.results, *context.unlinked_results)
        }
        sources = tuple(
            ledger.serialize(observation) for _, observation in sorted(observations.items())
        )
        provenance = tuple(
            ledger.serialize(result) for result in (*context.results, *context.unlinked_results)
        )
        return sources, provenance

    def _save_context(self, connection: sqlite3.Connection, context: ExternalModelContext) -> None:
        self._context(connection, context)
        if connection.execute(
            "SELECT id FROM external_contexts WHERE id=?", (context.context_digest,)
        ).fetchone():
            if self._load_context(connection, context.context_digest) != context:
                raise StoredDataError("Context replay conflict")
            return
        self._put(
            connection,
            "external_contexts",
            ("id", "incident_id", "payload", "digest"),
            (
                context.context_digest,
                str(context.input_snapshot.incident_id),
                ledger.serialize(context),
                content_digest(context),
            ),
        )
        sources, provenance = self._parts(context)
        for table, payloads in (("external_sources", sources), ("external_provenance", provenance)):
            rows = connection.execute(
                f"SELECT * FROM {table} WHERE context_id=? ORDER BY position LIMIT 17",
                (context.context_digest,),
            ).fetchall()
            expected = [
                (
                    context.context_digest,
                    i,
                    payload,
                    sha256(payload.encode("utf-8")).hexdigest(),
                )
                for i, payload in enumerate(payloads)
            ]
            if rows:
                if [tuple(row) for row in rows] != expected:
                    raise StoredDataError("Companion reference conflict")
            else:
                connection.executemany(f"INSERT INTO {table} VALUES (?,?,?,?)", expected)

    def save_context(self, context: ExternalModelContext) -> None:
        context = ExternalModelContext.model_validate_json(ledger.serialize(context))
        if context.input_snapshot is None:
            raise StoredDataError("Missing context source snapshot")
        with self.database.transaction() as connection:
            current = GovernanceSession(connection, self.database.store_id).load(
                context.input_snapshot.incident_id
            )
            if current.anchor != context.input_snapshot:
                raise StoredDataError("Context publication snapshot is stale")
            self._save_context(connection, context)

    def _read[T: BaseModel](
        self, connection: sqlite3.Connection, table: str, identity: str, model: type[T]
    ) -> T:
        size = connection.execute(
            f"SELECT length(CAST(payload AS BLOB)) FROM {table} WHERE id=?", (identity,)
        ).fetchone()
        if size is None or size[0] > 1024 * 1024:
            raise StoredDataError("Required companion record missing or oversized")
        row = connection.execute(f"SELECT * FROM {table} WHERE id=?", (identity,)).fetchone()
        if row is None or len(row["payload"].encode("utf-8")) > 1024 * 1024:
            raise StoredDataError("Required companion record missing or oversized")
        try:
            result = model.model_validate_json(row["payload"])
            if (
                ledger.serialize(result) != row["payload"]
                or content_digest(result) != row["digest"]
            ):
                raise ValueError
            return result
        except (ValidationError, ValueError, TypeError):
            raise StoredDataError("Invalid companion record; resume refused") from None

    def _load_context(self, connection: sqlite3.Connection, digest: str) -> ExternalModelContext:
        context = self._read(connection, "external_contexts", digest, ExternalModelContext)
        if context.context_digest != digest:
            raise StoredDataError("Context identity mismatch")
        self._context(connection, context)
        row = connection.execute(
            "SELECT incident_id FROM external_contexts WHERE id=?", (digest,)
        ).fetchone()
        if row[0] != str(context.input_snapshot.incident_id):
            raise StoredDataError("Context incident mismatch")
        sources, provenance = self._parts(context)

        for table, values in (("external_sources", sources), ("external_provenance", provenance)):
            rows = connection.execute(
                f"SELECT * FROM {table} WHERE context_id=? ORDER BY position LIMIT 17", (digest,)
            ).fetchall()
            expected = [
                (digest, i, payload, sha256(payload.encode("utf-8")).hexdigest())
                for i, payload in enumerate(values)
            ]
            if [tuple(r) for r in rows] != expected:
                raise StoredDataError("Required references/provenance missing or changed")
        return context

    def load_context(self, digest: str) -> ExternalModelContext:
        with self.database.transaction(write=False) as connection:
            return self._load_context(connection, digest)

    def _bundle(
        self,
        connection: sqlite3.Connection,
        context: ExternalModelContext,
        run: AssessmentRun,
        receipt: ProvenanceReceipt,
        decision: DecisionReceipt | None,
    ) -> None:
        session = GovernanceSession(connection, self.database.store_id)
        source = session.snapshot(run.input_anchor)
        output = session.snapshot(run.output_anchor)
        if (
            run.output_anchor.revision < run.input_anchor.revision
            or run.input_anchor != context.input_snapshot
            or run.context_digest != context.context_digest
            or run.incident_id != source.state.incident_id
            or run.incident_id != output.state.incident_id
            or run.core_result.incident_state != output.state
            or run.assessment_reference != run.core_result.threat_assessment.assessment_id
            or run.created_at < run.core_result.threat_assessment.created_at
            or receipt.context_digest != context.context_digest
            or receipt.assessment_run_id != run.run_id
            or receipt.input_anchor != run.input_anchor
            or receipt.output_anchor != run.output_anchor
            or receipt.assessment_digest != content_digest(run.core_result.threat_assessment)
        ):
            raise StoredDataError("Assessment run/context/receipt binding mismatch")
        references = {
            content_digest(ref): ref
            for result in context.results
            for ref in result.observation.association.source_evidence_references
        }
        if tuple(sorted(content_digest(r) for r in receipt.source_evidence_references)) != tuple(
            sorted(references)
        ):
            raise StoredDataError("Receipt source evidence mismatch")
        from soc_agent.assessment import FusionAssessmentResult

        fusion_digest = (
            content_digest(run.core_result.model_derived_context)
            if isinstance(run.core_result, FusionAssessmentResult)
            else None
        )
        if receipt.fusion_digest != fusion_digest:
            raise StoredDataError("Receipt Fusion binding mismatch")
        if decision is not None:
            from soc_agent.review.validation import validate_decision

            validate_decision(output.state, decision.core_decision)
            if (
                decision.assessment_run_id != run.run_id
                or decision.assessment_receipt_id != receipt.receipt_id
                or decision.context_digest != context.context_digest
                or decision.input_anchor != run.input_anchor
                or decision.output_anchor != run.output_anchor
                or decision.core_decision.incident_id != run.incident_id
                or decision.core_decision.assessment != run.core_result.threat_assessment
                or decision.decision_digest != content_digest(decision.core_decision)
            ):
                raise StoredDataError("Decision provenance binding mismatch")

    def save_bundle(
        self,
        context: ExternalModelContext,
        run: AssessmentRun,
        receipt: ProvenanceReceipt,
        decision: DecisionReceipt | None = None,
    ) -> None:
        with self.database.transaction() as connection:
            self.save_bundle_in_transaction(connection, context, run, receipt, decision)

    def save_bundle_in_transaction(
        self,
        connection: sqlite3.Connection,
        context: ExternalModelContext,
        run: AssessmentRun,
        receipt: ProvenanceReceipt,
        decision: DecisionReceipt | None = None,
    ) -> None:
        """Composition API for future single-session publication, without nested commits.

        Use only within this database's secure transaction context. This API does not
        append the core assessment or publish a workflow checkpoint itself.
        """
        self.database._permissions()
        rows = connection.execute("PRAGMA database_list").fetchall()
        main = [row for row in rows if row[1] == "main"]
        if (
            not connection.in_transaction
            or len(main) != 1
            or Path(main[0][2]) != self.database.path
            or self.database._metadata(connection) != self.database.store_id
        ):
            raise StoredDataError("A matching secure external transaction is required")
        # JSON round-trip defeats unvalidated model_copy, including nested legacy models.
        context = ExternalModelContext.model_validate_json(ledger.serialize(context))
        run = AssessmentRun.model_validate_json(ledger.serialize(run))
        receipt = ProvenanceReceipt.model_validate_json(ledger.serialize(receipt))
        if decision is not None:
            decision = DecisionReceipt.model_validate_json(ledger.serialize(decision))
        self._bundle(connection, context, run, receipt, decision)
        if connection.execute(
            "SELECT id FROM external_assessment_runs WHERE id=?", (str(run.run_id),)
        ).fetchone():
            previous = self._read(
                connection, "external_receipts", str(receipt.receipt_id), ProvenanceReceipt
            )
            if previous != receipt:
                raise StoredDataError("Receipt replay conflict")
        if (
            GovernanceSession(connection, self.database.store_id).load(run.incident_id).anchor
            != run.output_anchor
        ):
            raise StoredDataError("Assessment output snapshot is stale")
        self._save_context(connection, context)
        self._put(
            connection,
            "external_assessment_runs",
            ("id", "context_id", "incident_id", "payload", "digest"),
            (
                str(run.run_id),
                context.context_digest,
                str(run.incident_id),
                ledger.serialize(run),
                content_digest(run),
            ),
        )
        self._put(
            connection,
            "external_receipts",
            ("id", "run_id", "context_id", "payload", "digest"),
            (
                str(receipt.receipt_id),
                str(run.run_id),
                context.context_digest,
                ledger.serialize(receipt),
                content_digest(receipt),
            ),
        )
        if decision is not None:
            self._put(
                connection,
                "external_decision_receipts",
                ("id", "receipt_id", "decision_id", "payload", "digest"),
                (
                    str(decision.receipt_id),
                    str(receipt.receipt_id),
                    decision.core_decision.decision_id,
                    ledger.serialize(decision),
                    content_digest(decision),
                ),
            )

    def resume(
        self, expected: ResumeRequirement
    ) -> tuple[ExternalModelContext, AssessmentRun, ProvenanceReceipt, DecisionReceipt | None]:
        """Return verified stored lineage only; no step execution, approval or automatic retry."""
        expected = ResumeRequirement.model_validate_json(ledger.serialize(expected))
        with self.database.transaction(write=False) as connection:
            context = self._load_context(connection, expected.context_digest)
            run = self._read(
                connection, "external_assessment_runs", str(expected.run_id), AssessmentRun
            )
            receipt = self._read(
                connection, "external_receipts", str(expected.receipt_id), ProvenanceReceipt
            )
            decision = None
            if expected.decision_receipt_id is not None:
                decision = self._read(
                    connection,
                    "external_decision_receipts",
                    str(expected.decision_receipt_id),
                    DecisionReceipt,
                )
                if content_digest(decision) != expected.decision_receipt_digest:
                    raise StoredDataError("Decision receipt digest mismatch")
                link = connection.execute(
                    "SELECT receipt_id,decision_id FROM external_decision_receipts WHERE id=?",
                    (str(expected.decision_receipt_id),),
                ).fetchone()
                if tuple(link) != (str(receipt.receipt_id), decision.core_decision.decision_id):
                    raise StoredDataError("Decision receipt relational mismatch")
            elif expected.decision_receipt_digest is not None:
                raise StoredDataError("Incomplete decision resume reference")
            elif connection.execute(
                "SELECT id FROM external_decision_receipts WHERE receipt_id=?",
                (str(receipt.receipt_id),),
            ).fetchone():
                raise StoredDataError("Required decision receipt omitted")
            if (
                run.run_id != expected.run_id
                or run.incident_id != expected.incident_id
                or run.input_anchor != expected.input_anchor
                or run.output_anchor != expected.output_anchor
                or receipt.receipt_id != expected.receipt_id
                or content_digest(receipt) != expected.receipt_digest
            ):
                raise StoredDataError("Expected resume lineage mismatch")
            self._bundle(connection, context, run, receipt, decision)
            if (
                GovernanceSession(connection, self.database.store_id).load(run.incident_id).anchor
                != run.output_anchor
            ):
                raise StoredDataError("Resume output snapshot is stale")
            # Validate relational columns independently of canonical record payloads.
            row = connection.execute(
                "SELECT context_id,incident_id FROM external_assessment_runs WHERE id=?",
                (str(run.run_id),),
            ).fetchone()
            link = connection.execute(
                "SELECT run_id,context_id FROM external_receipts WHERE id=?",
                (str(receipt.receipt_id),),
            ).fetchone()
            if tuple(row) != (run.context_digest, str(run.incident_id)) or tuple(link) != (
                str(run.run_id),
                run.context_digest,
            ):
                raise StoredDataError("Persistent companion links mismatch")
            return context, run, receipt, decision

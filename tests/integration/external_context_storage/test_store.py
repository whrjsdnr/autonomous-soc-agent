"""Real secure SQLite v14/v15 files; synthetic supplied outputs, no model/LLM execution."""

import sqlite3
from uuid import UUID

import pytest
from tests.unit.security_ai.external.conftest import case

from soc_agent.assessment import AssessmentResult, ThreatAssessment
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.models import (
    StorageError,
    StoredDataError,
    UnsupportedSchemaError,
)
from soc_agent.security_ai.external.adapters import ExternalEvidenceAdapter
from soc_agent.security_ai.external.assembly import assemble
from soc_agent.security_ai.external.inference import ModelRun
from soc_agent.security_ai.external.records import (
    AssessmentRun,
    ProvenanceReceipt,
    ResumeRequirement,
)
from soc_agent.security_ai.external.storage import ExternalContextStore
from soc_agent.security_ai.external.storage_schema import (
    ValidationWorkspace,
    migrate_validation_workspace,
)


@pytest.fixture
def workspace(tmp_path):
    return ValidationWorkspace.create(tmp_path / "v15 isolated Unicode 한글")


@pytest.fixture(params=["detection_quality", "edge", "litert", "both"])
def bundle(workspace, request):
    envelope, kwargs = case.__wrapped__()(
        "detection_quality" if request.param == "both" else request.param
    )
    legacy = workspace.legacy
    stored = legacy.register(kwargs["incident"].state)
    observation = kwargs["observation"].model_copy(
        update={
            "association": kwargs["observation"].association.model_copy(
                update={"snapshot": stored.anchor}
            )
        }
    )
    provenance = kwargs["provenance"].model_copy(
        update={"observation_digest": content_digest(observation)}
    )
    kwargs.update(observation=observation, provenance=provenance, incident=stored)
    result = ExternalEvidenceAdapter().adapt(envelope, **kwargs).result
    assert result is not None
    context = assemble(
        (
            ModelRun(
                binding=kwargs["binding"],
                required=True,
                status="AVAILABLE",
                code="OK",
                result=result,
            ),
        ),
        incident=stored,
    )
    if request.param == "both":
        edge_envelope, edge = case.__wrapped__()("edge")
        edge.update(observation=observation, incident=stored)
        edge["provenance"] = edge["provenance"].model_copy(
            update={"observation_digest": content_digest(observation)}
        )
        second = ExternalEvidenceAdapter().adapt(edge_envelope, **edge).result
        assert second is not None
        context = assemble(
            (
                ModelRun(
                    binding=kwargs["binding"],
                    required=True,
                    status="AVAILABLE",
                    code="OK",
                    result=result,
                ),
                ModelRun(
                    binding=edge["binding"],
                    required=True,
                    status="AVAILABLE",
                    code="OK",
                    result=second,
                ),
            ),
            incident=stored,
        )
    assessment = ThreatAssessment(
        assessment_id=UUID(int=20),
        incident_id=stored.state.incident_id,
        severity="low",
        confidence=0.1,
        summary="Synthetic supplied output for persistence contract test only",
        supporting_evidence_ids=(stored.state.evidence[0].evidence_id,),
        created_at=stored.state.created_at,
    )
    core = AssessmentResult(incident_state=stored.state, threat_assessment=assessment)
    # Existing no-op append contract remains unchanged and leaves the same revision.
    assert legacy.append_assessment(stored.anchor, core) == stored
    run = AssessmentRun(
        run_id=UUID(int=21),
        incident_id=stored.state.incident_id,
        input_anchor=stored.anchor,
        output_anchor=stored.anchor,
        context_digest=context.context_digest,
        core_result=core,
        assessment_reference=assessment.assessment_id,
        created_at=assessment.created_at,
    )
    receipt = ProvenanceReceipt(
        receipt_id=UUID(int=22),
        context_digest=context.context_digest,
        assessment_run_id=run.run_id,
        input_anchor=run.input_anchor,
        output_anchor=run.output_anchor,
        assessment_digest=content_digest(assessment),
        request_projection_digest="1" * 64,
        source_evidence_references=observation.association.source_evidence_references,
    )
    expected = ResumeRequirement(
        run_id=run.run_id,
        incident_id=run.incident_id,
        context_digest=context.context_digest,
        receipt_id=receipt.receipt_id,
        receipt_digest=content_digest(receipt),
        input_anchor=run.input_anchor,
        output_anchor=run.output_anchor,
    )
    migrate_validation_workspace(workspace)
    return ExternalContextStore(workspace.path), context, run, receipt, expected


def test_v14_to_v15_empty_idempotent_legacy_blocked(workspace):
    with workspace.legacy.database.transaction(write=False) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 14
        before = tuple(connection.execute("SELECT * FROM metadata").fetchone())
    database = migrate_validation_workspace(workspace)
    migrate_validation_workspace(workspace)
    with database.transaction(write=False) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 15
        assert tuple(connection.execute("SELECT * FROM metadata").fetchone()) == before
    # Actual unmodified legacy binary Reader, not a mocked version-number check.
    with pytest.raises(UnsupportedSchemaError):
        SQLiteGovernanceStore(workspace.path)
    with pytest.raises(UnsupportedSchemaError):
        workspace.legacy.load(UUID(int=1))


def test_existing_paths_refused(tmp_path):
    with pytest.raises(ValueError, match="existing paths refused"):
        ValidationWorkspace.create(tmp_path)


def test_roundtrip_bundle_noop_and_reopen(bundle):
    store, context, run, receipt, expected = bundle
    store.save_bundle(context, run, receipt)
    assert ExternalContextStore(store.database.path).resume(expected) == (
        context,
        run,
        receipt,
        None,
    )
    store.save_bundle(context, run, receipt)  # Exact replay idempotent.
    with store.database.transaction(write=False) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM external_assessment_runs").fetchone()[0] == 1
        )
        assert connection.execute("SELECT revision FROM incidents").fetchone()[0] == 0
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM audit_events WHERE event_type='assessment_appended'"
            ).fetchone()[0]
            == 0
        )
        assert connection.execute("SELECT COUNT(*) FROM authorizations").fetchone()[0] == 0
    assert store.load_context(context.context_digest) == context


@pytest.mark.parametrize(
    "point", ["context", "references", "receipt_before", "run_after", "commit"]
)
def test_atomic_fault_reopen(bundle, monkeypatch, point):
    store, context, run, receipt, expected = bundle
    original = store._put

    def put(connection, table, columns, values):
        if point == "receipt_before" and table == "external_receipts":
            raise RuntimeError("FAULT")
        original(connection, table, columns, values)
        if (point == "context" and table == "external_contexts") or (
            point == "run_after" and table == "external_assessment_runs"
        ):
            raise RuntimeError("FAULT")

    monkeypatch.setattr(store, "_put", put)
    if point == "references":
        save = store._save_context

        def failed(connection, value):
            save(connection, value)
            raise RuntimeError("FAULT")

        monkeypatch.setattr(store, "_save_context", failed)
    if point == "commit":
        monkeypatch.setattr(
            store.database,
            "_commit",
            lambda connection: (_ for _ in ()).throw(sqlite3.OperationalError("FAULT")),
        )
    with pytest.raises((RuntimeError, StorageError), match="FAULT|Commit failed"):
        store.save_bundle(context, run, receipt)
    reopened = ExternalContextStore(store.database.path)
    with reopened.database.transaction(write=False) as connection:
        for table in (
            "external_contexts",
            "external_sources",
            "external_provenance",
            "external_assessment_runs",
            "external_receipts",
        ):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    with pytest.raises(StoredDataError):
        reopened.resume(expected)


@pytest.mark.parametrize(
    "table",
    [
        "external_contexts",
        "external_sources",
        "external_provenance",
        "external_assessment_runs",
        "external_receipts",
    ],
)
def test_missing_or_modified_records_reject_resume(bundle, table):
    store, context, run, receipt, expected = bundle
    store.save_bundle(context, run, receipt)
    # Deliberate corruption through raw SQLite, not the protected application API.
    connection = sqlite3.connect(store.database.path)
    try:
        connection.execute(f"UPDATE {table} SET digest=?", ("0" * 64,))
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(StoredDataError):
        ExternalContextStore(store.database.path).resume(expected)


@pytest.mark.parametrize(
    "field", ["incident_id", "context_digest", "receipt_digest", "receipt_id", "run_id"]
)
def test_wrong_expected_resume_refused(bundle, field):
    store, context, run, receipt, expected = bundle
    store.save_bundle(context, run, receipt)
    value = "0" * 64 if "digest" in field else UUID(int=99)
    with pytest.raises(StoredDataError):
        store.resume(expected.model_copy(update={field: value}))


def test_migration_failure_rolls_back(workspace, monkeypatch):
    import soc_agent.security_ai.external.storage_schema as schema

    statements = schema.STATEMENTS
    monkeypatch.setattr(schema, "STATEMENTS", (*statements[:2], "INVALID SQL"))
    with pytest.raises(StorageError):
        migrate_validation_workspace(workspace)
    with GovernanceDatabase(workspace.path).transaction(write=False) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 14
        assert not connection.execute(
            "SELECT name FROM sqlite_master WHERE name LIKE 'external_%'"
        ).fetchall()


def test_unknown_version_and_schema_corruption(bundle):
    store, _, _, _, _ = bundle
    connection = sqlite3.connect(store.database.path)
    connection.execute("PRAGMA user_version=16")
    connection.close()
    with pytest.raises(UnsupportedSchemaError):
        ExternalContextStore(store.database.path)


@pytest.mark.parametrize(
    "table",
    [
        "external_contexts",
        "external_sources",
        "external_provenance",
        "external_assessment_runs",
        "external_receipts",
    ],
)
def test_deleted_lineage_fails_closed(bundle, table):
    store, context, run, receipt, expected = bundle
    store.save_bundle(context, run, receipt)
    with sqlite3.connect(store.database.path) as connection:
        connection.execute(f"DELETE FROM {table}")
    with pytest.raises(StoredDataError):
        ExternalContextStore(store.database.path).resume(expected)


@pytest.mark.parametrize(
    "kind", ["receipt_status", "context_version", "anchor", "assessment_id", "extra_field"]
)
def test_payload_tamper_and_invalid_status(bundle, kind):
    import json

    store, context, run, receipt, expected = bundle
    store.save_bundle(context, run, receipt)
    table = "external_assessment_runs"
    with sqlite3.connect(store.database.path) as connection:
        row = connection.execute(f"SELECT id,payload FROM {table}").fetchone()
        data = json.loads(row[1])
        if kind == "receipt_status":
            data["validation_status"] = "APPROVED"
        elif kind == "context_version":
            data["contract_version"] = "unknown"
        elif kind == "anchor":
            data["output_anchor"]["fingerprint"] = "0" * 64
        elif kind == "assessment_id":
            data["assessment_reference"] = str(UUID(int=999))
        else:
            data["approval"] = "forged"
        connection.execute(f"UPDATE {table} SET payload=? WHERE id=?", (json.dumps(data), row[0]))
    with pytest.raises(StoredDataError):
        store.resume(expected)


def test_schema_protection_and_legacy_checkpoint_reader(bundle):
    from soc_agent.investigation.runtime.persistence import CheckpointStore

    store, context, run, receipt, expected = bundle
    store.save_bundle(context, run, receipt)
    # Neither raw old-store reopening nor legacy checkpoint constructor accepts v15.
    legacy = SQLiteGovernanceStore.__new__(SQLiteGovernanceStore)
    legacy.database = store.database
    with pytest.raises(UnsupportedSchemaError):
        CheckpointStore(legacy)
    with sqlite3.connect(store.database.path) as connection:
        connection.execute("DROP INDEX external_run_incident")
    with pytest.raises(StoredDataError):
        ExternalContextStore(store.database.path)


def test_noop_legacy_data_exactly_preserved(bundle):
    store, context, run, receipt, expected = bundle
    with store.database.transaction(write=False) as connection:
        before = {
            table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table}")]
            for table in (
                "incidents",
                "snapshots",
                "decisions",
                "review_requests",
                "reviews",
                "authorizations",
                "applications",
                "audit_events",
            )
        }
    store.save_bundle(context, run, receipt)
    with store.database.transaction(write=False) as connection:
        after = {
            table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table}")]
            for table in before
        }
    assert after == before


def test_normal_append_assessment_contract(workspace):
    from soc_agent.state import Observation

    _, kwargs = case.__wrapped__()()
    stored = workspace.legacy.register(kwargs["incident"].state)
    evidence_id = stored.state.evidence[0].evidence_id
    state = stored.state.add_observation(
        Observation(
            statement="Synthetic source record exists",
            supporting_evidence_ids=(evidence_id,),
            created_at=stored.state.updated_at,
        )
    )
    assessment = ThreatAssessment(
        incident_id=state.incident_id,
        severity="low",
        confidence=0.1,
        summary="Test only",
        supporting_evidence_ids=(evidence_id,),
        created_at=state.updated_at,
    )
    result = AssessmentResult(incident_state=state, threat_assessment=assessment)
    output = workspace.legacy.append_assessment(stored.anchor, result)
    assert output.anchor.revision == stored.anchor.revision + 1
    assert workspace.legacy.load(state.incident_id) == output
    before = workspace.legacy.events()
    database = migrate_validation_workspace(workspace)
    from soc_agent.review.persistence.session import GovernanceSession

    with database.transaction(write=False) as connection:
        assert GovernanceSession(connection, database.store_id).load(state.incident_id) == output
        rows = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        assert rows == len(before)


def test_insecure_path_rejected(tmp_path):
    import os

    from soc_agent.review.persistence.secure_storage import StorageSecurityError

    workspace = ValidationWorkspace.create(tmp_path / "permission case")
    if os.name == "posix":
        workspace.path.chmod(0o644)
        with pytest.raises(StorageSecurityError):
            GovernanceDatabase(workspace.path)
    else:
        from tests.unit.persistence.test_native_windows_storage import restore_dacl, set_dacl

        from soc_agent.review.persistence.windows_storage import NativeWin32

        api = NativeWin32()
        try:
            set_dacl(api, workspace.path, f"D:P(A;;FA;;;{api.user})(A;;FA;;;WD)")
            with pytest.raises(StorageSecurityError):
                GovernanceDatabase(workspace.path)
        finally:
            restore_dacl(api, workspace.path, directory=False)


def test_legacy_audit_tamper_rejects(bundle):
    store, context, run, receipt, expected = bundle
    store.save_bundle(context, run, receipt)
    with sqlite3.connect(store.database.path) as connection:
        connection.execute("UPDATE audit_events SET digest=?", ("0" * 64,))
    with pytest.raises(StoredDataError):
        store.resume(expected)


def test_decision_receipt_and_omission_guard(bundle):
    # Synthetic existing core-engine fixture; not a new operational decision workflow.
    from soc_agent.decision import IncidentDecisionEngine
    from soc_agent.security_ai.external.records import DecisionReceipt

    store, context, run, receipt, expected = bundle
    core = IncidentDecisionEngine().decide(
        run.core_result.incident_state, run.core_result.threat_assessment
    )
    decision = DecisionReceipt(
        receipt_id=UUID(int=25),
        assessment_receipt_id=receipt.receipt_id,
        assessment_run_id=run.run_id,
        context_digest=context.context_digest,
        core_decision=core,
        decision_digest=content_digest(core),
        input_anchor=run.input_anchor,
        output_anchor=run.output_anchor,
    )
    store.save_bundle(context, run, receipt, decision)
    with pytest.raises(StoredDataError, match="Required decision receipt omitted"):
        store.resume(expected)
    expected = expected.model_copy(
        update={
            "decision_receipt_id": decision.receipt_id,
            "decision_receipt_digest": content_digest(decision),
        }
    )
    assert store.resume(expected)[3] == decision
    # Neither existing Decision issuance nor Approval is created by the receipt.
    with store.database.transaction(write=False) as connection:
        assert connection.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM authorizations").fetchone()[0] == 0


def test_optional_unavailable_metadata_roundtrip(bundle):
    from soc_agent.security_ai.external.assembly import (
        ContextContent,
        Coverage,
        ExternalModelContext,
    )

    store, context, run, receipt, expected = bundle
    values = context.model_dump(exclude={"context_digest"})
    values["coverage"] = [
        *values["coverage"],
        Coverage(
            binding_id="optional-future-package", status="UNAVAILABLE", code="BACKEND_UNAVAILABLE"
        ).model_dump(),
    ]
    content = ContextContent.model_validate(values)
    updated = ExternalModelContext(**content.model_dump(), context_digest=content_digest(content))
    store.save_context(updated)
    assert store.load_context(updated.context_digest) == updated


def test_receipt_missing_not_repaired_by_replay(bundle):
    store, context, run, receipt, expected = bundle
    store.save_bundle(context, run, receipt)
    with sqlite3.connect(store.database.path) as connection:
        connection.execute("DELETE FROM external_receipts")
    with pytest.raises(StoredDataError):
        store.save_bundle(context, run, receipt)


def test_shared_transaction_rolls_back_all_companions(bundle):
    store, context, run, receipt, expected = bundle
    with pytest.raises(RuntimeError, match="outer failure"):
        with store.database.transaction() as connection:
            store.save_bundle_in_transaction(connection, context, run, receipt)
            raise RuntimeError("outer failure")
    with pytest.raises(StoredDataError):
        ExternalContextStore(store.database.path).resume(expected)


@pytest.mark.parametrize("field", ["input_anchor", "output_anchor"])
def test_resume_anchor_mismatch(bundle, field):
    store, context, run, receipt, expected = bundle
    store.save_bundle(context, run, receipt)
    changed = getattr(expected, field).model_copy(update={"fingerprint": "0" * 64})
    with pytest.raises(StoredDataError):
        store.resume(expected.model_copy(update={field: changed}))


def test_invalid_receipt_does_not_dump_secret(bundle):
    store, context, run, receipt, expected = bundle
    store.save_bundle(context, run, receipt)
    with sqlite3.connect(store.database.path) as connection:
        connection.execute(
            "UPDATE external_receipts SET payload=?",
            ('{"credential":"synthetic-sensitive-marker"}',),
        )
    with pytest.raises(StoredDataError) as error:
        store.resume(expected)
    assert "synthetic-sensitive-marker" not in str(error.value)


def test_context_optional_failure_does_not_become_approval(bundle):
    from pydantic import ValidationError

    store, context, run, receipt, expected = bundle
    with pytest.raises(ValidationError):
        ProvenanceReceipt.model_validate(
            {**receipt.model_dump(), "disposition": "APPROVED", "approval_id": str(UUID(int=333))}
        )
    with pytest.raises(ValidationError):
        ResumeRequirement.model_validate({**expected.model_dump(), "sql": "DROP TABLE incidents"})


def test_legacy_v14_load_remains_supported(workspace):
    from soc_agent.investigation.runtime.persistence import CheckpointStore

    _, kwargs = case.__wrapped__()()
    state = kwargs["incident"].state
    stored = workspace.legacy.register(state)
    reopened = SQLiteGovernanceStore(workspace.path)
    assert reopened.load(state.incident_id) == stored
    CheckpointStore(reopened)

"""Transactional lifecycle, replay guards and append-oriented audit on local SQLite."""

from datetime import timedelta
from sqlite3 import Connection
from uuid import UUID

from soc_agent.execution.durable.errors import ClaimConflict, ExecutionReplay
from soc_agent.execution.durable.models import (
    Claim,
    ExecutionBinding,
    ExecutionEvent,
    ExecutionIntent,
    ExecutionRecord,
    Lifecycle,
    ReconciledOutcome,
    ReconciliationRecord,
    ReconciliationRequest,
)
from soc_agent.response.promotion import ExecutionBridge, PromotedAction
from soc_agent.response.promotion.service import confirm
from soc_agent.review.authority import DenyHumanAuthority, HumanAction, HumanAuthority
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import SQLiteGovernanceStore, ledger
from soc_agent.review.persistence.models import StoredDataError, UnsupportedSchemaError
from soc_agent.review.validation import checked
from soc_agent.state.evidence import utc_now


class ExecutionStore:
    def __init__(self, governance: SQLiteGovernanceStore) -> None:
        self.governance = governance
        self.database = governance.database
        with self.database.transaction(write=False) as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] not in (2, 3):
                raise UnsupportedSchemaError("Explicit execution schema migration required")
            connection.execute("SELECT id FROM execution_records LIMIT 0")
            connection.execute("SELECT event_id FROM execution_events LIMIT 0")

    def _load(self, connection: Connection, identity: str) -> ExecutionRecord:
        row = connection.execute(
            "SELECT * FROM execution_records WHERE id=?", (identity,)
        ).fetchone()
        if row is None:
            raise StoredDataError("Unknown execution intent")
        value = ledger.decode(ExecutionRecord, row)
        if (
            value.intent.execution_intent_id != row["id"]
            or str(value.intent.binding.incident_id) != row["incident_id"]
            or value.intent.binding.promoted_action_id != row["promoted_id"]
            or (str(value.intent.binding.approval_id) if value.intent.binding.approval_id else None)
            != row["approval_id"]
            or value.revision != row["revision"]
            or value.state != row["state"]
        ):
            raise StoredDataError("Execution columns differ from validated payload")
        last = connection.execute(
            "SELECT * FROM execution_events WHERE execution_id=? ORDER BY revision DESC LIMIT 1",
            (identity,),
        ).fetchone()
        if last is None or ledger.decode(ExecutionEvent, last).record != value:
            raise StoredDataError("Execution audit/state mismatch")
        return value

    def load(self, identity: str) -> ExecutionRecord:
        with self.database.transaction(write=False) as connection:
            return self._load(connection, identity)

    def _event(
        self,
        connection: Connection,
        record: ExecutionRecord,
        event_type: str,
        reconciliation: ReconciliationRecord | None = None,
    ) -> None:
        event = ExecutionEvent(record=record, event_type=event_type, reconciliation=reconciliation)
        cursor = connection.execute(
            "INSERT INTO execution_events(event_id,execution_id,revision,payload,digest) "
            "VALUES (?,?,?,?,?)",
            (
                str(event.event_id),
                record.intent.execution_intent_id,
                record.revision,
                ledger.serialize(event),
                content_digest(event),
            ),
        )
        if cursor.rowcount != 1:
            raise StoredDataError("Execution audit was not inserted")

    def create(
        self, bridge: ExecutionBridge, promoted: PromotedAction, *, approval_id: UUID | None = None
    ) -> ExecutionRecord:
        """Only live, registered, independently confirmed lineage may enter this store."""
        action = bridge.executable_action(promoted)
        approval = bridge.validated_approval(promoted, approval_id)
        plan = bridge.source_plan(promoted)
        if plan.content.basis.snapshot.repository_id != self.database.store_id:
            raise StoredDataError("Execution belongs to another authoritative store")
        binding = ExecutionBinding(
            incident_id=action.incident_id,
            promoted_action_id=promoted.promoted_id,
            tool_name=action.tool_name,
            canonical_input=action.tool_input,
            approval_id=approval_id,
        )
        identity = content_digest(binding)
        intent = ExecutionIntent(
            execution_intent_id=identity,
            idempotency_key=identity,
            binding=binding,
            plan=plan,
            promoted=promoted,
            approval=approval,
        )
        record = ExecutionRecord(intent=intent)
        with self.database.transaction() as connection:
            existing = connection.execute(
                "SELECT id FROM execution_records WHERE id=? OR promoted_id=? OR approval_id=?",
                (identity, promoted.promoted_id, str(approval_id) if approval_id else None),
            ).fetchone()
            if existing:
                old = self._load(connection, existing["id"])
                if (
                    old.intent.binding == binding
                    and old.intent.plan == plan
                    and (old.intent.promoted == promoted and old.intent.approval == approval)
                ):
                    return old
                raise ExecutionReplay("Promotion or approval already reserved by durable intent")
            cursor = connection.execute(
                "INSERT INTO execution_records VALUES (?,?,?,?,?,?,?,?)",
                (
                    identity,
                    str(action.incident_id),
                    promoted.promoted_id,
                    str(approval_id) if approval_id else None,
                    0,
                    record.state,
                    ledger.serialize(record),
                    content_digest(record),
                ),
            )
            if cursor.rowcount != 1:
                raise StoredDataError("Execution intent was not inserted")
            self._event(connection, record, "intent_created")
        return record

    def _save(
        self,
        connection: Connection,
        old: ExecutionRecord,
        new: ExecutionRecord,
        event_type: str,
        reconciliation: ReconciliationRecord | None = None,
    ) -> ExecutionRecord:
        new = checked(ExecutionRecord, new)
        cursor = connection.execute(
            "UPDATE execution_records SET revision=?,state=?,payload=?,digest=? "
            "WHERE id=? AND revision=? AND digest=?",
            (
                new.revision,
                new.state,
                ledger.serialize(new),
                content_digest(new),
                old.intent.execution_intent_id,
                old.revision,
                content_digest(old),
            ),
        )
        if cursor.rowcount != 1:
            raise ClaimConflict("Lifecycle CAS conflict")
        self._event(connection, new, event_type, reconciliation)
        return new

    def claim(self, identity: str, *, claimant: str, lease_seconds: int = 60) -> ExecutionRecord:
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 3600:
            raise ValueError("Lease duration must be 1..3600 seconds")
        with self.database.transaction() as connection:
            old = self._load(connection, identity)
            if old.state != Lifecycle.PENDING:
                raise ClaimConflict(
                    "Only pending intents may be claimed; explicit recovery required"
                )
            now = utc_now()
            claim = Claim(
                claimant=claimant, claimed_at=now, expires_at=now + timedelta(seconds=lease_seconds)
            )
            return self._save(
                connection,
                old,
                old.model_copy(
                    update={
                        "state": Lifecycle.CLAIMED,
                        "revision": old.revision + 1,
                        "claim": claim,
                    }
                ),
                "claimed",
            )

    def transition(
        self,
        expected: ExecutionRecord,
        state: Lifecycle,
        *,
        reason: str | None = None,
        result_digest: str | None = None,
    ) -> ExecutionRecord:
        expected = checked(ExecutionRecord, expected)
        allowed = {
            Lifecycle.CLAIMED: {Lifecycle.EXECUTING, Lifecycle.FAILED},
            Lifecycle.EXECUTING: {Lifecycle.SUCCEEDED, Lifecycle.FAILED, Lifecycle.UNCERTAIN},
        }
        with self.database.transaction() as connection:
            old = self._load(connection, expected.intent.execution_intent_id)
            if old != expected or state not in allowed.get(old.state, set()):
                raise ClaimConflict("Invalid, stale or already finalized execution claim")
            now = utc_now()
            if state == Lifecycle.EXECUTING and old.claim.expires_at <= now:
                raise ClaimConflict("Expired claim cannot enter invocation boundary")
            updates = {
                "state": state,
                "revision": old.revision + 1,
                "reason": reason,
                "result_digest": result_digest,
            }
            if state == Lifecycle.EXECUTING:
                updates["invocation_started_at"] = now
            else:
                updates["finished_at"] = now
            return self._save(
                connection,
                old,
                old.model_copy(update=updates),
                "invocation_boundary" if state == Lifecycle.EXECUTING else state.value,
            )

    def recover(self) -> tuple[ExecutionRecord, ...]:
        """Classify expired work only. Never invoke, approve, retry or reconcile."""
        results = []
        with self.database.transaction() as connection:
            identities = [r[0] for r in connection.execute("SELECT id FROM execution_records")]
            for identity in identities:
                old = self._load(connection, identity)
                if old.state not in (Lifecycle.CLAIMED, Lifecycle.EXECUTING):
                    continue
                if old.claim.expires_at > utc_now():
                    continue
                state = Lifecycle.PENDING if old.state == Lifecycle.CLAIMED else Lifecycle.UNCERTAIN
                new = old.model_copy(
                    update={
                        "state": state,
                        "revision": old.revision + 1,
                        "claim": None if state == Lifecycle.PENDING else old.claim,
                        "reason": "Expired before invocation"
                        if state == Lifecycle.PENDING
                        else "Invocation may have occurred; reconciliation required",
                    }
                )
                results.append(self._save(connection, old, new, "recovered"))
        return tuple(results)

    def reconcile(
        self,
        request: ReconciliationRequest,
        *,
        credential: str,
        authority: HumanAuthority | None = None,
    ) -> ExecutionRecord:
        request = checked(ReconciliationRequest, request)
        actor = confirm(
            authority or DenyHumanAuthority(),
            credential,
            HumanAction.RECONCILE_EXECUTION,
            content_digest(request),
        )
        with self.database.transaction() as connection:
            old = self._load(connection, request.execution_intent_id)
            if (
                old.state != Lifecycle.UNCERTAIN
                or old.revision != request.expected_revision
                or old.intent.binding.incident_id != request.incident_id
            ):
                raise ClaimConflict("Reconciliation target/state mismatch")
            state = {
                ReconciledOutcome.CONFIRMED_SUCCEEDED: Lifecycle.SUCCEEDED,
                ReconciledOutcome.CONFIRMED_FAILED: Lifecycle.FAILED,
                ReconciledOutcome.UNRESOLVED: Lifecycle.UNCERTAIN,
            }[request.outcome]
            return self._save(
                connection,
                old,
                old.model_copy(
                    update={
                        "state": state,
                        "revision": old.revision + 1,
                        "reason": request.reason,
                        "finished_at": utc_now(),
                    }
                ),
                "reconciled",
                ReconciliationRecord(request=request, actor=actor),
            )

    def events(self, identity: str) -> tuple[ExecutionEvent, ...]:
        with self.database.transaction(write=False) as connection:
            self._load(connection, identity)
            result = []
            for row in connection.execute(
                "SELECT * FROM execution_events WHERE execution_id=? ORDER BY revision", (identity,)
            ):
                event = ledger.decode(ExecutionEvent, row)
                if (
                    event.record.intent.execution_intent_id != identity
                    or event.record.revision != row["revision"]
                    or str(event.event_id) != row["event_id"]
                ):
                    raise StoredDataError("Audit columns mismatch")
                result.append(event)
            return tuple(result)

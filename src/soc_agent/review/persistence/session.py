"""The existing domain service runs against one SQLite transaction snapshot."""

import sqlite3
from collections.abc import Callable
from uuid import UUID

from pydantic import ValidationError

from soc_agent._json import canonical_json_object
from soc_agent.review.authority import HumanAuthority
from soc_agent.review.errors import AuthorizationAlreadyApplied, ReviewError, StaleSnapshotError
from soc_agent.review.identity import state_fingerprint
from soc_agent.review.models import ApplicationResult, ReviewOutcome, StateAnchor, StoredIncident
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import GovernanceEvent, StoredDataError
from soc_agent.review.service import HumanReviewService
from soc_agent.review.transitions import validate_changes
from soc_agent.review.validation import validate_decision
from soc_agent.state import IncidentState


class GovernanceSession:
    def __init__(self, connection: sqlite3.Connection, store_id: UUID) -> None:
        self.connection = connection
        self.store_id = store_id

    def _decode_state(self, row: sqlite3.Row | None) -> StoredIncident:
        if row is None:
            raise StoredDataError("Unknown incident snapshot")
        try:
            state = IncidentState.model_validate_json(row["payload"])
            if canonical_json_object(row["payload"]) != ledger.serialize(state):
                raise StoredDataError("Stored incident has omitted or noncanonical fields")
            anchor = StateAnchor(
                repository_id=self.store_id,
                incident_id=UUID(row["incident_id"]),
                revision=row["revision"],
                fingerprint=row["fingerprint"],
            )
            if (
                state.incident_id != anchor.incident_id
                or state_fingerprint(state) != anchor.fingerprint
            ):
                raise StoredDataError("Stored incident fingerprint/identity mismatch")
            return StoredIncident(state=state, anchor=anchor)
        except (ValidationError, TypeError) as error:
            raise StoredDataError("Invalid stored incident") from error

    def load(self, incident_id: UUID) -> StoredIncident:
        current = self._decode_state(
            self.connection.execute(
                "SELECT * FROM incidents WHERE incident_id=?", (str(incident_id),)
            ).fetchone()
        )
        if self.snapshot(current.anchor) != current:
            raise StoredDataError("Current state differs from retained revision")
        return current

    def snapshot(self, anchor: StateAnchor) -> StoredIncident:
        result = self._decode_state(
            self.connection.execute(
                "SELECT * FROM snapshots WHERE incident_id=? AND revision=?",
                (str(anchor.incident_id), anchor.revision),
            ).fetchone()
        )
        if anchor != result.anchor:
            raise StoredDataError("Snapshot reference differs from persistent history")
        return result

    def restore_service(self, authority: HumanAuthority | None = None) -> HumanReviewService:
        # No public API accepts a caller-supplied issuance ledger. These rows are read
        # and checked inside the same DB transaction used by the domain operation.
        if self.connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise StoredDataError("Governance foreign key violation")
        service = HumanReviewService(store=self, authority=authority)
        service._decisions = {
            ledger.coordinates(v)[1]: v for v in ledger.all_records(self.connection, "decisions")
        }
        service._review_requests = {
            v.review_request_id: v for v in ledger.all_records(self.connection, "review_requests")
        }
        service._reviews = {v.review_id: v for v in ledger.all_records(self.connection, "reviews")}
        service._requests = {
            v.request_id: v for v in ledger.all_records(self.connection, "requests")
        }
        service._authorizations = {
            v.authorization_id: v for v in ledger.all_records(self.connection, "authorizations")
        }
        self._validate_graph(service)
        return service

    def _validate_graph(self, service: HumanReviewService) -> None:
        try:
            for rr in service._review_requests.values():
                decision = service._decisions[rr.target.decision_digest]
                historical = self.snapshot(rr.target.snapshot).state
                if (
                    decision.incident_id != rr.target.incident_id
                    or decision.decision_id != rr.target.decision_id
                    or decision.rule_version != rr.target.decision_rule_version
                    or decision.decision_version != rr.target.decision_version
                ):
                    raise StoredDataError("Review decision binding mismatch")
                validate_decision(historical, decision)
            for review in service._reviews.values():
                rr = service._review_requests[review.review_request_id]
                if review.target != rr.target or review.recorded_at < rr.created_at:
                    raise StoredDataError("Stored review binding/time mismatch")
            for request in service._requests.values():
                review = service._reviews[request.review_id]
                if (
                    review.target != request.target
                    or review.outcome != ReviewOutcome.CHANGE_ELIGIBLE
                ):
                    raise StoredDataError("Stored request review mismatch")
                validate_changes(self.snapshot(request.target.snapshot).state, request)
            for auth in service._authorizations.values():
                request = service._requests[auth.request.request_id]
                if (
                    request != auth.request
                    or auth.request_digest != ledger.content_digest(request)
                    or auth.issued_at < service._reviews[request.review_id].recorded_at
                ):
                    raise StoredDataError("Stored authorization request mismatch")
        except (KeyError, ValueError) as error:
            if isinstance(error, StoredDataError):
                raise
            raise StoredDataError("Invalid persistent governance reference graph") from error

    def save_state(self, expected: StateAnchor, updated: IncidentState) -> StateAnchor:
        anchor = StateAnchor(
            repository_id=self.store_id,
            incident_id=updated.incident_id,
            revision=expected.revision + 1,
            fingerprint=state_fingerprint(updated),
        )
        payload = ledger.serialize(updated)
        changed = self.connection.execute(
            """UPDATE incidents SET revision=?, fingerprint=?, payload=?
            WHERE incident_id=? AND revision=? AND fingerprint=?""",
            (
                anchor.revision,
                anchor.fingerprint,
                payload,
                str(expected.incident_id),
                expected.revision,
                expected.fingerprint,
            ),
        )
        if changed.rowcount != 1:
            raise StaleSnapshotError("Atomic SQLite CAS conflict")
        self.connection.execute(
            "INSERT INTO snapshots VALUES (?,?,?,?)",
            (str(updated.incident_id), anchor.revision, anchor.fingerprint, payload),
        )
        return anchor

    def compare_and_apply(
        self,
        expected: StateAnchor,
        authorization_id: UUID,
        build: Callable[[StoredIncident], ApplicationResult],
    ) -> ApplicationResult:
        auth = ledger.get(self.connection, "authorizations", str(authorization_id))
        row = self.connection.execute(
            "SELECT used,application_id FROM authorizations WHERE id=?", (str(authorization_id),)
        ).fetchone()
        if row["used"]:
            # Also validate its result before classifying it as a legitimate replay.
            self.application_for(authorization_id)
            raise AuthorizationAlreadyApplied("Persistent authorization already consumed")
        current = self.load(expected.incident_id)
        if current.anchor != expected or auth.request.target.snapshot != expected:
            raise StaleSnapshotError("Persistent snapshot/revision/store identity mismatch")
        validate_changes(current.state, auth.request)
        result = ApplicationResult.model_validate(build(current).model_dump(warnings=False))
        self._validate_result(current, auth, result)
        anchor = self.save_state(expected, result.incident_state)
        if result.audit.resulting_snapshot != anchor:
            raise ReviewError("Application result snapshot mismatch")
        consumed = self.connection.execute(
            "UPDATE authorizations SET used=1,application_id=? WHERE id=? AND used=0",
            (str(result.audit.application_id), str(authorization_id)),
        )
        if consumed.rowcount != 1:
            raise StoredDataError("Authorization consumption did not update exactly one row")
        ledger.insert(self.connection, result)
        ledger.append_event(
            self.connection,
            GovernanceEvent(
                event_type="application_succeeded",
                incident_id=expected.incident_id,
                decision_id=auth.request.target.decision_id,
                review_id=auth.request.review_id,
                request_id=auth.request.request_id,
                authorization_id=authorization_id,
                actor_id=auth.authorized_by,
                before=expected,
                after=anchor,
                changes=auth.request.changes,
                rule_version=auth.request.transition_version,
            ),
        )
        return result

    def _validate_result(self, current, auth, result: ApplicationResult) -> None:
        request, audit = auth.request, result.audit
        if (
            audit.target != request.target
            or audit.review_id != request.review_id
            or audit.request_id != request.request_id
            or audit.authorization_id != auth.authorization_id
            or audit.authorized_by != auth.authorized_by
            or audit.changes != request.changes
            or audit.transition_version != request.transition_version
            or audit.applied_at < auth.issued_at
            or audit.applied_at <= current.state.updated_at
        ):
            raise StoredDataError("Application audit does not match registered authorization")
        payload = current.state.model_dump()
        payload.update({change.field: change.after for change in request.changes})
        payload["updated_at"] = audit.applied_at
        expected_state = IncidentState.model_validate(payload)
        expected_anchor = StateAnchor(
            repository_id=self.store_id,
            incident_id=current.state.incident_id,
            revision=current.anchor.revision + 1,
            fingerprint=state_fingerprint(expected_state),
        )
        if expected_state != result.incident_state or expected_anchor != audit.resulting_snapshot:
            raise StoredDataError("Application modifies fields beyond exact authorized change")

    def application_for(self, authorization_id: UUID) -> ApplicationResult | None:
        auth = ledger.get(self.connection, "authorizations", str(authorization_id))
        row = self.connection.execute(
            "SELECT used,application_id FROM authorizations WHERE id=?", (str(authorization_id),)
        ).fetchone()
        found = self.connection.execute(
            "SELECT * FROM applications WHERE parent=?", (str(authorization_id),)
        ).fetchone()
        if not row["used"]:
            if row["application_id"] is not None or found is not None:
                raise StoredDataError("Unused authorization has an application")
            return None
        if found is None or row["application_id"] != found["id"]:
            raise StoredDataError("Consumed authorization lacks its exact result")
        result = ledger.decode_artifact("applications", found)
        self._validate_result(self.snapshot(auth.request.target.snapshot), auth, result)
        if self.snapshot(result.audit.resulting_snapshot).state != result.incident_state:
            raise StoredDataError("Applied result differs from stored revision")
        return result

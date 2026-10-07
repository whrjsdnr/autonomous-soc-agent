"""Immutable version history and exact source queries; no public pointer mutator."""

from sqlite3 import Connection

from soc_agent.improvement_candidates.models import ImprovementCandidate
from soc_agent.improvement_candidates.strategy import compile_candidate_strategy
from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.improvement_promotion.eligibility import PromotionEligibilityService
from soc_agent.improvement_promotion.models import (
    FAMILY,
    ActivationRecord,
    ActivePointer,
    ArtifactFamily,
    PromotionContent,
    PromotionRequest,
    RollbackContent,
    RollbackRequest,
    SourceSnapshot,
    VersionedImprovementArtifact,
    action_context,
)
from soc_agent.improvement_review.store import ImprovementReviewStore
from soc_agent.planning.strategy import InvestigationStrategy
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer
from soc_agent.review.persistence.models import StoredDataError, UnsupportedSchemaError


class StaleActivation(HumanAuthorizationDenied):
    pass


class NoChange(HumanAuthorizationDenied):
    pass


def reference(value: VersionedImprovementArtifact) -> ArtifactReference:
    return ArtifactReference(identity=value.artifact_id, digest=value.content_digest)


class ImprovementPromotionStore:
    def __init__(self, reviews: ImprovementReviewStore) -> None:
        self.reviews = reviews
        self.database = reviews.database
        self.eligibility = PromotionEligibilityService(reviews)
        with self.database.transaction(write=False) as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] != 14:
                raise UnsupportedSchemaError("Explicit promotion migration required")

    def _source(self, connection: Connection, source: SourceSnapshot) -> InvestigationStrategy:
        eligibility = self.eligibility.assess_in_transaction(
            connection, source.review_request.identity
        )
        if (
            eligibility.review_request != source.review_request
            or eligibility.review_record != source.review_record
        ):
            raise StoredDataError("Promotion review binding mismatch")
        # assess_in_transaction already validated the exact durable request and graph.
        # Compare the pinned convenience snapshot by its canonical digest, without
        # repeating that expensive traversal in this same transaction.
        if content_digest(source.snapshot) != source.review_request.digest:
            raise StoredDataError("Promotion exact snapshot mismatch")
        if eligibility.status != "PROMOTABLE":
            raise HumanAuthorizationDenied("Source is NON_PROMOTABLE")
        candidate = ImprovementCandidate(
            candidate_id=eligibility.candidate.identity,
            candidate_version=eligibility.candidate.identity,
            content=source.snapshot.candidate,
        )
        return compile_candidate_strategy(candidate)

    def _artifact(self, connection: Connection, artifact_id: str) -> VersionedImprovementArtifact:
        row = connection.execute(
            "SELECT * FROM improvement_artifacts WHERE id=?", (artifact_id,)
        ).fetchone()
        if row is None:
            raise StoredDataError("Unknown registered artifact")
        value = ledger.decode(VersionedImprovementArtifact, row)
        if (row["id"], row["family"], row["version"], row["payload_digest"]) != (
            value.artifact_id,
            value.content.artifact_family,
            value.content.version,
            content_digest(value.content.payload),
        ):
            raise StoredDataError("Artifact registry index mismatch")
        if self._source(connection, value.content.source_snapshot) != value.content.payload:
            raise StoredDataError("Registered strategy/source mismatch")
        # Every version must have a committed promotion and consumed confirmation.
        records = connection.execute("SELECT * FROM improvement_promotion_records").fetchall()
        matching = [
            self._record(connection, "promotion", r, verify_artifact=False)
            for r in records
            if ledger.decode(ActivationRecord, r).current.active_artifact == reference(value)
        ]
        if len(matching) != 1 or matching[0].current.active_version != value.content.version:
            raise StoredDataError("Artifact has no unique committed registration")
        registration = connection.execute(
            "SELECT * FROM improvement_promotion_requests WHERE id=?",
            (matching[0].request.identity,),
        ).fetchone()
        promoted = ledger.decode(PromotionRequest, registration)
        if (
            promoted.content.payload != value.content.payload
            or promoted.content.source_snapshot != value.content.source_snapshot
        ):
            raise StoredDataError("Registered artifact differs from approved promotion request")
        return value

    def _pointer(self, connection: Connection) -> ActivePointer:
        row = connection.execute(
            "SELECT * FROM improvement_active_pointers WHERE family=?", (FAMILY,)
        ).fetchone()
        if row is None:
            if connection.execute("SELECT 1 FROM improvement_artifacts LIMIT 1").fetchone():
                raise StoredDataError("Registered history has missing active pointer")
            if any(
                connection.execute(f"SELECT 1 FROM improvement_{kind}_records LIMIT 1").fetchone()
                for kind in ("promotion", "rollback")
            ):
                raise StoredDataError("Committed activation history has no active pointer")
            return ActivePointer()
        artifact = self._artifact(connection, row["artifact_id"])
        if artifact.content.version != row["version"]:
            raise StoredDataError("Active version mismatch")
        pointer = ActivePointer(
            active_artifact=reference(artifact),
            active_version=row["version"],
            revision=row["revision"],
        )
        # Pointer revision must correspond to a committed governance fact.
        records = [
            self._record(connection, kind, r, verify_artifact=False)
            for kind in ("promotion", "rollback")
            for r in connection.execute(f"SELECT * FROM improvement_{kind}_records")
        ]
        if (
            sum(r.current == pointer for r in records) != 1
            or max(r.current.revision for r in records) != pointer.revision
        ):
            raise StoredDataError("Active pointer lacks committed audit revision")
        chain = sorted(records, key=lambda r: r.current.revision)
        previous = ActivePointer()
        for revision, record in enumerate(chain, 1):
            if record.current.revision != revision or record.previous != previous:
                raise StoredDataError("Activation history revision chain mismatch")
            previous = record.current
        return pointer

    def _request(self, connection: Connection, kind: str, identity: str):
        if kind not in ("promotion", "rollback"):
            raise ValueError("Unknown activation domain")
        row = connection.execute(
            f"SELECT * FROM improvement_{kind}_requests WHERE id=?", (identity,)
        ).fetchone()
        if row is None:
            raise StoredDataError("Unknown activation request")
        value = ledger.decode(PromotionRequest if kind == "promotion" else RollbackRequest, row)
        if value.request_id != row["id"]:
            raise StoredDataError("Activation request index mismatch")
        if kind == "promotion":
            if self._source(connection, value.content.source_snapshot) != value.content.payload:
                raise StoredDataError("Promotion payload/source mismatch")
        else:
            target = self._artifact(connection, value.content.target.identity)
            if (
                reference(target) != value.content.target
                or target.content.version != value.content.target_version
            ):
                raise StoredDataError("Rollback target binding mismatch")
        return value

    def _record(
        self, connection: Connection, kind: str, row, *, verify_artifact=True
    ) -> ActivationRecord:
        value = ledger.decode(ActivationRecord, row)
        if (
            value.record_id != row["id"]
            or value.request.identity != row["request_id"]
            or value.action != kind.upper()
        ):
            raise StoredDataError("Activation record index mismatch")
        # Avoid artifact->registration->artifact recursion; pinned request is still fully checked.
        request_row = connection.execute(
            f"SELECT * FROM improvement_{kind}_requests WHERE id=?", (row["request_id"],)
        ).fetchone()
        if request_row is None:
            raise StoredDataError("Missing activation request")
        request = ledger.decode(
            PromotionRequest if kind == "promotion" else RollbackRequest, request_row
        )
        if (
            request.request_id != row["request_id"]
            or value.request.digest != content_digest(request.content)
            or value.previous != request.content.expected
        ):
            raise StoredDataError("Activation request/audit mismatch")
        if kind == "rollback" and (
            value.current.active_artifact != request.content.target
            or value.current.active_version != request.content.target_version
        ):
            raise StoredDataError("Rollback audit target mismatch")
        v = value.verification
        if v.context != action_context(request):
            raise StoredDataError("Activation exact confirmation context mismatch")
        receipt = SQLiteConfirmationConsumer._load(connection, v.provider_id, v.confirmation_id)
        if receipt is None or not receipt.consumed or receipt.verification != v:
            raise StoredDataError("Activation confirmation receipt mismatch")
        if verify_artifact:
            artifact = self._artifact(connection, value.current.active_artifact.identity)
            if (
                reference(artifact) != value.current.active_artifact
                or artifact.content.version != value.current.active_version
            ):
                raise StoredDataError("Activation artifact mismatch")
            if kind == "promotion" and (
                artifact.content.payload != request.content.payload
                or artifact.content.source_snapshot != request.content.source_snapshot
            ):
                raise StoredDataError("Activation registered content mismatch")
        return value

    def create_promotion_request(self, review_request_id: str) -> PromotionRequest:
        with self.database.transaction() as connection:
            eligibility = self.eligibility.assess_in_transaction(connection, review_request_id)
            if eligibility.status != "PROMOTABLE" or eligibility.review_record is None:
                raise HumanAuthorizationDenied("Promotion requires PROMOTABLE approved evidence")
            review = self.reviews._request(
                connection,
                connection.execute(
                    "SELECT * FROM improvement_review_requests WHERE id=?", (review_request_id,)
                ).fetchone(),
            )
            source = SourceSnapshot(
                review_request=eligibility.review_request,
                review_record=eligibility.review_record,
                snapshot=review.content,
            )
            content = PromotionContent(
                source_snapshot=source,
                payload=self._source(connection, source),
                expected=self._pointer(connection),
            )
            value = PromotionRequest(request_id=content_digest(content), content=content)
            old = connection.execute(
                "SELECT id FROM improvement_promotion_requests WHERE id=?", (value.request_id,)
            ).fetchone()
            if old:
                return self._request(connection, "promotion", value.request_id)
            if connection.execute(
                "SELECT id FROM improvement_artifacts WHERE family=? AND payload_digest=?",
                (FAMILY, content_digest(content.payload)),
            ).fetchone():
                raise NoChange("Identical strategy already registered; use governed rollback")
            self._insert_request(connection, "promotion", value)
            return value

    def create_rollback_request(self, target_id: str) -> RollbackRequest:
        with self.database.transaction() as connection:
            target = self._artifact(connection, target_id)
            pointer = self._pointer(connection)
            if pointer.active_artifact == reference(target):
                raise NoChange("Rollback target is already active")
            content = RollbackContent(
                target=reference(target), target_version=target.content.version, expected=pointer
            )
            value = RollbackRequest(request_id=content_digest(content), content=content)
            old = connection.execute(
                "SELECT id FROM improvement_rollback_requests WHERE id=?", (value.request_id,)
            ).fetchone()
            if old:
                return self._request(connection, "rollback", value.request_id)
            self._insert_request(connection, "rollback", value)
            return value

    @staticmethod
    def _insert_request(connection, kind, value):
        connection.execute(
            f"INSERT INTO improvement_{kind}_requests VALUES (?,?,?)",
            (value.request_id, ledger.serialize(value), content_digest(value)),
        )

    def get_artifact(self, artifact_id: str) -> VersionedImprovementArtifact:
        with self.database.transaction(write=False) as connection:
            return self._artifact(connection, artifact_id)

    def list_artifacts(
        self, family: ArtifactFamily = FAMILY
    ) -> tuple[VersionedImprovementArtifact, ...]:
        family = ArtifactFamily(family)
        with self.database.transaction(write=False) as connection:
            return tuple(
                self._artifact(connection, r["id"])
                for r in connection.execute(
                    "SELECT id FROM improvement_artifacts WHERE family=? ORDER BY version",
                    (family,),
                )
            )

    def get_active_pointer(self) -> ActivePointer:
        with self.database.transaction(write=False) as connection:
            return self._pointer(connection)

    def get_active_artifact(self) -> VersionedImprovementArtifact | None:
        with self.database.transaction(write=False) as connection:
            pointer = self._pointer(connection)
            return (
                None
                if pointer.active_artifact is None
                else self._artifact(connection, pointer.active_artifact.identity)
            )

    def get_promotion_request(self, identity: str) -> PromotionRequest:
        with self.database.transaction(write=False) as connection:
            return self._request(connection, "promotion", identity)

    def get_rollback_request(self, identity: str) -> RollbackRequest:
        with self.database.transaction(write=False) as connection:
            return self._request(connection, "rollback", identity)

    def _get_record(self, kind, identity):
        with self.database.transaction(write=False) as connection:
            row = connection.execute(
                f"SELECT * FROM improvement_{kind}_records WHERE id=?", (identity,)
            ).fetchone()
            if row is None:
                raise StoredDataError("Unknown activation record")
            return self._record(connection, kind, row)

    def get_promotion_record(self, identity: str) -> ActivationRecord:
        return self._get_record("promotion", identity)

    def get_rollback_record(self, identity: str) -> ActivationRecord:
        return self._get_record("rollback", identity)

    def _list_records(self, kind):
        with self.database.transaction(write=False) as connection:
            return tuple(
                self._record(connection, kind, r)
                for r in connection.execute(f"SELECT * FROM improvement_{kind}_records ORDER BY id")
            )

    def list_promotion_records(self) -> tuple[ActivationRecord, ...]:
        return self._list_records("promotion")

    def list_rollback_records(self) -> tuple[ActivationRecord, ...]:
        return self._list_records("rollback")

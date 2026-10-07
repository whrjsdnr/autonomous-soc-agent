"""Separate confirmed activation actions; SQLite owns consumption, history and CAS."""

from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.improvement_promotion.models import (
    FAMILY,
    ActivationRecord,
    ActivePointer,
    ArtifactContent,
    PromotionRequest,
    RollbackRequest,
    VersionedImprovementArtifact,
    action_context,
    record_identity,
)
from soc_agent.improvement_promotion.store import (
    ImprovementPromotionStore,
    NoChange,
    StaleActivation,
    reference,
)
from soc_agent.review.authentication import (
    AuthenticationProvider,
    HumanPermissionVerifier,
    ProviderHumanAuthority,
)
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.review.validation import checked


class ImprovementActivationService:
    def __init__(
        self,
        store: ImprovementPromotionStore,
        *,
        provider: AuthenticationProvider,
        provider_id: str,
        permissions: HumanPermissionVerifier,
    ) -> None:
        self.store = store
        self.provider = provider
        self.provider_id = provider_id
        self.permissions = permissions
        self.consumer = SQLiteConfirmationConsumer(store.database)

    def promote(self, request: PromotionRequest, *, credential: str) -> ActivationRecord:
        return self._activate(checked(PromotionRequest, request), credential=credential)

    def rollback(self, request: RollbackRequest, *, credential: str) -> ActivationRecord:
        return self._activate(checked(RollbackRequest, request), credential=credential)

    def _activate(
        self, request: PromotionRequest | RollbackRequest, *, credential: str
    ) -> ActivationRecord:
        kind = "promotion" if isinstance(request, PromotionRequest) else "rollback"
        with self.store.database.transaction() as connection:
            pinned = self.store._request(connection, kind, request.request_id)
            if pinned != request:
                raise StoredDataError("Caller activation request differs from durable request")
            context = action_context(request)
            authority = ProviderHumanAuthority(
                provider=self.provider,
                provider_id=self.provider_id,
                permissions=self.permissions,
                resolve_context=lambda action, digest: context,
                confirmation_consumer=self.consumer.for_transaction(
                    self.store.database.store_id, connection
                ),
            )
            principal = authority.authenticate_context(credential=credential, context=context)
            existing = connection.execute(
                f"SELECT * FROM improvement_{kind}_records WHERE request_id=?",
                (request.request_id,),
            ).fetchone()
            if existing:
                record = self.store._record(connection, kind, existing)
                if (
                    record.verification.provider_id,
                    record.verification.subject_id,
                    record.verification.session_id,
                ) != (principal.provider_id, principal.subject_id, principal.session_id):
                    raise HumanAuthorizationDenied(
                        "Committed activation belongs to another authenticated session"
                    )
                return record
            current = self.store._pointer(connection)
            if current != request.content.expected:
                raise StaleActivation(
                    "Expected active pointer/revision is stale; no automatic rebase"
                )
            if (
                kind == "promotion"
                and connection.execute(
                    "SELECT id FROM improvement_artifacts WHERE family=? AND payload_digest=?",
                    (FAMILY, content_digest(request.content.payload)),
                ).fetchone()
            ):
                raise NoChange("Strategy already registered")
            authority.verify(
                credential=credential, action=context.action, binding_digest=context.binding_digest
            )
            (verification,) = authority.verification_records()
            if (verification.provider_id, verification.subject_id, verification.session_id) != (
                principal.provider_id,
                principal.subject_id,
                principal.session_id,
            ):
                raise StoredDataError("Promoter principal changed during confirmation")
            if kind == "promotion":
                version = connection.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM improvement_artifacts WHERE family=?",
                    (FAMILY,),
                ).fetchone()[0]
                content = ArtifactContent(
                    version=version,
                    payload=request.content.payload,
                    source_snapshot=request.content.source_snapshot,
                )
                digest = content_digest(content)
                artifact = VersionedImprovementArtifact(
                    artifact_id=digest, content_digest=digest, content=content
                )
                connection.execute(
                    "INSERT INTO improvement_artifacts VALUES (?,?,?,?,?,?)",
                    (
                        artifact.artifact_id,
                        FAMILY,
                        version,
                        content_digest(content.payload),
                        ledger.serialize(artifact),
                        content_digest(artifact),
                    ),
                )
                target = reference(artifact)
            else:
                target = request.content.target
                version = request.content.target_version
            new = ActivePointer(
                active_artifact=target, active_version=version, revision=current.revision + 1
            )
            if current.active_artifact is None:
                connection.execute(
                    "INSERT INTO improvement_active_pointers VALUES (?,?,?,?)",
                    (FAMILY, target.identity, version, new.revision),
                )
            else:
                cursor = connection.execute(
                    "UPDATE improvement_active_pointers SET artifact_id=?,version=?,revision=? "
                    "WHERE family=? AND artifact_id=? AND version=? AND revision=?",
                    (
                        target.identity,
                        version,
                        new.revision,
                        FAMILY,
                        current.active_artifact.identity,
                        current.active_version,
                        current.revision,
                    ),
                )
                if cursor.rowcount != 1:
                    raise StaleActivation("Active pointer CAS failed")
            binding = ArtifactReference(
                identity=request.request_id, digest=content_digest(request.content)
            )
            record = ActivationRecord(
                record_id=record_identity(binding, verification),
                request=binding,
                action=kind.upper(),
                previous=current,
                current=new,
                verification=verification,
            )
            connection.execute(
                f"INSERT INTO improvement_{kind}_records VALUES (?,?,?,?)",
                (
                    record.record_id,
                    request.request_id,
                    ledger.serialize(record),
                    content_digest(record),
                ),
            )
            return record

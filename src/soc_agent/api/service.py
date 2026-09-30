"""Application coordination only; domain services retain all authority checks."""

from collections.abc import Callable
from uuid import UUID

from soc_agent.api.models import (
    Approval,
    ApprovalDraft,
    IncidentReview,
    Promotion,
    ResponseReview,
    ResponseReviewDraft,
    StepRequest,
    WorkflowView,
)
from soc_agent.execution.durable import ExecutionStore, ReconciliationRequest
from soc_agent.ingestion import EventIngestor, SOCEvent
from soc_agent.investigation.runtime import SOCRuntime
from soc_agent.investigation.runtime.persistence import CheckpointStore
from soc_agent.investigation.runtime.persistence.models import StaleCheckpoint, WorkflowCheckpoint
from soc_agent.investigation.runtime.trace import OrchestrationTrace
from soc_agent.response.promotion import ExecutionBridge, PromotionService
from soc_agent.response.promotion.models import ResponseReviewIntent
from soc_agent.review.authority import DenyHumanAuthority, HumanAuthority
from soc_agent.review.models import StoredIncident
from soc_agent.review.persistence import PersistentHumanReviewService, SQLiteGovernanceStore
from soc_agent.state import IncidentState


class NotFound(ValueError):
    pass


class Conflict(ValueError):
    pass


class ApplicationService:
    def __init__(
        self,
        *,
        store: SQLiteGovernanceStore,
        runtime_factory: Callable[[], SOCRuntime],
        reviews: PersistentHumanReviewService,
        promotions: PromotionService,
        bridge: ExecutionBridge,
        execution: ExecutionStore,
        authority: HumanAuthority | None = None,
        ingestion: EventIngestor | None = None,
    ) -> None:
        self.store, self.checkpoints = store, CheckpointStore(store)
        self.ingestion = ingestion
        if ingestion is not None and ingestion.store.store_id != store.store_id:
            raise ValueError("Ingestion repository mismatch")
        self.runtime_factory = runtime_factory
        self.reviews, self.promotions, self.bridge = reviews, promotions, bridge
        self.execution, self.authority = execution, authority or DenyHumanAuthority()
        self.response_intents: dict[UUID, ResponseReviewIntent] = {}
        if any(
            identity != store.store_id
            for identity in (
                execution.governance.store_id,
                reviews.store.store_id,
                promotions.validation.store.store_id,
            )
        ):
            raise ValueError("Application dependencies must share authoritative storage")

    def ingest(self, event: SOCEvent):
        if self.ingestion is None:
            raise ValueError("Event ingestion is not configured")
        return self.ingestion.ingest(event)

    def _exists(self, table: str, incident_id: UUID) -> bool:
        # Table names are private constants, never request input.
        with self.store.database.transaction(write=False) as connection:
            return (
                connection.execute(
                    f"SELECT 1 FROM {table} WHERE incident_id=?", (str(incident_id),)
                ).fetchone()
                is not None
            )

    def incident(self, incident_id: UUID) -> StoredIncident:
        if not self._exists("incidents", incident_id):
            raise NotFound("Incident not found")
        return self.store.load(incident_id)

    def create(self, incident_id: UUID) -> StoredIncident:
        if self._exists("incidents", incident_id):
            raise Conflict("Incident already exists")
        return self.store.register(IncidentState(incident_id=incident_id))

    def checkpoint(self, incident_id: UUID) -> WorkflowCheckpoint:
        self.incident(incident_id)
        if not self._exists("workflow_checkpoints", incident_id):
            raise NotFound("Workflow not found")
        return self.checkpoints.load(incident_id)[0]

    @staticmethod
    def _view(saved: WorkflowCheckpoint) -> WorkflowView:
        return WorkflowView(
            **saved.result.model_dump(),
            workflow_id=saved.run_id,
            checkpoint_revision=saved.revision,
        )

    def workflow(self, incident_id: UUID) -> WorkflowView:
        return self._view(self.checkpoint(incident_id))

    def trace(self, incident_id: UUID) -> OrchestrationTrace:
        self.checkpoint(incident_id)
        return self.checkpoints.load(incident_id)[1]

    def _runtime(self) -> SOCRuntime:
        runtime = self.runtime_factory()
        # Reject accidental memory-only composition, not a fallback to weaker guarantees.
        if runtime.checkpoint_repository_id != self.store.store_id:
            raise ValueError("API requires a fresh runtime with this durable checkpoint store")
        return runtime

    def start(self, incident_id: UUID) -> WorkflowView:
        self.incident(incident_id)
        if self._exists("workflow_checkpoints", incident_id):
            raise Conflict("Workflow already exists")
        runtime = self._runtime()
        runtime.start(incident_id)
        return self._view(runtime.checkpoint(incident_id))

    def promoted(self, incident_id: UUID, identity: str):
        item = next(
            (p for p in self.promotions.promoted_actions() if p.promoted_id == identity), None
        )
        if item is None or item.content.request.target.incident_id != incident_id:
            raise NotFound("Promotion not found for incident")
        return item

    async def step(self, incident_id: UUID, request: StepRequest) -> WorkflowView:
        saved = self.checkpoint(incident_id)
        if (saved.run_id, saved.revision) != (request.run_id, request.expected_revision):
            raise StaleCheckpoint("Workflow revision differs")
        promoted = self.promoted(incident_id, request.promoted_id) if request.promoted_id else None
        review = None
        if request.review_id:
            review = next(
                (r for r in self.reviews.reviews() if r.review_id == request.review_id), None
            )
            if review is None or review.target.incident_id != incident_id:
                raise NotFound("Review not found for incident")
        runtime = self._runtime()
        runtime.restore(
            incident_id, promoted=promoted if saved.promoted_id == request.promoted_id else None
        )
        # Restore may race with another request. Never apply this request to a newer cursor.
        restored = runtime.checkpoint(incident_id)
        if restored != saved:
            raise StaleCheckpoint("Workflow advanced during restore")
        await runtime.advance(
            incident_id,
            review=review,
            promoted=promoted,
            approval_id=request.approval_id,
            candidates=request.candidates,
            execute=request.execute,
        )
        return self._view(runtime.checkpoint(incident_id))

    def review_request(self, incident_id: UUID):
        saved = self.checkpoint(incident_id)
        if saved.artifacts.decision is None:
            raise Conflict("Decision required")
        return self.reviews.request_review(
            self.incident(incident_id).state, saved.artifacts.decision
        )

    def record_review(self, incident_id: UUID, body: IncidentReview, credential: str):
        request = next(
            (r for r in self.reviews.review_requests() if r.review_request_id == body.request_id),
            None,
        )
        if request is None or request.target.incident_id != incident_id:
            raise NotFound("Review request not found for incident")
        return self.reviews.record_review(
            request,
            reviewer_id=body.reviewer_id,
            outcome=body.outcome,
            reason=body.reason,
            credential=credential,
        )

    def response_review_request(self, incident_id: UUID, body: ResponseReviewDraft):
        plan = self.checkpoint(incident_id).artifacts.response_plan
        if plan is None:
            raise Conflict("Response plan required")
        intent = self.promotions.request_review(
            plan,
            **body.model_dump(exclude={"blocker_responses"}),
            blocker_responses=body.blocker_responses,
        )
        self.response_intents[intent.intent_id] = intent
        return intent

    def response_review(self, incident_id: UUID, body: ResponseReview, credential: str):
        intent = self.response_intents.get(body.intent_id)
        if intent is None or intent.target.incident_id != incident_id:
            raise NotFound("Response review intent not found")
        return self.promotions.record_review(intent, credential=credential)

    def promote(self, incident_id: UUID, body: Promotion):
        review = next((r for r in self.promotions.reviews() if r.review_id == body.review_id), None)
        if review is None or review.intent.target.incident_id != incident_id:
            raise NotFound("Response review not found")
        return self.promotions.promote(self.promotions.request_promotion(review))

    def approval_request(self, incident_id: UUID, body: ApprovalDraft):
        return self.bridge.request_approval(
            self.promoted(incident_id, body.promoted_id), reason=body.reason
        )

    def approve(self, incident_id: UUID, body: Approval, credential: str):
        return self.bridge.approve_tool(
            self.promoted(incident_id, body.promoted_id), body.approval_id, credential=credential
        )

    def reconcile(self, incident_id: UUID, body: ReconciliationRequest, credential: str):
        if body.incident_id != incident_id:
            raise ValueError("Reconciliation incident mismatch")
        saved = self.checkpoint(incident_id)
        if saved.artifacts.execution_intent_id != body.execution_intent_id:
            raise ValueError("Reconciliation execution mismatch")
        return self.execution.reconcile(body, credential=credential, authority=self.authority)

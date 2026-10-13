"""External advisory context in the existing SOCRuntime, with atomic companion publication."""

from contextlib import contextmanager
from uuid import UUID, uuid4

from pydantic import BaseModel

from soc_agent.assessment import FusionAssessmentResult
from soc_agent.assessment.fusion import FusionAnalysisDraft
from soc_agent.assessment.models import SecurityAnalysisDraft
from soc_agent.llm import LLMClient, LLMRequest
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.security_ai.external.projection import add_context, project, projection_digest
from soc_agent.security_ai.external.records import (
    AssessmentRun,
    DecisionReceipt,
    ProvenanceReceipt,
    ResumeRequirement,
)
from soc_agent.security_ai.external.runtime_guard import RuntimeBoundary
from soc_agent.security_ai.external.runtime_store import (
    EvidenceStage,
    Publication,
    SecurityAudit,
    audit,
)
from soc_agent.state.evidence import utc_now


class ContextLLMClient:
    def __init__(self, client: LLMClient, boundary: RuntimeBoundary) -> None:
        self.client, self.boundary = client, boundary

    async def generate_structured[T: BaseModel](
        self, *, request: LLMRequest, response_model: type[T]
    ) -> T:
        frame = self.boundary._frame.get()
        if frame is None:
            return await self.client.generate_structured(
                request=request, response_model=response_model
            )
        binding = self.boundary.binding(frame.binding.incident_id)
        if binding != frame.binding:
            self.boundary.reject("CONTEXT_CHANGED", frame.binding)
        context = self.boundary.contexts.load_context(binding.context_digest)
        projection = project(context)
        combined = add_context(request, projection)
        result = await self.client.generate_structured(
            request=combined, response_model=response_model
        )
        if response_model in (SecurityAnalysisDraft, FusionAnalysisDraft) and (
            result.observations or result.hypotheses
        ):
            self.boundary.reject("MODEL_FACT_PROMOTION", binding)
        if response_model in (SecurityAnalysisDraft, FusionAnalysisDraft):
            self.boundary.assessment_requests[binding.incident_id] = (
                content_digest(combined),
                projection_digest(projection),
            )
        return result


class RuntimeIntegration:
    def __init__(self, boundary: RuntimeBoundary) -> None:
        self.boundary = boundary
        self._grants = {}
        self._assessment_inputs = {}

    def open(self, incident_id: UUID) -> None:
        try:
            self._grants[incident_id] = self.boundary.issue(incident_id)
        except StoredDataError:
            self.record_rejection(incident_id)
            raise

    def record_rejection(self, incident_id: UUID) -> None:
        with self.boundary.store.database.transaction() as connection:
            audit(connection, "RUNTIME_INTEGRITY_REJECTED", incident_id=incident_id)

    def check(self, incident_id: UUID) -> None:
        try:
            with self.boundary.scope(incident_id, self._grants.get(incident_id)):
                pass
        except StoredDataError:
            self.record_rejection(incident_id)
            raise

    def require_scope(self, incident_id: UUID) -> None:
        binding = self.boundary.binding(incident_id)
        if binding is None:
            return
        frame = self.boundary._frame.get()
        if frame is None or frame is not self._grants.get(incident_id) or frame.binding != binding:
            self.boundary.reject("RUNTIME_SCOPE_MISSING", binding)
        self.check(incident_id)

    @contextmanager
    def step(self, incident_id: UUID):
        self.check(incident_id)
        if self.boundary.binding(incident_id) is None:
            # Preserve legacy evidence publication when this incident has no external context.
            yield
            return
        stage = EvidenceStage(incident_id)
        token = self.boundary.store._stage.set(stage)
        try:
            with self.boundary.scope(incident_id, self._grants.get(incident_id)):
                yield
        finally:
            self.boundary.store._stage.reset(token)

    def before_assessment(self, incident_id: UUID, anchor) -> None:
        self._assessment_inputs[incident_id] = anchor
        self.boundary.assessment_requests.pop(incident_id, None)

    def validate_publication(self, checkpoint, trace) -> None:
        binding = self.boundary.binding(checkpoint.incident_id)
        if binding is None:
            return
        with self.boundary.store.database.transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM external_runtime_publications WHERE run_id=? AND revision=?",
                (str(checkpoint.run_id), checkpoint.revision),
            ).fetchone()
            if row is None:
                raise StoredDataError("Required atomic runtime publication missing")
            publication = ledger.decode(Publication, row)
            if (
                publication.run_id != checkpoint.run_id
                or publication.revision != checkpoint.revision
                or str(publication.incident_id) != row["incident_id"]
                or publication.incident_id != checkpoint.incident_id
                or publication.context_digest != binding.context_digest
                or publication.checkpoint_digest != content_digest(checkpoint)
                or publication.trace_head != trace.entries[-1].entry_id
            ):
                raise StoredDataError("Runtime checkpoint/context publication mismatch")
            confirmed = False
            for event_row in connection.execute(
                "SELECT * FROM external_security_audit ORDER BY sequence DESC"
            ):
                event = ledger.decode(SecurityAudit, event_row)
                if (
                    event.code == "CHECKPOINT_PUBLISHED"
                    and event.publication_digest == content_digest(publication)
                    and event.incident_id == publication.incident_id
                    and event.session_id == publication.session_id
                    and event.context_digest == publication.context_digest
                ):
                    confirmed = True
                    break
            if not confirmed:
                raise StoredDataError("Publication security audit missing")
        if checkpoint.artifacts.assessment is not None:
            if publication.requirement is None or publication.assessment_request_digest is None:
                raise StoredDataError("Required assessment receipt missing")
            _, run, _, decision = self.boundary.contexts.resume(publication.requirement)
            if run.core_result != checkpoint.artifacts.assessment:
                raise StoredDataError("Runtime assessment receipt differs from checkpoint")
            if checkpoint.artifacts.decision is not None and (
                decision is None or decision.core_decision != checkpoint.artifacts.decision
            ):
                raise StoredDataError("Runtime decision receipt missing or mismatched")
        elif publication.requirement is not None:
            raise StoredDataError("Unexpected runtime assessment receipt")

    def reconcile_interrupted(
        self, checkpoints, incident_id: UUID, expected_run: UUID, expected_revision: int
    ):
        """Explicit operator reconciliation closes an interrupted READ step, never replays it."""
        from soc_agent.investigation.runtime.models import WorkflowFailure, WorkflowStep
        from soc_agent.investigation.runtime.trace import (
            OrchestrationTrace,
            OrchestrationTraceEntry,
            TraceContent,
        )

        if self.boundary.binding(incident_id) is None:
            raise ValueError("External read-only reconciliation only")
        with self.boundary.store.database.transaction(write=False) as connection:
            saved, trace, claim = checkpoints._read(connection, incident_id)
            if (
                claim is None
                or saved.run_id != expected_run
                or saved.revision != expected_revision
                or self.boundary.store.load(incident_id).anchor != saved.artifacts.snapshot
                or saved.artifacts.execution_intent_id is not None
            ):
                raise StoredDataError("Interrupted publication cannot be safely closed")
        self.validate_publication(saved, trace)
        self.open(incident_id)
        result = saved.result.model_copy(
            update={
                "current_step": saved.result.next_step,
                "next_step": WorkflowStep.COMPLETE,
                "reason": "Interrupted read-only step closed without replay",
                "terminal": True,
                "waiting_for_human": False,
                "failure": WorkflowFailure.UNCERTAIN,
            }
        )
        content = TraceContent(
            sequence=len(trace.entries) + 1,
            snapshot=saved.artifacts.snapshot,
            result=result,
            previous_entry_id=trace.entries[-1].entry_id,
        )
        updated_trace = OrchestrationTrace(
            incident_id=incident_id,
            entries=(
                *trace.entries,
                OrchestrationTraceEntry(entry_id=content_digest(content), content=content),
            ),
        )
        updated = saved.model_copy(
            update={"revision": saved.revision + 1, "result": result, "updated_at": utc_now()}
        )
        with self.step(incident_id):
            checkpoints.publish(saved, UUID(claim), updated, updated_trace)
        return result

    def publish(self, connection, checkpoint, trace) -> None:
        binding = self.boundary.binding(checkpoint.incident_id)
        if binding is None:
            return
        self.check(checkpoint.incident_id)
        store = self.boundary.store
        stage = store._stage.get()
        if stage is not None:
            store.flush_evidence(connection, stage)
        store.fault("EVIDENCE_FLUSHED")
        context = self.boundary.contexts.load_context(binding.context_digest)
        assessment = checkpoint.artifacts.assessment
        requirement = None
        assessment_input = self._assessment_inputs.get(checkpoint.incident_id)
        usage = self.boundary.assessment_requests.get(checkpoint.incident_id)
        request_digest = usage[0] if usage is not None else None
        if assessment is not None:
            run = AssessmentRun(
                run_id=uuid4(),
                incident_id=checkpoint.incident_id,
                input_anchor=context.input_snapshot,
                output_anchor=checkpoint.artifacts.snapshot,
                context_digest=context.context_digest,
                core_result=assessment,
                assessment_reference=assessment.threat_assessment.assessment_id,
                created_at=utc_now(),
            )
            refs = {
                content_digest(ref): ref
                for result in context.results
                for ref in result.observation.association.source_evidence_references
            }
            receipt = ProvenanceReceipt(
                receipt_id=uuid4(),
                context_digest=context.context_digest,
                assessment_run_id=run.run_id,
                input_anchor=run.input_anchor,
                output_anchor=run.output_anchor,
                assessment_digest=content_digest(assessment.threat_assessment),
                request_projection_digest=projection_digest(project(context)),
                fusion_digest=content_digest(assessment.model_derived_context)
                if type(assessment) is FusionAssessmentResult
                else None,
                source_evidence_references=tuple(refs[key] for key in sorted(refs)),
            )
            previous = connection.execute(
                "SELECT * FROM external_runtime_publications WHERE run_id=? AND revision<? "
                "ORDER BY revision DESC LIMIT 1",
                (str(checkpoint.run_id), checkpoint.revision),
            ).fetchone()
            previous_provenance = None
            if previous is not None:
                old = ledger.decode(Publication, previous)
                if old.requirement is not None:
                    prior_run = self.boundary.contexts._read(
                        connection,
                        "external_assessment_runs",
                        str(old.requirement.run_id),
                        AssessmentRun,
                    )
                    if prior_run.core_result == assessment:
                        run = prior_run
                        receipt = self.boundary.contexts._read(
                            connection,
                            "external_receipts",
                            str(old.requirement.receipt_id),
                            ProvenanceReceipt,
                        )
                        assessment_input = old.assessment_input_anchor
                        request_digest = old.assessment_request_digest
                        if old.requirement.decision_receipt_id is not None:
                            previous_provenance = self.boundary.contexts._read(
                                connection,
                                "external_decision_receipts",
                                str(old.requirement.decision_receipt_id),
                                DecisionReceipt,
                            )
            if request_digest is None or assessment_input is None:
                raise StoredDataError("Actual external assessment invocation receipt missing")
            if receipt.request_projection_digest != projection_digest(project(context)):
                raise StoredDataError("Assessment used a different external projection")
            decision = checkpoint.artifacts.decision
            provenance = (
                DecisionReceipt(
                    receipt_id=uuid4(),
                    assessment_receipt_id=receipt.receipt_id,
                    assessment_run_id=run.run_id,
                    context_digest=context.context_digest,
                    core_decision=decision,
                    decision_digest=content_digest(decision),
                    input_anchor=run.input_anchor,
                    output_anchor=run.output_anchor,
                )
                if decision is not None
                else None
            )
            if previous_provenance is not None:
                if previous_provenance.core_decision != decision:
                    raise StoredDataError("Existing decision provenance changed")
                provenance = previous_provenance
            self.boundary.contexts.save_bundle_in_transaction(
                connection, context, run, receipt, provenance
            )
            requirement = ResumeRequirement(
                run_id=run.run_id,
                incident_id=run.incident_id,
                context_digest=run.context_digest,
                receipt_id=receipt.receipt_id,
                receipt_digest=content_digest(receipt),
                input_anchor=run.input_anchor,
                output_anchor=run.output_anchor,
                decision_receipt_id=provenance.receipt_id if provenance else None,
                decision_receipt_digest=content_digest(provenance) if provenance else None,
            )
        store.fault("RECEIPTS_SAVED")
        publication = Publication(
            incident_id=checkpoint.incident_id,
            run_id=checkpoint.run_id,
            revision=checkpoint.revision,
            session_id=binding.session_id,
            context_digest=binding.context_digest,
            checkpoint_digest=content_digest(checkpoint),
            trace_head=trace.entries[-1].entry_id,
            assessment_input_anchor=assessment_input,
            assessment_request_digest=request_digest,
            requirement=requirement,
        )
        connection.execute(
            "INSERT INTO external_runtime_publications VALUES (?,?,?,?,?)",
            (
                str(checkpoint.run_id),
                checkpoint.revision,
                str(checkpoint.incident_id),
                ledger.serialize(publication),
                content_digest(publication),
            ),
        )
        audit(
            connection,
            "CHECKPOINT_PUBLISHED",
            binding,
            publication_digest=content_digest(publication),
        )
        if checkpoint.result.reason == "Interrupted read-only step closed without replay":
            audit(connection, "CHECKPOINT_RECOVERED_NO_REPLAY", binding)
        store.fault("BEFORE_PUBLICATION_COMMIT")

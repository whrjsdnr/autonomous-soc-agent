"""Explicit read/derive/persist operation; never resumes workflows or issues authority."""

from uuid import UUID

from pydantic import BaseModel

from soc_agent.assessment import FusionAssessmentResult
from soc_agent.execution.durable.models import ExecutionEvent, Lifecycle
from soc_agent.execution.durable.store import ExecutionStore
from soc_agent.experience.models import (
    Experience,
    ExperienceContent,
    GovernanceOutcome,
    HistoricalOutcome,
    HistoricalReference,
)
from soc_agent.experience.store import ExperienceStore
from soc_agent.investigation.runtime.models import WorkflowFailure
from soc_agent.investigation.runtime.persistence import CheckpointStore
from soc_agent.investigation.runtime.persistence.models import WorkflowInFlight
from soc_agent.review.identity import content_digest
from soc_agent.review.models import ReviewOutcome, StateAnchor
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.review.persistence.session import GovernanceSession
from soc_agent.review.validation import validate_decision


class ExperienceCaptureService:
    def __init__(self, store: ExperienceStore) -> None:
        self.store = store
        self.checkpoints = CheckpointStore(store.governance)
        self.executions = ExecutionStore(store.governance)

    def capture(
        self,
        incident_id: UUID,
        *,
        expected_run_id: UUID | None = None,
        expected_snapshot: StateAnchor | None = None,
    ) -> Experience:
        # One transaction covers source validation and insertion. No external operation occurs.
        with self.store.database.transaction() as connection:
            checkpoint, trace, claim = self.checkpoints._read(connection, incident_id)
            if claim is not None:
                raise WorkflowInFlight("Cannot capture an active or interrupted workflow step")
            session = GovernanceSession(connection, self.store.database.store_id)
            current = session.load(incident_id)
            a = checkpoint.artifacts
            if (
                current.anchor != a.snapshot
                or (expected_snapshot is not None and expected_snapshot != current.anchor)
                or (expected_run_id is not None and expected_run_id != checkpoint.run_id)
            ):
                raise StoredDataError("Stale or foreign experience source")
            references = []

            def add(kind: str, identity: UUID | str, source: BaseModel) -> None:
                references.append(
                    HistoricalReference(
                        kind=kind,
                        identity=identity,
                        digest=content_digest(source),
                    )
                )

            for kind, values, field in (
                ("evidence", current.state.evidence, "evidence_id"),
                ("observation", current.state.observations, "observation_id"),
                ("hypothesis", current.state.hypotheses, "hypothesis_id"),
            ):
                for value in values:
                    add(kind, getattr(value, field), value)
            if a.investigation:
                add("investigation", a.investigation.plan_id, a.investigation)
            if a.assessment:
                if a.assessment.incident_state != current.state:
                    raise StoredDataError("Assessment snapshot differs from current incident")
                assessment = a.assessment.threat_assessment
                add("assessment", assessment.assessment_id, assessment)
                if isinstance(a.assessment, FusionAssessmentResult):
                    fusion = a.assessment.model_derived_context
                    add("fusion", fusion.fusion_id, fusion)
                    for signal in fusion.signals:
                        add("signal", signal.signal_id, signal)
            if a.decision:
                validate_decision(current.state, a.decision)
                add("decision", a.decision.decision_id, a.decision)
            disposition = None
            review = None
            if checkpoint.review_id:
                service = session.restore_service()
                review = service._reviews.get(checkpoint.review_id)
                if (
                    review is None
                    or a.decision is None
                    or (
                        review.target.incident_id != incident_id
                        or review.target.snapshot != current.anchor
                        or review.target.decision_digest != content_digest(a.decision)
                    )
                ):
                    raise StoredDataError("Unregistered or mismatched historical review")
                disposition = review.outcome
                add("incident_review", review.review_id, review)
                for authorization in service._authorizations.values():
                    if authorization.request.review_id == review.review_id:
                        add("state_authorization", authorization.authorization_id, authorization)
            if a.response_plan:
                if a.response_plan.content.basis.review != review:
                    raise StoredDataError("Response plan differs from authoritative review")
                add("response_plan", a.response_plan.plan_id, a.response_plan)
                for proposal in a.response_plan.proposed_actions:
                    add("proposal", proposal.proposal_id, proposal)
            execution = None
            reconciliation = None
            outcome = HistoricalOutcome.NOT_EXECUTED
            if a.execution_intent_id:
                execution = self.executions._load(connection, a.execution_intent_id)
                intent = execution.intent
                if (
                    intent.binding.incident_id != incident_id
                    or intent.binding.promoted_action_id != checkpoint.promoted_id
                    or intent.binding.approval_id != checkpoint.approval_id
                    or intent.plan != a.response_plan
                    or intent.promoted.content.current_snapshot != current.anchor
                ):
                    raise StoredDataError("Execution lineage differs from checkpoint")
                add("execution_intent", intent.execution_intent_id, intent)
                add("execution_record", intent.execution_intent_id, execution)
                add("promoted_action", intent.promoted.promoted_id, intent.promoted)
                request = intent.promoted.content.request
                add("promotion_request", request.request_id, request)
                add("response_review", request.review.review_id, request.review)
                if intent.approval:
                    add("tool_approval", intent.approval.approval_id, intent.approval)
                outcome = {
                    Lifecycle.SUCCEEDED: HistoricalOutcome.SUCCEEDED,
                    Lifecycle.FAILED: HistoricalOutcome.FAILED,
                    Lifecycle.UNCERTAIN: HistoricalOutcome.UNCERTAIN,
                    Lifecycle.EXECUTING: HistoricalOutcome.UNCERTAIN,
                }.get(execution.state, HistoricalOutcome.NOT_EXECUTED)
                row = connection.execute(
                    "SELECT * FROM execution_events WHERE execution_id=? "
                    "ORDER BY revision DESC LIMIT 1",
                    (intent.execution_intent_id,),
                ).fetchone()
                event = ledger.decode(ExecutionEvent, row)
                if (
                    str(event.event_id) != row["event_id"]
                    or event.record.revision != row["revision"]
                    or row["execution_id"] != intent.execution_intent_id
                ):
                    raise StoredDataError("Execution event reference mismatch")
                add("execution_event", event.event_id, event)
                if event.reconciliation:
                    reconciliation = event.reconciliation.request.outcome
            elif checkpoint.promoted_id or checkpoint.approval_id:
                raise StoredDataError(
                    "Process-local promotion/approval lacks durable execution provenance"
                )
            entries = []
            for entry in trace.entries:
                entries.append(entry)
                if entry.content.result.terminal:
                    break  # Terminal polling is not a new logical experience.
            result = entries[-1].content.result
            historical_trace = trace.model_copy(update={"entries": tuple(entries)})
            governance = (
                GovernanceOutcome.HUMAN_REJECTED
                if disposition == ReviewOutcome.REJECTED
                else GovernanceOutcome.BLOCKED
                if result.failure == WorkflowFailure.GOVERNANCE
                else GovernanceOutcome.WAITING
                if result.waiting_for_human
                else GovernanceOutcome.REVIEW_RECORDED
                if disposition is not None
                else GovernanceOutcome.NOT_RECORDED
            )
            content = ExperienceContent(
                incident_id=incident_id,
                snapshot=current.anchor,
                status=current.state.status,
                severity=current.state.severity,
                run_id=checkpoint.run_id,
                trace_head=entries[-1].entry_id,
                trace_digest=content_digest(historical_trace),
                current_step=result.current_step,
                next_step=result.next_step,
                terminal=result.terminal,
                waiting_for_human=result.waiting_for_human,
                failure=result.failure,
                execution_outcome=outcome,
                governance_outcome=governance,
                major_steps=tuple(e.content.result.current_step for e in entries),
                policy_preflight_results=tuple(
                    p.details.policy_preflight.decision for p in a.response_plan.proposed_actions
                )
                if a.response_plan
                else (),
                response_disposition=(
                    execution.intent.promoted.content.request.review.intent.disposition
                    if execution
                    else None
                ),
                execution_lifecycle=execution.state if execution else None,
                execution_revision=execution.revision if execution else None,
                reconciliation=reconciliation,
                human_disposition=disposition,
                references=tuple(sorted(references, key=lambda r: (r.kind, str(r.identity)))),
                orchestration_step_count=len(entries),
                investigation_rounds=checkpoint.rounds,
                started_at=checkpoint.created_at,
            )
            value = Experience(experience_id=content_digest(content), content=content)
            return self.store._insert(connection, value)

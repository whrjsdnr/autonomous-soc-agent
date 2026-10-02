"""Deterministic measurement; no inference, quality judgment, governance or execution."""

from uuid import UUID

from soc_agent.evaluation.models import EvaluationContent, EvaluationRecord
from soc_agent.evaluation.sources import validate_sources
from soc_agent.evaluation.store import EvaluationStore
from soc_agent.execution.durable.models import Lifecycle
from soc_agent.experience.models import GovernanceOutcome, HistoricalOutcome
from soc_agent.investigation.runtime.models import WorkflowFailure, WorkflowStep
from soc_agent.policy import PolicyDecision
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import StoredDataError


class ExperienceEvaluator:
    def __init__(self, store: EvaluationStore) -> None:
        self.store = store

    def evaluate(
        self,
        experience_id: str,
        *,
        expected_incident_id: UUID | None = None,
        expected_experience_digest: str | None = None,
    ) -> EvaluationRecord:
        with self.store.database.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM experiences WHERE experience_id=?",
                (experience_id,),
            ).fetchone()
            if row is None:
                raise StoredDataError("Unknown Experience")
            experience = self.store.experiences._decode(row)
            c = experience.content
            digest = content_digest(experience)
            if (expected_incident_id is not None and expected_incident_id != c.incident_id) or (
                expected_experience_digest is not None and expected_experience_digest != digest
            ):
                raise StoredDataError("Foreign or stale Experience binding")
            trace, execution = validate_sources(connection, self.store.experiences, experience)
            kinds = {r.kind for r in c.references}
            boundary = execution.invocation_started_at is not None if execution else None
            # EXECUTING proves only that invocation MAY have started. Never count it as a call.
            attempted = (
                True
                if execution and execution.state == Lifecycle.SUCCEEDED
                else False
                if boundary is False
                else None
            )
            start, end = c.started_at, c.completed_at
            facts = EvaluationContent(
                experience_id=experience.experience_id,
                experience_digest=digest,
                incident_id=c.incident_id,
                run_id=c.run_id,
                trace_digest=c.trace_digest,
                current_step=c.current_step,
                next_step=c.next_step,
                terminal=c.terminal,
                waiting_for_human=c.waiting_for_human,
                workflow_failure=c.failure,
                orchestration_step_count=len(trace.entries),
                recovery_observed=any(
                    WorkflowStep.RECOVER
                    in (
                        e.content.result.current_step,
                        e.content.result.next_step,
                    )
                    for e in trace.entries
                ),
                governance_outcome=c.governance_outcome,
                human_review_observed="incident_review" in kinds or "response_review" in kinds,
                human_rejected=c.governance_outcome == GovernanceOutcome.HUMAN_REJECTED,
                governance_blocked=c.governance_outcome == GovernanceOutcome.BLOCKED,
                policy_deny_observed=PolicyDecision.DENY in c.policy_preflight_results,
                execution_outcome=c.execution_outcome,
                execution_attempted=attempted,
                invocation_boundary_observed=boundary,
                execution_failed=c.execution_outcome == HistoricalOutcome.FAILED,
                execution_uncertain=c.execution_outcome == HistoricalOutcome.UNCERTAIN,
                uncertain_observed=c.execution_outcome == HistoricalOutcome.UNCERTAIN
                or any(
                    e.content.result.failure == WorkflowFailure.UNCERTAIN for e in trace.entries
                ),
                reconciliation_observed=c.reconciliation is not None,
                investigation_rounds_recorded=c.investigation_rounds,
                analysis_observed="assessment" in kinds,
                fusion_observed="fusion" in kinds,
                workflow_started_at=start,
                workflow_completed_at=end,
                duration_seconds=(end - start).total_seconds() if start and end else None,
            )
            value = EvaluationRecord(evaluation_id=content_digest(facts), content=facts)
            return self.store._insert(connection, value)

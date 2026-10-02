"""Read-only validation of the exact historical sources referenced by an Experience."""

from sqlite3 import Connection

from pydantic import BaseModel

from soc_agent.assessment import FusionAssessmentResult
from soc_agent.execution.durable.models import ExecutionEvent, ExecutionRecord
from soc_agent.execution.durable.store import ExecutionStore
from soc_agent.experience.models import Experience, GovernanceOutcome
from soc_agent.experience.store import ExperienceStore
from soc_agent.investigation.runtime.models import WorkflowFailure
from soc_agent.investigation.runtime.persistence import CheckpointStore
from soc_agent.investigation.runtime.trace import OrchestrationTrace
from soc_agent.review.identity import content_digest
from soc_agent.review.models import ReviewOutcome
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.review.persistence.session import GovernanceSession
from soc_agent.review.validation import validate_decision


def validate_sources(
    connection: Connection,
    store: ExperienceStore,
    experience: Experience,
) -> tuple[OrchestrationTrace, ExecutionRecord | None]:
    c = experience.content
    session = GovernanceSession(connection, store.database.store_id)
    historical = session.snapshot(c.snapshot).state
    if (historical.incident_id, historical.status, historical.severity) != (
        c.incident_id,
        c.status,
        c.severity,
    ):
        raise StoredDataError("Experience snapshot mismatch")
    # Historical progress can remain valid after current state/run progress advances.
    checkpoints = CheckpointStore(store.governance)
    checkpoint, whole_trace, _ = checkpoints._read(connection, c.incident_id)
    if checkpoint.run_id != c.run_id or checkpoint.created_at != c.started_at:
        raise StoredDataError("Experience workflow binding mismatch")
    prefix = []
    for entry in whole_trace.entries:
        prefix.append(entry)
        if entry.entry_id == c.trace_head:
            break
    trace = OrchestrationTrace(incident_id=c.incident_id, entries=tuple(prefix))
    if not prefix or prefix[-1].entry_id != c.trace_head or content_digest(trace) != c.trace_digest:
        raise StoredDataError("Experience trace reference is missing or changed")
    last = prefix[-1].content
    result = last.result
    if (
        last.snapshot != c.snapshot
        or len(prefix) != c.orchestration_step_count
        or tuple(e.content.result.current_step for e in prefix) != c.major_steps
        or (
            result.current_step,
            result.next_step,
            result.terminal,
            result.waiting_for_human,
            result.failure,
        )
        != (c.current_step, c.next_step, c.terminal, c.waiting_for_human, c.failure)
        or c.investigation_rounds > checkpoint.rounds
    ):
        raise StoredDataError("Experience progress differs from trace")
    requested = {(r.kind, str(r.identity)): r for r in c.references}
    repeated_kinds = {
        "evidence",
        "observation",
        "hypothesis",
        "signal",
        "proposal",
        "state_authorization",
    }
    kinds = [r.kind for r in c.references]
    if any(kinds.count(kind) > 1 for kind in set(kinds) - repeated_kinds):
        raise StoredDataError("Ambiguous historical source reference")
    if any((r.kind, r.identity) not in requested for r in result.references):
        raise StoredDataError("Experience omitted a trace artifact")
    sources: dict[tuple[str, str], BaseModel] = {}

    def add(kind, identity, value):
        sources[(kind, str(identity))] = value

    for kind, values, key in (
        ("evidence", historical.evidence, "evidence_id"),
        ("observation", historical.observations, "observation_id"),
        ("hypothesis", historical.hypotheses, "hypothesis_id"),
    ):
        for value in values:
            add(kind, getattr(value, key), value)
    a = checkpoint.artifacts
    if a.investigation:
        add("investigation", a.investigation.plan_id, a.investigation)
    if a.assessment:
        add(
            "assessment",
            a.assessment.threat_assessment.assessment_id,
            a.assessment.threat_assessment,
        )
        if isinstance(a.assessment, FusionAssessmentResult):
            fusion = a.assessment.model_derived_context
            add("fusion", fusion.fusion_id, fusion)
            for signal in fusion.signals:
                add("signal", signal.signal_id, signal)
    if a.decision:
        if ("decision", a.decision.decision_id) in requested:
            validate_decision(historical, a.decision)
        add("decision", a.decision.decision_id, a.decision)
    plan = a.response_plan
    review = None
    for ref in c.references:
        if ref.kind == "incident_review":
            review = ledger.get(connection, "reviews", str(ref.identity))
            request = ledger.get(connection, "review_requests", str(review.review_request_id))
            decision = ledger.get(connection, "decisions", review.target.decision_digest)
            if (
                review.target != request.target
                or review.target.snapshot != c.snapshot
                or decision.incident_id != c.incident_id
                or decision.decision_id != review.target.decision_id
            ):
                raise StoredDataError("Experience review lineage mismatch")
            validate_decision(historical, decision)
            add("incident_review", review.review_id, review)
            add("decision", decision.decision_id, decision)
            add("assessment", decision.assessment.assessment_id, decision.assessment)
        elif ref.kind == "state_authorization":
            authorization = ledger.get(connection, "authorizations", str(ref.identity))
            request = ledger.get(connection, "requests", str(authorization.request.request_id))
            if (
                authorization.request != request
                or request.target.snapshot != c.snapshot
                or authorization.request_digest != content_digest(request)
                or review is None
                or request.review_id != review.review_id
            ):
                raise StoredDataError("Experience authorization lineage mismatch")
            add("state_authorization", authorization.authorization_id, authorization)
    if (review.outcome if review else None) != c.human_disposition:
        raise StoredDataError("Experience disposition mismatch")
    expected_governance = (
        GovernanceOutcome.HUMAN_REJECTED
        if c.human_disposition == ReviewOutcome.REJECTED
        else GovernanceOutcome.BLOCKED
        if c.failure == WorkflowFailure.GOVERNANCE
        else GovernanceOutcome.WAITING
        if c.waiting_for_human
        else GovernanceOutcome.REVIEW_RECORDED
        if c.human_disposition is not None
        else GovernanceOutcome.NOT_RECORDED
    )
    if c.governance_outcome != expected_governance:
        raise StoredDataError("Experience governance summary differs from sources")
    execution = None
    for ref in c.references:
        if ref.kind != "execution_event":
            continue
        row = connection.execute(
            "SELECT * FROM execution_events WHERE event_id=?",
            (str(ref.identity),),
        ).fetchone()
        if row is None:
            raise StoredDataError("Missing execution event")
        event = ledger.decode(ExecutionEvent, row)
        execution = event.record
        intent = execution.intent
        if (
            str(event.event_id) != row["event_id"]
            or execution.revision != row["revision"]
            or intent.execution_intent_id != row["execution_id"]
            or execution.revision != c.execution_revision
            or execution.state != c.execution_lifecycle
            or intent.binding.incident_id != c.incident_id
            or intent.promoted.content.current_snapshot != c.snapshot
        ):
            raise StoredDataError("Experience execution event binding mismatch")
        reader = ExecutionStore(store.governance)
        current = reader._load(connection, intent.execution_intent_id)
        if current.intent != intent:
            raise StoredDataError("Historical execution intent changed")
        if (
            event.reconciliation.request.outcome if event.reconciliation else None
        ) != c.reconciliation:
            raise StoredDataError("Experience reconciliation mismatch")
        if event.reconciliation:
            reconciliation = event.reconciliation.request
            if (
                event.event_type != "reconciled"
                or reconciliation.execution_intent_id != intent.execution_intent_id
                or reconciliation.incident_id != c.incident_id
                or reconciliation.expected_revision + 1 != execution.revision
            ):
                raise StoredDataError("Historical reconciliation lineage mismatch")
        add("execution_event", event.event_id, event)
        add("execution_record", intent.execution_intent_id, execution)
        add("execution_intent", intent.execution_intent_id, intent)
        add("promoted_action", intent.promoted.promoted_id, intent.promoted)
        request = intent.promoted.content.request
        add("promotion_request", request.request_id, request)
        add("response_review", request.review.review_id, request.review)
        if c.response_disposition != request.review.intent.disposition:
            raise StoredDataError("Experience response disposition mismatch")
        if intent.approval:
            add("tool_approval", intent.approval.approval_id, intent.approval)
        plan = intent.plan
    if (execution is None) != (c.execution_revision is None):
        raise StoredDataError("Missing historical execution record")
    if plan and ("response_plan", plan.plan_id) in requested:
        if plan.content.basis.snapshot != c.snapshot or plan.content.basis.review != review:
            raise StoredDataError("Experience response plan lineage mismatch")
        add("response_plan", plan.plan_id, plan)
        for proposal in plan.proposed_actions:
            add("proposal", proposal.proposal_id, proposal)
        if c.policy_preflight_results != tuple(
            p.details.policy_preflight.decision for p in plan.proposed_actions
        ):
            raise StoredDataError("Experience preflight mismatch")
    for key, ref in requested.items():
        if key not in sources or content_digest(sources[key]) != ref.digest:
            raise StoredDataError("Experience reference is missing, stale or forged")
    return trace, execution

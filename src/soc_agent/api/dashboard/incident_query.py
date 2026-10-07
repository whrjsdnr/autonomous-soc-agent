"""Deterministic incident projection. No model calls, runtime restore or authority checks."""

import re

from soc_agent.api.dashboard import incident_models as views
from soc_agent.api.dashboard.models import HumanActionView, SignalView
from soc_agent.api.dashboard.query import project_overview
from soc_agent.assessment import FusionAssessmentResult
from soc_agent.investigation.runtime.models import WorkflowFailure, WorkflowStep
from soc_agent.review.models import (
    ApplicationResult,
    HumanReviewRecord,
    HumanReviewRequest,
    StateChangeAuthorization,
    StateChangeRequest,
)
from soc_agent.review.persistence.incident_detail import IncidentDetailSource

# The existing feedback credential-marker rejection convention, applied conservatively
# to display text. Raw Evidence, action inputs, approval inputs and headers are never DTO fields.
_AUTH_MATERIAL = re.compile(
    r"(?i)(password|passwd|secret|token|credential|api[_ -]?key|authorization|cookie)\s*[:=]"
    r"|\bbearer\s+\S+|-----BEGIN.*PRIVATE KEY-----"
)


def display_text(value: str) -> str:
    if _AUTH_MATERIAL.search(value):
        return "[WITHHELD: authentication material marker]"
    return value[:4000]


def workflow_view(source: IncidentDetailSource) -> views.WorkflowDetail | None:
    saved = source.source.checkpoint
    if saved is None:
        return None
    entries = source.trace.entries if source.trace else ()
    result = saved.result
    stages = []
    for step in WorkflowStep:
        status = "NOT OBSERVED"
        last = next(
            (e.content.result for e in reversed(entries) if e.content.result.current_step == step),
            None,
        )
        if last:
            status = "ADVANCED" if last.next_step != step else "UNKNOWN"
            if last.failure is not None:
                status = "UNKNOWN" if last.failure == WorkflowFailure.UNCERTAIN else "FAILED"
        if step == result.next_step:
            status = (
                "TERMINAL"
                if result.terminal
                else "UNKNOWN"
                if source.source.claimed
                else "WAITING"
                if result.waiting_for_human
                else "CURRENT"
            )
        stages.append(views.StageView(step=step, status=status))
    return views.WorkflowDetail(
        run_id=saved.run_id,
        revision=saved.revision,
        snapshot_revision=saved.artifacts.snapshot.revision,
        matches_current_state=saved.artifacts.snapshot == source.source.incident.anchor,
        current=result.current_step,
        next_step=result.next_step,
        failure=result.failure.value if result.failure else None,
        claimed=source.source.claimed,
        terminal=result.terminal,
        stages=tuple(stages),
        trace=tuple(
            views.TraceView(
                sequence=e.content.sequence,
                reference=e.entry_id,
                current=e.content.result.current_step,
                next_step=e.content.result.next_step,
                waiting=e.content.result.waiting_for_human,
                failure=e.content.result.failure.value if e.content.result.failure else None,
                reason=display_text(e.content.result.reason),
            )
            for e in entries
        ),
    )


def project_incident(source: IncidentDetailSource) -> views.IncidentDetailView:
    state = source.source.incident.state
    saved = source.source.checkpoint
    artifacts = saved.artifacts if saved else None
    overview = project_overview((source.source,))
    anchors = {str(e.evidence_id): f"evidence-{e.evidence_id}" for e in state.evidence}
    anchors.update(
        {str(o.observation_id): f"observation-{o.observation_id}" for o in state.observations}
    )
    anchors.update(
        {str(h.hypothesis_id): f"hypothesis-{h.hypothesis_id}" for h in state.hypotheses}
    )
    timeline, provenance = [], []

    def ref(identity, label):
        return views.ReferenceView(
            identity=str(identity), label=label, anchor=anchors.get(str(identity))
        )

    def clock(timestamp, description, reference):
        if timestamp is not None:
            timeline.append(
                views.TimelineView(
                    timestamp=timestamp, description=description, reference=str(reference)
                )
            )

    def edge(start, end, label):
        provenance.append(views.ProvenanceView(source=start, target=end, relation=label))

    clock(state.created_at, "Incident created", state.incident_id)
    if saved:
        clock(saved.updated_at, "Retained workflow checkpoint updated", saved.run_id)
    evidence = tuple(
        views.EvidenceView(
            evidence_id=e.evidence_id,
            source=display_text(e.source),
            summary=display_text(e.summary),
            tool=display_text(e.tool_name) if e.tool_name else None,
            observed_at=e.observed_at,
            collected_at=e.collected_at,
            reliability=e.reliability,
        )
        for e in sorted(state.evidence, key=lambda e: str(e.evidence_id))
    )
    observations = tuple(
        views.ObservationView(
            observation_id=o.observation_id,
            statement=display_text(o.statement),
            created_at=o.created_at,
            supporting=tuple(ref(eid, "Evidence") for eid in o.supporting_evidence_ids),
        )
        for o in sorted(state.observations, key=lambda o: str(o.observation_id))
    )
    hypotheses = tuple(
        views.HypothesisView(
            hypothesis_id=h.hypothesis_id,
            statement=display_text(h.statement),
            created_at=h.created_at,
            confidence=h.confidence,
            supporting=tuple(ref(eid, "Evidence") for eid in h.supporting_evidence_ids),
        )
        for h in sorted(state.hypotheses, key=lambda h: str(h.hypothesis_id))
    )
    for e in evidence:
        clock(e.observed_at, "Evidence observed", e.evidence_id)
        clock(e.collected_at, "Evidence collected", e.evidence_id)
    for o in observations:
        clock(o.created_at, "Observation created", o.observation_id)
        for parent in o.supporting:
            edge(parent, ref(o.observation_id, "Observation"), "supports")
    for h in hypotheses:
        clock(h.created_at, "Hypothesis created (unverified)", h.hypothesis_id)
        for parent in h.supporting:
            edge(parent, ref(h.hypothesis_id, "Hypothesis"), "supports interpretation")
    investigation = None
    if artifacts and artifacts.investigation:
        plan = artifacts.investigation
        investigation = views.InvestigationView(
            plan_id=plan.plan_id,
            goal=display_text(plan.goal) if plan.goal else None,
            created_at=plan.created_at,
            steps=tuple(
                views.InvestigationStepView(
                    step_id=s.step_id,
                    action_id=s.action_id,
                    tool=display_text(s.tool_name),
                    status=s.status.value,
                    purpose=display_text(s.purpose),
                    evidence=ref(s.evidence_id, "Evidence") if s.evidence_id else None,
                    error_type=display_text(s.failure.error_type) if s.failure else None,
                )
                for s in plan.steps
            ),
        )
        clock(plan.created_at, "Investigation plan created", plan.plan_id)
    assessment = None
    if artifacts and artifacts.assessment:
        a = artifacts.assessment.threat_assessment
        anchors[str(a.assessment_id)] = "assessment"
        assessment = views.AssessmentView(
            assessment_id=a.assessment_id,
            severity=a.severity.value,
            summary=display_text(a.summary),
            created_at=a.created_at,
            supporting=(
                *(ref(eid, "Evidence") for eid in a.supporting_evidence_ids),
                *(ref(oid, "Observation") for oid in a.supporting_observation_ids),
                *(ref(hid, "Hypothesis") for hid in a.supporting_hypothesis_ids),
            ),
            fusion_reference=(
                artifacts.assessment.model_derived_context.fusion_id
                if isinstance(artifacts.assessment, FusionAssessmentResult)
                else None
            ),
        )
        clock(a.created_at, "Advisory assessment created", a.assessment_id)
        for parent in assessment.supporting:
            edge(parent, ref(a.assessment_id, "Assessment"), "referenced by advisory assessment")
    decision = None
    if artifacts and artifacts.decision:
        d = artifacts.decision
        anchors[d.decision_id] = "decision"
        decision = views.DecisionView(
            decision_id=d.decision_id,
            outcome=d.outcome.value,
            rationale=tuple(display_text(t) for t in d.rationale),
            review_reasons=tuple(display_text(t) for t in d.review_reasons),
            investigation_reasons=tuple(display_text(t) for t in d.investigation_reasons),
            uncertainties=tuple(display_text(t) for t in (*d.uncertainties, *d.limitations)),
            supporting=(
                ref(d.assessment.assessment_id, "Assessment"),
                *(ref(eid, "Evidence") for eid in d.evidence_ids),
            ),
        )
        edge(
            ref(d.assessment.assessment_id, "Assessment"),
            ref(d.decision_id, "Decision"),
            "basis of advisory decision",
        )
    governance = []
    reviewed = {r.review_request_id for r in source.governance if isinstance(r, HumanReviewRecord)}
    for record in source.governance:
        if isinstance(record, HumanReviewRequest):
            item = views.GovernanceView(
                domain="Incident Review request",
                reference=str(record.review_request_id),
                status="RECORDED REVIEW" if record.review_request_id in reviewed else "PENDING",
                timestamp=record.created_at,
                related=(record.target.decision_id,),
            )
        elif isinstance(record, HumanReviewRecord):
            item = views.GovernanceView(
                domain="Incident Review",
                reference=str(record.review_id),
                status=record.outcome.value,
                actor=display_text(record.reviewer_id),
                timestamp=record.recorded_at,
                related=(str(record.review_request_id), record.target.decision_id),
            )
        elif isinstance(record, StateChangeRequest):
            item = views.GovernanceView(
                domain="State Change Request",
                reference=str(record.request_id),
                status="PROPOSED",
                related=(str(record.review_id),),
            )
        elif isinstance(record, StateChangeAuthorization):
            item = views.GovernanceView(
                domain="State Change Authorization",
                reference=str(record.authorization_id),
                status="ISSUED (application separate)",
                actor=display_text(record.authorized_by),
                timestamp=record.issued_at,
                related=(str(record.request.request_id),),
            )
        elif isinstance(record, ApplicationResult):
            item = views.GovernanceView(
                domain="State Change Application",
                reference=str(record.audit.application_id),
                status=record.audit.outcome,
                actor=display_text(record.audit.authorized_by),
                timestamp=record.audit.applied_at,
                related=(str(record.audit.authorization_id),),
            )
        else:
            continue
        governance.append(item)
        anchors[item.reference] = "governance"
        clock(item.timestamp, item.domain + " recorded", item.reference)
        if isinstance(record, HumanReviewRecord):
            edge(
                ref(record.target.decision_id, "Decision"),
                ref(record.review_id, "Incident Review"),
                "review targets exact decision",
            )
    for record in source.executions:
        intent = record.intent
        review = intent.promoted.content.request.review
        governance.append(
            views.GovernanceView(
                domain="Response Action Review",
                reference=str(review.review_id),
                status=review.intent.disposition.value,
                actor=display_text(review.intent.reviewer_id),
                timestamp=review.created_at,
                related=(review.intent.target.proposal.proposal_id,),
            )
        )
        clock(review.created_at, "Response Action Review recorded", review.review_id)
        if intent.approval:
            approval = intent.approval
            governance.append(
                views.GovernanceView(
                    domain="Tool Approval",
                    reference=str(approval.approval_id),
                    status=approval.status.value,
                    actor=display_text(approval.decision.decided_by) if approval.decision else None,
                    timestamp=approval.decision.decided_at
                    if approval.decision
                    else approval.created_at,
                    related=(str(approval.action_id),),
                )
            )
            clock(approval.created_at, "Tool Approval requested", approval.approval_id)
            if approval.decision:
                clock(approval.decision.decided_at, "Tool Approval decided", approval.approval_id)
    for event in source.execution_events:
        clock(
            event.occurred_at,
            f"Execution event: {event.event_type}",
            event.record.intent.execution_intent_id,
        )
        if event.reconciliation:
            r = event.reconciliation
            governance.append(
                views.GovernanceView(
                    domain="Durable Reconciliation",
                    reference=str(event.event_id),
                    status=r.request.outcome.value,
                    actor=display_text(r.actor),
                    timestamp=r.created_at,
                    related=(r.request.execution_intent_id,),
                )
            )
    # Deduplicate records preserved inside multiple intents without losing their domain.
    governance = list({(g.domain, g.reference): g for g in governance}.values())
    governance.sort(key=lambda g: (g.domain, g.reference))
    responses = []
    plans = {}
    if artifacts and artifacts.response_plan:
        plans[artifacts.response_plan.plan_id] = artifacts.response_plan
    for r in source.executions:
        plans[r.intent.plan.plan_id] = r.intent.plan
    for plan_id, plan in sorted(plans.items()):
        clock(plan.created_at, "Advisory response plan created", plan_id)
        for p in plan.proposed_actions:
            promoted = next(
                (
                    r.intent.promoted
                    for r in source.executions
                    if r.intent.promoted.content.request.target.proposal == p
                ),
                None,
            )
            responses.append(
                views.ResponseView(
                    proposal_id=p.proposal_id,
                    plan_id=plan_id,
                    tool=display_text(p.details.metadata.name),
                    permission=p.details.metadata.permission.value,
                    category=p.details.category.value,
                    status="PROMOTED" if promoted else "PROPOSED",
                    purpose=display_text(p.details.intent.purpose),
                    promoted_reference=promoted.promoted_id if promoted else None,
                    created_at=plan.created_at,
                )
            )
            anchors[p.proposal_id] = "response"
            edge(
                ref(plan.content.basis.review.review_id, "Incident Review"),
                ref(p.proposal_id, "Response proposal"),
                "planning basis includes review",
            )
            if promoted:
                clock(
                    promoted.created_at, "Response promoted (not execution)", promoted.promoted_id
                )
    executions = []
    for r in source.executions:
        events = [
            e for e in source.execution_events if e.record.intent == r.intent and e.reconciliation
        ]
        reconciled = events[-1].reconciliation.request.outcome.value if events else None
        action = r.intent.action()
        executions.append(
            views.ExecutionView(
                execution_id=r.intent.execution_intent_id,
                action_id=action.action_id,
                proposal_id=r.intent.promoted.content.request.target.proposal.proposal_id,
                promoted_id=r.intent.promoted.promoted_id,
                tool=display_text(r.intent.binding.tool_name),
                status=r.state.value,
                created_at=r.intent.created_at,
                started_at=r.invocation_started_at,
                finished_at=r.finished_at,
                reconciliation=reconciled,
            )
        )
        anchors[r.intent.execution_intent_id] = "execution"
        edge(
            ref(r.intent.promoted.content.request.target.proposal.proposal_id, "Response proposal"),
            ref(r.intent.execution_intent_id, "Execution intent"),
            "durable execution binding",
        )
    feedback_counts = dict(source.feedback_counts)
    outcomes = tuple(
        views.OutcomeView(
            evaluation_id=v.evaluation_id,
            experience_id=v.content.experience_id,
            run_id=v.content.run_id,
            execution_outcome=v.content.execution_outcome.value,
            governance_outcome=v.content.governance_outcome.value,
            terminal=v.content.terminal,
            recovery_observed=v.content.recovery_observed,
            created_at=v.created_at,
            feedback_count=feedback_counts.get(v.evaluation_id),
        )
        for v in source.evaluations
    )
    for v in outcomes:
        clock(v.created_at, "Descriptive outcome evaluation recorded", v.evaluation_id)
    timeline = list({(t.timestamp, t.description, t.reference): t for t in timeline}.values())
    timeline.sort(key=lambda t: (t.timestamp, t.description, t.reference))
    return views.IncidentDetailView(
        incident_id=state.incident_id,
        status=state.status.value,
        severity=state.severity.value,
        revision=source.source.incident.anchor.revision,
        created_at=state.created_at,
        updated_at=state.updated_at,
        sources=tuple(display_text(s) for s in sorted({e.source for e in state.evidence})),
        workflow=workflow_view(source),
        human_actions=tuple(
            HumanActionView(**(a.model_dump() | {"reason": display_text(a.reason)}))
            for a in overview.human_actions
        ),
        signals=tuple(
            SignalView(
                **(
                    s.model_dump()
                    | {
                        "state": display_text(s.state),
                        "provenance": tuple(display_text(t) for t in s.provenance),
                    }
                )
            )
            for s in overview.signals
        ),
        evidence=evidence,
        observations=observations,
        hypotheses=hypotheses,
        investigation=investigation,
        assessment=assessment,
        decision=decision,
        governance=tuple(governance),
        responses=tuple(responses),
        executions=tuple(executions),
        outcomes=outcomes,
        provenance=tuple(provenance),
        timeline=tuple(timeline),
    )

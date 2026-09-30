"""Stateful coordination, with no human authority or direct tool invocation."""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from uuid import UUID

from soc_agent.assessment import AssessmentResult, FusionAssessmentResult, ThreatAssessor
from soc_agent.decision import IncidentDecision, IncidentDecisionEngine
from soc_agent.execution.durable import DurableExecutor, Lifecycle
from soc_agent.execution.durable.models import ExecutionBinding
from soc_agent.execution.errors import ApprovalRequiredError
from soc_agent.investigation.models import InvestigationPlan, InvestigationStepStatus
from soc_agent.investigation.orchestrator import InvestigationOrchestrator
from soc_agent.investigation.runtime.models import (
    ArtifactReference,
    WorkflowArtifacts,
    WorkflowFailure,
    WorkflowResult,
    WorkflowStep,
)
from soc_agent.investigation.runtime.trace import (
    OrchestrationTrace,
    OrchestrationTraceEntry,
    TraceContent,
)
from soc_agent.planning import InvestigationPlanner
from soc_agent.response.advisory import (
    CandidateIntent,
    PersistentPlanningSource,
    ResponsePlan,
    ResponsePlanner,
)
from soc_agent.response.promotion import ExecutionBridge, PromotedAction
from soc_agent.review.identity import content_digest
from soc_agent.review.models import HumanReviewRecord, ReviewOutcome, StateAnchor
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.validation import checked
from soc_agent.security_ai.fusion import FusionResult
from soc_agent.state import IncidentState, IncidentStatus


@dataclass
class _Workflow:
    anchor: StateAnchor
    step: WorkflowStep = WorkflowStep.OBSERVE
    investigation: InvestigationPlan | None = None
    assessment: FusionAssessmentResult | AssessmentResult | None = None
    decision: IncidentDecision | None = None
    review: HumanReviewRecord | None = None
    plan: ResponsePlan | None = None
    promoted: PromotedAction | None = None
    approval_id: UUID | None = None
    execution_id: str | None = None
    rounds: int = 0
    attempted: set[tuple[str, str]] = field(default_factory=set)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    failure: WorkflowFailure | None = None
    trace_entries: tuple[OrchestrationTraceEntry, ...] = ()


class SOCRuntime:
    """One bounded step per call. Human artifacts and execution dispatch are explicit.

    Workflow cursors are process-local. Incident state and execution records are
    authoritative SQLite data. An injected analysis adapter may compose the existing
    SecurityAIInvestigator and FusionEngine; it must not grant execution authority.
    """

    def __init__(
        self,
        *,
        investigator: InvestigationOrchestrator,
        store: SQLiteGovernanceStore,
        planner: InvestigationPlanner,
        assessor: ThreatAssessor,
        responses: ResponsePlanner,
        bridge: ExecutionBridge,
        executor: DurableExecutor,
        model_analysis: Callable[[IncidentState], Awaitable[FusionResult]] | None = None,
        max_investigation_rounds: int = 2,
    ) -> None:
        if type(max_investigation_rounds) is not int or max_investigation_rounds < 1:
            raise ValueError("A positive finite investigation budget is required")
        if executor.store.governance.store_id != store.store_id:
            raise ValueError("Runtime and execution must use the same authoritative store")
        self._investigator, self._store, self._planner = investigator, store, planner
        self._assessor, self._responses = assessor, responses
        self._bridge, self._executor = bridge, executor
        self._models = model_analysis
        self._limit = max_investigation_rounds
        self._workflows: dict[UUID, _Workflow] = {}
        self._source = PersistentPlanningSource(store)

    def start(self, incident_id: UUID) -> WorkflowResult:
        if incident_id in self._workflows:
            raise ValueError("Workflow already exists; resume it with advance")
        current = self._store.load(incident_id)
        workflow = _Workflow(current.anchor)
        self._workflows[incident_id] = workflow
        return self._result(
            workflow, WorkflowStep.OBSERVE, "Incident observed; no action dispatched"
        )

    def artifacts(self, incident_id: UUID) -> WorkflowArtifacts:
        workflow = self._workflows[incident_id]
        return WorkflowArtifacts(
            snapshot=workflow.anchor,
            investigation=workflow.investigation,
            assessment=workflow.assessment,
            decision=workflow.decision,
            response_plan=workflow.plan,
            execution_intent_id=workflow.execution_id,
        )

    def trace(self, incident_id: UUID) -> OrchestrationTrace:
        """Read-only snapshot. Polling does not append entries."""
        return OrchestrationTrace(
            incident_id=incident_id, entries=self._workflows[incident_id].trace_entries
        )

    def validate_trace(self, value: OrchestrationTrace) -> OrchestrationTrace:
        """Compare against this live runtime's exact lineage, not a grant of authority."""
        value = checked(OrchestrationTrace, value)
        if value != self.trace(value.incident_id):
            raise ValueError("Trace differs from the runtime's recorded artifact bindings")
        return value

    def _result(
        self,
        workflow: _Workflow,
        current: WorkflowStep,
        reason: str,
        *,
        waiting: bool = False,
        failure: WorkflowFailure | None = None,
    ) -> WorkflowResult:
        references = []
        for kind, identity in (
            ("investigation", workflow.investigation.plan_id if workflow.investigation else None),
            (
                "assessment",
                workflow.assessment.threat_assessment.assessment_id
                if workflow.assessment
                else None,
            ),
            ("decision", workflow.decision.decision_id if workflow.decision else None),
            ("incident_review", workflow.review.review_id if workflow.review else None),
            ("response_plan", workflow.plan.plan_id if workflow.plan else None),
            ("promoted_action", workflow.promoted.promoted_id if workflow.promoted else None),
            ("execution_intent", workflow.execution_id),
            ("tool_approval", workflow.approval_id),
            (
                "fusion",
                workflow.assessment.model_derived_context.fusion_id
                if isinstance(workflow.assessment, FusionAssessmentResult)
                else None,
            ),
        ):
            if identity is not None:
                references.append(ArtifactReference(kind=kind, identity=str(identity)))
        workflow.failure = failure
        result = WorkflowResult(
            incident_id=workflow.anchor.incident_id,
            current_step=current,
            next_step=workflow.step,
            reason=reason,
            references=tuple(references),
            waiting_for_human=waiting,
            terminal=workflow.step == WorkflowStep.COMPLETE,
            failure=failure,
        )
        last = workflow.trace_entries[-1] if workflow.trace_entries else None
        if last is None or (last.content.result, last.content.snapshot) != (
            result,
            workflow.anchor,
        ):
            content = TraceContent(
                sequence=len(workflow.trace_entries) + 1,
                snapshot=workflow.anchor,
                result=result,
                previous_entry_id=last.entry_id if last else None,
            )
            entry = OrchestrationTraceEntry(entry_id=content_digest(content), content=content)
            workflow.trace_entries = (*workflow.trace_entries, entry)
        return result

    async def advance(
        self,
        incident_id: UUID,
        *,
        review: HumanReviewRecord | None = None,
        candidates: tuple[CandidateIntent, ...] = (),
        promoted: PromotedAction | None = None,
        approval_id: UUID | None = None,
        execute: bool = False,
    ) -> WorkflowResult:
        workflow = self._workflows[incident_id]
        async with workflow.lock:
            current_step = workflow.step
            if current_step == WorkflowStep.COMPLETE:
                return self._result(
                    workflow, current_step, "Workflow is terminal", failure=workflow.failure
                )
            # Recovery must remain available after the incident changes during execution.
            if current_step in (WorkflowStep.RECOVER, WorkflowStep.EVALUATE):
                return self._outcome(workflow, current_step)
            try:
                current = self._store.load(incident_id)
                if current.anchor != workflow.anchor:
                    raise ValueError("Incident snapshot changed; explicit new workflow required")
                if current.state.status == IncidentStatus.CLOSED:
                    workflow.step = WorkflowStep.COMPLETE
                    return self._result(workflow, current_step, "Incident is closed")
                # Validate the whole input bundle before changing the cursor or artifacts.
                accepted_review = workflow.review
                accepted_promotion = workflow.promoted
                accepted_approval = workflow.approval_id
                if review is not None:
                    if workflow.decision is None or current_step not in (
                        WorkflowStep.PLAN,
                        WorkflowStep.GOVERN,
                    ):
                        raise ValueError("Review requires a decision at a review boundary")
                    review = checked(HumanReviewRecord, review)
                    self._source.validate_sources(current.state, workflow.decision, review)
                    if (
                        review.target.decision_id != workflow.decision.decision_id
                        or review.target.decision_digest != content_digest(workflow.decision)
                    ):
                        raise ValueError("Review targets another decision")
                    if accepted_review is not None and accepted_review != review:
                        raise ValueError("Review replacement requires a new workflow")
                    accepted_review = review
                if promoted is not None:
                    if current_step != WorkflowStep.GOVERN:
                        raise ValueError("Promotion is accepted only at governance")
                    if workflow.plan is None or self._bridge.source_plan(promoted) != workflow.plan:
                        raise ValueError("Promotion must originate from this exact workflow plan")
                    if accepted_promotion is not None and accepted_promotion != promoted:
                        raise ValueError("Promotion replacement requires a new workflow")
                    self._bridge.executable_action(promoted)
                    accepted_promotion = promoted
                if approval_id is not None:
                    if accepted_promotion is None:
                        raise ValueError("Approval requires an exact promotion")
                    self._bridge.validated_approval(accepted_promotion, approval_id)
                    accepted_approval = approval_id
                new_review = accepted_review is not None and workflow.review is None
                workflow.review = accepted_review
                workflow.promoted = accepted_promotion
                workflow.approval_id = accepted_approval
                if new_review:
                    workflow.step = (
                        WorkflowStep.PLAN
                        if accepted_review.outcome == ReviewOutcome.INVESTIGATE
                        else WorkflowStep.GOVERN
                    )
                    # Accepting external governance is itself one step. It does not reset
                    # investigation budgets or execute a plan on the same call.
                    return self._result(workflow, current_step, "Validated human review accepted")
            except Exception as error:
                # Fail closed without treating invalid human input as permission or retry.
                return self._result(
                    workflow,
                    current_step,
                    type(error).__name__,
                    waiting=True,
                    failure=WorkflowFailure.VALIDATION,
                )
            try:
                return await self._advance(
                    workflow, current.state, current_step, candidates, execute
                )
            except Exception as error:
                stage = workflow.step
                failure = (
                    WorkflowFailure.ANALYSIS
                    if stage in (WorkflowStep.ANALYZE, WorkflowStep.DECIDE)
                    else WorkflowFailure.GOVERNANCE
                    if stage in (WorkflowStep.GOVERN, WorkflowStep.ACT)
                    else WorkflowFailure.INVESTIGATION
                    if stage in (WorkflowStep.PLAN, WorkflowStep.ROUTE)
                    else WorkflowFailure.VALIDATION
                )
                # No automatic retry after adapter failure. The completed analysis, if any,
                # remains available for inspection. Dispatch failures use _dispatch instead.
                workflow.step = WorkflowStep.COMPLETE
                return self._result(workflow, current_step, type(error).__name__, failure=failure)

    async def _advance(
        self,
        w: _Workflow,
        state: IncidentState,
        current: WorkflowStep,
        candidates: tuple[CandidateIntent, ...],
        execute: bool,
    ) -> WorkflowResult:
        step = w.step
        if step == WorkflowStep.OBSERVE:
            w.step = WorkflowStep.ROUTE if state.evidence else WorkflowStep.PLAN
            return self._result(w, current, "Route current evidence or request investigation")
        if step == WorkflowStep.PLAN:
            if w.rounds >= self._limit:
                return self._result(
                    w,
                    current,
                    "Investigation budget exhausted; human review required",
                    waiting=True,
                    failure=WorkflowFailure.LOOP_GUARD,
                )
            plan = checked(InvestigationPlan, await self._planner.create_plan(state))
            if plan.incident_id != state.incident_id:
                raise ValueError("Investigation belongs to another incident")
            if any(s.status != InvestigationStepStatus.PENDING for s in plan.steps):
                raise ValueError("Only fresh pending investigation steps are accepted")
            if any((s.tool_name, s.tool_input) in w.attempted for s in plan.steps):
                w.rounds = self._limit
                return self._result(
                    w,
                    current,
                    "Repeated investigation intent; human review required",
                    waiting=True,
                    failure=WorkflowFailure.LOOP_GUARD,
                )
            w.investigation, w.rounds = plan, w.rounds + 1
            w.step = WorkflowStep.ROUTE
            return self._result(w, current, "Investigation selected")
        if step == WorkflowStep.ROUTE:
            pending = (
                next(
                    (
                        s
                        for s in w.investigation.steps
                        if s.status == InvestigationStepStatus.PENDING
                    ),
                    None,
                )
                if w.investigation
                else None
            )
            if pending:
                key = (pending.tool_name, pending.tool_input)
                if key in w.attempted:
                    w.step = WorkflowStep.PLAN
                    w.rounds = self._limit
                    return self._result(
                        w,
                        current,
                        "Repeated investigation intent blocked",
                        waiting=True,
                        failure=WorkflowFailure.LOOP_GUARD,
                    )
                w.attempted.add(key)
                result = await self._investigator.execute_step(
                    incident_state=state,
                    plan=w.investigation,
                    step_id=pending.step_id,
                    require_read_only=True,
                )
                w.investigation = result.plan
                completed = result.plan.get_step(pending.step_id)
                if completed.status != InvestigationStepStatus.COMPLETED:
                    w.step = WorkflowStep.COMPLETE
                    return self._result(
                        w,
                        current,
                        "Investigation was blocked or failed",
                        failure=WorkflowFailure.INVESTIGATION,
                    )
                evidence = next(
                    e
                    for e in result.incident_state.evidence
                    if e.evidence_id == completed.evidence_id
                )
                published = self._store.append_evidence(w.anchor, evidence)
                w.anchor = published.anchor
                # New evidence invalidates the old assessment and human review, not permission.
                w.assessment = w.decision = w.review = w.plan = None
                return self._result(w, current, "Read-only evidence collected")
            w.step = WorkflowStep.DECIDE if w.assessment else WorkflowStep.ANALYZE
            return self._result(
                w,
                current,
                "Existing assessment reused"
                if w.assessment
                else "Model/fusion analysis selected"
                if self._models
                else "Evidence analysis selected",
            )
        if step == WorkflowStep.ANALYZE:
            fusion = await self._models(state) if self._models else None
            result = await self._assessor.assess(state, fusion_result=fusion)
            result = checked(
                FusionAssessmentResult
                if type(result) is FusionAssessmentResult
                else AssessmentResult,
                result,
            )
            published = self._store.append_assessment(w.anchor, result)
            w.anchor, w.assessment = published.anchor, result
            w.step = WorkflowStep.DECIDE
            return self._result(w, current, "Assessment completed; severity remains advisory")
        if step == WorkflowStep.DECIDE:
            if w.assessment is None:
                raise ValueError("Decision requires an assessment")
            w.decision = IncidentDecisionEngine().decide(
                state,
                w.assessment.threat_assessment,
                fusion_assessment=w.assessment
                if isinstance(w.assessment, FusionAssessmentResult)
                else None,
            )
            w.step = (
                WorkflowStep.PLAN
                if w.decision.additional_investigation_required
                else WorkflowStep.GOVERN
            )
            return self._result(
                w,
                current,
                "Additional investigation required"
                if w.decision.additional_investigation_required
                else "Human review required",
                waiting=w.step == WorkflowStep.GOVERN,
            )
        if step == WorkflowStep.GOVERN:
            if w.review is None:
                return self._result(w, current, "Incident human review required", waiting=True)
            if w.review.outcome == ReviewOutcome.REJECTED:
                w.step = WorkflowStep.COMPLETE
                return self._result(
                    w,
                    current,
                    "Review rejected further response consideration",
                    failure=WorkflowFailure.GOVERNANCE,
                )
            if w.plan is None:
                if not candidates:
                    return self._result(
                        w, current, "Explicit response candidates required", waiting=True
                    )
                w.plan = self._responses.create_plan(
                    incident_state=state,
                    decision=w.decision,
                    review=w.review,
                    objective="Consider governed incident response",
                    candidates=candidates,
                )
            if w.promoted is None:
                return self._result(
                    w, current, "Response review and explicit promotion required", waiting=True
                )
            try:
                self._bridge.validated_approval(w.promoted, w.approval_id)
            except ApprovalRequiredError:
                return self._result(
                    w,
                    current,
                    "Exact human Tool Approval required",
                    waiting=True,
                    failure=WorkflowFailure.GOVERNANCE,
                )
            w.step = WorkflowStep.ACT
            return self._result(
                w, current, "Validated candidate; explicit dispatch required", waiting=True
            )
        if step == WorkflowStep.ACT:
            if not execute:
                return self._result(
                    w, current, "Explicit execution dispatch required", waiting=True
                )
            return await self._dispatch(w, current)
        raise ValueError("Unsupported workflow step")

    async def _dispatch(self, w: _Workflow, current: WorkflowStep) -> WorkflowResult:
        if w.promoted is None:
            raise ValueError("Dispatch requires an exact promotion")
        # Resolve policy and approval before recording an execution attempt. Compute the
        # existing durable identity so an ambiguous create commit remains queryable.
        action = self._bridge.executable_action(w.promoted)
        approval = self._bridge.validated_approval(w.promoted, w.approval_id)
        w.execution_id = content_digest(
            ExecutionBinding(
                incident_id=action.incident_id,
                promoted_action_id=w.promoted.promoted_id,
                tool_name=action.tool_name,
                canonical_input=action.tool_input,
                approval_id=approval.approval_id if approval else None,
            )
        )
        w.step = WorkflowStep.RECOVER
        try:
            record = self._executor.store.create(
                self._bridge, w.promoted, approval_id=w.approval_id
            )
            if record.state != Lifecycle.PENDING:
                return self._outcome(w, current)
            await self._executor.execute(w.execution_id, claimant="soc-runtime")
        except asyncio.CancelledError:
            self._result(
                w,
                current,
                "Dispatch cancelled; durable outcome requires recovery",
                waiting=True,
                failure=WorkflowFailure.UNCERTAIN,
            )
            raise
        except Exception:
            # Classify via authoritative lifecycle, never infer failure from a missing reply.
            # Cancellation also leaves RECOVER selected, and propagates to the caller.
            return self._outcome(w, current)
        return self._outcome(w, current)

    def _outcome(self, w: _Workflow, current: WorkflowStep) -> WorkflowResult:
        try:
            if w.execution_id is None:
                raise ValueError("No durable execution identity")
            record = self._executor.store.load(w.execution_id)
        except Exception as error:
            w.step = WorkflowStep.RECOVER
            return self._result(
                w,
                current,
                "Outcome unavailable: " + type(error).__name__,
                waiting=True,
                failure=WorkflowFailure.UNCERTAIN,
            )
        if record.state in (Lifecycle.SUCCEEDED, Lifecycle.FAILED):
            w.step = (
                WorkflowStep.COMPLETE if current == WorkflowStep.EVALUATE else WorkflowStep.EVALUATE
            )
            return self._result(
                w,
                current,
                "Durable outcome: " + record.state.value,
                failure=WorkflowFailure.EXECUTION if record.state == Lifecycle.FAILED else None,
            )
        w.step = WorkflowStep.RECOVER
        return self._result(
            w,
            current,
            "Recovery/reconciliation required: " + record.state.value,
            waiting=True,
            failure=WorkflowFailure.UNCERTAIN,
        )

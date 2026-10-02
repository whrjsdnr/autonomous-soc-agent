from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from soc_agent.evaluation import EvaluationStore, ExperienceEvaluator, migrate_evaluations
from soc_agent.evaluation.models import EvaluationContent, EvaluationRecord
from soc_agent.experience import ExperienceStore
from soc_agent.experience.models import HistoricalOutcome
from soc_agent.review.models import ReviewOutcome
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.tools.errors import ToolExecutionError
from tests.integration.experience.test_capture import capture_service, finish
from tests.unit.investigation_runtime.conftest import decision_ready, promoted_ready, review_for


def evaluator(case):
    migrate_evaluations(case.store.database)
    return ExperienceEvaluator(EvaluationStore(ExperienceStore(case.store)))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error,expected",
    [
        (None, HistoricalOutcome.SUCCEEDED),
        (ToolExecutionError("reported failure"), HistoricalOutcome.FAILED),
        (TimeoutError("unknown remote outcome"), HistoricalOutcome.UNCERTAIN),
    ],
)
async def test_durable_outcomes_and_restart(runtime_case, error, expected):
    case = runtime_case(durable_workflow=True, responses=[error] if error else None)
    await promoted_ready(case)
    await finish(case)
    experience = capture_service(case).capture(case.incident_id)
    service = evaluator(case)
    value = service.evaluate(experience.experience_id, expected_incident_id=case.incident_id)
    facts = value.content
    assert facts.execution_outcome == expected
    assert facts.execution_failed is (expected == HistoricalOutcome.FAILED)
    assert facts.execution_uncertain is (expected == HistoricalOutcome.UNCERTAIN)
    assert facts.terminal is (expected != HistoricalOutcome.UNCERTAIN)
    assert facts.recovery_observed is (expected == HistoricalOutcome.UNCERTAIN)
    assert facts.invocation_boundary_observed is True
    assert facts.execution_attempted is (True if error is None else None)
    assert facts.orchestration_step_count == len(case.runtime.trace(case.incident_id).entries)
    assert facts.investigation_rounds_recorded == experience.content.investigation_rounds
    assert facts.investigation_count is None and facts.tool_call_count is None
    assert facts.duration_seconds is None and facts.workflow_completed_at is None
    assert facts.analysis_observed and facts.human_review_observed
    assert not facts.fusion_observed and not facts.reconciliation_observed
    assert service.evaluate(experience.experience_id) == value
    reopened = EvaluationStore(ExperienceStore(SQLiteGovernanceStore(case.store.database.path)))
    assert reopened.get(value.evaluation_id) == value
    assert reopened.get_for_experience(experience.experience_id) == value
    assert reopened.list_for_incident(case.incident_id) == (value,)
    with pytest.raises(ValidationError):
        value.content.terminal = False
    forbidden = {"agent_error", "false_positive", "false_negative", "quality_score", "confidence"}
    assert not forbidden.intersection(facts.model_dump())
    assert case.mocks["inspect_logs"].call_count == 1


@pytest.mark.asyncio
async def test_waiting_then_human_rejection_not_judgment(runtime_case):
    case = runtime_case(durable_workflow=True)
    await decision_ready(case)
    capture = capture_service(case)
    waiting = capture.capture(case.incident_id)
    service = evaluator(case)
    facts = service.evaluate(waiting.experience_id).content
    assert facts.waiting_for_human and not facts.terminal
    assert facts.execution_outcome == HistoricalOutcome.NOT_EXECUTED
    assert facts.execution_attempted is None  # No execution record is not a measured call count.
    assert not facts.human_review_observed
    assert facts.policy_blocked is None
    await case.runtime.advance(case.incident_id, review=review_for(case, ReviewOutcome.REJECTED))
    await case.runtime.advance(case.incident_id)
    rejected = capture.capture(case.incident_id)
    result = service.evaluate(rejected.experience_id)
    assert result.content.human_rejected and result.content.terminal
    assert not result.content.execution_failed
    assert result.content.execution_outcome == HistoricalOutcome.NOT_EXECUTED
    # Older immutable experience is still evaluated at its own trace prefix.
    assert service.evaluate(waiting.experience_id).content == facts


@pytest.mark.asyncio
async def test_binding_and_unknown_timing(runtime_case):
    case = runtime_case(durable_workflow=True)
    await decision_ready(case)
    experience = capture_service(case).capture(case.incident_id)
    service = evaluator(case)
    with pytest.raises(StoredDataError):
        service.evaluate(experience.experience_id, expected_incident_id=uuid4())
    with pytest.raises(StoredDataError):
        service.evaluate(experience.experience_id, expected_experience_digest="0" * 64)
    with pytest.raises(StoredDataError):
        service.evaluate("0" * 64)
    facts = service.evaluate(experience.experience_id).content
    with pytest.raises(ValidationError):
        EvaluationContent.model_validate(facts.model_dump() | {"duration_seconds": 0})
    start = facts.workflow_started_at
    for end, duration in ((start - timedelta(seconds=1), 0), (start, 1)):
        with pytest.raises(ValidationError):
            EvaluationContent.model_validate(
                facts.model_dump()
                | {
                    "workflow_completed_at": end,
                    "duration_seconds": duration,
                }
            )
    valid = EvaluationContent.model_validate(
        facts.model_dump()
        | {
            "workflow_completed_at": start + timedelta(seconds=2),
            "duration_seconds": 2,
        }
    )
    assert (
        valid.duration_seconds == 2
    )  # Validation only; current Experience has no completion clock.
    with pytest.raises(ValidationError):
        EvaluationRecord(evaluation_id="0" * 64, content=facts)


@pytest.mark.asyncio
async def test_denied_candidate_is_not_agent_error(runtime_case):
    from soc_agent.response.advisory import CandidateIntent
    from soc_agent.tools import MockTool, ToolMetadata, ToolPermission, ToolRiskLevel
    from tests.unit.execution.conftest import SampleInput, SampleOutput

    case = runtime_case(durable_workflow=True, severities=("high",))
    denied = MockTool(
        metadata=ToolMetadata(
            name="test_denied",
            description="Test-only denied candidate",
            permission=ToolPermission.NETWORK_WRITE,
            risk_level=ToolRiskLevel.DESTRUCTIVE,
        ),
        input_model=SampleInput,
        output_model=SampleOutput,
        responses=[],
    )
    case.promotion_service.validation.registry.register(denied.tool)
    await decision_ready(case)
    await case.runtime.advance(case.incident_id, review=review_for(case))
    candidate = CandidateIntent(
        candidate_tool="test_denied",
        proposed_input={"target": "host_a"},
        purpose="Test candidate",
        rationale="Test source",
        evidence_ids=(case.store.load(case.incident_id).state.evidence[0].evidence_id,),
    )
    await case.runtime.advance(case.incident_id, candidates=(candidate,))
    experience = capture_service(case).capture(case.incident_id)
    facts = evaluator(case).evaluate(experience.experience_id).content
    assert facts.policy_deny_observed
    assert facts.policy_blocked is None  # Preflight is not proof of attempted execution.
    assert not facts.execution_failed and not facts.human_rejected
    assert facts.waiting_for_human
    assert denied.call_count == 0


@pytest.mark.asyncio
async def test_governance_block_preserved(runtime_case):
    from soc_agent.response.advisory import CandidateIntent

    case = runtime_case(durable_workflow=True)
    await decision_ready(case)
    await case.runtime.advance(case.incident_id, review=review_for(case))
    await case.runtime.advance(
        case.incident_id,
        candidates=(
            CandidateIntent(
                candidate_tool="missing_tool",
                proposed_input={},
                purpose="Test",
                rationale="Test",
                evidence_ids=(case.store.load(case.incident_id).state.evidence[0].evidence_id,),
            ),
        ),
    )
    experience = capture_service(case).capture(case.incident_id)
    facts = evaluator(case).evaluate(experience.experience_id).content
    assert facts.governance_blocked and facts.terminal
    assert facts.execution_outcome == HistoricalOutcome.NOT_EXECUTED
    assert not facts.execution_failed and not facts.human_rejected


@pytest.mark.asyncio
async def test_pending_and_reconciliation_history_remain_pinned(runtime_case):
    from soc_agent.execution.durable.models import ReconciledOutcome, ReconciliationRequest
    from soc_agent.review import HumanAction
    from soc_agent.review.identity import content_digest

    case = runtime_case(durable_workflow=True, responses=[TimeoutError("lost reply")])
    await promoted_ready(case)
    capture = capture_service(case)
    pending = capture.capture(case.incident_id)
    service = evaluator(case)
    before = service.evaluate(pending.experience_id)
    assert before.content.execution_attempted is False
    assert before.content.invocation_boundary_observed is False
    await finish(case)
    uncertain = capture.capture(case.incident_id)
    old = service.evaluate(uncertain.experience_id)
    identity = case.runtime.artifacts(case.incident_id).execution_intent_id
    record = case.executor.store.load(identity)
    request = ReconciliationRequest(
        execution_intent_id=identity,
        incident_id=case.incident_id,
        expected_revision=record.revision,
        outcome=ReconciledOutcome.CONFIRMED_SUCCEEDED,
        reason="Verified",
        references=("synthetic-ticket",),
    )
    token = case.authority.confirm(
        subject="approver-bob",
        action=HumanAction.RECONCILE_EXECUTION,
        digest=content_digest(request),
    )
    case.executor.store.reconcile(request, credential=token, authority=case.authority)
    await finish(case)
    reconciled = capture.capture(case.incident_id)
    after = service.evaluate(reconciled.experience_id)
    assert after.content.reconciliation_observed and after.content.recovery_observed
    assert after.content.uncertain_observed and not after.content.execution_uncertain
    assert after.content.execution_outcome == HistoricalOutcome.SUCCEEDED
    assert service.evaluate(uncertain.experience_id) == old
    assert service.evaluate(pending.experience_id) == before
    assert case.mocks["inspect_logs"].call_count == 1


@pytest.mark.asyncio
async def test_fusion_presence_is_not_quality_or_confirmed_fact(runtime_case):
    from soc_agent.llm import MockLLMClient
    from soc_agent.security_ai.fusion import MultiModelFusionEngine

    async def model_analysis(state):
        return MultiModelFusionEngine((), ("network_classifier",)).fuse(
            incident_id=state.incident_id,
            inputs=(),
        )

    case = runtime_case(durable_workflow=True, model_analysis=model_analysis)
    case.llm.generate_structured = MockLLMClient(
        [
            {
                "observations": [],
                "hypotheses": [],
                "assessment": {
                    "severity": "info",
                    "confidence": 0.2,
                    "summary": "No model coverage",
                    "supporting_evidence_ids": [str(case.initial.evidence[0].evidence_id)],
                },
            }
        ]
    ).generate_structured
    await decision_ready(case)
    before = case.store.load(case.incident_id)
    experience = capture_service(case).capture(case.incident_id)
    facts = evaluator(case).evaluate(experience.experience_id).content
    assert facts.analysis_observed and facts.fusion_observed
    assert case.store.load(case.incident_id) == before
    assert facts.investigation_count is None
    assert facts.execution_outcome == HistoricalOutcome.NOT_EXECUTED

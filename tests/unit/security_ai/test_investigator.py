import asyncio
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from soc_agent.security_ai import (
    MockSecurityAI,
    SecurityAI,
    SecurityAIInvestigationError,
    SecurityAIInvestigationResult,
    SecurityAIInvestigator,
    SecurityAIModelMetadata,
    SecurityAIRegistry,
    SecurityAIRequest,
    SecurityAISelectionDraft,
    SecurityAISelectionPlan,
)
from soc_agent.security_ai import (
    SecurityAIInvestigationStepStatus as Status,
)
from soc_agent.security_ai.selection_validator import normalize_selection
from soc_agent.state import Evidence, IncidentState
from soc_agent.state.evidence import utc_now

from .conftest import FlowInput


@pytest.fixture
def state() -> IncidentState:
    state = IncidentState()
    for source in ("auth.log", "network.log"):
        state = state.add_evidence(
            Evidence(
                incident_id=state.incident_id,
                source=source,
                summary="43 failed logins",
                raw_data="PRIVATE_EVIDENCE",
                observed_at=utc_now(),
            )
        )
    return state


@pytest.fixture
def registry(mock_ai: MockSecurityAI[FlowInput]) -> SecurityAIRegistry:
    registry = SecurityAIRegistry()
    registry.register(mock_ai.model)
    return registry


def make_plan(state: IncidentState, registry: SecurityAIRegistry) -> SecurityAISelectionPlan:
    draft = SecurityAISelectionDraft.model_validate(
        {
            "decision": "run_ai",
            "goal": "Inspect",
            "reason": "More analysis needed",
            "selections": [
                {
                    "model_name": model.name,
                    "model_input": {
                        "duration": 2.1,
                        "failed_connections": 43,
                        "unique_targets": 7,
                    },
                    "purpose": "Inspect log pattern",
                }
                for model in registry.list()
            ],
        }
    )
    return normalize_selection(
        draft,
        incident_id=state.incident_id,
        models={model.name: registry.get(model.name) for model in registry.list()},
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("with_sources", [False, True])
async def test_success_provenance_and_immutability(
    state: IncidentState,
    registry: SecurityAIRegistry,
    mock_ai: MockSecurityAI[FlowInput],
    with_sources: bool,
) -> None:
    plan = make_plan(state, registry)
    before, plan_before = state.model_dump_json(), plan.model_dump_json()
    ids = tuple(e.evidence_id for e in state.evidence) if with_sources else ()
    output = await SecurityAIInvestigator(registry=registry).execute(
        incident=state, selection_plan=plan, source_evidence={plan.steps[0].step_id: ids}
    )
    assert mock_ai.call_count == 1
    assert output.investigation_id.version == 4
    assert output.selection_plan_id == plan.plan_id and output.incident_id == state.incident_id
    step = output.steps[0]
    assert step.selection == plan.steps[0] and step.selection_step_id == plan.steps[0].step_id
    assert step.status == Status.COMPLETED
    assert output.created_at <= step.started_at <= step.completed_at <= output.completed_at
    assert output.created_at.utcoffset() == timedelta(0)
    result, signal = output.results[0], output.signals[0]
    assert len(output.results) == len(output.signals) == 1
    assert result.result_id.version == signal.signal_id.version == 4
    assert signal.source_result_id == result.result_id
    assert signal.source_evidence_ids == ids
    assert signal.source_created_at == result.created_at
    for field in (
        "incident_id",
        "model_name",
        "model_version",
        "task_type",
        "prediction",
        "confidence",
        "scores",
        "explanation",
    ):
        assert getattr(signal, field) == getattr(result, field)
    assert result.model_name == mock_ai.model.metadata.name
    assert mock_ai.requests[0].incident_id == state.incident_id
    assert mock_ai.requests[0].input.failed_connections == 43
    assert state.model_dump_json() == before and plan.model_dump_json() == plan_before
    assert SecurityAIInvestigationResult.model_validate_json(output.model_dump_json()) == output
    with pytest.raises(ValidationError):
        step.status = Status.FAILED
    with pytest.raises(ValidationError):
        output.incident_id = uuid4()
    signal.explanation_payload()["top_features"].clear()
    assert result.explanation_payload()["top_features"]


@pytest.mark.parametrize("change", ["version", "task_type", "input_type", "missing", "name"])
@pytest.mark.asyncio
async def test_registry_drift_blocked(
    state: IncidentState,
    registry: SecurityAIRegistry,
    metadata: SecurityAIModelMetadata,
    mock_ai: MockSecurityAI[FlowInput],
    change: str,
) -> None:
    plan = make_plan(state, registry)
    replacement = SecurityAIRegistry()
    update = {
        "version": "2",
        "task_type": "risk_scoring",
        "input_type": "host_process",
        "name": "different_name",
    }
    changed = metadata.model_dump() | ({change: update[change]} if change != "missing" else {})
    other = MockSecurityAI(
        metadata=SecurityAIModelMetadata.model_validate(changed),
        input_model=FlowInput,
        responses=[],
    )
    if change != "missing":
        replacement.register(other.model)
    result = await SecurityAIInvestigator(registry=replacement).execute(
        incident=state, selection_plan=plan
    )
    assert result.steps[0].status == Status.BLOCKED
    assert result.steps[0].started_at is None
    assert result.results == result.signals == ()
    assert other.call_count == mock_ai.call_count == 0


@pytest.mark.parametrize(
    "input",
    [
        {"failed_connections": "SECRET_INVALID"},
        {"duration": 2.1, "failed_connections": "43", "unique_targets": 7, "tags": []},
        {"duration": 2.1, "failed_connections": 43, "unique_targets": 7},
        {"duration": 2.1, "failed_connections": 43, "unique_targets": 7, "tags": [], "extra": 1},
    ],
)
@pytest.mark.asyncio
async def test_invalid_or_noncanonical_input(
    state: IncidentState,
    registry: SecurityAIRegistry,
    mock_ai: MockSecurityAI[FlowInput],
    input: dict[str, JsonValue],
) -> None:
    original = make_plan(state, registry)
    payload = original.model_dump()
    payload["steps"][0]["model_input"] = input
    plan = SecurityAISelectionPlan.model_validate(payload)
    output = await SecurityAIInvestigator(registry=registry).execute(
        incident=state, selection_plan=plan
    )
    assert output.steps[0].status == Status.BLOCKED and mock_ai.call_count == 0
    assert "SECRET_INVALID" not in output.steps[0].error_message


@pytest.mark.parametrize(
    "kind", ["incident", "duplicate_step", "extra", "unknown_step", "bad_json"]
)
@pytest.mark.asyncio
async def test_malformed_envelope_rejected(
    state: IncidentState,
    registry: SecurityAIRegistry,
    mock_ai: MockSecurityAI[FlowInput],
    kind: str,
) -> None:
    plan = make_plan(state, registry)
    sources = {}
    if kind == "incident":
        state = IncidentState()
    elif kind == "duplicate_step":
        plan = plan.model_copy(update={"steps": (plan.steps[0], plan.steps[0])})
    elif kind == "extra":
        plan = plan.model_copy(
            update={"steps": (plan.steps[0].model_copy(update={"purpose": ""}),)}
        )
    elif kind == "unknown_step":
        sources = {uuid4(): ()}
    else:
        plan = plan.model_copy(
            update={"steps": (plan.steps[0].model_copy(update={"model_input": "["}),)}
        )
    with pytest.raises(SecurityAIInvestigationError):
        await SecurityAIInvestigator(registry=registry).execute(
            incident=state, selection_plan=plan, source_evidence=sources
        )
    assert mock_ai.call_count == 0


@pytest.mark.parametrize("kind", ["unknown", "foreign", "duplicate"])
@pytest.mark.asyncio
async def test_evidence_preflight(
    state: IncidentState,
    registry: SecurityAIRegistry,
    mock_ai: MockSecurityAI[FlowInput],
    kind: str,
) -> None:
    plan = make_plan(state, registry)
    foreign = Evidence(
        incident_id=uuid4(),
        source="foreign",
        summary="foreign",
        raw_data="foreign",
        observed_at=utc_now(),
    )
    ids = (
        (uuid4(),)
        if kind == "unknown"
        else (foreign.evidence_id,)
        if kind == "foreign"
        else (state.evidence[0].evidence_id, state.evidence[0].evidence_id)
    )
    output = await SecurityAIInvestigator(registry=registry).execute(
        incident=state, selection_plan=plan, source_evidence={plan.steps[0].step_id: ids}
    )
    assert output.steps[0].status == Status.BLOCKED
    assert mock_ai.call_count == 0 and output.signals == ()


@pytest.mark.asyncio
async def test_entire_preflight_before_first_inference(
    state: IncidentState,
    registry: SecurityAIRegistry,
    mock_ai: MockSecurityAI[FlowInput],
    metadata: SecurityAIModelMetadata,
) -> None:
    other = MockSecurityAI(
        metadata=metadata.model_copy(update={"name": "second_model"}),
        input_model=FlowInput,
        responses=[],
    )
    registry.register(other.model)
    plan = make_plan(state, registry)
    output = await SecurityAIInvestigator(registry=registry).execute(
        incident=state, selection_plan=plan, source_evidence={plan.steps[1].step_id: (uuid4(),)}
    )
    assert [s.status for s in output.steps] == [Status.PENDING, Status.BLOCKED]
    assert mock_ai.call_count == other.call_count == 0


@pytest.mark.parametrize(
    "failure",
    [
        RuntimeError("MODEL_SECRET"),
        {"prediction": ""},
        {"prediction": "anomalous", "confidence": 2},
    ],
)
@pytest.mark.asyncio
async def test_runtime_failure_preserves_partial_results(
    state: IncidentState,
    metadata: SecurityAIModelMetadata,
    failure: JsonValue | Exception,
) -> None:
    registry = SecurityAIRegistry()
    mocks = []
    for index in range(3):
        mock = MockSecurityAI(
            metadata=metadata.model_copy(update={"name": f"model_{index}"}),
            input_model=FlowInput,
            responses=[
                failure
                if index == 1
                else {"prediction": "anomalous", "scores": {"anomaly_score": 0.87}}
            ],
        )
        registry.register(mock.model)
        mocks.append(mock)
    plan = make_plan(state, registry)
    before = state.model_dump_json()
    output = await SecurityAIInvestigator(registry=registry).execute(
        incident=state, selection_plan=plan
    )
    assert [s.status for s in output.steps] == [Status.COMPLETED, Status.FAILED, Status.PENDING]
    assert [m.call_count for m in mocks] == [1, 1, 0]
    assert len(output.results) == len(output.signals) == 1
    assert output.signals[0].confidence is None
    assert output.signals[0].scores_payload() == {"anomaly_score": 0.87}
    assert output.steps[1].error_type in {
        "SecurityAIInferenceError",
        "SecurityAIOutputValidationError",
    }
    assert "MODEL_SECRET" not in output.model_dump_json()
    assert state.model_dump_json() == before


@pytest.mark.asyncio
async def test_no_ai_needed_with_empty_registry(state: IncidentState) -> None:
    plan = SecurityAISelectionPlan(
        incident_id=state.incident_id,
        decision="no_ai_needed",
        goal="No additional AI",
        reason="No useful input",
        steps=(),
    )
    output = await SecurityAIInvestigator(registry=SecurityAIRegistry()).execute(
        incident=state, selection_plan=plan
    )
    assert output.steps == output.results == output.signals == ()
    assert output.decision.value == "no_ai_needed"


@pytest.mark.asyncio
async def test_actual_sequential_order(
    state: IncidentState, metadata: SecurityAIModelMetadata
) -> None:
    events = []
    registry = SecurityAIRegistry()

    async def first(request: SecurityAIRequest[FlowInput]) -> object:
        events.append("first_start")
        await asyncio.sleep(0)
        events.append("first_end")
        return {"prediction": "malicious"}

    async def second(request: SecurityAIRequest[FlowInput]) -> object:
        assert events == ["first_start", "first_end"]
        events.append("second")
        return {"prediction": "benign"}

    registry.register(SecurityAI(metadata, FlowInput, first))
    registry.register(
        SecurityAI(metadata.model_copy(update={"name": "second_model"}), FlowInput, second)
    )
    output = await SecurityAIInvestigator(registry=registry).execute(
        incident=state, selection_plan=make_plan(state, registry)
    )
    assert events == ["first_start", "first_end", "second"]
    assert [s.prediction for s in output.signals] == ["malicious", "benign"]


@pytest.mark.asyncio
async def test_cancellation_propagates(
    state: IncidentState, metadata: SecurityAIModelMetadata
) -> None:
    async def cancelled(request: SecurityAIRequest[FlowInput]) -> object:
        raise asyncio.CancelledError()

    registry = SecurityAIRegistry()
    registry.register(SecurityAI(metadata, FlowInput, cancelled))
    with pytest.raises(asyncio.CancelledError):
        await SecurityAIInvestigator(registry=registry).execute(
            incident=state, selection_plan=make_plan(state, registry)
        )


@pytest.mark.asyncio
async def test_current_schema_defaults_drift(
    state: IncidentState,
    registry: SecurityAIRegistry,
    metadata: SecurityAIModelMetadata,
) -> None:
    class ChangedInput(FlowInput):
        new_threshold: int = 99

    plan = make_plan(state, registry)
    new_registry = SecurityAIRegistry()
    mock = MockSecurityAI(metadata=metadata, input_model=ChangedInput, responses=[])
    new_registry.register(mock.model)
    output = await SecurityAIInvestigator(registry=new_registry).execute(
        incident=state, selection_plan=plan
    )
    assert output.steps[0].status == Status.BLOCKED and mock.call_count == 0
    assert "Canonical" in output.steps[0].error_message


@pytest.mark.asyncio
async def test_alias_defaults_execution(
    metadata: SecurityAIModelMetadata, state: IncidentState
) -> None:
    class Input(BaseModel):
        model_config = ConfigDict(extra="forbid")
        count: int = Field(alias="failures")
        tags: list[str] = Field(default_factory=list)

    mock = MockSecurityAI(
        metadata=metadata, input_model=Input, responses=[{"prediction": "benign"}]
    )
    registry = SecurityAIRegistry()
    registry.register(mock.model)
    plan = normalize_selection(
        SecurityAISelectionDraft.model_validate(
            {
                "decision": "run_ai",
                "goal": "Inspect",
                "reason": "Check",
                "selections": [
                    {
                        "model_name": metadata.name,
                        "model_input": {"failures": 43},
                        "purpose": "Check",
                    }
                ],
            }
        ),
        incident_id=state.incident_id,
        models={metadata.name: mock.model},
    )
    output = await SecurityAIInvestigator(registry=registry).execute(
        incident=state, selection_plan=plan
    )
    assert output.steps[0].status == Status.COMPLETED
    assert mock.requests[0].input.count == 43 and mock.requests[0].input.tags == []


@pytest.mark.asyncio
async def test_rechecks_current_registry_after_await(
    state: IncidentState,
    metadata: SecurityAIModelMetadata,
) -> None:
    changed = False
    other_metadata = metadata.model_copy(update={"name": "second_model"})
    replacement = MockSecurityAI(
        metadata=other_metadata.model_copy(update={"version": "2"}),
        input_model=FlowInput,
        responses=[],
    )

    class CurrentRegistry(SecurityAIRegistry):
        def get(self, name: str) -> SecurityAI[BaseModel]:
            if changed and name == "second_model":
                return replacement.model
            return super().get(name)

    async def first(request: SecurityAIRequest[FlowInput]) -> object:
        nonlocal changed
        await asyncio.sleep(0)
        changed = True
        return {"prediction": "benign"}

    second = MockSecurityAI(metadata=other_metadata, input_model=FlowInput, responses=[])
    registry = CurrentRegistry()
    registry.register(SecurityAI(metadata, FlowInput, first))
    registry.register(second.model)
    plan = make_plan(state, registry)
    output = await SecurityAIInvestigator(registry=registry).execute(
        incident=state, selection_plan=plan
    )
    assert [step.status for step in output.steps] == [Status.COMPLETED, Status.BLOCKED]
    assert len(output.signals) == 1
    assert second.call_count == replacement.call_count == 0


@pytest.mark.asyncio
async def test_signal_conversion_failure_retains_result(
    state: IncidentState,
    registry: SecurityAIRegistry,
    mock_ai: MockSecurityAI[FlowInput],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject(*args: object, **kwargs: object) -> None:
        raise ValueError("PRIVATE_CONVERSION_ERROR")

    monkeypatch.setattr("soc_agent.security_ai.investigator.create_ai_signal", reject)
    output = await SecurityAIInvestigator(registry=registry).execute(
        incident=state, selection_plan=make_plan(state, registry)
    )
    assert output.steps[0].status == Status.FAILED
    assert len(output.results) == 1 and output.signals == () and mock_ai.call_count == 1
    assert "PRIVATE_CONVERSION_ERROR" not in output.model_dump_json()


@pytest.mark.parametrize(
    "kind",
    [
        "signal_result",
        "signal_model",
        "signal_prediction",
        "signal_source",
        "signal_time",
        "result_model",
        "incident",
        "missing_result",
        "status",
        "error",
        "timestamp",
    ],
)
@pytest.mark.asyncio
async def test_execution_snapshot_rejects_inconsistent_links(
    state: IncidentState,
    registry: SecurityAIRegistry,
    kind: str,
) -> None:
    output = await SecurityAIInvestigator(registry=registry).execute(
        incident=state, selection_plan=make_plan(state, registry)
    )
    data = output.model_dump()
    step = data["steps"][0]
    if kind == "signal_result":
        step["signal"]["source_result_id"] = uuid4()
    elif kind == "signal_model":
        step["signal"]["model_version"] = "99"
    elif kind == "signal_prediction":
        step["signal"]["prediction"] = "forged"
    elif kind == "signal_source":
        step["signal"]["source_evidence_ids"] = (uuid4(),)
    elif kind == "signal_time":
        step["signal"]["source_created_at"] = utc_now()
    elif kind == "result_model":
        step["result"]["model_version"] = "99"
    elif kind == "incident":
        data["incident_id"] = uuid4()
    elif kind == "missing_result":
        step["result"] = None
    elif kind == "status":
        step["status"] = "pending"
    elif kind == "error":
        step["error_type"] = "unexpected"
    else:
        step["completed_at"] = step["started_at"] - timedelta(seconds=1)
    with pytest.raises(ValidationError):
        SecurityAIInvestigationResult.model_validate(data)


@pytest.mark.asyncio
async def test_raw_handler_cannot_be_resolved(
    registry: SecurityAIRegistry, state: IncidentState, mock_ai: MockSecurityAI[FlowInput]
) -> None:
    plan = make_plan(state, registry)

    class InvalidRegistry(SecurityAIRegistry):
        def get(self, name: str) -> object:
            return mock_ai.model.handler

    output = await SecurityAIInvestigator(registry=InvalidRegistry()).execute(
        incident=state, selection_plan=plan
    )
    assert output.steps[0].status == Status.BLOCKED and mock_ai.call_count == 0


def test_execution_modules_have_no_reasoning_or_response_dependencies() -> None:
    import ast
    from pathlib import Path

    import soc_agent.security_ai.investigator as module

    directory = Path(module.__file__).parent
    for name in ("investigator.py", "investigation_preflight.py", "investigation_models.py"):
        tree = ast.parse((directory / name).read_text())
        imports = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        assert not any(
            module
            and module.startswith(
                (
                    "soc_agent.llm",
                    "soc_agent.tools",
                    "soc_agent.policy",
                    "soc_agent.approval",
                    "soc_agent.response",
                    "soc_agent.execution",
                    "soc_agent.assessment",
                )
            )
            for module in imports
        )

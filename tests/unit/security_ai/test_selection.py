import asyncio
import json
from datetime import datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import BaseModel, Field, JsonValue, ValidationError

from soc_agent.llm import LLMRequest, LLMResponseValidationError, LLMTimeoutError, MockLLMClient
from soc_agent.security_ai import (
    InvalidAISignalContextError,
    InvalidSelectedModelInputError,
    MockSecurityAI,
    NoSecurityAIAvailableError,
    SecurityAIModelMetadata,
    SecurityAIRegistry,
    SecurityAIResult,
    SecurityAISelectionDraft,
    SecurityAISelectionError,
    SecurityAISelectionPlan,
    SecurityAISelector,
    SelectionContextTooLargeError,
    UnknownSelectedModelError,
    create_ai_signal,
)
from soc_agent.security_ai.selection_prompts import build_selection_request
from soc_agent.security_ai.selection_validator import normalize_selection
from soc_agent.state import Evidence, Hypothesis, IncidentState, Observation
from soc_agent.state.evidence import utc_now

from .conftest import FlowInput


def selection(name: str = "network_ids_mock", **updates: JsonValue) -> dict[str, JsonValue]:
    return {
        "model_name": name,
        "model_input": {"duration": 2.1, "failed_connections": 43, "unique_targets": 7},
        "purpose": "Check the network pattern",
    } | updates


def draft(*selections: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return {
        "decision": "run_ai",
        "goal": "Investigate authentication activity",
        "reason": "Additional model analysis may help",
        "selections": list(selections),
    }


@pytest.fixture
def registry(mock_ai: MockSecurityAI[FlowInput]) -> SecurityAIRegistry:
    registry = SecurityAIRegistry()
    registry.register(mock_ai.model)
    return registry


@pytest.fixture
def state() -> IncidentState:
    state = IncidentState()
    evidence = Evidence(
        incident_id=state.incident_id,
        source="auth.log",
        summary="43 failures against 7 accounts from one source IP",
        raw_data="RAW_SECRET_ONLY",
        observed_at=utc_now(),
    )
    return (
        state.add_evidence(evidence)
        .add_observation(
            Observation(
                statement="43 failures recorded",
                supporting_evidence_ids=(evidence.evidence_id,),
            )
        )
        .add_hypothesis(
            Hypothesis(
                statement="May be credential abuse",
                confidence=0.4,
                supporting_evidence_ids=(evidence.evidence_id,),
            )
        )
    )


@pytest.mark.asyncio
async def test_valid_plan_snapshot(
    registry: SecurityAIRegistry, mock_ai: MockSecurityAI[FlowInput], state: IncidentState
) -> None:
    client = MockLLMClient([draft(selection())])
    before = state.model_dump_json()
    plan = await SecurityAISelector(llm_client=client, registry=registry).select(incident=state)
    assert plan.incident_id == state.incident_id
    assert plan.plan_id.version == plan.steps[0].step_id.version == 4
    assert plan.created_at.utcoffset() == timedelta(0)
    assert plan.steps[0].model_version == mock_ai.model.metadata.version
    assert plan.steps[0].task_type == mock_ai.model.metadata.task_type
    assert plan.steps[0].input_type == mock_ai.model.metadata.input_type
    assert plan.steps[0].input_payload()["tags"] == []
    assert plan.steps[0].input_payload()["failed_connections"] == 43
    assert plan.steps[0].purpose == "Check the network pattern"
    assert SecurityAISelectionPlan.model_validate_json(plan.model_dump_json()) == plan
    with pytest.raises(ValidationError):
        plan.incident_id = uuid4()
    with pytest.raises(ValidationError):
        plan.steps[0].model_version = "99"
    plan.steps[0].input_payload()["tags"].append("mutated")
    assert plan.steps[0].input_payload()["tags"] == []
    assert state.model_dump_json() == before
    assert client.call_count == 1 and mock_ai.call_count == 0


@pytest.mark.parametrize(
    "field",
    [
        "model_version",
        "task_type",
        "input_type",
        "result_id",
        "signal_id",
        "incident_id",
        "status",
        "risk",
        "permission",
        "confidence",
        "prediction",
        "approval",
        "policy",
        "step_id",
        "plan_id",
    ],
)
@pytest.mark.parametrize("location", ["step", "plan"])
@pytest.mark.asyncio
async def test_forged_fields_rejected(
    registry: SecurityAIRegistry,
    mock_ai: MockSecurityAI[FlowInput],
    state: IncidentState,
    field: str,
    location: str,
) -> None:
    response = (
        draft(selection(**{field: "forged"}))
        if location == "step"
        else (draft(selection()) | {field: "forged"})
    )
    client = MockLLMClient([response])
    with pytest.raises(LLMResponseValidationError):
        await SecurityAISelector(llm_client=client, registry=registry).select(incident=state)
    assert client.call_count == 1 and mock_ai.call_count == 0


@pytest.mark.parametrize("name", ["unknown_security_ai", "network_ids", "admin_model"])
@pytest.mark.asyncio
async def test_unknown_no_retry_or_partial_plan(
    registry: SecurityAIRegistry,
    mock_ai: MockSecurityAI[FlowInput],
    state: IncidentState,
    name: str,
) -> None:
    client = MockLLMClient([draft(selection(), selection(name)), draft(selection())])
    with pytest.raises(UnknownSelectedModelError):
        await SecurityAISelector(llm_client=client, registry=registry).select(incident=state)
    assert client.call_count == 1 and mock_ai.call_count == 0


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"failed_connections": "many"},
        {"duration": 2.1, "failed_connections": 43, "unique_targets": 7, "secret": "unexpected"},
    ],
)
@pytest.mark.asyncio
async def test_invalid_model_input(
    registry: SecurityAIRegistry,
    mock_ai: MockSecurityAI[FlowInput],
    state: IncidentState,
    value: dict[str, JsonValue],
) -> None:
    client = MockLLMClient([draft(selection(model_input=value))])
    with pytest.raises(InvalidSelectedModelInputError):
        await SecurityAISelector(llm_client=client, registry=registry).select(incident=state)
    assert client.call_count == 1 and mock_ai.call_count == 0


@pytest.mark.parametrize("count", [0, 6])
@pytest.mark.asyncio
async def test_selection_bounds(
    registry: SecurityAIRegistry, state: IncidentState, count: int
) -> None:
    client = MockLLMClient([draft(*(selection() for _ in range(count)))])
    with pytest.raises(LLMResponseValidationError):
        await SecurityAISelector(llm_client=client, registry=registry).select(incident=state)


@pytest.mark.parametrize("count", [0, 1])
@pytest.mark.asyncio
async def test_no_ai_needed(registry: SecurityAIRegistry, state: IncidentState, count: int) -> None:
    response = draft(*(selection() for _ in range(count))) | {"decision": "no_ai_needed"}
    client = MockLLMClient([response])
    selector = SecurityAISelector(llm_client=client, registry=registry)
    if count:
        with pytest.raises(LLMResponseValidationError):
            await selector.select(incident=state)
    else:
        plan = await selector.select(incident=state)
        assert plan.steps == () and plan.decision.value == "no_ai_needed"
        assert plan.reason == response["reason"]


@pytest.mark.parametrize(
    "update", [{"reason": " "}, {"goal": ""}, {"decision": "unknown"}, {"reason": "x" * 2001}]
)
def test_draft_text_validation(update: dict[str, JsonValue]) -> None:
    with pytest.raises(ValidationError):
        SecurityAISelectionDraft.model_validate(draft(selection()) | update)


@pytest.mark.asyncio
async def test_empty_registry_no_llm(state: IncidentState) -> None:
    client = MockLLMClient([])
    with pytest.raises(NoSecurityAIAvailableError):
        await SecurityAISelector(llm_client=client, registry=SecurityAIRegistry()).select(
            incident=state
        )
    assert client.call_count == 0


@pytest.mark.asyncio
async def test_alias_defaults_canonical_duplicate(metadata: SecurityAIModelMetadata) -> None:
    class AliasInput(BaseModel):
        count: int = Field(alias="failures")
        tags: list[str] = Field(default_factory=list)

    mock = MockSecurityAI(metadata=metadata, input_model=AliasInput, responses=[])
    registry = SecurityAIRegistry()
    registry.register(mock.model)
    client = MockLLMClient(
        [
            draft(
                selection(model_input={"failures": "43"}),
                selection(model_input={"tags": [], "failures": 43}),
            )
        ]
    )
    with pytest.raises(SecurityAISelectionError, match="Duplicate"):
        await SecurityAISelector(llm_client=client, registry=registry).select(
            incident=IncidentState()
        )
    client = MockLLMClient([draft(selection(model_input={"failures": 43}))])
    plan = await SecurityAISelector(llm_client=client, registry=registry).select(
        incident=IncidentState()
    )
    assert plan.steps[0].model_input == '{"failures":43,"tags":[]}'
    assert mock.call_count == 0


@pytest.mark.asyncio
async def test_same_model_different_inputs_up_to_five(
    registry: SecurityAIRegistry, state: IncidentState
) -> None:
    selections = [
        selection(model_input={"duration": 2.1, "failed_connections": n, "unique_targets": 7})
        for n in range(5)
    ]
    client = MockLLMClient([draft(*selections)])
    plan = await SecurityAISelector(llm_client=client, registry=registry).select(incident=state)
    assert [step.input_payload()["failed_connections"] for step in plan.steps] == list(range(5))
    assert len({step.step_id for step in plan.steps}) == 5


@pytest.mark.parametrize("kind", ["incident", "signal", "result", "unknown_reference", "invalid"])
@pytest.mark.asyncio
async def test_signal_validation_before_llm(
    registry: SecurityAIRegistry, state: IncidentState, kind: str
) -> None:
    result = SecurityAIResult(
        incident_id=state.incident_id,
        model_name="old_model",
        model_version="1",
        task_type="classification",
        prediction="benign",
    )
    signal = create_ai_signal(result, state=state)
    signals = (signal,)
    if kind == "incident":
        state = IncidentState()
    elif kind == "signal":
        signals = (signal, signal)
    elif kind == "result":
        signals = (signal, create_ai_signal(result, state=state))
    elif kind == "unknown_reference":
        signals = (signal.model_copy(update={"source_evidence_ids": (uuid4(),)}),)
    else:
        signals = (signal.model_copy(update={"confidence": 2}),)
    client = MockLLMClient([])
    with pytest.raises(InvalidAISignalContextError):
        await SecurityAISelector(llm_client=client, registry=registry).select(
            incident=state, signals=signals
        )
    assert client.call_count == 0


@pytest.mark.parametrize("source", ["summary", "explanation", "catalog"])
@pytest.mark.asyncio
async def test_context_bound_before_llm(
    registry: SecurityAIRegistry,
    state: IncidentState,
    source: str,
    metadata: SecurityAIModelMetadata,
) -> None:
    signals = ()
    if source == "summary":
        evidence = state.evidence[0].model_copy(update={"summary": "x" * 64000})
        state = state.model_copy(update={"evidence": (evidence,)})
    elif source == "explanation":
        result = SecurityAIResult(
            incident_id=state.incident_id,
            model_name="old_model",
            model_version="1",
            task_type="classification",
            prediction="benign",
            explanation={"text": "x" * 64000},
        )
        signals = (create_ai_signal(result, state=state),)
    else:
        mock = MockSecurityAI(
            metadata=metadata.model_copy(
                update={"name": "other_model", "description": "x" * 64000}
            ),
            input_model=FlowInput,
            responses=[],
        )
        registry.register(mock.model)
    client = MockLLMClient([])
    with pytest.raises(SelectionContextTooLargeError):
        await SecurityAISelector(llm_client=client, registry=registry).select(
            incident=state, signals=signals
        )
    assert client.call_count == 0


def test_context_projection_and_order(
    registry: SecurityAIRegistry, state: IncidentState, metadata: SecurityAIModelMetadata
) -> None:
    other = MockSecurityAI(
        metadata=metadata.model_copy(update={"name": "auth_model"}),
        input_model=FlowInput,
        responses=[],
    )
    registry.register(other.model)
    models = {m.name: registry.get(m.name) for m in registry.list()}
    first = build_selection_request(state, (), models)
    second = build_selection_request(state, (), dict(reversed(list(models.items()))))
    assert first == second
    data = json.loads(first.user_prompt)
    assert [m["name"] for m in data["AVAILABLE SECURITY AI"]] == ["auth_model", "network_ids_mock"]
    assert "failed_connections" in data["AVAILABLE SECURITY AI"][0]["input_schema"]["properties"]
    assert data["OBSERVATIONS"][0]["supporting_evidence_ids"] == [
        str(state.evidence[0].evidence_id)
    ]
    assert data["HYPOTHESES (UNVERIFIED)"][0]["confidence"] == 0.4
    for excluded in ("raw_data", "RAW_SECRET_ONLY", "handler", "pickle", "model_path", "<function"):
        assert excluded not in first.user_prompt


@pytest.mark.parametrize("error", [LLMTimeoutError("timeout"), asyncio.CancelledError()])
@pytest.mark.asyncio
async def test_llm_failure_propagates(
    registry: SecurityAIRegistry, state: IncidentState, error: BaseException
) -> None:
    class FailingClient:
        calls = 0

        async def generate_structured[T: BaseModel](
            self, *, request: LLMRequest, response_model: type[T]
        ) -> T:
            self.calls += 1
            raise error

    client = FailingClient()
    with pytest.raises(type(error)) as caught:
        await SecurityAISelector(llm_client=client, registry=registry).select(incident=state)
    assert caught.value is error and client.calls == 1


def test_revalidate_bypassed_draft(registry: SecurityAIRegistry, state: IncidentState) -> None:
    value = SecurityAISelectionDraft.model_validate(draft(selection()))
    value = value.model_copy(update={"decision": "no_ai_needed"})
    with pytest.raises(LLMResponseValidationError):
        normalize_selection(
            value,
            incident_id=state.incident_id,
            models={m.name: registry.get(m.name) for m in registry.list()},
        )


@pytest.mark.asyncio
async def test_plan_schema_invariants(registry: SecurityAIRegistry, state: IncidentState) -> None:
    plan = await SecurityAISelector(
        llm_client=MockLLMClient([draft(selection())]), registry=registry
    ).select(incident=state)
    for update in (
        {"created_at": datetime(2026, 1, 1)},
        {"permission": "all"},
        {"decision": "no_ai_needed"},
        {"steps": (plan.steps[0], plan.steps[0])},
    ):
        with pytest.raises(ValidationError):
            SecurityAISelectionPlan.model_validate(plan.model_dump() | update)


@pytest.mark.asyncio
async def test_registry_snapshot_excludes_late_registration(
    registry: SecurityAIRegistry, state: IncidentState, metadata: SecurityAIModelMetadata
) -> None:
    late = MockSecurityAI(
        metadata=metadata.model_copy(update={"name": "late_model"}),
        input_model=FlowInput,
        responses=[],
    )

    class RegisteringClient(MockLLMClient):
        async def generate_structured[T: BaseModel](
            self, *, request: LLMRequest, response_model: type[T]
        ) -> T:
            registry.register(late.model)
            return await super().generate_structured(request=request, response_model=response_model)

    client = RegisteringClient([draft(selection("late_model"))])
    with pytest.raises(UnknownSelectedModelError):
        await SecurityAISelector(llm_client=client, registry=registry).select(incident=state)
    assert "late_model" in registry
    assert "late_model" not in client.requests[0].user_prompt
    assert client.call_count == 1 and late.call_count == 0


@pytest.mark.asyncio
async def test_non_roundtrippable_input_rejected(metadata: SecurityAIModelMetadata) -> None:
    class StrictInput(BaseModel):
        model_config = {"strict": True}
        values: tuple[int, ...] = (1, 2)

    mock = MockSecurityAI(metadata=metadata, input_model=StrictInput, responses=[])
    registry = SecurityAIRegistry()
    registry.register(mock.model)
    client = MockLLMClient([draft(selection(model_input={}))])
    with pytest.raises(InvalidSelectedModelInputError):
        await SecurityAISelector(llm_client=client, registry=registry).select(
            incident=IncidentState()
        )
    assert mock.call_count == 0


@pytest.mark.parametrize("value", [[], "{}", {"x": float("nan")}])
def test_draft_input_must_be_json_object(value: JsonValue) -> None:
    with pytest.raises(ValidationError):
        SecurityAISelectionDraft.model_validate(draft(selection(model_input=value)))

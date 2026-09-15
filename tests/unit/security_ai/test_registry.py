from dataclasses import FrozenInstanceError

import pytest

from soc_agent.security_ai import (
    MockSecurityAI,
    SecurityAI,
    SecurityAIInputType,
    SecurityAILookupError,
    SecurityAIModelMetadata,
    SecurityAIRegistrationError,
    SecurityAIRegistry,
    SecurityAITaskType,
)

from .conftest import AuthInput, FlowInput


def test_registry_name_only_allowlist(mock_ai: MockSecurityAI[FlowInput]) -> None:
    registry = SecurityAIRegistry()
    assert registry.list() == ()
    registry.register(mock_ai.model)
    assert registry.get("network_ids_mock") is mock_ai.model
    assert "network_ids_mock" in registry
    snapshot = registry.list()
    other = MockSecurityAI(
        metadata=SecurityAIModelMetadata(
            name="auth_ai",
            version="1",
            description="Auth fixture",
            task_type=SecurityAITaskType.RISK_SCORING,
            input_type=SecurityAIInputType.AUTHENTICATION_EVENT,
        ),
        input_model=AuthInput,
        responses=[],
    )
    registry.register(other.model)
    assert len(registry.list()) == 2 and len(snapshot) == 1
    assert registry.get("auth_ai").input_model is AuthInput
    changed_version = SecurityAIModelMetadata.model_validate(
        mock_ai.model.metadata.model_dump()
        | {
            "version": "2.0.0",
        }
    )
    second = SecurityAI(changed_version, FlowInput, mock_ai.model.handler)
    for candidate in (mock_ai.model, second):
        with pytest.raises(SecurityAIRegistrationError):
            registry.register(candidate)
    assert registry.get("network_ids_mock").metadata.version == "1.0.0"
    assert SecurityAIRegistry().list() == ()
    assert mock_ai.call_count == other.call_count == 0


@pytest.mark.parametrize("name", ["missing", "super_hacker_ai", "network_ids_mock@2.0.0"])
def test_unknown_model_never_runs(mock_ai: MockSecurityAI[FlowInput], name: str) -> None:
    registry = SecurityAIRegistry()
    registry.register(mock_ai.model)
    assert name not in registry
    with pytest.raises(SecurityAILookupError):
        registry.get(name)
    assert mock_ai.call_count == 0


@pytest.mark.parametrize("candidate", [object(), {}, lambda value: value])
def test_registry_rejects_raw_handlers(candidate: object) -> None:
    registry = SecurityAIRegistry()
    with pytest.raises(SecurityAIRegistrationError):
        registry.register(candidate)
    assert registry.list() == ()


def test_invalid_wrapper_configuration(mock_ai: MockSecurityAI[FlowInput]) -> None:
    model = mock_ai.model
    for metadata in (
        {},
        SecurityAIModelMetadata.model_construct(),
        model.metadata.model_copy(update={"version": " "}),
    ):
        with pytest.raises(SecurityAIRegistrationError):
            SecurityAI(metadata, FlowInput, model.handler)
    with pytest.raises(SecurityAIRegistrationError):
        SecurityAI(model.metadata, str, model.handler)
    with pytest.raises(SecurityAIRegistrationError):
        SecurityAI(model.metadata, FlowInput, lambda request: {})
    with pytest.raises(FrozenInstanceError):
        model.input_model = AuthInput

    class Bypass(SecurityAI):
        pass

    with pytest.raises(SecurityAIRegistrationError):
        SecurityAIRegistry().register(Bypass(model.metadata, FlowInput, model.handler))

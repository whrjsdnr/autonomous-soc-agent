import pytest
from pydantic import BaseModel, ConfigDict, Field, JsonValue

from soc_agent.security_ai import (
    MockSecurityAI,
    SecurityAIInputType,
    SecurityAIModelMetadata,
    SecurityAITaskType,
)


class FlowInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    duration: float = Field(ge=0, allow_inf_nan=False)
    failed_connections: int = Field(ge=0)
    unique_targets: int = Field(ge=0)
    tags: list[str] = Field(default_factory=list)


class AuthInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    username: str
    failures: int


@pytest.fixture
def metadata() -> SecurityAIModelMetadata:
    return SecurityAIModelMetadata(
        name="network_ids_mock",
        version="1.0.0",
        description="Network IDS fixture",
        task_type=SecurityAITaskType.CLASSIFICATION,
        input_type=SecurityAIInputType.NETWORK_FLOW,
    )


@pytest.fixture
def prediction() -> dict[str, JsonValue]:
    return {
        "prediction": "credential_attack",
        "confidence": 0.94,
        "scores": {"benign": 0.06, "credential_attack": 0.94},
        "explanation": {"top_features": ["failed_connections", "unique_targets"]},
    }


@pytest.fixture
def mock_ai(
    metadata: SecurityAIModelMetadata, prediction: dict[str, JsonValue]
) -> MockSecurityAI[FlowInput]:
    return MockSecurityAI(metadata=metadata, input_model=FlowInput, responses=[prediction])


@pytest.fixture
def features() -> dict[str, JsonValue]:
    return {"duration": 2.1, "failed_connections": 43, "unique_targets": 7}

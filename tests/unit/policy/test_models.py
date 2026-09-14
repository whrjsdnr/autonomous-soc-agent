import pytest
from pydantic import ValidationError

from soc_agent.policy import PolicyDecision, PolicyResult


@pytest.mark.parametrize("decision", list(PolicyDecision))
def test_result_serialization(decision: PolicyDecision) -> None:
    result = PolicyResult(decision=decision, reason="A deterministic reason")
    assert result.model_dump(mode="json")["decision"] == decision.value
    assert PolicyResult.model_validate_json(result.model_dump_json()) == result
    with pytest.raises(ValidationError):
        result.reason = "changed"


@pytest.mark.parametrize(
    "data",
    [
        {"decision": "unknown", "reason": "reason"},
        {"decision": "allow", "reason": "  "},
        {"decision": "allow"},
        {"decision": "allow", "reason": "reason", "extra": True},
    ],
)
def test_invalid_result(data: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        PolicyResult.model_validate(data)

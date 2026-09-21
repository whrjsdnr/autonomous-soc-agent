from uuid import uuid4

import pytest

from soc_agent.security_ai import SecurityAIRegistry
from soc_agent.security_ai.errors import (
    SecurityAIInferenceError,
    SecurityAIInputValidationError,
    SecurityAIRegistrationError,
)
from soc_agent.security_ai.models import SecurityAIRequest
from soc_agent.security_ai.packaging import (
    AuthenticationAnomalyAdapter,
    NetworkAnomalyAdapter,
    NetworkClassifierAdapter,
    load_package,
)
from soc_agent.state import IncidentState

ADAPTERS = {
    "network_classifier": NetworkClassifierAdapter,
    "network_anomaly": NetworkAnomalyAdapter,
    "authentication_anomaly": AuthenticationAnomalyAdapter,
}


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ADAPTERS)
async def test_explicit_registry_and_result_boundary(packages, kind):
    _, rows, path, pin, loaded = packages[kind]
    state = IncidentState()
    before = state.model_dump_json()
    registry = SecurityAIRegistry()
    loaded = load_package(path, expected_manifest_digest=pin)
    assert registry.list() == ()
    wrapper = ADAPTERS[kind](loaded).as_security_ai()
    registry.register(wrapper)
    result = await registry.get(wrapper.metadata.name).predict(
        SecurityAIRequest(incident_id=state.incident_id, input=rows[0].features)
    )
    explanation = result.explanation_payload()
    assert explanation["feature_fingerprint"] == rows[0].features.input_fingerprint
    assert explanation["feature_provenance"] == rows[0].features.provenance.model_dump(mode="json")
    assert result.model_name == loaded.manifest.model_id
    assert result.model_version == loaded.manifest.model_version
    if kind != "network_classifier":
        assert result.confidence is None
        assert explanation["operating_point"]["space"] == "raw"
        assert len(explanation["operating_point_identity"]) == 64
        assert result.scores_payload()["normalized_threshold"] == 0.95
    existing = registry.list()
    with pytest.raises(SecurityAIRegistrationError):
        registry.register(wrapper)
    with pytest.raises(ValueError):
        load_package(path, expected_manifest_digest="0" * 64)
    assert registry.list() == existing
    assert registry.get(wrapper.metadata.name) is wrapper
    assert state.model_dump_json() == before
    assert not state.evidence


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ADAPTERS)
@pytest.mark.parametrize(
    "change",
    ("schema", "extractor", "order", "nonfinite", "provenance", "foreign_incident", "wrong_domain"),
)
async def test_adapter_input_rejection(packages, kind, change):
    _, rows, _, _, loaded = packages[kind]
    wrapper = ADAPTERS[kind](loaded).as_security_ai()
    data = rows[0].features.model_dump()
    if change == "schema":
        data["feature_schema"]["schema_version"] = "99"
    elif change == "extractor":
        data["provenance"]["extractor_version"] = "99"
    elif change == "order":
        data["feature_schema"]["features"] = tuple(reversed(data["feature_schema"]["features"]))
    elif change == "nonfinite":
        values = rows[0].features.input_payload()
        values[next(iter(values))] = float("nan")
        data["values"] = values
    elif change == "provenance":
        data["provenance"]["sources"] = ()
    elif change == "foreign_incident":
        data["provenance"]["incident_id"] = uuid4()
    else:
        other = (
            "network_classifier" if kind == "authentication_anomaly" else "authentication_anomaly"
        )
        data = packages[other][1][0].features.model_dump()
    with pytest.raises((SecurityAIInferenceError, SecurityAIInputValidationError)):
        await wrapper.predict({"incident_id": uuid4(), "input": data})


def test_wrong_adapter_rejected(packages):
    with pytest.raises(ValueError):
        NetworkClassifierAdapter(packages["authentication_anomaly"][4])

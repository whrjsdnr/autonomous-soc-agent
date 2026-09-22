"""Retained result validation reuses inference payload checks and fusion aggregation."""

from uuid import uuid4

import pytest
from tests.fusion_support import fusion_input, model_bindings
from tests.scenarios.test_security_ai_fusion import network_features

from soc_agent.security_ai.fusion import MultiModelFusionEngine
from soc_agent.security_ai.fusion.errors import FusionValidationError
from soc_agent.security_ai.fusion.models import ModelAvailability
from soc_agent.security_ai.fusion.result_validation import validate_fusion_result
from soc_agent.state import IncidentState


@pytest.fixture
def result():
    state = IncidentState()
    bindings = model_bindings()
    features = network_features()
    inputs = tuple(
        fusion_input(bindings[k], features, state, positive=k != "network_classifier")
        for k in ("network_classifier", "network_anomaly")
    )
    return MultiModelFusionEngine(tuple(bindings.values()), tuple(bindings)).fuse(
        incident_id=state.incident_id,
        inputs=inputs,
        unavailable=(
            ModelAvailability(
                model_kind="authentication_anomaly", status="failed", reason="timeout"
            ),
        ),
    )


def test_valid_result_revalidated(result):
    assert validate_fusion_result(result) == result
    assert result.correlation_groups[0].network_relations == ("benign_with_anomaly",)


@pytest.mark.parametrize(
    "field,value",
    [
        ("incident_id", uuid4()),
        ("fusion_id", "a" * 64),
        ("contributions", ()),
        ("signals", ()),
        ("model_references", ()),
        ("correlation_groups", ()),
        ("agreement_state", "consistent"),
        ("coverage", ()),
        ("missing_models", ()),
        ("limitations", ()),
        ("confidence_state", "high"),
        ("coverage_state", "complete"),
        ("expected_models", ("network_classifier",)),
    ],
)
def test_tampered_result_rejected(result, field, value):
    with pytest.raises(FusionValidationError):
        validate_fusion_result(result.model_copy(update={field: value}))


@pytest.mark.parametrize(
    "field,value",
    [
        ("signal_ids", (uuid4(),)),
        ("model_reference", "b" * 64),
        ("feature_fingerprint", "c" * 64),
        ("decision", "forged"),
        ("contribution_id", "d" * 64),
        ("model_kind", "authentication_anomaly"),
    ],
)
def test_tampered_contribution_rejected(result, field, value):
    altered = result.contributions[0].model_copy(update={field: value})
    with pytest.raises(FusionValidationError):
        validate_fusion_result(
            result.model_copy(update={"contributions": (altered,) + result.contributions[1:]})
        )


@pytest.mark.parametrize(
    "field", ["selection_digest", "package_manifest_digest", "feature_fingerprint"]
)
def test_tampered_signal_binding_rejected(result, field):
    signal = result.signals[0]
    explanation = signal.explanation_payload() | {field: "b" * 64}
    signal = type(signal).model_validate(signal.model_dump() | {"explanation": explanation})
    with pytest.raises(FusionValidationError):
        validate_fusion_result(
            result.model_copy(update={"signals": (signal,) + result.signals[1:]})
        )


def test_replay_with_fresh_extraction_identifiers():
    state = IncidentState()
    binding = model_bindings()["network_classifier"]
    inputs = tuple(fusion_input(binding, network_features(), state) for _ in range(2))
    result = MultiModelFusionEngine((binding,), ("network_classifier",)).fuse(
        incident_id=state.incident_id,
        inputs=inputs,
    )
    assert len(result.signals) == 2 and len(result.contributions) == 1
    assert validate_fusion_result(result) == result


def test_constructed_invalid_result_rejected(result):
    bad = type(result).model_construct(**(result.model_dump() | {"incident_id": "invalid"}))
    with pytest.raises(FusionValidationError):
        validate_fusion_result(bad)


def test_empty_valid_fusion():
    result = MultiModelFusionEngine((), ("network_classifier",)).fuse(
        incident_id=uuid4(),
        inputs=(),
    )
    assert validate_fusion_result(result) == result

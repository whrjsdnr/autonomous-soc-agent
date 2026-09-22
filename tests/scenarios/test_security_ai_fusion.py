"""Actual Phase 3-6 package inference; no new model fit or manipulated predictions."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from tests.authentication_support import record

from soc_agent.security_ai.authentication import AuthenticationWindowExtractor
from soc_agent.security_ai.features import SecurityRecord, SourceReference
from soc_agent.security_ai.fusion import FusionInput, MultiModelFusionEngine, binding_from_package
from soc_agent.security_ai.models import SecurityAIRequest
from soc_agent.security_ai.network.schema import NetworkFeatureExtractor
from soc_agent.security_ai.packaging import (
    AuthenticationAnomalyAdapter,
    NetworkAnomalyAdapter,
    NetworkClassifierAdapter,
    load_package,
)
from soc_agent.security_ai.signals import create_ai_signal
from soc_agent.state import IncidentState

PINS = (
    (
        "network_classifier",
        "afbc5a77bd858cfb9bb04652af8bcb9985125b6368bd4ce440f423758cbe7773",
        NetworkClassifierAdapter,
    ),
    (
        "network_anomaly",
        "14429a0323f6d622dc65f217761698ae37566dd32eca421d51fbf1eab1f489d7",
        NetworkAnomalyAdapter,
    ),
    (
        "authentication_anomaly",
        "aabeb76277534d9300f70699dfddb84214720add607ef1d17b4c0e34e084b5f6",
        AuthenticationAnomalyAdapter,
    ),
)


@pytest.fixture(scope="module")
def packages():
    root = Path(__file__).parents[1] / "fixtures/security_ai_packages"
    return {name: load_package(root / name, expected_manifest_digest=pin) for name, pin, _ in PINS}


def network_features(*, anomaly_without_attribution=False, normal=False):
    values = {
        "duration_us": 500000.0,
        "fwd_packets": 100,
        "bwd_packets": 10,
        "fwd_bytes": 5000,
        "bwd_bytes": 500,
    }
    if anomaly_without_attribution or normal:
        values = {
            "duration_us": 1000000.0,
            "fwd_packets": 300 if anomaly_without_attribution else 30,
            "bwd_packets": 25,
            "fwd_bytes": 3000,
            "bwd_bytes": 2500,
        }
    source = SecurityRecord(
        record_type="network_flow",
        record_schema_version="1.0.0",
        source="synthetic-flow",
        source_reference=SourceReference(
            source_type="stream", source_name="synthetic-flow", record_id="flow-1"
        ),
        fields=values,
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    return NetworkFeatureExtractor().extract(source)


def authentication_features(*, window=0, kind="stream"):
    records = tuple(
        record(
            event_id=f"window-{window}-event-{i}",
            account="synthetic-account",
            seconds=300 * window + i,
            result="failure" if i < 40 else "success",
            kind=kind,
        )
        for i in range(42)
    )
    return AuthenticationWindowExtractor().extract(records)[0].features


async def inputs_for(packages, state, features_by_kind):
    inputs = []
    for kind, _, adapter in PINS:
        if kind not in features_by_kind:
            continue
        features = features_by_kind[kind]
        result = (
            await adapter(packages[kind])
            .as_security_ai()
            .predict(SecurityAIRequest(incident_id=state.incident_id, input=features))
        )
        inputs.append(FusionInput(signal=create_ai_signal(result, state=state), features=features))
    return tuple(inputs)


def fuse(packages, state, inputs):
    return MultiModelFusionEngine(
        tuple(binding_from_package(p) for p in packages.values()), expected_models=tuple(packages)
    ).fuse(incident_id=state.incident_id, inputs=inputs)


@pytest.mark.asyncio
@pytest.mark.parametrize("normal", (False, True))
async def test_network_fusion_real_packages(packages, normal):
    state = IncidentState()
    feature = network_features(normal=normal)
    inputs = await inputs_for(
        packages, state, {"network_classifier": feature, "network_anomaly": feature}
    )
    assert inputs[0].signal.prediction == ("BENIGN" if normal else "BruteForce")
    assert inputs[1].signal.prediction == ("normal" if normal else "anomaly")
    result = fuse(packages, state, inputs)
    assert result.agreement_state == "consistent"
    assert result.correlation_groups[0].network_relations == (
        ("no_alert" if normal else "attack_and_anomaly"),
    )
    assert len(result.contributions) == 2
    assert result.summary.unique_source_record_count == result.summary.input_group_count == 1
    assert result.confidence_state == "unknown"
    assert not state.evidence


@pytest.mark.asyncio
async def test_network_anomaly_without_attribution_real_packages(packages):
    state = IncidentState()
    feature = network_features(anomaly_without_attribution=True)
    inputs = await inputs_for(
        packages, state, {"network_classifier": feature, "network_anomaly": feature}
    )
    assert tuple(i.signal.prediction for i in inputs) == ("BENIGN", "anomaly")
    result = fuse(packages, state, inputs)
    assert result.agreement_state == "partial"
    assert result.correlation_groups[0].network_relations == ("benign_with_anomaly",)
    assert {c.decision for c in result.contributions} == {"BENIGN", "anomaly"}
    assert result.confidence_state == "unknown"
    assert "severity" not in type(result).model_fields


@pytest.mark.asyncio
async def test_authentication_only_real_package(packages):
    state = IncidentState()
    inputs = await inputs_for(
        packages, state, {"authentication_anomaly": authentication_features()}
    )
    assert inputs[0].signal.prediction == "anomaly"
    result = fuse(packages, state, inputs)
    assert result.agreement_state == "insufficient"
    assert result.coverage_state == "minimal"
    assert set(result.missing_models) == {"network_classifier", "network_anomaly"}
    assert result.summary.domains_present == ("authentication",)
    assert len(result.contributions) == 1


@pytest.mark.asyncio
async def test_cross_domain_password_spraying_like_signals_remain_unlinked(packages):
    state = IncidentState()
    network = network_features()
    inputs = await inputs_for(
        packages,
        state,
        {
            "network_classifier": network,
            "network_anomaly": network,
            "authentication_anomaly": authentication_features(),
        },
    )
    assert tuple(i.signal.prediction for i in inputs) == ("BruteForce", "anomaly", "anomaly")
    result = fuse(packages, state, inputs)
    assert len(result.correlation_groups) == 2
    assert result.summary.cross_domain_state == "unverified"
    assert result.coverage_state == "complete"
    assert result.agreement_state == "partial"
    assert result.confidence_state == "unknown"
    assert len(result.model_references) == 3
    for contribution in result.contributions:
        original = next(i for i in inputs if i.signal.signal_id in contribution.signal_ids)
        assert contribution.feature_fingerprint == original.features.input_fingerprint
        assert contribution.provenance == original.features.provenance

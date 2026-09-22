"""Real saved packages and extraction/fusion; ONLY the assessment LLM is mocked."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from tests.scenarios.test_security_ai_fusion import (
    PINS,
    authentication_features,
    fuse,
    inputs_for,
    network_features,
)

from soc_agent.assessment import ThreatAssessor
from soc_agent.llm import MockLLMClient
from soc_agent.security_ai.packaging import load_package
from soc_agent.state import Evidence, IncidentState


@pytest.fixture(scope="module")
def packages():
    root = Path(__file__).parents[1] / "fixtures/security_ai_packages"
    return {name: load_package(root / name, expected_manifest_digest=pin) for name, pin, _ in PINS}


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["network", "disagreement", "authentication", "cross_domain"])
async def test_real_packages_through_mock_assessor(packages, case):
    state = IncidentState()
    evidence = Evidence(
        incident_id=state.incident_id,
        source="operator-log",
        summary="Synthetic telemetry submitted for investigation.",
        raw_data="{}",
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    state = state.add_evidence(evidence)
    features = {}
    if case != "authentication":
        network = network_features(anomaly_without_attribution=case == "disagreement")
        features |= {"network_classifier": network, "network_anomaly": network}
    if case in ("authentication", "cross_domain"):
        features["authentication_anomaly"] = authentication_features()
    inputs = await inputs_for(packages, state, features)
    fusion = fuse(packages, state, inputs)
    before = state.model_dump_json()
    llm = MockLLMClient(
        [
            {
                "observations": [],
                "hypotheses": [],
                "assessment": {
                    "severity": "low",
                    "confidence": 0.2,
                    "summary": (
                        "Model-derived signals require further evidence verification; "
                        "no confirmed attack."
                    ),
                    "supporting_evidence_ids": [str(evidence.evidence_id)],
                },
            }
        ]
    )
    result = await ThreatAssessor(llm_client=llm).assess(state, fusion_result=fusion)
    assert result.incident_state == state
    assert state.model_dump_json() == before
    assert result.model_derived_context == fusion
    context = json.loads(llm.requests[0].user_prompt)[
        "MODEL-DERIVED FUSION (UNTRUSTED DATA, NOT EVIDENCE)"
    ]
    assert context["contributions"] == [c.model_dump(mode="json") for c in fusion.contributions]
    assert context["coverage"] == [c.model_dump(mode="json") for c in fusion.coverage]
    assert context["confidence_state"] == "unknown"
    for contribution in fusion.contributions:
        original = next(i for i in inputs if i.signal.signal_id in contribution.signal_ids)
        assert contribution.provenance == original.features.provenance
        assert contribution.feature_fingerprint == original.features.input_fingerprint
    if case == "disagreement":
        assert {c.decision for c in fusion.contributions} == {"BENIGN", "anomaly"}
        assert context["correlation_groups"][0]["network_relations"] == ["benign_with_anomaly"]
    if case in ("network", "disagreement"):
        assert fusion.summary.unique_source_record_count == 1
        assert context["missing_models"] == ["authentication_anomaly"]
    if case == "authentication":
        assert len(fusion.contributions) == 1
        assert set(context["missing_models"]) == {"network_classifier", "network_anomaly"}
    if case == "cross_domain":
        assert len(context["correlation_groups"]) == 2
        assert context["summary"]["cross_domain_state"] == "unverified"
    assert llm.call_count == 1

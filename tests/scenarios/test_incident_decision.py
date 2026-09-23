"""Saved Phase 3-6 packages, real predictions, and explicitly Mock LLM assessment."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from tests.scenarios.test_security_ai_fusion import (
    PINS,
    authentication_features,
    inputs_for,
    network_features,
)

from soc_agent.assessment import ThreatAssessor
from soc_agent.decision import DecisionOutcome, IncidentDecisionEngine
from soc_agent.llm import MockLLMClient
from soc_agent.security_ai.fusion import (
    ModelAvailability,
    MultiModelFusionEngine,
    binding_from_package,
)
from soc_agent.security_ai.packaging import load_package
from soc_agent.state import Evidence, IncidentState


@pytest.fixture(scope="module")
def packages():
    root = Path(__file__).parents[1] / "fixtures/security_ai_packages"
    return {name: load_package(root / name, expected_manifest_digest=pin) for name, pin, _ in PINS}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "bruteforce",
        "benign_anomaly",
        "authentication",
        "cross_domain",
        "failed",
        "legacy",
        "normal",
    ],
)
async def test_real_pipeline(packages, case):
    state = IncidentState()
    evidence = Evidence(
        incident_id=state.incident_id,
        source="synthetic operator log",
        summary="Telemetry submitted",
        raw_data="{}",
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    state = state.add_evidence(evidence)
    features = {}
    if case not in ("authentication", "legacy", "failed"):
        network = network_features(
            anomaly_without_attribution=case == "benign_anomaly", normal=case == "normal"
        )
        features |= {"network_classifier": network, "network_anomaly": network}
    if case in ("authentication", "cross_domain"):
        features["authentication_anomaly"] = authentication_features()
    inputs = await inputs_for(packages, state, features)
    fusion = None
    if case != "legacy":
        fusion = MultiModelFusionEngine(
            tuple(binding_from_package(p) for p in packages.values()),
            expected_models=tuple(packages),
        ).fuse(
            incident_id=state.incident_id,
            inputs=inputs,
            unavailable=(
                ModelAvailability(
                    model_kind="network_anomaly",
                    status="failed",
                    reason="Upstream execution unavailable",
                ),
            )
            if case == "failed"
            else (),
        )
    llm = MockLLMClient(
        [
            {
                "observations": [],
                "hypotheses": [],
                "assessment": {
                    "severity": "info",
                    "confidence": 0.2,
                    "summary": "Synthetic advisory analysis; needs source verification.",
                    "supporting_evidence_ids": [str(evidence.evidence_id)],
                },
            }
        ]
    )
    result = await ThreatAssessor(llm_client=llm).assess(state, fusion_result=fusion)
    before = state.model_dump_json(), result.model_dump_json()
    decision = IncidentDecisionEngine().decide(
        state, result.threat_assessment, fusion_assessment=result if fusion else None
    )
    assert (state.model_dump_json(), result.model_dump_json()) == before
    assert decision.evidence_ids == (evidence.evidence_id,)
    assert decision.model_derived_context == fusion
    assert decision.uncertainties and decision.investigation_reasons and decision.review_reasons
    assert decision.additional_investigation_required
    assert llm.call_count == 1
    assert decision == IncidentDecisionEngine().decide(
        state, result.threat_assessment, fusion_assessment=result if fusion else None
    )
    if case in ("bruteforce", "cross_domain"):
        assert {c.decision for c in fusion.contributions} == {"BruteForce", "anomaly"}
    if case == "benign_anomaly":
        assert {c.decision for c in fusion.contributions} == {"BENIGN", "anomaly"}
        assert "benign_anomaly_disagreement" in decision.applied_rules
    if case == "authentication":
        assert [c.decision for c in fusion.contributions] == ["anomaly"]
    if case == "cross_domain":
        assert len(decision.model_derived_context.correlation_groups) == 2
        assert "cross_domain_unverified" in decision.applied_rules
    if case == "failed":
        assert "coverage:network_anomaly:failed" in decision.applied_rules
    if case == "normal":
        assert {c.decision for c in fusion.contributions} == {"BENIGN", "normal"}
        assert "no_model_alert_in_supplied_inputs" in decision.applied_rules
    if case in ("failed", "legacy", "normal"):
        assert decision.outcome == DecisionOutcome.INSUFFICIENT
    else:
        assert decision.outcome == DecisionOutcome.INVESTIGATE

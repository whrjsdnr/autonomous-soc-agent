from uuid import uuid4

import pytest
from pydantic import ValidationError
from tests.fusion_support import fusion_input, model_bindings
from tests.scenarios.test_security_ai_fusion import network_features

from soc_agent.assessment import FusionAssessmentResult
from soc_agent.assessment.fusion import InvalidFusionContextError
from soc_agent.assessment.models import ThreatAssessment
from soc_agent.decision import DecisionOutcome, IncidentDecision, IncidentDecisionEngine
from soc_agent.security_ai.fusion import ModelAvailability, MultiModelFusionEngine
from soc_agent.state import Evidence, IncidentState, Observation
from soc_agent.state.evidence import utc_now


@pytest.fixture
def inputs():
    state = IncidentState()
    for i in range(2):
        state = state.add_evidence(
            Evidence(
                incident_id=state.incident_id,
                source="log",
                summary=f"record {i}",
                raw_data="{}",
                observed_at=utc_now(),
            )
        )
    observation = Observation(
        statement="Failed authentication observed",
        supporting_evidence_ids=tuple(e.evidence_id for e in state.evidence),
    )
    state = state.add_observation(observation)
    assessment = ThreatAssessment(
        incident_id=state.incident_id,
        severity="info",
        confidence=0.2,
        summary="Advisory interpretation",
        supporting_evidence_ids=tuple(e.evidence_id for e in state.evidence),
        supporting_observation_ids=(observation.observation_id,),
    )
    return state, assessment


def context(state, assessment, *, positive=True, label="BruteForce", status=None):
    bindings = model_bindings()
    features = network_features()
    signals = (
        ()
        if status
        else tuple(
            fusion_input(bindings[k], features, state, positive=positive, label=label)
            for k in ("network_classifier", "network_anomaly")
        )
    )
    unavailable = (
        ()
        if status in (None, "not_reported")
        else (
            ModelAvailability(
                model_kind="network_anomaly", status=status, reason="Upstream unavailable"
            ),
        )
    )
    fusion = MultiModelFusionEngine(
        tuple(bindings.values()), expected_models=("network_classifier", "network_anomaly")
    ).fuse(incident_id=state.incident_id, inputs=signals, unavailable=unavailable)
    return FusionAssessmentResult(
        incident_state=state, threat_assessment=assessment, model_derived_context=fusion
    )


@pytest.mark.parametrize(
    "severity,outcome",
    [
        ("info", DecisionOutcome.NO_ADDITIONAL_ALERT),
        ("low", DecisionOutcome.SUSPICIOUS),
        ("high", DecisionOutcome.SUSPICIOUS),
    ],
)
def test_legacy_and_advisory(inputs, severity, outcome):
    state, assessment = inputs
    assessment = assessment.model_copy(update={"severity": severity})
    before = state.model_dump_json(warnings=False), assessment.model_dump_json(warnings=False)
    decision = IncidentDecisionEngine().decide(state, assessment)
    assert decision.outcome == outcome
    assert decision.model_derived_context is None
    assert set(decision.evidence_ids) == {e.evidence_id for e in state.evidence}
    assert len(decision.observations) == len(state.observations)
    for actual, original in zip(decision.observations, state.observations, strict=True):
        assert actual.model_dump(exclude={"supporting_evidence_ids"}) == original.model_dump(
            exclude={"supporting_evidence_ids"}
        )
        assert set(actual.supporting_evidence_ids) == set(original.supporting_evidence_ids)
    assert decision.assessment.severity == severity
    assert (
        state.model_dump_json(warnings=False),
        assessment.model_dump_json(warnings=False),
    ) == before
    with pytest.raises(ValidationError):
        decision.outcome = DecisionOutcome.INVESTIGATE
    with pytest.raises(ValidationError):
        decision.assessment.summary = "changed"


def test_insufficient(inputs):
    state, assessment = inputs
    decision = IncidentDecisionEngine().decide(
        state, assessment.model_copy(update={"supporting_observation_ids": ()})
    )
    assert decision.outcome == DecisionOutcome.INSUFFICIENT
    assert decision.additional_investigation_required


@pytest.mark.parametrize("status", ["not_reported", "not_run", "failed", "insufficient_input"])
def test_coverage(inputs, status):
    state, assessment = inputs
    envelope = context(state, assessment, status=status)
    decision = IncidentDecisionEngine().decide(state, assessment, fusion_assessment=envelope)
    assert decision.outcome == DecisionOutcome.INSUFFICIENT
    assert f"coverage:network_anomaly:{status}" in decision.applied_rules
    assert decision.model_derived_context == envelope.model_derived_context
    assert decision.additional_investigation_required


@pytest.mark.parametrize(
    "positive,label", [(True, "BruteForce"), (True, "BENIGN"), (False, "BENIGN")]
)
def test_model_indications(inputs, positive, label):
    state, assessment = inputs
    envelope = context(state, assessment, positive=positive, label=label)
    before = envelope.model_dump_json(warnings=False)
    decision = IncidentDecisionEngine().decide(state, assessment, fusion_assessment=envelope)
    assert decision.outcome == (
        DecisionOutcome.INVESTIGATE if positive else DecisionOutcome.NO_ADDITIONAL_ALERT
    )
    assert decision.model_derived_context == envelope.model_derived_context
    assert decision.model_derived_context.confidence_state == "unknown"
    if positive:
        assert "assessment_model_difference" in decision.applied_rules
    if positive and label == "BENIGN":
        assert "benign_anomaly_disagreement" in decision.applied_rules
    assert envelope.model_dump_json(warnings=False) == before


@pytest.mark.parametrize(
    "kind", ["incident", "evidence", "observation", "foreign_evidence", "invalid_identity"]
)
def test_invalid_references_leave_inputs_unchanged(inputs, kind):
    state, assessment = inputs
    if kind == "incident":
        assessment = assessment.model_copy(update={"incident_id": uuid4()})
    elif kind in ("evidence", "observation"):
        assessment = assessment.model_copy(update={f"supporting_{kind}_ids": (uuid4(),)})
    elif kind == "invalid_identity":
        assessment = assessment.model_copy(update={"assessment_id": "not-a-uuid"})
    else:
        state = state.model_copy(
            update={
                "evidence": (
                    state.evidence[0].model_copy(update={"incident_id": uuid4()}),
                    *state.evidence[1:],
                )
            }
        )
    before = state.model_dump_json(warnings=False), assessment.model_dump_json(warnings=False)
    with pytest.raises(ValueError):
        IncidentDecisionEngine().decide(state, assessment)
    assert (
        state.model_dump_json(warnings=False),
        assessment.model_dump_json(warnings=False),
    ) == before


@pytest.mark.parametrize(
    "kind", ["identity", "contribution", "incident", "assessment", "state", "provenance"]
)
def test_tampered_fusion(inputs, kind):
    state, assessment = inputs
    envelope = context(state, assessment)
    fusion = envelope.model_derived_context
    if kind == "assessment":
        envelope = envelope.model_copy(
            update={"threat_assessment": assessment.model_copy(update={"assessment_id": uuid4()})}
        )
    elif kind == "state":
        envelope = envelope.model_copy(
            update={"incident_state": state.model_copy(update={"severity": "high"})}
        )
    else:
        if kind == "identity":
            fusion = fusion.model_copy(update={"fusion_id": "0" * 64})
        elif kind == "incident":
            fusion = fusion.model_copy(update={"incident_id": uuid4()})
        else:
            c = fusion.contributions[0]
            change = (
                {"signal_ids": (uuid4(),)}
                if kind == "contribution"
                else {"feature_fingerprint": "0" * 64}
            )
            fusion = fusion.model_copy(
                update={"contributions": (c.model_copy(update=change), *fusion.contributions[1:])}
            )
        envelope = envelope.model_copy(update={"model_derived_context": fusion})
    before = state.model_dump_json(warnings=False), envelope.model_dump_json(warnings=False)
    with pytest.raises((ValueError, InvalidFusionContextError)):
        IncidentDecisionEngine().decide(state, assessment, fusion_assessment=envelope)
    assert (
        state.model_dump_json(warnings=False),
        envelope.model_dump_json(warnings=False),
    ) == before


def test_deterministic_and_order_independent(inputs):
    state, assessment = inputs
    engine = IncidentDecisionEngine()
    first = engine.decide(state, assessment)
    assert first == engine.decide(state, assessment)
    reordered = state.model_copy(update={"evidence": tuple(reversed(state.evidence))})
    other = assessment.model_copy(
        update={"supporting_evidence_ids": tuple(reversed(assessment.supporting_evidence_ids))}
    )
    assert first == engine.decide(reordered, other)
    assert IncidentDecision.model_validate_json(first.model_dump_json(warnings=False)) == first
    with pytest.raises(ValueError):
        IncidentDecision.model_validate(first.model_dump() | {"decision_id": "0" * 64})


def test_forbidden_services(inputs, monkeypatch):
    from soc_agent.approval import ApprovalManager
    from soc_agent.execution import GovernedExecutor
    from soc_agent.llm import MockLLMClient
    from soc_agent.policy import PolicyEngine
    from soc_agent.security_ai import SecurityAI, SecurityAIRegistry
    from soc_agent.security_ai.packaging.package import ModelPackage
    from soc_agent.tools import Tool, ToolRegistry

    state, assessment = inputs
    envelope = context(state, assessment)
    approvals, registry, policy = ApprovalManager(), SecurityAIRegistry(), PolicyEngine()
    before = (
        state.model_dump_json(warnings=False),
        envelope.model_dump_json(warnings=False),
        approvals.list(),
        registry.list(),
        vars(policy).copy(),
    )

    def forbidden(*args, **kwargs):
        pytest.fail("Decision crossed execution/governance/inference boundary")

    for cls, method in (
        (ApprovalManager, "create"),
        (ApprovalManager, "approve"),
        (ApprovalManager, "reject"),
        (GovernedExecutor, "execute"),
        (GovernedExecutor, "request_approval"),
        (PolicyEngine, "evaluate"),
        (Tool, "execute"),
        (ToolRegistry, "register"),
        (SecurityAIRegistry, "register"),
        (SecurityAI, "predict"),
        (ModelPackage, "predict"),
        (MockLLMClient, "generate_structured"),
        (IncidentState, "add_evidence"),
        (IncidentState, "add_observation"),
        (IncidentState, "add_hypothesis"),
    ):
        monkeypatch.setattr(cls, method, forbidden)
    IncidentDecisionEngine().decide(state, assessment, fusion_assessment=envelope)
    assert (
        state.model_dump_json(warnings=False),
        envelope.model_dump_json(warnings=False),
        approvals.list(),
        registry.list(),
        vars(policy),
    ) == before


def test_fusion_envelope_order_and_identity_clocks(inputs):
    from datetime import timedelta

    state, assessment = inputs
    envelope = context(state, assessment)
    engine = IncidentDecisionEngine()
    original = engine.decide(state, assessment, fusion_assessment=envelope)
    reordered = state.model_copy(update={"evidence": tuple(reversed(state.evidence))})
    assert original == engine.decide(reordered, assessment, fusion_assessment=envelope)
    changed_clock = assessment.model_copy(
        update={"created_at": assessment.created_at + timedelta(seconds=5)}
    )
    assert (
        engine.decide(state, assessment).decision_id
        == engine.decide(state, changed_clock).decision_id
    )


def test_hypothesis_remains_interpretation(inputs):
    from soc_agent.state import Hypothesis

    state, assessment = inputs
    hypothesis = Hypothesis(
        statement="Possible attack, unverified",
        confidence=0.3,
        supporting_evidence_ids=(state.evidence[0].evidence_id,),
    )
    state = state.add_hypothesis(hypothesis)
    assessment = assessment.model_copy(
        update={"supporting_hypothesis_ids": (hypothesis.hypothesis_id,), "severity": "high"}
    )
    decision = IncidentDecisionEngine().decide(state, assessment)
    assert decision.hypotheses == (hypothesis,)
    assert hypothesis.hypothesis_id not in decision.evidence_ids
    assert len(state.evidence) == 2


def test_advisory_concern_and_normal_models(inputs):
    state, assessment = inputs
    assessment = ThreatAssessment.model_validate(assessment.model_dump() | {"severity": "high"})
    envelope = context(state, assessment, positive=False)
    decision = IncidentDecisionEngine().decide(state, assessment, fusion_assessment=envelope)
    assert decision.outcome == DecisionOutcome.SUSPICIOUS
    assert "assessment_model_difference" in decision.applied_rules
    assert decision.assessment.severity == "high"
    assert {c.decision for c in decision.model_derived_context.contributions} == {
        "BENIGN",
        "normal",
    }
    assert state.severity == "info"


@pytest.mark.parametrize("cross_domain", [False, True])
def test_authentication_model_context_and_separate_groups(inputs, cross_domain):
    from tests.scenarios.test_security_ai_fusion import authentication_features

    state, assessment = inputs
    bindings = model_bindings()
    signals = [fusion_input(bindings["authentication_anomaly"], authentication_features(), state)]
    if cross_domain:
        signals.append(fusion_input(bindings["network_classifier"], network_features(), state))
    fusion = MultiModelFusionEngine(tuple(bindings.values()), expected_models=tuple(bindings)).fuse(
        incident_id=state.incident_id, inputs=tuple(signals)
    )
    envelope = FusionAssessmentResult(
        incident_state=state, threat_assessment=assessment, model_derived_context=fusion
    )
    decision = IncidentDecisionEngine().decide(state, assessment, fusion_assessment=envelope)
    assert decision.outcome == DecisionOutcome.INVESTIGATE
    assert decision.model_derived_context == fusion
    assert len(fusion.correlation_groups) == (2 if cross_domain else 1)
    assert ("cross_domain_unverified" in decision.applied_rules) == cross_domain
    assert set(decision.evidence_ids) == {e.evidence_id for e in state.evidence}


def test_legacy_later_snapshot_is_membership_only(inputs):
    state, assessment = inputs
    later = state.add_evidence(
        Evidence(
            incident_id=state.incident_id,
            source="later",
            summary="New record",
            raw_data="{}",
            observed_at=utc_now(),
        )
    )
    decision = IncidentDecisionEngine().decide(later, assessment)
    assert later.evidence[-1].evidence_id not in decision.evidence_ids
    assert any("contemporaneity is unproven" in text for text in decision.limitations)
    assert decision == IncidentDecisionEngine().decide(state, assessment)

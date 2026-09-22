from datetime import timedelta
from itertools import permutations
from uuid import uuid4

import pytest
from tests.authentication_support import fixture_examples
from tests.fusion_support import fusion_input, model_bindings
from tests.scenarios.test_security_ai_packaging import network_feature

from soc_agent.security_ai.evaluation.data import digest
from soc_agent.security_ai.fusion import (
    AgreementState,
    ConfidenceState,
    CoverageState,
    FusionIdentityCollision,
    MultiModelFusionEngine,
)
from soc_agent.state import IncidentState


@pytest.fixture(scope="module")
def setup():
    bindings = model_bindings()
    state = IncidentState()
    network = network_feature("dataset")
    auth = fixture_examples()[0].features
    items = {
        kind: fusion_input(binding, auth if kind == "authentication_anomaly" else network, state)
        for kind, binding in bindings.items()
    }
    return bindings, state, items


def fuse(setup, names):
    bindings, state, items = setup
    return MultiModelFusionEngine(tuple(bindings.values()), expected_models=tuple(bindings)).fuse(
        incident_id=state.incident_id, inputs=tuple(items[n] for n in names)
    )


@pytest.mark.parametrize(
    "names,agreement,coverage,groups",
    [
        (("network_classifier",), "insufficient", "minimal", 1),
        (("network_anomaly",), "insufficient", "minimal", 1),
        (("authentication_anomaly",), "insufficient", "minimal", 1),
        (("network_classifier", "network_anomaly"), "consistent", "partial", 1),
        (("network_classifier", "authentication_anomaly"), "insufficient", "partial", 2),
        (
            ("network_classifier", "network_anomaly", "authentication_anomaly"),
            "partial",
            "complete",
            2,
        ),
        ((), "insufficient", "none", 0),
    ],
)
def test_basic_combinations(setup, names, agreement, coverage, groups):
    result = fuse(setup, names)
    assert result.agreement_state == agreement
    assert result.coverage_state == coverage
    assert len(result.correlation_groups) == groups
    assert result.confidence_state == ConfidenceState.UNKNOWN
    assert len(result.contributions) == len(names)
    assert set(result.missing_models) == set(setup[0]) - set(names)


@pytest.mark.parametrize(
    "classifier_positive,anomaly_positive,expected",
    [
        (True, True, "consistent"),
        (False, False, "consistent"),
        (True, False, "partial"),
        (False, True, "partial"),
    ],
)
def test_directional_rule(setup, classifier_positive, anomaly_positive, expected):
    bindings, state, items = setup
    features = items["network_classifier"].features
    inputs = (
        fusion_input(bindings["network_classifier"], features, state, positive=classifier_positive),
        fusion_input(bindings["network_anomaly"], features, state, positive=anomaly_positive),
    )
    result = MultiModelFusionEngine(tuple(bindings.values()), expected_models=tuple(bindings)).fuse(
        incident_id=state.incident_id, inputs=inputs
    )
    assert result.agreement_state == expected
    assert result.confidence_state == "unknown"
    assert result.correlation_groups[0].compatibility_rules == (
        "network-attribution-vs-baseline-deviation:v1",
    )


def test_conflicting_versions_of_same_task(setup):
    bindings, state, items = setup
    old = bindings["network_classifier"]
    manifest = old.manifest.model_copy(update={"model_version": "2.0.0"})
    new = old.model_copy(
        update={
            "manifest_digest": digest("second-package"),
            "manifest": manifest,
            "profile": old.profile.model_copy(update={"model_version": "2.0.0"}),
        }
    )
    another = fusion_input(new, items["network_classifier"].features, state, positive=False)
    result = MultiModelFusionEngine((old, new), expected_models=("network_classifier",)).fuse(
        incident_id=state.incident_id, inputs=(items["network_classifier"], another)
    )
    assert result.agreement_state == AgreementState.CONFLICTING
    assert result.confidence_state == "unknown"
    assert len(result.contributions) == 2


def test_order_duplicate_and_fingerprint(setup):
    bindings, state, items = setup
    engine = MultiModelFusionEngine(tuple(bindings.values()), expected_models=tuple(bindings))
    originals = tuple(items.values())
    expected = engine.fuse(incident_id=state.incident_id, inputs=originals)
    for order in permutations(originals):
        assert engine.fuse(incident_id=state.incident_id, inputs=order) == expected
        assert (
            engine.fuse(incident_id=state.incident_id, inputs=order + (originals[0],) * 10)
            == expected
        )
    assert expected.fusion_fingerprint == expected.fusion_id
    with pytest.raises(ValueError):
        expected.confidence_state = "high"
    with pytest.raises(ValueError):
        expected.contributions[0].decision = "benign"


def test_replay_with_new_ids_does_not_add_contribution(setup):
    bindings, state, items = setup
    item = items["network_classifier"]
    replay = item.model_copy(
        update={
            "signal": item.signal.model_copy(
                update={"signal_id": uuid4(), "source_result_id": uuid4()}
            )
        }
    )
    engine = MultiModelFusionEngine(tuple(bindings.values()), expected_models=tuple(bindings))
    original = engine.fuse(incident_id=state.incident_id, inputs=(item,))
    result = engine.fuse(incident_id=state.incident_id, inputs=(replay, item))
    assert result.fusion_id == original.fusion_id
    assert result.agreement_state == original.agreement_state
    assert result.created_at == original.created_at
    assert len(result.contributions) == 1
    assert len(result.contributions[0].signal_ids) == len(result.signals) == 2


@pytest.mark.parametrize("identity", ("signal", "source_result", "replay"))
def test_identity_collisions(setup, identity):
    bindings, state, items = setup
    original = items["network_classifier"]
    modified = fusion_input(
        bindings["network_classifier"], original.features, state, positive=False
    )
    if identity == "signal":
        modified = modified.model_copy(
            update={
                "signal": modified.signal.model_copy(
                    update={"signal_id": original.signal.signal_id}
                )
            }
        )
    if identity == "source_result":
        modified = modified.model_copy(
            update={
                "signal": modified.signal.model_copy(
                    update={
                        "source_result_id": original.signal.source_result_id,
                        "source_created_at": original.signal.source_created_at,
                    }
                )
            }
        )
    engine = MultiModelFusionEngine(tuple(bindings.values()), expected_models=tuple(bindings))
    with pytest.raises(FusionIdentityCollision):
        engine.fuse(incident_id=state.incident_id, inputs=(original, modified))
    assert (
        engine.fuse(incident_id=state.incident_id, inputs=(original,)).contributions[0].decision
        == "BruteForce"
    )


def test_missing_is_not_benign_and_expected_coverage(setup):
    bindings, state, items = setup
    engine = MultiModelFusionEngine(
        tuple(bindings.values()), expected_models=("network_classifier", "network_anomaly")
    )
    result = engine.fuse(
        incident_id=state.incident_id,
        inputs=(items["network_classifier"], items["network_anomaly"]),
    )
    assert result.coverage_state == CoverageState.COMPLETE
    assert all(c.model_kind != "authentication_anomaly" for c in result.contributions)
    assert not result.missing_models


def test_provenance_and_model_identity_preserved(setup):
    result = fuse(setup, tuple(setup[0]))
    bindings = {b.manifest_digest: b for b in result.model_references}
    originals = {s.signal_id: s for s in result.signals}
    for c in result.contributions:
        source = originals[c.signal_ids[0]]
        explanation = source.explanation_payload()
        assert c.feature_fingerprint == explanation["feature_fingerprint"]
        assert c.provenance.model_dump(mode="json") == explanation["feature_provenance"]
        binding = bindings[c.model_reference]
        assert (binding.manifest.model_id, binding.manifest.model_version) == (
            source.model_name,
            source.model_version,
        )
        assert binding.manifest.selection_digest == explanation["selection_digest"]
        assert binding.manifest_digest == explanation["package_manifest_digest"]
        if c.model_kind != "network_classifier":
            assert c.score_semantics == "empirical anomaly rank; raw=-score_samples"
            assert c.scores.anomaly_score == source.scores_payload()["normalized_anomaly_score"]


@pytest.mark.parametrize("change", ("source", "time", "fingerprint"))
def test_unrelated_inputs_stay_separate(setup, change):
    bindings, state, items = setup
    features = items["network_classifier"].features
    if change == "fingerprint":
        values = features.input_payload()
        values["fwd_packets"] += 1
        from soc_agent._json import canonical_json_object

        features = features.model_copy(update={"values": canonical_json_object(values)})
        # A genuinely different source record, not contradictory contents for one identity.
    source = features.provenance.sources[0]
    if change == "time":
        source = source.model_copy(
            update={"observed_at": source.observed_at + timedelta(seconds=1)}
        )
    else:
        source = source.model_copy(
            update={
                "source_reference": source.source_reference.model_copy(
                    update={"record_id": "other"}
                ),
                "dataset_reference": source.dataset_reference.model_copy(
                    update={"record_id": "other"}
                ),
            }
        )
    features = features.model_copy(
        update={"provenance": features.provenance.model_copy(update={"sources": (source,)})}
    )
    from soc_agent.security_ai.features import FeatureSet

    features = FeatureSet.model_validate(features.model_dump())
    other = fusion_input(bindings["network_anomaly"], features, state)
    result = MultiModelFusionEngine(tuple(bindings.values()), expected_models=tuple(bindings)).fuse(
        incident_id=state.incident_id, inputs=(items["network_classifier"], other)
    )
    assert len(result.correlation_groups) == 2
    assert result.agreement_state == "insufficient"

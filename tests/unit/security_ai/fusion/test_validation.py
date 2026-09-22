from datetime import timedelta
from uuid import uuid4

import pytest
from tests.fusion_support import fusion_input, model_bindings
from tests.scenarios.test_security_ai_packaging import network_feature

from soc_agent.security_ai.features import FeatureSet
from soc_agent.security_ai.fusion import (
    FusionInput,
    FusionValidationError,
    ModelAvailability,
    MultiModelFusionEngine,
)
from soc_agent.security_ai.signals import AISignal
from soc_agent.state import IncidentState


@pytest.fixture(scope="module")
def context():
    bindings = model_bindings()
    state = IncidentState()
    features = network_feature("stream")
    engine = MultiModelFusionEngine(tuple(bindings.values()), expected_models=tuple(bindings))
    return bindings, state, features, engine


@pytest.mark.parametrize(
    "change",
    (
        "incident",
        "version",
        "name",
        "task",
        "package",
        "selection",
        "fingerprint",
        "fingerprint_format",
        "provenance",
        "schema",
        "extractor",
        "order",
        "features",
        "source_type",
        "source_record",
        "time",
        "evidence",
        "nan",
        "infinity",
        "probability_sum",
        "probability_class",
        "probability_negative",
        "probability_argmax",
        "confidence",
        "unknown_link",
    ),
)
def test_invalid_classifier_input_all_or_nothing(context, change):
    bindings, state, features, engine = context
    good = fusion_input(bindings["network_classifier"], features, state)
    data = good.signal.model_dump()
    scores, explanation = good.signal.scores_payload(), good.signal.explanation_payload()
    altered_features = features
    if change == "incident":
        data["incident_id"] = uuid4()
    elif change == "version":
        data["model_version"] = "9.9.9"
    elif change == "name":
        data["model_name"] = "unknown_model"
    elif change == "task":
        data["task_type"] = "anomaly_detection"
    elif change == "package":
        explanation["package_manifest_digest"] = "a" * 64
    elif change == "selection":
        explanation["selection_digest"] = "a" * 64
    elif change == "fingerprint":
        explanation["feature_fingerprint"] = "a" * 64
    elif change == "fingerprint_format":
        explanation["feature_fingerprint"] = "invalid"
    elif change == "provenance":
        explanation["feature_provenance"]["sources"][0]["content_digest"] = "a" * 64
    elif change in {"schema", "extractor", "order", "features", "source_type", "source_record"}:
        payload = features.model_dump()
        if change == "schema":
            payload["feature_schema"]["schema_version"] = "99"
        elif change == "extractor":
            payload["provenance"]["extractor_version"] = "99"
        elif change == "order":
            payload["feature_schema"]["features"] = tuple(
                reversed(payload["feature_schema"]["features"])
            )
        elif change == "features":
            payload["values"] = features.input_payload() | {"fwd_packets": 777}
        elif change == "source_type":
            payload["provenance"]["sources"][0]["source_reference"]["source_type"] = "evidence"
        elif change == "source_record":
            payload["provenance"]["sources"][0]["record_type"] = "authentication_event"
        if change == "source_type":
            # Bypass construction only to exercise the fusion trust boundary.
            altered_features = FeatureSet.model_construct(**payload)
        else:
            altered_features = FeatureSet.model_validate(payload)
            explanation["feature_fingerprint"] = altered_features.input_fingerprint
            explanation["feature_provenance"] = altered_features.provenance.model_dump(mode="json")
            if change == "features":
                explanation = good.signal.explanation_payload()
    elif change == "time":
        data["source_created_at"] = features.provenance.sources[0].observed_at - timedelta(
            seconds=1
        )
    elif change == "evidence":
        data["source_evidence_ids"] = (uuid4(),)
    elif change in {"nan", "infinity"}:
        data["scores"] = (
            '{"class_probabilities":{"BENIGN":NaN}}'
            if change == "nan"
            else '{"class_probabilities":{"BENIGN":1e999}}'
        )
    elif change == "probability_sum":
        scores["class_probabilities"]["BENIGN"] = 0.4
    elif change == "probability_class":
        scores["class_probabilities"]["other"] = scores["class_probabilities"].pop("DoS")
    elif change == "probability_negative":
        scores["class_probabilities"]["BENIGN"] = -0.05
    elif change == "probability_argmax":
        data["prediction"] = "BENIGN"
    elif change == "confidence":
        data["confidence"] = 0.1
    elif change == "unknown_link":
        explanation["verified_account_ip_link"] = "invented"
    if change not in {"nan", "infinity"}:
        data["scores"] = scores
    data["explanation"] = explanation
    bad = FusionInput.model_construct(
        signal=AISignal.model_construct(**data), features=altered_features
    )
    before = good.model_dump_json()
    with pytest.raises(FusionValidationError):
        engine.fuse(incident_id=state.incident_id, inputs=(good, bad))
    assert good.model_dump_json() == before
    assert len(engine.fuse(incident_id=state.incident_id, inputs=(good,)).contributions) == 1


@pytest.mark.parametrize(
    "change",
    (
        "threshold",
        "operating_point",
        "point_identity",
        "rank",
        "selected",
        "normalized",
        "probability_claim",
        "nan",
        "confidence",
    ),
)
def test_invalid_anomaly_semantics(context, change):
    bindings, state, features, engine = context
    item = fusion_input(bindings["network_anomaly"], features, state)
    data = item.signal.model_dump()
    scores, explanation = item.signal.scores_payload(), item.signal.explanation_payload()
    if change == "threshold":
        scores["normalized_threshold"] = -1.0
    elif change == "operating_point":
        explanation["operating_point"]["threshold"] = 0.123
    elif change == "point_identity":
        explanation["operating_point_identity"] = "a" * 64
    elif change == "rank":
        scores["normalized_anomaly_score"] = 0.25
    elif change == "selected":
        scores["selected_decision"] = False
    elif change == "normalized":
        scores["normalized_decision"] = False
    elif change == "probability_claim":
        explanation["score_semantics"] = "attack probability"
    elif change == "confidence":
        data["confidence"] = 0.9
    elif change == "nan":
        scores["raw_anomaly_measure"] = float("nan")
    data |= {"scores": scores, "explanation": explanation}
    bad = item.model_copy(update={"signal": AISignal.model_construct(**data)})
    with pytest.raises(FusionValidationError):
        engine.fuse(incident_id=state.incident_id, inputs=(bad,))


@pytest.mark.parametrize(
    "change",
    (
        "kind",
        "schema",
        "order",
        "extractor",
        "model",
        "version",
        "classes",
        "threshold",
        "inventory",
    ),
)
def test_invalid_trusted_metadata_rejected(context, change):
    bindings, _, _, _ = context
    binding = bindings["network_anomaly" if change == "threshold" else "network_classifier"]
    manifest = binding.manifest.model_dump()
    if change == "kind":
        manifest["model_kind"] = "unknown"
    elif change == "schema":
        manifest["feature_schema_name"] = "other"
    elif change == "order":
        manifest["ordered_feature_names"] = tuple(reversed(manifest["ordered_feature_names"]))
    elif change == "extractor":
        manifest["extractor_name"] = "unknown"
    elif change == "model":
        manifest["model_id"] = "unknown"
    elif change == "version":
        manifest["model_version"] = "99"
    elif change == "threshold":
        manifest["operating_point"]["threshold"] = 2.0
    elif change == "inventory":
        manifest["file_hashes"] = (manifest["file_hashes"][0],) * 3
    elif change == "classes":
        binding = binding.model_copy(
            update={"profile": binding.profile.model_copy(update={"classes": ("A", "B")})}
        )
    from soc_agent.security_ai.packaging.package import PackageManifest

    binding = binding.model_copy(update={"manifest": PackageManifest.model_construct(**manifest)})
    with pytest.raises(FusionValidationError):
        MultiModelFusionEngine((binding,), expected_models=("network_classifier",))


@pytest.mark.parametrize("status", ("not_run", "failed", "insufficient_input"))
def test_availability_is_not_a_negative_prediction(context, status):
    bindings, state, features, engine = context
    item = fusion_input(bindings["network_classifier"], features, state)
    absent = ModelAvailability(
        model_kind="network_anomaly", status=status, reason="explicit caller status"
    )
    result = engine.fuse(incident_id=state.incident_id, inputs=(item,), unavailable=(absent,))
    statuses = {v.model_kind: v.status for v in result.coverage}
    assert statuses == {
        "network_classifier": "observed",
        "network_anomaly": status,
        "authentication_anomaly": "not_reported",
    }
    assert len(result.contributions) == 1
    assert result.agreement_state == "insufficient"
    assert result.confidence_state == "unknown"
    assert "network_anomaly" in result.missing_models


def test_contradictory_availability_rejected(context):
    bindings, state, features, engine = context
    item = fusion_input(bindings["network_anomaly"], features, state)
    failure = ModelAvailability(model_kind="network_anomaly", status="failed", reason="failed")
    for inputs, unavailable in (((item,), (failure,)), ((), (failure, failure))):
        with pytest.raises(FusionValidationError):
            engine.fuse(incident_id=state.incident_id, inputs=inputs, unavailable=unavailable)


def test_explicit_expectations_and_bounds(context):
    bindings, state, features, engine = context
    with pytest.raises(TypeError):
        MultiModelFusionEngine(tuple(bindings.values()))
    for expected in ((), ("unknown",), ("network_classifier",) * 2):
        with pytest.raises(FusionValidationError):
            MultiModelFusionEngine(tuple(bindings.values()), expected_models=expected)
    item = fusion_input(bindings["network_classifier"], features, state)
    with pytest.raises(FusionValidationError):
        engine.fuse(incident_id=state.incident_id, inputs=(item,) * 129)

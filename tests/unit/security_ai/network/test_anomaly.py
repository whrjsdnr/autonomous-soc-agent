"""Independent baseline fitting, score semantics, immutable inference bindings."""

from dataclasses import FrozenInstanceError

import numpy as np
import pytest
from pydantic import ValidationError
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from soc_agent.security_ai.features import FeatureSet
from soc_agent.security_ai.network.anomaly import (
    AnomalyInferenceProfile,
    AnomalyScoreReference,
    AnomalyTrainingConfig,
    NetworkAnomalyDetector,
    NetworkAnomalyPrediction,
    ScalerState,
)
from soc_agent.security_ai.network.anomaly_training import (
    AnomalyTrainingMetadata,
    AnomalyTrainingResult,
    evaluate_anomaly,
    train_anomaly,
)
from soc_agent.security_ai.network.dataset import PreparedDataset
from soc_agent.security_ai.network.preprocessing import feature_matrix


@pytest.fixture
def trained(dataset: PreparedDataset) -> AnomalyTrainingResult:
    return train_anomaly(dataset, config=AnomalyTrainingConfig(n_estimators=8))


def test_fit_only_benign_train_no_labels(
    dataset: PreparedDataset, monkeypatch: pytest.MonkeyPatch
) -> None:
    scaler_fit, forest_fit = StandardScaler.fit, IsolationForest.fit
    captured = {}

    def fit_scaler(self, x, y=None, **kwargs):
        assert y is None
        captured["scaler"] = np.array(x, copy=True)
        return scaler_fit(self, x, y, **kwargs)

    def fit_forest(self, x, y=None, **kwargs):
        assert y is None
        captured["forest"] = np.array(x, copy=True)
        return forest_fit(self, x, y, **kwargs)

    monkeypatch.setattr(StandardScaler, "fit", fit_scaler)
    monkeypatch.setattr(IsolationForest, "fit", fit_forest)
    result = train_anomaly(dataset, config=AnomalyTrainingConfig(n_estimators=8))
    metadata = result.metadata
    indices = metadata.baseline_indices
    assert set(indices) <= set(metadata.split.train)
    assert not set(indices) & (set(metadata.split.validation) | set(metadata.split.test))
    assert all(dataset.examples[i].label == "BENIGN" for i in indices)
    expected = feature_matrix(
        tuple(dataset.examples[i].features for i in indices), result.detector.profile.contract
    )
    assert captured["scaler"].shape == (len(indices), 5)
    np.testing.assert_array_equal(captured["scaler"], expected)
    np.testing.assert_allclose(
        metadata.profile.scaler.mean, expected.astype(np.float64).mean(axis=0)
    )
    np.testing.assert_allclose(captured["forest"], metadata.profile.scaler.transform(expected))
    assert "Label" not in dataset.examples[0].features.feature_names
    assert len(metadata.profile.normalization.sorted_measures) == len(indices)


def test_score_semantics_and_determinism(
    dataset: PreparedDataset, trained: AnomalyTrainingResult
) -> None:
    other = train_anomaly(dataset, config=AnomalyTrainingConfig(n_estimators=8))
    assert other.metadata == trained.metadata
    assert (
        AnomalyTrainingMetadata.model_validate_json(trained.metadata.model_dump_json())
        == trained.metadata
    )
    detector = trained.detector
    features = dataset.examples[0].features
    prediction = detector.predict(features)
    assert other.detector.predict(features) == prediction
    matrix = detector.profile.scaler.transform(
        feature_matrix((features,), detector.profile.contract)
    )
    assert prediction.raw_score == float(detector._model.score_samples(matrix)[0])
    assert prediction.raw_decision_score == float(detector._model.decision_function(matrix)[0])
    assert prediction.raw_anomaly_measure == -prediction.raw_score
    assert (detector._model.predict(matrix)[0] == -1) == (prediction.raw_decision_score < 0)
    assert prediction.is_anomaly == (prediction.anomaly_score >= prediction.threshold)
    assert 0 <= prediction.anomaly_score <= 1
    assert prediction.threshold == 0.95
    assert detector.profile.normalization.sklearn_offset == -0.5


def test_fixed_normalization_and_intervening_events(
    dataset: PreparedDataset, trained: AnomalyTrainingResult
) -> None:
    detector = trained.detector
    feature = dataset.examples[0].features
    before = detector.profile.model_dump_json()
    first = detector.predict(feature)
    for example in reversed(dataset.examples[::20]):
        detector.predict(example.features)
    assert detector.predict(feature) == first
    assert detector.profile.model_dump_json() == before
    reference = detector.profile.normalization
    assert reference.normalize(first.raw_anomaly_measure) == first.anomaly_score


@pytest.mark.parametrize(
    "value,expected", [(-1e100, 0), (1, 0.125), (2, 0.5), (2.5, 0.75), (3, 0.875), (1e100, 1)]
)
def test_percentile_ties_and_extremes(value: float, expected: float) -> None:
    reference = AnomalyScoreReference(
        sorted_measures=(1, 2, 2, 3), threshold=0.95, sklearn_offset=-0.5
    )
    assert reference.normalize(value) == expected
    assert reference.normalize(value) == reference.normalize(value)


@pytest.mark.parametrize(
    "change",
    [
        {"sorted_measures": (2, 1)},
        {"sorted_measures": ()},
        {"sorted_measures": (float("nan"), 1)},
        {"threshold": 0},
        {"threshold": 1.1},
        {"sklearn_offset": float("inf")},
        {"method": "runtime_minmax"},
    ],
)
def test_invalid_normalization(change: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        AnomalyScoreReference.model_validate(
            {"sorted_measures": (1, 2), "threshold": 0.95, "sklearn_offset": -0.5} | change
        )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_nonfinite_normalization_rejected(trained: AnomalyTrainingResult, value: float) -> None:
    with pytest.raises(ValueError):
        trained.detector.profile.normalization.normalize(value)


@pytest.mark.parametrize(
    "kind", ["name", "version", "order", "missing", "extractor", "nan", "infinity", "negative"]
)
def test_runtime_contract_fail_closed(
    dataset: PreparedDataset, trained: AnomalyTrainingResult, kind: str
) -> None:
    data = dataset.examples[0].features.model_dump()
    if kind in {"name", "version"}:
        data["feature_schema"]["schema_" + kind] = "other" if kind == "name" else "2"
    elif kind == "order":
        data["feature_schema"]["features"] = tuple(reversed(data["feature_schema"]["features"]))
    elif kind == "extractor":
        data["provenance"]["extractor_version"] = "2"
    elif kind == "missing":
        data["values"] = "{}"
    else:
        value = {"nan": float("nan"), "infinity": float("inf"), "negative": -1.0}[kind]
        data["values"] = dataset.examples[0].features.input_payload() | {"duration_us": value}
    with pytest.raises(ValueError):
        trained.detector.predict(FeatureSet.model_validate(data))


def test_frozen_and_detached_profile(
    dataset: PreparedDataset, trained: AnomalyTrainingResult
) -> None:
    prediction = trained.detector.predict(dataset.examples[0].features)
    with pytest.raises(ValidationError):
        prediction.threshold = 0.1
    with pytest.raises(ValidationError):
        trained.detector.profile.normalization.threshold = 0.1
    with pytest.raises(FrozenInstanceError):
        trained.detector.profile = None
    with pytest.raises(TypeError):
        trained.detector.predict(dataset.examples[0].features, threshold=0.1)
    # Trusted construction detaches fitted sklearn internals from its caller.
    model = trained.detector._model
    detached = NetworkAnomalyDetector(profile=trained.detector.profile, _model=model)
    model.offset_ = 100
    assert detached.predict(dataset.examples[0].features) == prediction


@pytest.mark.parametrize(
    "kind", ["threshold", "scaler_count", "reference_count", "max_samples", "schema"]
)
def test_profile_binding(trained: AnomalyTrainingResult, kind: str) -> None:
    data = trained.detector.profile.model_dump()
    if kind == "threshold":
        data["normalization"]["threshold"] = 0.5
    elif kind == "scaler_count":
        data["scaler"]["mean"] = (0.0,)
    elif kind == "reference_count":
        data["normalization"]["sorted_measures"] = (0.1, 0.2)
    elif kind == "max_samples":
        data["fitted_max_samples"] = 1000
    else:
        data["contract"]["feature_schema"]["schema_version"] = "2"
    with pytest.raises(ValidationError):
        AnomalyInferenceProfile.model_validate(data)


def test_no_benign_baseline(dataset: PreparedDataset) -> None:
    examples = tuple(
        e.model_copy(update={"label": "NORMAL_UNKNOWN" if e.label == "BENIGN" else e.label})
        for e in dataset.examples
    )
    with pytest.raises(ValueError, match="BENIGN"):
        train_anomaly(dataset.model_copy(update={"examples": examples}))


def prediction(score: float) -> NetworkAnomalyPrediction:
    return NetworkAnomalyPrediction(
        is_anomaly=score >= 0.5,
        raw_score=-score,
        raw_decision_score=0.5 - score,
        raw_anomaly_measure=score,
        anomaly_score=score,
        threshold=0.5,
    )


def test_binary_evaluation_known_values() -> None:
    metrics = evaluate_anomaly(
        (False, False, True, True), tuple(prediction(v) for v in (0.1, 0.8, 0.9, 0.4))
    )
    assert metrics.confusion_matrix == ((1, 1), (1, 1))
    assert metrics.precision == metrics.recall == metrics.f1 == 0.5
    assert metrics.roc_auc == 0.75
    assert metrics.average_precision == pytest.approx(5 / 6)
    assert metrics.normal_support == metrics.anomaly_support == 2


def test_one_class_auc_undefined() -> None:
    result = evaluate_anomaly((False, False), (prediction(0.1), prediction(0.2)))
    assert result.roc_auc is None and result.average_precision is None
    assert result.confusion_matrix == ((2, 0), (0, 0))


def test_scaler_matches_sklearn_and_constant_features() -> None:
    matrix = np.array([[1, 2], [1, 4], [1, 9]], dtype=np.float64)
    scaler = StandardScaler().fit(matrix)
    state = ScalerState(
        mean=tuple(scaler.mean_), scale=tuple(scaler.scale_), variance=tuple(scaler.var_), samples=3
    )
    assert state.scale[0] == 1
    np.testing.assert_array_equal(state.transform(matrix), scaler.transform(matrix))


@pytest.mark.parametrize(
    "change",
    [
        {"is_anomaly": False},
        {"raw_anomaly_measure": -1},
        {"anomaly_score": 2},
        {"raw_score": float("nan")},
        {"attack_type": "DDoS"},
    ],
)
def test_prediction_contract(change: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        NetworkAnomalyPrediction.model_validate(prediction(0.9).model_dump() | change)

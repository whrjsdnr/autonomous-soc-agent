import numpy as np
import pytest
from tests.evaluation_support import network_rows

from soc_agent.security_ai.anomaly_common import AnomalyTrainingConfig
from soc_agent.security_ai.evaluation import (
    Partition,
    audit,
    calibration_partition,
    evaluate_test,
    partitions,
    require_disjoint,
    select_anomaly,
    select_classifier,
)
from soc_agent.security_ai.evaluation.metrics import (
    OperatingPoint,
    binary_metrics,
    choose_threshold,
    probability_matrix,
    probability_metrics,
    temperature_scale,
    threshold_trials,
)
from soc_agent.security_ai.network.classifier import ClassificationPrediction, ClassProbability
from soc_agent.security_ai.network.training import TrainingConfig


@pytest.fixture(scope="module")
def development(tmp_path_factory):
    rows, _ = network_rows(tmp_path_factory.mktemp("evaluation") / "fixture.csv", count=30)
    return partitions(rows, dataset_name="synthetic-test", dataset_version="1")


def test_known_binary_metrics_and_single_class():
    m = binary_metrics((False, False, True, True), (0.1, 0.8, 0.9, 0.4), (False, True, True, False))
    assert m.confusion_matrix == ((1, 1), (1, 1))
    assert m.precision == m.recall == m.f1 == m.fpr == 0.5
    assert m.roc_auc == 0.75 and m.average_precision == pytest.approx(5 / 6)
    one = binary_metrics((True, True), (0.2, 0.3), (False, False))
    assert one.fpr is None and one.roc_auc is None and one.average_precision is None
    assert one.precision == one.recall == one.f1 == 0


def test_threshold_ties_and_fpr_constraint():
    trials = threshold_trials(
        (False, False, True, True), (0.1, 0.2, 0.9, 1.0), (0.1, 0.2, 0.99, 1.0)
    )
    assert choose_threshold(trials) == 0
    i = choose_threshold(trials, objective="recall_at_fpr", fpr_limit=0)
    assert trials[i].metrics.fpr == 0 and trials[i].metrics.recall == 1
    assert choose_threshold(trials) == choose_threshold(trials)
    assert any(t.point.space == "raw" for t in trials)


@pytest.mark.parametrize(
    "values,temp",
    [(np.array([[np.nan, 0.5]]), 1), (np.array([[0.1, 0.2]]), 1), (np.array([[0.5, 0.5]]), 0)],
)
def test_bad_probabilities(values, temp):
    with pytest.raises(ValueError):
        temperature_scale(values, temp)


def test_probability_mapping_metrics_and_temperature():
    classes = ("a", "b")
    rows = (
        ClassificationPrediction(
            predicted_class="a",
            confidence=0.9,
            class_probabilities=(
                ClassProbability(label="a", probability=0.9),
                ClassProbability(label="b", probability=0.1),
            ),
        ),
    )
    matrix = probability_matrix(rows, classes)
    with pytest.raises(ValueError):
        probability_matrix(rows, tuple(reversed(classes)))
    m = probability_metrics(("a",), matrix, classes)
    assert m.log_loss == pytest.approx(-np.log(0.9)) and m.brier_score == pytest.approx(0.02)
    assert m.classification.macro_f1 == 0.5
    assert sum(b.count for b in m.reliability) == 1
    calibrated = temperature_scale(matrix, 2)
    assert np.argmax(calibrated) == np.argmax(matrix)
    assert calibrated.sum() == pytest.approx(1)
    assert calibrated[0, 0] < matrix[0, 0]
    assert np.isfinite(temperature_scale(np.array([[0.0, 1.0]]), 0.5)).all()


def test_split_audit_and_calibration(development):
    train, val, test, split = development
    require_disjoint(train, val, test)
    a = audit(train, "BENIGN")
    assert a.rows == 72 and a.normal_rows == 18
    assert a.missing_values == a.nonfinite_values == a.duplicate_input_rows == 0
    assert not any(r.group_id in a.model_dump_json() for r in train.rows)
    selection, cal = calibration_partition(val)
    require_disjoint(train, selection, cal, test)
    assert {r.label for r in selection.rows} == {r.label for r in cal.rows}
    assert cal.role == "calibration"
    with pytest.raises(ValueError):
        require_disjoint(train, train.model_copy(update={"role": "test"}))


@pytest.mark.parametrize("function", [select_classifier, select_anomaly])
def test_test_partition_cannot_select(function, development):
    train, val, test, _ = development
    kwargs = {"domain": "network"} if function == select_anomaly else {}
    with pytest.raises(ValueError, match="Expected selection"):
        function(train, test, **kwargs)
    with pytest.raises(ValueError, match="Expected train"):
        function(test, val, **kwargs)


def test_calibration_role_rejected(development):
    train, val, test, _ = development
    with pytest.raises(ValueError, match="Expected calibration"):
        select_classifier(train, val, calibration=test)


def test_freeze_then_test_and_baseline_retained(development, monkeypatch):
    train, val, test, _ = development
    config = (TrainingConfig(n_estimators=3),)
    frozen = select_classifier(train, val, configs=config)
    assert frozen.report.selected_candidate == "baseline"
    before = frozen.freeze_digest
    import soc_agent.security_ai.evaluation.experiments as module

    def forbidden(*args, **kwargs):
        pytest.fail("test evaluation performed fitting")

    monkeypatch.setattr(module, "fit_classifier", forbidden)
    result = evaluate_test(frozen, test)
    assert result.baseline == result.selected
    assert before == frozen.freeze_digest == result.selection_digest
    with pytest.raises(ValueError):
        evaluate_test(frozen, val)
    with pytest.raises(ValueError):
        evaluate_test(frozen, train.model_copy(update={"role": "test"}))


def test_train_only_scaler_and_deterministic_selection(development, monkeypatch):
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    train, val, _, _ = development
    captured = []
    fit = StandardScaler.fit
    forest_fit = IsolationForest.fit

    def capture(self, x, y=None, **kwargs):
        assert y is None
        captured.append(x.copy())
        return fit(self, x, y, **kwargs)

    def forest(self, x, y=None, **kwargs):
        assert y is None
        return forest_fit(self, x, y, **kwargs)

    monkeypatch.setattr(StandardScaler, "fit", capture)
    monkeypatch.setattr(IsolationForest, "fit", forest)
    configs = (AnomalyTrainingConfig(n_estimators=4),)
    first = select_anomaly(train, val, domain="network", configs=configs)
    second = select_anomaly(train, val, domain="network", configs=configs)
    assert first.report == second.report
    expected = np.asarray(
        [r.features.feature_values for r in train.rows if r.label == "BENIGN"], dtype=np.float32
    ).astype(float)
    np.testing.assert_array_equal(captured[0], expected)
    assert first.report.candidates[0].training_rows == 18
    with pytest.raises(ValueError, match="Duplicate effective"):
        select_anomaly(
            train,
            val,
            domain="network",
            configs=(
                AnomalyTrainingConfig(max_samples=256),
                AnomalyTrainingConfig(max_samples=128),
            ),
        )


def test_duplicate_input_audited_not_always_rejected(development):
    train, _, _, _ = development
    r = train.rows[0].model_copy(update={"row_id": "duplicate-row", "group_id": "other-group"})
    duplicate = Partition(
        role="train", rows=train.rows + (r,), dataset_name="fixture", dataset_version="1"
    )
    a = audit(duplicate, "BENIGN")
    assert a.duplicate_input_rows == 1 and a.duplicate_inputs_across_groups == 1


@pytest.mark.parametrize("identity", ["group", "fingerprint", "event", "source"])
def test_leakage_dimensions_blocked(development, identity):
    train, val, _, _ = development
    row = val.rows[0]
    if identity == "group":
        row = row.model_copy(update={"group_id": train.rows[0].group_id})
    elif identity == "fingerprint":
        row = row.model_copy(update={"features": train.rows[0].features})
    elif identity == "event":
        train = train.model_copy(
            update={
                "rows": (train.rows[0].model_copy(update={"event_ids": ("shared-event",)}),)
                + train.rows[1:]
            }
        )
        row = row.model_copy(update={"event_ids": ("shared-event",)})
    else:
        f = row.features.model_copy(update={"provenance": train.rows[0].features.provenance})
        row = row.model_copy(update={"features": f})
    with pytest.raises(ValueError, match="leakage"):
        require_disjoint(train, val.model_copy(update={"rows": (row,) + val.rows[1:]}))


def test_undefined_fpr_cannot_satisfy_constraint():
    table = threshold_trials((True, True), (0.1, 0.2), (0.1, 0.2))
    with pytest.raises(ValueError, match="FPR"):
        choose_threshold(table, objective="recall_at_fpr")


def test_calibration_separate_and_parameters_frozen(development):
    from dataclasses import FrozenInstanceError

    train, val, test, _ = development
    selection, cal = calibration_partition(val)
    frozen = select_classifier(
        train, selection, calibration=cal, configs=(TrainingConfig(n_estimators=3),)
    )
    report = frozen.report.calibration
    assert len(report.fitting_trials) == 6
    assert report.after.log_loss <= report.before.log_loss
    assert report.after.brier_score <= report.before.brier_score
    assert report.before.classification == report.after.classification
    with pytest.raises(FrozenInstanceError):
        frozen.temperature = 2
    with pytest.raises(ValueError):
        frozen.report.selected_candidate = "other"
    assert evaluate_test(frozen, test).selection_digest == frozen.freeze_digest


def test_small_calibration_fails_no_seed_search(development):
    _, val, _, _ = development
    too_small = val.model_copy(update={"rows": val.rows[:2]})
    with pytest.raises(ValueError, match="Insufficient"):
        calibration_partition(too_small)


def test_repeated_configuration_and_search_bound(development):
    train, val, _, _ = development
    with pytest.raises(ValueError):
        select_classifier(train, val, configs=(TrainingConfig(),) * 2)
    with pytest.raises(ValueError):
        select_anomaly(train, val, domain="network", configs=())


def test_nonfinite_and_missing_inputs_fail_before_training(development):
    from soc_agent.security_ai.features import FeatureSet

    train, _, _, _ = development
    values = train.rows[0].features.input_payload()
    for altered in (values | {"duration_us": float("nan")}, {}):
        data = train.rows[0].features.model_dump() | {"values": altered}
        with pytest.raises(ValueError):
            FeatureSet.model_validate(data)


def test_temperature_extremes_stay_finite():
    for t in (1e-320, 1e300):
        values = temperature_scale(np.array([[0.1, 0.9], [0.5, 0.5], [0.0, 1.0]]), t)
        assert np.isfinite(values).all()
        np.testing.assert_allclose(values.sum(axis=1), 1)


def test_frozen_bundle_rejects_configuration_substitution(development):
    from dataclasses import replace

    train, val, _, _ = development
    frozen = select_classifier(train, val, configs=(TrainingConfig(n_estimators=2),))
    with pytest.raises(ValueError, match="temperature"):
        replace(frozen, temperature=3.0)
    with pytest.raises(ValueError, match="operating point"):
        replace(frozen, point=OperatingPoint(threshold=0.5))

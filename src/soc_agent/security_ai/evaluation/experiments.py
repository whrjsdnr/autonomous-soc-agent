"""Bounded offline selection. Test partitions are accepted only after a frozen selection."""

import platform
from dataclasses import dataclass
from typing import Literal

import numpy as np
import sklearn
import xgboost
from pydantic import Field

from soc_agent._json import canonical_json_object
from soc_agent.security_ai.anomaly_common import AnomalyTrainingConfig
from soc_agent.security_ai.authentication.anomaly import AuthenticationAnomalyDetector
from soc_agent.security_ai.authentication.training import fit_authentication_anomaly
from soc_agent.security_ai.evaluation.data import (
    Partition,
    PartitionAudit,
    audit,
    checked,
    digest,
    require_disjoint,
)
from soc_agent.security_ai.evaluation.metrics import (
    BinaryMetrics,
    OperatingPoint,
    ProbabilityMetrics,
    ThresholdTrial,
    binary_metrics,
    choose_threshold,
    probability_matrix,
    probability_metrics,
    temperature_scale,
    threshold_trials,
)
from soc_agent.security_ai.features.models import Snapshot
from soc_agent.security_ai.network.anomaly import NetworkAnomalyDetector
from soc_agent.security_ai.network.anomaly_training import fit_network_anomaly
from soc_agent.security_ai.network.classifier import NetworkAttackClassifier
from soc_agent.security_ai.network.training import TrainingConfig, fit_classifier

Model = NetworkAttackClassifier | NetworkAnomalyDetector | AuthenticationAnomalyDetector


class ScoreDistribution(Snapshot):
    label: str
    count: int
    raw_min: float
    raw_max: float
    normalized_min: float
    normalized_max: float
    unique_raw_scores: int
    unique_normalized_scores: int
    baseline_positive_count: int
    saturated_count: int
    feature_means: tuple[tuple[str, float], ...]


def score_diagnostics(
    partition: Partition, raw: tuple[float, ...], norm: tuple[float, ...]
) -> tuple[ScoreDistribution, ...]:
    result = []
    for label in sorted({r.label for r in partition.rows}):
        ids = [i for i, r in enumerate(partition.rows) if r.label == label]
        a = [raw[i] for i in ids]
        b = [norm[i] for i in ids]
        matrix = np.asarray([partition.rows[i].features.feature_values for i in ids], dtype=float)
        result.append(
            ScoreDistribution(
                label=label,
                count=len(ids),
                raw_min=min(a),
                raw_max=max(a),
                normalized_min=min(b),
                normalized_max=max(b),
                unique_raw_scores=len(set(a)),
                unique_normalized_scores=len(set(b)),
                baseline_positive_count=sum(v >= 0.95 for v in b),
                saturated_count=sum(v in (0, 1) for v in b),
                feature_means=tuple(
                    zip(
                        partition.rows[0].features.feature_names,
                        map(float, matrix.mean(axis=0)),
                        strict=True,
                    )
                ),
            )
        )
    return tuple(result)


class ErrorSlice(Snapshot):
    outcome: str
    rows: int
    groups: int
    feature_means: tuple[tuple[str, float], ...]


def error_slices(
    partition: Partition, truth: tuple[bool, ...], decisions: tuple[bool, ...]
) -> tuple[ErrorSlice, ...]:
    result = []
    for outcome, actual, predicted in (
        ("TN", False, False),
        ("FP", False, True),
        ("FN", True, False),
        ("TP", True, True),
    ):
        ids = [
            i
            for i, (a, b) in enumerate(zip(truth, decisions, strict=True))
            if (a, b) == (actual, predicted)
        ]
        means = ()
        if ids:
            matrix = np.asarray(
                [partition.rows[i].features.feature_values for i in ids], dtype=float
            )
            means = tuple(
                zip(
                    partition.rows[0].features.feature_names,
                    map(float, matrix.mean(axis=0)),
                    strict=True,
                )
            )
        result.append(
            ErrorSlice(
                outcome=outcome,
                rows=len(ids),
                groups=len({partition.rows[i].group_id for i in ids}),
                feature_means=means,
            )
        )
    return tuple(result)


class CandidateResult(Snapshot):
    candidate_id: str
    configuration: str
    training_rows: int
    training_metrics: ProbabilityMetrics | None = None
    validation: BinaryMetrics | ProbabilityMetrics
    operating_point: OperatingPoint | None = None
    threshold_trials: tuple[ThresholdTrial, ...] = ()
    diagnostics: tuple[ScoreDistribution, ...] = ()
    selected: bool = False
    reason: str = ""


class TemperatureTrial(Snapshot):
    temperature: float
    log_loss: float
    brier_score: float


class CalibrationReport(Snapshot):
    method: Literal["none", "temperature_scaling"]
    temperature: float = Field(gt=0, allow_inf_nan=False)
    fitting_trials: tuple[TemperatureTrial, ...] = ()
    before: ProbabilityMetrics
    after: ProbabilityMetrics
    reason: str


class SelectionReport(Snapshot):
    model_name: str
    model_version: str = "1.1.0"
    objective: str
    seed: int
    audits: tuple[PartitionAudit, ...]
    candidates: tuple[CandidateResult, ...]
    selected_candidate: str
    calibration: CalibrationReport | None = None
    baseline_configuration: str
    selected_binding: str
    versions: tuple[tuple[str, str], ...] = (
        ("numpy", np.__version__),
        ("sklearn", sklearn.__version__),
        ("xgboost", xgboost.__version__),
        ("python", platform.python_version()),
    )


@dataclass(frozen=True)
class FrozenSelection:
    """Trusted in-memory bundle. Report is frozen before any test prediction."""

    report: SelectionReport
    baseline_model: Model
    selected_model: Model
    development: tuple[Partition, ...]
    normal_label: str
    point: OperatingPoint | None = None
    temperature: float = 1.0

    def __post_init__(self) -> None:
        if type(self.baseline_model) is not type(self.selected_model):
            raise ValueError("Baseline and selected model domains differ")
        selected = [c for c in self.report.candidates if c.selected]
        if len(selected) != 1 or selected[0].candidate_id != self.report.selected_candidate:
            raise ValueError("Frozen selection record is inconsistent")
        if selected[0].operating_point != self.point:
            raise ValueError("Frozen operating point differs from selection report")
        if isinstance(self.selected_model, NetworkAttackClassifier):
            if (
                self.report.calibration is None
                or self.report.calibration.temperature != self.temperature
            ):
                raise ValueError("Frozen temperature differs from selection report")
            expected = canonical_json_object(
                {
                    "contract": self.selected_model.contract.model_dump(mode="json"),
                    "configuration": TrainingConfig.model_validate_json(
                        selected[0].configuration
                    ).model_dump(),
                    "temperature": self.temperature,
                    "calibration_digest": self.development[2].content_digest
                    if len(self.development) == 3
                    else None,
                }
            )
        else:
            if self.point is None or self.temperature != 1.0:
                raise ValueError(
                    "Anomaly operating point required; probability calibration forbidden"
                )
            expected = canonical_json_object(
                {
                    "profile": self.selected_model.profile.model_dump(mode="json"),
                    "operating_point": self.point.model_dump(mode="json"),
                }
            )
        if expected != self.report.selected_binding:
            raise ValueError("Frozen model/configuration differs from selection report")

    @property
    def freeze_digest(self) -> str:
        return digest(self.report.model_dump(mode="json"))


class FinalTestReport(Snapshot):
    error_slices: tuple[ErrorSlice, ...] = ()
    selection_digest: str
    test_audit: PartitionAudit
    baseline: BinaryMetrics | ProbabilityMetrics
    selected: BinaryMetrics | ProbabilityMetrics
    diagnostics: tuple[ScoreDistribution, ...] = ()


def _predictions(model: NetworkAttackClassifier, partition: Partition) -> np.ndarray:
    return probability_matrix(
        tuple(model.predict(r.features) for r in partition.rows), model.contract.classes
    )


def _scores(
    model: NetworkAnomalyDetector | AuthenticationAnomalyDetector, partition: Partition
) -> tuple[tuple[float, ...], tuple[float, ...]]:
    predictions = tuple(model.predict(r.features) for r in partition.rows)
    return tuple(p.raw_anomaly_measure for p in predictions), tuple(
        p.anomaly_score for p in predictions
    )


def select_anomaly(
    train: Partition,
    validation: Partition,
    *,
    domain: Literal["network", "authentication"],
    configs: tuple[AnomalyTrainingConfig, ...] = (
        AnomalyTrainingConfig(),
        AnomalyTrainingConfig(n_estimators=128),
    ),
) -> FrozenSelection:
    train = checked(train, "train")
    validation = checked(validation, "selection")
    require_disjoint(train, validation)
    if domain not in {"network", "authentication"}:
        raise ValueError("Unknown anomaly domain")
    normal = "BENIGN" if domain == "network" else "normal"
    if any({r.label == normal for r in p.rows} != {False, True} for p in (train, validation)):
        raise ValueError("Both normal and anomaly labels required in development partitions")
    configs = tuple(AnomalyTrainingConfig.model_validate(c.model_dump()) for c in configs)
    if not 1 <= len(configs) <= 4 or any(
        c.seed != configs[0].seed or c.threshold != 0.95 for c in configs
    ):
        raise ValueError("Bounded candidates require shared seed and baseline threshold 0.95")
    features = tuple(r.features for r in train.rows if r.label == normal)
    # Ignore nominal max_samples differences that are identical on this population.
    keys = {(c.n_estimators, min(c.max_samples, len(features)), c.seed) for c in configs}
    if len(keys) != len(configs):
        raise ValueError("Duplicate effective model configurations")
    fitter = fit_network_anomaly if domain == "network" else fit_authentication_anomaly
    models = []
    trials = []
    truth = tuple(r.label != normal for r in validation.rows)
    for i, config in enumerate(configs):
        model = fitter(features, config=config, model_version="1.1.0")
        raw, norm = _scores(model, validation)
        table = threshold_trials(truth, raw, norm)
        if i == 0:
            trials.append(
                CandidateResult(
                    candidate_id="baseline",
                    configuration=config.model_dump_json(),
                    training_rows=len(features),
                    validation=table[0].metrics,
                    operating_point=table[0].point,
                    diagnostics=score_diagnostics(validation, raw, norm),
                )
            )
            models.append(model)
        chosen = table[choose_threshold(table)]
        trials.append(
            CandidateResult(
                candidate_id=f"model-{i}-threshold-selected",
                configuration=config.model_dump_json(),
                training_rows=len(features),
                validation=chosen.metrics,
                operating_point=chosen.point,
                threshold_trials=table,
                diagnostics=score_diagnostics(validation, raw, norm),
            )
        )
        models.append(model)
    # Strictly greater F1 only; baseline wins ties, then predefined candidate order.
    winner = max(range(len(trials)), key=lambda i: (trials[i].validation.f1, -i))
    trials = tuple(
        t.model_copy(
            update={
                "selected": i == winner,
                "reason": "selected by validation F1; baseline/earlier candidate wins ties"
                if i == winner
                else "no strict validation F1 advantage over selected candidate",
            }
        )
        for i, t in enumerate(trials)
    )
    selected = models[winner]
    report = SelectionReport(
        model_name=selected.profile.contract.model_name,
        objective="maximize validation F1; retain baseline on ties",
        seed=configs[0].seed,
        audits=(audit(train, normal), audit(validation, normal)),
        candidates=trials,
        selected_candidate=trials[winner].candidate_id,
        baseline_configuration=configs[0].model_dump_json(),
        selected_binding=canonical_json_object(
            {
                "profile": selected.profile.model_dump(mode="json"),
                "operating_point": trials[winner].operating_point.model_dump(mode="json"),
            }
        ),
    )
    return FrozenSelection(
        report=report,
        baseline_model=models[0],
        selected_model=selected,
        development=(train, validation),
        normal_label=normal,
        point=trials[winner].operating_point,
    )


def select_classifier(
    train: Partition,
    validation: Partition,
    *,
    calibration: Partition | None = None,
    configs: tuple[TrainingConfig, ...] = (
        TrainingConfig(),
        TrainingConfig(n_estimators=60, max_depth=2),
        TrainingConfig(learning_rate=0.05),
    ),
) -> FrozenSelection:
    train = checked(train, "train")
    validation = checked(validation, "selection")
    development = (
        (train, validation)
        if calibration is None
        else (train, validation, checked(calibration, "calibration"))
    )
    require_disjoint(*development)
    classes = tuple(sorted({r.label for r in train.rows}))
    if any({r.label for r in p.rows} != set(classes) for p in development):
        raise ValueError("All development partitions must contain every class")
    configs = tuple(TrainingConfig.model_validate(c.model_dump()) for c in configs)
    if (
        not 1 <= len(configs) <= 4
        or len({c.model_dump_json() for c in configs}) != len(configs)
        or any(c.seed != configs[0].seed for c in configs)
    ):
        raise ValueError("Bounded distinct configurations with shared seed required")
    labels = tuple(r.label for r in validation.rows)
    models = []
    trials = []
    for i, config in enumerate(configs):
        model = fit_classifier(
            tuple(r.features for r in train.rows),
            tuple(r.label for r in train.rows),
            config=config,
            model_version="1.1.0",
        )
        metrics = probability_metrics(labels, _predictions(model, validation), classes)
        trials.append(
            CandidateResult(
                candidate_id="baseline" if i == 0 else f"model-{i}",
                configuration=config.model_dump_json(),
                training_rows=len(train.rows),
                training_metrics=probability_metrics(
                    tuple(r.label for r in train.rows), _predictions(model, train), classes
                ),
                validation=metrics,
            )
        )
        models.append(model)
    winner = max(
        range(len(trials)), key=lambda i: (trials[i].validation.classification.macro_f1, -i)
    )
    trials = tuple(
        t.model_copy(
            update={
                "selected": i == winner,
                "reason": "selected by validation Macro F1; baseline/earlier candidate wins ties"
                if i == winner
                else "no strict validation Macro F1 advantage",
            }
        )
        for i, t in enumerate(trials)
    )
    model = models[winner]
    before = trials[winner].validation
    val_prob = _predictions(model, validation)
    temp = 1.0
    fitting = ()
    reason = "No independent calibration subset; calibration not fitted"
    if calibration is not None:
        calibration = development[2]
        cal_prob = _predictions(model, calibration)
        cal_labels = tuple(r.label for r in calibration.rows)
        fitting = tuple(
            TemperatureTrial(temperature=t, log_loss=m.log_loss, brier_score=m.brier_score)
            for t in (1.0, 0.5, 0.75, 1.5, 2.0, 3.0)
            for m in (probability_metrics(cal_labels, temperature_scale(cal_prob, t), classes),)
        )
        chosen = min(fitting, key=lambda x: x.log_loss)  # T=1 first, retained on ties.
        candidate = probability_metrics(
            labels, temperature_scale(val_prob, chosen.temperature), classes
        )
        if candidate.log_loss < before.log_loss and candidate.brier_score <= before.brier_score:
            temp = chosen.temperature
            reason = "Calibration-subset NLL minimum accepted on separate selection NLL/Brier"
        else:
            reason = "Calibration candidate rejected: no separate selection NLL/Brier improvement"
    after = probability_metrics(labels, temperature_scale(val_prob, temp), classes)
    cal_report = CalibrationReport(
        method="none" if temp == 1 else "temperature_scaling",
        temperature=temp,
        fitting_trials=fitting,
        before=before,
        after=after,
        reason=reason,
    )
    report = SelectionReport(
        model_name=model.contract.model_name,
        objective="maximize validation Macro F1; retain baseline on ties",
        seed=configs[0].seed,
        audits=tuple(audit(p, "BENIGN") for p in development),
        candidates=trials,
        selected_candidate=trials[winner].candidate_id,
        calibration=cal_report,
        baseline_configuration=configs[0].model_dump_json(),
        selected_binding=canonical_json_object(
            {
                "contract": model.contract.model_dump(mode="json"),
                "configuration": configs[winner].model_dump(),
                "temperature": temp,
                "calibration_digest": calibration.content_digest if calibration else None,
            }
        ),
    )
    return FrozenSelection(
        report=report,
        baseline_model=models[0],
        selected_model=model,
        development=development,
        normal_label="BENIGN",
        temperature=temp,
    )


def evaluate_test(selection: FrozenSelection, test: Partition) -> FinalTestReport:
    """Evaluate fixed baseline and selected models; never refit or reselect."""
    test = checked(test, "test")
    require_disjoint(*selection.development, test)
    if isinstance(selection.selected_model, NetworkAttackClassifier):
        classes = selection.selected_model.contract.classes
        labels = tuple(r.label for r in test.rows)
        baseline = probability_metrics(
            labels, _predictions(selection.baseline_model, test), classes
        )
        selected = probability_metrics(
            labels,
            temperature_scale(_predictions(selection.selected_model, test), selection.temperature),
            classes,
        )
        diagnostics = ()
        errors = ()
    else:
        truth = tuple(r.label != selection.normal_label for r in test.rows)
        raw, norm = _scores(selection.baseline_model, test)
        baseline = binary_metrics(truth, raw, OperatingPoint(threshold=0.95).decisions(raw, norm))
        raw, norm = _scores(selection.selected_model, test)
        selected = binary_metrics(truth, raw, selection.point.decisions(raw, norm))
        diagnostics = score_diagnostics(test, raw, norm)
        errors = error_slices(test, truth, selection.point.decisions(raw, norm))
    return FinalTestReport(
        error_slices=errors,
        selection_digest=selection.freeze_digest,
        test_audit=audit(test, selection.normal_label),
        baseline=baseline,
        selected=selected,
        diagnostics=diagnostics,
    )

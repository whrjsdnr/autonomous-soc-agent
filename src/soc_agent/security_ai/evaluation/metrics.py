"""Operating points, ranking metrics, and class-order-aware probability diagnostics."""

from typing import Literal

import numpy as np
from pydantic import Field
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

from soc_agent.security_ai.anomaly_common import Probability
from soc_agent.security_ai.features.models import Snapshot
from soc_agent.security_ai.network.classifier import ClassificationPrediction
from soc_agent.security_ai.network.training import ClassificationEvaluation, evaluate


class BinaryMetrics(Snapshot):
    precision: Probability
    recall: Probability
    f1: Probability
    fpr: Probability | None
    predicted_anomalies: int
    confusion_matrix: tuple[tuple[int, int], tuple[int, int]]
    roc_auc: Probability | None
    average_precision: Probability | None


def binary_metrics(
    truth: tuple[bool, ...], scores: tuple[float, ...], decisions: tuple[bool, ...]
) -> BinaryMetrics:
    if not truth or len(truth) != len(scores) or len(truth) != len(decisions):
        raise ValueError("Aligned nonempty evaluation required")
    if any(type(v) is not bool for v in truth + decisions) or not np.isfinite(scores).all():
        raise ValueError("Finite scores and explicit binary labels required")
    p, r, f, _ = precision_recall_fscore_support(
        truth, decisions, average="binary", zero_division=0
    )
    cm = confusion_matrix(truth, decisions, labels=[False, True])
    tn, fp, fn, tp = cm.ravel()
    both = len(set(truth)) == 2
    return BinaryMetrics(
        precision=float(p),
        recall=float(r),
        f1=float(f),
        fpr=float(fp / (tn + fp)) if tn + fp else None,
        predicted_anomalies=int(fp + tp),
        confusion_matrix=tuple(tuple(int(v) for v in row) for row in cm),
        roc_auc=float(roc_auc_score(truth, scores)) if both else None,
        average_precision=float(average_precision_score(truth, scores)) if both else None,
    )


class ReliabilityBin(Snapshot):
    lower: float
    upper: float
    count: int
    mean_confidence: float | None
    accuracy: float | None


class ProbabilityMetrics(Snapshot):
    classification: ClassificationEvaluation
    log_loss: float
    brier_score: float
    reliability: tuple[ReliabilityBin, ...]
    # Off-diagonal confusion counts are also preserved in classification.confusion_matrix.
    classes: tuple[str, ...]


def probability_matrix(
    predictions: tuple[ClassificationPrediction, ...], classes: tuple[str, ...]
) -> np.ndarray:
    if not predictions or len(classes) < 2 or len(set(classes)) != len(classes):
        raise ValueError("Nonempty predictions and unique class mapping required")
    checked = tuple(ClassificationPrediction.model_validate(p.model_dump()) for p in predictions)
    if any(tuple(p.label for p in row.class_probabilities) != classes for row in checked):
        raise ValueError("Probability column order differs from class mapping")
    return np.asarray(
        [[p.probability for p in row.class_probabilities] for row in checked], dtype=float
    )


def temperature_scale(probabilities: np.ndarray, temperature: float) -> np.ndarray:
    if not np.isfinite(temperature) or temperature <= 0:
        raise ValueError("Temperature must be positive and finite")
    values = np.asarray(probabilities, dtype=float)
    if (
        values.ndim != 2
        or values.shape[1] < 2
        or not len(values)
        or not np.isfinite(values).all()
        or (values < 0).any()
        or (values > 1).any()
        or not np.allclose(values.sum(axis=1), 1, atol=1e-5)
    ):
        raise ValueError("Invalid probability matrix")
    if temperature == 1:
        return values.copy()
    logits = np.log(np.clip(values, np.finfo(float).tiny, 1))
    # Subtract first: even subnormal positive temperatures keep at least one zero logit.
    logits -= logits.max(axis=1, keepdims=True)
    with np.errstate(over="ignore"):
        logits = logits / temperature
    exp = np.exp(logits)
    return exp / exp.sum(axis=1, keepdims=True)


def probability_metrics(
    labels: tuple[str, ...], probabilities: np.ndarray, classes: tuple[str, ...]
) -> ProbabilityMetrics:
    values = temperature_scale(probabilities, 1.0)
    if (
        len(values) != len(labels)
        or values.shape[1] != len(classes)
        or len(set(classes)) != len(classes)
        or not set(labels) <= set(classes)
    ):
        raise ValueError("Labels and probability mapping differ")
    y = np.asarray([classes.index(label) for label in labels])
    pred = values.argmax(axis=1)
    confidence = values.max(axis=1)
    nll = float(-np.log(np.clip(values[np.arange(len(y)), y], np.finfo(float).tiny, 1)).mean())
    onehot = np.eye(len(classes))[y]
    bins = []
    for i in range(10):
        mask = (confidence >= i / 10) & (
            (confidence < (i + 1) / 10) if i < 9 else (confidence <= 1)
        )
        bins.append(
            ReliabilityBin(
                lower=i / 10,
                upper=(i + 1) / 10,
                count=int(mask.sum()),
                mean_confidence=float(confidence[mask].mean()) if mask.any() else None,
                accuracy=float((pred[mask] == y[mask]).mean()) if mask.any() else None,
            )
        )
    return ProbabilityMetrics(
        classification=evaluate(y.tolist(), pred.tolist(), classes),
        log_loss=nll,
        brier_score=float(np.mean(np.sum((values - onehot) ** 2, axis=1))),
        reliability=tuple(bins),
        classes=classes,
    )


class OperatingPoint(Snapshot):
    space: Literal["normalized", "raw"] = "normalized"
    threshold: float = Field(allow_inf_nan=False)

    def decisions(self, raw: tuple[float, ...], normalized: tuple[float, ...]) -> tuple[bool, ...]:
        values = raw if self.space == "raw" else normalized
        return tuple(v >= self.threshold for v in values)


class ThresholdTrial(Snapshot):
    point: OperatingPoint
    metrics: BinaryMetrics


def threshold_trials(
    truth: tuple[bool, ...], raw: tuple[float, ...], normalized: tuple[float, ...]
) -> tuple[ThresholdTrial, ...]:
    if (
        len(normalized) != len(raw)
        or not np.isfinite(normalized).all()
        or any(not 0 <= v <= 1 for v in normalized)
    ):
        raise ValueError("Invalid normalized scores")
    # Fixed normalized grid; at most 64 validation-derived raw cutpoints + all-negative.
    values = sorted(set(raw))
    if not values or not np.isfinite(values).all():
        raise ValueError("Invalid raw scores")
    if len(values) > 64:
        values = [values[int(i)] for i in np.linspace(0, len(values) - 1, 64)]
    points = [OperatingPoint(threshold=t) for t in (0.95, 0.5, 0.75, 0.9)]
    points += [
        OperatingPoint(space="raw", threshold=t)
        for t in values + [float(np.nextafter(values[-1], np.inf))]
    ]
    return tuple(
        ThresholdTrial(point=p, metrics=binary_metrics(truth, raw, p.decisions(raw, normalized)))
        for p in points
    )


def choose_threshold(
    trials: tuple[ThresholdTrial, ...],
    *,
    objective: Literal["f1", "recall_at_fpr"] = "f1",
    fpr_limit: float = 0.1,
) -> int:
    if objective not in {"f1", "recall_at_fpr"} or not 0 <= fpr_limit <= 1:
        raise ValueError("Invalid selection objective")
    eligible = [
        i
        for i, t in enumerate(trials)
        if objective == "f1" or (t.metrics.fpr is not None and t.metrics.fpr <= fpr_limit)
    ]
    if not eligible:
        raise ValueError("No operating point satisfies FPR constraint")

    # First entry is baseline: retain it on objective ties. Then lower FPR, stable trial order.
    def key(i: int) -> tuple[float, int, float, int]:
        m = trials[i].metrics
        return (
            m.f1 if objective == "f1" else m.recall,
            int(i == 0),
            -(m.fpr if m.fpr is not None else 1),
            -i,
        )

    return max(eligible, key=key)

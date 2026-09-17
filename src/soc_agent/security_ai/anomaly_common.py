"""Shared frozen scaler, score reference and binary metrics; no domain decisions."""

import math
from bisect import bisect_left, bisect_right
from typing import Annotated, Literal, Self

import numpy as np
from pydantic import Field, model_validator
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

from soc_agent.security_ai.features.models import Snapshot

Finite = Annotated[float, Field(allow_inf_nan=False)]
Probability = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
Threshold = Annotated[float, Field(gt=0, le=1, allow_inf_nan=False)]


class AnomalyTrainingConfig(Snapshot):
    seed: int = Field(default=42, ge=0, le=2147483647, strict=True)
    n_estimators: int = Field(default=64, ge=1, le=1000, strict=True)
    max_samples: int = Field(default=256, ge=2, strict=True)
    contamination: Literal["auto"] = "auto"
    n_jobs: Literal[1] = 1
    threshold: Threshold = 0.95


class ScalerState(Snapshot):
    """StandardScaler(with_mean=True, with_std=True) training-only parameters."""

    mean: tuple[Finite, ...]
    scale: tuple[Annotated[float, Field(gt=0, allow_inf_nan=False)], ...]
    variance: tuple[Annotated[float, Field(ge=0, allow_inf_nan=False)], ...]
    samples: int = Field(ge=2, strict=True)

    @model_validator(mode="after")
    def validate_dimensions(self) -> Self:
        if not self.mean or not len(self.mean) == len(self.scale) == len(self.variance):
            raise ValueError("Invalid scaler dimensions")
        return self

    def transform(self, matrix: np.ndarray) -> np.ndarray:
        if matrix.ndim != 2 or matrix.shape[1] != len(self.mean):
            raise ValueError("Matrix and scaler dimensions differ")
        # Reproduce StandardScaler's two float64 operations without mutable runtime fitting.
        with np.errstate(over="ignore", invalid="ignore", divide="ignore"):
            scaled = (matrix.astype(np.float64) - np.asarray(self.mean)) / np.asarray(self.scale)
        if not np.isfinite(scaled).all() or (np.abs(scaled) > np.finfo(np.float32).max).any():
            raise ValueError("Scaled values cannot be represented as finite model inputs")
        return scaled


class AnomalyScoreReference(Snapshot):
    """Frozen distribution of -score_samples on the training benign population."""

    method: Literal["empirical_midrank:v1"] = "empirical_midrank:v1"
    sorted_measures: tuple[Finite, ...] = Field(min_length=2)
    threshold: Threshold
    sklearn_offset: Finite

    @model_validator(mode="after")
    def validate_order(self) -> Self:
        if self.sorted_measures != tuple(sorted(self.sorted_measures)):
            raise ValueError("Reference scores must be sorted")
        return self

    def normalize(self, raw_anomaly_measure: float) -> float:
        if not math.isfinite(raw_anomaly_measure):
            raise ValueError("Raw anomaly measure must be finite")
        low = bisect_left(self.sorted_measures, raw_anomaly_measure)
        high = bisect_right(self.sorted_measures, raw_anomaly_measure)
        return (low + high) / (2 * len(self.sorted_measures))


class AnomalyPrediction(Snapshot):
    is_anomaly: bool = Field(strict=True)
    raw_score: Finite
    raw_decision_score: Finite
    raw_anomaly_measure: Finite
    anomaly_score: Probability
    threshold: Threshold

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        if self.raw_anomaly_measure != -self.raw_score:
            raise ValueError("Anomaly measure must negate sklearn score_samples")
        if self.is_anomaly != (self.anomaly_score >= self.threshold):
            raise ValueError("Anomaly decision differs from fixed threshold")
        return self


class AnomalyEvaluation(Snapshot):
    precision: Probability
    recall: Probability
    f1: Probability
    confusion_matrix: tuple[tuple[int, int], tuple[int, int]]
    normal_support: int = Field(ge=0)
    anomaly_support: int = Field(ge=0)
    roc_auc: Probability | None
    average_precision: Probability | None


def evaluate_anomaly(
    truth: tuple[bool, ...], predictions: tuple[AnomalyPrediction, ...]
) -> AnomalyEvaluation:
    if not truth or len(truth) != len(predictions) or any(type(y) is not bool for y in truth):
        raise ValueError("Evaluation requires aligned nonempty binary labels and predictions")
    predictions = tuple(AnomalyPrediction.model_validate(p.model_dump()) for p in predictions)
    y = np.asarray(truth, dtype=int)
    decisions = [p.is_anomaly for p in predictions]
    # Raw measure retains ranking beyond the empirical percentile's saturated tails.
    scores = [p.raw_anomaly_measure for p in predictions]
    precision, recall, f1, _ = precision_recall_fscore_support(
        y, decisions, average="binary", zero_division=0
    )
    both_classes = len(set(truth)) == 2
    matrix = confusion_matrix(y, decisions, labels=[0, 1])
    return AnomalyEvaluation(
        precision=float(precision),
        recall=float(recall),
        f1=float(f1),
        confusion_matrix=tuple(tuple(int(v) for v in row) for row in matrix),
        normal_support=int(np.count_nonzero(y == 0)),
        anomaly_support=int(np.count_nonzero(y == 1)),
        roc_auc=float(roc_auc_score(y, scores)) if both_classes else None,
        average_precision=float(average_precision_score(y, scores)) if both_classes else None,
    )

"""Independent benign-baseline anomaly inference; no attack attribution or authority."""

import math
from bisect import bisect_left, bisect_right
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Annotated, Literal, Self

import numpy as np
from pydantic import Field, model_validator
from sklearn.ensemble import IsolationForest
from sklearn.utils.validation import check_is_fitted

from soc_agent.security_ai.features import FeatureSchema, FeatureSet
from soc_agent.security_ai.features.models import Snapshot, Version
from soc_agent.security_ai.network.preprocessing import feature_matrix
from soc_agent.security_ai.network.schema import network_feature_schema

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


class AnomalyModelContract(Snapshot):
    model_name: Literal["network_anomaly_iforest"] = "network_anomaly_iforest"
    model_version: Version = "1.0.0"
    feature_schema: FeatureSchema = Field(default_factory=network_feature_schema)
    extractor_name: Literal["network_flow"] = "network_flow"
    extractor_version: Literal["1.0.0"] = "1.0.0"
    preprocessing: Literal["ordered_float32;standard_scaler_float64:v1"] = (
        "ordered_float32;standard_scaler_float64:v1"
    )

    @model_validator(mode="after")
    def validate_schema(self) -> Self:
        if self.feature_schema != network_feature_schema():
            raise ValueError("Unsupported anomaly feature contract")
        return self


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


class AnomalyInferenceProfile(Snapshot):
    """One immutable schema/scaler/normalization/threshold binding."""

    contract: AnomalyModelContract
    config: AnomalyTrainingConfig
    scaler: ScalerState
    normalization: AnomalyScoreReference
    fitted_max_samples: int = Field(ge=2, strict=True)

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if len(self.scaler.mean) != len(self.contract.feature_schema.features):
            raise ValueError("Scaler and feature schema dimensions differ")
        if self.scaler.samples != len(self.normalization.sorted_measures):
            raise ValueError("Scaler and score reference populations differ")
        if self.config.threshold != self.normalization.threshold:
            raise ValueError("Configured and reference thresholds differ")
        if self.fitted_max_samples != min(self.config.max_samples, self.scaler.samples):
            raise ValueError("Fitted sample count differs from configuration")
        return self


class NetworkAnomalyPrediction(Snapshot):
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


@dataclass(frozen=True)
class NetworkAnomalyDetector:
    """Trusted in-memory fitted model; no persisted-object loader or batch recalibration.

    Profile and estimator are detached at construction. Private sklearn internals
    remain trusted Python, not a tamper-proof runtime or signed artifact.
    """

    profile: AnomalyInferenceProfile
    _model: IsolationForest = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        profile = AnomalyInferenceProfile.model_validate(self.profile.model_dump(warnings=False))
        if type(self._model) is not IsolationForest:
            raise TypeError("Expected a fitted IsolationForest")
        check_is_fitted(self._model)
        model = deepcopy(self._model)
        if (
            model.n_features_in_ != len(profile.scaler.mean)
            or model.offset_ != profile.normalization.sklearn_offset
        ):
            raise ValueError("Fitted model and inference profile differ")
        expected = profile.config
        if (
            model.n_estimators,
            model.random_state,
            model.contamination,
            model.n_jobs,
            model.max_samples_,
        ) != (
            expected.n_estimators,
            expected.seed,
            expected.contamination,
            expected.n_jobs,
            profile.fitted_max_samples,
        ):
            raise ValueError("Fitted model configuration differs")
        object.__setattr__(self, "profile", profile)
        object.__setattr__(self, "_model", model)

    def predict(self, features: FeatureSet) -> NetworkAnomalyPrediction:
        matrix = feature_matrix((features,), self.profile.contract)
        raw = float(self._model.score_samples(self.profile.scaler.transform(matrix))[0])
        reference = self.profile.normalization
        normalized = reference.normalize(-raw)
        return NetworkAnomalyPrediction(
            is_anomaly=normalized >= reference.threshold,
            raw_score=raw,
            raw_anomaly_measure=-raw,
            raw_decision_score=raw - reference.sklearn_offset,
            anomaly_score=normalized,
            threshold=reference.threshold,
        )

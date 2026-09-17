"""Independent benign-baseline anomaly inference; no attack attribution or authority."""

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Literal, Self

import numpy as np
from pydantic import Field, model_validator
from sklearn.ensemble import IsolationForest
from sklearn.utils.validation import check_is_fitted

from soc_agent.security_ai.anomaly_common import (
    AnomalyPrediction,
    AnomalyScoreReference,
    AnomalyTrainingConfig,
    ScalerState,
)
from soc_agent.security_ai.authentication.aggregation import (
    AuthenticationBehavior,
    authentication_feature_schema,
    validate_authentication_features,
)
from soc_agent.security_ai.features import FeatureSchema, FeatureSet
from soc_agent.security_ai.features.models import Snapshot, Version


def feature_matrix(features: tuple[FeatureSet, ...]) -> np.ndarray:
    if not features:
        raise ValueError("No authentication features supplied")
    rows = [validate_authentication_features(f).feature_values for f in features]
    if any(v < 0 or v > np.finfo(np.float32).max for row in rows for v in row):
        raise ValueError("Authentication features outside supported numeric range")
    matrix = np.asarray(rows, dtype=np.float32)
    if not np.isfinite(matrix).all():
        raise ValueError("Authentication features must be finite")
    return matrix


class AuthenticationAnomalyPrediction(AnomalyPrediction):
    feature_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    behavior: AuthenticationBehavior


class AuthenticationModelContract(Snapshot):
    model_name: Literal["authentication_anomaly_iforest"] = "authentication_anomaly_iforest"
    model_version: Version = "1.0.0"
    feature_schema: FeatureSchema = Field(default_factory=authentication_feature_schema)
    extractor_name: Literal["authentication_window"] = "authentication_window"
    extractor_version: Literal["1.0.0"] = "1.0.0"
    preprocessing: Literal["ordered_float32;standard_scaler_float64:v1"] = (
        "ordered_float32;standard_scaler_float64:v1"
    )

    @model_validator(mode="after")
    def validate_schema(self) -> Self:
        if self.feature_schema != authentication_feature_schema():
            raise ValueError("Unsupported anomaly feature contract")
        return self


class AuthenticationInferenceProfile(Snapshot):
    """One immutable schema/scaler/normalization/threshold binding."""

    contract: AuthenticationModelContract
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


@dataclass(frozen=True)
class AuthenticationAnomalyDetector:
    """Trusted in-memory fitted model; no persisted-object loader or batch recalibration.

    Profile and estimator are detached at construction. Private sklearn internals
    remain trusted Python, not a tamper-proof runtime or signed artifact.
    """

    profile: AuthenticationInferenceProfile
    _model: IsolationForest = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        profile = AuthenticationInferenceProfile.model_validate(
            self.profile.model_dump(warnings=False)
        )
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

    def predict(self, features: FeatureSet) -> AuthenticationAnomalyPrediction:
        features = validate_authentication_features(features)
        matrix = feature_matrix((features,))
        raw = float(self._model.score_samples(self.profile.scaler.transform(matrix))[0])
        reference = self.profile.normalization
        normalized = reference.normalize(-raw)
        return AuthenticationAnomalyPrediction(
            is_anomaly=normalized >= reference.threshold,
            raw_score=raw,
            raw_anomaly_measure=-raw,
            raw_decision_score=raw - reference.sklearn_offset,
            anomaly_score=normalized,
            threshold=reference.threshold,
            feature_fingerprint=features.input_fingerprint,
            behavior=AuthenticationBehavior.model_validate(features.input_payload()),
        )

"""Strict feature-bound native XGBoost inference; no SecurityAI registration."""

import math
from typing import Self

import numpy as np
import xgboost as xgb
from pydantic import Field, model_validator

from soc_agent._json import canonical_json_object
from soc_agent.security_ai.features import FeatureSchema, FeatureSet
from soc_agent.security_ai.features.models import Snapshot, Version
from soc_agent.security_ai.network.schema import network_feature_schema


class ClassProbability(Snapshot):
    label: str
    probability: float = Field(ge=0, le=1, allow_inf_nan=False)


class ClassificationPrediction(Snapshot):
    predicted_class: str
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    class_probabilities: tuple[ClassProbability, ...]

    @model_validator(mode="after")
    def validate_probabilities(self) -> Self:
        values = self.class_probabilities
        if not values or len({p.label for p in values}) != len(values):
            raise ValueError("Invalid probability labels")
        if not math.isclose(sum(p.probability for p in values), 1, abs_tol=1e-5):
            raise ValueError("Probabilities must sum to one")
        winner = max(values, key=lambda p: p.probability)
        if (self.predicted_class, self.confidence) != (winner.label, winner.probability):
            raise ValueError("Prediction differs from probability maximum")
        return self


class ModelContract(Snapshot):
    model_name: str = "network_attack_xgb"
    model_version: Version = "1.0.0"
    feature_schema: FeatureSchema = Field(default_factory=network_feature_schema)
    extractor_name: str = "network_flow"
    extractor_version: Version = "1.0.0"
    classes: tuple[str, ...] = Field(min_length=2)
    preprocessing: str = "reject_missing_nonfinite_negative;ordered_float32;no_imputation:v1"

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if self.classes != tuple(sorted(set(self.classes))) or not all(self.classes):
            raise ValueError("Classes must be unique, nonempty and sorted")
        if self.feature_schema != network_feature_schema() or (
            self.extractor_name,
            self.extractor_version,
            self.preprocessing,
            self.model_name,
        ) != (
            "network_flow",
            "1.0.0",
            "reject_missing_nonfinite_negative;ordered_float32;no_imputation:v1",
            "network_attack_xgb",
        ):
            raise ValueError("Unsupported classifier contract")
        return self


def feature_matrix(features: tuple[FeatureSet, ...], contract: ModelContract) -> np.ndarray:
    if not features:
        raise ValueError("No features supplied")
    rows = []
    for feature in features:
        feature = FeatureSet.model_validate(feature.model_dump(warnings=False))
        if feature.feature_schema != contract.feature_schema or (
            feature.provenance.extractor_name,
            feature.provenance.extractor_version,
        ) != (contract.extractor_name, contract.extractor_version):
            raise ValueError("Runtime feature schema or extractor differs from model contract")
        values = feature.feature_values
        if any(value is None or value < 0 or value > np.finfo(np.float32).max for value in values):
            raise ValueError("Features are outside the supported numeric range")
        if values[0] <= 0:
            raise ValueError("Flow duration must be positive")
        rows.append(values)
    matrix = np.asarray(rows, dtype=np.float32)
    if not np.isfinite(matrix).all() or (matrix[:, 0] <= 0).any():
        raise ValueError("Features are not representable as finite float32")
    return matrix


class NetworkAttackClassifier:
    def __init__(self, *, booster: xgb.Booster, contract: ModelContract) -> None:
        self.contract = ModelContract.model_validate(contract.model_dump())
        self._booster = booster
        if booster.num_features() != len(contract.feature_schema.features):
            raise ValueError("Model feature count differs from contract")
        expected = [feature.name for feature in contract.feature_schema.features]
        if booster.feature_names != expected:
            raise ValueError("Model feature order differs from contract")
        if booster.attr("feature_contract") != canonical_json_object(
            contract.model_dump(mode="json")
        ):
            raise ValueError("Model and declared contract differ")

    def predict(self, features: FeatureSet) -> ClassificationPrediction:
        matrix = feature_matrix((features,), self.contract)
        raw = self._booster.predict(
            xgb.DMatrix(
                matrix,
                feature_names=[f.name for f in self.contract.feature_schema.features],
                nthread=1,
            )
        )
        if raw.shape != (1, len(self.contract.classes)):
            raise ValueError("Model probability shape differs from classes")
        probabilities = tuple(
            ClassProbability(label=label, probability=float(value))
            for label, value in zip(self.contract.classes, raw[0], strict=True)
        )
        winner = max(probabilities, key=lambda item: item.probability)
        return ClassificationPrediction(
            predicted_class=winner.label,
            confidence=winner.probability,
            class_probabilities=probabilities,
        )

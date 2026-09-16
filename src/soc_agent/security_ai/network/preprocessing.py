"""Shared ordered matrix validation for independent network models."""

from typing import Protocol

import numpy as np

from soc_agent.security_ai.features import FeatureSchema, FeatureSet


class NetworkInputContract(Protocol):
    feature_schema: FeatureSchema
    extractor_name: str
    extractor_version: str


def feature_matrix(features: tuple[FeatureSet, ...], contract: NetworkInputContract) -> np.ndarray:
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

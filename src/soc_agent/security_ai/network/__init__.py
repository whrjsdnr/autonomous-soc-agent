"""Shared network contracts and anomaly inference; no import-time training or I/O."""

from soc_agent.security_ai.network.anomaly import (
    AnomalyTrainingConfig,
    NetworkAnomalyDetector,
    NetworkAnomalyPrediction,
)
from soc_agent.security_ai.network.dataset import (
    CICIDS2017Adapter,
    DatasetInspection,
    PreparedDataset,
)
from soc_agent.security_ai.network.schema import NetworkFeatureExtractor, network_feature_schema

__all__ = [
    "AnomalyTrainingConfig",
    "NetworkAnomalyDetector",
    "NetworkAnomalyPrediction",
    "CICIDS2017Adapter",
    "DatasetInspection",
    "PreparedDataset",
    "NetworkFeatureExtractor",
    "network_feature_schema",
]

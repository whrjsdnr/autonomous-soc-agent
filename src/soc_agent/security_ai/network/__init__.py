"""Public contracts on demand; Controller startup never imports ML training."""

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from soc_agent.security_ai.network.anomaly import AnomalyTrainingConfig as AnomalyTrainingConfig
    from soc_agent.security_ai.network.anomaly import (
        NetworkAnomalyDetector as NetworkAnomalyDetector,
    )
    from soc_agent.security_ai.network.anomaly import (
        NetworkAnomalyPrediction as NetworkAnomalyPrediction,
    )
    from soc_agent.security_ai.network.dataset import CICIDS2017Adapter as CICIDS2017Adapter
    from soc_agent.security_ai.network.dataset import DatasetInspection as DatasetInspection
    from soc_agent.security_ai.network.dataset import PreparedDataset as PreparedDataset
    from soc_agent.security_ai.network.schema import (
        NetworkFeatureExtractor as NetworkFeatureExtractor,
    )
    from soc_agent.security_ai.network.schema import (
        network_feature_schema as network_feature_schema,
    )

_EXPORTS = {
    "AnomalyTrainingConfig": ("soc_agent.security_ai.network.anomaly", "AnomalyTrainingConfig"),
    "NetworkAnomalyDetector": ("soc_agent.security_ai.network.anomaly", "NetworkAnomalyDetector"),
    "NetworkAnomalyPrediction": (
        "soc_agent.security_ai.network.anomaly",
        "NetworkAnomalyPrediction",
    ),
    "CICIDS2017Adapter": ("soc_agent.security_ai.network.dataset", "CICIDS2017Adapter"),
    "DatasetInspection": ("soc_agent.security_ai.network.dataset", "DatasetInspection"),
    "PreparedDataset": ("soc_agent.security_ai.network.dataset", "PreparedDataset"),
    "NetworkFeatureExtractor": ("soc_agent.security_ai.network.schema", "NetworkFeatureExtractor"),
    "network_feature_schema": ("soc_agent.security_ai.network.schema", "network_feature_schema"),
}

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


def __getattr__(name: str):
    if name not in _EXPORTS:
        raise AttributeError(name)
    module, attribute = _EXPORTS[name]
    value = getattr(import_module(module), attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_EXPORTS))

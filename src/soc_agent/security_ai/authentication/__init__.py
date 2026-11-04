"""Public contracts on demand; Controller startup never imports ML training."""

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from soc_agent.security_ai.anomaly_common import AnomalyTrainingConfig as AnomalyTrainingConfig
    from soc_agent.security_ai.authentication.aggregation import (
        AuthenticationEvent as AuthenticationEvent,
    )
    from soc_agent.security_ai.authentication.aggregation import (
        AuthenticationResult as AuthenticationResult,
    )
    from soc_agent.security_ai.authentication.aggregation import (
        AuthenticationWindow as AuthenticationWindow,
    )
    from soc_agent.security_ai.authentication.aggregation import (
        AuthenticationWindowExtractor as AuthenticationWindowExtractor,
    )
    from soc_agent.security_ai.authentication.aggregation import (
        authentication_feature_schema as authentication_feature_schema,
    )
    from soc_agent.security_ai.authentication.aggregation import (
        authentication_record as authentication_record,
    )
    from soc_agent.security_ai.authentication.anomaly import (
        AuthenticationAnomalyDetector as AuthenticationAnomalyDetector,
    )
    from soc_agent.security_ai.authentication.anomaly import (
        AuthenticationAnomalyPrediction as AuthenticationAnomalyPrediction,
    )
    from soc_agent.security_ai.authentication.training import (
        AuthenticationExample as AuthenticationExample,
    )
    from soc_agent.security_ai.authentication.training import (
        AuthenticationTrainingResult as AuthenticationTrainingResult,
    )
    from soc_agent.security_ai.authentication.training import (
        split_authentication as split_authentication,
    )
    from soc_agent.security_ai.authentication.training import (
        train_authentication as train_authentication,
    )

_EXPORTS = {
    "AnomalyTrainingConfig": ("soc_agent.security_ai.anomaly_common", "AnomalyTrainingConfig"),
    "AuthenticationEvent": (
        "soc_agent.security_ai.authentication.aggregation",
        "AuthenticationEvent",
    ),
    "AuthenticationResult": (
        "soc_agent.security_ai.authentication.aggregation",
        "AuthenticationResult",
    ),
    "AuthenticationWindow": (
        "soc_agent.security_ai.authentication.aggregation",
        "AuthenticationWindow",
    ),
    "AuthenticationWindowExtractor": (
        "soc_agent.security_ai.authentication.aggregation",
        "AuthenticationWindowExtractor",
    ),
    "authentication_feature_schema": (
        "soc_agent.security_ai.authentication.aggregation",
        "authentication_feature_schema",
    ),
    "authentication_record": (
        "soc_agent.security_ai.authentication.aggregation",
        "authentication_record",
    ),
    "AuthenticationAnomalyDetector": (
        "soc_agent.security_ai.authentication.anomaly",
        "AuthenticationAnomalyDetector",
    ),
    "AuthenticationAnomalyPrediction": (
        "soc_agent.security_ai.authentication.anomaly",
        "AuthenticationAnomalyPrediction",
    ),
    "AuthenticationExample": (
        "soc_agent.security_ai.authentication.training",
        "AuthenticationExample",
    ),
    "AuthenticationTrainingResult": (
        "soc_agent.security_ai.authentication.training",
        "AuthenticationTrainingResult",
    ),
    "split_authentication": (
        "soc_agent.security_ai.authentication.training",
        "split_authentication",
    ),
    "train_authentication": (
        "soc_agent.security_ai.authentication.training",
        "train_authentication",
    ),
}

__all__ = [
    "AnomalyTrainingConfig",
    "AuthenticationEvent",
    "AuthenticationResult",
    "AuthenticationWindow",
    "AuthenticationWindowExtractor",
    "authentication_feature_schema",
    "authentication_record",
    "AuthenticationAnomalyDetector",
    "AuthenticationAnomalyPrediction",
    "AuthenticationExample",
    "AuthenticationTrainingResult",
    "split_authentication",
    "train_authentication",
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

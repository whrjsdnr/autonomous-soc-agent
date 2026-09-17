"""Independent authentication behavior contracts and in-memory anomaly inference."""

from soc_agent.security_ai.anomaly_common import AnomalyTrainingConfig
from soc_agent.security_ai.authentication.aggregation import (
    AuthenticationEvent,
    AuthenticationResult,
    AuthenticationWindow,
    AuthenticationWindowExtractor,
    authentication_feature_schema,
    authentication_record,
)
from soc_agent.security_ai.authentication.anomaly import (
    AuthenticationAnomalyDetector,
    AuthenticationAnomalyPrediction,
)
from soc_agent.security_ai.authentication.training import (
    AuthenticationExample,
    AuthenticationTrainingResult,
    split_authentication,
    train_authentication,
)

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

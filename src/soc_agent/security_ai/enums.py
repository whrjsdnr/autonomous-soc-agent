"""Inference tasks and input domains, not permissions or response authority."""

from enum import StrEnum


class SecurityAITaskType(StrEnum):
    CLASSIFICATION = "classification"
    ANOMALY_DETECTION = "anomaly_detection"
    RISK_SCORING = "risk_scoring"


class SecurityAIInputType(StrEnum):
    NETWORK_FLOW = "network_flow"
    AUTHENTICATION_EVENT = "authentication_event"
    HOST_PROCESS = "host_process"
    GENERIC_FEATURE_VECTOR = "generic_feature_vector"

"""Offline evaluation and bounded validation-only selection; no deployment authority."""

from soc_agent.security_ai.evaluation.data import (
    EvaluationRow,
    Partition,
    audit,
    calibration_partition,
    partitions,
    require_disjoint,
)
from soc_agent.security_ai.evaluation.experiments import (
    FrozenSelection,
    evaluate_test,
    select_anomaly,
    select_classifier,
)

__all__ = [
    "EvaluationRow",
    "Partition",
    "audit",
    "calibration_partition",
    "partitions",
    "require_disjoint",
    "FrozenSelection",
    "evaluate_test",
    "select_anomaly",
    "select_classifier",
]

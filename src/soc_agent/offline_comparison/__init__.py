"""Offline-only unavailable evaluation records. No runtime integration."""

from soc_agent.offline_comparison.coverage_models import CoverageConfiguration, FrozenBaseline
from soc_agent.offline_comparison.models import (
    BUILDER_VERSION,
    COMPARATOR_VERSION,
    EVALUATOR_VERSION,
    EvaluationArtifacts,
    OfflineCandidateVariant,
    OfflineComparison,
    OfflineEvaluationResult,
)
from soc_agent.offline_comparison.schema import migrate_frozen_baselines, migrate_offline_comparison
from soc_agent.offline_comparison.service import OfflineEvaluationRunner
from soc_agent.offline_comparison.store import OfflineComparisonStore

__all__ = [
    "CoverageConfiguration",
    "FrozenBaseline",
    "migrate_frozen_baselines",
    "BUILDER_VERSION",
    "COMPARATOR_VERSION",
    "EVALUATOR_VERSION",
    "EvaluationArtifacts",
    "OfflineCandidateVariant",
    "OfflineComparison",
    "OfflineComparisonStore",
    "OfflineEvaluationResult",
    "OfflineEvaluationRunner",
    "migrate_offline_comparison",
]

"""Optional pure external Evidence validation; no model or runtime activation."""

from soc_agent.security_ai.external.adapters import ExternalEvidenceAdapter
from soc_agent.security_ai.external.models import (
    AdapterOutcome,
    ExternalModelResult,
    InferenceProvenance,
    SourceFeatureObservation,
    TrustedExternalModelBinding,
    ValidationReport,
)

__all__ = [
    "AdapterOutcome",
    "ExternalEvidenceAdapter",
    "ExternalModelResult",
    "InferenceProvenance",
    "SourceFeatureObservation",
    "TrustedExternalModelBinding",
    "ValidationReport",
]

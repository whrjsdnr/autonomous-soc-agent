"""Immutable analytical artifacts reusing the existing signal and feature contracts."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import Field

from soc_agent.security_ai.anomaly_common import AnomalyPrediction
from soc_agent.security_ai.evaluation.metrics import OperatingPoint
from soc_agent.security_ai.features import FeatureSet
from soc_agent.security_ai.features.models import FeatureExtractionProvenance, Snapshot
from soc_agent.security_ai.fusion.enums import AgreementState, ConfidenceState, CoverageState
from soc_agent.security_ai.network.classifier import ClassificationPrediction
from soc_agent.security_ai.packaging.package import Hash, Kind, PackageManifest, Profile
from soc_agent.security_ai.signals import AISignal
from soc_agent.state.evidence import UTCTimestamp


class FusionInput(Snapshot):
    signal: AISignal
    features: FeatureSet


class FusionModelBinding(Snapshot):
    """Trusted setup metadata only; never holds a model or invokes inference."""

    manifest_digest: Hash
    manifest: PackageManifest
    profile: Profile


class FusionContribution(Snapshot):
    contribution_id: Hash
    signal_ids: tuple[UUID, ...]
    model_reference: Hash
    model_kind: Kind
    decision: str
    scores: ClassificationPrediction | AnomalyPrediction
    score_semantics: Literal["class probabilities", "empirical anomaly rank; raw=-score_samples"]
    operating_point: OperatingPoint | Literal["argmax"]
    feature_fingerprint: Hash
    provenance: FeatureExtractionProvenance


class CorrelationGroup(Snapshot):
    group_id: Hash
    domain: Literal["network", "authentication"]
    contribution_ids: tuple[Hash, ...]
    basis: Literal[
        "same domain, fingerprint and exact logical sources/content/observation times"
    ] = "same domain, fingerprint and exact logical sources/content/observation times"
    agreement_state: AgreementState
    compatibility_rules: tuple[str, ...]
    network_relations: tuple[
        Literal["attack_and_anomaly", "benign_with_anomaly", "attack_without_anomaly", "no_alert"],
        ...,
    ] = ()


class FusionResult(Snapshot):
    """Model-derived analysis, NOT Evidence, Hypothesis or ThreatAssessment."""

    fusion_id: Hash
    incident_id: UUID
    fusion_version: Literal["1.0.0"] = "1.0.0"
    signals: tuple[AISignal, ...]
    contributions: tuple[FusionContribution, ...]
    model_references: tuple[FusionModelBinding, ...]
    correlation_groups: tuple[CorrelationGroup, ...]
    agreement_state: AgreementState
    confidence_state: ConfidenceState = ConfidenceState.UNKNOWN
    coverage_state: CoverageState
    expected_models: tuple[Kind, ...]
    missing_models: tuple[Kind, ...]
    coverage: tuple[CoverageEntry, ...]
    summary: FusionSummary
    limitations: tuple[str, ...] = (
        "Model-derived analysis, not observed evidence or a threat assessment.",
        "Agreement is not calibrated confidence; anomaly rank is not attack probability.",
        "No verified cross-domain identity mapping is available.",
        "Synthetic model selection and contract tests do not establish SOC efficacy.",
    )
    # Source-time watermark, not an execution clock. Empty inputs have no timestamp.
    created_at: UTCTimestamp | None
    compatibility_version: Literal["directional-compatibility:v1"] = "directional-compatibility:v1"

    @property
    def deduplicated_signals(self) -> tuple[AISignal, ...]:
        representatives = {c.signal_ids[0] for c in self.contributions}
        return tuple(s for s in self.signals if s.signal_id in representatives)

    @property
    def fusion_fingerprint(self) -> str:
        return self.fusion_id


class ModelAvailability(Snapshot):
    """Caller-reported absence/failure, never a substitute prediction."""

    model_kind: Kind
    status: Literal["not_run", "failed", "insufficient_input"]
    reason: str = Field(min_length=1, max_length=500)


class CoverageEntry(Snapshot):
    model_kind: Kind
    status: Literal["observed", "not_reported", "not_run", "failed", "insufficient_input"]
    reason: str | None = None


class FusionSummary(Snapshot):
    model_contribution_count: int = Field(ge=0)
    unique_source_record_count: int = Field(ge=0)
    input_group_count: int = Field(ge=0)
    domains_present: tuple[Literal["network", "authentication"], ...]
    cross_domain_state: Literal["not_applicable", "unverified"]


FusionResult.model_rebuild()

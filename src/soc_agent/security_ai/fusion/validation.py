"""Strict adapter payload parsing and trusted metadata binding; no model execution."""

from typing import Annotated, Literal

from pydantic import Field

from soc_agent._json import canonical_json_object
from soc_agent.security_ai.anomaly_common import AnomalyPrediction
from soc_agent.security_ai.authentication.anomaly import AuthenticationInferenceProfile
from soc_agent.security_ai.authentication.anomaly import feature_matrix as auth_matrix
from soc_agent.security_ai.enums import SecurityAITaskType
from soc_agent.security_ai.evaluation.data import digest
from soc_agent.security_ai.evaluation.metrics import OperatingPoint
from soc_agent.security_ai.features import FeatureSet
from soc_agent.security_ai.features.models import FeatureExtractionProvenance, Snapshot
from soc_agent.security_ai.fusion.compatibility import CLASS_DIRECTIONS
from soc_agent.security_ai.fusion.errors import FusionValidationError
from soc_agent.security_ai.fusion.models import FusionInput, FusionModelBinding
from soc_agent.security_ai.network.anomaly import AnomalyInferenceProfile
from soc_agent.security_ai.network.classifier import (
    ClassificationPrediction,
    ClassProbability,
    ModelContract,
)
from soc_agent.security_ai.network.preprocessing import feature_matrix
from soc_agent.security_ai.network.training import TrainingConfig
from soc_agent.security_ai.packaging.package import Hash, ModelPackage, make_manifest
from soc_agent.security_ai.signals import AISignal

Probability = Annotated[float, Field(strict=True, ge=0, le=1, allow_inf_nan=False)]


class _Explanation(Snapshot):
    feature_fingerprint: Hash
    feature_provenance: FeatureExtractionProvenance
    package_manifest_digest: Hash
    selection_digest: Hash
    synthetic_selection_not_operational_approval: Literal[True]


class _ClassifierExplanation(_Explanation):
    operating_point: Literal["argmax"]
    temperature: float = Field(strict=True, gt=0, allow_inf_nan=False)


class _AnomalyExplanation(_Explanation):
    operating_point: OperatingPoint
    operating_point_identity: Hash
    score_semantics: Literal["anomaly ranking; not attack probability"]


class _ClassifierScores(Snapshot):
    class_probabilities: dict[str, Probability]


class _AnomalyScores(Snapshot):
    raw_anomaly_measure: Probability
    normalized_anomaly_score: Probability
    normalized_threshold: float = Field(strict=True, gt=0, le=1, allow_inf_nan=False)
    normalized_decision: bool = Field(strict=True)
    selected_decision: bool = Field(strict=True)


def validate_binding(value: FusionModelBinding) -> FusionModelBinding:
    value = FusionModelBinding.model_validate(value.model_dump(warnings=False))
    manifest = value.manifest
    profile_type = {
        "network_classifier": ModelContract,
        "network_anomaly": AnomalyInferenceProfile,
        "authentication_anomaly": AuthenticationInferenceProfile,
    }[manifest.model_kind]
    profile = profile_type.model_validate(value.profile.model_dump())
    contract = profile if isinstance(profile, ModelContract) else profile.contract
    if (
        manifest.model_id,
        manifest.model_version,
        manifest.feature_schema_name,
        manifest.feature_schema_version,
        manifest.extractor_name,
        manifest.extractor_version,
        manifest.ordered_feature_names,
    ) != (
        contract.model_name,
        contract.model_version,
        contract.feature_schema.schema_name,
        contract.feature_schema.schema_version,
        contract.extractor_name,
        contract.extractor_version,
        tuple(f.name for f in contract.feature_schema.features),
    ):
        raise FusionValidationError("Manifest and feature contract differ")
    if len({f.path for f in manifest.file_hashes}) != 3:
        raise FusionValidationError("Duplicate manifest inventory")
    if isinstance(profile, ModelContract):
        TrainingConfig.model_validate_json(manifest.training_configuration)
        if profile.classes != tuple(name for name, _ in CLASS_DIRECTIONS):
            raise FusionValidationError("Unsupported classifier class mapping")
        if manifest.operating_point is not None:
            raise FusionValidationError("Classifier operating point must be argmax")
    else:
        if (
            manifest.training_configuration != profile.config.model_dump_json()
            or manifest.temperature != 1
        ):
            raise FusionValidationError("Anomaly configuration mismatch")
        point = manifest.operating_point
        if point is None or not 0 < point.threshold <= 1:
            raise FusionValidationError("Invalid anomaly operating threshold")
    return FusionModelBinding(
        manifest_digest=value.manifest_digest, manifest=manifest, profile=profile
    )


def binding_from_package(package: ModelPackage) -> FusionModelBinding:
    """Trusted setup projects a previously verified package into metadata only."""
    if (
        make_manifest(
            package.selection,
            package.profile,
            package.manifest.model_kind,
            package.manifest.file_hashes,
        )
        != package.manifest
    ):
        raise FusionValidationError("Package selection metadata mismatch")
    return validate_binding(
        FusionModelBinding(
            manifest_digest=package.manifest_digest,
            manifest=package.manifest,
            profile=package.profile,
        )
    )


def source_payload(provenance: FeatureExtractionProvenance) -> tuple[str, ...]:
    """Logical source identity ignores only freshly allocated extraction record UUIDs."""
    return tuple(
        sorted(
            canonical_json_object(s.model_dump(mode="json", exclude={"record_id"}))
            for s in provenance.sources
        )
    )


def validated_prediction(
    item: FusionInput, binding: FusionModelBinding
) -> ClassificationPrediction | AnomalyPrediction:
    features = item.features
    profile = binding.profile
    if isinstance(profile, AuthenticationInferenceProfile):
        auth_matrix((features,))
    else:
        feature_matrix(
            (features,), profile if isinstance(profile, ModelContract) else profile.contract
        )
    return validated_signal(item.signal, features.provenance, features.input_fingerprint, binding)


def validated_signal(
    signal: AISignal,
    provenance: FeatureExtractionProvenance,
    fingerprint: str,
    binding: FusionModelBinding,
) -> ClassificationPrediction | AnomalyPrediction:
    """Validate retained inference lineage; does not claim to revalidate absent feature values."""
    manifest, profile = binding.manifest, binding.profile
    classifier = isinstance(profile, ModelContract)
    task = SecurityAITaskType.CLASSIFICATION if classifier else SecurityAITaskType.ANOMALY_DETECTION
    if (signal.model_name, signal.model_version, signal.task_type) != (
        manifest.model_id,
        manifest.model_version,
        task,
    ):
        raise FusionValidationError("Signal model identity/task differs from package binding")
    if provenance.incident_id not in (None, signal.incident_id):
        raise FusionValidationError("Feature incident differs from signal")
    if signal.source_created_at > signal.created_at or any(
        s.observed_at > signal.source_created_at for s in provenance.sources
    ):
        raise FusionValidationError("Signal predates its source observations/result")
    if len(set(signal.source_evidence_ids)) != len(signal.source_evidence_ids) or not set(
        signal.source_evidence_ids
    ) <= set(provenance.source_evidence_ids):
        raise FusionValidationError("Signal evidence references differ from feature provenance")
    record_type = (
        "authentication_event"
        if manifest.model_kind == "authentication_anomaly"
        else "network_flow"
    )
    if any(
        s.record_type != record_type or s.record_schema_version != "1.0.0"
        for s in provenance.sources
    ):
        raise FusionValidationError("Source record contract mismatch")
    contract = profile if classifier else profile.contract
    if (provenance.extractor_name, provenance.extractor_version) != (
        contract.extractor_name,
        contract.extractor_version,
    ):
        raise FusionValidationError("Source extractor differs from package")
    explanation_type = _ClassifierExplanation if classifier else _AnomalyExplanation
    explanation = explanation_type.model_validate(signal.explanation_payload())
    if (
        explanation.package_manifest_digest != binding.manifest_digest
        or explanation.selection_digest != manifest.selection_digest
        or explanation.feature_fingerprint != fingerprint
        or explanation.feature_provenance != provenance
    ):
        raise FusionValidationError("Signal package, fingerprint or provenance mismatch")
    if classifier:
        scores = _ClassifierScores.model_validate(signal.scores_payload())
        if (
            set(scores.class_probabilities) != set(profile.classes)
            or explanation.temperature != manifest.temperature
        ):
            raise FusionValidationError("Classifier probability mapping/calibration mismatch")
        return ClassificationPrediction(
            predicted_class=signal.prediction,
            confidence=signal.confidence,
            class_probabilities=tuple(
                ClassProbability(label=label, probability=scores.class_probabilities[label])
                for label in profile.classes
            ),
        )
    scores = _AnomalyScores.model_validate(signal.scores_payload())
    point = manifest.operating_point
    reference = profile.normalization
    if explanation.operating_point != point or explanation.operating_point_identity != digest(
        {
            "model": manifest.model_id,
            "version": manifest.model_version,
            "selection": manifest.selection_digest,
            "operating_point": point.model_dump(mode="json"),
        }
    ):
        raise FusionValidationError("Anomaly operating point identity mismatch")
    if (
        signal.confidence is not None
        or scores.normalized_threshold != reference.threshold
        or scores.normalized_anomaly_score != reference.normalize(scores.raw_anomaly_measure)
    ):
        raise FusionValidationError("Anomaly rank/threshold semantics mismatch")
    selected = point.decisions((scores.raw_anomaly_measure,), (scores.normalized_anomaly_score,))[0]
    if scores.selected_decision != selected or signal.prediction != (
        "anomaly" if selected else "normal"
    ):
        raise FusionValidationError("Anomaly selected decision mismatch")
    return AnomalyPrediction(
        raw_score=-scores.raw_anomaly_measure,
        raw_anomaly_measure=scores.raw_anomaly_measure,
        raw_decision_score=-scores.raw_anomaly_measure - reference.sklearn_offset,
        anomaly_score=scores.normalized_anomaly_score,
        threshold=scores.normalized_threshold,
        is_anomaly=scores.normalized_decision,
    )


def checked_input(item: FusionInput) -> FusionInput:
    if type(item) is not FusionInput:
        raise FusionValidationError("FusionInput required")
    return FusionInput(
        signal=AISignal.model_validate(item.signal.model_dump(warnings=False)),
        features=FeatureSet.model_validate(item.features.model_dump(warnings=False)),
    )

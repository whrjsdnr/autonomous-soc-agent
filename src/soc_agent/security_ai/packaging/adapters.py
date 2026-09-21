"""Explicit FeatureSet adapters; results never create evidence or execution authority."""

from dataclasses import dataclass
from typing import ClassVar

from soc_agent.security_ai.base import SecurityAI
from soc_agent.security_ai.enums import SecurityAIInputType, SecurityAITaskType
from soc_agent.security_ai.evaluation.data import digest
from soc_agent.security_ai.features import FeatureSet
from soc_agent.security_ai.models import (
    SecurityAIModelMetadata,
    SecurityAIPrediction,
    SecurityAIRequest,
)
from soc_agent.security_ai.network.classifier import ClassificationPrediction
from soc_agent.security_ai.packaging.package import ModelPackage


@dataclass(frozen=True)
class _Adapter:
    package: ModelPackage
    kind: ClassVar[str]

    def __post_init__(self) -> None:
        if self.package.manifest.model_kind != self.kind:
            raise ValueError("Adapter and package model kind differ")

    async def __call__(self, request: SecurityAIRequest[FeatureSet]) -> SecurityAIPrediction:
        features = FeatureSet.model_validate(request.input.model_dump())
        if features.provenance.incident_id not in (None, request.incident_id):
            raise ValueError("Feature provenance belongs to another incident")
        record_type = (
            "authentication_event" if self.kind == "authentication_anomaly" else "network_flow"
        )
        if any(
            s.record_type != record_type or s.record_schema_version != "1.0.0"
            for s in features.provenance.sources
        ):
            raise ValueError("Feature source record contract differs from adapter")
        prediction = self.package.predict(features)
        manifest = self.package.manifest
        explanation = {
            "feature_fingerprint": features.input_fingerprint,
            "feature_provenance": features.provenance.model_dump(mode="json"),
            "package_manifest_digest": self.package.manifest_digest,
            "selection_digest": manifest.selection_digest,
            "synthetic_selection_not_operational_approval": True,
        }
        if isinstance(prediction, ClassificationPrediction):
            return SecurityAIPrediction(
                prediction=prediction.predicted_class,
                confidence=prediction.confidence,
                scores={
                    "class_probabilities": {
                        p.label: p.probability for p in prediction.class_probabilities
                    }
                },
                explanation=explanation
                | {"operating_point": "argmax", "temperature": manifest.temperature},
            )
        point = manifest.operating_point.model_dump(mode="json")
        identity = digest(
            {
                "model": manifest.model_id,
                "version": manifest.model_version,
                "selection": manifest.selection_digest,
                "operating_point": point,
            }
        )
        return SecurityAIPrediction(
            prediction="anomaly" if self.package.operating_decision(prediction) else "normal",
            confidence=None,
            scores={
                "raw_anomaly_measure": prediction.raw_anomaly_measure,
                "normalized_anomaly_score": prediction.anomaly_score,
                "normalized_threshold": prediction.threshold,
                "normalized_decision": prediction.is_anomaly,
                "selected_decision": self.package.operating_decision(prediction),
            },
            explanation=explanation
            | {
                "operating_point": point,
                "operating_point_identity": identity,
                "score_semantics": "anomaly ranking; not attack probability",
            },
        )

    def as_security_ai(self) -> SecurityAI[FeatureSet]:
        manifest = self.package.manifest
        return SecurityAI(
            metadata=SecurityAIModelMetadata(
                name=manifest.model_id,
                version=manifest.model_version,
                description="Packaged offline-selected model; inference only",
                task_type=(
                    SecurityAITaskType.CLASSIFICATION
                    if self.kind == "network_classifier"
                    else SecurityAITaskType.ANOMALY_DETECTION
                ),
                input_type=(
                    SecurityAIInputType.AUTHENTICATION_EVENT
                    if self.kind == "authentication_anomaly"
                    else SecurityAIInputType.NETWORK_FLOW
                ),
            ),
            input_model=FeatureSet,
            handler=self,
        )


class NetworkClassifierAdapter(_Adapter):
    kind = "network_classifier"


class NetworkAnomalyAdapter(_Adapter):
    kind = "network_anomaly"


class AuthenticationAnomalyAdapter(_Adapter):
    kind = "authentication_anomaly"

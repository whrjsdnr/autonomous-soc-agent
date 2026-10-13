"""Packaged inference routed by retained source domain; no fitting or authority."""

from collections.abc import Sequence

from soc_agent.ingestion import EventIngestor
from soc_agent.ingestion.authentication import authentication_records
from soc_agent.ingestion.network import network_record
from soc_agent.security_ai.authentication import AuthenticationWindowExtractor
from soc_agent.security_ai.fusion import (
    FusionInput,
    FusionResult,
    ModelAvailability,
    MultiModelFusionEngine,
    binding_from_package,
)
from soc_agent.security_ai.models import SecurityAIRequest
from soc_agent.security_ai.network.schema import NetworkFeatureExtractor
from soc_agent.security_ai.packaging import (
    AuthenticationAnomalyAdapter,
    ModelPackage,
    NetworkAnomalyAdapter,
    NetworkClassifierAdapter,
)
from soc_agent.security_ai.signals import create_ai_signal
from soc_agent.state import IncidentState

ADAPTERS = {
    "network_classifier": NetworkClassifierAdapter,
    "network_anomaly": NetworkAnomalyAdapter,
    "authentication_anomaly": AuthenticationAnomalyAdapter,
}


class PackagedAnalysis:
    """SOCRuntime's existing model_analysis callback determines inference timing."""

    def __init__(self, ingestion: EventIngestor, packages: Sequence[ModelPackage]):
        self.ingestion = ingestion
        self.packages = {p.manifest.model_kind: p for p in packages}
        if len(self.packages) != len(packages):
            raise ValueError("Duplicate configured model kind")
        self.models = {
            kind: ADAPTERS[kind](package).as_security_ai()
            for kind, package in self.packages.items()
        }
        self.fusion = MultiModelFusionEngine(
            tuple(binding_from_package(p) for p in self.packages.values()), tuple(ADAPTERS)
        )

    async def __call__(self, state: IncidentState) -> FusionResult:
        receipt = self.ingestion.load(state.incident_id)
        domain = receipt.event.event_type
        applicable = (
            ("authentication_anomaly",)
            if domain == "authentication"
            else ("network_classifier", "network_anomaly")
        )
        unavailable = tuple(
            ModelAvailability(
                model_kind=kind,
                status="insufficient_input" if kind not in applicable else "not_run",
                reason=(
                    "Event domain has no applicable source records; no cross-domain inference"
                    if kind not in applicable
                    else "No package explicitly configured; artifact not available"
                ),
            )
            for kind in ADAPTERS
            if kind not in applicable or kind not in self.models
        )
        features = ()
        if any(kind in self.models for kind in applicable):
            features = (
                tuple(
                    w.features
                    for w in AuthenticationWindowExtractor().extract(
                        authentication_records(receipt), state=state
                    )
                )
                if domain == "authentication"
                else (NetworkFeatureExtractor().extract(network_record(receipt), state=state),)
            )
        inputs = []
        for kind in applicable:
            if kind not in self.models:
                continue
            for feature in features:
                result = await self.models[kind].predict(
                    SecurityAIRequest(incident_id=state.incident_id, input=feature)
                )
                inputs.append(
                    FusionInput(signal=create_ai_signal(result, state=state), features=feature)
                )
        return self.fusion.fuse(
            incident_id=state.incident_id, inputs=tuple(inputs), unavailable=unavailable
        )

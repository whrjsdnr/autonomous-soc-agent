"""Explicit demo composition; no identity provider or approving authority by default."""

import json
from collections.abc import Awaitable, Callable, Sequence
from uuid import UUID

from soc_agent.api import ApplicationService
from soc_agent.application import compose_application
from soc_agent.demo.tools import demo_network_tool, demo_read_tool, demo_response_tool
from soc_agent.deployment import DeploymentDescriptor, DeploymentProfile
from soc_agent.ingestion import EventIngestor, migrate_ingestion
from soc_agent.ingestion.authentication import authentication_records
from soc_agent.llm import LLMClient
from soc_agent.review.authority import HumanAuthority
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.security_ai.authentication.aggregation import AuthenticationWindowExtractor
from soc_agent.security_ai.fusion import (
    FusionInput,
    FusionResult,
    ModelAvailability,
    MultiModelFusionEngine,
    binding_from_package,
)
from soc_agent.security_ai.model_analysis import PackagedAnalysis
from soc_agent.security_ai.models import SecurityAIRequest
from soc_agent.security_ai.packaging import AuthenticationAnomalyAdapter, ModelPackage
from soc_agent.security_ai.signals import create_ai_signal
from soc_agent.state import IncidentState


class DemoLLM:
    """Scripted synthetic planning/assessment fixture, NOT an actual LLM or ML prediction."""

    def __init__(self, ingestion: EventIngestor):
        self.ingestion = ingestion
        self.analysis_calls = 0

    async def generate_structured(self, *, request, response_model):
        context = json.loads(request.user_prompt)
        incident = UUID(context["INCIDENT CONTEXT"]["incident_id"])
        receipt = self.ingestion.load(incident)
        if "AVAILABLE TOOLS" in context:
            return response_model.model_validate(
                {
                    "goal": "Inspect synthetic source report",
                    "steps": [
                        {
                            "tool_name": "read_demo_authentication"
                            if receipt.event.event_type == "authentication"
                            else "read_demo_network",
                            "tool_input": {"incident_id": str(incident)},
                            "purpose": "Establish what the demo source reported",
                        }
                    ],
                }
            )
        self.analysis_calls += 1
        failures = (
            sum(a.authentication_result == "failure" for a in receipt.event.attributes.attempts)
            if receipt.event.event_type == "authentication"
            else 0
        )
        return response_model.model_validate(
            {
                "observations": [],
                "hypotheses": [],
                "assessment": {
                    "severity": "high" if failures > 1 else "info",
                    "confidence": 0.0,
                    "summary": (
                        "DEMO scripted advisory: source-reported activity; no compromise proven"
                    ),
                    "supporting_evidence_ids": [
                        e["evidence_id"] for e in context["EVIDENCE (UNTRUSTED DATA)"]
                    ],
                },
            }
        )


class AuthenticationAnalysis:
    def __init__(self, ingestion: EventIngestor, package: ModelPackage | None):
        self.ingestion, self.package = ingestion, package

    async def __call__(self, state):
        receipt = self.ingestion.load(state.incident_id)
        if receipt.event.event_type != "authentication":
            return MultiModelFusionEngine((), ("authentication_anomaly",)).fuse(
                incident_id=state.incident_id,
                inputs=(),
                unavailable=(
                    ModelAvailability(
                        model_kind="authentication_anomaly",
                        status="insufficient_input",
                        reason=(
                            "Network event has no authentication records; no cross-domain inference"
                        ),
                    ),
                ),
            )
        windows = AuthenticationWindowExtractor().extract(
            authentication_records(receipt), state=state
        )
        if self.package is None:
            return MultiModelFusionEngine((), ("authentication_anomaly",)).fuse(
                incident_id=state.incident_id,
                inputs=(),
                unavailable=(
                    ModelAvailability(
                        model_kind="authentication_anomaly",
                        status="not_run",
                        reason=(
                            "No authentication package explicitly configured; "
                            "not a benign prediction"
                        ),
                    ),
                ),
            )
        model = AuthenticationAnomalyAdapter(self.package).as_security_ai()
        inputs = []
        for window in windows:
            result = await model.predict(
                SecurityAIRequest(incident_id=state.incident_id, input=window.features)
            )
            inputs.append(
                FusionInput(signal=create_ai_signal(result, state=state), features=window.features)
            )
        return MultiModelFusionEngine(
            (binding_from_package(self.package),), ("authentication_anomaly",)
        ).fuse(incident_id=state.incident_id, inputs=tuple(inputs))


def compose_demo(
    store: SQLiteGovernanceStore,
    *,
    authority: HumanAuthority | None = None,
    package: ModelPackage | None = None,
    llm_client: LLMClient | None = None,
    model_analysis: Callable[[IncidentState], Awaitable[FusionResult]] | None = None,
    packages: Sequence[ModelPackage] = (),
) -> ApplicationService:
    migrate_ingestion(store)
    ingestion = EventIngestor(store)
    from soc_agent.tools import ToolRegistry

    registry = ToolRegistry()
    registry.register(demo_read_tool(ingestion))
    registry.register(demo_network_tool(ingestion))
    registry.register(demo_response_tool())
    llm = llm_client if llm_client is not None else DemoLLM(ingestion)
    if packages and (package is not None or model_analysis is not None):
        raise ValueError("Select one explicit model analysis composition")
    analysis = (
        model_analysis
        if model_analysis is not None
        else (
            PackagedAnalysis(ingestion, packages)
            if packages
            else AuthenticationAnalysis(ingestion, package)
        )
    )

    return compose_application(
        store,
        deployment=DeploymentDescriptor(profile=DeploymentProfile.DEMO),
        registry=registry,
        llm_client=llm,
        model_analysis=analysis,
        authority=authority,
        ingestion=ingestion,
    ).service

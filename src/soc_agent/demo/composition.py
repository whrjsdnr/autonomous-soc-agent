"""Explicit demo composition; no identity provider or approving authority by default."""

import json
from uuid import UUID

from soc_agent.api import ApplicationService
from soc_agent.approval import ApprovalManager
from soc_agent.assessment import ThreatAssessor
from soc_agent.demo.tools import demo_read_tool, demo_response_tool
from soc_agent.execution import GovernedExecutor
from soc_agent.execution.durable import DurableExecutor, ExecutionStore
from soc_agent.ingestion import EventIngestor, migrate_ingestion
from soc_agent.ingestion.authentication import authentication_records
from soc_agent.investigation import InvestigationOrchestrator
from soc_agent.investigation.runtime import SOCRuntime
from soc_agent.investigation.runtime.persistence import CheckpointStore
from soc_agent.planning import InvestigationPlanner
from soc_agent.policy import PolicyEngine
from soc_agent.response.advisory import PersistentPlanningSource, ResponsePlanner
from soc_agent.response.promotion import ExecutionBridge, PromotionService
from soc_agent.review.authority import HumanAuthority
from soc_agent.review.persistence import PersistentHumanReviewService, SQLiteGovernanceStore
from soc_agent.security_ai.authentication.aggregation import AuthenticationWindowExtractor
from soc_agent.security_ai.fusion import (
    FusionInput,
    ModelAvailability,
    MultiModelFusionEngine,
    binding_from_package,
)
from soc_agent.security_ai.models import SecurityAIRequest
from soc_agent.security_ai.packaging import AuthenticationAnomalyAdapter, ModelPackage
from soc_agent.security_ai.signals import create_ai_signal


class DemoLLM:
    """Scripted synthetic planning/assessment fixture, NOT an actual LLM or ML prediction."""

    def __init__(self, ingestion: EventIngestor):
        self.ingestion = ingestion
        self.analysis_calls = 0

    async def generate_structured(self, *, request, response_model):
        context = json.loads(request.user_prompt)
        incident = UUID(context["INCIDENT CONTEXT"]["incident_id"])
        if "AVAILABLE TOOLS" in context:
            return response_model.model_validate(
                {
                    "goal": "Inspect synthetic source report",
                    "steps": [
                        {
                            "tool_name": "read_demo_authentication",
                            "tool_input": {"incident_id": str(incident)},
                            "purpose": "Establish what the demo source reported",
                        }
                    ],
                }
            )
        self.analysis_calls += 1
        receipt = self.ingestion.load(incident)
        failures = sum(
            a.authentication_result == "failure" for a in receipt.event.attributes.attempts
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
) -> ApplicationService:
    migrate_ingestion(store)
    ingestion = EventIngestor(store)
    from soc_agent.tools import ToolRegistry

    registry = ToolRegistry()
    registry.register(demo_read_tool(ingestion))
    registry.register(demo_response_tool())
    policy, approvals = PolicyEngine(), ApprovalManager()
    promotions = PromotionService(
        store=store, registry=registry, policy=policy, authority=authority
    )
    bridge = ExecutionBridge(promotions=promotions, approvals=approvals, authority=authority)
    executor = DurableExecutor(store=ExecutionStore(store), registry=registry, policy=policy)
    llm = DemoLLM(ingestion)

    def runtime():
        return SOCRuntime(
            store=store,
            checkpoints=CheckpointStore(store),
            investigator=InvestigationOrchestrator(
                executor=GovernedExecutor(registry=registry, policy=policy, approvals=approvals)
            ),
            planner=InvestigationPlanner(llm_client=llm, registry=registry),
            assessor=ThreatAssessor(llm_client=llm),
            responses=ResponsePlanner(registry=registry, source=PersistentPlanningSource(store)),
            bridge=bridge,
            executor=executor,
            model_analysis=AuthenticationAnalysis(ingestion, package),
        )

    return ApplicationService(
        store=store,
        runtime_factory=runtime,
        reviews=PersistentHumanReviewService(store=store, authority=authority),
        promotions=promotions,
        bridge=bridge,
        execution=executor.store,
        authority=authority,
        ingestion=ingestion,
    )

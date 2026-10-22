"""Shared application wiring. Callers select deployment adapters, never new authority."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from soc_agent.api.service import ApplicationService
from soc_agent.api.startup import open_store
from soc_agent.application_contracts import DeploymentDescriptor
from soc_agent.approval import ApprovalManager
from soc_agent.assessment import ThreatAssessor
from soc_agent.evaluation import migrate_evaluations
from soc_agent.execution import GovernedExecutor
from soc_agent.execution.durable import DurableExecutor, ExecutionStore
from soc_agent.experience import migrate_experiences
from soc_agent.feedback import migrate_feedback
from soc_agent.improvement_candidates import migrate_candidates
from soc_agent.improvement_dataset import migrate_datasets
from soc_agent.improvement_promotion import migrate_improvement_promotion
from soc_agent.improvement_review import migrate_improvement_review
from soc_agent.ingestion import EventIngestor
from soc_agent.investigation import InvestigationOrchestrator
from soc_agent.investigation.runtime import SOCRuntime
from soc_agent.investigation.runtime.persistence import CheckpointStore
from soc_agent.llm import LLMClient
from soc_agent.offline_comparison import migrate_frozen_baselines, migrate_offline_comparison
from soc_agent.offline_evaluation import migrate_offline_evaluation
from soc_agent.planning import InvestigationPlanner
from soc_agent.policy import PolicyEngine
from soc_agent.response.advisory import PersistentPlanningSource, ResponsePlanner
from soc_agent.response.promotion import ExecutionBridge, PromotionService
from soc_agent.review.authority import HumanAuthority
from soc_agent.review.persistence import PersistentHumanReviewService, SQLiteGovernanceStore
from soc_agent.security_ai.fusion import FusionResult
from soc_agent.state import IncidentState
from soc_agent.tools import ToolRegistry

type ModelAnalysis = Callable[[IncidentState], Awaitable[FusionResult]]


def open_application_store(path: Path, *, create: bool = False) -> SQLiteGovernanceStore:
    """Same existing schema/migrations; the deployment supplies and owns the path."""
    store = open_store(path, create=create)
    for migration in (
        migrate_experiences,
        migrate_evaluations,
        migrate_feedback,
        migrate_datasets,
        migrate_candidates,
        migrate_offline_evaluation,
        migrate_offline_comparison,
        migrate_frozen_baselines,
        migrate_improvement_review,
        migrate_improvement_promotion,
    ):
        migration(store.database)
    return store


@dataclass(frozen=True)
class ApplicationComposition:
    """The deployment owns metadata; the core service receives no profile."""

    deployment: DeploymentDescriptor
    service: ApplicationService


def compose_application(
    store: SQLiteGovernanceStore,
    *,
    deployment: DeploymentDescriptor,
    registry: ToolRegistry,
    llm_client: LLMClient,
    ingestion: EventIngestor | None = None,
    model_analysis: ModelAnalysis | None = None,
    authority: HumanAuthority | None = None,
    external_artifacts: Path | None = None,
    external_interpreter: Path | None = None,
) -> ApplicationComposition:
    """Same wiring for every profile; initialized persistence and adapters are explicit.

    No filesystem path, source transport, GUI, provider settings, model discovery or
    profile-specific policy belongs here. Absent human authority remains deny-by-default.
    """
    descriptor = DeploymentDescriptor.model_validate(deployment.model_dump())
    configure = getattr(store, "configure_backend", None)
    external_boundary = configure(registry) if configure is not None else None
    if external_boundary is not None:
        from soc_agent.security_ai.external.runtime_integration import ContextLLMClient

        llm_client = ContextLLMClient(llm_client, external_boundary)
    policy, approvals = PolicyEngine(), ApprovalManager()
    if external_boundary is not None:
        approvals.execution_guard = external_boundary
    promotions = PromotionService(
        store=store, registry=registry, policy=policy, authority=authority
    )
    bridge = ExecutionBridge(promotions=promotions, approvals=approvals, authority=authority)
    executor = DurableExecutor(store=ExecutionStore(store), registry=registry, policy=policy)

    def runtime() -> SOCRuntime:
        external = None
        if external_boundary is not None:
            from soc_agent.security_ai.external.runtime_integration import RuntimeIntegration

            external = RuntimeIntegration(external_boundary)
        return SOCRuntime(
            store=store,
            checkpoints=CheckpointStore(store),
            investigator=InvestigationOrchestrator(
                executor=GovernedExecutor(registry=registry, policy=policy, approvals=approvals)
            ),
            planner=InvestigationPlanner(llm_client=llm_client, registry=registry),
            assessor=ThreatAssessor(llm_client=llm_client),
            responses=ResponsePlanner(registry=registry, source=PersistentPlanningSource(store)),
            bridge=bridge,
            executor=executor,
            model_analysis=model_analysis,
            external=external,
        )

    service = ApplicationService(
        store=store,
        runtime_factory=runtime,
        reviews=PersistentHumanReviewService(store=store, authority=authority),
        promotions=promotions,
        bridge=bridge,
        execution=executor.store,
        authority=authority,
        ingestion=ingestion,
    )
    if external_boundary is not None:
        from soc_agent.security_ai.external.runtime_integration import RuntimeIntegration

        # Existing authenticated read APIs must verify the same companion publication.
        service.checkpoints.external = RuntimeIntegration(external_boundary)
    if external_artifacts is not None:
        if external_boundary is None:
            raise ValueError("External inference requires explicit runtime persistence")
        from soc_agent.security_ai.external.service import ExternalSecurityAIService

        service.external_ai = ExternalSecurityAIService(
            external_boundary, artifacts=external_artifacts, interpreter=external_interpreter
        )
    return ApplicationComposition(deployment=descriptor, service=service)

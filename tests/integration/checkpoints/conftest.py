# Shared governance fixtures also allow migration preservation of all prior ledgers.
from soc_agent.approval import ApprovalManager
from soc_agent.execution import GovernedExecutor
from soc_agent.execution.durable import DurableExecutor, ExecutionStore
from soc_agent.investigation import InvestigationOrchestrator
from soc_agent.investigation.runtime import SOCRuntime
from soc_agent.investigation.runtime.persistence import CheckpointStore
from soc_agent.response.advisory import PersistentPlanningSource, ResponsePlanner
from soc_agent.response.promotion import ExecutionBridge, PromotionService
from soc_agent.review.persistence import SQLiteGovernanceStore
from tests.unit.confirmations.conftest import boundary as boundary
from tests.unit.durable_execution.conftest import durable as durable
from tests.unit.investigation_runtime.conftest import runtime_case as runtime_case
from tests.unit.persistence.conftest import prepared as prepared
from tests.unit.promotion.conftest import case as case
from tests.unit.promotion.conftest import planning as planning
from tests.unit.promotion.conftest import workflow as workflow


def restart(case):
    old = case.runtime
    store = SQLiteGovernanceStore(case.store.database.path)
    registry = case.executor.validation.registry
    case.approvals = ApprovalManager()
    case.promotion_service = PromotionService(
        store=store, registry=registry, policy=case.policy, authority=case.authority
    )
    case.bridge = ExecutionBridge(
        promotions=case.promotion_service, approvals=case.approvals, authority=case.authority
    )
    case.executor = DurableExecutor(
        store=ExecutionStore(store), registry=registry, policy=case.policy
    )
    case.runtime = SOCRuntime(
        store=store,
        investigator=InvestigationOrchestrator(
            executor=GovernedExecutor(
                registry=registry, policy=case.policy, approvals=case.approvals
            )
        ),
        planner=old._planner,
        assessor=old._assessor,
        responses=ResponsePlanner(registry=registry, source=PersistentPlanningSource(store)),
        bridge=case.bridge,
        executor=case.executor,
        checkpoints=CheckpointStore(store),
    )
    return old

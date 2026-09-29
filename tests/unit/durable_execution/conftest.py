import pytest
from tests.unit.persistence.conftest import prepared as prepared
from tests.unit.promotion.conftest import (
    approve,
    promoted,
)
from tests.unit.promotion.conftest import (
    case as case,
)
from tests.unit.promotion.conftest import (
    planning as planning,
)
from tests.unit.promotion.conftest import (
    workflow as workflow,
)

from soc_agent.execution.durable import DurableExecutor, ExecutionStore, migrate


@pytest.fixture
def durable(workflow):
    governance = workflow[0][3]
    migrate(governance.database)
    store = ExecutionStore(governance)
    value = promoted(workflow, "test_response")
    approval = approve(workflow, value)
    record = store.create(workflow[5], value, approval_id=approval.approval_id)
    executor = DurableExecutor(store=store, registry=workflow[0][5], policy=workflow[2])
    return store, record, executor, workflow

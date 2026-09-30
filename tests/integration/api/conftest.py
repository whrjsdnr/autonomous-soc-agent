import json
from types import SimpleNamespace

import pytest

from soc_agent.api import ApplicationService, SOCApplication
from soc_agent.investigation.runtime import SOCRuntime
from soc_agent.investigation.runtime.persistence import CheckpointStore
from soc_agent.review.authentication import HumanActionContext
from soc_agent.review.authority import HumanAction
from soc_agent.review.authorization import HumanRole
from soc_agent.review.persistence import PersistentHumanReviewService
from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer
from tests.unit.confirmations.conftest import authority_for
from tests.unit.identity.conftest import Boundary
from tests.unit.investigation_runtime.conftest import runtime_case as runtime_case


class TestAccess:
    def __init__(self):
        self.denied = False

    def require_access(self, principal, incident_id, operation):
        if self.denied:
            raise ValueError("test denial")


async def call(app, method, path, body=None, token=None):
    output = []

    async def receive():
        return {"type": "http.request", "body": json.dumps(body or {}).encode()}

    async def send(message):
        output.append(message)

    await app(
        {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [(b"authorization", f"Bearer {token}".encode())] if token else [],
        },
        receive,
        send,
    )
    return output[0]["status"], json.loads(output[1]["body"])


@pytest.fixture
def api_case(runtime_case):
    def build(**kwargs):
        c = runtime_case(durable_workflow=True, **kwargs)
        boundary = Boundary()
        authority = authority_for(boundary, SQLiteConfirmationConsumer(c.store.database))
        c.reviews = PersistentHumanReviewService(store=c.store, authority=authority)
        c.promotion_service._authority = authority
        c.bridge._authority = authority
        old = c.runtime

        def factory():
            return SOCRuntime(
                investigator=old._investigator,
                store=c.store,
                planner=old._planner,
                assessor=old._assessor,
                responses=old._responses,
                bridge=c.bridge,
                executor=c.executor,
                checkpoints=CheckpointStore(c.store),
                max_investigation_rounds=old._limit,
            )

        service = ApplicationService(
            store=c.store,
            runtime_factory=factory,
            reviews=c.reviews,
            promotions=c.promotion_service,
            bridge=c.bridge,
            execution=c.executor.store,
            authority=authority,
        )
        access = TestAccess()
        app = SOCApplication(
            lambda: service, provider=boundary.provider, provider_id="test-identity", access=access
        )
        context = HumanActionContext(
            incident_id=c.incident_id,
            action=HumanAction.RECORD_REVIEW,
            binding_digest="a" * 64,
            decision_id="b" * 64,
        )
        token = boundary.issue(context, (HumanRole.ADMIN,))
        return SimpleNamespace(
            c=c,
            service=service,
            app=app,
            b=boundary,
            token=token,
            access=access,
            base=f"/incidents/{c.incident_id}",
        )

    return build


async def step(a, **kwargs):
    saved = a.service.checkpoint(a.c.incident_id)
    return await call(
        a.app,
        "POST",
        a.base + "/workflow/step",
        {"run_id": str(saved.run_id), "expected_revision": saved.revision, **kwargs},
        a.token,
    )

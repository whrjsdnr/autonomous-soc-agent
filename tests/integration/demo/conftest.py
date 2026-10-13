import json
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from soc_agent.api import SOCApplication
from soc_agent.api.startup import open_store
from soc_agent.demo.composition import compose_demo
from soc_agent.review.authentication import HumanActionContext
from soc_agent.review.authority import HumanAction
from soc_agent.review.authorization import HumanRole
from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer
from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    validate_directory,
)
from tests.integration.api.conftest import TestAccess, call
from tests.unit.confirmations.conftest import authority_for
from tests.unit.identity.conftest import Boundary


@pytest.fixture
def live_runtime_directory(tmp_path):
    """Only Windows needs an explicit protected private child of pytest's temp path."""
    if os.name != "nt":
        return tmp_path
    from tests.windows_storage_support import acl_diagnostics

    directory = tmp_path / "SOC private runtime 한글 space"
    # Diagnostic output contains ACL metadata/aliases, never user SIDs or raw events.
    print(acl_diagnostics(tmp_path, target_alias="$PYTEST_TMP"))
    create_private_directory(directory, exist_ok=False)
    validate_directory(directory)  # Real native verification; no ACL repair or bypass.
    print(acl_diagnostics(directory, target_alias="$SOC_PRIVATE"))
    return directory


@pytest.fixture
def event():
    return json.loads(
        (Path(__file__).parents[3] / "examples/authentication/suspicious.json").read_text()
    )


@pytest.fixture
def demo(tmp_path):
    store = open_store(tmp_path / "demo.sqlite", create=True)
    b = Boundary()
    authority = authority_for(b, SQLiteConfirmationConsumer(store.database))
    service = compose_demo(store, authority=authority)
    token = b.issue(
        HumanActionContext(
            incident_id=UUID(int=1),
            action=HumanAction.RECORD_REVIEW,
            binding_digest="a" * 64,
            decision_id="b" * 64,
        ),
        (HumanRole.ADMIN,),
    )
    app = SOCApplication(
        lambda: service, provider=b.provider, provider_id="test-identity", access=TestAccess()
    )
    return SimpleNamespace(
        store=store, b=b, service=service, app=app, token=token, authority=authority
    )


async def ingest(d, event):
    status, result = await call(d.app, "POST", "/events", event, d.token)
    assert status == 200, result
    d.incident_id = UUID(result["incident_id"])
    d.base = f"/incidents/{d.incident_id}"
    return result


async def step(d, **kwargs):
    saved = d.service.checkpoint(d.incident_id)
    return await call(
        d.app,
        "POST",
        d.base + "/workflow/step",
        {
            "run_id": str(saved.run_id),
            "expected_revision": saved.revision,
            **kwargs,
        },
        d.token,
    )

"""Fixture auth, actual private audit and response reservation; no marker modification."""

import pytest
from tests.integration.restricted_response.test_executor import approved, endpoint

from soc_agent.linux_runtime.__main__ import status


@pytest.mark.asyncio
@pytest.mark.parametrize("recover", [False, True])
async def test_restricted_unknown_prevents_ready_without_replaying(tmp_path, monkeypatch, recover):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, finding, _, server):
        candidate = await approved(root, finding)
        executor = server.restricted
        record = next(
            r for r in executor.records() if r.candidate_id == candidate["record"]["candidate_id"]
        )
        before = (root / "test-resources/marker").read_bytes()
        with monitor.store.database.transaction() as c:
            executor._save(c, record.model_copy(update={"status": "STARTED"}))
        if recover:
            executor.recover()
        assert executor.records()[0].status == ("UNKNOWN" if recover else "STARTED")
        monitor.store.update(state="RUNNING", collector="RESUMED_EXACT", last_error=None)
        with monitor.store.database.transaction(write=False) as c:
            database_before = tuple(c.iterdump())
        view = status(root)
        assert view["readiness"] == "NOT_READY"
        assert view["health"] != "HEALTHY"
        with monitor.store.database.transaction(write=False) as c:
            assert tuple(c.iterdump()) == database_before
        assert (root / "test-resources/marker").read_bytes() == before


@pytest.mark.asyncio
async def test_restricted_conflict_prevents_ready(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, *_):
        monitor.store.event("RESTRICTED_RECOVERY_CONFLICT", {"code": "FIXTURE_CONFLICT"})
        monitor.store.update(state="RUNNING", collector="RESUMED_EXACT", last_error=None)
        view = status(root)
        assert view["restricted_response"]["state"] == "BLOCKED"
        assert view["readiness"] == "NOT_READY"

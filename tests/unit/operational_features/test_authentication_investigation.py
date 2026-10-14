"""Actual orchestration/tools/governance and SQLite, using explicit SSH text fixtures."""

import json
from uuid import UUID

import pytest
from tests.unit.operational_features.test_native_authentication import INCIDENT, row, setup

from soc_agent.approval import ApprovalManager
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.errors import ExecutionDeniedError
from soc_agent.investigation import InvestigationStepStatus
from soc_agent.policy import PolicyEngine
from soc_agent.security_ai.operational.authentication_investigation import (
    NAME,
    AuthenticationReadQuery,
    AuthenticationReadView,
    authentication_read_registry,
    investigate_authentication,
    read_authentication_view,
)
from soc_agent.security_ai.operational.native_authentication import project_journal
from soc_agent.tools import Tool, ToolExecutionError, ToolMetadata


def populate(p):
    for r in (row(), row(2, 30, "Failed password for fixture-user from 192.0.2.5 port 34567 ssh2")):
        p.queue.enqueue(project_journal(r))
        p.step()


@pytest.mark.asyncio
async def test_real_core_read_only_investigation_with_fixture_data(tmp_path):
    p = setup(tmp_path)
    populate(p)
    view = read_authentication_view(p)
    assert view.authentication_events_verified == 2
    w = view.authentication_window[0]
    assert (w.total, w.succeeded, w.failed) == (2, 1, 1)
    assert w.provenance_reference and view.source_reference
    result = await investigate_authentication(p)
    assert result.plan.steps[0].status == InvestigationStepStatus.COMPLETED
    assert len(result.incident_state.evidence) == 1
    payload = json.loads(result.incident_state.evidence[0].raw_data)
    output = AuthenticationReadView.model_validate(payload["output"])
    assert output.evidence_digest == view.evidence_digest
    assert output.inference_status == "NOT_INFERABLE" and output.action_policy == "WRITE_DENIED"
    assert "fixture-user" not in output.model_dump_json()
    assert "192.0.2.5" not in output.model_dump_json()
    assert "fixture-cursor" not in output.model_dump_json()


@pytest.mark.asyncio
async def test_empty_or_unsupported_read_does_not_fake_authentication(tmp_path):
    p = setup(tmp_path)
    p.queue.enqueue(project_journal(row(message="pam_unix(sudo:session): session opened")))
    p.step()
    view = read_authentication_view(p)
    assert view.authentication_events_unsupported == 1
    assert view.authentication_events_verified == 0
    assert not view.authentication_window
    assert (await investigate_authentication(p)).plan.steps[
        0
    ].status == InvestigationStepStatus.COMPLETED


@pytest.mark.asyncio
async def test_direct_read_tool_wrong_incident_and_digest_rejected(tmp_path):
    p = setup(tmp_path)
    populate(p)
    registry = authentication_read_registry(p)
    tool = registry.get(NAME)
    with pytest.raises(ExecutionDeniedError):
        await tool.execute({"incident_id": str(UUID(int=333))})
    with pytest.raises(ToolExecutionError):
        await tool.execute({"incident_id": str(INCIDENT), "expected_evidence_digest": "0" * 64})
    executor = GovernedExecutor(
        registry=registry, policy=PolicyEngine(), approvals=ApprovalManager()
    )
    with pytest.raises(ExecutionDeniedError):
        await executor.execute(
            ActionProposal(
                incident_id=UUID(int=333), tool_name=NAME, tool_input={"incident_id": str(INCIDENT)}
            )
        )


@pytest.mark.asyncio
async def test_write_alias_and_direct_call_denied_before_spy_even_with_approval(tmp_path):
    p = setup(tmp_path)
    registry = authentication_read_registry(p)
    calls = []

    async def write(value):
        calls.append(value)
        pytest.fail("WRITE SPY CALLED")

    tool = Tool(
        ToolMetadata(
            name="disable_account", description="spy", permission="system_write", risk_level="high"
        ),
        AuthenticationReadQuery,
        AuthenticationReadView,
        write,
    )
    with pytest.raises(ExecutionDeniedError):
        registry.register(tool)
    # Exercise real handler boundary directly with the scope guard.
    guarded = Tool(
        tool.metadata, tool.input_model, tool.output_model, tool.handler, registry.execution_guard
    )
    with pytest.raises(ExecutionDeniedError):
        await guarded.execute({"incident_id": str(INCIDENT)})
    approvals = ApprovalManager()
    action = ActionProposal(
        incident_id=INCIDENT, tool_name="disable_account", tool_input={"incident_id": str(INCIDENT)}
    )
    approval = approvals.create(
        incident_id=INCIDENT,
        metadata=tool.metadata,
        reason="fixture approval",
        action_id=action.action_id,
        action_input_json=action.tool_input,
    )
    approvals.approve(approval.approval_id, actor="fixture-operator")
    executor = GovernedExecutor(registry=registry, policy=PolicyEngine(), approvals=approvals)
    with pytest.raises(ExecutionDeniedError):
        await executor.execute(action, approval_id=approval.approval_id)
    with pytest.raises(ExecutionDeniedError):
        await executor.execute(
            ActionProposal(
                incident_id=INCIDENT,
                tool_name="read_authentication_context_alias",
                tool_input={"incident_id": str(INCIDENT)},
            )
        )
    assert calls == []


@pytest.mark.parametrize(
    "tamper", ["source", "window", "queue", "receipt", "missing_source", "missing_queue"]
)
def test_read_path_revalidates_persisted_chain(tmp_path, tamper):
    p = setup(tmp_path)
    populate(p)
    if tamper in ("source", "window", "missing_source"):
        with p.store.database.transaction() as c:
            if tamper == "source":
                c.execute("UPDATE operational_sources SET digest=?", ("0" * 64,))
            elif tamper == "window":
                c.execute("DELETE FROM operational_auth_windows")
            else:
                c.execute("DELETE FROM operational_auth_windows")
                c.execute("DELETE FROM operational_watermarks")
                c.execute("DELETE FROM operational_sources")
    else:
        with p.queue.database.transaction() as c:
            if tamper == "queue":
                c.execute("UPDATE realtime_events SET digest=?", ("0" * 64,))
            elif tamper == "missing_queue":
                c.execute("DELETE FROM realtime_cursors")
                c.execute("DELETE FROM realtime_events")
            else:
                c.execute("UPDATE realtime_events SET outcome=?", ('{"workflow":{}}',))
    with pytest.raises(ValueError):
        read_authentication_view(p)


def test_read_view_reopens_with_same_integrity_and_provenance(tmp_path):
    p = setup(tmp_path)
    populate(p)
    before = read_authentication_view(p)
    # Source IDs and saved provenance remain replayable after reopening real databases.
    from soc_agent.realtime.queue import EventQueue
    from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
    from soc_agent.security_ai.operational.source_store import OperationalSourceStore

    reopened = AuthenticationPipeline(
        EventQueue(p.queue.database.path),
        OperationalSourceStore(
            p.store.database.path, allowed_lateness_seconds=60, max_future_skew_seconds=5
        ),
        INCIDENT,
    )
    assert read_authentication_view(reopened) == before


def test_rehashed_native_receipt_source_link_still_rejected(tmp_path):
    from soc_agent.security_ai.external.models import content_digest_payload

    p = setup(tmp_path)
    populate(p)
    with p.queue.database.transaction() as c:
        r = c.execute("SELECT * FROM realtime_events LIMIT 1").fetchone()
        outcome = json.loads(r["outcome"])
        payload = outcome["workflow"]["receipt"]
        payload["authentication_source_digest"] = "0" * 64
        outcome["workflow"]["digest"] = content_digest_payload(payload)
        c.execute(
            "UPDATE realtime_events SET outcome=? WHERE event_id=?",
            (json.dumps(outcome), r["event_id"]),
        )
    with pytest.raises(ValueError, match="SOURCE_RECEIPT_LINK"):
        read_authentication_view(p)


def test_late_event_is_counted_separately_from_window_totals(tmp_path):
    p = setup(tmp_path)
    for n, t in enumerate((300, 240, 239), start=1):
        p.queue.enqueue(project_journal(row(n, t)))
        p.step()
    view = read_authentication_view(p)
    assert view.authentication_events_verified == 3
    assert view.authentication_events_late_quarantined == 1
    assert sum(w.total for w in view.authentication_window) == 2

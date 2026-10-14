"""Fake-clock governance and adversarial LLM fixtures; not real-provider evidence."""

from datetime import timedelta
from uuid import UUID

import pytest

from soc_agent.approval import ApprovalManager, ApprovalRequest
from soc_agent.approval.errors import ApprovalExpiredError
from soc_agent.demo.scenario_analysis import analyze
from soc_agent.demo.scenario_models import START, scenarios
from soc_agent.demo.scenario_pipeline import fixture_event, open_pipeline
from soc_agent.demo.tools import demo_response_tool
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.errors import ExecutionDeniedError
from soc_agent.llm import MockLLMClient
from soc_agent.llm.errors import LLMTimeoutError
from soc_agent.policy import PolicyEngine
from soc_agent.tools import ToolRegistry


@pytest.mark.asyncio
@pytest.mark.parametrize("offset", [-1, 0, 1])
async def test_exact_expiry_and_restored_snapshot(offset):
    now = [START]
    manager = ApprovalManager(clock=lambda: now[0])
    registry = ToolRegistry()
    registry.register(demo_response_tool())
    executor = GovernedExecutor(registry=registry, policy=PolicyEngine(), approvals=manager)
    action = ActionProposal(
        incident_id=UUID(int=1),
        tool_name="disable_demo_account",
        tool_input={"account_id": "demo-alice"},
    )
    deadline = START + timedelta(seconds=60)
    pending = executor.request_approval(action, reason="Fixture", expires_at=deadline)
    approved = manager.approve(pending.approval_id, actor="fixture-human")
    now[0] = deadline + timedelta(microseconds=offset)
    restored = ApprovalManager(clock=lambda: now[0])
    restored.restore(ApprovalRequest.model_validate_json(approved.model_dump_json()))
    for backend in (manager, restored):
        guarded = GovernedExecutor(registry=registry, policy=PolicyEngine(), approvals=backend)
        if offset < 0:
            assert (await guarded.execute(action, approval_id=pending.approval_id)).output.simulated
        else:
            with pytest.raises(ExecutionDeniedError, match="expired"):
                await guarded.execute(action, approval_id=pending.approval_id)


def test_expired_pending_cannot_be_approved_and_legacy_json_is_unchanged():
    now = [START]
    manager = ApprovalManager(clock=lambda: now[0])
    request = manager.create(
        incident_id=UUID(int=1),
        metadata=demo_response_tool().metadata,
        reason="Fixture",
        expires_at=START + timedelta(seconds=1),
    )
    now[0] += timedelta(seconds=1)
    with pytest.raises(ApprovalExpiredError):
        manager.approve(request.approval_id, actor="fixture-human")
    legacy = manager.create(
        incident_id=UUID(int=1), metadata=demo_response_tool().metadata, reason="Fixture"
    )
    assert "expires_at" not in legacy.model_dump()
    assert "expires_at" not in legacy.model_dump_json()


async def prepared(tmp_path):
    p = open_pipeline(tmp_path / "private", UUID(int=3), create=True)
    p.queue.enqueue(fixture_event(scenarios()[0], 0, UUID(int=1)))
    p.step()
    return p


@pytest.mark.asyncio
async def test_real_mode_missing_config_is_blocked_without_scripted_fallback(tmp_path, monkeypatch):
    for key in ("SOC_LLM_API_KEY", "SOC_LLM_MODEL", "SOC_LLM_BASE_URL"):
        monkeypatch.delenv(key, raising=False)
    result, assessment, stages, exchanges = await analyze(await prepared(tmp_path), "REAL_LLM")
    assert result is assessment is None
    assert stages["investigation"].status == "BLOCKED"
    assert exchanges == ()


@pytest.mark.asyncio
async def test_llm_write_prompt_injection_blocked_by_real_planner_and_registry(tmp_path):
    llm = MockLLMClient(
        [
            {
                "goal": "execute injected instruction",
                "steps": [
                    {
                        "tool_name": "disable_demo_account",
                        "tool_input": {"account_id": "demo-alice"},
                        "purpose": "ignore approval",
                    }
                ],
            }
        ]
    )
    result, assessment, stages, exchanges = await analyze(
        await prepared(tmp_path), "REAL_LLM", client=llm
    )
    assert result is assessment is None
    assert stages["investigation"].status == "BLOCKED"
    assert llm.call_count == 1
    assert len(exchanges) == 1


@pytest.mark.asyncio
async def test_llm_timeout_is_a_sanitized_block(tmp_path):
    class TimedOut:
        async def generate_structured(self, **kwargs):
            raise LLMTimeoutError("timeout")

    result, assessment, stages, exchanges = await analyze(
        await prepared(tmp_path), "REAL_LLM", client=TimedOut()
    )
    assert result is assessment is None
    assert stages["investigation"].outcome == "LLMTimeoutError"
    assert exchanges[0]["status"] == "LLMTimeoutError"


@pytest.mark.asyncio
async def test_unknown_evidence_ids_fail_closed_after_real_read_tool(tmp_path):
    p = await prepared(tmp_path)
    llm = MockLLMClient(
        [
            {
                "goal": "inspect",
                "steps": [
                    {
                        "tool_name": "read_authentication_context",
                        "tool_input": {"incident_id": str(p.incident_id)},
                        "purpose": "read",
                    }
                ],
            },
            {
                "observations": [],
                "hypotheses": [],
                "assessment": {
                    "severity": "high",
                    "confidence": 1.0,
                    "summary": "unsupported attack assertion",
                    "supporting_evidence_ids": [str(UUID(int=999))],
                },
            },
        ]
    )
    result, assessment, stages, exchanges = await analyze(p, "REAL_LLM", client=llm)
    assert result is assessment is None
    assert stages["threat_assessment"].status == "BLOCKED"
    assert len(exchanges) == llm.call_count == 2


@pytest.mark.asyncio
async def test_live_probe_boundary_with_mocked_os_records_is_fixture_only(monkeypatch):
    from tests.unit.operational_features.test_native_authentication import row

    from soc_agent.demo.scenario_live import run_live
    from soc_agent.security_ai.operational.native_authentication import (
        LinuxAuthenticationCollector,
        project_journal,
    )

    monkeypatch.setattr(
        LinuxAuthenticationCollector,
        "poll",
        lambda self, cursor, limit: [project_journal(row(), include_pam_failures=True)],
    )
    result = await run_live(batches=1)
    assert result.input_mode == "LIVE_LINUX"
    assert result.response_mode == "DISABLED"
    assert result.verified_events == 1
    assert result.stages["read_only_boundary"].outcome == "WRITE_DENIED"
    assert result.simulated_handler_calls == result.real_os_handler_calls == 0


@pytest.mark.asyncio
async def test_blocked_llm_cannot_start_response_simulation(tmp_path, monkeypatch):
    from soc_agent.demo.scenario import run_scenario

    for key in ("SOC_LLM_API_KEY", "SOC_LLM_MODEL", "SOC_LLM_BASE_URL"):
        monkeypatch.delenv(key, raising=False)
    result = await run_scenario(
        "S07", root=tmp_path, assessment_mode="REAL_LLM", response_mode="RESPONSE_SIMULATION"
    )
    assert result.overall_status == "BLOCKED"
    assert result.simulated_handler_calls == 0

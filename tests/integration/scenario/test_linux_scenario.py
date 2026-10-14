"""WSL/Linux fixture E2E, not native authentication or live LLM evidence."""

import json
import subprocess
import sys
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid5

import pytest
from tests.authentication_crash_harness import crash_case

from soc_agent.demo import scenario as runner
from soc_agent.demo.scenario_models import scenarios
from soc_agent.demo.scenario_pipeline import fixture_event, open_pipeline
from soc_agent.realtime.models import CommonEvent
from soc_agent.security_ai.operational.authentication_detection import DetectionConfig
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.security_ai.operational.native_authentication import (
    SCENARIO_IDENTITY,
    LinuxAuthenticationCollector,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("spec", scenarios(), ids=lambda s: s.scenario_id)
async def test_all_scenarios_use_real_pipeline_and_deterministic_outcomes(tmp_path, spec):
    results = [
        await runner.run_scenario(
            spec.scenario_id, root=tmp_path, response_mode="RESPONSE_SIMULATION"
        )
        for _ in range(2)
    ]
    for result in results:
        assert result.overall_status == "PASS"
        assert result.input_origin == "FIXTURE"
        assert result.real_os_handler_calls == 0
        assert result.verified_events == len(spec.messages)
        assert result.stages["read_only_boundary"].outcome == "WRITE_DENIED"
        assert result.stages["threat_assessment"].outcome == "SCRIPTED_ADVISORY_NO_LIVE_LLM"
        assert result.stages["restart"].status == "PASS"
        assert result.inference_status == "NOT_INFERABLE"
        assert result.simulated_handler_calls == (1 if spec.scenario_id == "S07" else 0)
        assert Path(result.audit_path).parent.parent == tmp_path
        incident = uuid5(NAMESPACE_URL, f"scenario:{spec.fixture_identity}:{result.replay_run_id}")
        assert runner.verify_audit(Path(result.audit_path).parent, incident) == result.audit_receipt
    assert results[0].stages == results[1].stages
    assert results[0].detections == results[1].detections
    assert results[0].fixture_identity == results[1].fixture_identity
    assert results[0].replay_run_id != results[1].replay_run_id


@pytest.mark.asyncio
async def test_response_is_disabled_by_default_and_never_collects_native(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Native collector was called by a fixture runner")

    monkeypatch.setattr(LinuxAuthenticationCollector, "poll", forbidden)
    result = await runner.run_scenario("S07", root=tmp_path)
    assert result.overall_status == "SKIPPED"
    assert result.simulated_handler_calls == 0
    assert result.stages["approval"].status == "SKIPPED"


@pytest.mark.parametrize(
    "change",
    [
        {"platform": "linux"},
        {"provenance": "native_read_only"},
        {"schema_version": "soc-common-event:v1"},
        {"collector_id": "journald-auth:v1"},
    ],
)
def test_fixture_cannot_be_relabelled_as_native(change):
    event = fixture_event(scenarios()[0], 0, UUID(int=1))
    assert event.platform == "validated_fixture"
    assert event.provenance == "explicit_log_fixture"
    with pytest.raises(ValueError):
        CommonEvent.model_validate(event.model_dump() | change)


def test_fixture_cannot_enter_native_bound_pipeline(tmp_path):
    event = fixture_event(scenarios()[0], 0, UUID(int=2))
    p = open_pipeline(tmp_path / "private", UUID(int=3), create=True)
    with pytest.raises(ValueError, match="BINDING_MISMATCH"):
        AuthenticationPipeline(p.queue, p.store, p.incident_id)
    p.queue.enqueue(event)
    assert p.step().provenance.sources[0].source.namespace.startswith("scenario:")


@pytest.mark.asyncio
async def test_custom_threshold_is_explicit_and_expected_mismatch_fails(tmp_path):
    result = await runner.run_scenario(
        "S03", root=tmp_path, config=DetectionConfig(repeated_failures=6)
    )
    assert result.overall_status == "FAIL"
    assert result.stages["detection"].status == "FAIL"


@pytest.mark.asyncio
async def test_s11_replay_has_no_duplicate_effect(tmp_path):
    result = await runner.run_scenario("S11", root=tmp_path)
    assert result.duplicate_events == 2
    assert result.verified_events == 2


@pytest.mark.asyncio
async def test_audit_tampering_rejected(tmp_path):
    spec = scenarios()[0]
    result = await runner.run_scenario("S01", root=tmp_path)
    incident = uuid5(NAMESPACE_URL, f"scenario:{spec.fixture_identity}:{result.replay_run_id}")
    directory = Path(result.audit_path).parent
    p = open_pipeline(directory, incident, create=False)
    with p.queue.database.transaction() as c:
        c.execute("UPDATE scenario_audit SET digest=?", ("0" * 64,))
    with pytest.raises(ValueError, match="AUDIT_INTEGRITY"):
        runner.verify_audit(directory, incident)


@pytest.mark.parametrize("point", ["CP-02", "CP-04", "CP-05", "CP-08", "CP-10"])
def test_scenario_crash_recovery_reuses_owned_child_harness(tmp_path, point):
    event = fixture_event(scenarios()[0], 0, UUID(int=5))
    result = crash_case(tmp_path / "private", event, point, identity=SCENARIO_IDENTITY)
    assert result["event_loss"] == result["duplicate_window_effect"] == 0
    assert result["status"] == "PASS"


def test_cli_list_and_live_mode_rejection():
    listing = subprocess.run(
        [sys.executable, "-m", "soc_agent.demo.scenario", "list"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert len(json.loads(listing.stdout)) == 12
    live = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_agent.demo.scenario",
            "run",
            "S01",
            "--input-mode",
            "LIVE_LINUX",
        ],
        capture_output=True,
        text=True,
    )
    assert live.returncode == 2
    assert "LIVE_LINUX requires" in live.stderr


@pytest.mark.asyncio
async def test_partial_simulator_failure_is_audited_and_not_pass(tmp_path, monkeypatch):
    from soc_agent.demo import scenario_response

    async def failed(value):
        raise ValueError("fixture-secret-must-not-appear")

    monkeypatch.setattr(scenario_response, "simulate_disable", failed)
    result = await runner.run_scenario("S07", root=tmp_path, response_mode="RESPONSE_SIMULATION")
    assert result.overall_status == "FAIL"
    assert result.stages["response_simulation"].status == "FAIL"
    assert result.simulated_handler_calls is None
    assert result.real_os_handler_calls == 0
    assert "fixture-secret" not in result.model_dump_json()
    incident = uuid5(
        NAMESPACE_URL, f"scenario:{scenarios()[6].fixture_identity}:{result.replay_run_id}"
    )
    assert runner.verify_audit(Path(result.audit_path).parent, incident) == result.audit_receipt


@pytest.mark.asyncio
async def test_audit_storage_failure_never_reports_success(tmp_path, monkeypatch):
    def failed(*args):
        raise ValueError("SCENARIO_AUDIT_STORAGE_FAILED")

    monkeypatch.setattr(runner, "verify_audit", failed)
    with pytest.raises(ValueError, match="AUDIT_STORAGE"):
        await runner.run_scenario("S07", root=tmp_path)


@pytest.mark.parametrize(
    "seconds,expected",
    [
        ((0, 0), ()),
        ((0, 1), ("FAILURE_THEN_SUCCESS",)),
        ((302, 0), ()),
        ((30, 0), ()),
    ],
)
def test_correlation_requires_time_order_and_excludes_late_events(
    tmp_path, monkeypatch, seconds, expected
):
    from soc_agent.demo import scenario_pipeline
    from soc_agent.demo.scenario_models import START
    from soc_agent.security_ai.operational.authentication_detection import detect

    original = scenario_pipeline.journal_fixture

    def timed(spec, index, run_id):
        payload = original(spec, index, run_id)
        payload["__REALTIME_TIMESTAMP"] = str(int((START.timestamp() + seconds[index]) * 1e6))
        return payload

    monkeypatch.setattr(scenario_pipeline, "journal_fixture", timed)
    spec = scenarios()[4]
    p = open_pipeline(tmp_path / "private", UUID(int=33), create=True)
    for index in range(2):
        p.queue.enqueue(fixture_event(spec, index, UUID(int=7)))
        p.step()
    assert detect(p, DetectionConfig()) == expected

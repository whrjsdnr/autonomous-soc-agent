import json
from pathlib import Path

import pytest
from tests.calibrated_capacity_support import simulate, trace

from soc_agent.security_ai.operational.network_capture import calibrated_helper, calibrated_session
from soc_agent.security_ai.operational.network_capture.calibrated_policy import CANDIDATES, policy
from soc_agent.security_ai.operational.network_capture.total_session import verify_bundle as legacy
from soc_agent.security_ai.research.models import digest


@pytest.mark.parametrize("name", CANDIDATES)
def test_exact_scope_rate_boundaries_and_fixed_total(name):
    p = policy(name)
    assert p.frame_budget == p.frames_per_second * 300 + p.burst_frames and p.seconds == 300
    assert p.interface == "lo" and p.transport_capacity == 512 and p.inference_capacity == 8
    assert p.helper_cpu_seconds == 35 and p.controller_cpu_seconds == 160
    for field, value in [
        ("burst_frames", 1024),
        ("inference_capacity", 9),
        ("seconds", 301),
        ("frames_per_second", 999),
        ("total_frames", 99999),
    ]:
        with pytest.raises(ValueError):
            type(p).model_validate({**p.model_dump(), field: value})
    for fps in (p.frames_per_second / 2, p.frames_per_second):
        r = simulate(name, [i / fps for i in range(int(fps * 5))], service_seconds=0.0003)
        assert r["failure"] is None
    above = simulate(
        name,
        [i / (p.frames_per_second * 2) for i in range(p.frames_per_second * 20)],
        service_seconds=0.0003,
    )
    assert above["failure"] == "STREAM_RATE_BUDGET_EXCEEDED"
    assert simulate(name, [0] * p.burst_frames, service_seconds=0.0003)["failure"] is None
    assert simulate(name, [0] * (p.burst_frames + 1), service_seconds=0.0003)["failure"] == (
        "STREAM_RATE_BUDGET_EXCEEDED"
    )


def test_same_trace_compares_candidates_and_backpressure_has_explicit_failure():
    rows = [simulate(n, trace(), service_seconds=0.0003) for n in CANDIDATES]
    assert [r["failure"] for r in rows] == [
        "STREAM_RATE_BUDGET_EXCEEDED",
        "STREAM_RATE_BUDGET_EXCEEDED",
        None,
    ]
    slow = simulate("performance-v2", trace(), service_seconds=0.003, paused_until=4)
    assert slow["failure"] == "HELPER_TRANSPORT_BACKPRESSURE"
    assert slow["peak_queue"] == 512 and not slow["model_eligible"]
    assert not slow["automatic_retry"]


def test_new_bundle_and_session_bind_explicit_approval_before_privileges(tmp_path, monkeypatch):
    old = legacy()
    session = calibrated_session.prepare(tmp_path / "session", policy("performance-v2"))
    assert legacy() == old
    assert calibrated_session.load(tmp_path / "session") == session
    command = calibrated_session.instructions(tmp_path / "session", session)
    assert command["approval_state"] == "APPROVAL_REQUIRED"
    assert command["bundle_digest"] == digest(calibrated_session.verify_bundle())
    monkeypatch.setattr(calibrated_helper, "check_privileges", lambda: pytest.fail("NO PRIVILEGE"))
    with pytest.raises(ValueError, match="APPROVAL_MISMATCH"):
        calibrated_helper.main(
            [
                "--directory",
                str(tmp_path / "session"),
                "--session-digest",
                digest(session.model_dump(mode="json")),
                "--approval-digest",
                "0" * 64,
            ]
        )
    original = json.loads((tmp_path / "session/session.json").read_text())
    original["policy"]["frames_per_second"] = 1024
    (tmp_path / "session/session.json").write_text(json.dumps(original))
    with pytest.raises(ValueError):
        calibrated_session.load(tmp_path / "session")


def test_resource_failure_and_helper_replay_are_denied(tmp_path, monkeypatch):
    from soc_agent.security_ai.operational.network_capture import calibrated_policy

    monkeypatch.setattr(
        calibrated_policy, "hardware", lambda: dict(affinity_cpus=1, available_memory_bytes=1024**3)
    )
    with pytest.raises(ValueError, match="RESOURCE_HEADROOM_REQUIRED"):
        calibrated_session.prepare(tmp_path / "denied", policy("performance-v2"))
    monkeypatch.setattr(
        calibrated_policy,
        "hardware",
        lambda: dict(affinity_cpus=4, available_memory_bytes=8 * 1024**3),
    )
    session = calibrated_session.prepare(tmp_path / "session", policy("performance-v2"))
    (tmp_path / "session/rejected-closed.json").write_text("{}")
    monkeypatch.setattr(calibrated_helper, "check_privileges", lambda: pytest.fail("NO PRIVILEGE"))
    with pytest.raises(ValueError, match="REPLAY_DENIED"):
        calibrated_helper.main(
            [
                "--directory",
                str(tmp_path / "session"),
                "--session-digest",
                digest(session.model_dump(mode="json")),
                "--approval-digest",
                calibrated_session.approval_digest(session),
            ]
        )


def test_legacy_approval_does_not_satisfy_new_scope(tmp_path):
    session = calibrated_session.prepare(tmp_path / "session", policy("performance-v2"))
    assert calibrated_session.approval_digest(session) != digest(session.model_dump(mode="json"))
    assert session.code_sha256["calibrated_helper.py"] != session.code_sha256["total_helper.py"]
    assert (tmp_path / "session").stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "session/session.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("name", CANDIDATES)
def test_helper_entry_reuses_engine_only_after_exact_approval(tmp_path, monkeypatch, name):
    session = calibrated_session.prepare(tmp_path / "session", policy(name))
    calls = []
    monkeypatch.setattr(
        calibrated_helper, "check_privileges", lambda: calls.append("MOCK_PRIVILEGE_CHECK")
    )
    monkeypatch.setattr(calibrated_helper, "run", lambda *a, **kw: calls.append((a, kw)))
    calibrated_helper.main(
        [
            "--directory",
            str(tmp_path / "session"),
            "--session-digest",
            digest(session.model_dump(mode="json")),
            "--approval-digest",
            calibrated_session.approval_digest(session),
        ]
    )
    assert calls[0] == "MOCK_PRIVILEGE_CHECK"
    assert calls[1][1] == dict(session_loader=calibrated_session.load, dns_metadata=True)


def test_cli_candidate_needs_new_sha_and_yes_before_mock_auth(monkeypatch, tmp_path):
    import soc_agent.gui.__main__ as gui
    from soc_agent import cli

    calls = []
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(cli.ResearchAdapter, "status", lambda _: dict(status="READY"))
    monkeypatch.setattr(cli, "terminal_authenticate", lambda: calls.append("AUTH_MOCK"))
    monkeypatch.setattr(gui, "main", lambda args: calls.append(args) or 0)
    args = [
        "start",
        "--gui",
        "--monitor",
        "total",
        "--rate-policy",
        "performance-v2",
        "--data-directory",
        str(tmp_path),
    ]
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    assert cli.main(args) == 1 and not calls
    sha = calibrated_session.verify_bundle()["calibrated_helper.py"]
    monkeypatch.setattr("builtins.input", lambda _: "no")
    assert cli.main(args + ["--approve-calibrated-sha", sha]) == 1 and not calls
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    assert cli.main(args + ["--approve-calibrated-sha", sha]) == 0
    assert calls[0] == "AUTH_MOCK" and "--calibrated-approved-bundle" in calls[1]
    assert "performance-v2" in calls[1]


@pytest.fixture(autouse=True)
def controlled_fixture_headroom(monkeypatch):
    # Policy behavior test only: not a Native resource-readiness assertion.
    monkeypatch.setattr(
        "soc_agent.security_ai.operational.network_capture.calibrated_policy.hardware",
        lambda: dict(affinity_cpus=4, available_memory_bytes=8 * 1024**3),
    )


def test_expanded_reference_budget_is_bounded_and_quarantined_never_promotes(tmp_path):
    import os
    import time
    from types import SimpleNamespace
    from uuid import UUID

    from tests.streaming_network_support import packet

    from soc_agent.security_ai.operational.network_capture.isolated_flow import IsolatedFlows

    limit = policy("performance-v2").frame_budget
    assert IsolatedFlows().packet_limit == 38656  # Legacy default unchanged.
    with pytest.raises(ValueError):
        IsolatedFlows(packets=38657)
    flows = IsolatedFlows(packets=limit, extended_reference_budget=True)
    owner = SimpleNamespace(session=SimpleNamespace(interface_id="a" * 64))
    flows.add(packet(owner, 1), UUID(int=1))
    flows.add(packet(owner, 0), UUID(int=2))
    value = packet(owner, 2)
    before = int(Path("/proc/self/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    started = time.monotonic()
    for i in range(3, limit + 1):
        assert flows.add(value, UUID(int=i)) == []
    assert len(flows.seen) == limit and flows.bytes == 0
    assert flows.snapshot()["quarantined_flow_keys"] == 1
    with pytest.raises(ValueError, match="PACKET_REFERENCE_LIMIT"):
        flows.add(value, UUID(int=limit + 1))
    after = int(Path("/proc/self/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    assert after - before < 64 * 1024**2
    if os.getenv("SOC_REFERENCE_PROFILE"):
        Path(os.environ["SOC_REFERENCE_PROFILE"]).write_text(
            json.dumps(
                dict(
                    scope="QUARANTINED_SYNTHETIC_METADATA_REFERENCE_BOUND_NO_CAPTURE",
                    maximum_references=limit,
                    rss_growth_bytes=after - before,
                    elapsed_seconds=time.monotonic() - started,
                    unbounded_eviction=False,
                ),
                indent=2,
            )
        )

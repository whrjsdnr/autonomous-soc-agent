"""Phase D preparation and fixed IPC only; no auth, capture or capability changes."""

import copy
import hashlib
import json
from types import SimpleNamespace

import pytest
from tests.unit.ebpf_tc.test_supervisor import Operations, inventory, request

from soc_agent.security_ai.ebpf import eligibility
from soc_agent.security_ai.ebpf_tc import phase_d
from soc_agent.security_ai.ebpf_tc import supervisor_engine as engine
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.research.models import digest


@pytest.fixture(scope="module")
def candidate(tmp_path_factory):
    directory = tmp_path_factory.mktemp("phase-d") / "candidate"
    identity = phase_d.prepare(directory)
    return directory, identity


@pytest.mark.parametrize("failed", [False, True])
def test_native_cli_exit_status_reflects_result_without_native_execution(monkeypatch, failed):
    import sys

    from soc_agent.security_ai import native_campaign

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "phase_d",
            "candidate",
            "--execute",
            "--manifest",
            "m",
            "--image",
            "i",
            "--campaign",
            "campaign",
            "--approval-file",
            "approval",
            "--approval-sha",
            "a",
        ],
    )
    monkeypatch.setattr(
        native_campaign,
        "execute_phase_d",
        lambda *args, **kwargs: dict(
            last_error="HANDOFF_COMMAND_FAILED" if failed else None,
            cleanup_status="CLEANUP_UNVERIFIED" if failed else "PROCESS_AND_AUDIT_VERIFIED",
        ),
    )
    if failed:
        with pytest.raises(SystemExit) as caught:
            phase_d.main()
        assert caught.value.code == 1
    else:
        assert phase_d.main() is None


def test_combined_release_source_and_component_identity(candidate):
    directory, identity = candidate
    value = phase_d.validate(directory, identity["manifest"], identity["image"])
    assert (
        value["tcx_program"] == "9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06"
    )
    assert value["dns_baseline_image"] == phase_d.DNS_BASELINE_IMAGE
    assert value["scope"]["queue"] == 32
    source = (directory / "supervisor-image.py").read_text()
    compile(source, "<phase-d-fixture>", "exec")  # Never execute privileged source.
    assert "start_dns_worker" in source and "start_receive" in source
    assert "soc_agent.security_ai.ebpf_tc.supervisor" in value["sources"]
    assert "soc_agent.security_ai.ebpf_tc.gui" in value["sources"]
    assert value["native_ai"] == value["dns9"] == "BLOCKED"


@pytest.mark.parametrize("mutation", ["scope", "source", "dns_scope"])
def test_scope_or_source_failure_stops_before_authentication(candidate, monkeypatch, mutation):
    directory, identity = candidate
    path = directory / "phase-d.json"
    dns_path = directory / "dns-sidecar/release.json"
    original, dns_original = path.read_bytes(), dns_path.read_bytes()
    value = json.loads(original)
    monkeypatch.setattr(phase_d.supervisor_startup, "execute", lambda *a, **k: pytest.fail("auth"))
    try:
        if mutation == "scope":
            value["scope"]["queue"] = 33
        elif mutation == "source":
            value["sources"]["soc_agent.security_ai.ebpf_tc.supervisor"] = "0" * 64
        else:
            dns = json.loads(dns_original)
            dns["scope"]["target"] = "8.8.8.8:53"
            dns_path.write_bytes(canonical(dns))
            value["dns_manifest"] = hashlib.sha256(canonical(dns)).hexdigest()
        path.write_bytes(canonical(value))
        changed = hashlib.sha256(canonical(value)).hexdigest()
        with pytest.raises(ValueError, match="PHASE_D_"):
            phase_d.execute(directory, changed, identity["image"])
    finally:
        path.write_bytes(original)
        dns_path.write_bytes(dns_original)


def test_single_use_dns_command_uses_same_session_and_no_second_authentication():
    ops = Operations()
    ops.start_dns = lambda: 123
    core = engine.SupervisorCore(ops, "b" * 64, inventory())
    response, fd = core.dispatch(request("START_DNS"))
    assert fd == 123 and not response["error"]
    with pytest.raises(ValueError, match="REQUEST_REJECTED"):
        core.dispatch(dict(request("START_DNS", 2), binding="c" * 64))
    with pytest.raises(ValueError, match="REQUEST_REJECTED"):
        core.dispatch(request("START_DNS", 2, {"command": "shell"}))
    response, fd = core.dispatch(request("START_DNS", 2))
    assert fd is None and response["error"] == "DNS_SUPERVISOR_NO_RESTART"
    assert core.finish()["cleanup"] == "VERIFIED"
    assert ops.calls[-2:] == ["inspect", "close"]


def test_partial_dns_failure_still_closes_other_collector_and_preserves_both_errors(monkeypatch):
    calls = []

    def fail_dns():
        calls.append("dns")
        raise OSError(5, "DNS_CLOSE_FIXTURE")

    def fail_zeek():
        calls.append("zeek")
        raise ValueError("ZEEK_CLOSE_FIXTURE")

    monkeypatch.setattr(engine, "DockerAPI", lambda *a: None)
    ops = engine.RootOperations({}, "net:[4026531833]", "s", None, SimpleNamespace(close=fail_dns))
    ops._stop_zeek = fail_zeek
    with pytest.raises(ValueError, match="DNS_CLOSE.*ZEEK_CLOSE"):
        ops.stop()
    assert calls == ["dns", "zeek"]
    assert [r["stage"] for r in ops.collector_cleanup_errors] == ["DNS_CLOSE", "ZEEK_CLOSE"]
    assert ops.collector_cleanup_errors[0]["errno"] == 5


def candidate_summary(close="INCOMPLETE"):
    values = [0.0] * 14
    return dict(
        feature_tail=[
            dict(
                flow_id="retained-flow",
                close_reason=close,
                flow_completeness="INCOMPLETE",
                packet_count=16,
                feature_names=[v[0] for v in eligibility.NETWORK14],
                values=values,
                values_digest=digest(values),
            )
        ],
        finalized_count=1,
        cpu_sequence=dict(unrepresented_attempts=3),
        clock=dict(calibration="DECLARED_ONLY"),
        ordering=dict(inversions=0, late_events=0),
        queue_discarded=89,
        last_error="TCX_DATA_SOCKET_DELIVERY_LOSS",
    )


def test_rca_distinguishes_ring_loss_attempt_gaps_delivery_and_incomplete_flow():
    summary = candidate_summary()
    transport = dict(
        counter_evidence=dict(
            retrieval="SUCCESS",
            delivered=181,
            totals=dict(emitted=385, ring_reservation_failures=0),
        )
    )
    result = eligibility.candidate_rca(summary, transport)[0]
    assert result["values_digest_valid"] and result["network14_float32_contract"]
    assert result["ring_reservation_failures"] == 0 and not result["eligible"]
    assert "RING_RESERVATION_LOSS" not in result["reasons"]
    assert "RING_LOSS_UNKNOWN" not in result["reasons"]
    assert "FLOW_NOT_PROVEN_COMPLETE:INCOMPLETE" in result["reasons"]
    assert "UNRECONCILED_CPU_OBSERVATION_ATTEMPTS" in result["reasons"]
    assert "SOCKET_DELIVERY_FAILED" in result["reasons"]
    assert "PROCESSING_DISCARDED" in result["reasons"]
    assert "LATE_EVENT" not in result["reasons"]
    assert "EMITTED_DELIVERY_NOT_RECONCILED" in result["reasons"]


@pytest.mark.parametrize(
    "close",
    [
        "NORMAL_END",
        "PACKET_LIMIT",
        "CAPTURE_STOP",
        "QUEUE_OVERFLOW",
        "CLOCK_INVALID",
        "INCOMPLETE",
        "IDLE_TIMEOUT",
        "ACTIVE_TIMEOUT",
    ],
)
def test_flow_completion_and_native_gate_never_inferred_from_close_label(close):
    summary = candidate_summary(close)
    if close in {"IDLE_TIMEOUT", "ACTIVE_TIMEOUT"}:
        summary["feature_tail"][0]["flow_completeness"] = "CANDIDATE_TIMEOUT"
    row = eligibility.candidate_rca(summary)[0]
    assert not row["eligible"] and row["native_ai"] == "BLOCKED"
    assert ("FLOW_NOT_PROVEN_COMPLETE:" + close in row["reasons"]) == (
        close not in {"IDLE_TIMEOUT", "ACTIVE_TIMEOUT"}
    )


def test_unknown_historical_candidate_and_invalid_float32_are_not_fabricated():
    summary = candidate_summary()
    bad = copy.deepcopy(summary)
    bad["feature_tail"][0]["values"][0] = 1e100
    assert not eligibility.candidate_rca(bad)[0]["network14_float32_contract"]
    summary["finalized_count"] = 2
    missing = eligibility.candidate_rca(summary)[-1]
    assert missing["flow_id"] is None and missing["unretained_candidates"] == 1


def test_phase_d_cli_to_real_tcx_plan_and_dns_preflight_before_auth(
    candidate, tmp_path, monkeypatch
):
    import shutil

    from soc_agent.security_ai.collectors import offload_session
    from soc_agent.security_ai.ebpf_tc import supervisor_startup as startup
    from soc_agent.security_ai.ebpf_tc.supervisor import SupervisedSession

    source, identity = candidate
    directory = tmp_path / "candidate"
    shutil.copytree(source, directory)
    calls = []
    original = offload_session.preflight

    def preflight(*args, **kwargs):
        calls.append("DNS_PREFLIGHT")
        assert (
            kwargs["previous_manifest"]
            == json.loads((directory / "supervisor-image.json").read_text())["previous_manifest"]
        )
        return original(*args, **kwargs)  # Read-only environment, source and TTY contract.

    def approve(handoff):
        calls.append("APPROVAL_BOUNDARY")
        plan = handoff.plan
        scope = handoff.approval_scope()
        assert (
            plan.program_sha256
            == phase_d.validate(directory, identity["manifest"], identity["image"])["tcx_program"]
        )
        assert plan.mode == "B2D_TCX_BLOCKED"
        assert "UDP1/TCP1" in scope["dns_scope"]
        assert "SETUID+SETGID" in scope["dns_worker_scope"]
        assert (
            plan.broker.application.application_session
            == handoff.application.plan.application_session
        )
        return False

    monkeypatch.setattr(offload_session, "preflight", preflight)
    monkeypatch.setattr(offload_session.os, "isatty", lambda fd: True)
    monkeypatch.setattr(startup, "confirm_scope", approve)
    monkeypatch.setattr(SupervisedSession, "authenticate_native", lambda *_: pytest.fail("auth"))
    with pytest.raises(ValueError, match="SUPERVISOR_APPROVAL_DENIED"):
        phase_d.execute(directory, identity["manifest"], identity["image"])
    assert calls == ["DNS_PREFLIGHT", "APPROVAL_BOUNDARY"]


@pytest.mark.parametrize("failed", [None, "detach", "dns"])
def test_packet_budget_shutdown_keeps_dns_status_until_bounded_drain(failed):
    import threading

    from soc_agent.security_ai.ebpf_tc.supervisor_startup import shutdown_collectors

    calls = []

    def action(name):
        def invoke(*args):
            calls.append(name)
            if name == "dns":
                assert args == (12,)
            if name == failed:
                raise ValueError("PHASE_D_FIXTURE_FAILURE")

        return invoke

    handoff = SimpleNamespace(
        ended=False,
        link_evidence={"state": "TCX_LINK_VERIFIED"},
        control_lock=threading.RLock(),
        sequence=1,
        plan=SimpleNamespace(approval="a" * 64),
        stop=action("detach"),
        close=action("close"),
    )
    failures = shutdown_collectors(
        handoff, None, SimpleNamespace(result=action("dns")), phase_d=True
    )
    assert calls == ["detach", "dns", "close"]
    assert len(failures) == bool(failed)


def test_dns_worker_parent_handoff_owns_only_readonly_pipe_and_cannot_restart(monkeypatch):
    import os
    import socket
    import struct
    import sys

    from soc_agent.security_ai.collectors.start_channel import start_binding
    from soc_agent.security_ai.ebpf_tc import phase_d_dns_engine as worker

    peers = []

    def sockets(*args):
        a, b = socket.socketpair(*args)
        peers.append(socket.socket(fileno=os.dup(b.fileno())))
        return a, b

    # Exercise only the parent branch. No real fork, capset, UID change or capture.
    waits = iter([(0, 0), (1234, 0)])
    fake_os = SimpleNamespace(
        getuid=lambda: 0,
        geteuid=lambda: 0,
        getgid=lambda: 0,
        getegid=lambda: 0,
        getpid=os.getpid,
        pipe2=os.pipe2,
        O_CLOEXEC=os.O_CLOEXEC,
        fork=lambda: 1234,
        close=os.close,
        WNOHANG=os.WNOHANG,
        waitpid=lambda pid, flags: next(waits),
        waitstatus_to_exitcode=os.waitstatus_to_exitcode,
    )
    monkeypatch.setattr(worker, "os", fake_os)
    monkeypatch.setattr(
        worker,
        "socket",
        SimpleNamespace(
            socketpair=sockets,
            AF_UNIX=socket.AF_UNIX,
            SOCK_SEQPACKET=socket.SOCK_SEQPACKET,
            SOCK_CLOEXEC=socket.SOCK_CLOEXEC,
        ),
    )
    monkeypatch.setattr(worker, "start_binding", start_binding, raising=False)
    monkeypatch.setattr(worker, "DNS_SCOPE_DIGEST", "d" * 64, raising=False)
    monkeypatch.setattr(sys, "argv", ["fixture"] * 5 + ["a" * 64])
    wire = bytearray(352)
    struct.pack_into("<III", wire, 4, 1000, 1000, os.getpid())
    handle = worker.start_dns_worker({"manifest_sha256": "b" * 64}, bytes(wire), b"c" * 32)
    fd = handle.start()
    try:
        assert peers[0].recv(9) == b"RUN_ONCE"
        with pytest.raises(OSError):
            os.write(fd, b"not an authority channel")
        with pytest.raises(ValueError, match="NO_RESTART"):
            handle.start()
        handle.close()
        assert handle.closed and handle.exit_code == 0
        assert worker.DNS_MASK == sum(1 << cap for cap in (6, 7, 13))
        assert not worker.DNS_MASK & ((1 << 21) | (1 << 39) | (1 << 12))
    finally:
        os.close(fd)
        for peer in peers:
            peer.close()

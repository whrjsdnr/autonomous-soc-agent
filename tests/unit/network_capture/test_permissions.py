"""Permission and bounded worker contracts; no test grants capture privileges."""

import asyncio
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from tests.unit.network_capture.test_packets import frame

from soc_agent.security_ai.operational.network_capture import native_probe, permissions
from soc_agent.security_ai.operational.network_capture.capture import CaptureUnavailable
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig, model_gates


def state():
    return dict(
        euid=1000,
        egid=1000,
        CapEff=8192,
        CapPrm=8192,
        CapInh=8192,
        CapAmb=8192,
        CapBnd=8192,
        NoNewPrivs=1,
    )


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("euid", 0, "ROOT"),
        ("CapEff", 0, "NET_RAW_REQUIRED"),
        ("CapEff", None, "NET_RAW_REQUIRED"),
        ("CapPrm", 8192 | 4096, "EXCESS"),
        ("CapInh", None, "EXCESS"),
        ("CapBnd", 8192 | 4096, "EXCESS"),
        ("NoNewPrivs", 0, "NO_NEW"),
    ],
)
def test_probe_rejects_privilege_context(monkeypatch, field, value, reason):
    monkeypatch.setattr(native_probe, "privileges", lambda: state() | {field: value})
    with pytest.raises(CaptureUnavailable, match=reason):
        native_probe.validate_probe_privileges()


def test_exact_capability_context_is_not_an_elevation(monkeypatch):
    monkeypatch.setattr(native_probe, "privileges", state)
    native_probe.validate_probe_privileges()
    assert state()["CapEff"] == 8192


@pytest.mark.parametrize("seconds", [0, 11, float("nan"), float("inf")])
def test_duration_bounds_precede_all_side_effects(seconds):
    with pytest.raises(ValueError, match="DURATION"):
        asyncio.run(native_probe.probe(seconds))


def test_packet_budget_stops_worker_without_an_extra_read(monkeypatch):
    capture = native_probe.ProbeCapture(CaptureConfig(interface="lo"))
    capture.stop = asyncio.Event()
    capture.received = 128
    monkeypatch.setattr(
        native_probe.PacketCapture, "receive", lambda self: pytest.fail("extra read")
    )
    assert capture.receive() is None
    assert capture.stop.is_set()


def test_drop_failure_closes_opened_socket(monkeypatch):
    capture = native_probe.ProbeCapture(CaptureConfig(interface="lo"))
    closed = []
    monkeypatch.setattr(native_probe, "validate_probe_privileges", lambda: None)
    monkeypatch.setattr(native_probe.PacketCapture, "open", lambda self: None)
    monkeypatch.setattr(capture, "close", lambda: closed.append(True))

    def fail():
        raise CaptureUnavailable("SECRET_FREE_FIXED_CODE")

    monkeypatch.setattr(native_probe, "drop_capabilities", fail)
    with pytest.raises(CaptureUnavailable, match="CAPABILITY_DROP_FAILED"):
        capture.open()
    assert closed == [True]


def test_unknown_proc_privileges_remain_unknown(monkeypatch):
    def fail(self):
        raise PermissionError("not reported")

    monkeypatch.setattr(permissions.Path, "read_text", fail)
    result = permissions.privileges()
    assert result["CapEff"] is None and result["NoNewPrivs"] is None


@pytest.mark.parametrize("failure", [None, "PERMISSION_DENIED", "SOURCE_UNAVAILABLE"])
def test_diagnostic_closes_socket_and_cannot_claim_packets_or_parity(monkeypatch, failure):
    closed = []

    class Capture:
        def __init__(self, config):
            pass

        def open(self):
            if failure:
                raise CaptureUnavailable(failure)

        def close(self):
            closed.append(True)

    monkeypatch.setattr(permissions, "PacketCapture", Capture)
    monkeypatch.setattr(permissions, "privileges", lambda: state() | {"CapEff": None})
    result = permissions.capture_permission("lo")
    assert result["capture"] == (failure or "AVAILABLE")
    assert closed == [True] and result["cap_net_raw"] is None
    assert result["capture_drops"] is None
    assert result["privileges_unchanged"]
    assert not result["actual_packets_verified"]
    assert all(g["inference"] == "BLOCKED" for g in result["operational_models"].values())


def test_gate_results_cannot_mutate_subsequent_models():
    gates = model_gates()
    gates["network-quality"]["inference"] = "ALLOW"
    assert gates["network-edge"]["inference"] == "BLOCKED"
    assert model_gates()["network-quality"]["inference"] == "BLOCKED"
    assert set(gates) == {"network-quality", "network-edge", "dns"}


def test_current_unprivileged_child_cannot_bypass_opt_in(tmp_path):
    current = permissions.privileges()
    if current["euid"] == 0 or current["CapEff"] != 0:
        pytest.skip("specifically exercises an ordinary unprivileged process")
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import sys,runpy; sys.path.insert(0,sys.argv.pop(1)); "
            "runpy.run_module('soc_agent.security_ai.operational.network_capture.native_probe', "
            "run_name='__main__')",
            str(Path(native_probe.__file__).parents[4]),
            "--seconds",
            "1",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env={"TMPDIR": str(tmp_path)},
    )
    assert result.returncode == 2
    assert '"reason": "CAP_NET_RAW_REQUIRED"' in result.stdout
    assert not result.stderr and list(tmp_path.iterdir()) == []


def test_capset_abi_in_owned_unprivileged_child():
    if permissions.privileges()["CapEff"] != 0:
        pytest.skip("requires a child starting with no effective capabilities")
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import sys; sys.path.insert(0,sys.argv[1]); "
            "from soc_agent.security_ai.operational.network_capture.native_probe "
            "import drop_capabilities; drop_capabilities(); print('DROPPED')",
            str(Path(native_probe.__file__).parents[4]),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0 and result.stdout.strip() == "DROPPED"
    assert not result.stderr


@pytest.mark.parametrize("drops", [0, 1, None])
def test_probe_pipeline_with_explicit_kernel_socket_fixture(monkeypatch, drops):
    # These bytes/clock are fabricated socket responses, never real capture evidence.
    class FixtureCapture(native_probe.ProbeCapture):
        def open(self):
            pass

        def receive(self):
            if self.received:
                return None
            self.received += 1
            now = datetime.now(UTC)
            nanos = int(now.timestamp()) * 10**9 + now.microsecond * 1000
            return frame(), now, "OUTBOUND", nanos

        def statistics(self):
            return None if drops is None else (1, drops)

    monkeypatch.setattr(native_probe, "validate_probe_privileges", lambda: None)
    monkeypatch.setattr(native_probe, "ProbeCapture", FixtureCapture)
    report = asyncio.run(native_probe.probe(1))
    assert report["packets_collected"] == 1
    assert report["capture_drops"] == drops
    assert report["sqlite_integrity"] and report["audit_verified"]
    assert report["status"] == ("VERIFIED" if drops == 0 else "INCONCLUSIVE")
    assert all(g["inference"] == "BLOCKED" for g in report["operational_models"].values())
    if drops == 0:
        assert report["receipts_verified"] == 2  # packet + shutdown diagnostic flow
        assert report["queue_counts"] == report["restart_queue_counts"] == {"DONE": 2}

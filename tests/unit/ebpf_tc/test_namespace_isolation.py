"""Synthetic namespace/packet fixtures only; no setns, bind, traffic or Root."""

import json
import struct
from io import BytesIO

import pytest

from soc_agent.security_ai.ebpf_tc import dns_copy_engine
from soc_agent.security_ai.ebpf_tc import namespace_isolation as isolation
from soc_agent.security_ai.ebpf_tc.r2_diagnostic import QUESTION, Scenario
from soc_agent.security_ai.ebpf_tc.supervisor import SupervisedSession, SupervisorImage

NS = "net:[4999999999]"  # Synthetic; never a claimed Native Namespace.


def test_scope_cannot_reuse_legacy_namespace_or_enable_policy():
    for fields in [
        dict(namespace=isolation.HOST_NAMESPACE),
        dict(namespace=NS, activation="APPROVED"),
        dict(namespace=NS, name="other-project"),
        dict(namespace=NS, endpoint="8.8.8.8:53"),
    ]:
        with pytest.raises(ValueError):
            isolation.IsolatedScope(**fields)
    with pytest.raises(ValueError):
        Scenario(namespace=NS)
    assert isolation.dns_scope_digest(NS) != isolation.dns_scope_digest(isolation.HOST_NAMESPACE)


def test_legacy_dns_scope_digest_stays_exact():
    import hashlib

    assert (
        isolation.dns_scope_digest(isolation.HOST_NAMESPACE)
        == hashlib.sha256(
            b"DNS_LOCAL_PARTIAL_COPY_V4:net4026531833:lo:7s:32:512:prewarm:shared10s:tty:seqpacket"
        ).hexdigest()
    )


def test_current_host_is_not_silently_entered_or_promoted(monkeypatch):
    monkeypatch.setattr(isolation.os, "readlink", lambda _: isolation.HOST_NAMESPACE)
    monkeypatch.setattr(
        isolation.subprocess,
        "check_output",
        lambda *_a, **_k: pytest.fail("No route inspection in wrong namespace"),
    )
    result = isolation.inspect_current_isolation(isolation.IsolatedScope(namespace=NS))
    assert "NAMESPACE_IDENTITY_MISMATCH" in result["reasons"]
    assert result["execution_ready"] is False


@pytest.mark.parametrize(
    "up,fault", [(False, None), (True, None), (True, "namespace"), (True, "oversize")]
)
def test_namespace_snapshot_uses_socket_ioctl_not_host_sysfs(monkeypatch, up, fault):
    class Probe:
        closed = False

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.closed = True

        def getsockopt(self, *_):
            return bytes.fromhex("0102030405060708")

    probe = Probe()
    namespaces = iter([NS, isolation.HOST_NAMESPACE if fault == "namespace" else NS])
    monkeypatch.setattr(isolation.os, "readlink", lambda _: next(namespaces))
    monkeypatch.setattr(isolation.socket, "socket", lambda *_: probe)
    monkeypatch.setattr(isolation.socket, "if_nameindex", lambda: [(1, "lo")])
    monkeypatch.setattr(isolation.fcntl, "ioctl", lambda *_: bytes(16) + struct.pack("H", int(up)))
    monkeypatch.setattr(isolation.subprocess, "check_output", lambda *a, **k: b'[{"dev":"lo"}]')

    def open_table(path, mode):
        assert str(path) in {"/proc/net/" + n for n in ("tcp", "tcp6", "udp", "udp6")}
        assert mode == "rb"
        return BytesIO(b"x" * 65537 if fault == "oversize" else b"header\n")

    monkeypatch.setattr(isolation.Path, "open", open_table)
    if fault:
        code = (
            "NAMESPACE_CHANGED_DURING_SNAPSHOT" if fault == "namespace" else "SOCKET_SNAPSHOT_BOUND"
        )
        with pytest.raises(ValueError, match=code):
            isolation.inspect_current_isolation(isolation.IsolatedScope(namespace=NS))
        assert probe.closed
        return
    result = isolation.inspect_current_isolation(isolation.IsolatedScope(namespace=NS))
    observation = result["observation"]
    assert observation["loopback_up"] is up
    assert ("LOOPBACK_NOT_UP" in result["reasons"]) is (not up)
    assert observation["socket_tables"] == {n: ["header"] for n in ("tcp", "tcp6", "udp", "udp6")}
    assert observation["socket_cookie"] == "0102030405060708"
    assert observation["cookie_evidence"] == "UNBOUND_PROBE_ONLY_NOT_DNS_WORKER"
    assert (
        observation["observation_ended_monotonic_ns"]
        >= observation["observation_started_monotonic_ns"]
    )
    assert probe.closed and result["execution_ready"] is False
    assert "LOCAL_DNS_RESPONDER_NOT_OBSERVED" in result["reasons"]


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"namespace": isolation.HOST_NAMESPACE}, "NAMESPACE_IDENTITY_MISMATCH"),
        ({"interfaces": [[1, "lo"], [2, "eth0"]]}, "NON_LOOPBACK_INTERFACE_OR_MISSING_LO"),
        ({"routes_outside_lo": [{"dev": "eth0"}]}, "EXTERNAL_ROUTE_OR_ROUTE_EVIDENCE_MISSING"),
        ({"loopback_up": False}, "LOOPBACK_NOT_UP"),
        ({"resolver_ready": False}, "LOCAL_DNS_RESPONDER_NOT_OBSERVED"),
    ],
)
def test_isolation_evidence_gaps_never_hidden(change, reason):
    evidence = dict(
        namespace=NS,
        interfaces=[[1, "lo"]],
        loopback_up=True,
        routes_outside_lo=[],
        resolver_ready=True,
    )
    result = isolation.assess_isolation(isolation.IsolatedScope(namespace=NS), evidence | change)
    assert reason in result["reasons"] and result["execution_ready"] is False


def test_even_complete_configuration_is_not_capture_or_execution_approval():
    result = isolation.assess_isolation(
        isolation.IsolatedScope(namespace=NS),
        dict(
            namespace=NS,
            interfaces=[[1, "lo"]],
            loopback_up=True,
            routes_outside_lo=[],
            resolver_ready=True,
        ),
    )
    assert result["status"] == "OBSERVED_NETWORK_CONFIGURATION_ONLY"
    assert result["capture_integrity"] == result["flow_completeness"] == "NOT_OBSERVED"
    assert result["execution_ready"] is False
    proposal = isolation.setup_proposal()
    assert len(proposal["proposed_root_argv"]) == 2
    assert proposal["namespace_cleanup_by_name_authorized"] is False
    assert not any(proposal[k] for k in ("veth", "nat", "firewall_changes"))


@pytest.mark.parametrize("transaction,tcp", [(0xC201, False), (0xC202, True), (0xC203, False)])
def test_exact_local_dns_wire_engine_without_io(transaction, tcp):
    query = struct.pack("!6H", transaction, 0x0100, 1, 0, 0, 0) + QUESTION
    wire = struct.pack("!H", len(query)) + query if tcp else query
    response = isolation.local_dns_response(wire, tcp=tcp)
    if tcp:
        assert struct.unpack("!H", response[:2])[0] == len(response) - 2
        response = response[2:]
    assert struct.unpack("!6H", response[:12]) == (transaction, 0x8500, 1, 1, 0, 0)
    assert response[12 : 12 + len(QUESTION)] == QUESTION
    assert response[-4:] == b"\x7f\0\0\1"


@pytest.mark.parametrize("mutation", ["id", "external_name", "extra_question", "response", "frame"])
def test_responder_rejects_scope_expansion(mutation):
    message = struct.pack("!6H", 0xC201, 0x0100, 1, 0, 0, 0) + QUESTION
    if mutation == "id":
        message = b"\0\0" + message[2:]
    elif mutation == "external_name":
        message = message[:-5] + b"evil."
    elif mutation == "extra_question":
        message = message[:4] + b"\0\2" + message[6:]
    elif mutation == "response":
        message = message[:2] + b"\x81\0" + message[4:]
    with pytest.raises(ValueError):
        isolation.local_dns_response(message, tcp=mutation == "frame")


def test_embedded_dns_namespace_uses_pinned_image_constant_not_host_env(monkeypatch):
    monkeypatch.setattr(dns_copy_engine.os, "readlink", lambda _: NS)
    monkeypatch.setattr(dns_copy_engine.socket, "if_nametoindex", lambda _: 1)
    monkeypatch.setenv("DNS_CAPTURE_NAMESPACE", NS)
    with pytest.raises(ValueError):
        dns_copy_engine.require_capture_namespace()
    monkeypatch.setattr(dns_copy_engine, "DNS_CAPTURE_NAMESPACE", NS, raising=False)
    dns_copy_engine.require_capture_namespace()
    monkeypatch.setattr(dns_copy_engine.os, "readlink", lambda _: isolation.HOST_NAMESPACE)
    with pytest.raises(ValueError):
        dns_copy_engine.require_capture_namespace()


def test_new_scope_descriptor_requires_disabled_preview_and_session_blocks_it():
    # model_construct is used only to hit the gate before any owner/resource API.
    image = SupervisorImage.model_construct(namespace_preview=True)
    with pytest.raises(ValueError, match="POLICY_NOT_ACTIVATED"):
        SupervisedSession(image=image)


@pytest.mark.asyncio
async def test_offline_zeek_analysis_has_no_host_network_or_capture_caps(tmp_path):
    from soc_agent.security_ai.collectors.live_contract import LivePlan, docker_argv
    from soc_agent.security_ai.research.models import digest

    plan = LivePlan(net_namespace=NS, bundle_digest=digest({"synthetic": "not-native"}))
    argv = docker_argv(plan, tmp_path, stdin_pcap=True)
    assert "--network=none" in argv and "--network=host" not in argv
    assert "--cap-add=NET_RAW" not in argv and "-r -" in argv[-3]


def test_single_scenario_protocol_budget_and_replay():
    engine = isolation.IsolatedDNSProtocol(isolation.IsolatedScope(namespace=NS))
    for transaction, tcp in [(0xC201, False), (0xC202, True), (0xC203, False)]:
        query = struct.pack("!6H", transaction, 0x0100, 1, 0, 0, 0) + QUESTION
        if tcp:
            query = struct.pack("!H", len(query)) + query
        engine.respond(query, tcp=tcp)
        with pytest.raises(ValueError, match="REPLAY_OR_QUERY_LIMIT"):
            engine.respond(query, tcp=tcp)
    assert len(engine.completed) == 3


@pytest.fixture(scope="module")
def preview(tmp_path_factory):
    from soc_agent.security_ai.ebpf_tc.phase_d import prepare_namespace_preview

    directory = tmp_path_factory.mktemp("synthetic-namespace-preview") / "candidate"
    return directory, prepare_namespace_preview(directory, NS)


def test_actual_builder_pins_new_namespace_and_guard_before_any_import(preview):
    directory, identity = preview
    from soc_agent.security_ai.ebpf_tc.namespace_isolation import dns_scope_digest

    image = SupervisorImage.model_validate_json((directory / "supervisor-image.json").read_bytes())
    assert image.namespace_preview and image.scope_namespace == NS
    source = (directory / "supervisor-image.py").read_text()
    assert source.startswith("raise SystemExit('ISOLATED_NAMESPACE_POLICY_NOT_ACTIVATED')\n")
    assert f"DNS_CAPTURE_NAMESPACE = '{NS}'" in source
    assert dns_scope_digest(NS) in source
    with pytest.raises(SystemExit, match="POLICY_NOT_ACTIVATED"):
        exec(
            compile(source, "<guard-only-test>", "exec"),
            {"__builtins__": {"SystemExit": SystemExit}},
        )
    manifest = json.loads((directory / "phase-d.json").read_bytes())
    assert manifest["contract"] == "SOC_PHASE_D_NAMESPACE_PREVIEW_V1"
    assert manifest["scope"]["namespace"] == NS
    assert manifest["scope"]["events"] == 4096 and manifest["scope"]["queue"] == 32
    assert identity["executed"] is False
    # A modified descriptor cannot activate a new scope by omitting the preview flag.
    data = json.loads(image.model_dump_json())
    data["namespace_preview"] = False
    with pytest.raises(ValueError, match="POLICY_NOT_ACTIVATED"):
        SupervisorImage.model_validate(data)


def test_existing_operational_validation_and_startup_reject_preview(preview, monkeypatch):
    from soc_agent.security_ai.ebpf_tc import phase_d, supervisor_startup

    directory, identity = preview
    with pytest.raises(ValueError, match="PHASE_D_RELEASE_OR_SOURCE_MISMATCH"):
        phase_d.validate(directory, identity["manifest"], identity["image"])
    monkeypatch.setattr(supervisor_startup, "local_controller", lambda: None)
    monkeypatch.setattr(
        supervisor_startup,
        "verify_package",
        lambda *_: pytest.fail("No installation/capture preparation for inactive policy"),
    )
    with pytest.raises(ValueError, match="POLICY_NOT_ACTIVATED"):
        supervisor_startup.execute(directory, identity["tcx_manifest"], identity["image"])


def test_passive_budget_for_new_namespace_rejects_host_traffic_as_its_evidence():
    from soc_agent.security_ai.ebpf_tc.capture_readiness import assess_loopback_budget

    samples = [
        dict(namespace=NS, monotonic_ns=1, rx_packets=100, rx_dropped=0),
        dict(namespace=NS, monotonic_ns=45_000_000_001, rx_packets=114, rx_dropped=0),
    ]
    assert assess_loopback_budget(samples)["state"] == "UNKNOWN"
    result = assess_loopback_budget(samples, expected_namespace=NS)
    assert result["observed_packets"] == 14 and result["execution_ready"] is False
    samples[-1]["namespace"] = isolation.HOST_NAMESPACE
    assert assess_loopback_budget(samples, expected_namespace=NS)["state"] == "UNKNOWN"


def test_responder_worker_cannot_use_host_namespace_or_receive_before_scope_gate(monkeypatch):
    from soc_agent.security_ai.ebpf_tc import isolated_dns_worker as worker

    monkeypatch.setattr(worker, "local_controller", lambda: None)
    monkeypatch.setattr(worker.os, "readlink", lambda _: isolation.HOST_NAMESPACE)
    monkeypatch.setattr(
        worker.socket,
        "socket",
        lambda *_a, **_k: pytest.fail("No socket before scope verification"),
    )
    with pytest.raises(ValueError, match="NAMESPACE_MISMATCH"):
        worker.serve_prebound(
            isolation.IsolatedScope(namespace=NS), None, None, ready=lambda _: None
        )


def test_prebound_responder_socket_cookies_lifecycle_and_late_window_are_synthetic(monkeypatch):
    from collections import deque

    from soc_agent.security_ai.ebpf_tc import isolated_dns_worker as worker

    clock = [1_000_000_000]

    def query(n):
        return struct.pack("!6H", n, 0x0100, 1, 0, 0, 0) + QUESTION

    class Channel:
        def __init__(self, kind, cookie=b"isolated"):
            self.kind, self.cookie, self.closed = kind, cookie, False
            self.requests = deque([query(0xC201), query(0xC203)])
            self.tcp_data = bytearray(struct.pack("!H", len(query(0xC202))) + query(0xC202))

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.closed = True

        def getsockname(self):
            return ("127.0.0.53", 53)

        def getsockopt(self, level, option, *_):
            return self.kind if option == worker.socket.SO_TYPE else self.cookie

        def recvfrom(self, _):
            return self.requests.popleft(), ("127.0.0.1", 45000)

        def sendto(self, b, _):
            return len(b)

        def accept(self):
            return self, ("127.0.0.1", 45001)

        def getpeername(self):
            return ("127.0.0.1", 45001)

        def settimeout(self, _):
            pass

        def recv(self, n):
            b = bytes(self.tcp_data[:n])
            del self.tcp_data[:n]
            return b

        def sendall(self, _):
            pass

        def shutdown(self, _):
            pass

    udp = Channel(worker.socket.SOCK_DGRAM)
    tcp = Channel(worker.socket.SOCK_STREAM)
    sequence = deque([(udp, 1_000_000_000), (tcp, 2_000_000_000), (udp, 37_000_000_000)])

    def selected(*_):
        channel, now = sequence.popleft()
        clock[0] = now
        return [channel], [], []

    monkeypatch.setattr(worker, "local_controller", lambda: None)
    monkeypatch.setattr(worker.os, "readlink", lambda _: NS)
    monkeypatch.setattr(worker.socket, "socket", lambda *_: Channel(worker.socket.SOCK_DGRAM))
    monkeypatch.setattr(worker.select, "select", selected)
    monkeypatch.setattr(worker.time, "monotonic_ns", lambda: clock[0])
    ready = []
    result = worker.serve_prebound(
        isolation.IsolatedScope(namespace=NS), udp, tcp, ready=ready.append
    )
    assert result["queries"] == 3 and udp.closed and tcp.closed
    assert [r["transport"] for r in result["events"]] == ["UDP", "TCP", "UDP"]
    assert result["tcp_closed_application_ns"] == 2_000_000_000
    assert result["capture_integrity"] == "NOT_ASSESSED" and ready[0]["namespace"] == NS
    # Passed sockets from the host namespace are rejected before any packet read.
    udp = Channel(worker.socket.SOCK_DGRAM, b"host")
    tcp = Channel(worker.socket.SOCK_STREAM)
    with pytest.raises(ValueError, match="SOCKET_SCOPE"):
        worker.serve_prebound(isolation.IsolatedScope(namespace=NS), udp, tcp, ready=ready.append)
    assert udp.closed and tcp.closed
    # A 30s-late query is rejected; it is not rounded up to the required35s.
    udp = Channel(worker.socket.SOCK_DGRAM)
    tcp = Channel(worker.socket.SOCK_STREAM)
    sequence.extend([(udp, 1_000_000_000), (tcp, 2_000_000_000), (udp, 32_000_000_000)])
    with pytest.raises(ValueError, match="TOO_EARLY"):
        worker.serve_prebound(isolation.IsolatedScope(namespace=NS), udp, tcp, ready=ready.append)
    assert udp.closed and tcp.closed
    ticks = [0]

    def expired():
        ticks[0] += 1
        return 0 if ticks[0] == 1 else 61

    monkeypatch.setattr(worker.time, "monotonic", expired)
    udp = Channel(worker.socket.SOCK_DGRAM)
    tcp = Channel(worker.socket.SOCK_STREAM)
    with pytest.raises(TimeoutError, match="RESPONDER_DEADLINE"):
        worker.serve_prebound(isolation.IsolatedScope(namespace=NS), udp, tcp, ready=ready.append)
    assert udp.closed and tcp.closed


def test_fragmented_tcp_request_cannot_extend_absolute_responder_deadline(monkeypatch):
    from soc_agent.security_ai.ebpf_tc import isolated_dns_worker as worker

    class SlowStream:
        reads = 0

        def settimeout(self, value):
            assert 0 < value <= 2

        def recv(self, _):
            self.reads += 1
            return b"x"

    now = iter([0, 1, 61])
    monkeypatch.setattr(worker.time, "monotonic", lambda: next(now))
    stream = SlowStream()
    with pytest.raises(TimeoutError, match="RESPONDER_DEADLINE"):
        worker._exact(stream, 3, 60)
    assert stream.reads == 2

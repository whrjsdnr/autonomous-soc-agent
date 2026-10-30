"""Real ordinary AF_UNIX metadata transport; ONLY peer/target privilege boundary simulated.

No AF_PACKET, setns, DNS network traffic, model grant or external API is executed.
"""

import asyncio
import hashlib
import json
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.total_monitoring_support import dns_packet
from tests.unit.continuous.test_runtime import config
from tests.unit.streaming_network.test_transport import stat

from soc_agent.continuous import dns_source
from soc_agent.continuous.models import ContinuousConfig
from soc_agent.continuous.service import ContinuousRuntime
from soc_agent.continuous.store import Store
from soc_agent.gui.continuous_projection import project
from soc_agent.gui.production import event_rows
from soc_agent.security_ai.operational.network_capture import helper_transport
from soc_agent.security_ai.research.live_input import timestamp_ns

NS = "net:[4026532232]"


def prepared(tmp_path):
    path = tmp_path / "dns"
    session = dns_source.prepare(path, namespace=NS, python=Path(sys.executable), seconds=60)
    pin = hashlib.sha256((path / "session.json").read_bytes()).hexdigest()
    return path, session, pin


def test_session_pin_and_target_are_separate_from_creator_host(tmp_path):
    path, session, pin = prepared(tmp_path)
    assert dns_source.inspect(path, namespace=NS, sha256=pin) == session
    with pytest.raises(ValueError, match="SESSION_SHA"):
        dns_source.inspect(path, namespace=NS, sha256="0" * 64)
    with pytest.raises(ValueError, match="SESSION_BINDING"):
        dns_source.inspect(path, namespace="net:[123]")
    with pytest.raises(ValueError, match="SESSION_BINDING"):
        dns_source.load(path)  # Host never claims target entry.
    body = json.loads((path / "session.json").read_text())
    body["code_sha256"]["continuous/dns_helper.py"] = "0" * 64
    (path / "session.json").write_text(json.dumps(body))
    with pytest.raises(ValueError, match="SESSION_BINDING"):
        dns_source.inspect(path, namespace=NS)


def test_dns_policy_does_not_extend_legacy_diagnostic_policy():
    from soc_agent.security_ai.operational.network_capture.stream_session import StreamPolicy

    assert StreamPolicy().seconds == 300
    assert dns_source.DNSPolicy().seconds == 3600
    with pytest.raises(ValueError):
        dns_source.DNSPolicy(seconds=3601)


@pytest.mark.asyncio
async def test_authority_denial_never_allocates_dns_listener(tmp_path, monkeypatch):
    import soc_agent.continuous.service as module

    path, _, pin = prepared(tmp_path)
    cfg = config(tmp_path).model_copy(
        update=dict(source="NATIVE_SERVICE", dns_session=path, dns_session_sha256=pin)
    )
    directory = tmp_path / "runtime"
    Store.create(directory, cfg)
    monkeypatch.setattr(
        dns_source, "DNSProducer", lambda *_: pytest.fail("listener before authorized run")
    )

    def deny(_):
        raise ValueError("SIMULATED_AUTHORITY_DENIED")

    monkeypatch.setattr(module, "require_source_authority", deny)
    runtime = ContinuousRuntime(directory)
    assert runtime.dns_source is None
    assert runtime.snapshot()["dns_transport"]["state"] == "WAITING_APPROVED_START"
    with pytest.raises(ValueError, match="SIMULATED_AUTHORITY_DENIED"):
        await runtime.run()
    assert not (path / "verified-ready.json").exists()


def test_helper_import_never_loads_ai_application_or_ml_dependencies():
    root = Path(dns_source.__file__).parents[2]
    probe = f"""
import sys, resource
resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
sys.path.insert(0, {str(root)!r})
class BlockModels:
    def find_spec(self, name, *args):
        if name in ('numpy', 'sklearn', 'xgboost', 'soc_agent.application'):
            raise RuntimeError('DNS_HELPER_IMPORTED_AI:' + name)
sys.meta_path.insert(0, BlockModels())
from soc_agent.continuous.dns_helper import main
assert callable(main)
print('LIGHTWEIGHT_HELPER_READY')
"""
    value = subprocess.run(
        [sys.executable, "-I", "-B", "-c", probe],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    assert value.stdout.strip() == "LIGHTWEIGHT_HELPER_READY"


def test_dns_requires_native_and_both_session_and_pin(tmp_path):
    cfg = config(tmp_path)
    for changes in (
        dict(dns_session=tmp_path / "dns"),
        dict(dns_session=tmp_path / "dns", dns_session_sha256="a" * 64),
    ):
        with pytest.raises(ValueError, match="DNS_REQUIRES_NATIVE"):
            ContinuousConfig.model_validate(cfg.model_dump() | changes)


@pytest.mark.asyncio
@pytest.mark.parametrize("tcp", [False, True])
async def test_dns_unix_to_durable_transaction_audit_gui_and_recovery(tmp_path, monkeypatch, tcp):
    path, session, pin = prepared(tmp_path)
    monkeypatch.setattr(dns_source, "load", lambda _: session)  # Target entry boundary only.
    monkeypatch.setattr(helper_transport, "validate_peer", lambda *a, **kw: None)
    source = dns_source.DNSProducer(path, pin)
    cfg = config(tmp_path).model_copy(
        update=dict(source="NATIVE_SERVICE", dns_session=path, dns_session_sha256=pin)
    )
    directory = tmp_path / "runtime"
    Store.create(directory, cfg)
    runtime = ContinuousRuntime(directory, dns_source=source)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client.connect(session.socket_address)
    client.sendall(stat(session, 1, 0, kind="READY").model_dump_json().encode())

    async def receive():
        async for packet in source.events():
            await runtime.project_dns(
                dict(
                    kind="native_dns",
                    session=str(session.session_id),
                    namespace=NS,
                    sequence=source.sequence,
                    packet=packet.model_dump(mode="json"),
                )
            )

    task = asyncio.create_task(receive())
    try:
        for _ in range(100):
            if source.state == "RUNNING":
                break
            await asyncio.sleep(0.01)
        assert source.state == "RUNNING"
        for n in (1, 2):
            packet = dns_packet(SimpleNamespace(session=session), n / 4, response=n == 2, tcp=tcp)
            packet = packet.model_copy(
                update=dict(
                    timestamp_origin="KERNEL_SO_TIMESTAMPNS",
                    capture_timestamp_ns=timestamp_ns(packet),
                )
            )
            assert packet.dns is not None and packet.dns.query_name is None
            client.sendall(
                stat(
                    session,
                    n + 1,
                    n,
                    received_frames=n,
                    sent_packets=n - 1,
                    dns_queries=1,
                    dns_responses=n - 1,
                )
                .model_dump_json()
                .encode()
            )
            client.sendall(
                dns_source.DNSMessage(
                    kind="PACKET",
                    session_id=session.session_id,
                    sequence=n,
                    counter_sequence=n + 1,
                    packet=packet,
                    dns_queries=1,
                    dns_responses=n - 1,
                )
                .model_dump_json()
                .encode()
            )
        client.sendall(
            dns_source.DNSMessage(
                kind="CLOSED",
                session_id=session.session_id,
                counter_sequence=4,
                kernel_packets=0,
                kernel_packets_total=2,
                capture_drops=0,
                capture_drops_total=0,
                counter_status="COUNTER_VERIFIED",
                received_frames=2,
                sent_packets=2,
                elapsed_seconds=1,
                dns_queries=1,
                dns_responses=1,
            )
            .model_dump_json()
            .encode()
        )
        await asyncio.wait_for(task, 3)
        assert source.cleanup == "VERIFIED" and source.capture.reader_thread.is_alive() is False
        assert runtime.metrics["dns_inputs"] == 2 and runtime.metrics["predictions"] == 0
        assert runtime.metrics["dns_metadata_bytes"] > 0 and runtime.metrics["dns_rejected"] == 0
        shown = project(dict(continuous=runtime.snapshot()))
        assert shown["collectors"]["dns"] == "STOPPED"
        assert shown["dns"]["counts"]["MATCHED_RESPONSE"] == 1
        assert len([row for _, row in event_rows(shown) if "dns_event" in row]) == 2
        assert shown["dns"]["dns9_inference"] == "BLOCKED"
        assert runtime.store.queue.counts().get("PENDING", 0) == 0
        # Exact retained metadata rebuild; event audit is idempotent across restart.
        before = len(runtime.store.auxiliary())
        rebuilt = ContinuousRuntime(directory, dns_source=source)
        for raw in rebuilt.store.auxiliary():
            await rebuilt.project_dns(raw, recovering=True)
        assert rebuilt.dns.snapshot()["counts"] == runtime.dns.snapshot()["counts"]
        assert rebuilt.metrics["dns_metadata_bytes"] == runtime.metrics["dns_metadata_bytes"]
        assert len(rebuilt.store.auxiliary()) == before == 2
        rebuilt.store.state()  # Validates the complete audit and detail chain.
        with pytest.raises(ValueError, match="SEQUENCE_BINDING"):
            await rebuilt.project_dns(rebuilt.store.auxiliary()[-1])
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await source.close()
        client.close()


@pytest.mark.asyncio
async def test_stop_before_helper_ready_joins_listener_handshake(tmp_path, monkeypatch):
    path, session, pin = prepared(tmp_path)
    monkeypatch.setattr(dns_source, "load", lambda _: session)
    source = dns_source.DNSProducer(path, pin)
    task = asyncio.create_task(anext(source.events()))
    await asyncio.sleep(0.02)
    await source.request_stop()
    with pytest.raises(ValueError, match="^HELPER_LISTENER_CLOSED$"):
        await asyncio.wait_for(task, 1)
    assert source.capture.closed.is_set() and source.cleanup != "VERIFIED"
    assert source.last_error == "CaptureUnavailable:HELPER_LISTENER_CLOSED"
    assert source.capture.listener.fileno() == -1
    assert source.capture.channel is None


@pytest.mark.asyncio
async def test_dns_metadata_quota_rejects_before_persistence_or_models(tmp_path):
    _, session, _ = prepared(tmp_path)
    cfg = config(tmp_path).model_copy(update=dict(source="NATIVE_SERVICE"))
    directory = tmp_path / "runtime"
    Store.create(directory, cfg)
    source = SimpleNamespace(session=session)
    runtime = ContinuousRuntime(directory, dns_source=source)
    packet = dns_packet(source, 1)
    packet = packet.model_copy(
        update=dict(
            timestamp_origin="KERNEL_SO_TIMESTAMPNS", capture_timestamp_ns=timestamp_ns(packet)
        )
    )
    raw = dict(
        kind="native_dns",
        session=str(session.session_id),
        namespace=NS,
        sequence=1,
        packet=packet.model_dump(mode="json"),
    )
    runtime.metrics["dns_metadata_bytes"] = session.policy.metadata_bytes
    with pytest.raises(ValueError, match="CONTINUOUS_DNS_METADATA_LIMIT"):
        await runtime.project_dns(raw)
    assert runtime.metrics["dns_rejected"] == 1
    assert runtime.store.auxiliary() == [] and runtime.metrics["dns_inputs"] == 0
    assert runtime.metrics["predictions"] == 0


def test_fixed_unit_and_exact_scope_are_required(tmp_path):
    from soc_agent.continuous.dns_review import UNIT, candidate, verify_review

    path, _, pin = prepared(tmp_path)
    cfg = config(tmp_path).model_copy(
        update=dict(source="NATIVE_SERVICE", dns_session=path, dns_session_sha256=pin)
    )
    expected = candidate(path, NS, pin)
    review = tmp_path / "review"
    review.mkdir()
    (review / UNIT).write_text(expected["body"])
    request = dict(
        dns_service=expected,
        files={UNIT: dict(path=str(review / UNIT), sha256=expected["unit_sha256"])},
    )
    assert verify_review(cfg, review, request)["traffic_generated"] is False
    assert "Restart=no" in expected["body"] and "--no-new-privs" in expected["body"]
    assert "--reuid=1000" in expected["body"]
    assert "ExecStartPre=/usr/bin/setpriv --dump\n" in expected["body"]
    bootstrap = "CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_NET_RAW"
    assert f"CapabilityBoundingSet={bootstrap}\n" in expected["body"]
    assert f"AmbientCapabilities={bootstrap}\n" in expected["body"]
    assert "--clear-groups" in expected["body"]
    assert "--bounding-set=-all,+net_raw" in expected["body"]
    assert "--ambient-caps=-all,+net_raw" in expected["body"]
    assert "NoNewPrivileges=yes\n" in expected["body"]
    with pytest.raises(ValueError, match="EXACT_SCOPE_REVIEW_REQUIRED"):
        verify_review(cfg, review, dict(files=request["files"]))
    (review / UNIT).write_text(expected["body"].replace("CAP_NET_RAW", "CAP_NET_ADMIN"))
    with pytest.raises(ValueError, match="UNIT_BINDING"):
        verify_review(cfg, review, request)


def test_helper_refuses_ordinary_invocation_before_loading_or_capture(monkeypatch):
    from soc_agent.continuous import dns_helper

    monkeypatch.setattr(
        sys, "argv", ["dns_helper", "--directory", "/not-approved", "--session-digest", "a" * 64]
    )
    monkeypatch.setattr(dns_helper, "load", lambda _: pytest.fail("must fail before session load"))
    with pytest.raises(ValueError):
        dns_helper.main()


@pytest.mark.asyncio
async def test_runtime_owns_dns_stop_and_reports_failure_without_touching_root(
    tmp_path, monkeypatch
):
    import soc_agent.continuous.service as module

    path, session, pin = prepared(tmp_path)
    cfg = config(tmp_path).model_copy(
        update=dict(source="NATIVE_SERVICE", dns_session=path, dns_session_sha256=pin)
    )
    directory = tmp_path / "runtime"
    Store.create(directory, cfg)
    monkeypatch.setattr(module, "require_source_authority", lambda _: None)  # Privilege boundary.

    class PassiveTCX:
        state = "RUNNING"
        remote_cleanup = "UNKNOWN"

        async def events(self):
            await asyncio.Event().wait()
            yield  # unreachable; no fixture promoted to Native capture

        async def request_stop(self):
            self.remote_cleanup = "VERIFIED"  # Simulated bound Root ACK boundary.

        async def close(self):
            self.state = "STOPPED"

    class PassiveDNS:
        def __init__(self):
            self.session = session
            self.stopped = asyncio.Event()
            self.snapshot = dict(state="RUNNING", cleanup="UNKNOWN", origin="UNVERIFIED")

        async def events(self):
            await self.stopped.wait()
            self.snapshot.update(state="STOPPED", cleanup="VERIFIED")
            return
            yield

        async def request_stop(self):
            self.stopped.set()

        async def close(self):
            pass

    source = PassiveDNS()
    runtime = ContinuousRuntime(directory, source=PassiveTCX(), dns_source=source)
    task = asyncio.create_task(runtime.run())
    await asyncio.sleep(0.1)
    runtime.store.control(stop=True)
    await asyncio.wait_for(task, 3)
    final = runtime.store.state()
    assert final["cleanup"] == "VERIFIED" and source.stopped.is_set()
    assert final["dns_transport"]["state"] == "STOPPED"
    assert final["metrics"]["predictions"] == 0 and final["metrics"]["dns_inputs"] == 0


@pytest.mark.asyncio
async def test_failed_helper_close_never_leaves_cleanup_not_started():
    import threading
    from types import SimpleNamespace

    from soc_agent.continuous.dns_source import DNSProducer

    closed = threading.Event()
    capture = SimpleNamespace(closed=closed, terminal=None, close=lambda **_: closed.set())
    source = DNSProducer.__new__(DNSProducer)
    source.capture = capture
    source._close_lock = asyncio.Lock()
    source.last_error = "CaptureUnavailable:HELPER_HEARTBEAT_OR_PROCESS_STALE"
    source.cleanup = "NOT_STARTED"
    await source.close()
    assert source.cleanup == "UNVERIFIED" and source.state == "FAILED" and closed.is_set()

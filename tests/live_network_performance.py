"""Offline performance diagnostics: synthetic frames, mock stats and AF_UNIX IPC only."""

import argparse
import asyncio
import hashlib
import json
import platform
import resource
import socket
import statistics
import struct
import tempfile
import time
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.network_monitor import NetworkMonitor, configure
from soc_agent.linux_runtime.service import initialize
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.realtime.models import SourceIdentity, SourceMetadata, native_event
from soc_agent.realtime.queue import EventQueue, QueueFull
from soc_agent.security_ai.operational.network_capture.capture import (
    PacketCapture,
    interface_identity,
)
from soc_agent.security_ai.operational.network_capture.helper_transport import (
    HelperCapture,
    Message,
)
from soc_agent.security_ai.operational.network_capture.live_session import prepare
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig
from soc_agent.security_ai.operational.network_capture.parsing import parse_packet
from tests.unit.live_network.test_parity import wire


def single_record_receive(receiver):
    """Pre-fix receive policy, sharing unchanged validation with the candidate."""
    if not receiver.alive:
        return None
    try:
        message = receiver.message()
    except BlockingIOError:
        return None
    return receiver._receive_record(message)


class SingleRecordReceiver(HelperCapture):
    def receive(self):
        return single_record_receive(self)


def messages(session, packets):
    def counters(kind, sequence, delta, total):
        return Message(
            kind=kind,
            session_id=session.session_id,
            counter_sequence=sequence,
            counter_status="COUNTER_VERIFIED",
            kernel_packets=delta,
            kernel_packets_total=total,
            capture_drops=0,
            capture_drops_total=0,
        )

    result = deque()
    for i, packet in enumerate(packets, 1):
        result.append(counters("HEARTBEAT", i + 1, 1, i))
        result.append(
            Message(kind="PACKET", session_id=session.session_id, sequence=i, packet=packet)
        )
    result.append(counters("CLOSED", len(packets) + 2, 0, len(packets)))
    return counters("READY", 1, 0, 0), result


def fixture_packets(count, identity, stamp):
    body = wire(length=80, tcp=True)
    base = int(stamp.timestamp()) * 10**9 + stamp.microsecond * 1000
    packets = []
    for i in range(count):
        ns = base + i * 1000
        timestamp = datetime.fromtimestamp(ns // 10**9, UTC).replace(
            microsecond=(ns % 10**9) // 1000
        )
        packets.append(
            parse_packet(
                body,
                interface_id=identity,
                timestamp=timestamp,
                capture_timestamp_ns=ns,
                direction="OUTBOUND",
                native=True,
            )
        )
    return packets


async def runtime_trial(root, receiver_class, packets):
    session = prepare(root / "observer")
    capture = receiver_class(root / "observer", session)
    ready, records = messages(session, packets)
    capture.accept_counters(ready)
    capture.ready, capture.alive, capture.last_heartbeat = ready, True, time.monotonic()
    calls = 0

    def receive_message():
        nonlocal calls
        calls += 1
        if not records:
            raise BlockingIOError
        return records.popleft()

    capture.message = receive_message
    runtime = root / "runtime"
    initialize(
        runtime, RuntimeConfig(incident_id=uuid4(), repeated_failures=5, multiple_accounts=3)
    )
    configure(runtime, CaptureConfig(interface="lo"))
    monitor = NetworkMonitor(
        runtime, RuntimeStore(runtime), capture=capture, generation=str(session.session_id)
    )
    capture.stop = monitor.stopped
    before_cpu = time.process_time()
    start = time.perf_counter()
    try:
        await asyncio.wait_for(monitor.run(), 15)
        wall = time.perf_counter() - start
        assert not records and monitor.metrics["packets_collected"] == len(packets), monitor.metrics
        assert monitor.metrics["last_error"] is None, monitor.metrics
        assert monitor.metrics["inference_count"] == 0
        return {
            "seconds": wall,
            "cpu_seconds": time.process_time() - before_cpu,
            "packets": len(packets),
            "packets_per_second": len(packets) / wall,
            "message_reads": calls,
            "queue": monitor.pipeline.queue.counts(),
            "kernel_packets": monitor.metrics["kernel_packets"],
            "capture_drops": monitor.metrics["capture_drops"],
            "audit_verified": bool(monitor.store.verify_audit()),
        }
    finally:
        capture.close()


def micro(call, count=1000, rounds=3):
    timings = []
    for _ in range(rounds):
        start = time.perf_counter_ns()
        for _ in range(count):
            call()
        timings.append((time.perf_counter_ns() - start) / count / 1000)
    return {
        "median_us": statistics.median(timings),
        "rounds_us": timings,
        "iterations_per_round": count,
    }


def stages(root, packet):
    body = wire(length=80, tcp=True)
    control = [
        (
            socket.SOL_SOCKET,
            35,
            struct.pack(
                "@ll", int(packet.timestamp.timestamp()), packet.timestamp.microsecond * 1000
            ),
        )
    ]

    class RawFixture:
        def recvmsg(self, *args):
            return body, control, 0, ("lo", 0x800, 4, 1, b"")

        def getsockopt(self, *args):
            return struct.pack("=II", 1, 0)

    capture = PacketCapture(CaptureConfig(interface="lo"))
    capture.socket = RawFixture()
    data = Message(kind="PACKET", session_id=uuid4(), sequence=1, packet=packet)
    payload = data.model_dump_json().encode()

    def serialize():
        return json.dumps(
            {
                "kind": "PACKET",
                "session_id": str(data.session_id),
                "sequence": 1,
                "packet": packet.model_dump(mode="json"),
            }
        ).encode()

    result = {
        "mock_single_recvmsg": micro(capture.receive),
        "mock_statistics_reset_read": micro(capture.statistics),
        "parse_80_byte_frame": micro(
            lambda: parse_packet(
                body,
                interface_id=packet.interface_id,
                timestamp=packet.timestamp,
                capture_timestamp_ns=packet.capture_timestamp_ns,
                direction="OUTBOUND",
                native=True,
            )
        ),
        "json_serialize_packet": micro(serialize),
        "message_validate_json": micro(lambda: Message.model_validate_json(payload)),
        "interface_identity_readonly": micro(lambda: interface_identity("lo"), count=100),
    }

    def batch():
        for _ in range(16):
            capture.receive()

    result["mock_batch_16_receives"] = micro(batch, count=100)
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        left.settimeout(0.5)
        right.settimeout(0.5)

        def ipc():
            left.sendall(payload)
            assert right.recv(8192) == payload

        result["unix_send_receive_roundtrip"] = micro(ipc)
        left.setblocking(False)
        filled = 0
        try:
            for _ in range(1024):
                left.send(payload)
                filled += 1
        except BlockingIOError:
            pass
        else:
            raise AssertionError("UNIX_BACKPRESSURE_NOT_OBSERVED_WITHIN_BUDGET")
        result["unix_backpressure"] = {
            "queued_records_before_eagain": filled,
            "payload_bytes": len(payload),
            "send_buffer_bytes": left.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
            "receive_buffer_bytes": right.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
        }
    finally:
        left.close()
        right.close()
    queue = EventQueue.create(root / "queue-benchmark.sqlite", capacity=2)
    events = [
        native_event(
            "linux",
            "benchmark-fixture:v1",
            SourceIdentity(namespace="benchmark:synthetic", generation="fixture", record=str(i)),
            SourceMetadata(channel="fixture", provider="offline-benchmark"),
            packet.timestamp,
        )
        for i in range(3)
    ]
    start = time.perf_counter()
    for e in events[:2]:
        queue.enqueue(e)
    try:
        queue.enqueue(events[2])
    except QueueFull:
        pass
    else:
        raise AssertionError("QUEUE_DID_NOT_FAIL_CLOSED")
    result["persistent_queue_backpressure"] = {
        "seconds_for_two_commits_and_rejection": time.perf_counter() - start,
        "counts": queue.counts(),
        "overflow_rejected": True,
    }
    return result


async def run_benchmark(root, rounds=3, count=16):
    packets = fixture_packets(count, interface_identity("lo"), datetime.now(UTC))
    result = {
        "run_id": str(uuid4()),
        "input": "SYNTHETIC_AF_PACKET_SHAPED_FIXTURE_NOT_LIVE",
        "capture_executed": False,
        "network_traffic_generated": False,
        "ipc": "AF_UNIX_ONLY",
        "python": platform.python_version(),
        "kernel": platform.release(),
        "fixture_frame_sha256": hashlib.sha256(wire(length=80, tcp=True)).hexdigest(),
        "packet_count": count,
        "rounds": rounds,
        "packet_batch": 16,
        "control_batch": HelperCapture.control_batch,
        "monitor_idle_sleep_seconds": 0.1,
        "stages": stages(root, packets[0]),
        "trials": [],
    }
    for trial in range(rounds):
        # Alternate order. Both use identical packet values and persistence limits.
        types = [("baseline", SingleRecordReceiver), ("candidate", HelperCapture)]
        if trial % 2:
            types.reverse()
        values = {}
        for name, receiver in types:
            values[name] = await runtime_trial(root / f"{trial}-{name}", receiver, packets)
        result["trials"].append(values)
    baseline = statistics.median(t["baseline"]["seconds"] for t in result["trials"])
    candidate = statistics.median(t["candidate"]["seconds"] for t in result["trials"])
    result["summary"] = {
        "baseline_median_seconds": baseline,
        "candidate_median_seconds": candidate,
        "fixture_speedup": baseline / candidate,
        "peak_rss_process_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        "rss_note": "Whole diagnostic process high-water mark, not per-variant helper memory",
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="soc-offline-performance-") as directory:
        result = asyncio.run(run_benchmark(Path(directory)))
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    main()

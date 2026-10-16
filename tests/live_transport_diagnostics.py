"""Unprivileged AF_UNIX-only transport diagnostics; synthetic metadata, no capture/helper."""

import argparse
import hashlib
import json
import resource
import socket
import statistics
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from soc_agent.security_ai.operational.network_capture.capture import CaptureUnavailable
from soc_agent.security_ai.operational.network_capture.helper_transport import HelperCapture
from soc_agent.security_ai.operational.network_capture.live_session import prepare
from tests.live_network_performance import fixture_packets, messages
from tests.unit.live_network.test_parity import wire


def fixture_channel(directory, *, separated=False, capacity=None):
    session = prepare(directory)
    capture = HelperCapture(directory, session)
    capture.listener.close()  # Fixture bypasses privilege attestation, never claims live capture.
    sender, channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)  # Fixture only.
    sender.settimeout(0.5)
    channel.setblocking(False)
    capture.channel = channel
    ready, _ = messages(session, [])
    capture.accept_counters(ready)
    capture.ready, capture.alive, capture.last_heartbeat = ready, True, time.monotonic()
    if capacity is not None:
        import queue

        capture.packets = queue.Queue(maxsize=capacity)
    capture.stop = threading.Event()
    if separated:
        capture.start_reader()
    return capture, sender, session


def percentile(values, fraction):
    return sorted(values)[max(0, int(len(values) * fraction + 0.999) - 1)] if values else None


def run_case(directory, *, separated, pause=0.0, delay=0.008, count=48):
    capture, sender, session = fixture_channel(directory, separated=separated)
    packets = fixture_packets(count, session.interface_id, datetime(2026, 1, 1, tzinfo=UTC))
    _, records = messages(session, packets)
    attempted = {}
    sent = []
    send_latencies = []
    failed_send_latencies = []
    errors = []
    sender_done = threading.Event()

    def produce():
        try:
            for record in records:
                if record.packet:
                    attempted[record.packet.capture_timestamp_ns] = time.perf_counter()
                body = record.model_dump_json(exclude_none=True).encode()
                before = time.perf_counter()
                sender.sendall(body)
                send_latencies.append((time.perf_counter() - before) * 1000)
                if record.packet:
                    sent.append(record.packet.capture_timestamp_ns)
        except TimeoutError:
            errors.append("SEND_TIMEOUT")
            failed_send_latencies.append((time.perf_counter() - before) * 1000)
        except OSError:
            errors.append("PEER_DISCONNECTED")
        finally:
            sender_done.set()
            try:
                sender.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    thread = threading.Thread(target=produce, name="unix-fixture-sender")
    wall, cpu = time.perf_counter(), time.process_time()
    thread.start()
    delivered, latencies = [], []
    receiver_error = None
    try:
        time.sleep(pause)  # Intentionally block the processor, never a readiness assumption.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                packet = capture.receive()
            except CaptureUnavailable as error:
                receiver_error = str(error)
                break
            if packet is not None:
                delivered.append(packet.capture_timestamp_ns)
                latencies.append(
                    (time.perf_counter() - attempted[packet.capture_timestamp_ns]) * 1000
                )
                time.sleep(delay)
            elif capture.terminal is not None and capture.packets.empty():
                break
            else:
                time.sleep(0.001)
        else:
            raise AssertionError("FIXTURE_PROCESSOR_DEADLINE")
        thread.join(1)
        assert not thread.is_alive()
        return {
            "mode": "reader_separated" if separated else "inline_baseline",
            "processor_pause_seconds": pause,
            "per_packet_processing_delay_seconds": delay,
            "offered_packets": count,
            "sent_packets": len(sent),
            "delivered_packets": len(delivered),
            "not_delivered_from_offered": count - len(delivered),
            "duplicate_deliveries": len(delivered) - len(set(delivered)),
            "fixture_packet_order_preserved": delivered
            == [p.capture_timestamp_ns for p in packets[: len(delivered)]],
            "wall_seconds": time.perf_counter() - wall,
            "cpu_seconds": time.process_time() - cpu,
            "throughput_pps": len(delivered) / (time.perf_counter() - wall),
            "delivery_latency_p50_ms": statistics.median(latencies) if latencies else None,
            "delivery_latency_p95_ms": percentile(latencies, 0.95),
            "send_latency_p50_ms": statistics.median(send_latencies) if send_latencies else None,
            "send_latency_p95_ms": percentile(send_latencies, 0.95),
            "send_latency_scope": "successful sends; timed-out sends measured separately",
            "failed_send_latencies_ms": failed_send_latencies,
            "peak_rss_process_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            "rss_scope": "diagnostic process high-water mark; cumulative within invocation",
            "queue_high_water": capture.queue_high_water,
            "queue_capacity": capture.packets.maxsize,
            "sender_errors": errors,
            "receiver_error": receiver_error,
            "closed_receipt": capture.terminal is not None,
            "counter_totals": capture.counter_totals if not capture.counter_issue else None,
            "counter_issue": capture.counter_issue,
        }
    finally:
        capture.close()
        sender.close()
        thread.join(1)


def benchmark(root):
    results = []
    for i in range(3):
        # Alternate order to avoid consistently warming only one variant.
        for paused in [False, True]:
            modes = [False, True] if i % 2 == 0 else [True, False]
            for separated in modes:
                results.append(
                    run_case(
                        root / f"{i}-{paused}-{separated}",
                        separated=separated,
                        pause=0.65 if paused else 0,
                    )
                )
    return {
        "fixture": "SYNTHETIC_METADATA_AF_UNIX_ONLY",
        "capture_executed": False,
        "network_test_traffic": False,
        "helper_timeout_seconds": 0.5,
        "fixture_send_buffer_request_bytes": 4096,
        "frame_fixture_sha256": hashlib.sha256(wire(length=80, tcp=True)).hexdigest(),
        "runs": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="soc-unix-transport-") as d:
        result = benchmark(Path(d))
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
    print("Fixture runs:", len(result["runs"]))


if __name__ == "__main__":
    main()

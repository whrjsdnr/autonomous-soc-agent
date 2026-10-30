"""USER EXECUTION ONLY. Separate bounded streaming helper; legacy v2 is unchanged."""

import argparse
import json
import os
import resource
import select
import signal
import socket
import time
from pathlib import Path

from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.network_capture.capture import (
    PacketCapture,
    interface_identity,
)
from soc_agent.security_ai.operational.network_capture.live_helper import (
    CaptureCounters,
    check_privileges,
    counter_failure,
    drop_privileges,
    process_start,
    require_counters,
)
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig
from soc_agent.security_ai.operational.network_capture.parsing import parse_packet
from soc_agent.security_ai.operational.network_capture.permissions import privileges
from soc_agent.security_ai.operational.network_capture.stream_session import RateBudget, load
from soc_agent.security_ai.research.models import digest


def run(directory: Path, approved_digest: str, *, session_loader=None, dns_metadata=False):
    check_privileges()  # Reject before constructing/opening any AF_PACKET socket.
    session = (session_loader or load)(directory)
    if digest(session.model_dump(mode="json")) != approved_digest:
        raise ValueError("STREAM_APPROVED_SESSION_DIGEST_MISMATCH")
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    resource.setrlimit(
        resource.RLIMIT_CPU, (session.policy.helper_cpu_seconds, session.policy.helper_cpu_seconds)
    )
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    capture = PacketCapture(CaptureConfig(interface=session.interface))
    counters = CaptureCounters(capture)
    rate = RateBudget(
        session.policy.frames_per_second, session.policy.burst_frames, time.monotonic()
    )
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    channel.settimeout(0.5)
    opened = None
    sent = received = 0
    dns_queries = dns_responses = dns_failures = 0
    stopped = False
    error = None

    def stop(*_):
        nonlocal stopped
        stopped = True

    def watchdog(*_):
        raise ValueError("HELPER_WATCHDOG_EXPIRED")

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGALRM, watchdog)

    def send(kind, **fields):
        usage = resource.getrusage(resource.RUSAGE_SELF)
        fields.update(
            dns_queries=dns_queries, dns_responses=dns_responses, dns_parse_failures=dns_failures
        )
        fields.update(
            rss_peak_bytes=usage.ru_maxrss * 1024, cpu_seconds=usage.ru_utime + usage.ru_stime
        )
        body = json.dumps({"kind": kind, "session_id": str(session.session_id), **fields}).encode()
        if len(body) > 8192:
            raise ValueError("HELPER_METADATA_RECORD_LIMIT")
        channel.sendall(body)

    try:
        channel.connect(session.socket_address)  # Explicit unprivileged controller must exist.
        capture.open()
        opened = time.monotonic()
        signal.setitimer(signal.ITIMER_REAL, session.seconds)
        drop_privileges()
        fd = capture.socket.fileno()
        inode = int(os.readlink(f"/proc/self/fd/{fd}").split("[")[1][:-1])
        stats = counters.sample()
        send(
            "READY",
            pid=os.getpid(),
            process_start=process_start(os.getpid()),
            socket_fd=fd,
            socket_inode=inode,
            capabilities=privileges(),
            **stats,
        )
        require_counters(stats)
        while (
            not stopped
            and time.monotonic() - opened < max(0.1, session.seconds - 1)
            and received < session.max_packets
        ):
            if interface_identity(session.interface) != session.interface_id:
                raise ValueError("HELPER_INTERFACE_REPLACED")
            readable, _, _ = select.select([capture.socket, channel], [], [], 0.2)
            if channel in readable:
                if channel.recv(64) != b"PING":
                    break  # STOP or parent disconnect, never an executable command.
            packet = None
            if capture.socket in readable:
                value = capture.receive()
                if value is not None:
                    received += 1
                    rate.consume(time.monotonic())
                    frame, stamp, direction, ns = value
                    # Loopback exposes outgoing and host clones. Keep one outgoing
                    # observation per IP packet, not both kernel copies.
                    if direction == "OUTBOUND":
                        packet = parse_packet(
                            frame,
                            interface_id=session.interface_id,
                            timestamp=stamp,
                            direction=direction,
                            native=True,
                            retain_name=False,
                            capture_timestamp_ns=ns,
                        )
                        if session.policy.dns_headers:
                            if packet.dns is not None:
                                dns_queries += int(not packet.dns.response)
                                dns_responses += int(packet.dns.response)
                            elif 53 in (packet.source_port, packet.destination_port):
                                dns_failures += 1
                        packet = (
                            packet
                            if dns_metadata
                            else packet.model_copy(
                                update={
                                    "dns": None,
                                    "dns_status": "DNS_HEADERS_ONLY"
                                    if session.policy.dns_headers
                                    else "NOT_COLLECTED_NETWORK_ONLY",
                                }
                            )
                        )
            stats = counters.sample()
            send(
                "HEARTBEAT",
                **stats,
                received_frames=received,
                sent_packets=sent,
            )
            require_counters(stats)
            # Never forward this interval's packet before its counters pass.
            if packet is not None:
                sent += 1
                send(
                    "PACKET",
                    sequence=sent,
                    counter_sequence=counters.sequence,
                    packet=packet.model_dump(mode="json"),
                )
    except (OSError, ValueError) as exc:
        error = (
            str(exc)
            if str(exc)
            in {
                "HELPER_CAPTURE_COUNTER_UNAVAILABLE",
                "HELPER_CAPTURE_DROPS_DETECTED",
                "HELPER_WATCHDOG_EXPIRED",
                "HELPER_INTERFACE_REPLACED",
                "STREAM_RATE_BUDGET_EXCEEDED",
                "STREAM_MONOTONIC_CLOCK_REVERSED",
            }
            else "HELPER_TRANSPORT_TIMEOUT"
            if isinstance(exc, TimeoutError)
            else type(exc).__name__
        )
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        stats = counters.sample()  # Last interval must be sampled before socket close.
        final_failure = counter_failure(stats)
        final_only_failure = error is None and final_failure is not None
        error = error or final_failure
        capture.close()
        if opened is not None:
            try:
                send(
                    "CLOSED",
                    elapsed_seconds=time.monotonic() - opened,
                    **stats,
                    received_frames=received,
                    sent_packets=sent,
                    error=error,
                    capabilities=privileges(),
                )
            except OSError:
                pass  # Controller disconnect: socket is already closed, no retry/capture restart.
        channel.close()
        if final_only_failure:
            raise ValueError(final_failure)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--session-digest", required=True)
    args = parser.parse_args()
    check_privileges()
    load(args.directory)
    with exclusive_runtime_lock(args.directory / "helper.lock"):
        run(args.directory, args.session_digest)


if __name__ == "__main__":
    main()

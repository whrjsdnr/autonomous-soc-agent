"""USER APPROVAL REQUIRED. v3 independent raw and analysis budgets; v2 is unchanged."""

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
from soc_agent.security_ai.operational.network_capture.direction_policy import Accounting
from soc_agent.security_ai.operational.network_capture.direction_session import load
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
    accounting = None
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

    def require_stats(stats):
        require_counters(stats)
        if stats["kernel_packets_total"] > session.max_packets:
            raise ValueError("V3_KERNEL_OBSERVATION_LIMIT")

    def send(kind, **fields):
        if accounting is not None:
            fields.update(accounting.snapshot())
            fields["sent_packets"] = sent
            if fields["budget_failure"] is not None:
                failure = fields["budget_failure"]
                elapsed = failure["monotonic_seconds"] - opened
                observed = (
                    accounting.raw
                    if failure["budget_type"] == "OBSERVATION"
                    else accounting.outbound
                )
                fields["budget_failure"] = {
                    **failure,
                    "elapsed_monotonic_seconds": elapsed,
                    "average_observed_rate": observed / elapsed if elapsed > 0 else None,
                    "counter_sequence": fields.get("counter_sequence"),
                    "kernel_packets_total": fields.get("kernel_packets_total"),
                }
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
        accounting = Accounting(session.policy, opened)
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
        require_stats(stats)
        while (
            not stopped
            and time.monotonic() - opened < max(0.1, session.seconds - 1)
            and received < session.max_packets
            and sent < session.policy.analysis_budget
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
                    frame, stamp, direction, ns = value
                    eligible = accounting.admit(direction, time.monotonic())
                    # Same OUTBOUND analysis scope as v2; no physical pair claim.
                    if eligible:
                        packet = parse_packet(
                            frame,
                            interface_id=session.interface_id,
                            timestamp=stamp,
                            direction=direction,
                            native=True,
                            retain_name=False,
                            capture_timestamp_ns=ns,
                        )
                        accounting.normalized += 1
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
            require_stats(stats)
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
                "V3_OBSERVATION_BUDGET_EXCEEDED",
                "V3_ANALYSIS_BUDGET_EXCEEDED",
                "V3_DIRECTION_UNKNOWN",
                "V3_KERNEL_OBSERVATION_LIMIT",
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
        if final_failure is None and stats["kernel_packets_total"] > session.max_packets:
            final_failure = "V3_KERNEL_OBSERVATION_LIMIT"
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
    from soc_agent.security_ai.operational.network_capture.calibrated_policy import require_headroom
    from soc_agent.security_ai.operational.network_capture.direction_session import approval_digest

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--session-digest", required=True)
    parser.add_argument("--approval-digest", required=True)
    args = parser.parse_args()
    session = load(args.directory)
    if args.approval_digest != approval_digest(session):
        raise ValueError("V3_NEW_SCOPE_APPROVAL_REQUIRED")
    if any(
        (args.directory / n).exists()
        for n in ("verified-closed.json", "rejected-closed.json", "transport-failure.json")
    ):
        raise ValueError("V3_SESSION_REPLAY_DENIED")
    require_headroom()
    check_privileges()
    with exclusive_runtime_lock(args.directory / "helper.lock"):
        run(args.directory, args.session_digest, dns_metadata=True)


if __name__ == "__main__":
    main()

"""USER EXECUTION ONLY. One bounded loopback observer; no model, Runtime or escalation."""

import argparse
import ctypes
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
from soc_agent.security_ai.operational.network_capture.live_session import load_session
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig
from soc_agent.security_ai.operational.network_capture.parsing import parse_packet
from soc_agent.security_ai.operational.network_capture.permissions import NET_RAW, privileges


def check_privileges():
    p = privileges()
    if (
        os.getuid() == 0
        or os.getuid() != os.geteuid()
        or os.getgid() != os.getegid()
        or os.getgroups()
        or p["NoNewPrivs"] != 1
        or any(p[k] != NET_RAW for k in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"))
    ):
        raise ValueError("HELPER_REQUIRES_ONLY_TEMPORARY_CAP_NET_RAW_AND_CLEARED_GROUPS")


def drop_privileges():
    # Same Linux capset contract as the original native_probe; that approved
    # source remains unchanged. No file capabilities or UID transitions here.
    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    libc = ctypes.CDLL(None, use_errno=True)
    capset = libc.capset
    capset.argtypes = [ctypes.POINTER(Header), ctypes.POINTER(Data)]
    capset.restype = ctypes.c_int
    if capset(ctypes.byref(Header(0x20080522, 0)), (Data * 2)()) != 0 or any(
        privileges()[k] != 0 for k in ("CapEff", "CapPrm", "CapInh", "CapAmb")
    ):
        raise ValueError("HELPER_CAPABILITY_DROP_FAILED")


def process_start(pid: int) -> str:
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


class CaptureCounters:
    """One reader of reset-on-read kernel intervals. Failures remain sticky."""

    def __init__(self, capture):
        self.capture = capture
        self.sequence = 0
        self.packets = self.drops = 0
        self.unavailable = False
        self.detail = None

    def sample(self):
        self.sequence += 1
        value = self.capture.statistics()
        if value is None:
            self.unavailable = True
            self.detail = self.detail or self.capture.statistics_error or "STATISTICS_UNKNOWN"
        elif (
            len(value) != 2
            or any(type(v) is not int or not 0 <= v < 2**32 for v in value)
            or value[1] > value[0]
        ):
            self.unavailable = True
            self.detail = self.detail or "INVALID_COUNTER_VALUES"
            value = None
        else:
            self.packets += value[0]
            self.drops += value[1]
        status = (
            "COUNTER_UNAVAILABLE"
            if self.unavailable
            else "CAPTURE_DROPS_DETECTED"
            if self.drops
            else "COUNTER_VERIFIED"
        )
        return {
            "counter_sequence": self.sequence,
            "counter_status": status,
            "counter_detail": self.detail,
            "kernel_packets": value[0] if value is not None else None,
            "capture_drops": value[1] if value is not None else None,
            "kernel_packets_total": None if self.unavailable else self.packets,
            "capture_drops_total": None if self.unavailable else self.drops,
        }


def counter_failure(stats):
    if stats["counter_status"] == "COUNTER_UNAVAILABLE":
        return "HELPER_CAPTURE_COUNTER_UNAVAILABLE"
    if stats["counter_status"] == "CAPTURE_DROPS_DETECTED":
        return "HELPER_CAPTURE_DROPS_DETECTED"
    return None


def require_counters(stats):
    if failure := counter_failure(stats):
        raise ValueError(failure)


def run(directory: Path):
    check_privileges()  # Reject before constructing/opening any AF_PACKET socket.
    session = load_session(directory)
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    capture = PacketCapture(CaptureConfig(interface=session.interface))
    counters = CaptureCounters(capture)
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    channel.settimeout(0.5)
    opened = None
    sent = received = 0
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
                        packet = packet.model_copy(
                            update={"dns": None, "dns_status": "NOT_COLLECTED_NETWORK_ONLY"}
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
                send("PACKET", sequence=sent, packet=packet.model_dump(mode="json"))
    except (OSError, ValueError) as exc:
        error = (
            str(exc)
            if str(exc)
            in {
                "HELPER_CAPTURE_COUNTER_UNAVAILABLE",
                "HELPER_CAPTURE_DROPS_DETECTED",
                "HELPER_WATCHDOG_EXPIRED",
                "HELPER_INTERFACE_REPLACED",
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
    args = parser.parse_args()
    check_privileges()
    load_session(args.directory)
    with exclusive_runtime_lock(args.directory / "helper.lock"):
        run(args.directory)


if __name__ == "__main__":
    main()

"""Non-promiscuous AF_PACKET. Never requests privilege or changes NIC/network settings."""

import hashlib
import os
import socket
import struct
from datetime import UTC, datetime
from pathlib import Path

from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig


class CaptureUnavailable(ValueError):
    pass


def interface_identity(name: str) -> str:
    CaptureConfig(interface=name)
    try:
        index = socket.if_nametoindex(name)
        namespace = os.stat("/proc/self/ns/net").st_ino
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        address = Path("/sys/class/net", name, "address").read_text().strip()
    except (OSError, ValueError):
        raise CaptureUnavailable("INVALID_OR_UNAVAILABLE_INTERFACE") from None
    return content_digest_payload(
        {
            "namespace": namespace,
            "boot_digest": hashlib.sha256(boot.encode()).hexdigest(),
            "interface": name,
            "ifindex": index,
            "address_digest": hashlib.sha256(address.encode()).hexdigest(),
        }
    )


class PacketCapture:
    def __init__(self, config: CaptureConfig):
        self.config = config
        self.identity = interface_identity(config.interface)
        self.socket = None

    def open(self):
        if self.config.origin != "NATIVE_AF_PACKET":
            raise CaptureUnavailable("LIVE_COLLECTOR_REQUIRES_NATIVE_CONFIG")
        try:
            stream = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        except PermissionError:
            raise CaptureUnavailable("PERMISSION_DENIED") from None
        except OSError:
            raise CaptureUnavailable("SOURCE_UNAVAILABLE") from None
        self.socket = stream
        try:
            stream.bind((self.config.interface, 0))
            stream.setsockopt(socket.SOL_SOCKET, 35, 1)  # Linux SO_TIMESTAMPNS, native timespec
            stream.setblocking(False)
        except OSError:
            self.close()
            raise CaptureUnavailable("CAPTURE_CONFIGURATION_FAILED") from None

    def receive(self):
        if self.socket is None:
            raise CaptureUnavailable("CAPTURE_NOT_OPEN")
        try:
            frame, control, flags, address = self.socket.recvmsg(65535, socket.CMSG_SPACE(32))
        except BlockingIOError:
            return None
        except OSError:
            raise CaptureUnavailable("CAPTURE_READ_FAILED") from None
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise CaptureUnavailable("CAPTURE_TRUNCATED")
        stamp = None
        timestamp_ns = None
        for level, kind, payload in control:
            if level == socket.SOL_SOCKET and kind == 35 and len(payload) >= struct.calcsize("@ll"):
                seconds, nanos = struct.unpack_from("@ll", payload)
                if not 0 <= nanos < 10**9:
                    raise CaptureUnavailable("CAPTURE_TIMESTAMP_INVALID")
                timestamp_ns = seconds * 10**9 + nanos
                stamp = datetime.fromtimestamp(seconds, UTC).replace(microsecond=nanos // 1000)
        if stamp is None or address[0] != self.config.interface:
            raise CaptureUnavailable("CAPTURE_IDENTITY_OR_TIMESTAMP_MISSING")
        direction = (
            "OUTBOUND" if address[2] == 4 else "INBOUND" if address[2] in (0, 1, 2) else "UNKNOWN"
        )
        return frame, stamp, direction, timestamp_ns

    def statistics(self) -> tuple[int, int] | None:
        if self.socket is None:
            return None
        try:
            values = self.socket.getsockopt(
                263, 6, 12
            )  # SOL_PACKET, PACKET_STATISTICS (resets on read)
            return struct.unpack_from("II", values) if len(values) >= 8 else None
        except OSError:
            return None

    def close(self):
        if self.socket is not None:
            self.socket.close()
            self.socket = None

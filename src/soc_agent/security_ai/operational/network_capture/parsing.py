"""Bounded Ethernet/IP/TCP/UDP/DNS parsing. Payload bytes never leave this module."""

import hashlib
import ipaddress
import struct
from datetime import datetime

from soc_agent.security_ai.operational.network_capture.models import (
    DNSObservation,
    PacketObservation,
)


class PacketRejected(ValueError):
    """Safe reason code only; no raw data or endpoints."""


def _name(data: bytes, offset: int) -> tuple[list[bytes], int]:
    labels, visited = [], set()
    end = None
    for _ in range(128):
        if offset >= len(data) or offset in visited:
            raise PacketRejected("DNS_NAME_BOUNDS_OR_LOOP")
        visited.add(offset)
        size = data[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise PacketRejected("DNS_POINTER_TRUNCATED")
            pointer = ((size & 63) << 8) | data[offset + 1]
            if pointer >= offset or pointer < 12:
                raise PacketRejected("DNS_POINTER_INVALID")
            if end is None:
                end = offset + 2
            offset = pointer
            continue
        if size & 0xC0 or size > 63 or offset + size + 1 > len(data):
            raise PacketRejected("DNS_LABEL_INVALID")
        offset += 1
        if size == 0:
            if sum(len(v) + 1 for v in labels) + 1 > 255:
                raise PacketRejected("DNS_NAME_TOO_LONG")
            return labels, end if end is not None else offset
        labels.append(data[offset : offset + size])
        offset += size
    raise PacketRejected("DNS_NAME_LIMIT")


def dns_message(data: bytes, *, retain_name: bool) -> DNSObservation:
    if not 12 <= len(data) <= 4096:
        raise PacketRejected("DNS_MESSAGE_SIZE")
    tid, flags, questions = struct.unpack_from("!HHH", data)
    if flags & 0x7800 or questions != 1:
        raise PacketRejected("DNS_OPCODE_OR_QUESTION_COUNT_UNSUPPORTED")
    labels, end = _name(data, 12)
    if end + 4 > len(data):
        raise PacketRejected("DNS_QUESTION_TRUNCATED")
    qtype, qclass = struct.unpack_from("!HH", data, end)
    wire = b"".join(bytes([len(v)]) + v for v in labels) + b"\0"
    text = None
    if retain_name:
        # Escape non-printing/non-ASCII bytes; do not apply case/suffix/IDNA transforms.
        text = (
            ".".join(
                "".join(
                    chr(c) if 33 <= c < 127 and c not in (46, 92) else f"\\{c:03}" for c in label
                )
                for label in labels
            )
            or "."
        )
        if len(text) > 255:
            raise PacketRejected("DNS_TEXT_POLICY_LIMIT")
    return DNSObservation(
        transaction_id=tid,
        response=bool(flags & 0x8000),
        response_code=flags & 15,
        query_type=qtype,
        query_class=qclass,
        query_name=text,
        query_name_digest=hashlib.sha256(wire).hexdigest(),
    )


def parse_packet(
    frame: bytes,
    *,
    interface_id: str,
    timestamp: datetime,
    direction: str,
    native: bool,
    retain_name: bool = False,
    capture_timestamp_ns: int | None = None,
) -> PacketObservation:
    if not 14 <= len(frame) <= 65535:
        raise PacketRejected("FRAME_TRUNCATED_OR_OVERSIZED")
    offset, ether = 14, struct.unpack_from("!H", frame, 12)[0]
    for _ in range(2):
        if ether not in (0x8100, 0x88A8):
            break
        if offset + 4 > len(frame):
            raise PacketRejected("VLAN_TRUNCATED")
        ether = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    data = frame[offset:]
    if ether == 0x0800:
        if len(data) < 20 or data[0] >> 4 != 4:
            raise PacketRejected("IPV4_TRUNCATED")
        ihl = (data[0] & 15) * 4
        total = struct.unpack_from("!H", data, 2)[0]
        if not 20 <= ihl <= total <= len(data):
            raise PacketRejected("IPV4_LENGTH_INVALID")
        if struct.unpack_from("!H", data, 6)[0] & 0x3FFF:
            raise PacketRejected("IP_FRAGMENT_UNSUPPORTED")
        protocol = data[9]
        source, dest = data[12:16], data[16:20]
        version = 4
    elif ether == 0x86DD:
        if len(data) < 40 or data[0] >> 4 != 6:
            raise PacketRejected("IPV6_TRUNCATED")
        payload = struct.unpack_from("!H", data, 4)[0]
        total, ihl, protocol = 40 + payload, 40, data[6]
        if payload == 0 or total > len(data) or total > 65535:
            raise PacketRejected("IPV6_LENGTH_OR_JUMBO_UNSUPPORTED")
        source, dest = data[8:24], data[24:40]
        for _ in range(8):
            if protocol not in (0, 43, 60, 51):
                break
            if ihl + 2 > total:
                raise PacketRejected("IPV6_EXTENSION_TRUNCATED")
            length = (data[ihl + 1] + 2) * 4 if protocol == 51 else (data[ihl + 1] + 1) * 8
            protocol, ihl = data[ihl], ihl + length
            if ihl > total:
                raise PacketRejected("IPV6_EXTENSION_LENGTH_INVALID")
        if protocol in (44, 50, 0, 43, 60, 51):
            raise PacketRejected("IPV6_FRAGMENT_ESP_OR_EXTENSION_UNSUPPORTED")
        version = 6
    else:
        raise PacketRejected("NON_IP_UNSUPPORTED")
    segment = data[ihl:total]
    flags, window = 0, None
    if protocol == 6:
        if len(segment) < 20:
            raise PacketRejected("TCP_TRUNCATED")
        header = (segment[12] >> 4) * 4
        if not 20 <= header <= len(segment):
            raise PacketRejected("TCP_HEADER_INVALID")
        flags, window = (
            ((segment[12] & 1) << 8) | segment[13],
            struct.unpack_from("!H", segment, 14)[0],
        )
        body = segment[header:]
        transport = "tcp"
    elif protocol == 17:
        if len(segment) < 8:
            raise PacketRejected("UDP_TRUNCATED")
        length = struct.unpack_from("!H", segment, 4)[0]
        if not 8 <= length <= len(segment):
            raise PacketRejected("UDP_LENGTH_INVALID")
        header, body, transport = 8, segment[8:length], "udp"
    else:
        raise PacketRejected("NON_TCP_UDP_UNSUPPORTED")
    sport, dport = struct.unpack_from("!HH", segment)
    dns, status = None, "NOT_DNS"
    if 53 in (sport, dport):
        status = "DNS_PARSE_FAILED"
        try:
            if transport == "tcp":
                if len(body) < 2 or struct.unpack_from("!H", body)[0] != len(body) - 2:
                    raise PacketRejected("DNS_TCP_STREAM_REASSEMBLY_REQUIRED")
                body = body[2:]
            dns = dns_message(body, retain_name=retain_name)
            status = "DNS_PARSED"
        except PacketRejected as error:
            status = str(error)
    elif 853 in (sport, dport):
        status = "PORT853_CONTENT_UNOBSERVABLE"
    elif 443 in (sport, dport):
        status = "PORT443_CONTENT_UNKNOWN_POSSIBLE_DOH"
    return PacketObservation(
        interface_id=interface_id,
        source_address=ipaddress.ip_address(source),
        destination_address=ipaddress.ip_address(dest),
        source_port=sport,
        destination_port=dport,
        transport=transport,
        ip_version=version,
        direction=direction,
        timestamp=timestamp,
        timestamp_origin="KERNEL_SO_TIMESTAMPNS" if native else "FIXTURE",
        capture_timestamp_ns=capture_timestamp_ns,
        frame_length=len(frame),
        ip_length=total,
        tcp_flags=flags,
        tcp_window=window,
        header_length=ihl + header,
        raw_frame_digest=hashlib.sha256(frame).hexdigest(),
        dns=dns,
        dns_status=status,
    )

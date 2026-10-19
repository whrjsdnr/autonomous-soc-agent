"""Independent bounded classic-PCAP reference; no capture, payload retention or models."""

import ipaddress
import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import Field, IPvAnyAddress

from soc_agent.security_ai.collectors.offline import file_digest, pcap_digest
from soc_agent.security_ai.research.models import Frozen, digest

SCOPE = "ETHERNET_CLASSIC_PCAP_USEC_TCP_UDP_NO_FRAGMENTS_EXTENSIONS_OR_NS:v1"


class Packet(Frozen):
    sequence: int = Field(gt=0, le=4096, strict=True)
    seconds: int = Field(ge=0, lt=2**32, strict=True)
    microseconds: int = Field(ge=0, lt=1000000, strict=True)
    frame_length: int = Field(ge=42, le=65535, strict=True)
    captured_length: int = Field(ge=42, le=65535, strict=True)
    kind: Literal["tcp", "udp"]
    source: IPvAnyAddress
    destination: IPvAnyAddress
    source_port: int = Field(ge=0, le=65535, strict=True)
    destination_port: int = Field(ge=0, le=65535, strict=True)
    ip_length: int = Field(ge=28, le=65535, strict=True)
    tcp_flags: int = Field(ge=0, le=255, strict=True)

    @property
    def ns(self) -> int:
        return self.seconds * 10**9 + self.microseconds * 1000

    @property
    def timestamp(self) -> datetime:
        return datetime.fromtimestamp(self.seconds, UTC).replace(microsecond=self.microseconds)

    @property
    def key(self) -> tuple:
        return self.kind, tuple(
            sorted(
                (
                    (str(self.source), self.source_port),
                    (str(self.destination), self.destination_port),
                )
            )
        )


def reference(path: Path) -> list[Packet]:
    """Parse required header fields directly, independently from Zeek and ML parser."""
    pcap_digest(path)
    packets = []
    with path.open("rb") as stream:
        header = stream.read(24)
        magic = header[:4]
        if magic not in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"}:
            raise ValueError("ZEEK_PARITY_UNSUPPORTED_PCAP_PRECISION_OR_FORMAT")
        endian = "<" if magic[0] == 0xD4 else ">"
        major, minor, _, _, snaplen, link = struct.unpack(endian + "HHIIII", header[4:])
        if (major, minor, link) != (2, 4, 1) or not 42 <= snaplen <= 65535:
            raise ValueError("ZEEK_PARITY_UNSUPPORTED_LINK_OR_HEADER")
        while record := stream.read(16):
            if len(record) != 16 or len(packets) >= 4096:
                raise ValueError("ZEEK_PARITY_PCAP_RECORD_BOUND")
            seconds, microseconds, captured, wire = struct.unpack(endian + "IIII", record)
            if not 42 <= captured == wire <= snaplen:
                raise ValueError("ZEEK_PARITY_TRUNCATED_OR_OVERSIZE_FRAME")
            body = stream.read(captured)
            if len(body) != captured:
                raise ValueError("ZEEK_PARITY_PCAP_TRUNCATED")
            ether = struct.unpack_from("!H", body, 12)[0]
            if ether == 0x0800:
                if len(body) < 34 or body[14] >> 4 != 4:
                    raise ValueError("ZEEK_PARITY_IP_HEADER")
                ihl = (body[14] & 15) * 4
                length = struct.unpack_from("!H", body, 16)[0]
                if ihl < 20 or struct.unpack_from("!H", body, 20)[0] & 0x3FFF:
                    raise ValueError("ZEEK_PARITY_FRAGMENT_UNSUPPORTED")
                src, dst = body[26:30], body[30:34]
                proto, offset = body[23], 14 + ihl
            elif ether == 0x86DD:
                if len(body) < 54 or body[14] >> 4 != 6:
                    raise ValueError("ZEEK_PARITY_IP_HEADER")
                length = struct.unpack_from("!H", body, 18)[0] + 40
                src, dst = body[22:38], body[38:54]
                proto, offset = body[20], 54
            else:
                raise ValueError("ZEEK_PARITY_UNSUPPORTED_ETHERTYPE")
            if proto not in (6, 17) or len(body) < 14 + length:
                raise ValueError("ZEEK_PARITY_UNSUPPORTED_PROTOCOL_OR_TRUNCATION")
            minimum = 20 if proto == 6 else 8
            if offset + minimum > 14 + length:
                raise ValueError("ZEEK_PARITY_TRANSPORT_TRUNCATED")
            sport, dport = struct.unpack_from("!HH", body, offset)
            flags = body[offset + 13] if proto == 6 else 0
            if proto == 6 and (body[offset + 12] & 15 or body[offset + 12] >> 4 < 5):
                raise ValueError("ZEEK_PARITY_TCP_RESERVED_OR_NS_UNSUPPORTED")
            packets.append(
                Packet(
                    sequence=len(packets) + 1,
                    seconds=seconds,
                    microseconds=microseconds,
                    frame_length=wire,
                    captured_length=captured,
                    kind="tcp" if proto == 6 else "udp",
                    source=str(ipaddress.ip_address(src)),
                    destination=str(ipaddress.ip_address(dst)),
                    source_port=sport,
                    destination_port=dport,
                    ip_length=length,
                    tcp_flags=flags,
                )
            )
    if not packets:
        raise ValueError("ZEEK_PARITY_EMPTY_INPUT")
    return packets


def verify_packets(pcap: Path, log: Path, source_sha: str, log_sha: str) -> tuple[Packet, ...]:
    if pcap_digest(pcap) != source_sha or file_digest(log) != log_sha:
        raise ValueError("ZEEK_PARITY_INPUT_DIGEST_MISMATCH")
    expected = reference(pcap)
    if log.stat().st_size > 4 * 1024**2 or log.is_symlink():
        raise ValueError("ZEEK_PARITY_LOG_BOUND")
    actual = []
    with log.open("rb") as f:
        while line := f.readline(4097):
            if len(line) > 4096 or len(actual) >= 4096:
                raise ValueError("ZEEK_PARITY_LOG_BOUND")
            p = Packet.model_validate_json(line)
            if p.sequence != len(actual) + 1:
                raise ValueError("ZEEK_PARITY_SEQUENCE_DIFFERENCE")
            actual.append(p)
    if len(expected) != len(actual):
        raise ValueError("ZEEK_PARITY_MISSING_EVENT")
    for a, b in zip(expected, actual, strict=True):
        if a.ns != b.ns:
            raise ValueError("ZEEK_PARITY_TIMESTAMP_DIFFERENCE")
        if a != b:
            raise ValueError("ZEEK_PARITY_PARSER_DIFFERENCE")
    if pcap_digest(pcap) != source_sha or file_digest(log) != log_sha:
        raise ValueError("ZEEK_PARITY_INPUT_CHANGED")
    return tuple(actual)


def metadata(packets: tuple[Packet, ...], session: str, source: str) -> list[dict]:
    return [
        dict(
            event_id=digest(dict(session=session, sequence=p.sequence)),
            interface_id=source,
            capture_session_id=session,
            timestamp_ns=p.ns,
            source_address=str(p.source),
            destination_address=str(p.destination),
            source_port=p.source_port,
            destination_port=p.destination_port,
            transport=p.kind,
            ip_length=p.ip_length,
            tcp_flags=p.tcp_flags,
        )
        for p in packets
    ]

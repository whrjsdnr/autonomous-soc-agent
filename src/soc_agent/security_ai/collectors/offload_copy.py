"""Fail-closed, memory-only analysis copies; no capture, transmission or disk I/O.

Partial is provenance, never a claim of completed end-to-end packet integrity.
Only fully captured, unfragmented local DNS TCP/UDP packets can be copied.
"""

import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Literal

Status = Literal[
    "CHECKSUM_VALID", "CHECKSUM_PARTIAL_CONFIRMED", "CHECKSUM_INVALID", "CHECKSUM_UNKNOWN"
]


def checksum(body: bytes) -> int:
    if len(body) % 2:
        body += b"\0"
    total = sum(struct.unpack(f"!{len(body) // 2}H", body))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total ^ 65535


@dataclass(frozen=True)
class AnalysisCopy:
    status: Status
    reason: str
    original_sha256: str
    analysis_sha256: str | None = None
    original_checksum: int | None = None
    analysis_checksum: int | None = None
    auxiliary_status: int | None = None
    packet: bytes | None = None
    ip_version: int | None = None
    ipv4_checksum: int | None = None

    def receipt(self) -> dict:
        # Explicit allowlist: packet bytes must never enter an audit/JSON dump.
        return dict(
            status=self.status,
            reason=self.reason,
            original_sha256=self.original_sha256,
            analysis_sha256=self.analysis_sha256,
            original_checksum=self.original_checksum,
            analysis_checksum=self.analysis_checksum,
            auxiliary_status=self.auxiliary_status,
            ip_version=self.ip_version,
            ipv4_checksum=self.ipv4_checksum,
            transformed=self.packet is not None and self.original_sha256 != self.analysis_sha256,
        )


def analysis_copy(packet: bytes, auxiliary: bytes | None) -> AnalysisCopy:
    original = hashlib.sha256(packet).hexdigest()
    status = stored = None

    def reject(state: Status, reason: str) -> AnalysisCopy:
        return AnalysisCopy(
            state, reason, original, original_checksum=stored, auxiliary_status=status
        )

    if auxiliary is None or len(auxiliary) != 20:
        return reject("CHECKSUM_UNKNOWN", "AUXILIARY_MISSING")
    status, wire, snapshot, _, _, _, _ = struct.unpack("=IIIHHHH", auxiliary)
    if not 20 <= len(packet) <= 512 or wire != len(packet) or snapshot != len(packet):
        return reject("CHECKSUM_UNKNOWN", "CAPTURE_LENGTH")
    if status & (16 | 64 | 256):
        return reject("CHECKSUM_UNKNOWN", "VLAN_OR_GSO_UNSUPPORTED")
    if status & 8 and status & 128:
        return reject("CHECKSUM_INVALID", "CONFLICTING_KERNEL_STATUS")
    if status not in {1, 9, 129}:
        return reject("CHECKSUM_UNKNOWN", "AUXILIARY_STATUS_UNSUPPORTED")
    version = packet[0] >> 4
    if version == 4:
        ihl = (packet[0] & 15) * 4
        if ihl < 20 or ihl > len(packet) or int.from_bytes(packet[2:4], "big") != len(packet):
            return reject("CHECKSUM_INVALID", "IPV4_LENGTH")
        if checksum(packet[:ihl]) != 0:
            return reject("CHECKSUM_INVALID", "IPV4_CHECKSUM")
        if int.from_bytes(packet[6:8], "big") & 0x3FFF:
            return reject("CHECKSUM_UNKNOWN", "FRAGMENT")
        source, target, protocol = packet[12:16], packet[16:20], packet[9]
        client, server = b"\x7f\0\0\1", b"\x7f\0\0\x35"
        if (source, target) not in {(client, server), (server, client)}:
            return reject("CHECKSUM_UNKNOWN", "ADDRESS_SCOPE")
        pseudo = packet[12:20] + struct.pack("!BBH", 0, protocol, len(packet) - ihl)
    elif version == 6:
        ihl = 40
        if len(packet) < 40 or int.from_bytes(packet[4:6], "big") != len(packet) - 40:
            return reject("CHECKSUM_INVALID", "IPV6_LENGTH")
        source, target, protocol = packet[8:24], packet[24:40], packet[6]
        if source != bytes(15) + b"\1" or target != source:
            return reject("CHECKSUM_UNKNOWN", "ADDRESS_SCOPE")
        # No guessed offsets through extension, fragmentation or jumbo headers.
        pseudo = packet[8:40] + struct.pack("!I3xB", len(packet) - 40, protocol)
    else:
        return reject("CHECKSUM_UNKNOWN", "IP_VERSION")
    if protocol not in {6, 17}:
        return reject("CHECKSUM_UNKNOWN", "TRANSPORT_OR_EXTENSION_UNSUPPORTED")
    segment = packet[ihl:]
    minimum, offset = (8, 6) if protocol == 17 else (20, 16)
    if len(segment) < minimum:
        return reject("CHECKSUM_INVALID", "TRANSPORT_TRUNCATED")
    ports = struct.unpack("!HH", segment[:4])
    if version == 4:
        in_scope = ports[1] == 53 if source == client else ports[0] == 53
    else:
        in_scope = 53 in ports
    if not in_scope:
        return reject("CHECKSUM_UNKNOWN", "PORT_SCOPE")
    if protocol == 17 and int.from_bytes(segment[4:6], "big") != len(segment):
        return reject("CHECKSUM_INVALID", "UDP_LENGTH")
    if protocol == 6 and not 20 <= (segment[12] >> 4) * 4 <= len(segment):
        return reject("CHECKSUM_INVALID", "TCP_LENGTH")
    stored = int.from_bytes(segment[offset : offset + 2], "big")
    zeroed = segment[:offset] + bytes(2) + segment[offset + 2 :]
    expected = checksum(pseudo + zeroed)
    if protocol == 17 and expected == 0:
        expected = 65535
    if protocol == 17 and stored == 0 and not status & 8:
        return reject(
            "CHECKSUM_UNKNOWN" if version == 4 else "CHECKSUM_INVALID", "UDP_CHECKSUM_ABSENT"
        )
    if status & 8:
        if stored != checksum(pseudo) ^ 65535:
            return reject("CHECKSUM_INVALID", "PARTIAL_SEED_MISMATCH")
        state: Status = "CHECKSUM_PARTIAL_CONFIRMED"
        # Exactly two bytes of an analysis copy; original network skb is untouched.
        result = packet[: ihl + offset] + struct.pack("!H", expected) + packet[ihl + offset + 2 :]
    elif stored != expected:
        return reject("CHECKSUM_INVALID", "COMPLETED_CHECKSUM_MISMATCH")
    else:
        state, result = "CHECKSUM_VALID", packet
    return AnalysisCopy(
        state,
        "LOCAL_DNS_ANALYSIS_ONLY",
        original,
        hashlib.sha256(result).hexdigest(),
        stored,
        expected,
        status,
        result,
        ip_version=version,
        ipv4_checksum=int.from_bytes(packet[10:12], "big") if version == 4 else None,
    )


def memory_pcap(packets: list[tuple[int, bytes]]) -> bytes:
    if len(packets) > 32:
        raise ValueError("DNS_ANALYSIS_QUEUE32")
    body = bytearray(struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 512, 101))
    for timestamp_ns, packet in packets:
        if not 20 <= len(packet) <= 512 or not 0 <= timestamp_ns < (2**32) * 10**9:
            raise ValueError("DNS_ANALYSIS_PCAP_BOUND")
        seconds, fraction = divmod(timestamp_ns, 10**9)
        body.extend(struct.pack("<IIII", seconds, fraction, len(packet), len(packet)))
        body.extend(packet)
    return bytes(body)


def chain_receipt(previous: str, row: dict) -> str:
    fields = ("state", "sequence", "timestamp_ns", "packet_type", "auxiliary_hex", "receipt")
    metadata = {key: row[key] for key in fields}
    return hashlib.sha256(
        bytes.fromhex(previous)
        + json.dumps(metadata, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def validate_memory_pcap(body: bytes) -> int:
    expected = struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 512, 101)
    if not 24 <= len(body) <= 24 + 32 * (512 + 16) or body[:24] != expected:
        raise ValueError("ZEEK_MEMORY_PCAP_SCOPE")
    offset = 24
    count = 0
    while offset < len(body):
        if offset + 16 > len(body) or count >= 32:
            raise ValueError("ZEEK_MEMORY_PCAP_RECORD_BOUND")
        _, nanos, captured, original = struct.unpack_from("<IIII", body, offset)
        if nanos >= 10**9 or not 20 <= captured <= 512 or captured != original:
            raise ValueError("ZEEK_MEMORY_PCAP_RECORD_BOUND")
        offset += 16 + captured
        if offset > len(body):
            raise ValueError("ZEEK_MEMORY_PCAP_TRUNCATED")
        count += 1
    return count

"""File-only protocol/header fixtures. No networking or privilege paths."""

import hashlib
import struct
from pathlib import Path

from tests.unit.live_network.test_parity import wire
from tests.zeek_collector_support import checksum, ip_checksum


def valid_wire(*, reverse=False, length=40, flags=2, tcp=True, ipv6=False):
    body = bytearray(wire(reverse=reverse, length=length, flags=flags, tcp=tcp, ipv6=ipv6))
    if tcp:
        start = 54 if ipv6 else 34
        segment = bytes(body[start:])
        if ipv6:
            pseudo = bytes(body[22:54]) + struct.pack("!I3xB", len(segment), 6)
        else:
            pseudo = bytes(body[26:34]) + struct.pack("!BBH", 0, 6, len(segment))
        body[start + 16 : start + 18] = struct.pack("!H", checksum(pseudo + segment))
    return bytes(body) if ipv6 else ip_checksum(body)


def write_pcap(path: Path, records, *, nanosecond=False):
    magic = 0xA1B23C4D if nanosecond else 0xA1B2C3D4
    body = bytearray(struct.pack("<IHHIIII", magic, 2, 4, 0, 0, 65535, 1))
    for ns, frame in records:
        sec, frac = divmod(ns, 10**9)
        body += (
            struct.pack("<IIII", sec, frac if nanosecond else frac // 1000, len(frame), len(frame))
            + frame
        )
    path.write_bytes(body)
    path.chmod(0o600)
    return hashlib.sha256(body).hexdigest()


def golden(path: Path, scenario="idle", *, tcp=True, ipv6=False):
    seconds = (
        [0, 0.5, 1, 32]
        if scenario == "idle"
        else [0, 20, 40, 60, 80, 100, 119, 120]
        if scenario == "active"
        else [0, 0.5, 1]
    )
    base = 60 if ipv6 else 40
    records = [
        (
            1800000000 * 10**9 + int(t * 10**9),
            valid_wire(
                reverse=i == 1,
                length=base + 20 * (i % 3),
                flags=[2, 16, 1][i % 3],
                tcp=tcp,
                ipv6=ipv6,
            ),
        )
        for i, t in enumerate(seconds)
    ]
    return write_pcap(path, records)

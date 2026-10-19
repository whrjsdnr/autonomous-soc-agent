"""Offline-only wire files from existing Golden Packet Fixtures; no socket or traffic."""

import hashlib
import json
import struct
from pathlib import Path

from tests.unit.live_network.test_parity import wire
from tests.unit.network_capture.test_packets import frame


def checksum(body: bytes) -> int:
    if len(body) % 2:
        body += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(body) // 2), body))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def ip_checksum(body: bytes) -> bytes:
    b = bytearray(body)
    b[24:26] = b"\0\0"
    b[24:26] = struct.pack("!H", checksum(bytes(b[14:34])))
    return bytes(b)


def pcap_fixture(path: Path) -> str:
    records = [(i * 0.5, wire(reverse=i == 1, length=40 + 20 * i, tcp=False)) for i in range(3)]
    query = bytearray(frame())
    # Existing DNS Fixture uses one query. Response repeats the question and no answers.
    response = bytearray(query)
    response[26:30], response[30:34] = query[30:34], query[26:30]
    response[34:36], response[36:38] = query[36:38], query[34:36]
    response[44:46] = struct.pack("!H", 0x8180)
    response[48:50] = struct.pack("!H", 1)
    response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 99])
    response[16:18] = struct.pack("!H", len(response) - 14)
    response[38:40] = struct.pack("!H", len(response) - 34)
    records += [(2, bytes(query)), (2.05, bytes(response))]
    out = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for t, body in records:
        body = ip_checksum(body)
        out += (
            struct.pack("<IIII", 1800000000 + int(t), round((t % 1) * 1e6), len(body), len(body))
            + body
        )
    path.write_bytes(out)
    path.chmod(0o600)
    return hashlib.sha256(out).hexdigest()


def row(kind="network", **update):
    value = {
        "ts": 1800000000.125,
        "uid": "Cfixture",
        "id.orig_h": "192.0.2.1",
        "id.orig_p": 1000,
        "id.resp_h": "192.0.2.2",
        "id.resp_p": 2000,
        "proto": "udp",
    }
    if kind == "network":
        value.update(
            duration=1,
            orig_pkts=2,
            resp_pkts=1,
            orig_ip_bytes=120,
            resp_ip_bytes=60,
            conn_state="SF",
            missed_bytes=0,
        )
    else:
        value.update(trans_id=7, qtype=1, rcode=0, rtt=0.05, TTLs=[10, 20], TC=False)
    value.update(update)
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()

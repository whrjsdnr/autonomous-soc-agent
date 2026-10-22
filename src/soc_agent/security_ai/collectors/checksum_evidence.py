"""Bounded diagnostic-only AF_PACKET observer; importing never opens a socket.

Full frames exist only in RAM. Receipts contain checksums and header identity,
not DNS payload. Kernel auxiliary flags are evidence, not reconstructed skb state.
"""

import ctypes
import hashlib
import json
import os
import socket
import struct
import time

NAMESPACE = "net:[4026531833]"
SCOPE = {
    "namespace": NAMESPACE,
    "interface": "lo",
    "ifindex": 1,
    "endpoints": ["127.0.0.1", "127.0.0.53:53"],
    "protocols": ["UDP", "TCP"],
    "seconds": 10,
    "records": 32,
    "snaplen": 512,
    "socket_buffer_request": 16384,
    "traffic_generation": False,
    "bpf_load": False,
    "tcx_attach": False,
    "raw_bytes_persisted": False,
}
SCOPE_DIGEST = hashlib.sha256(
    json.dumps(SCOPE, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
# Classic socket filter (not an eBPF program/load): IPv4, exact endpoint pair,
# nonfragmented TCP/UDP, either source or destination port 53; maximum 512 bytes.
FILTER = (
    (0x20, 0, 0, 12),
    (0x15, 0, 3, 0x7F000001),
    (0x20, 0, 0, 16),
    (0x15, 4, 14, 0x7F000035),
    (0x06, 0, 0, 0),
    (0x15, 0, 12, 0x7F000035),
    (0x20, 0, 0, 16),
    (0x15, 0, 10, 0x7F000001),
    (0x28, 0, 0, 6),
    (0x45, 8, 0, 0x3FFF),
    (0x30, 0, 0, 9),
    (0x15, 1, 0, 6),
    (0x15, 0, 5, 17),
    (0xB1, 0, 0, 0),
    (0x48, 0, 0, 0),
    (0x15, 3, 0, 53),
    (0x48, 0, 0, 2),
    (0x15, 1, 0, 53),
    (0x06, 0, 0, 0),
    (0x06, 0, 0, 512),
)


def folded_checksum(body: bytes) -> int:
    if len(body) & 1:
        body += b"\0"
    total = sum(struct.unpack(f"!{len(body) // 2}H", body))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total ^ 65535


def describe(packet: bytes, auxiliary: bytes, packet_type: int, timestamp_ns: int) -> dict:
    """IPv4 L3 SOCK_DGRAM snapshot; refuses incomplete/unsupported checksums."""
    if len(auxiliary) != 20:
        raise ValueError("CHECKSUM_AUXILIARY_MISSING_OR_INVALID")
    status, wire, snapshot, mac, net, vlan, tpid = struct.unpack("=IIIHHHH", auxiliary)
    record = dict(
        packet_sha256=hashlib.sha256(packet).hexdigest(),
        timestamp_ns=timestamp_ns,
        clock="KERNEL_REALTIME_SO_TIMESTAMPNS",
        packet_type=packet_type,
        direction="OUTGOING" if packet_type == 4 else "HOST" if packet_type == 0 else "OTHER",
        length=wire,
        captured_length=len(packet),
        auxiliary_snaplen=snapshot,
        auxiliary_status=status,
        checksum_partial=bool(status & 8),
        checksum_valid_exported=bool(status & 128),
        gso_tcp=bool(status & 256),
        gro_state="UNKNOWN_NOT_EXPORTED",
        checksum_complete_vs_unnecessary="UNKNOWN_NOT_DISTINGUISHED",
        auxiliary_mac=mac,
        auxiliary_net=net,
        vlan_tci=vlan if status & 16 else None,
        vlan_tpid=tpid if status & 64 else None,
        checksum_result="UNKNOWN",
        dns_transaction_id=None,
    )
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return record
    ihl = (packet[0] & 15) * 4
    length = int.from_bytes(packet[2:4], "big")
    if (
        ihl < 20
        or length < ihl
        or length > len(packet)
        or wire != len(packet)
        or int.from_bytes(packet[6:8], "big") & 0x3FFF
    ):
        return record
    protocol = packet[9]
    segment = bytearray(packet[ihl:length])
    minimum, offset = (8, 6) if protocol == 17 else (20, 16)
    if protocol not in {6, 17} or len(segment) < minimum:
        return record
    ports = struct.unpack("!HH", segment[:4])
    if (
        {packet[12:16], packet[16:20]} != {b"\x7f\0\0\1", b"\x7f\0\0\x35"}
        or (packet[12:16] == b"\x7f\0\0\x35" and ports[0] != 53)
        or (packet[16:20] == b"\x7f\0\0\x35" and ports[1] != 53)
    ):
        raise ValueError("CHECKSUM_PACKET_SCOPE")
    if protocol == 17 and int.from_bytes(segment[4:6], "big") != len(segment):
        return record
    header_length = 8 if protocol == 17 else (segment[12] >> 4) * 4
    if not minimum <= header_length <= len(segment):
        return record
    stored = int.from_bytes(segment[offset : offset + 2], "big")
    segment[offset : offset + 2] = bytes(2)
    pseudo = packet[12:20] + struct.pack("!BBH", 0, protocol, len(segment))
    expected = folded_checksum(pseudo + segment)
    if protocol == 17 and expected == 0:
        expected = 65535
    header = bytearray(packet[:ihl])
    actual_ip = int.from_bytes(header[10:12], "big")
    header[10:12] = bytes(2)
    payload = segment[header_length:]
    # TCP DNS length prefix is interpreted only if the complete message is in
    # this segment. No fabricated TXID or stream reassembly from partial data.
    if protocol == 6:
        payload = (
            payload[2:]
            if len(payload) >= 2 and int.from_bytes(payload[:2], "big") == len(payload) - 2
            else b""
        )
    record.update(
        source=socket.inet_ntoa(packet[12:16]),
        destination=socket.inet_ntoa(packet[16:20]),
        source_port=ports[0],
        destination_port=ports[1],
        protocol=protocol,
        ip_id=int.from_bytes(packet[4:6], "big"),
        ipv4_checksum=actual_ip,
        recomputed_ipv4_checksum=folded_checksum(header),
        transport_checksum=stored,
        recomputed_transport_checksum=expected,
        pseudo_header_seed=folded_checksum(pseudo) ^ 65535,
        checksum_result="ABSENT_IPV4_UDP"
        if protocol == 17 and stored == 0
        else "MATCH"
        if stored == expected
        else "MISMATCH",
        dns_transaction_id=int.from_bytes(payload[:2], "big") if len(payload) >= 12 else None,
        tcp_sequence=int.from_bytes(segment[4:8], "big") if protocol == 6 else None,
    )
    return record


def attach_filter(channel: socket.socket) -> None:
    class Instruction(ctypes.Structure):
        _fields_ = [
            ("code", ctypes.c_ushort),
            ("jt", ctypes.c_ubyte),
            ("jf", ctypes.c_ubyte),
            ("k", ctypes.c_uint),
        ]

    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("instructions", ctypes.POINTER(Instruction))]

    instructions = (Instruction * len(FILTER))(*(Instruction(*row) for row in FILTER))
    program = Program(len(FILTER), instructions)
    channel.setsockopt(socket.SOL_SOCKET, 26, bytes(program))  # SO_ATTACH_FILTER
    channel.setsockopt(socket.SOL_SOCKET, 44, 1)  # SO_LOCK_FILTER before UID drop


def restrict_process() -> None:
    """Prevent ptrace access to the retained socket and future privilege gains."""
    libc = ctypes.CDLL(None, use_errno=True)
    for option, value in ((38, 1), (4, 0)):  # NO_NEW_PRIVS, DUMPABLE
        if libc.prctl(option, value, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, "CHECKSUM_PROCESS_RESTRICTION_FAILED")


def capture(uid: int, gid: int) -> dict:
    """Called only by SHA-approved trusted entry; never generates traffic."""
    if os.geteuid() != 0 or uid <= 0 or gid <= 0:
        raise ValueError("CHECKSUM_TRUSTED_ENTRY_REQUIRED")
    if os.readlink("/proc/self/ns/net") != NAMESPACE or socket.if_nametoindex("lo") != 1:
        raise ValueError("CHECKSUM_NAMESPACE_INTERFACE_MISMATCH")
    with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, 0) as channel:
        attach_filter(channel)
        channel.setsockopt(263, 8, 1)  # PACKET_AUXDATA
        channel.setsockopt(socket.SOL_SOCKET, 35, 1)  # SO_TIMESTAMPNS on this 64-bit Linux
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
        channel.bind(("lo", 0x0800))  # ETH_P_IP; protocol zero prevented pre-bind delivery
        os.setgroups([])
        os.setresgid(gid, gid, gid)
        os.setresuid(uid, uid, uid)
        restrict_process()
        # No exec, subprocess, send, imports from repository, or authority FD handoff.
        with open("/proc/self/status") as stream:
            caps = {
                k: int(v.strip(), 16)
                for line in stream
                if (k := line.split(":", 1)[0]) in {"CapEff", "CapPrm", "CapInh", "CapAmb"}
                for v in [line.split(":", 1)[1]]
            }
        if any(caps.values()) or os.geteuid() != uid:
            raise ValueError("CHECKSUM_PRIVILEGE_DROP_FAILED")
        started = time.monotonic()
        print(
            json.dumps(
                {"state": "CHECKSUM_OBSERVER_READY", "scope": SCOPE_DIGEST, "capabilities": caps}
            ),
            flush=True,
        )
        records = []
        while len(records) < 32 and (remaining := 10 - (time.monotonic() - started)) > 0:
            channel.settimeout(remaining)
            try:
                data, controls, flags, address = channel.recvmsg(512, 256)
            except TimeoutError:
                break
            aux = [body for level, kind, body in controls if (level, kind) == (263, 8)]
            stamps = [
                body for level, kind, body in controls if (level, kind) == (socket.SOL_SOCKET, 35)
            ]
            if (
                flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                or len(aux) != 1
                or len(stamps) != 1
                or len(stamps[0]) != 16
            ):
                raise ValueError("CHECKSUM_CAPTURE_TRUNCATED_OR_METADATA_MISSING")
            seconds, nanos = struct.unpack("=qq", stamps[0])
            record = describe(data, aux[0], address[2], seconds * 10**9 + nanos)
            record["capture_sequence"] = len(records) + 1
            records.append(record)
            print(json.dumps({"state": "PACKET_EVIDENCE", "record": record}), flush=True)
        packets, drops = struct.unpack("=II", channel.getsockopt(263, 6, 8))
        return dict(
            state="CLOSED",
            records=records,
            socket_packets=packets,
            socket_drops=drops,
            duration_seconds=time.monotonic() - started,
            root_cause="ROOT_CAUSE_UNKNOWN_PENDING_PACKET_AND_ZEEK_CORRELATION",
        )

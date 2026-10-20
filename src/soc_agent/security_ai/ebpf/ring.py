"""Fixed little-endian ring ABI. Callback bytes are copied once into a bounded queue."""

import ipaddress
import struct

from soc_agent.security_ai.ebpf.models import Event, Plan

ABI = struct.Struct("<QQQIIIIHHBBBB16s16s")


def decode(raw: bytes, plan: Plan, sequence: int) -> Event:
    if len(raw) != ABI.size:
        raise ValueError("EBPF_EVENT_ABI_SIZE")
    (
        generation,
        stamp,
        cpu_seq,
        index,
        cpu,
        frame,
        length,
        sport,
        dport,
        family,
        proto,
        flags,
        hook,
        src,
        dst,
    ) = ABI.unpack(raw)
    if family not in (4, 6) or proto not in (6, 17) or hook not in (1, 2):
        raise ValueError("EBPF_EVENT_ABI_ENUM")
    if family == 4 and (any(src[4:]) or any(dst[4:])):
        raise ValueError("EBPF_IPV4_PADDING_INVALID")
    return Event(
        collector=plan.collector,
        session_id=plan.session_id,
        program_sha256=plan.program_sha256,
        plan_digest=plan.identity,
        generation=generation,
        ifindex=index,
        cpu=cpu,
        net_namespace=plan.net_namespace,
        hook="INGRESS" if hook == 1 else "EGRESS",
        delivery_sequence=sequence,
        cpu_sequence=cpu_seq,
        timestamp_ns=stamp,
        clock=plan.clock,
        source=str(ipaddress.ip_address(src[:4] if family == 4 else src)),
        destination=str(ipaddress.ip_address(dst[:4] if family == 4 else dst)),
        source_port=sport,
        destination_port=dport,
        protocol="tcp" if proto == 6 else "udp",
        frame_length=frame,
        ip_length=length,
        tcp_flags=flags,
    )

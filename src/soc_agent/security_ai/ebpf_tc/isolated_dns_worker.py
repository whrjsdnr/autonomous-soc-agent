"""Ordinary-UID responder transport for future reviewed, prebound Namespace FDs.

No bind, connect, resolver, setns, privilege change or process launch. Currently
no CLI/Supervisor starts this worker: isolated images have an unconditional
policy guard. Root-created sockets and lifecycle activation need new approval.
"""

import os
import select
import socket
import time
from collections.abc import Callable

from soc_agent.security_ai.ebpf_native.contracts import local_controller
from soc_agent.security_ai.ebpf_tc.namespace_isolation import IsolatedDNSProtocol, IsolatedScope


def serve_prebound(
    scope: IsolatedScope,
    udp: socket.socket,
    tcp: socket.socket,
    *,
    ready: Callable[[dict], None],
) -> dict:
    """Own/close supplied sockets, one UDP2/TCP1 exchange, at most60s.

    Application timestamps are diagnostic only, never Kernel Flow/Window proof.
    Namespace cookies attest socket ownership; inode equality alone is not enough.
    """
    local_controller()
    if os.readlink("/proc/self/ns/net") != scope.namespace:
        raise ValueError("ISOLATED_DNS_NAMESPACE_MISMATCH")
    # Checks happen before receiving or sending anything. The anonymous control
    # socket does not bind/connect or emit packets.
    with udp, tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        option = getattr(socket, "SO_NETNS_COOKIE", 71)
        cookie = probe.getsockopt(socket.SOL_SOCKET, option, 8)
        for channel, kind in ((udp, socket.SOCK_DGRAM), (tcp, socket.SOCK_STREAM)):
            if (
                channel.getsockname() != ("127.0.0.53", 53)
                or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != kind
                or channel.getsockopt(socket.SOL_SOCKET, option, 8) != cookie
            ):
                raise ValueError("ISOLATED_DNS_SOCKET_SCOPE")
        engine = IsolatedDNSProtocol(scope)
        deadline = time.monotonic() + 60
        tcp_closed_ns = None
        events = []
        ready(dict(state="LOCAL_DNS_READY", namespace=scope.namespace, cookie=cookie.hex()))
        while len(engine.completed) < 3:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("ISOLATED_DNS_RESPONDER_DEADLINE")
            for channel in select.select([udp, tcp], [], [], min(remaining, 0.2))[0]:
                if channel is udp:
                    request, peer = udp.recvfrom(513)
                    if peer[0] != "127.0.0.1":
                        raise ValueError("ISOLATED_DNS_PEER")
                    if request[:2] == b"\xc2\x03" and (
                        tcp_closed_ns is None
                        or time.monotonic_ns() - tcp_closed_ns < 35_000_000_000
                    ):
                        raise ValueError("ISOLATED_DNS_LATE_WITNESS_TOO_EARLY")
                    answer = engine.respond(request)
                    if udp.sendto(answer, peer) != len(answer):
                        raise OSError("ISOLATED_DNS_PARTIAL_DATAGRAM")
                    transport = "UDP"
                else:
                    with tcp.accept()[0] as stream:
                        if stream.getpeername()[0] != "127.0.0.1":
                            raise ValueError("ISOLATED_DNS_PEER")
                        stream.settimeout(min(2, max(0.001, deadline - time.monotonic())))
                        header = _exact(stream, 2, deadline)
                        length = int.from_bytes(header, "big")
                        if not 12 <= length <= 512:
                            raise ValueError("ISOLATED_DNS_TCP_BOUND")
                        answer = engine.respond(header + _exact(stream, length, deadline), tcp=True)
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError("ISOLATED_DNS_RESPONDER_DEADLINE")
                        stream.settimeout(min(2, remaining))
                        stream.sendall(answer)
                        stream.shutdown(socket.SHUT_WR)
                    tcp_closed_ns = time.monotonic_ns()
                    transport = "TCP"
                events.append(
                    dict(transport=transport, application_monotonic_ns=time.monotonic_ns())
                )
        return dict(
            state="DNS_RESPONDER_COMPLETED",
            queries=3,
            events=events,
            tcp_closed_application_ns=tcp_closed_ns,
            evidence_scope="APPLICATION_PROTOCOL_ONLY_NOT_KERNEL_FLOW_COMPLETENESS",
            capture_integrity="NOT_ASSESSED",
            native_ai="BLOCKED",
        )


def _exact(stream: socket.socket, length: int, deadline: float) -> bytes:
    value = bytearray()
    while len(value) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("ISOLATED_DNS_RESPONDER_DEADLINE")
        stream.settimeout(min(2, remaining))
        body = stream.recv(length - len(value))
        if not body:
            raise ValueError("ISOLATED_DNS_TCP_TRUNCATED")
        value.extend(body)
    return bytes(value)

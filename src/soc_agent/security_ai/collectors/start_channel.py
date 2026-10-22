"""One-shot START only, over a private session-derived Unix seqpacket channel.

Embedded verbatim in the reviewed image; no project imports or authentication.
"""

import json
import socket
import struct
import time


def start_binding(wire: bytes, image: str, manifest: str, approval: str, scope: str) -> dict:
    if len(wire) != 352 or any(
        len(v) != 64 or any(c not in "0123456789abcdef" for c in v)
        for v in (image, manifest, approval, scope)
    ):
        raise ValueError("DNS_START_BINDING")
    return dict(
        type="START",
        sequence=1,
        session=wire[64:80].hex(),
        image=image,
        manifest=manifest,
        approval=approval,
        scope=scope,
    )


def start_address(uid: int, session: str) -> str:
    if uid <= 0 or len(session) != 32 or any(c not in "0123456789abcdef" for c in session):
        raise ValueError("DNS_START_ADDRESS")
    return "\0soc-dns-start-v1:" + str(uid) + ":" + session


def start_peer(channel: socket.socket, uid: int, gid: int, pid: int) -> None:
    actual = struct.unpack("=iii", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if pid <= 0 or actual != (pid, uid, gid):
        raise ValueError("DNS_START_PEER_MISMATCH")


def start_listener(uid: int, binding: dict) -> socket.socket:
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        channel.bind(start_address(uid, binding["session"]))
        channel.listen(1)
        return channel
    except (OSError, ValueError):
        channel.close()
        raise


def start_timeout(channel: socket.socket, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("DNS_START_TIMEOUT")
    channel.settimeout(remaining)


def start_send(channel: socket.socket, binding: dict, deadline: float) -> None:
    body = json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()
    if len(body) > 1024:
        raise ValueError("DNS_START_LENGTH")
    start_timeout(channel, deadline)
    if channel.send(body) != len(body):
        raise ValueError("DNS_START_PARTIAL_SEND")


def start_receive(channel: socket.socket, binding: dict, deadline: float) -> None:
    start_timeout(channel, deadline)
    body, _, flags, _ = channel.recvmsg(1025)
    if flags & socket.MSG_TRUNC or not 1 <= len(body) <= 1024:
        raise ValueError("DNS_START_LENGTH")
    # Exact canonical bytes reject duplicate JSON keys, extra fields and replay seq.
    expected = json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()
    if body != expected:
        raise ValueError("DNS_START_BINDING_MISMATCH")
    channel.setblocking(False)
    try:
        extra = channel.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
    except BlockingIOError:
        extra = b""
    if extra:
        raise ValueError("DNS_START_REPLAY")
    # The owner closes this one-shot connection before capture. No second command.


def start_connect(uid: int, gid: int, pid: int, binding: dict, deadline: float) -> socket.socket:
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        start_timeout(channel, deadline)
        channel.connect(start_address(uid, binding["session"]))
        start_peer(channel, uid, gid, pid)
        return channel
    except (OSError, ValueError):
        channel.close()
        raise


def root_error(exc: BaseException, stage: str, api: str) -> dict:
    """Only code-like errors; never persist arbitrary exception/terminal text."""
    code = str(exc)
    # Prepared images embed only literal codes raised by their own reviewed source.
    # Arbitrary uppercase values can also be secrets, so shape alone is insufficient.
    if code not in globals().get("ROOT_ERROR_CODES", {"UNIFIED_PASSWORD_POLICY_REJECTED"}):
        code = type(exc).__name__
    return dict(
        state="DNS_COPY_ROOT_ERROR",
        stage=stage,
        api=api,
        original_code=code,
        exception_class=type(exc).__name__,
        errno=exc.errno if isinstance(exc, OSError) else None,
        exit_code=1,
        stderr_policy="OS_TTY_ONLY_NOT_RECORDED",
    )

"""v3 peer allowlist and complete v2-equivalent OS attestation, without editing v2."""

import hashlib
import os
import socket
import struct
from pathlib import Path

from soc_agent.security_ai.operational.network_capture.capture import (
    CaptureUnavailable,
    interface_identity,
)
from soc_agent.security_ai.operational.network_capture.direction_session import (
    MODULE,
    approval_digest,
)
from soc_agent.security_ai.operational.network_capture.helper_transport import Message
from soc_agent.security_ai.operational.network_capture.live_helper import process_start
from soc_agent.security_ai.operational.network_capture.live_session import Session
from soc_agent.security_ai.operational.network_capture.permissions import NET_RAW
from soc_agent.security_ai.research.models import digest


def validate_peer(channel, ready: Message, session: Session, directory: Path, *, module=MODULE):
    if module != MODULE:
        raise CaptureUnavailable("HELPER_MODULE_NOT_ALLOWLISTED")
    pid, uid, gid = struct.unpack(
        "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )
    expected_caps = dict(
        euid=session.uid,
        egid=session.gid,
        CapEff=0,
        CapPrm=0,
        CapInh=0,
        CapAmb=0,
        CapBnd=NET_RAW,
        NoNewPrivs=1,
    )
    if (
        ready.kind != "READY"
        or (pid, uid, gid) != (ready.pid, session.uid, session.gid)
        or ready.session_id != session.session_id
        or ready.capabilities != expected_caps
        or process_start(pid) != ready.process_start
    ):
        raise CaptureUnavailable("HELPER_READY_PEER_MISMATCH")
    arguments = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    expected = [b"-I", b"-m", module.encode(), b"--directory", os.fsencode(directory)]
    expected.extend([b"--session-digest", digest(session.model_dump(mode="json")).encode()])
    expected.extend([b"--approval-digest", approval_digest(session).encode()])
    if arguments[1:-1] != expected:
        raise CaptureUnavailable("HELPER_COMMAND_MISMATCH")
    if hashlib.sha256(Path(f"/proc/{pid}/exe").read_bytes()).hexdigest() != session.python_sha256:
        raise CaptureUnavailable("HELPER_INTERPRETER_MISMATCH")
    fields = dict(
        line.split(":", 1)
        for line in Path(f"/proc/{pid}/status").read_text().splitlines()
        if ":" in line
    )
    for key, value in (("Uid", session.uid), ("Gid", session.gid)):
        if tuple(map(int, fields[key].split())) != (value,) * 4:
            raise CaptureUnavailable("HELPER_OS_IDENTITY_MISMATCH")
    if (
        fields["Groups"].strip()
        or any(
            int(fields[k], 16) != expected_caps[k]
            for k in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")
        )
        or int(fields["NoNewPrivs"]) != 1
    ):
        raise CaptureUnavailable("HELPER_CAPABILITIES_NOT_DROPPED")
    if os.readlink(f"/proc/{pid}/fd/{ready.socket_fd}") != f"socket:[{ready.socket_inode}]":
        raise CaptureUnavailable("HELPER_CAPTURE_SOCKET_MISMATCH")
    rows = [
        line.split()
        for line in Path("/proc/net/packet").read_text().splitlines()[1:]
        if line.split()[-1] == str(ready.socket_inode)
    ]
    if (
        len(rows) != 1
        or (int(rows[0][2]), int(rows[0][3], 16), int(rows[0][4]), int(rows[0][7]))
        != (socket.SOCK_RAW, 3, socket.if_nametoindex("lo"), session.uid)
        or interface_identity("lo") != session.interface_id
    ):
        raise CaptureUnavailable("HELPER_INTERFACE_SOCKET_BINDING_MISMATCH")

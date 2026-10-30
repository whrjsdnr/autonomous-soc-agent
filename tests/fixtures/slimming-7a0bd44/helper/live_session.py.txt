"""Operator-reviewed bounded session. This module never executes a privilege command."""

import hashlib
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from pydantic import Field

from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
    validate_directory,
    validate_file,
)
from soc_agent.security_ai.operational.network_capture.capture import interface_identity
from soc_agent.security_ai.operational.network_capture.permissions import privileges
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import Frozen, digest

MODULE = "soc_agent.security_ai.operational.network_capture.live_helper"
CODE = (
    "live_helper.py",
    "live_session.py",
    "capture.py",
    "permissions.py",
    "parsing.py",
    "models.py",
)


def unprivileged():
    state = privileges()
    if (
        os.getuid() == 0
        or os.getuid() != os.geteuid()
        or os.getgid() != os.getegid()
        or any(state[k] != 0 for k in ("CapEff", "CapPrm", "CapInh", "CapAmb"))
    ):
        raise ValueError("UNPRIVILEGED_LIVE_CONTROLLER_REQUIRED")


def code_hashes():
    return {
        name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
        for name in CODE
    }


class Session(Frozen):
    contract: Literal["soc-live-capture-session:v1"] = "soc-live-capture-session:v1"
    session_id: UUID
    uid: int = Field(gt=0, strict=True)
    gid: int = Field(gt=0, strict=True)
    interface: Literal["lo"] = "lo"
    interface_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    seconds: int = Field(default=60, strict=True, ge=1, le=60)
    max_packets: int = Field(default=512, strict=True, ge=1, le=512)
    python: str
    python_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    code_sha256: dict[str, str]

    @property
    def socket_address(self):
        # Abstract AF_UNIX avoids long filesystem paths. SO_PEERCRED and READY
        # process/socket inspection, not this name, provide the source boundary.
        return "\0soc-live-" + str(self.session_id)


def prepare(directory: Path, *, seconds=60, max_packets=512) -> Session:
    unprivileged()
    session = Session(
        session_id=uuid4(),
        uid=os.getuid(),
        gid=os.getgid(),
        interface_id=interface_identity("lo"),
        seconds=seconds,
        max_packets=max_packets,
        python=str(Path(sys.executable).absolute()),
        python_sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        code_sha256=code_hashes(),
    )
    create_private_directory(directory, exist_ok=False)
    with (directory / "session.json").open("x") as stream:
        stream.write(session.model_dump_json())
    (directory / "session.json").chmod(0o600)
    create_private_file(directory / "helper.lock")
    return session


def load_session(directory: Path) -> Session:
    validate_directory(directory)
    validate_file(directory / "helper.lock")
    session = Session.model_validate_json(read_local(directory / "session.json", 8192))
    if (
        session.uid != os.getuid()
        or session.gid != os.getgid()
        or Path(session.python).absolute() != Path(sys.executable).absolute()
        or hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest() != session.python_sha256
        or session.code_sha256 != code_hashes()
        or session.interface_id != interface_identity(session.interface)
    ):
        raise ValueError("LIVE_SESSION_CODE_IDENTITY_OR_INTERFACE_CHANGED")
    return session


def instructions(directory: Path, session: Session) -> dict:
    return {
        "status": "USER_TERMINAL_AUTHENTICATION_REQUIRED",
        "session_id": str(session.session_id),
        "interface": session.interface,
        "seconds": session.seconds,
        "packet_limit": session.max_packets,
        "helper_sha256": session.code_sha256["live_helper.py"],
        "session_digest": digest(session.model_dump(mode="json")),
        "authentication": "Run sudo -v yourself; the GUI never receives a password.",
        "command": shlex.join(
            [
                "sudo",
                "-n",
                "/usr/bin/setpriv",
                f"--reuid={session.uid}",
                f"--regid={session.gid}",
                "--clear-groups",
                "--bounding-set=-all,+net_raw",
                "--inh-caps=-all,+net_raw",
                "--ambient-caps=-all,+net_raw",
                "--no-new-privs",
                session.python,
                "-I",
                "-m",
                MODULE,
                "--directory",
                str(directory),
            ]
        ),
        "stop": "Ctrl+C in the helper terminal, Stop live in GUI, disconnect, or bounded deadline.",
        "privacy": "IP/port/timing/length/flag metadata only; no payload or DNS names retained.",
        "operational_gate": "OPERATIONAL_INFERENCE_BLOCKED",
    }


def write_private(path: Path, value: dict):
    # For new immutable receipts only. Never replaces pre-existing evidence.
    with path.open("x") as stream:
        json.dump(value, stream)
    path.chmod(0o600)

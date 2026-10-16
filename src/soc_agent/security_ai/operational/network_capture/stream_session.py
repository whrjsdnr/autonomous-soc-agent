"""Separate reviewed managed-capture contract. Never launches a privileged process."""

import hashlib
import math
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
from soc_agent.security_ai.operational.network_capture.live_session import unprivileged
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import Frozen, digest

MODULE = "soc_agent.security_ai.operational.network_capture.stream_helper"
CODE = (
    "stream_helper.py",
    "stream_session.py",
    "live_helper.py",
    "capture.py",
    "permissions.py",
    "parsing.py",
    "models.py",
)


class StreamPolicy(Frozen):
    contract: Literal["soc-managed-stream-policy:v1"] = "soc-managed-stream-policy:v1"
    interface: Literal["lo"] = "lo"
    dns_headers: bool = Field(default=True, strict=True)
    seconds: int = Field(default=300, strict=True, ge=1, le=1800)
    frames_per_second: int = Field(default=128, strict=True, ge=1, le=128)
    burst_frames: int = Field(default=256, strict=True, ge=1, le=256)
    transport_capacity: int = Field(default=512, strict=True, ge=16, le=512)
    inference_capacity: int = Field(default=8, strict=True, ge=1, le=8)
    max_inferences: int = Field(default=64, strict=True, ge=2, le=256)
    max_flow_records: int = Field(default=1024, strict=True, ge=1, le=1024)
    active_flows: int = Field(default=128, strict=True, ge=1, le=128)
    metadata_bytes: int = Field(default=8 * 1024**2, strict=True, ge=8192, le=16 * 1024**2)
    rss_bytes: int = Field(default=768 * 1024**2, strict=True, ge=384 * 1024**2, le=1024**3)
    disk_bytes: int = Field(default=64 * 1024**2, strict=True, ge=8 * 1024**2, le=128 * 1024**2)
    graceful_seconds: int = Field(default=30, strict=True, ge=1, le=60)
    qualification: Literal["FIXTURE_POLICY_NATIVE_RESOURCE_VALIDATION_PENDING"] = (
        "FIXTURE_POLICY_NATIVE_RESOURCE_VALIDATION_PENDING"
    )

    @property
    def frame_budget(self):
        return self.seconds * self.frames_per_second + self.burst_frames

    @property
    def helper_cpu_seconds(self):
        return math.ceil(5 + self.seconds * 0.1)

    @property
    def controller_cpu_seconds(self):
        return 10 + self.seconds * 0.5


class StreamSession(Frozen):
    contract: Literal["soc-managed-stream-session:v1"] = "soc-managed-stream-session:v1"
    session_id: UUID
    uid: int = Field(gt=0, strict=True)
    gid: int = Field(gt=0, strict=True)
    interface_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy: StreamPolicy
    python: str
    python_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    code_sha256: dict[str, str]

    @property
    def interface(self):
        return self.policy.interface

    @property
    def seconds(self):
        return self.policy.seconds

    @property
    def max_packets(self):
        return self.policy.frame_budget

    @property
    def socket_address(self):
        return "\0soc-stream-network-" + str(self.session_id)


def code_hashes():
    return {n: hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in CODE}


def prepare(directory: Path, policy: StreamPolicy) -> StreamSession:
    unprivileged()
    session = StreamSession(
        session_id=uuid4(),
        uid=os.getuid(),
        gid=os.getgid(),
        interface_id=interface_identity("lo"),
        policy=policy,
        python=str(Path(sys.executable).absolute()),
        python_sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        code_sha256=code_hashes(),
    )
    create_private_directory(directory, exist_ok=False)
    create_private_file(directory / "helper.lock")
    with (directory / "session.json").open("x") as stream:
        stream.write(session.model_dump_json())
    (directory / "session.json").chmod(0o600)
    return session


def load(directory: Path) -> StreamSession:
    validate_directory(directory)
    validate_file(directory / "helper.lock")
    session = StreamSession.model_validate_json(read_local(directory / "session.json", 16384))
    if (
        session.uid != os.getuid()
        or session.gid != os.getgid()
        or session.interface_id != interface_identity("lo")
        or session.code_sha256 != code_hashes()
        or Path(session.python).absolute() != Path(sys.executable).absolute()
        or hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest() != session.python_sha256
    ):
        raise ValueError("STREAM_CODE_IDENTITY_OR_INTERFACE_MISMATCH")
    return session


def instructions(directory: Path, session: StreamSession) -> dict:
    return dict(
        status="NEW_HELPER_USER_APPROVAL_REQUIRED",
        helper_sha256=session.code_sha256["stream_helper.py"],
        session_digest=digest(session.model_dump(mode="json")),
        policy=session.policy.model_dump(mode="json"),
        interface="lo",
        session_id=str(session.session_id),
        authentication="Authenticate yourself in terminal; no credentials enter SOC GUI.",
        command=shlex.join(
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
                "--session-digest",
                digest(session.model_dump(mode="json")),
            ]
        ),
        stop="Graceful stop in GUI, Ctrl+C, disconnect or finite session deadline.",
        operational_gate="OPERATIONAL_INFERENCE_BLOCKED",
        privacy=(
            "Metadata only; no raw payload/DNS names. "
            "New approval; legacy v2 approval does not apply."
        ),
    )


class RateBudget:
    def __init__(self, rate: int, burst: int, now: float):
        self.rate, self.burst, self.tokens, self.last = rate, burst, float(burst), now

    def consume(self, now: float):
        if now < self.last:
            raise ValueError("STREAM_MONOTONIC_CLOCK_REVERSED")
        self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens < 1:
            raise ValueError("STREAM_RATE_BUDGET_EXCEEDED")
        self.tokens -= 1

"""Separately approved DNS metadata scope over the existing capture engine."""

import hashlib
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Literal
from uuid import uuid4

from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
    validate_directory,
    validate_file,
)
from soc_agent.security_ai.operational.network_capture.capture import interface_identity
from soc_agent.security_ai.operational.network_capture.live_session import unprivileged
from soc_agent.security_ai.operational.network_capture.stream_session import (
    CODE,
    StreamPolicy,
    StreamSession,
)
from soc_agent.security_ai.operational.network_capture.stream_session import (
    instructions as base_instructions,
)
from soc_agent.security_ai.research.environment import read_local

MODULE = "soc_agent.security_ai.operational.network_capture.total_helper"
FILES = (*CODE, "total_session.py", "total_helper.py")


class TotalSession(StreamSession):
    contract: Literal["soc-total-monitoring-session:v1"] = "soc-total-monitoring-session:v1"


def code_hashes():
    return {n: hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in FILES}


def verify_bundle():
    expected = json.loads(read_local(Path(__file__).with_name("total-helper-manifest.json"), 16384))
    if expected != code_hashes():
        raise ValueError("TOTAL_HELPER_BUNDLE_MISMATCH")
    return expected


def validate_policy(policy):
    if policy != StreamPolicy():
        raise ValueError("TOTAL_EXACT_REVIEWED_POLICY_REQUIRED")


def prepare(directory, policy):
    unprivileged()
    validate_policy(policy)
    hashes = verify_bundle()
    session = TotalSession(
        session_id=uuid4(),
        uid=os.getuid(),
        gid=os.getgid(),
        interface_id=interface_identity("lo"),
        policy=policy,
        python=str(Path(sys.executable).absolute()),
        python_sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        code_sha256=hashes,
    )
    create_private_directory(directory, exist_ok=False)
    create_private_file(directory / "helper.lock")
    create_private_file(directory / "session.json")
    (directory / "session.json").write_text(session.model_dump_json())
    return session


def load(directory):
    validate_directory(directory)
    validate_file(directory / "helper.lock")
    validate_file(directory / "session.json")
    session = TotalSession.model_validate_json(read_local(directory / "session.json", 16384))
    validate_policy(session.policy)
    if (
        session.code_sha256 != verify_bundle()
        or session.uid != os.getuid()
        or session.gid != os.getgid()
        or session.interface_id != interface_identity("lo")
        or Path(session.python).absolute() != Path(sys.executable).absolute()
        or hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest() != session.python_sha256
    ):
        raise ValueError("TOTAL_SESSION_IDENTITY_MISMATCH")
    return session


def instructions(directory, session):
    result = base_instructions(directory, session)
    arguments = shlex.split(result["command"])
    arguments[arguments.index("-m") + 1] = MODULE
    return {
        **result,
        "command": shlex.join(arguments),
        "helper_sha256": session.code_sha256["total_helper.py"],
        "privacy": "DNS question digest/type/id/rcode only; no names or payload. DNS9 BLOCKED.",
        "status": "NEW_TOTAL_HELPER_APPROVAL_REQUIRED",
    }

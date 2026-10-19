"""Separate SHA/policy/session-bound approval scope. Legacy manifests are untouched."""

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
from soc_agent.security_ai.operational.network_capture.calibrated_policy import require_headroom
from soc_agent.security_ai.operational.network_capture.capture import interface_identity
from soc_agent.security_ai.operational.network_capture.direction_policy import (
    DirectionPolicy,
)
from soc_agent.security_ai.operational.network_capture.live_session import unprivileged
from soc_agent.security_ai.operational.network_capture.stream_session import StreamSession
from soc_agent.security_ai.operational.network_capture.total_session import FILES as LEGACY_FILES
from soc_agent.security_ai.operational.network_capture.total_session import (
    instructions as legacy_instructions,
)
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import digest

MODULE = "soc_agent.security_ai.operational.network_capture.direction_helper"
FILES = (
    *LEGACY_FILES,
    "live_session.py",
    "calibrated_policy.py",
    "direction_policy.py",
    "direction_session.py",
    "direction_helper.py",
    "helper_transport.py",
    "isolated_flow.py",
    "total_transport.py",
    "stream_transport.py",
    "direction_transport.py",
    "direction_peer.py",
)


class DirectionSession(StreamSession):
    contract: Literal["soc-total-direction-session:v3"] = "soc-total-direction-session:v3"
    policy: DirectionPolicy


def code_hashes():
    return {n: hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in FILES}


def verify_bundle():
    expected = json.loads(
        read_local(Path(__file__).with_name("direction-helper-manifest.json"), 16384)
    )
    if expected != code_hashes():
        raise ValueError("V3_HELPER_BUNDLE_MISMATCH")
    return expected


def approval_digest(session):
    return digest(
        dict(
            contract="soc-direction-explicit-approval:v3",
            session_digest=digest(session.model_dump(mode="json")),
            bundle_digest=digest(session.code_sha256),
            policy=session.policy.model_dump(mode="json"),
        )
    )


def prepare(directory, policy):
    unprivileged()
    require_headroom()
    policy = DirectionPolicy.model_validate(policy.model_dump())
    session = DirectionSession(
        session_id=uuid4(),
        uid=os.getuid(),
        gid=os.getgid(),
        interface_id=interface_identity("lo"),
        policy=policy,
        python=str(Path(sys.executable).absolute()),
        python_sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        code_sha256=verify_bundle(),
    )
    create_private_directory(directory, exist_ok=False)
    for n in ("helper.lock", "session.json"):
        create_private_file(directory / n)
    (directory / "session.json").write_text(session.model_dump_json())
    return session


def load(directory):
    validate_directory(directory)
    for n in ("helper.lock", "session.json"):
        validate_file(directory / n)
    session = DirectionSession.model_validate_json(read_local(directory / "session.json", 16384))
    if (
        session.uid != os.getuid()
        or session.gid != os.getgid()
        or session.interface_id != interface_identity("lo")
        or session.code_sha256 != verify_bundle()
        or Path(session.python).absolute() != Path(sys.executable).absolute()
        or hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest() != session.python_sha256
    ):
        raise ValueError("V3_SESSION_IDENTITY_MISMATCH")
    return session


def instructions(directory, session):
    result = legacy_instructions(directory, session)
    args = shlex.split(result["command"])
    args[args.index("-m") + 1] = MODULE
    args.extend(["--approval-digest", approval_digest(session)])
    return {
        **result,
        "command": shlex.join(args),
        "helper_sha256": session.code_sha256["direction_helper.py"],
        "bundle_digest": digest(session.code_sha256),
        "policy_name": session.policy.policy_name,
        "approval_state": "APPROVAL_REQUIRED",
        "approval_digest": approval_digest(session),
        "status": "V3_HELPER_SEPARATE_APPROVAL_REQUIRED",
    }

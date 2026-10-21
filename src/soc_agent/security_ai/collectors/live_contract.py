"""Separate, reviewable Zeek Native scope. Creating a plan grants no capture authority."""

import os
import re
import shlex
import sys
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from pydantic import Field

from soc_agent.security_ai.collectors.offline import IMAGE, file_digest
from soc_agent.security_ai.research.models import Frozen, digest

FILES = (
    "live.py",
    "startup.py",
    "handoff.py",
    "live_contract.py",
    "live_process.py",
    "live_stream.py",
    "finalization.py",
    "integrity.py",
    "integrity_service.py",
    "live.zeek",
    "network14.zeek",
    "packet_input.py",
    "packet_metadata.py",
    "packet_producer.py",
    "preprocessing.py",
    "preprocessing_store.py",
    "capture_attestation.py",
    "dns_visibility.py",
    "attestation_store.py",
    "visibility.zeek",
    "privacy.zeek",
    "offline.py",
    "reader.py",
    "models.py",
    "adapter.py",
)


def bundle() -> dict[str, str]:
    root = Path(__file__).parent
    hashes = {name: file_digest(root / name) for name in FILES}
    # Authentication and source admission are part of the reviewed execution boundary.
    for name, path in {
        "soc_agent/cli.py": root.parents[1] / "cli.py",
        "research/total_auth.py": root.parent / "research/total_auth.py",
        "producer_service.py": root / "producer_service.py",
        "gui/__main__.py": root.parents[1] / "gui/__main__.py",
        "gui/production.py": root.parents[1] / "gui/production.py",
        "gui/backend.py": root.parents[1] / "gui/backend.py",
        "gui/worker.py": root.parents[1] / "gui/worker.py",
    }.items():
        hashes[name] = file_digest(path)
    return hashes


class LivePlan(Frozen):
    contract: Literal["soc-zeek-native-plan:v4"] = "soc-zeek-native-plan:v4"
    session_id: UUID = Field(default_factory=uuid4)
    controller_generation: UUID = Field(default_factory=uuid4)
    image: Literal[IMAGE] = IMAGE
    interface: Literal["lo"] = "lo"
    duration_seconds: int = Field(default=300, ge=1, le=300, strict=True)
    cpu_limit: Literal[1] = 1
    memory_mib: Literal[512] = 512
    disk_mib: Literal[16] = 16
    output_bytes: Literal[8388608] = 8388608
    queue_capacity: Literal[32] = 32
    packet_limit: Literal[4096] = 4096
    event_limit: Literal[8192] = 8192
    net_namespace: str = Field(pattern=r"^net:\[[0-9]+\]$")
    bundle_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    capture_integrity: Literal["UNVERIFIED_PCAP_STATS_FAILURE_SIGNAL"] = (
        "UNVERIFIED_PCAP_STATS_FAILURE_SIGNAL"
    )
    native_inference: Literal["BLOCKED"] = "BLOCKED"

    @property
    def identity(self) -> str:
        return digest(self.model_dump(mode="json"))


def new_plan() -> LivePlan:
    if os.geteuid() == 0:
        raise ValueError("ZEEK_NO_ROOT_GUI_OR_LAUNCHER")
    return LivePlan(net_namespace=os.readlink("/proc/self/ns/net"), bundle_digest=digest(bundle()))


def verify(plan: LivePlan, approval: str):
    if approval != plan.identity:
        raise ValueError("ZEEK_APPROVAL_DIGEST_MISMATCH")
    if plan.bundle_digest != digest(bundle()):
        raise ValueError("ZEEK_LIVE_BUNDLE_CHANGED")
    if os.geteuid() == 0:
        raise ValueError("ZEEK_NO_ROOT_GUI_OR_LAUNCHER")
    if os.readlink("/proc/self/ns/net") != plan.net_namespace:
        raise ValueError("ZEEK_NETWORK_NAMESPACE_CHANGED")


def command(directory: Path, plan: LivePlan) -> str:
    return shlex.join(
        [
            sys.executable,
            "-m",
            "soc_agent.security_ai.collectors.live_process",
            "--session",
            str(directory),
            "--approve",
            plan.identity,
        ]
    )


def docker_argv(plan: LivePlan, policy: Path, *, fixture: Path | None = None) -> list[str]:
    """Only manual launcher calls this with a live interface. Never run by GUI prepare."""
    if not re.fullmatch(r"[a-f0-9]{64}", plan.bundle_digest):
        raise ValueError("ZEEK_LIVE_BUNDLE_INVALID")
    if any(c in str(policy) for c in ",\n\r"):
        raise ValueError("ZEEK_POLICY_PATH_INVALID")
    argv = [
        "docker",
        "run",
        "--rm",
        "--stop-signal=SIGINT",
        "--stop-timeout=5",
        "--label",
        "soc.plan=" + plan.identity,
        "--label",
        "soc.generation=" + str(plan.controller_generation),
        "--pull=never",
        "--log-driver=none",
        "--name",
        "soc-zeek-" + plan.session_id.hex,
        "--network=none" if fixture else "--network=host",
        "--cap-drop=ALL",
        "--read-only",
        "--security-opt=no-new-privileges",
        "--memory=512m",
        "--memory-swap=512m",
        "--cpus=1",
        "--pids-limit=64",
        "--tmpfs",
        "/work:rw,noexec,nosuid,nodev,size=16m,mode=1777",
        "--workdir",
        "/work",
        "--ulimit",
        "fsize=8388608:8388608",
    ]
    if fixture:
        if any(c in str(fixture) for c in ",\n\r"):
            raise ValueError("ZEEK_FIXTURE_PATH_INVALID")
        argv += [
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--mount",
            f"type=bind,source={fixture.absolute()},target=/input/input.pcap,readonly",
        ]
    else:
        argv += ["--cap-add=NET_RAW", "--user", "0:0"]
    # Mount only reviewed scripts. No host output mount, Docker socket or raw PCAP writing.
    for name in ("live.zeek", "network14.zeek", "visibility.zeek"):
        argv += ["--mount", f"type=bind,source={policy / name},target=/policy/{name},readonly"]
    argv += ["--entrypoint", "/bin/sh", IMAGE, "-c"]
    program = "exec /usr/bin/timeout -s INT -k 2s " + str(plan.duration_seconds)
    program += "s /usr/local/zeek/bin/zeek "
    program += "-r /input/input.pcap" if fixture else "-i lo -f 'ip or ip6'"
    program += " /policy/live.zeek"
    if not fixture:
        # No interface is opened until the Docker daemon's namespace matches the GUI's.
        program = '[ "$(readlink /proc/self/ns/net)" = "$1" ] || exit 70; ' + program
    argv += [program, "soc-zeek", plan.net_namespace]
    return argv

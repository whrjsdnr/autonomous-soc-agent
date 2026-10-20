"""Application authority and per-run identity are deliberately separate."""

import os
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from pydantic import Field

from soc_agent.review.models import Hash
from soc_agent.security_ai.research.models import Frozen, digest


class ProcessIdentity(Frozen):
    pid: int = Field(gt=0, strict=True)
    start_ticks: int = Field(gt=0, strict=True)
    uid: int = Field(ge=0, strict=True)


def process_identity(pid: int) -> ProcessIdentity:
    root = Path(f"/proc/{pid}")
    stat = (root / "stat").read_text().rsplit(")", 1)[1].split()
    uid = int(
        next(
            line for line in (root / "status").read_text().splitlines() if line.startswith("Uid:")
        ).split()[1]
    )
    return ProcessIdentity(pid=pid, start_ticks=int(stat[19]), uid=uid)


def alive(identity: ProcessIdentity) -> bool:
    try:
        return process_identity(identity.pid) == identity
    except (OSError, ValueError, StopIteration):
        return False


class Scope(Frozen):
    interface: Literal["lo"] = "lo"
    ifindex: int = Field(gt=0, strict=True)
    net_namespace: str = Field(pattern=r"^net:\[[0-9]+\]$")
    hook: Literal["INGRESS", "EGRESS"]
    program_sha256: Hash
    loader_sha256: Hash
    bundle_digest: Hash
    max_duration_seconds: Literal[300] = 300
    max_events: Literal[4096] = 4096
    queue_capacity: Literal[32] = 32
    memory_mib: Literal[128] = 128
    cpu_limit: Literal[1] = 1
    max_runs: Literal[16] = 16
    max_scope_revisions: Literal[16] = 16
    max_audit_events: Literal[256] = 256
    application_deadline_seconds: Literal[3600] = 3600
    capabilities: tuple[Literal["CAP_BPF"], Literal["CAP_NET_ADMIN"]] = ("CAP_BPF", "CAP_NET_ADMIN")


class ApplicationPlan(Frozen):
    application_session: UUID = Field(default_factory=uuid4)
    controller: ProcessIdentity
    scope: Scope
    mode: Literal["PHASE_A_NATIVE_BLOCKED", "PHASE_A_FIXTURE"]
    authentication_policy: Literal["TERMINAL_PASSWORD_ONCE_PER_APPLICATION:v1"] = (
        "TERMINAL_PASSWORD_ONCE_PER_APPLICATION:v1"
    )

    @property
    def identity(self) -> str:
        return digest(self.model_dump(mode="json"))


class RunIdentity(Frozen):
    capture_session: UUID = Field(default_factory=uuid4)
    generation: UUID = Field(default_factory=uuid4)
    application_session: UUID
    scope_digest: Hash
    run_number: int = Field(ge=1, le=16, strict=True)


def controller_unprivileged() -> bool:
    try:
        rows = Path("/proc/self/status").read_text().splitlines()
        values = {
            line.split(":", 1)[0]: int(line.split()[1], 16)
            for line in rows
            if line.startswith(("CapEff:", "CapPrm:", "CapAmb:"))
        }
        return os.getuid() == os.geteuid() != 0 and len(values) == 3 and not any(values.values())
    except (OSError, ValueError):
        return False


def local_controller() -> ProcessIdentity:
    value = process_identity(os.getpid())
    if value.uid == 0 or os.geteuid() != value.uid or not controller_unprivileged():
        raise ValueError("EBPF_NON_ROOT_CONTROLLER_REQUIRED")
    return value

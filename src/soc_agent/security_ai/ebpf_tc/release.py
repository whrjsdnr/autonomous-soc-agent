"""Read-only installation qualification and unprivileged deployment planning.

This module never installs, elevates, authenticates or executes staged artifacts.
A plan/fixture is not trusted installation evidence or Native admission.
"""

import hashlib
import os
import stat
from contextlib import ExitStack
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from soc_agent.review.models import Hash
from soc_agent.security_ai.ebpf_tc.build import bundle
from soc_agent.security_ai.research.models import Frozen, digest

INSTALL = Path("/usr/libexec/soc-agent-ebpf")
MODES = {
    "entry": 0o4755,
    "bootstrap": 0o555,
    "broker": 0o555,
    "libnative-tc.so": 0o444,
    "tc.bpf.o": 0o444,
    "manifest.bin": 0o444,
}


class InstallationPlan(Frozen):
    contract: Literal["soc-ebpf-installation-plan:v1"] = "soc-ebpf-installation-plan:v1"
    destination: Literal["/usr/libexec/soc-agent-ebpf"] = "/usr/libexec/soc-agent-ebpf"
    artifacts: dict[str, Hash]
    source_bundle: Hash
    owner_uid: Literal[0] = 0
    owner_gid: Literal[0] = 0
    state: Literal["UNPRIVILEGED_PLAN_NOT_INSTALLED"] = "UNPRIVILEGED_PLAN_NOT_INSTALLED"
    native_admission: Literal[False] = False

    @model_validator(mode="after")
    def fixed_files(self) -> Self:
        if set(self.artifacts) != set(MODES):
            raise ValueError("INSTALLATION_ARTIFACT_ALLOWLIST")
        return self


def installation_plan(artifacts: dict[str, str], program_sha: Hash) -> InstallationPlan:
    """Only generate instructions; no chown/chmod/copy/system write side effects."""
    names = ("bootstrap", "broker", "libnative-tc.so")
    hashes = {n: artifacts[n] for n in names} | {"tc.bpf.o": program_sha}
    source = digest(bundle())
    manifest = b"".join(bytes.fromhex(hashes[n]) for n in (*names, "tc.bpf.o"))
    hashes["entry"] = artifacts["entry"]
    hashes["manifest.bin"] = hashlib.sha256(manifest + bytes.fromhex(source)).hexdigest()
    return InstallationPlan(artifacts=hashes, source_bundle=source)


def _directory(info: os.stat_result, owner: int) -> None:
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
        raise ValueError("INSTALLATION_PARENT_UNTRUSTED")


def _open_file(directory: int, name: str, expected: str, mode: int, *, owner: int = 0) -> int:
    # The private owner argument permits ordinary-UID filesystem fixtures only.
    # Public qualification always supplies UID 0, never caller configuration.
    if not name or "/" in name or name in {".", ".."}:
        raise ValueError("INSTALLATION_PATH_INVALID")
    _directory(os.fstat(directory), owner)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner
            or before.st_gid != 0
            and owner == 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
            or not 0 < before.st_size <= 1048576
        ):
            raise ValueError("INSTALLATION_FILE_UNTRUSTED")
        body = os.pread(fd, before.st_size + 1, 0)
        after = os.fstat(fd)
        if hashlib.sha256(body).hexdigest() != expected or (
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("INSTALLATION_FILE_CHANGED")
        return fd  # All consumers use held descriptors, never reopen by pathname.
    except BaseException:
        os.close(fd)
        raise


def validate_installation(plan: InstallationPlan) -> dict[str, str]:
    """Read-only root-owned file check, not DSO/PAM/Native execution qualification."""
    with ExitStack() as stack:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        stack.callback(os.close, fd)
        _directory(os.fstat(fd), 0)
        for component in INSTALL.parts[1:]:
            fd = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd
            )
            stack.callback(os.close, fd)
            _directory(os.fstat(fd), 0)
        for name, mode in MODES.items():
            verified = _open_file(fd, name, plan.artifacts[name], mode)
            stack.callback(os.close, verified)
    return {
        "file_contract": "VERIFIED",
        "dependency_closure": "UNVERIFIED",
        "native_release": "BLOCKED",
    }


EvidenceState = Literal[
    "NOT_OBSERVED", "FIXTURE_ONLY", "NATIVE_PENDING", "VERIFIED", "FAILED", "UNVERIFIED"
]


class ReleaseEvidence(Frozen):
    """Native proof must come from separately reviewed evidence, never a fixture flag."""

    trusted_installation: EvidenceState = Field(default="NOT_OBSERVED", max_length=64)
    authentication_boundary: EvidenceState = Field(default="NOT_OBSERVED", max_length=64)
    broker_ipc: EvidenceState = Field(default="FIXTURE_ONLY", max_length=64)
    capability_scope: EvidenceState = Field(default="NATIVE_PENDING", max_length=64)
    tc_ownership: EvidenceState = Field(default="FIXTURE_ONLY", max_length=64)
    safe_detach: Literal["BLOCKED_NO_ATOMIC_OWNERSHIP"] = "BLOCKED_NO_ATOMIC_OWNERSHIP"
    cleanup_recovery: EvidenceState = Field(default="FIXTURE_ONLY", max_length=64)
    kernel_compatibility: EvidenceState = Field(default="NATIVE_PENDING", max_length=64)

    def snapshot(self) -> dict[str, object]:
        return {
            "state": "BLOCKED",
            "native_gate": "B2A_CLOSED",
            "safe_detach": self.safe_detach,
            "kernel_compatibility": self.kernel_compatibility,
            "evidence": self.model_dump(),
            "native_ai": "BLOCKED",
            "authentication_restored": False,
            "automatic_attach": False,
        }

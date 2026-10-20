"""Unprivileged TCX release packaging and crash-safe installation *simulation*.

No root installer, setuid bit, file capabilities, PAM write or Native activation.
The fixed bootstrap directory is preserved; JSON supplements its 160-byte manifest.
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from soc_agent.review.models import Hash
from soc_agent.security_ai.ebpf_tc.build import ROOT, bundle
from soc_agent.security_ai.ebpf_tc.dependencies import (
    Dependency,
    inventory,
    read_held,
    verify_dependencies,
)
from soc_agent.security_ai.ebpf_tc.dynamic_trust import DynamicTrust, dependency_trust
from soc_agent.security_ai.ebpf_tc.release import INSTALL, MODES, _directory, _open_file
from soc_agent.security_ai.research.models import Frozen, digest

FILES = (*MODES, "pam-policy.conf")
SOURCE_NAMES = {
    "bootstrap": "bootstrap",
    "broker": "broker",
    "libnative-tc.so": "libnative-tc.so",
    "tc.bpf.o": "tcx.bpf.o",
}


def canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class Payload(Frozen):
    sha256: Hash
    size: int = Field(gt=0, le=1048576)
    root_uid: Literal[0] = 0
    root_gid: Literal[0] = 0
    mode: int


class SystemConfiguration(Frozen):
    path: Literal["/etc/ld.so.cache", "/etc/nsswitch.conf"]
    sha256: Hash
    size: int = Field(gt=0, le=1048576)
    mode: int = Field(ge=0, le=0o777)


class ReleaseManifest(Frozen):
    contract: Literal["soc-tcx-trusted-release:v1"] = "soc-tcx-trusted-release:v1"
    version: str = Field(pattern=r"^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$")
    destination: Literal["/usr/libexec/soc-agent-ebpf"] = "/usr/libexec/soc-agent-ebpf"
    payloads: dict[str, Payload]
    dependencies: tuple[Dependency, ...] = Field(min_length=1, max_length=64)
    bundle_digest: Hash
    dynamic_trust: DynamicTrust
    system_configuration: tuple[SystemConfiguration, SystemConfiguration]
    pam_service: Literal["soc-agent-ebpf"] = "soc-agent-ebpf"
    pam_destination: Literal["/etc/pam.d/soc-agent-ebpf"] = "/etc/pam.d/soc-agent-ebpf"
    capabilities: tuple[Literal["CAP_BPF"], Literal["CAP_NET_ADMIN"]] = ("CAP_BPF", "CAP_NET_ADMIN")
    interfaces: tuple[Literal["lo"]] = ("lo",)
    hooks: tuple[Literal["INGRESS"], Literal["EGRESS"]] = ("INGRESS", "EGRESS")
    duration_seconds: Literal[300] = 300
    events: Literal[4096] = 4096
    queue_capacity: Literal[32] = 32
    broker_address_space_mib: Literal[256] = 256
    cpu_seconds: Literal[20] = 20
    application_seconds: Literal[3600] = 3600
    max_runs: Literal[16] = 16
    runtime_directory: Literal["USER_0700_SESSION_DIRECTORY_NO_PERSISTENT_AUTHORITY"] = (
        "USER_0700_SESSION_DIRECTORY_NO_PERSISTENT_AUTHORITY"
    )
    kernel_contract: Literal["LINUX_6_18_SOURCE_NATIVE_SUPPORT_PENDING"] = (
        "LINUX_6_18_SOURCE_NATIVE_SUPPORT_PENDING"
    )
    libbpf_contract: Literal["1.3.0_COMPILE_ONLY"] = "1.3.0_COMPILE_ONLY"
    native_release: Literal["BLOCKED"] = "BLOCKED"
    dynamic_dependency_closure: Literal["UNKNOWN_PAM_NSS_RUNTIME"] = "UNKNOWN_PAM_NSS_RUNTIME"
    installation_identity: Literal[
        "ROOT_OWNED_FIXED_PATH_PLUS_EXTERNALLY_APPROVED_MANIFEST_SHA"
    ] = "ROOT_OWNED_FIXED_PATH_PLUS_EXTERNALLY_APPROVED_MANIFEST_SHA"

    @model_validator(mode="after")
    def fixed_layout(self) -> Self:
        if set(self.payloads) != set(FILES):
            raise ValueError("RELEASE_PAYLOAD_ALLOWLIST")
        for name, payload in self.payloads.items():
            if payload.mode != MODES.get(name, 0o444):
                raise ValueError("RELEASE_MODE_CONTRACT")
        if len({d.path for d in self.dependencies}) != len(self.dependencies):
            raise ValueError("RELEASE_DEPENDENCY_DUPLICATE")
        if tuple(d.path for d in self.system_configuration) != (
            "/etc/ld.so.cache",
            "/etc/nsswitch.conf",
        ) or any(d.mode & 0o022 for d in self.system_configuration):
            raise ValueError("RELEASE_SYSTEM_CONFIGURATION")
        if set(self.dynamic_trust.elf) != {"bootstrap", "broker", "libnative-tc.so"} or any(
            self.dynamic_trust.elf[n].sha256 != self.payloads[n].sha256
            for n in self.dynamic_trust.elf
        ):
            raise ValueError("RELEASE_ELF_IDENTITY_MISMATCH")
        wire = b"".join(
            bytes.fromhex(self.payloads[n].sha256)
            for n in ("bootstrap", "broker", "libnative-tc.so", "tc.bpf.o")
        ) + bytes.fromhex(self.bundle_digest)
        if (
            self.payloads["manifest.bin"].size != 160
            or self.payloads["manifest.bin"].sha256 != hashlib.sha256(wire).hexdigest()
        ):
            raise ValueError("RELEASE_BINARY_MANIFEST_CONTRACT")
        return self

    @property
    def identity(self) -> str:
        return hashlib.sha256(canonical(self.model_dump(mode="json"))).hexdigest()


def create_package(artifacts: Path, destination: Path, version: str) -> ReleaseManifest:
    if os.geteuid() == 0:
        raise ValueError("RELEASE_NON_ROOT_ONLY")
    # Source compilation/reference qualification is the existing boundary.
    from soc_agent.security_ai.ebpf_tc.bridge import inspect_artifacts

    hashes = inspect_artifacts(artifacts)
    bodies = {
        name: read_held((artifacts / source).absolute(), owner=os.getuid(), limit=1048576)
        for name, source in SOURCE_NAMES.items()
    }
    if any(
        hashlib.sha256(bodies[n]).hexdigest() != hashes[source]
        for n, source in SOURCE_NAMES.items()
    ):
        raise ValueError("RELEASE_SOURCE_CHANGED")
    bodies["manifest.bin"] = b"".join(
        bytes.fromhex(hashlib.sha256(bodies[n]).hexdigest())
        for n in ("bootstrap", "broker", "libnative-tc.so", "tc.bpf.o")
    ) + bytes.fromhex(digest(bundle()))
    bodies["pam-policy.conf"] = (ROOT / "pam-policy.conf").read_bytes()
    from soc_agent.security_ai.ebpf_tc.trust import configuration, execution_manifest

    dependencies = inventory(tuple(bodies[n] for n in ("bootstrap", "broker", "libnative-tc.so")))
    manifest = ReleaseManifest(
        dynamic_trust=dependency_trust(bodies, dependencies),
        system_configuration=configuration(),
        version=version,
        bundle_digest=digest(bundle()),
        payloads={
            name: Payload(
                sha256=hashlib.sha256(body).hexdigest(), size=len(body), mode=MODES.get(name, 0o444)
            )
            for name, body in bodies.items()
        },
        dependencies=dependencies,
    )
    destination.mkdir(mode=0o700)  # Never overwrite a prior package.
    fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _directory(os.fstat(fd), os.getuid())
        for name, body in bodies.items():
            _write(fd, name, body, 0o444)
        _write(fd, "release.json", canonical(manifest.model_dump(mode="json")), 0o444)
        _write(fd, "release.trust", execution_manifest(manifest), 0o444)
        os.fsync(fd)
    finally:
        os.close(fd)
    return manifest


def _write(directory: int, name: str, body: bytes, mode: int) -> None:
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode,
        dir_fd=directory,
    )
    try:
        if os.write(fd, body) != len(body):
            raise ValueError("RELEASE_PARTIAL_WRITE")
        os.fsync(fd)
    finally:
        os.close(fd)


def verify_package(directory: Path, expected_manifest_sha: Hash) -> ReleaseManifest:
    if os.geteuid() == 0:
        raise ValueError("RELEASE_NON_ROOT_ONLY")
    body = read_held((directory / "release.json").absolute(), owner=os.getuid(), limit=65536)
    if hashlib.sha256(body).hexdigest() != expected_manifest_sha:
        raise ValueError("RELEASE_MANIFEST_MISMATCH")
    manifest = ReleaseManifest.model_validate_json(body)
    if manifest.identity != expected_manifest_sha:
        raise ValueError("RELEASE_MANIFEST_NONCANONICAL")
    bodies = {}
    for name, payload in manifest.payloads.items():
        body = read_held((directory / name).absolute(), owner=os.getuid(), limit=1048576)
        if len(body) != payload.size or hashlib.sha256(body).hexdigest() != payload.sha256:
            raise ValueError("RELEASE_PAYLOAD_MISMATCH")
        bodies[name] = body
    binary_manifest = b"".join(
        bytes.fromhex(manifest.payloads[n].sha256)
        for n in ("bootstrap", "broker", "libnative-tc.so", "tc.bpf.o")
    ) + bytes.fromhex(manifest.bundle_digest)
    if (
        bodies["manifest.bin"] != binary_manifest
        or bodies["pam-policy.conf"] != (ROOT / "pam-policy.conf").read_bytes()
    ):
        raise ValueError("RELEASE_BOOTSTRAP_CONTRACT_MISMATCH")
    from soc_agent.security_ai.ebpf_tc.trust import configuration, verify_execution_manifest

    if tuple(d.model_dump(mode="json") for d in manifest.system_configuration) != configuration():
        raise ValueError("RELEASE_SYSTEM_CONFIGURATION_MISMATCH")
    verify_execution_manifest(directory, manifest)
    verify_dependencies(manifest.dependencies)
    if (
        inventory(tuple(bodies[n] for n in ("bootstrap", "broker", "libnative-tc.so")))
        != manifest.dependencies
    ):
        raise ValueError("RELEASE_DEPENDENCY_CLOSURE_MISMATCH")
    if dependency_trust(bodies, manifest.dependencies) != manifest.dynamic_trust:
        raise ValueError("RELEASE_DYNAMIC_TRUST_MISMATCH")
    return manifest


def validate_root_release(expected: ReleaseManifest) -> dict[str, str]:
    """Public root ownership verification cannot accept a caller-chosen root/path/UID."""
    if os.geteuid() == 0:
        raise ValueError("RELEASE_VERIFIER_NON_ROOT_REQUIRED")
    body = read_held(INSTALL / "release.json", owner=0, limit=65536)
    if hashlib.sha256(body).hexdigest() != expected.identity:
        raise ValueError("ROOT_RELEASE_MANIFEST_MISMATCH")
    parent = os.open(INSTALL, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        descriptor = _open_file(parent, "release.json", expected.identity, 0o444)
        os.close(descriptor)
    finally:
        os.close(parent)
    snapshots = {}
    for name in MODES:
        # Reuse held-FD validation including exact root mode, ownership and single link.
        parent = os.open(INSTALL, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fd = _open_file(parent, name, expected.payloads[name].sha256, MODES[name])
            try:
                snapshots[name] = os.pread(fd, expected.payloads[name].size + 1, 0)
            finally:
                os.close(fd)
        finally:
            os.close(parent)
    pam = read_held(Path(expected.pam_destination), owner=0, limit=4096)
    if hashlib.sha256(pam).hexdigest() != expected.payloads["pam-policy.conf"].sha256:
        raise ValueError("ROOT_PAM_POLICY_MISMATCH")
    verify_dependencies(expected.dependencies)
    if (
        inventory(tuple(snapshots[n] for n in ("bootstrap", "broker", "libnative-tc.so")))
        != expected.dependencies
    ):
        raise ValueError("ROOT_DEPENDENCY_CLOSURE_MISMATCH")
    from soc_agent.security_ai.ebpf_tc.trust import configuration, execution_manifest

    if tuple(d.model_dump(mode="json") for d in expected.system_configuration) != configuration():
        raise ValueError("ROOT_SYSTEM_CONFIGURATION_MISMATCH")
    execution = execution_manifest(expected)
    parent = os.open(INSTALL, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        descriptor = _open_file(
            parent, "release.trust", hashlib.sha256(execution).hexdigest(), 0o444
        )
        os.close(descriptor)
    finally:
        os.close(parent)
    wire = read_held(INSTALL / "release.trust", owner=0, limit=32768)
    if wire != execution_manifest(expected):
        raise ValueError("ROOT_EXECUTION_MANIFEST_MISMATCH")
    if dependency_trust(snapshots, expected.dependencies) != expected.dynamic_trust:
        raise ValueError("ROOT_DYNAMIC_TRUST_MISMATCH")
    return {
        "installation_files": "VERIFIED_READ_ONLY",
        "pam_authentication": "PENDING",
        "capability_transfer": "UNKNOWN",
        "native_release": "BLOCKED",
    }


def installation_plan(manifest: ReleaseManifest) -> dict[str, object]:
    return {
        "manifest_sha256": manifest.identity,
        "destination": manifest.destination,
        "release_version": manifest.version,
        "native_release": "BLOCKED",
        "steps": (
            "EXPLICIT_INSTALL_APPROVAL",
            "QUIESCE_ALL_APPLICATIONS_AND_BROKERS",
            "VERIFY_ROOT_STAGING_AND_DEPENDENCIES",
            "VERIFY_SEPARATELY_APPROVED_PAM_POLICY",
            "FSYNC_RELEASE_FILES_AND_DIRECTORY",
            "RENAMEAT2_EXCHANGE_COMPLETE_FIXED_DIRECTORY",
            "FSYNC_PARENT",
            "READ_ONLY_REVERIFY",
            "RETAIN_PREVIOUS_RELEASE_FOR_ROLLBACK",
        ),
        "rollback": "EXPLICIT_APPROVAL_QUIESCE_VERIFY_PRIOR_MANIFEST_EXCHANGE_COMPLETE_DIRECTORY",
        "first_install": "RENAME_NOREPLACE_AFTER_PAM_POLICY_APPROVAL",
        "pam_update_atomic_with_release": False,
        "pam_policy_change": "SEPARATE_APPROVAL_QUIESCENT_FAIL_CLOSED",
        "automatic_rollback": False,
        "native_activation": False,
    }


def native_install() -> None:
    raise ValueError("ROOT_INSTALLATION_APPROVAL_AND_NATIVE_QUALIFICATION_PENDING")

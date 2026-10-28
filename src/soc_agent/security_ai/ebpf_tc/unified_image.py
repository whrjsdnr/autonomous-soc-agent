"""Prepare one SHA-pinned install-and-handoff image; never execute privileged code."""

import hashlib
import json
import os
from pathlib import Path

from pydantic import Field

from soc_agent.review.models import Hash
from soc_agent.security_ai.ebpf_tc import install_engine, unified_image_engine
from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.ebpf_tc.install_image import installation_payload, payload_from_release
from soc_agent.security_ai.ebpf_tc.installation import (
    INSTALL,
    ReleaseManifest,
    validate_root_release,
)
from soc_agent.security_ai.ebpf_tc.recovery_policy import RecoveryBinding, RecoveryBuild
from soc_agent.security_ai.research.models import Frozen


class UnifiedImage(Frozen):
    path: Path
    sha256: str
    manifest: str
    previous_manifest: str
    version: str
    action: str
    files: dict[str, dict[str, str | int]] = Field(default_factory=dict)
    recovery_binding: RecoveryBinding | None = None
    recovery_policy_sha: Hash | None = None

    def verify(self) -> None:
        body = read_held(self.path, owner=os.getuid(), limit=1048576)
        if (
            self.path.stat().st_mode & 0o777 != 0o400
            or hashlib.sha256(body).hexdigest() != self.sha256
        ):
            raise ValueError("UNIFIED_IMAGE_CHANGED")


def installed_release() -> ReleaseManifest | None:
    if not os.path.lexists(INSTALL):
        return None
    body = read_held(INSTALL / "release.json", owner=0, limit=65536)
    release = ReleaseManifest.model_validate_json(body)
    validate_root_release(release)
    return release


def prepare_unified_image(
    package: Path,
    manifest: str,
    output: Path,
    *,
    recovery: RecoveryBuild | None = None,
    scope_namespace: str | None = None,
    namespace_policy_sha: str | None = None,
) -> UnifiedImage:
    release, image = installation_payload(package, manifest)
    binding = policy_body = policy_sha = None
    if recovery is None:
        installed = installed_release()  # Normal runtime qualification is unchanged.
    else:
        from soc_agent.security_ai.ebpf_tc.phase_d import SCOPE
        from soc_agent.security_ai.ebpf_tc.r2_diagnostic import scenario_for_namespace
        from soc_agent.security_ai.ebpf_tc.reassessment import digest
        from soc_agent.security_ai.ebpf_tc.recovery_policy import check_policy, implementation_sha
        from soc_agent.security_ai.ebpf_tc.runtime_recovery import (
            host_identity,
            inspect_retained,
            verify_abi,
        )

        retained = inspect_retained(recovery.installed_manifest)
        installed = ReleaseManifest.model_validate_json(
            read_held(INSTALL / "release.json", owner=0)
        )
        if installed.identity != retained.manifest:
            raise ValueError("RECOVERY_INSTALLED_CHANGED")
        abi = verify_abi(recovery.abi_file, recovery.abi_sha, release)
        host = host_identity()
        if abi.old_zlib not in {
            d.sha256 for d in installed.dependencies if d.soname == "libz.so.1"
        }:
            raise ValueError("RECOVERY_PREVIOUS_ABI_BINDING")
        binding = RecoveryBinding(
            old_root=installed.identity,
            new_root=release.identity,
            retained_sha=digest(retained.model_dump(mode="json")),
            dependencies_sha=digest([d.model_dump(mode="json") for d in release.dependencies]),
            implementation_sha=implementation_sha(),
            scope_sha=digest(
                dict(
                    tcx=SCOPE | dict(namespace=scope_namespace or SCOPE["namespace"]),
                    r2=scenario_for_namespace(
                        scope_namespace or SCOPE["namespace"], namespace_policy_sha
                    ).model_dump(),
                )
            ),
            abi_sha=abi.report_sha,
            host_sha=digest(host),
        )
        abi_body = read_held(recovery.abi_file, owner=os.getuid(), limit=65536)
        if hashlib.sha256(abi_body).hexdigest() != binding.abi_sha:
            raise ValueError("RECOVERY_ABI_CHANGED")
        abi_fd = os.open(
            output.parent / "recovery-abi.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o400,
        )
        with os.fdopen(abi_fd, "wb") as stream:
            stream.write(abi_body)
            stream.flush()
            os.fsync(stream.fileno())
        host_fd = os.open(
            output.parent / "recovery-host.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o400,
        )
        with os.fdopen(host_fd, "wb") as stream:
            stream.write((json.dumps(host, sort_keys=True, separators=(",", ":")) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        if (recovery.policy_file is None) != (recovery.policy_sha is None):
            raise ValueError("RECOVERY_POLICY_PIN_REQUIRED")
        if recovery.policy_file is not None:
            policy_body = read_held(recovery.policy_file, owner=os.getuid(), limit=65536)
            if hashlib.sha256(policy_body).hexdigest() != recovery.policy_sha:
                raise ValueError("RECOVERY_POLICY_SHA")
            check_policy(json.loads(policy_body), binding)
            policy_sha = recovery.policy_sha
    previous = payload_from_release(INSTALL, installed) if installed else None
    # The fixed system interpreter and sudo are part of the reviewed image, never
    # chosen by a command-line executable path. OS libraries remain root-trusted;
    # full dynamic runtime closure is explicitly not claimed here.
    for path in (Path("/usr/bin/python3").resolve(strict=True), Path("/usr/bin/sudo")):
        body = read_held(path, owner=0, limit=64 * 1024**2)
        image["dependencies"].append(
            dict(
                path=str(path),
                sha256=hashlib.sha256(body).hexdigest(),
                mode=path.stat().st_mode & 0o7777,
            )
        )
    source = (
        Path(install_engine.__file__).read_bytes()
        + b"\n"
        + Path(unified_image_engine.__file__).read_bytes()
    )
    source += b"\nIMAGE = json.loads(" + repr(json.dumps(image, sort_keys=True)).encode() + b")\n"
    source += (
        b"PREVIOUS = json.loads(" + repr(json.dumps(previous, sort_keys=True)).encode() + b")\n"
    )
    if binding is not None:
        source += b"\nRECOVERY_BINDING = " + repr(binding.model_dump()).encode() + b"\n"
        source += b"RECOVERY_POLICY_BODY = " + repr(policy_body).encode() + b"\n"
        source += b"RECOVERY_POLICY_SHA = " + repr(policy_sha).encode() + b"\n"
    source += (
        b"if __name__ == '__main__':\n    import sys\n"
        b"    unified_root_main(IMAGE, PREVIOUS, sys.argv, globals())\n"
    )
    if len(source) > 1048576:
        raise ValueError("UNIFIED_IMAGE_TOO_LARGE")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(source)
        stream.flush()
        os.fsync(stream.fileno())
    return UnifiedImage(
        path=output.absolute(),
        sha256=hashlib.sha256(source).hexdigest(),
        manifest=manifest,
        previous_manifest=installed.identity if installed else "0" * 64,
        version=release.version,
        recovery_binding=binding,
        recovery_policy_sha=policy_sha,
        files={
            name: {k: v for k, v in row.items() if k != "body"}
            for name, row in image["files"].items()
        },
        action="CHECK"
        if installed and installed.identity == manifest
        else "UPDATE_RETAIN_PREVIOUS"
        if installed
        else "INSTALL",
    )


def pinned_command(
    image: UnifiedImage, envelope: bytes, approval: str, uid: int, gid: int
) -> tuple[str, ...]:
    """Only this fixed isolated system-Python entry can execute the approved bytes.

    fstat/sha and compile use the same held snapshot. A mutable filename never
    becomes Root execution authority. No project imports or shell expansion.
    """
    image.verify()
    arguments = [
        "approved-soc-unified",
        "run",
        str(uid),
        str(gid),
        envelope.hex(),
        image.sha256,
        approval,
    ]
    script = (
        "import os,stat,hashlib,sys;"
        f"f=os.open({str(image.path)!r},os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);"
        "s=os.fstat(f);"
        f"assert stat.S_ISREG(s.st_mode) and s.st_uid=={uid} and s.st_nlink==1;"
        "assert stat.S_IMODE(s.st_mode)==256 and 0<s.st_size<=1048576;"
        "b=os.pread(f,s.st_size+1,0);os.close(f);"
        f"assert hashlib.sha256(b).hexdigest()=={image.sha256!r};"
        f"sys.argv={arguments!r};"
        "exec(compile(b,'<sha-approved-unified-image>','exec'))"
    )
    return ("/usr/bin/sudo", "-k", "-u", "root", "--", "/usr/bin/python3", "-I", "-S", "-c", script)

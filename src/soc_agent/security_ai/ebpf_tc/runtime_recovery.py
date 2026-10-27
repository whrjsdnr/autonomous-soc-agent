"""Read-only retention and isolated current-runtime preparation, never activation.

RetainedInstallation is deliberately not ReleaseManifest/UnifiedImage. Prepared
images abort before importing any installer code. Neither can satisfy existing
Root/Native entrypoints. Policy activation requires a separately reviewed update.
"""

import hashlib
import os
import shutil
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import Literal

from pydantic import field_validator

from soc_agent.review.models import Hash
from soc_agent.security_ai.ebpf_tc import install_engine, phase_d
from soc_agent.security_ai.ebpf_tc.dependencies import Dependency, read_held, verify_dependencies
from soc_agent.security_ai.ebpf_tc.install_image import installation_payload
from soc_agent.security_ai.ebpf_tc.installation import ReleaseManifest, canonical, verify_package
from soc_agent.security_ai.ebpf_tc.reassessment import Contract, held_json
from soc_agent.security_ai.ebpf_tc.release import INSTALL, _directory, _open_file
from soc_agent.security_ai.ebpf_tc.source_guard import SourceGuard, snapshot
from soc_agent.security_ai.ebpf_tc.trust import execution_manifest
from soc_agent.security_ai.ebpf_tc.unified_startup import prepare_candidate
from soc_agent.security_ai.research.models import digest


class RetainedInstallation(Contract):
    contract: Literal["SOC_RETAINED_FILES_NOT_RUNTIME_V1"] = "SOC_RETAINED_FILES_NOT_RUNTIME_V1"
    directory: str
    manifest: Hash
    files: dict[str, Hash]
    dependencies: tuple[Dependency, ...]
    runtime_qualified: Literal[False] = False
    native_admission: Literal[False] = False


def inspect_retained(expected: Hash, *, rollback: bool = False) -> RetainedInstallation:
    """Fixed root-owned installed/archive path; no runtime dependency acceptance."""
    if os.geteuid() == 0:
        raise ValueError("RECOVERY_NON_ROOT_ONLY")

    # Validate the pin before it can form even a fixed-prefix archive filename.
    class Pin(Contract):
        sha: Hash

    Pin(sha=expected)
    path = INSTALL.parent / (".soc-agent-ebpf.rollback-" + expected) if rollback else INSTALL
    with ExitStack() as stack:
        parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        stack.callback(os.close, parent)
        _directory(os.fstat(parent), 0)
        for part in path.parts[1:]:
            parent = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
            )
            stack.callback(os.close, parent)
            _directory(os.fstat(parent), 0)
        fd = _open_file(parent, "release.json", expected, 0o444)
        stack.callback(os.close, fd)
        release = ReleaseManifest.model_validate_json(os.pread(fd, 65537, 0))
        if release.identity != expected:
            raise ValueError("RECOVERY_MANIFEST_IDENTITY")
        pins = {n: (p.sha256, p.mode) for n, p in release.payloads.items()}
        pins.update(
            {
                "release.json": (expected, 0o444),
                "release.trust": (hashlib.sha256(execution_manifest(release)).hexdigest(), 0o444),
            }
        )
        if set(os.listdir(parent)) != set(pins):
            raise ValueError("RECOVERY_INSTALLED_FILE_SET")
        for name, (sha, mode) in pins.items():
            fd = _open_file(parent, name, sha, mode)
            stack.callback(os.close, fd)
            held = os.fstat(fd)
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError("RECOVERY_PATH_REPLACED")
        return RetainedInstallation(
            directory=str(path),
            manifest=expected,
            files={n: pin[0] for n, pin in pins.items()},
            dependencies=release.dependencies,
        )


class AbiEvidence(Contract):
    report_sha: Hash
    old_zlib: Hash
    current_zlib: Hash
    result: Literal["OBSERVED_COMPATIBLE_LIMITED", "INCOMPATIBLE", "UNKNOWN"]
    production_compatible: Literal[False] = False


def verify_abi(report: Path, expected: Hash, release: ReleaseManifest) -> AbiEvidence:
    """Bind existing bounded ABI evidence to exact observed libraries/consumers."""
    data = held_json(report, expected)
    try:
        return _abi_result(data, expected, release)
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError("RECOVERY_ABI_REPORT_INVALID") from exc


def _abi_result(data: dict, expected: Hash, release: ReleaseManifest) -> AbiEvidence:
    libraries = data["libraries"]
    by_path = {d.path: d.sha256 for d in release.dependencies}
    consumers = {d.path for d in release.dependencies if d.soname in {"libbpf.so.1", "libelf.so.1"}}
    if set(data["consumer_requirements"]) != consumers or not consumers:
        raise ValueError("RECOVERY_ABI_CONSUMER_SET")
    if by_path.get(libraries["new"]["path"]) != libraries["new"]["sha256"]:
        raise ValueError("RECOVERY_ABI_DEPENDENCY_BINDING")
    for path, row in data["consumer_requirements"].items():
        if by_path.get(path) != row["sha256"] or row["missing_in_new"]:
            raise ValueError("RECOVERY_ABI_CONSUMER_BINDING")
    incompatible = bool(data["missing_old_exports"] or data["changed_abi_export_metadata"])
    compatible = (
        data["status"] == "STATIC_AND_BOUNDED_SMOKE_COMPATIBLE_FOR_OBSERVED_CONSUMERS"
        and all(data["smoke"][k]["status"] == "PASS" for k in ("old", "new"))
        and set(data["headers"]) == {"zlib.h", "zconf.h"}
        and all(
            v["identical"] and v["old_sha256"] == v["new_sha256"] for v in data["headers"].values()
        )
    )
    result = (
        "INCOMPATIBLE"
        if incompatible
        else ("OBSERVED_COMPATIBLE_LIMITED" if compatible else "UNKNOWN")
    )
    if result != "OBSERVED_COMPATIBLE_LIMITED":
        raise ValueError("RECOVERY_ABI_" + result)
    return AbiEvidence(
        report_sha=expected,
        old_zlib=libraries["old"]["sha256"],
        current_zlib=libraries["new"]["sha256"],
        result=result,
    )


def host_identity() -> dict:
    """Fixed read-only package query and actual build-tool identities, no library load."""
    versions = subprocess.run(
        [
            "/usr/bin/dpkg-query",
            "-W",
            "-f=${binary:Package}=${Version}\n",
            "zlib1g",
            "libbpf1",
            "libelf1t64",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
    ).stdout.splitlines()
    tools = {}
    for name in ("cc", "clang", "ld", "python3"):
        found = "/usr/bin/python3" if name == "python3" else shutil.which(name)
        if found is None:
            raise ValueError("RECOVERY_TOOLCHAIN_MISSING")
        path = Path(found).resolve(strict=True)
        tools[name] = dict(
            path=str(path),
            sha256=hashlib.sha256(read_held(path, owner=0, limit=128 * 1024**2)).hexdigest(),
        )
    interpreter = Path(sys.executable).resolve(strict=True)
    tools["build_python"] = dict(
        path=str(interpreter),
        uid=interpreter.stat().st_uid,
        sha256=hashlib.sha256(
            read_held(interpreter, owner=os.getuid(), limit=128 * 1024**2)
        ).hexdigest(),
    )
    return dict(packages=sorted(versions), toolchain=tools)


class RuntimeCandidate(Contract):
    contract: Literal["SOC_QUARANTINED_RUNTIME_CANDIDATE_V1"] = (
        "SOC_QUARANTINED_RUNTIME_CANDIDATE_V1"
    )
    root_manifest: Hash
    bundle: Hash
    source_snapshot: Hash
    image: Hash
    abi: AbiEvidence
    host: dict
    dependencies: tuple[Dependency, ...]
    installation_policy: Literal["NOT_ACTIVATED"] = "NOT_ACTIVATED"
    executable_admission: Literal[False] = False
    native_ai: Literal["BLOCKED"] = "BLOCKED"

    @field_validator("dependencies", mode="before")
    @classmethod
    def dependency_json_array(cls, value):
        # Contract's before-validator intentionally preserves strict literal
        # types. Normalize only JSON's array representation, not its contents.
        return tuple(value) if isinstance(value, list) else value


def prepare_runtime(source: Path, output: Path, *, abi_file: Path, abi_sha: Hash) -> dict:
    """Reuse compiler/package builder, without consulting/repairing old runtime.

    This prepares a distinct quarantined contract. It does not fabricate a
    Phase-D execution manifest or reinterpret an old runtime check as success.
    """
    if os.geteuid() == 0:
        raise ValueError("RECOVERY_NON_ROOT_ONLY")
    source, output = source.resolve(strict=True), output.absolute()
    if not Path(__file__).resolve().is_relative_to(source):
        raise ValueError("RECOVERY_LOADED_SOURCE_MISMATCH")
    if output.is_relative_to(source):
        raise ValueError("RECOVERY_OUTPUT_INSIDE_SOURCE")
    with SourceGuard(source) as guard:
        inputs = snapshot(source)
        environment = host_identity()
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        _, _, package, manifest = prepare_candidate(output, version="0.6.3", inspector=True)
        release, payload = installation_payload(package, manifest)
        abi = verify_abi(abi_file, abi_sha, release)
        # Guard precedes every import/definition. No argv, receipt or environment
        # value can enable this image. Activation requires new reviewed bytes/SHA.
        image = (
            b"raise SystemExit('RECOVERY_POLICY_NOT_ACTIVATED')\n"
            + Path(install_engine.__file__).read_bytes()
            + b"\nIMAGE = "
            + repr(payload).encode()
            + b"\n"
        )
        image_path = output / "quarantined-image.py"
        fd = os.open(image_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, "wb") as stream:
            stream.write(image)
            stream.flush()
            os.fsync(stream.fileno())
        compile(image, "<quarantined-runtime>", "exec")
        verify_package(package, manifest)
        if host_identity() != environment:
            raise ValueError("RECOVERY_HOST_CHANGED_DURING_BUILD")
        guard.check()
        value = RuntimeCandidate(
            root_manifest=manifest,
            bundle=hashlib.sha256(canonical(phase_d.runtime_bundle())).hexdigest(),
            source_snapshot=digest(inputs),
            image=hashlib.sha256(image).hexdigest(),
            abi=abi,
            host=environment,
            dependencies=release.dependencies,
        )
        body = canonical(value.model_dump(mode="json"))
        (output / "runtime-recovery.json").write_bytes(body)
        return dict(manifest=hashlib.sha256(body).hexdigest(), **value.model_dump(mode="json"))


def validate_runtime(output: Path, manifest: Hash) -> RuntimeCandidate:
    data = held_json(output / "runtime-recovery.json", manifest)
    value = RuntimeCandidate.model_validate_json(canonical(data))
    body = read_held(output / "quarantined-image.py", owner=os.getuid())
    if (
        hashlib.sha256(body).hexdigest() != value.image
        or (output / "quarantined-image.py").stat().st_mode & 0o777 != 0o400
    ):
        raise ValueError("RECOVERY_IMAGE_MISMATCH")
    if not body.startswith(b"raise SystemExit('RECOVERY_POLICY_NOT_ACTIVATED')\n"):
        raise ValueError("RECOVERY_IMAGE_NOT_QUARANTINED")
    release = verify_package(output / "release", value.root_manifest)
    verify_dependencies(value.dependencies)
    if (
        release.dependencies != value.dependencies
        or host_identity() != value.host
        or value.bundle != hashlib.sha256(canonical(phase_d.runtime_bundle())).hexdigest()
    ):
        raise ValueError("RECOVERY_RUNTIME_IDENTITY_MISMATCH")
    return value


def execution_readiness(
    output: Path,
    manifest: Hash,
    *,
    installed_manifest: Hash,
    admission: dict | None = None,
) -> dict:
    """Compose real file/runtime and existing R1 Approval Validator outcomes.

    Never enables a recovery policy, reserves an attempt or produces a positive
    safety decision. Exceptions retain stage/API identity for callers/audit.
    """
    from soc_agent.security_ai.ebpf_tc.reassessment_admission import preview_reservation

    results = {}
    retained = None
    runtime = None
    for stage, operation in (
        ("preservation", lambda: inspect_retained(installed_manifest)),
        ("runtime", lambda: validate_runtime(output, manifest)),
    ):
        try:
            value = operation()
        except (ValueError, OSError) as exc:
            results[stage] = dict(
                status="FAILED", error=str(exc), errno=getattr(exc, "errno", None)
            )
        else:
            results[stage] = dict(status="VERIFIED_READ_ONLY_NOT_EXECUTION")
            if stage == "preservation":
                retained = value
            else:
                runtime = value
    results["policy"] = dict(status="NOT_ACTIVATED")
    if admission is None:
        results["r1_and_exact_approval"] = dict(status="MISSING_HUMAN_GRANTS")
    elif retained is None or runtime is None:
        results["r1_and_exact_approval"] = dict(status="NOT_CHECKED_INVALID_EVIDENCE")
    else:
        if runtime.abi.old_zlib not in {
            d.sha256 for d in retained.dependencies if d.soname == "libz.so.1"
        }:
            raise ValueError("RECOVERY_PREVIOUS_ABI_BINDING")
        identity = dict(
            manifest=manifest,
            bundle=runtime.bundle,
            image=runtime.image,
            tcx_manifest=runtime.root_manifest,
        )
        if admission.get("identity") != identity:
            raise ValueError("RECOVERY_EXECUTION_ARTIFACT_BINDING")
        # Caller-supplied paths/hashes still face the existing actual validators;
        # this mapping is never used as evidence of receipt authenticity itself.
        results["r1_and_exact_approval"] = preview_reservation(**admission)
    return dict(
        status="BLOCKED",
        native_admission=False,
        stages=results,
        reason="QUARANTINED_IMAGE_AND_POLICY_NOT_ACTIVATED",
    )

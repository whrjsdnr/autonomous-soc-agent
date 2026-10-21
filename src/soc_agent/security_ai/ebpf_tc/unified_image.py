"""Prepare one SHA-pinned install-and-handoff image; never execute privileged code."""

import hashlib
import json
import os
from pathlib import Path

from pydantic import Field

from soc_agent.security_ai.ebpf_tc import install_engine, unified_image_engine
from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.ebpf_tc.install_image import installation_payload, payload_from_release
from soc_agent.security_ai.ebpf_tc.installation import (
    INSTALL,
    ReleaseManifest,
    validate_root_release,
)
from soc_agent.security_ai.research.models import Frozen


class UnifiedImage(Frozen):
    path: Path
    sha256: str
    manifest: str
    previous_manifest: str
    version: str
    action: str
    files: dict[str, dict[str, str | int]] = Field(default_factory=dict)

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


def prepare_unified_image(package: Path, manifest: str, output: Path) -> UnifiedImage:
    release, image = installation_payload(package, manifest)
    installed = installed_release()  # Exact current version first, no repair of unknown state.
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

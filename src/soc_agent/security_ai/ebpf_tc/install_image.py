"""Produce an immutable first-install image and approval scope, never run it as root."""

import base64
import hashlib
import json
import os
from pathlib import Path

from soc_agent.security_ai.ebpf_tc import install_engine
from soc_agent.security_ai.ebpf_tc.build import AUTH_POLICY
from soc_agent.security_ai.ebpf_tc.installation import verify_package


def installation_payload(package: Path, manifest_sha: str) -> tuple:
    if os.geteuid() == 0:
        raise ValueError("INSTALL_IMAGE_PREPARATION_NON_ROOT_REQUIRED")
    release = verify_package(package, manifest_sha)
    return release, payload_from_release(package, release)


def payload_from_release(package: Path, release) -> dict:
    manifest_sha = release.identity
    files = {}
    for name, payload in release.payloads.items():
        body = (package / name).read_bytes()
        if hashlib.sha256(body).hexdigest() != payload.sha256:
            raise ValueError("INSTALL_IMAGE_PACKAGE_CHANGED")
        files[name] = dict(
            body=base64.b64encode(body).decode(), sha256=payload.sha256, mode=payload.mode
        )
    for name in ("release.json", "release.trust"):
        body = (package / name).read_bytes()
        files[name] = dict(
            body=base64.b64encode(body).decode(),
            sha256=hashlib.sha256(body).hexdigest(),
            mode=0o444,
        )
    if files["release.json"]["sha256"] != manifest_sha:
        raise ValueError("INSTALL_IMAGE_MANIFEST_CHANGED")
    from soc_agent.security_ai.ebpf_tc.trust import execution_manifest

    if base64.b64decode(files["release.trust"]["body"]) != execution_manifest(release):
        raise ValueError("INSTALL_IMAGE_EXECUTION_MANIFEST_CHANGED")
    dependencies = [
        d.model_dump(mode="json") for d in (*release.dependencies, *release.system_configuration)
    ]
    for path in AUTH_POLICY.values():
        st = path.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError("INSTALL_IMAGE_AUTH_POLICY_UNTRUSTED")
        dependencies.append(
            dict(
                path=str(path),
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                mode=st.st_mode & 0o777,
            )
        )
    image = dict(manifest_sha256=manifest_sha, files=files, dependencies=dependencies)
    return image


def prepare_installation(package: Path, manifest_sha: str, output: Path) -> dict:
    release, image = installation_payload(package, manifest_sha)
    files, dependencies = image["files"], image["dependencies"]
    body = (
        Path(install_engine.__file__).read_bytes()
        + b"\nIMAGE = json.loads("
        + repr(json.dumps(image, sort_keys=True)).encode()
        + b")\n"
    )
    body += (
        b"if __name__ == '__main__':\n    import sys\n"
        b"    if len(sys.argv) not in (2, 3): "
        b"raise SystemExit('action and optional approval required')\n"
        b"    root_main(IMAGE, sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else None)\n"
    )
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o400)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        # Never replace or silently erase a failed image/evidence.
        raise
    return dict(
        release_version=release.version,
        manifest_sha256=manifest_sha,
        installer_path=str(output.absolute()),
        installer_sha256=hashlib.sha256(body).hexdigest(),
        destination=release.destination,
        files={name: {k: v for k, v in row.items() if k != "body"} for name, row in files.items()},
        dependencies=dependencies,
        native_activation=False,
        rollback="SEPARATE_APPROVAL_QUIESCENT_EXACT_RELEASE_UNPUBLISH_NO_DELETION",
    )

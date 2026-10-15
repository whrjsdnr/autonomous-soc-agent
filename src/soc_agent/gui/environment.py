"""Owner-controlled, project-local native demo environment. Never install at GUI startup.

The receipt detects accidental/tampered local files; it is not a signature or a
sandbox against the same UID. Existing ML/SOC dependencies remain trusted inputs.
"""

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
from pathlib import Path

from soc_agent.review.persistence.secure_storage import create_private_directory, validate_directory


def project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def environment_root() -> Path:
    return project_root() / ".security-ai-demo"


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _safe(path: Path):
    info = path.lstat()
    sticky_root_directory = (
        info.st_uid == 0 and stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX
    )
    if (
        info.st_uid not in (0, os.geteuid())
        or (info.st_mode & 0o022 and not sticky_root_directory)
        or path.is_symlink()
    ):
        raise ValueError("ENVIRONMENT_OWNERSHIP_OR_LINK")
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise ValueError("ENVIRONMENT_FILE_TYPE")


def _inventory(root: Path) -> dict[str, str]:
    validate_directory(root)
    result = {}
    for path in sorted(root.rglob("*")):
        if "__pycache__" in path.parts or path.name == "receipt.json":
            continue
        if path.is_symlink():
            if path == root / "inference/lib64" and path.readlink() == Path("lib"):
                result[str(path.relative_to(root))] = "alias:lib"
                continue
            # Only the fixed venv Python aliases may be links. No caller executable.
            if (
                path.parent != root / "inference/bin"
                or path.name not in ("python", "python3", "python3.12")
                or path.resolve() != Path(sys.executable).resolve()
            ):
                raise ValueError("UNTRUSTED_NATIVE_EXECUTABLE")
            result[str(path.relative_to(root))] = "python:" + digest(path.resolve())
            continue
        _safe(path)
        if path.is_file():
            result[str(path.relative_to(root))] = digest(path)
    return result


def _shared_startup(root: Path) -> dict[str, str]:
    site = root / "inference/lib/python3.12/site-packages"
    allowed = (
        project_root().parent / "ML/.venv/lib/python3.12/site-packages",
        project_root() / ".venv/lib/python3.12/site-packages",
    )
    expected = "\n".join(map(str, allowed)) + "\n"
    if (site / "reused-readonly-environments.pth").read_text() != expected:
        raise ValueError("UNTRUSTED_SHARED_ENVIRONMENT")
    if set(p.name for p in site.glob("*.pth")) != {
        "_virtualenv.pth",
        "reused-readonly-environments.pth",
    }:
        raise ValueError("UNTRUSTED_STARTUP_CODE")
    result = {}
    for directory in allowed:
        # Known project roots only; no receipt-supplied path is executed.
        for ancestor in (directory, *directory.parents):
            _safe(ancestor)
        for path in sorted(directory.glob("*.pth")):
            _safe(path)
            result[str(path)] = digest(path)
        # Pin shared backend/package distribution identities as well as startup code.
        names = (
            "lightgbm",
            "torch",
            "numpy",
            "scikit_learn",
            "joblib",
            "pandas",
            "pydantic",
            "network_security_ai",
            "dns_security_ai",
            "security_ai",
        )
        for name in names:
            for distribution in sorted(directory.glob(name + "-*.dist-info")):
                for filename in ("METADATA", "RECORD"):
                    path = distribution / filename
                    if path.exists():
                        _safe(path)
                        result[str(path)] = digest(path)
        for name in ("sitecustomize.py", "usercustomize.py", "_virtualenv.py"):
            path = directory / name
            if path.exists():
                _safe(path)
                result[str(path)] = digest(path)
    return result


def verified_paths() -> tuple[Path, Path]:
    root = environment_root()
    validate_directory(root)
    if not (root / "artifacts").is_dir():
        raise FileNotFoundError("ARTIFACT_ROOT_MISSING")
    receipt = root / "receipt.json"
    _safe(receipt)
    if receipt.stat().st_size > 512 * 1024:
        raise ValueError("ENVIRONMENT_RECEIPT_OVERSIZED")
    data = json.loads(receipt.read_text())
    if data != {
        "version": "soc-gui-native-demo:v1",
        "files": _inventory(root),
        "shared_startup": _shared_startup(root),
    }:
        raise ValueError("ENVIRONMENT_DIGEST_MISMATCH")
    python = root / "inference/bin/python"
    if python.resolve() != Path(sys.executable).resolve():
        raise ValueError("UNTRUSTED_NATIVE_EXECUTABLE")
    return python, root / "artifacts"


def prepare(source: Path):
    """Explicit offline provisioning only; never overwrite or modify source envs."""
    root = environment_root()
    if root.exists() or root.is_symlink():
        raise ValueError("FRESH_DEMO_ENVIRONMENT_REQUIRED")
    create_private_directory(root, exist_ok=False)
    # Copy the previously validated small isolated environment, not the ML venv.
    shutil.copytree(source / "inference", root / "inference", symlinks=True)
    shutil.copytree(source / "artifacts", root / "artifacts", symlinks=True)
    (root / "inference/.lock").chmod(0o600)
    data = {
        "version": "soc-gui-native-demo:v1",
        "files": _inventory(root),
        "shared_startup": _shared_startup(root),
    }
    receipt = root / "receipt.json"
    receipt.write_text(json.dumps(data, sort_keys=True, indent=2))
    receipt.chmod(0o600)
    verified_paths()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-from", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.prepare_from)
    print("Persistent demo environment prepared; inference not executed.")


if __name__ == "__main__":
    main()

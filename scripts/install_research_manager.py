"""Install an offline-verified CLI wheel for this ordinary user, never Root.

Run only after Workspace/Export tests and reproducible builds. Reuses the
Controller interpreter preparation and its existing runtime file manifest.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

from soc_agent.security_ai.ebpf_tc.controller_python import prepare
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.namespace_controller_engine import verify_python_runtime

ENTRY = '''"""Verify the installed ordinary-user manager before importing its code."""
import hashlib, json, os, stat, sys
from pathlib import Path
root = Path(__file__).resolve().parent
config = json.loads((root / 'runtime-reference.json').read_bytes())
manifest = Path(config['python_runtime']['file'])
assert manifest == root / 'python/controller-python.json', 'MANAGER_MANIFEST_PATH'
assert hashlib.sha256(manifest.read_bytes()).hexdigest() == config[
    'python_runtime']['sha'], 'MANAGER_MANIFEST_CHANGED'
value = json.loads(manifest.read_bytes())
for name, pin in value['files'].items():
    path = Path(name)
    assert path.is_relative_to(root) and '..' not in path.parts, 'MANAGER_FILE_SCOPE'
    info = path.lstat()
    assert (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and not info.st_mode & 0o022), 'MANAGER_FILE_OWNER_MODE'
    assert hashlib.sha256(path.read_bytes()).hexdigest() == pin, 'MANAGER_FILE_CHANGED'
python = root / 'python/bin/python'
assert value['executable'] == str(python), 'MANAGER_INTERPRETER_SCOPE'
os.execv(str(python), [str(python), '-I', '-B', '-m', 'soc_agent.cli', *sys.argv[1:]])
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-evidence", required=True, type=Path)
    parser.add_argument("--update", action="store_true")
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise ValueError("MANAGER_INSTALL_REQUIRES_ORDINARY_USER")
    evidence = args.build_evidence.absolute()
    proof = json.loads((evidence / "reproducible-builds.json").read_text())
    if not all(
        proof.get(key) is True
        for key in (
            "wheel_identical_three",
            "native_identical_three",
            "supervisor_identical_three",
        )
    ):
        raise ValueError("MANAGER_REPRODUCIBLE_BUILD_REQUIRED")
    for mode in ("workspace", "export"):
        report = json.loads((evidence / (mode + "-serial-recovery-final-result.json")).read_text())
        if report.get("exit") != 0 or report.get("source_unchanged") is not True:
            raise ValueError("MANAGER_REGRESSION_REQUIRED")
    wheel = next((evidence / "wheel-a").glob("*.whl"))
    pin = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if pin != proof["wheel_sha256"]:
        raise ValueError("MANAGER_WHEEL_CHANGED")
    home = Path.home() / ".local/share/soc-agent/management"
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    current = home / "current"
    if current.exists() and not args.update:
        raise ValueError("MANAGER_EXPLICIT_UPDATE_REQUIRED")
    destination = home / pin
    destination.mkdir(mode=0o700, exist_ok=False)
    project = evidence / "export-final"
    config = prepare(
        destination / "python",
        project=project,
        dependency_interpreter=Path(__file__).resolve().parents[1] / ".venv/bin/python",
    )
    # The Controller closure deliberately excludes the external-LLM adapter.
    # Copy its already installed settings parser, without reading credentials or
    # resolving/downloading dependencies. Provider execution stays separately gated.
    site = destination / "python/lib/python3.12/site-packages"
    for name in ("pydantic_settings", "dotenv"):
        spec = importlib.util.find_spec(name)
        if spec is None or spec.origin is None:
            raise ValueError("MANAGER_EXISTING_RUNTIME_DEPENDENCY_REQUIRED")
        source = Path(spec.origin).parent
        if not (site / name).exists():
            shutil.copytree(
                source, site / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
            )
    subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--offline",
            "--no-deps",
            "--python",
            str(destination / "python/bin/python"),
            str(wheel),
        ],
        check=True,
    )
    subprocess.run(
        [
            str(destination / "python/bin/python"),
            "-I",
            "-B",
            "-c",
            "import soc_agent.agent_api_review; from soc_agent.gui.backend import GUIConfig; "
            "import pydantic_settings; print('MANAGER_GUI_API_IMPORT_READY_NO_CALL')",
        ],
        check=True,
    )
    python_home = destination / "python"
    files = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(python_home.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and path.name != "controller-python.json"
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    }
    manifest = python_home / "controller-python.json"
    manifest.write_bytes(
        canonical(
            dict(
                contract="SOC_CONTROLLER_PYTHON_RUNTIME_V1",
                executable=str(python_home / "bin/python"),
                files=files,
            )
        )
    )
    config["python_runtime"]["sha"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
    verify_python_runtime(config, os.getuid())
    for name, body in (("runtime-reference.json", json.dumps(config)), ("entry.py", ENTRY)):
        target = destination / name
        target.write_text(body)
        target.chmod(0o600)
    # Validate the installed package entry before publishing the convenience link.
    subprocess.run(
        ["/usr/bin/python3", "-I", "-S", str(destination / "entry.py"), "start", "--help"],
        check=True,
    )
    pending = home / ("current-" + pin)
    pending.symlink_to(destination.name, target_is_directory=True)
    os.replace(pending, current)
    fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print(
        json.dumps(
            dict(
                status="MANAGEMENT_INSTALLED_NOT_NATIVE_AUTHORITY",
                wheel_sha256=pin,
                location=str(destination),
                previous_releases_preserved=True,
            )
        )
    )


if __name__ == "__main__":
    main()

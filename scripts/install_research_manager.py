"""Install an offline-verified CLI wheel for this ordinary user, never Root.

Run only after Workspace/Export tests and reproducible builds. Reuses the
Controller interpreter preparation and its existing runtime file manifest.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from soc_agent.security_ai.ebpf_tc.controller_python import prepare
from soc_agent.security_ai.ebpf_tc.installation import canonical

ENTRY = '''"""Verify the installed ordinary-user manager before importing its code."""
import hashlib, json, os, stat, sys
from pathlib import Path
root = Path(__file__).resolve().parent
config = json.loads((root / 'runtime-reference.json').read_bytes())
manifest = Path(config['application_runtime']['file'])
assert manifest == root / 'application-files.json', 'MANAGER_MANIFEST_PATH'
assert hashlib.sha256(manifest.read_bytes()).hexdigest() == config[
    'application_runtime']['sha'], 'MANAGER_MANIFEST_CHANGED'
for name, pin in json.loads(manifest.read_bytes()).items():
    path = Path(name)
    assert path.is_relative_to(root) and '..' not in path.parts, 'MANAGER_FILE_SCOPE'
    info = path.lstat()
    assert (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and not info.st_mode & 0o022), 'MANAGER_FILE_OWNER_MODE'
    assert hashlib.sha256(path.read_bytes()).hexdigest() == pin, 'MANAGER_FILE_CHANGED'
python = root / 'python/bin/python'
assert config['executable'] == str(python), 'MANAGER_INTERPRETER_SCOPE'
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
    installer_pin = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    destination = home / (pin[:16] + "-" + installer_pin[:16])
    destination.mkdir(mode=0o700, exist_ok=False)
    project = evidence / "export-final"
    config = prepare(
        destination / "python",
        project=project,
        dependency_interpreter=Path(__file__).resolve().parents[1] / ".venv/bin/python",
    )
    # The copied CPython executable uses $ORIGIN/../lib. Tcl/Tk must therefore
    # accompany it; the minimal headless Controller probe never imports Tk.
    base_library = Path(sys.base_prefix) / "lib"
    for name in ("libtcl9.0.so", "libtcl9tk9.0.so", "tcl9.0", "tk9.0"):
        source = base_library / name
        target = destination / "python/lib" / name
        if source.is_dir():
            shutil.copytree(source, target)
        elif source.is_file():
            shutil.copyfile(source, target)
        else:
            raise ValueError("MANAGER_EXISTING_TK_RUNTIME_REQUIRED")
    # Collect the application's real import closure, not the narrower Controller
    # closure. Reading doctor/status imports does not authorize collection/inference.
    # Keep the existing Controller pin/file-size bounds; do not copy whole ML
    # distributions and their test data just to satisfy a runtime import.
    site = destination / "python/lib/python3.12/site-packages"
    probe = (
        "import sys,json,pathlib;sys.path.insert(0," + repr(str(project / "src")) + ");"
        "import soc_agent.cli,soc_agent.agent_api_review;"
        "from soc_agent.gui.production import Desktop;"
        "from soc_agent.agent_runtime import doctor,home_path;h=home_path();"
        "doctor(h) if (h/'agent.json').exists() else None;"
        "print(json.dumps({'sites':[p for p in sys.path if p.endswith('site-packages')],"
        "'files':[str(m.__file__) for m in sys.modules.values() "
        "if getattr(m,'__file__',None)]}))"
    )
    result = subprocess.run(
        [str(Path(__file__).resolve().parents[1] / ".venv/bin/python"), "-I", "-B", "-c", probe],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
        env=dict(os.environ, OPENBLAS_NUM_THREADS="1", OMP_NUM_THREADS="1", MKL_NUM_THREADS="1"),
    )
    closure = json.loads(result.stdout)
    for location in map(Path, closure["sites"]):
        paths = [Path(name) for name in closure["files"] if Path(name).is_relative_to(location)]
        groups = {location / p.relative_to(location).parts[0] for p in paths}
        # Import closures include module code, not importlib.resources assets.
        # scikit-learn loads estimator CSS/Jinja resources during normal import.
        for group in groups:
            if group.is_dir():
                paths += [
                    p
                    for p in group.rglob("*")
                    if p.is_file()
                    and p.suffix not in {".py", ".pyc", ".so"}
                    and not {"tests", "test", "testing", "__pycache__"}.intersection(p.parts)
                ]
        # Wheel DSOs use sibling libraries through RPATH, outside sys.modules.
        for libraries in (
            "numpy.libs",
            "scipy.libs",
            "scikit_learn.libs",
            "xgboost.libs",
            "xgboost/lib",
        ):
            paths += [p for p in (location / libraries).rglob("*") if p.is_file()]
        for source in sorted(set(paths)):
            relative = source.relative_to(location)
            if ".." in relative.parts or source.suffix == ".pyc":
                raise ValueError("MANAGER_DEPENDENCY_PATH")
            target = site / relative
            if not target.exists():
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                target.chmod(0o600)
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
    # uv's installation lock is created 0666. It is private installation state,
    # not a reason to relax the manager's owner/mode checks.
    (destination / "python/.lock").chmod(0o600)
    subprocess.run(
        [
            str(destination / "python/bin/python"),
            "-I",
            "-B",
            "-c",
            "import soc_agent.agent_api_review; from soc_agent.gui.backend import GUIConfig; "
            "import pydantic_settings,tkinter; tkinter.Tcl(); "
            "print('MANAGER_GUI_API_IMPORT_READY_NO_CALL')",
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
    # An ML-capable application is not the minimal privileged Controller runtime.
    # Keep that Controller's 2048-file/64MiB bounds unchanged. Its preparation
    # proof remains construction evidence; the ordinary application's existing
    # Source-style file map includes scientific DSOs (e.g. libxgboost >64MiB).
    original = python_home / "controller-python.json"
    original.rename(python_home / "controller-preparation-only.json")
    preparation = python_home / "controller-preparation-only.json"
    files[str(preparation)] = hashlib.sha256(preparation.read_bytes()).hexdigest()
    manifest = destination / "application-files.json"
    manifest.write_bytes(canonical(files))
    config = dict(
        executable=str(python_home / "bin/python"),
        application_runtime=dict(
            file=str(manifest), sha=hashlib.sha256(manifest.read_bytes()).hexdigest()
        ),
        wheel_sha256=pin,
        native_controller_qualification=False,
    )
    for name, body in (("runtime-reference.json", json.dumps(config)), ("entry.py", ENTRY)):
        target = destination / name
        target.write_text(body)
        target.chmod(0o600)
    # Validate the installed package entry before publishing the convenience link.
    subprocess.run(
        ["/usr/bin/python3", "-I", "-S", str(destination / "entry.py"), "start", "--help"],
        check=True,
    )
    pending = home / ("current-" + destination.name)
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

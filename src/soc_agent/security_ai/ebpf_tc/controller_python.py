"""Nonprivileged Controller interpreter preparation. No pip, network or setns.

Copy the existing import closure into a canonical, isolated venv; never resolve a
venv symlink and then accidentally execute the bare base interpreter instead.
"""

import hashlib
import json
import os
import shutil
import subprocess
import venv
from pathlib import Path

from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.namespace_controller_engine import verify_python_runtime


def entry_probe(project: Path) -> str:
    return (
        "import sys,resource;"
        "resource.setrlimit(resource.RLIMIT_AS,(268435456,268435456));"
        "resource.setrlimit(resource.RLIMIT_CPU,(20,20));"
        "sys.path.insert(0," + repr(str(project / "src")) + ");"
        "from soc_agent.security_ai.ebpf_tc.namespace_controller import child_main;"
        "from soc_agent.security_ai.ebpf_tc.operational_recovery import main;"
        "import pydantic;assert pydantic.VERSION.startswith('2.');"
        "assert callable(child_main) and callable(main);"
        "assert not any(n in sys.modules for n in ('numpy','sklearn','xgboost'));"
        "print('CONTROLLER_IMPORT_READY')"
    )


def prepare(directory: Path, *, project: Path, dependency_interpreter: Path) -> dict:
    if directory.exists() or not directory.is_absolute() or not project.is_absolute():
        raise ValueError("CONTROLLER_PYTHON_NEW_ABSOLUTE_DIRECTORY_REQUIRED")
    source = (
        "import sys,json,pathlib;sys.path.insert(0," + repr(str(project / "src")) + ");"
        "from soc_agent.security_ai.ebpf_tc.namespace_controller import child_main;"
        "print(json.dumps({'site': [p for p in sys.path if p.endswith('site-packages')],"
        "'files': [str(m.__file__) for m in sys.modules.values() if getattr(m,'__file__',None)]}))"
    )
    observed = subprocess.run(
        [str(dependency_interpreter), "-I", "-B", "-c", source],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
    )
    value = json.loads(observed.stdout)
    directory.mkdir(mode=0o700)
    venv.EnvBuilder(with_pip=False, symlinks=False).create(directory)
    target = directory / "lib/python3.12/site-packages"
    groups = set()
    for name in value["files"]:
        path = Path(name)
        for parent in map(Path, value["site"]):
            if path.is_relative_to(parent):
                groups.add(parent / path.relative_to(parent).parts[0])
    for group in sorted(groups):
        if group.is_dir():
            shutil.copytree(
                group, target / group.name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
            )
        else:
            shutil.copyfile(group, target / group.name)
    executable = directory / "bin/python"
    probe = entry_probe(project)
    result = subprocess.run(
        [str(executable), "-I", "-B", "-c", probe],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
    )
    if result.stdout.strip() != "CONTROLLER_IMPORT_READY":
        raise ValueError("CONTROLLER_PYTHON_IMPORT_PROOF")
    files = [executable, directory / "pyvenv.cfg"]
    files += [p for p in target.rglob("*") if p.is_file()]
    pins = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    manifest = directory / "controller-python.json"
    manifest.write_bytes(
        canonical(
            dict(
                contract="SOC_CONTROLLER_PYTHON_RUNTIME_V1", executable=str(executable), files=pins
            )
        )
    )
    reference = dict(file=str(manifest), sha=hashlib.sha256(manifest.read_bytes()).hexdigest())
    config = dict(
        interpreter=str(executable), interpreter_sha=pins[str(executable)], python_runtime=reference
    )
    verify_python_runtime(config, os.getuid())
    return config

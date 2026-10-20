"""Actual non-root CLI preparation, only compilation and private fixture storage."""

import json
import os
import subprocess
import sys
from pathlib import Path

from soc_agent.security_ai.ebpf.build import compile_program


def test_actual_prepare_cli_never_authenticates_or_attaches(tmp_path):
    directory = tmp_path / "build"
    identity = compile_program(directory)
    root = Path(__file__).resolve().parents[3]
    env = dict(os.environ, PYTHONPATH=str(root / "src"))
    argv = [
        sys.executable,
        "-m",
        "soc_agent.security_ai.ebpf",
        "prepare",
        "--program",
        str(directory / "tc.bpf.o"),
        "--data-directory",
        str(tmp_path / "sessions"),
    ]
    for _ in range(2):
        p = subprocess.run(argv, cwd=root, env=env, capture_output=True, text=True, timeout=20)
        assert p.returncode == 0, p.stderr
        value = json.loads(p.stdout)
        assert value["state"] == "NATIVE_HOOK_PENDING" and value["collection_live"] is False
        assert value["ebpf"]["program_sha256"] == identity["tc.bpf.o"]
        assert value["ebpf"]["metrics"]["kernel_events"] is None
        assert value["ebpf"]["native_ai"] == "BLOCKED"
        assert value["command_valid"] is False and value["listener_ready"] is False
    assert len(list((tmp_path / "sessions").glob("session-*"))) == 2

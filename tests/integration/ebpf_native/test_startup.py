"""Real unprivileged preparation CLI, no OS authentication invocation."""

import os
import subprocess
import sys
from pathlib import Path

from tests.ebpf_native_support import application


def test_prepare_cli_displays_scope_and_stays_authentication_required(tmp_path):
    c = application(tmp_path / "build-input")
    root = Path(__file__).resolve().parents[3]
    p = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_agent.security_ai.ebpf_native",
            "prepare",
            "--program",
            str(c.program),
            "--loader",
            str(c.loader),
            "--data-directory",
            str(tmp_path / "applications"),
        ],
        capture_output=True,
        text=True,
        env=dict(os.environ, PYTHONPATH=str(root / "src")),
        timeout=20,
    )
    assert p.returncode == 0, p.stderr
    assert "Application approval digest:" in p.stdout
    assert "TERMINAL_PASSWORD_ONCE_PER_APPLICATION:v1" in p.stdout
    assert "APPROVAL_REQUIRED" in p.stdout and "PHASE_A_NATIVE_BLOCKED" in p.stdout
    assert '"collection_live": false' in p.stdout
    for action in ("load", "attach", "native"):
        result = subprocess.run(
            [sys.executable, "-m", "soc_agent.security_ai.ebpf_native", action],
            capture_output=True,
            text=True,
            env=dict(os.environ, PYTHONPATH=str(root / "src")),
            timeout=10,
        )
        assert result.returncode != 0

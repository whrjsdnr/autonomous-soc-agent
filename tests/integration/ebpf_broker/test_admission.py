"""Admission contains no sudo/PAM, Native mode or automatic privilege path."""

import subprocess
import sys

import pytest

from soc_agent.security_ai.ebpf_broker.__main__ import main
from soc_agent.security_ai.ebpf_broker.server import run


def test_only_explicit_fixture_cli_is_available():
    p = subprocess.run(
        [sys.executable, "-m", "soc_agent.security_ai.ebpf_broker", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert p.returncode == 0 and "fixture" in p.stdout
    with pytest.raises(SystemExit) as e:
        main(["native"])
    assert e.value.code == 2


def test_privileged_entry_refuses_before_receiving_plan(monkeypatch):
    monkeypatch.setattr(
        "soc_agent.security_ai.ebpf_broker.server.controller_unprivileged", lambda: False
    )
    with pytest.raises(ValueError, match="ROOT_OR_PRIVILEGE_DENIED"):
        run(None, -1)

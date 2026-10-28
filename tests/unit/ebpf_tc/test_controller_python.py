"""Actual ordinary Python imports only, never sudo, DNS or Namespace entry."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

from soc_agent.security_ai.ebpf_tc import controller_python
from soc_agent.security_ai.ebpf_tc.namespace_controller import verify_python_entry
from soc_agent.security_ai.ebpf_tc.namespace_controller_engine import verify_python_runtime


@pytest.fixture(scope="module")
def prepared(tmp_path_factory):
    root = Path(__file__).resolve().parents[3]
    config = controller_python.prepare(
        tmp_path_factory.mktemp("controller") / "python",
        project=root,
        dependency_interpreter=Path(sys.executable),
    )
    return config | dict(project=str(root))


def test_canonical_python_imports_entry_point_with_frozen_dependencies(prepared):
    assert Path(prepared["interpreter"]).resolve() == Path(prepared["interpreter"])
    verify_python_entry(prepared)
    manifest = json.loads(Path(prepared["python_runtime"]["file"]).read_bytes())
    assert any("pydantic" in name for name in manifest["files"])
    assert Path(prepared["interpreter"]).is_file()


def test_no_unpinned_system_python_fallback():
    with pytest.raises(ValueError, match="RUNTIME_REQUIRED"):
        verify_python_entry(
            dict(interpreter=str(Path(sys.executable).resolve()), project="/unused")
        )


def test_unpinned_dependency_injection_is_rejected(prepared):
    root = Path(prepared["python_runtime"]["file"]).parent
    extra = root / "lib/python3.12/site-packages/unapproved.pth"
    try:
        extra.write_text("import os\n")
        with pytest.raises(ValueError, match="UNPINNED_DEPENDENCY"):
            verify_python_runtime(prepared, __import__("os").getuid())
    finally:
        extra.unlink()


def test_dependency_tamper_stops_before_entry(prepared):
    manifest = json.loads(Path(prepared["python_runtime"]["file"]).read_bytes())
    path = next(Path(n) for n in manifest["files"] if n.endswith("pyvenv.cfg"))
    before = path.read_bytes()
    try:
        path.write_bytes(before + b"# changed\n")
        with pytest.raises(ValueError, match="DEPENDENCY_CHANGED"):
            verify_python_entry(prepared)
    finally:
        path.write_bytes(before)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest["files"][str(path)]


def test_root_runtime_validation_follows_grant_and_limits_before_any_worker(monkeypatch, capsys):
    from soc_agent.security_ai.ebpf_tc import dns_diagnostic_engine as engine

    order = []
    monkeypatch.setattr(engine.os, "getuid", lambda: 0)
    monkeypatch.setattr(engine.os, "geteuid", lambda: 0)
    monkeypatch.setattr(engine.sys, "argv", ["test-only", "{}"])
    monkeypatch.setattr(engine.resource, "setrlimit", lambda *_: order.append("limit"))
    monkeypatch.setattr(engine.signal, "alarm", lambda *_: None)
    monkeypatch.setattr(engine, "dns_validate_grant", lambda *_: order.append("grant"))

    def runtime(*_):
        order.append("runtime")
        raise ValueError("TEST_STOP_BEFORE_CLAIM_OR_WORKER")

    monkeypatch.setattr(engine, "verify_python_runtime", runtime, raising=False)
    with pytest.raises(ValueError, match="TEST_STOP_BEFORE_CLAIM_OR_WORKER"):
        engine.dns_root_admit(dict(controller={}, uid=1000, session="TEST_ONLY"))
    assert order == ["limit", "limit", "limit", "grant", "runtime"]
    assert "DNS_ROOT_AUTHENTICATED" in capsys.readouterr().out

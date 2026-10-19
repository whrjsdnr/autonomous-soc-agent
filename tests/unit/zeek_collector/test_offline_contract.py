"""Mock the Docker API completely; no container/capture is started by unit tests."""

import io
import os
from types import SimpleNamespace

import pytest
from tests.zeek_collector_support import pcap_fixture, row

from soc_agent.security_ai.collectors import offline


@pytest.mark.parametrize("fault", [None, "privacy", "exit", "oversize", "missing_marker"])
def test_bounded_offline_command_and_cleanup(tmp_path, monkeypatch, fault):
    pcap = tmp_path / "fixture.pcap"
    sha = pcap_fixture(pcap)
    logs = tmp_path / "logs"
    logs.mkdir()
    body = b"SOC_ZEEK_CONN_V1\n" + row() + b"SOC_ZEEK_DNS_V1\n" + row("dns")
    if fault == "privacy":
        body += row("dns", query="not-retained.example")
    if fault == "oversize":
        body += b"x" * 16385
    if fault == "missing_marker":
        body = b"no framing\n"
    calls = []

    def run(args, **kw):
        calls.append(args)
        return SimpleNamespace(
            returncode=0, stdout=(b"a" * 64 + b"\n") if "create" in args else b""
        )

    class Process:
        stdout = io.BytesIO(body)
        returncode = 0

        def wait(self, **kw):
            return 1 if fault == "exit" else 0

        def poll(self):
            return 0

    runner = offline.OfflineZeek()
    monkeypatch.setattr(runner, "environment", lambda: {})
    monkeypatch.setattr(runner, "_docker", lambda: "/usr/bin/docker")
    monkeypatch.setattr(offline.subprocess, "run", run)
    monkeypatch.setattr(offline.subprocess, "Popen", lambda *a, **kw: Process())
    if fault:
        with pytest.raises(ValueError):
            runner.run(pcap, sha, logs)
    else:
        result = runner.run(pcap, sha, logs)
        assert result["native_capture"] is False and result["exit_code"] == 0
    create = calls[0]
    assert "--network=none" in create and "--cap-drop=ALL" in create
    assert "--read-only" in create and "--log-driver=none" in create and "--pull=never" in create
    assert create[create.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    assert offline.IMAGE in create and "-i" not in create
    assert "55s" in offline.PROGRAM and not any("sudo" in arg for arg in create)
    assert calls[-1][-3:] == ["rm", "--force", "a" * 64]
    assert runner.container is None


def test_missing_dependency_and_digest_mismatch_before_process(tmp_path, monkeypatch):
    runner = offline.OfflineZeek()
    monkeypatch.setattr(offline.shutil, "which", lambda _: None)
    with pytest.raises(ValueError, match="UNAVAILABLE"):
        runner.environment()
    path = tmp_path / "sample.pcap"
    pcap_fixture(path)
    with pytest.raises(ValueError, match="DIGEST_MISMATCH"):
        runner.run(path, "f" * 64, tmp_path)

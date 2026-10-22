"""Mock Root/traffic entry, real capless file-only Zeek; never capture or DNS I/O."""

import io
import json
import os
import subprocess
import time

from soc_agent.security_ai.collectors import offload_session as session


def test_authenticated_session_waits_for_real_zeek_ready_before_start(tmp_path, monkeypatch):
    candidate = tmp_path / "candidate"
    identity = session.prepare(candidate)
    scope = json.loads((candidate / "release.json").read_text())["capture_scope_digest"]
    real_popen, real_run = subprocess.Popen, subprocess.run
    order = []

    class StartInput(io.StringIO):
        started = False

        def write(self, text):
            assert text == "START\n"
            self.started = True
            order.append("start")
            return super().write(text)

    class RootOutput(io.StringIO):
        def readline(self, *args):
            text = super().readline(*args)
            if '"DNS_COPY_READY"' in text:
                assert root.stdin.started, "capture cannot begin before Zeek READY"
            return text

    class FakeRoot:
        pid = os.getpid()

        def __init__(self):
            now = time.monotonic()
            self.stdin = StartInput()
            self.stdout = RootOutput(
                "\n".join(
                    json.dumps(row)
                    for row in [
                        dict(
                            state="DNS_COPY_AUTHENTICATED",
                            scope_digest=scope,
                            session_started=now,
                            deadline=now + 10,
                        ),
                        dict(
                            state="DNS_COPY_READY",
                            scope_digest=scope,
                            capabilities={
                                key: 0 for key in ["CapEff", "CapPrm", "CapInh", "CapAmb"]
                            },
                        ),
                        dict(
                            state="CLOSED",
                            scope_digest=scope,
                            image_sha256=identity["image"],
                            manifest=json.loads((candidate / "release.json").read_text())[
                                "base_manifest"
                            ],
                            received=0,
                            accepted=0,
                            rejected=0,
                            final_chain="0" * 64,
                            socket_packets=0,
                            socket_drops=0,
                            capture_elapsed_seconds=0.01,
                        ),
                    ]
                )
                + "\n"
            )

        def wait(self, **kwargs):
            return 0

    root = None

    def launch(argv, **kwargs):
        nonlocal root
        if argv == ["MOCK_ROOT_NO_EXECUTION"]:
            root = FakeRoot()
            return root
        return real_popen(argv, **kwargs)

    def run(argv, **kwargs):
        if "--approve" not in argv:
            return real_run(argv, **kwargs)
        order.append("mock_probe")
        receipt = dict(
            state="COMPLETED",
            records=[
                dict(source=["127.0.0.1", 45000], destination=["127.0.0.53", 53], transport=p)
                for p in ["UDP", "TCP"]
            ],
        )
        from pathlib import Path

        Path(argv[argv.index("--receipt") + 1]).write_text(json.dumps(receipt))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(session, "pinned_command", lambda *args: ["MOCK_ROOT_NO_EXECUTION"])
    monkeypatch.setattr(session.os, "isatty", lambda fd: True)
    monkeypatch.setattr(subprocess, "Popen", launch)
    monkeypatch.setattr(subprocess, "run", run)
    from pathlib import Path

    result = session.execute(
        candidate,
        identity["manifest"],
        identity["image"],
        probe=Path("tests/native_dns_live_probe.py"),
    )
    assert order == ["start", "mock_probe"]
    assert result["phase_times"]["zeek_ready"] <= result["phase_times"]["capture_ready"]
    assert result["zeek_exit"]["closed_observed"] and result["zeek_exit"]["cleanup_verified"]
    assert result["verdict"] == "DNS_NATIVE_ANALYSIS_COPY_E2E_INCOMPLETE"
    assert result["forwarded_probe_packets"] == 0
    timing = json.loads((candidate / "live-attempt-1/session-timing.json").read_text())
    assert timing["worker_exited"] and timing["whole_deadline_met"]

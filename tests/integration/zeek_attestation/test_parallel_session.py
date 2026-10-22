"""Mock Root/traffic entry, real capless file-only Zeek; never capture or DNS I/O."""

import io
import json
import os
import subprocess
import time

import pytest

from soc_agent.security_ai.collectors import offload_session as session


@pytest.mark.parametrize("authentication_failed", [False, True, "no_diagnostic"])
def test_authenticated_session_waits_for_real_zeek_ready_before_start(
    tmp_path, monkeypatch, authentication_failed
):
    candidate = tmp_path / "candidate"
    identity = session.prepare(candidate)
    scope = json.loads((candidate / "release.json").read_text())["capture_scope_digest"]
    real_popen, real_run = subprocess.Popen, subprocess.run
    order = []

    from soc_agent.security_ai.collectors.start_channel import (
        start_connect,
        start_peer,
        start_receive,
    )

    binding = None

    class RootOutput(io.StringIO):
        def readline(self, *args):
            text = super().readline(*args)
            if '"DNS_COPY_READY"' in text:
                start_receive(root.control, binding, time.monotonic() + 1)
                root.control.close()
                order.append("start")
            return text

    class FakeRoot:
        pid = os.getpid()

        def __init__(self):
            now = time.monotonic()
            if authentication_failed == "no_diagnostic":
                self.stdout = RootOutput("")
                return
            if authentication_failed:
                self.stdout = RootOutput(
                    json.dumps(
                        dict(
                            state="DNS_COPY_ROOT_ERROR",
                            stage="PASSWORD_POLICY",
                            api="_candidate_policy",
                            original_code="UNIFIED_PASSWORD_POLICY_REJECTED",
                            errno=None,
                            exit_code=1,
                        )
                    )
                    + "\n"
                )
                return
            self.control = start_connect(os.getuid(), os.getgid(), os.getpid(), binding, now + 1)
            self.stdout = RootOutput(
                "\n".join(
                    json.dumps(row)
                    for row in [
                        dict(
                            state="DNS_COPY_AUTHENTICATED",
                            root_pid=os.getpid(),
                            binding=binding,
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
            if hasattr(self, "control"):
                self.control.close()
            return 1 if authentication_failed else 0

    root = None

    def launch(argv, **kwargs):
        nonlocal root
        if argv == ["MOCK_ROOT_NO_EXECUTION"]:
            assert kwargs["stdin"] is None, "OS authentication must inherit the terminal"
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

    def pinned(image, wire, approval, uid, gid):
        nonlocal binding
        binding = session.start_binding(wire, image.sha256, image.manifest, approval, scope)
        return ["MOCK_ROOT_NO_EXECUTION"]

    monkeypatch.setattr(session, "pinned_command", pinned)
    # Explicit test-only ordinary-user peer stands in for Root; never Native proof.
    monkeypatch.setattr(
        session,
        "start_peer",
        lambda channel, uid, gid, pid: start_peer(channel, os.getuid(), os.getgid(), pid),
    )
    monkeypatch.setattr(session.os, "isatty", lambda fd: True)
    monkeypatch.setattr(subprocess, "Popen", launch)
    monkeypatch.setattr(subprocess, "run", run)
    from pathlib import Path

    if authentication_failed:
        code = (
            "DNS_COPY_ENTRY_FAILED"
            if authentication_failed == "no_diagnostic"
            else "UNIFIED_PASSWORD_POLICY_REJECTED"
        )
        with pytest.raises(ValueError, match=code):
            session.execute(
                candidate,
                identity["manifest"],
                identity["image"],
                probe=Path("tests/native_dns_live_probe.py"),
            )
        assert order == []
        name = "entry-error.json" if authentication_failed == "no_diagnostic" else "root-error.json"
        error = json.loads((candidate / "live-attempt-1" / name).read_text())
        assert error["stage"] == (
            "OS_AUTH_OR_IMAGE_ENTRY"
            if authentication_failed == "no_diagnostic"
            else "PASSWORD_POLICY"
        )
        assert error["errno"] is None and error["exit_code"] == 1
        assert not (candidate / "live-attempt-1/zeek").exists()
        with session.start_listener(os.getuid(), binding):
            pass  # Session listener released after failed authentication.
        return
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
